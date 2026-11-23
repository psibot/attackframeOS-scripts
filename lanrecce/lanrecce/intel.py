"""CVE prioritisation, same idea as recce's cve_intel: CISA KEV + FIRST EPSS
-> fire / smoke / ice. Severity is only ever raised, never lowered.

  fire   on KEV, or EPSS >= 0.5, or (public exploit and EPSS >= 0.1)
  smoke  CVSS >= 7, or public exploit, or EPSS >= 0.1
  ice    everything else

Feeds are cached under ~/.cache/lanrecce (KEV 12h). Offline / --offline means
tiering from CVSS + exploit flag only; the run never fails on a feed outage.
"""
from __future__ import annotations

import json
import os
import time
import urllib.request
from pathlib import Path

from .model import SEV_RANK, State
from .runner import log, sudo_user

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss?cve={}"
UA = {"User-Agent": "lanrecce/0.1"}


def _cache_dir() -> Path:
    su = sudo_user()
    home = Path(su.pw_dir) if su else Path.home()
    d = Path(os.environ.get("XDG_CACHE_HOME", home / ".cache")) / "lanrecce"
    d.mkdir(parents=True, exist_ok=True)
    if su:
        os.chown(d, su.pw_uid, su.pw_gid)
    return d


def _get(url: str, timeout=20) -> bytes:
    with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=timeout) as r:
        return r.read()


def load_kev() -> set[str]:
    f = _cache_dir() / "kev.json"
    if not f.exists() or time.time() - f.stat().st_mtime > 12 * 3600:
        try:
            f.write_bytes(_get(KEV_URL, 30))
            su = sudo_user()
            if su:
                os.chown(f, su.pw_uid, su.pw_gid)
        except Exception as e:
            log(f"KEV fetch failed ({e}); {'using stale cache' if f.exists() else 'no KEV data'}", "warn")
    try:
        return {v["cveID"].upper() for v in json.loads(f.read_text())["vulnerabilities"]}
    except Exception:
        return set()


def load_epss(cves: list[str]) -> dict[str, float]:
    out = {}
    for i in range(0, len(cves), 100):
        chunk = cves[i:i + 100]
        try:
            data = json.loads(_get(EPSS_URL.format(",".join(chunk))))
            for row in data.get("data", []):
                out[row["cve"].upper()] = float(row["epss"])
        except Exception as e:
            log(f"EPSS fetch failed ({e})", "warn")
            break
    return out


def tier(kev: bool, epss: float | None, exploit: bool, cvss: float | None) -> str:
    e = epss or 0.0
    if kev or e >= 0.5 or (exploit and e >= 0.1):
        return "fire"
    if (cvss or 0) >= 7 or exploit or e >= 0.1:
        return "smoke"
    return "ice"


def enrich(state: State, offline: bool) -> None:
    cve_findings = [f for f in state.findings.values() if f.cve_id]
    if not cve_findings:
        return
    kev, epss = set(), {}
    if not offline:
        kev = load_kev()
        epss = load_epss(sorted({f.cve_id for f in cve_findings}))
    for f in cve_findings:
        f.kev = f.cve_id in kev if kev else None
        f.epss = epss.get(f.cve_id)
        f.priority = tier(bool(f.kev), f.epss, f.exploit, f.cvss_score)
        if f.kev and SEV_RANK[f.severity] > SEV_RANK["critical"]:
            f.severity = "critical"
        elif f.priority == "fire" and SEV_RANK[f.severity] > SEV_RANK["high"]:
            f.severity = "high"
    n_kev = sum(1 for f in cve_findings if f.kev)
    n_fire = sum(1 for f in cve_findings if f.priority == "fire")
    log(f"CVE intel: {len(cve_findings)} CVE findings, {n_kev} on CISA KEV, {n_fire} fire-tier", "ok")
