"""Stage 5: nuclei, in two passes.

  web pass      live URLs from httpx        -pt http
  network pass  every open ip:port          -pt tcp,javascript,ssl

The network pass is what recce doesn't do and what matters most on a LAN:
SMB/SSH/RDP/Redis/Mongo/FTP/MQTT/etc. misconfigs, exposures and CVEs.

Interactsh (out-of-band callbacks to oast.* servers on the internet) is off by
default: `-ni`. Pass --interactsh to allow it.
"""
from __future__ import annotations

import json
import re
import time
from urllib.parse import urlsplit

from ..model import Finding
from ..profiles import NUCLEI_EXCLUDE_TAGS, NUCLEI_LOGIN_TAGS
from ..runner import have, log, run

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)


def _base_cmd(ctx) -> list[str]:
    prof, a = ctx.profile, ctx.args
    sev = a.severity.split(",") if a.severity else prof["nuclei_severity"]
    etags = list(NUCLEI_EXCLUDE_TAGS)
    if not a.default_logins:
        etags += NUCLEI_LOGIN_TAGS
    cmd = ["nuclei", "-jsonl", "-silent", "-nc", "-duc", "-ot",
           "-s", ",".join(sev), "-etags", ",".join(etags),
           "-rl", str(prof["nuclei_rate"]), "-c", str(prof["nuclei_concurrency"]),
           "-timeout", "10", "-retries", "1", "-mhe", "20"]
    if not a.interactsh:
        cmd.append("-ni")
    if a.nuclei_templates:
        cmd += ["-ud", a.nuclei_templates]
    if a.nuclei_args:
        cmd += a.nuclei_args.split()
    return cmd


def _to_finding(n: dict, scope) -> Finding | None:
    info = n.get("info") or {}
    cls = info.get("classification") or {}
    matched = n.get("matched-at") or n.get("host") or ""
    ip = n.get("ip") or ""
    port = n.get("port")
    if not ip:
        h = urlsplit(matched if "://" in matched else f"x://{matched}")
        ip, port = h.hostname or "", port or h.port
    if not scope.allows(ip):
        return None
    try:
        port = int(port) if port else None
    except ValueError:
        port = None
    tid = n.get("template-id") or "nuclei"
    cves = cls.get("cve-id") or CVE_RE.findall(tid) or []
    cwe = (cls.get("cwe-id") or [None])[0]
    ev = []
    if n.get("matcher-name"):
        ev.append(f"matcher: {n['matcher-name']}")
    if n.get("extracted-results"):
        ev.append("extracted: " + ", ".join(map(str, n["extracted-results"]))[:2000])
    if n.get("request"):
        ev.append("--- request ---\n" + n["request"][:3000])
    if n.get("response"):
        ev.append("--- response ---\n" + n["response"][:3000])
    refs = info.get("reference") or []
    if isinstance(refs, str):
        refs = [refs]
    tags = info.get("tags") or []
    if isinstance(tags, str):
        tags = [t.strip() for t in tags.split(",")]
    return Finding(
        title=info.get("name") or tid,
        severity=(info.get("severity") or "info").lower().replace("unknown", "info"),
        host=ip, port=port, proto="tcp", source="nuclei", rule=tid,
        description=(info.get("description") or "").strip() or None,
        remediation=(info.get("remediation") or "").strip() or None,
        cvss_score=cls.get("cvss-score"), cvss_vector=cls.get("cvss-metrics"),
        cwe=cwe.upper() if cwe else None,
        cve_id=cves[0].upper() if cves else None,
        references=refs, evidence="\n".join(ev) or None, matched_at=matched,
        tags=tags,
    )


def _pass(ctx, name: str, targets: list[str], ptypes: str) -> int:
    if not targets:
        log(f"nuclei {name} pass: no targets")
        return 0
    tfile = ctx.raw / f"nuclei-{name}-targets.txt"
    tfile.write_text("\n".join(targets) + "\n")
    count = 0
    last_save = time.time()

    def on_line(line):
        nonlocal count, last_save
        try:
            n = json.loads(line)
        except json.JSONDecodeError:
            return
        f = _to_finding(n, ctx.scope)
        if f:
            ctx.state.add(f)
            count += 1
            if time.time() - last_save > 3:  # let the web UI show findings live
                ctx.state.save()
                last_save = time.time()
            if f.severity in ("critical", "high", "medium"):
                log(f"  {f.severity.upper():8} {f.title}  @ {f.matched_at}", "ok")

    log(f"nuclei {name} pass: {len(targets)} targets, types={ptypes}")
    run(_base_cmd(ctx) + ["-l", str(tfile), "-pt", ptypes],
        logfile=ctx.toollog, stdout_file=ctx.raw / f"nuclei-{name}.jsonl",
        on_line=on_line, timeout=ctx.args.nuclei_timeout)
    ctx.state.save()
    return count


def run_stage(ctx) -> None:
    if not have("nuclei"):
        log("nuclei not installed: skipped", "err")
        return
    st = ctx.state
    urls = sorted({w["url"] for h in st.hosts.values() for w in h["web"]})
    hostports = sorted({f"{ip}:{p['port']}" for ip, p in st.open_ports("tcp")})
    n = _pass(ctx, "web", urls, "http")
    n += _pass(ctx, "network", hostports, "tcp,javascript,ssl")
    log(f"nuclei: {n} results", "ok")
