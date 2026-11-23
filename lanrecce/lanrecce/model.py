"""Run state: hosts, services, web endpoints and findings.

Findings use the same shape as recce's (Dossier-style): severity, cvss, cwe,
cve_id, description, remediation, evidence, references, dedup_key. That keeps
the JSON export importable into recce/Dossier later if you want it.
"""
from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}


def sev_from_cvss(cvss: float | None) -> str:
    if cvss is None:
        return "info"
    return ("critical" if cvss >= 9 else "high" if cvss >= 7 else
            "medium" if cvss >= 4 else "low" if cvss > 0 else "info")


@dataclass
class Finding:
    title: str
    severity: str
    host: str
    port: int | None = None
    proto: str | None = None
    source: str = ""                 # nuclei | nmap | vulners | check
    rule: str = ""                   # template id / script id / check id
    description: str | None = None
    remediation: str | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    cwe: str | None = None
    cve_id: str | None = None
    references: list = field(default_factory=list)
    evidence: str | None = None
    matched_at: str | None = None
    tags: list = field(default_factory=list)
    exploit: bool = False            # public exploit known (vulners *EXPLOIT*)
    kev: bool | None = None
    epss: float | None = None
    priority: str | None = None      # fire | smoke | ice (CVE findings)
    status: str = "open"             # open | new | fixed (with --baseline)

    @property
    def dedup_key(self) -> str:
        return f"{self.source}:{self.rule}:{self.host}:{self.port or ''}"

    def to_json(self) -> dict:
        d = asdict(self)
        d["dedup_key"] = self.dedup_key
        return d


class State:
    def __init__(self, rundir: Path):
        self.rundir = rundir
        self.meta: dict = {"started": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "stages": {}}
        self.hosts: dict[str, dict] = {}
        self.findings: dict[str, Finding] = {}

    # ---- hosts -----------------------------------------------------------
    def host(self, ip: str) -> dict:
        h = self.hosts.get(ip)
        if h is None:
            h = self.hosts[ip] = {"ip": ip, "mac": None, "vendor": None, "hostnames": [],
                                  "os": None, "reason": None, "ports": {}, "web": []}
        return h

    def port(self, ip: str, port: int, proto: str = "tcp") -> dict:
        key = f"{port}/{proto}"
        ports = self.host(ip)["ports"]
        if key not in ports:
            ports[key] = {"port": int(port), "proto": proto, "service": None,
                          "product": None, "version": None, "extrainfo": None,
                          "tunnel": None, "cpe": [], "scripts": {}}
        return ports[key]

    def open_ports(self, proto: str | None = "tcp"):
        for ip, h in self.hosts.items():
            for p in h["ports"].values():
                if proto is None or p["proto"] == proto:
                    yield ip, p

    # ---- findings --------------------------------------------------------
    def add(self, f: Finding) -> None:
        k = f.dedup_key
        old = self.findings.get(k)
        if old is None or SEV_RANK[f.severity] < SEV_RANK[old.severity]:
            self.findings[k] = f

    def sorted_findings(self) -> list[Finding]:
        prio = {"fire": 0, "smoke": 1, "ice": 2, None: 3}
        return sorted(self.findings.values(), key=lambda f: (
            SEV_RANK[f.severity], prio.get(f.priority, 3), -(f.cvss_score or 0),
            _ipkey(f.host), f.port or 0, f.title))

    # ---- persistence -----------------------------------------------------
    def stage_done(self, name: str) -> bool:
        return self.meta["stages"].get(name, {}).get("status") == "done"

    def mark(self, name: str, status: str, **extra) -> None:
        self.meta["stages"].setdefault(name, {}).update(status=status, at=time.time(), **extra)
        self.save()

    def save(self) -> None:
        data = {"meta": self.meta, "hosts": self.hosts,
                "findings": [f.to_json() for f in self.sorted_findings()]}
        tmp = self.rundir / "state.json.tmp"
        tmp.write_text(json.dumps(data, indent=1, default=str))
        tmp.replace(self.rundir / "state.json")

    @classmethod
    def load(cls, rundir: Path) -> "State":
        s = cls(rundir)
        data = json.loads((rundir / "state.json").read_text())
        s.meta, s.hosts = data["meta"], data["hosts"]
        fields = set(Finding.__dataclass_fields__)
        for fd in data["findings"]:
            f = Finding(**{k: v for k, v in fd.items() if k in fields})
            s.findings[f.dedup_key] = f
        return s


def _ipkey(ip: str):
    try:
        import ipaddress
        a = ipaddress.ip_address(ip)
        return (a.version, int(a))
    except ValueError:
        return (9, 0)
