"""Export for Dossier (the pentest reporting app).

Dossier has no API: it imports scanner files on its Import page (several at
once). Its importers were read from the deployed bundle, and this module
targets the two that carry the most:

  dossier-findings.nessus   Nessus v2 XML. Dossier's Nessus importer is its
                            richest: Critical..Info, CVSS (cvss3_base_score),
                            CWE, CVEs + see_also as references, synopsis ->
                            description, description -> impact, solution ->
                            remediation and plugin_output -> EVIDENCE. (The
                            nuclei importer keeps only matched-at as evidence.)
  dossier-hosts.xml         nmap XML with every live host and open port with
                            product/version. Dossier's Nessus importer only
                            creates services for ports that have a finding;
                            this file fills in the full inventory and the
                            versions (Dossier merges hosts by IP and services
                            by port/proto, filling empty versions).

How Dossier merges imports (so re-importing is safe):
  * hosts:    matched by IP, then hostname
  * findings: de-duplicated on (lower(title), severity, hosts). Two findings with
              the same title on one host would collapse, so the port is added to
              the title when that would happen.
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
import zlib
from collections import Counter

from .model import State

SEV_NUM = {"critical": "4", "high": "3", "medium": "2", "low": "1", "info": "0"}
# XML 1.0 forbids most control chars; banners/HTTP bodies are full of them and
# one bad byte makes Dossier reject the whole file ("Malformed XML").
_BAD_XML = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\ud800-\udfff￾￿]")
MAX_EVIDENCE = 12000


def _clean(s) -> str:
    return _BAD_XML.sub("", "" if s is None else str(s))


def _sub(parent, tag, text=None, **attrs):
    el = ET.SubElement(parent, tag, {k: _clean(v) for k, v in attrs.items() if v is not None})
    if text not in (None, ""):
        el.text = _clean(text)
    return el


def _os_name(os_field: str | None) -> str:
    return re.sub(r"\s*\(\d+%\)$", "", os_field or "")


def _plugin_output(f) -> str:
    lines = []
    if f.matched_at:
        lines.append(f"Matched at: {f.matched_at}")
    src = {"nuclei": f"nuclei template {f.rule}", "vulners": "nmap vulners (version match)",
           "check": f"lanrecce check {f.rule}"}.get(f.source, f.source)
    lines.append(f"Source: {src}")
    intel = []
    if f.priority:
        intel.append(f"priority {f.priority}")
    if f.kev is not None:
        intel.append(f"CISA KEV: {'YES' if f.kev else 'no'}")
    if f.epss is not None:
        intel.append(f"EPSS {f.epss * 100:.1f}%")
    if f.exploit:
        intel.append("public exploit available")
    if intel:
        lines.append("CVE intel: " + ", ".join(intel))
    out = "\n".join(lines)
    if f.evidence:
        out += "\n\n" + f.evidence
    if len(out) > MAX_EVIDENCE:
        out = out[:MAX_EVIDENCE] + "\n[... truncated]"
    return out


def to_nessus(state: State, name: str = "lanrecce") -> bytes:
    findings = state.sorted_findings()
    clash = Counter((f.title.lower(), f.severity, f.host) for f in findings)

    root = ET.Element("NessusClientData_v2")
    report = _sub(root, "Report", name=name)
    by_host: dict[str, list] = {}
    for f in findings:
        by_host.setdefault(f.host, []).append(f)

    for ip, h in state.hosts.items():
        items = by_host.get(ip, [])
        if not items:
            continue  # hosts without findings come in via dossier-hosts.xml
        rh = _sub(report, "ReportHost", name=ip)
        props = _sub(rh, "HostProperties")
        _sub(props, "tag", ip, name="host-ip")
        if h.get("hostnames"):
            _sub(props, "tag", h["hostnames"][0], name="host-fqdn")
        if h.get("os"):
            _sub(props, "tag", _os_name(h["os"]), name="operating-system")
        if h.get("mac"):
            _sub(props, "tag", h["mac"], name="mac-address")
        for f in items:
            port = h["ports"].get(f"{f.port}/{f.proto or 'tcp'}", {}) if f.port else {}
            title = f.title
            if clash[(f.title.lower(), f.severity, f.host)] > 1 and f.port:
                title = f"{f.title} ({f.port}/{f.proto or 'tcp'})"
            ri = _sub(rh, "ReportItem",
                      port=str(f.port or 0), protocol=f.proto or "tcp",
                      svc_name=port.get("service") or ("general" if not f.port else "unknown"),
                      severity=SEV_NUM.get(f.severity, "0"),
                      pluginID=str(zlib.crc32(f"{f.source}:{f.rule}".encode()) % 900000 + 100000),
                      pluginName=title, pluginFamily=f"lanrecce/{f.source}")
            _sub(ri, "risk_factor", {"critical": "Critical", "high": "High", "medium": "Medium",
                                     "low": "Low"}.get(f.severity, "None"))
            # Dossier: description <- synopsis, impact <- description (if different).
            # Full text in synopsis keeps Dossier's description complete.
            _sub(ri, "synopsis", f.description or f.title)
            _sub(ri, "solution", f.remediation or "")
            _sub(ri, "plugin_output", _plugin_output(f))
            if f.cvss_score is not None:
                _sub(ri, "cvss3_base_score", f"{float(f.cvss_score):.1f}")
            if f.cvss_vector:
                _sub(ri, "cvss3_vector", f.cvss_vector)
            if f.cwe:
                _sub(ri, "cwe", f.cwe)
            if f.cve_id:
                _sub(ri, "cve", f.cve_id)
            refs = [r for r in (f.references or []) if isinstance(r, str)]
            if refs:
                _sub(ri, "see_also", "\n".join(refs[:10]))
    ET.indent(root)
    return b'<?xml version="1.0" ?>\n' + ET.tostring(root, encoding="utf-8")


def to_nmap_xml(state: State) -> bytes:
    root = ET.Element("nmaprun", scanner="nmap", args="lanrecce export",
                      version="7.0", xmloutputversion="1.05")
    for ip, h in state.hosts.items():
        host = _sub(root, "host")
        _sub(host, "status", state="up", reason=h.get("reason") or "lanrecce")
        _sub(host, "address", addr=ip, addrtype="ipv6" if ":" in ip else "ipv4")
        if h.get("mac"):
            _sub(host, "address", addr=h["mac"], addrtype="mac", vendor=h.get("vendor"))
        hns = _sub(host, "hostnames")
        for n in h.get("hostnames") or []:
            _sub(hns, "hostname", name=n, type="PTR")
        ports = _sub(host, "ports")
        for p in sorted(h["ports"].values(), key=lambda p: (p["proto"], p["port"])):
            pe = _sub(ports, "port", protocol=p["proto"], portid=str(p["port"]))
            _sub(pe, "state", state="open", reason="lanrecce")
            _sub(pe, "service", name=p.get("service") or "unknown", product=p.get("product"),
                 version=p.get("version"), extrainfo=p.get("extrainfo"), tunnel=p.get("tunnel"))
        if h.get("os"):
            os_el = _sub(host, "os")
            _sub(os_el, "osmatch", name=_os_name(h["os"]), accuracy="")
    ET.indent(root)
    return b'<?xml version="1.0" ?>\n' + ET.tostring(root, encoding="utf-8")


def write(state: State, out) -> list:
    name = out.name
    (out / "dossier-findings.nessus").write_bytes(to_nessus(state, f"lanrecce {name}"))
    (out / "dossier-hosts.xml").write_bytes(to_nmap_xml(state))
    return [out / "dossier-findings.nessus", out / "dossier-hosts.xml"]
