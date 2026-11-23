"""Parse nmap XML into lanrecce State."""
from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

from ..model import State


def parse_into(state: State, xml_path: Path, scope, *, ports: bool = True) -> list[str]:
    """Merge an nmap XML file into state. Returns the in-scope IPs that were up."""
    try:
        root = ET.parse(xml_path).getroot()
    except (ET.ParseError, FileNotFoundError):
        return []
    up = []
    for h in root.findall("host"):
        st = h.find("status")
        if st is not None and st.get("state") != "up":
            continue
        ip = mac = vendor = None
        for a in h.findall("address"):
            t = a.get("addrtype")
            if t in ("ipv4", "ipv6") and not ip:
                ip = a.get("addr")
            elif t == "mac":
                mac, vendor = a.get("addr"), a.get("vendor")
        if not ip or not scope.allows(ip):
            continue
        up.append(ip)
        host = state.host(ip)
        if mac:
            host["mac"] = mac
        if vendor:
            host["vendor"] = vendor
        if st is not None and not host.get("reason"):
            host["reason"] = st.get("reason")
        for hn in h.findall("hostnames/hostname"):
            n = hn.get("name")
            if n and n not in host["hostnames"]:
                host["hostnames"].append(n)
        osm = h.find("os/osmatch")
        if osm is not None:
            host["os"] = f"{osm.get('name')} ({osm.get('accuracy')}%)"
        hs = h.find("hostscript")
        if hs is not None:
            host.setdefault("scripts", {})
            for s in hs.findall("script"):
                host["scripts"][s.get("id")] = s.get("output") or ""
        if not ports:
            continue
        for p in h.findall("ports/port"):
            pst = p.find("state")
            if pst is None or pst.get("state") != "open":
                continue
            rec = state.port(ip, int(p.get("portid")), p.get("protocol"))
            svc = p.find("service")
            if svc is not None:
                for k in ("product", "version", "extrainfo", "tunnel"):
                    if svc.get(k):
                        rec[k] = svc.get(k)
                if svc.get("name"):
                    rec["service"] = svc.get("name")
                for c in svc.findall("cpe"):
                    if c.text and c.text not in rec["cpe"]:
                        rec["cpe"].append(c.text)
            for s in p.findall("script"):
                rec["scripts"][s.get("id")] = s.get("output") or ""
    return up
