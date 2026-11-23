"""Stage 2: port scan (naabu, falling back to nmap)."""
from __future__ import annotations

import json

from ..profiles import port_spec
from ..runner import has_cap_net_raw, have, is_root, log, run, which
from .discovery import sorted_ips
from .nmapxml import parse_into


def run_stage(ctx) -> None:
    st, scope = ctx.state, ctx.scope
    ips = sorted_ips(ip for ip in st.hosts if scope.allows(ip))
    if not ips:
        log("no live hosts to port-scan", "warn")
        return
    ports = ctx.args.ports or ctx.profile["ports"]
    (ctx.raw / "hosts.txt").write_text("\n".join(ips) + "\n")

    if have("naabu") and not ctx.args.nmap_ports:
        syn = is_root() or has_cap_net_raw(which("naabu"))
        cmd = ["naabu", "-list", str(ctx.raw / "hosts.txt"), "-j", "-silent", "-Pn",
               "-s", "s" if syn else "c", "-rate", str(ctx.args.rate), "-c", "50",
               "-retries", "2", "-timeout", "1500"]
        spec = port_spec(ports)
        cmd += ["-p", spec or "1-65535"]
        log(f"naabu {'SYN' if syn else 'connect'} scan, ports={ports}, {len(ips)} hosts")
        n = 0

        def on_line(line):
            nonlocal n
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                return
            ip = r.get("ip") or r.get("host")
            if ip and r.get("port") and scope.allows(ip):
                st.port(ip, int(r["port"]), r.get("protocol") or "tcp")
                n += 1

        run(cmd, logfile=ctx.toollog, stdout_file=ctx.raw / "naabu.jsonl",
            privileged=True, on_line=on_line)
    else:
        xml = ctx.raw / "ports.xml"
        cmd = ["nmap", "-Pn", "-n", "--open", ctx.profile["nmap_timing"], "-oX", str(xml),
               "-iL", str(ctx.raw / "hosts.txt"), "--min-rate", str(ctx.args.rate)]
        cmd += (ctx.nmap_priv + ["-sS"]) if ctx.raw_ok else ["-sT"]
        spec = port_spec(ports)
        cmd += ["-p", spec or "1-65535"]
        log(f"nmap port scan, ports={ports}, {len(ips)} hosts")
        run(cmd, logfile=ctx.toollog, privileged=True)
        parse_into(st, xml, scope)

    total = sum(len(h["ports"]) for h in st.hosts.values())
    log(f"{total} open TCP ports across {sum(1 for h in st.hosts.values() if h['ports'])} hosts", "ok")
