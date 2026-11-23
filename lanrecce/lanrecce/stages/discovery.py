"""Stage 1: host discovery (nmap -sn).

Root (or nmap with cap_net_raw) gets ARP on the local segment, which finds
every device including ones that drop all TCP. Unprivileged nmap can only do
TCP connect pings, so hosts with no listening ports on the probe list are
missed; lanrecce warns about that.
"""
from __future__ import annotations

import ipaddress

from ..runner import log, run
from .nmapxml import parse_into

PROBE_PORTS = "21,22,23,25,53,80,111,135,139,443,445,515,631,1433,2375,3306,3389,5000,5432,5900,6379,8000,8080,8443,9100,9200,27017,62078"
MAX_BLIND = 4096


def run_stage(ctx) -> None:
    st, scope = ctx.state, ctx.scope
    if ctx.args.no_discovery:
        n = 0
        for net in scope.include:
            for a in (net.hosts() if net.num_addresses > 2 else net):
                if scope.allows(str(a)):
                    st.host(str(a))["reason"] = "assumed-up"
                    n += 1
                    if n >= MAX_BLIND:
                        log(f"--no-discovery capped at {MAX_BLIND} addresses", "warn")
                        return
        log(f"discovery skipped: treating {n} addresses as up", "warn")
        return

    xml = ctx.raw / "discovery.xml"
    cmd = ["nmap", "-sn", "-n" if ctx.args.no_dns else "-R", ctx.profile["nmap_timing"],
           "--max-retries", "2", "-oX", str(xml)]
    if ctx.raw_ok:
        cmd += ctx.nmap_priv + ["-PE", "-PP", f"-PS{PROBE_PORTS}", "-PA80,443,3389", "-PU53,161"]
    else:
        log("not root: discovery uses TCP connect pings only (no ARP). Hosts with no "
            "common port open will be missed. Run with sudo for ARP discovery.", "warn")
        cmd += [f"-PS{PROBE_PORTS}"]
    if scope.exclude:
        cmd += ["--exclude", ",".join(scope.nmap_excludes())]
    cmd += scope.nmap_targets()
    run(cmd, logfile=ctx.toollog, privileged=True)
    up = parse_into(st, xml, scope, ports=False)
    for ip in up:
        if ip in ctx.own_ips:
            st.host(ip)["self"] = True
    log(f"{len(up)} live hosts", "ok")


def sorted_ips(ips):
    return sorted(ips, key=lambda s: int(ipaddress.ip_address(s)))
