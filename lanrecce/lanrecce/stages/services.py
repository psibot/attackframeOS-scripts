"""Stage 3: service/version detection + safe NSE scripts (+ vulners CVEs).

One nmap per host (each host has its own port list), run in parallel.
"""
from __future__ import annotations

import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..runner import log, run, which
from .discovery import sorted_ips
from .nmapxml import parse_into


def _have_script(name: str) -> bool:
    nmap = which("nmap")
    r = subprocess.run([nmap, "--script-help", name], capture_output=True, text=True)
    return r.returncode == 0 and name in r.stdout


def run_stage(ctx) -> None:
    st, scope = ctx.state, ctx.scope
    targets = {ip: sorted(p["port"] for p in h["ports"].values() if p["proto"] == "tcp")
               for ip, h in st.hosts.items() if h["ports"] and scope.allows(ip)}
    scripts = list(ctx.profile["nse"])
    if not ctx.args.no_vulners and _have_script("vulners"):
        scripts.insert(0, "vulners")
    elif not ctx.args.no_vulners:
        log("vulners NSE not installed: no version->CVE matching (see install.sh)", "warn")
    ctx.state.meta["nse"] = scripts

    base = ["nmap", "-sV", "-Pn", "-n", ctx.profile["nmap_timing"], "--version-intensity", "7",
            "--script", ",".join(scripts), "--script-timeout", "90s", "--host-timeout", "30m"]
    if ctx.raw_ok:
        base += ctx.nmap_priv + ["-sS", "-O", "--osscan-limit"]
    else:
        base += ["-sT"]

    def one(ip, ports):
        xml = ctx.raw / f"svc-{ip.replace(':', '_')}.xml"
        run(base + ["-p", ",".join(map(str, ports)), "-oX", str(xml), ip],
            logfile=ctx.toollog, privileged=True)
        return ip, xml

    if targets:
        log(f"nmap -sV + {len(scripts)} NSE scripts on {len(targets)} hosts "
            f"({ctx.args.workers} in parallel)")
        with ThreadPoolExecutor(max_workers=ctx.args.workers) as ex:
            futs = [ex.submit(one, ip, targets[ip]) for ip in sorted_ips(targets)]
            for i, fut in enumerate(as_completed(futs), 1):
                ip, xml = fut.result()
                parse_into(st, xml, scope)
                h = st.hosts[ip]
                svcs = ", ".join(f"{p['port']}/{p['service'] or '?'}" for p in h["ports"].values())
                log(f"  [{i}/{len(futs)}] {ip}  {svcs[:110]}")
                st.save()

    if ctx.profile["udp"] and not ctx.args.no_udp:
        if not ctx.raw_ok:
            log("UDP scan needs root: skipped", "warn")
        elif st.hosts:
            xml = ctx.raw / "udp.xml"
            (ctx.raw / "hosts.txt").write_text("\n".join(sorted_ips(st.hosts)) + "\n")
            log("nmap UDP top-25 (snmp, ipmi, nbns, ntp, mdns ...)")
            run(["nmap", "-sU", "-sV", "-Pn", "-n", "--open", "--top-ports", "25",
                 "--version-intensity", "2", "--script",
                 "snmp-info,nbstat,ipmi-version,ntp-info", "-oX", str(xml),
                 "-iL", str(ctx.raw / "hosts.txt")] + ctx.nmap_priv,
                logfile=ctx.toollog, privileged=True)
            parse_into(st, xml, scope)
