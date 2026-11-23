"""lanrecce command line.

  lanrecce scan  10.0.0.0/24 [--profile quick|standard|full] [...]
  lanrecce scan  --auto                  # every LAN subnet this machine is on
  lanrecce scan  --resume runs/<dir>     # continue an interrupted run
  lanrecce report runs/<dir> [--baseline runs/<older>]
  lanrecce doctor                        # what's installed / privileged
  lanrecce subnets                       # what --auto would pick
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from types import SimpleNamespace

from . import __version__, intel, report
from .model import State
from .profiles import PROFILES
from .runner import chown_to_sudo_user, has_cap_net_raw, have, is_root, log, sudo_user, which
from .scope import Scope, ScopeError, local_subnets, own_addresses
from .stages import checks, discovery, nuclei, ports, services, web

STAGES = [
    ("discovery", discovery.run_stage),
    ("ports", ports.run_stage),
    ("services", services.run_stage),
    ("web", web.run_stage),
    ("nuclei", nuclei.run_stage),
    ("checks", checks.run_stage),
]
CONFIRM_ABOVE = 1024  # addresses


def _parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="lanrecce", description="Local network assessment: "
                                 "nmap + naabu + httpx + nuclei, with an HTML report.")
    ap.add_argument("--version", action="version", version=f"lanrecce {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="run an assessment")
    s.add_argument("targets", nargs="*", help="CIDRs, IPs or ranges (10.0.0.1-50), or @file")
    s.add_argument("--auto", action="store_true", help="scan the LAN subnets this machine is on")
    s.add_argument("--include-virtual", action="store_true",
                   help="with --auto, also include docker/libvirt/VPN interfaces")
    s.add_argument("-x", "--exclude", action="append", default=[], help="CIDR/IP/range to skip (repeatable, or @file)")
    s.add_argument("-p", "--profile", choices=PROFILES, default="standard")
    s.add_argument("-o", "--out", default="runs", help="parent dir for run output (default ./runs)")
    s.add_argument("--name", help="run name (default: timestamp)")
    s.add_argument("--resume", metavar="RUNDIR", help="continue an interrupted run")
    s.add_argument("--baseline", metavar="RUNDIR", help="previous run to diff against (new/fixed)")
    s.add_argument("--only", help="comma list of stages to run: " + ",".join(n for n, _ in STAGES))
    s.add_argument("--skip", default="", help="comma list of stages to skip")
    s.add_argument("--ports", help="override port spec: 100 | 1000 | full | 22,80,8000-8100")
    s.add_argument("--nmap-ports", action="store_true", help="use nmap instead of naabu for port scan")
    s.add_argument("--rate", type=int, default=1000, help="port-scan packets/sec (default 1000)")
    s.add_argument("--workers", type=int, default=6, help="parallel nmap -sV hosts (default 6)")
    s.add_argument("--no-discovery", action="store_true", help="treat every address as up (-Pn)")
    s.add_argument("--no-dns", action="store_true", help="skip reverse DNS")
    s.add_argument("--no-udp", action="store_true", help="skip the UDP scan in the full profile")
    s.add_argument("--no-vulners", action="store_true", help="skip nmap vulners CVE matching")
    s.add_argument("--min-cvss", type=float, help="vulners: report CVEs at/above this CVSS individually")
    s.add_argument("--severity", help="nuclei severities, e.g. critical,high")
    s.add_argument("--default-logins", action="store_true",
                   help="run nuclei default-login templates (attempts logins; can lock accounts)")
    s.add_argument("--interactsh", action="store_true",
                   help="allow nuclei out-of-band callbacks to public oast.* servers")
    s.add_argument("--nuclei-templates", help="nuclei templates dir (-ud)")
    s.add_argument("--nuclei-args", help="extra raw nuclei args, quoted")
    s.add_argument("--nuclei-timeout", type=int, help="max seconds per nuclei pass")
    s.add_argument("--offline", action="store_true", help="no KEV/EPSS lookups")
    s.add_argument("--allow-public", action="store_true", help="permit non-private targets (authorised engagements only)")
    s.add_argument("-y", "--yes", action="store_true", help="don't ask for confirmation")

    r = sub.add_parser("report", help="rebuild the report for a run")
    r.add_argument("rundir")
    r.add_argument("--baseline", metavar="RUNDIR")

    w = sub.add_parser("serve", help="web console: launch scans, watch them, browse/export results")
    w.add_argument("--host", default=os.environ.get("LANRECCE_BIND", "127.0.0.1"),
                   help="listen address (default 127.0.0.1; others need a token)")
    w.add_argument("--port", type=int, default=int(os.environ.get("LANRECCE_PORT", "8088")))
    w.add_argument("--runs", default=os.environ.get("LANRECCE_RUNS", "runs"), help="runs directory")
    w.add_argument("--token", help="access token (or LANRECCE_TOKEN)")
    w.add_argument("--allow-public", action="store_true",
                   default=os.environ.get("LANRECCE_ALLOW_PUBLIC") == "1",
                   help="let the UI scan non-private ranges")
    w.add_argument("--insecure-no-auth", action="store_true",
                   help="listen on a non-loopback address without a token (don't)")

    sub.add_parser("doctor", help="check tools, templates and privileges")
    sub.add_parser("subnets", help="show subnets --auto would scan")
    return ap


def _expand(items: list[str]) -> list[str]:
    out = []
    for i in items:
        if i.startswith("@"):
            out += [l.split("#")[0].strip() for l in Path(i[1:]).read_text().splitlines()]
        else:
            out += [x for x in i.replace(",", " ").split()]
    return [x for x in out if x]


def cmd_doctor() -> int:
    ok = True
    print(f"lanrecce {__version__}  python {sys.version.split()[0]}")
    print(f"running as {'root' + (' (sudo from ' + sudo_user().pw_name + ')' if sudo_user() else '') if is_root() else 'unprivileged user'}")
    for tool, need in [("nmap", True), ("naabu", False), ("httpx", False), ("nuclei", True)]:
        p = which(tool)
        cap = " +cap_net_raw" if p and has_cap_net_raw(p) else ""
        print(f"  {'ok ' if p else ('MISSING' if need else 'missing')} {tool:7} {p or ''}{cap}")
        ok &= bool(p) or not need
    if have("nmap"):
        import subprocess
        v = subprocess.run([which("nmap"), "--script-help", "vulners"], capture_output=True, text=True)
        print(f"  {'ok ' if 'vulners' in v.stdout else 'missing'} vulners.nse")
    home = Path(sudo_user().pw_dir) if sudo_user() else Path.home()
    tdir = home / "nuclei-templates"
    print(f"  {'ok ' if tdir.exists() else 'missing'} nuclei templates  {tdir}")
    if not is_root() and not has_cap_net_raw(which("nmap") or ""):
        print("\nnot privileged: no ARP discovery, SYN scans, OS detection or UDP.\n"
              "  run with sudo, or see install.sh --setcap")
    return 0 if ok else 1


def cmd_subnets() -> int:
    for n in local_subnets(include_virtual=True):
        flag = "  (virtual, needs --include-virtual)" if n["virtual"] else ""
        print(f"{n['cidr']:20} {n['iface']:16} {n['addr']}{flag}")
    return 0


def cmd_report(a) -> int:
    rundir = Path(a.rundir)
    st = State.load(rundir)
    diff = report.diff_against(st, Path(a.baseline)) if a.baseline else None
    p = report.write_all(st, rundir, diff)
    print(p)
    return 0


def cmd_scan(a) -> int:
    if not have("nmap"):
        log("nmap is required (sudo apt install nmap)", "err")
        return 2

    # ---- resume or new run ----------------------------------------------
    if a.resume:
        rundir = Path(a.resume)
        st = State.load(rundir)
        saved = st.meta["args"]
        defaults = vars(_parser().parse_args(["scan"]))
        for k, v in saved.items():
            # restore the original run's settings, unless overridden on this command line
            if k not in ("resume", "yes", "only", "skip", "baseline") and \
                    getattr(a, k, None) == defaults.get(k):
                setattr(a, k, v)
        scope = Scope.build(st.meta["scope"]["include"], st.meta["scope"]["exclude"], True)
        log(f"resuming {rundir}")
    else:
        targets = _expand(a.targets)
        if a.auto:
            nets = local_subnets(a.include_virtual)
            if not nets:
                log("--auto found no LAN subnets (try `lanrecce subnets`)", "err")
                return 2
            targets += [n["cidr"] for n in nets]
            log("auto scope: " + ", ".join(f"{n['cidr']} ({n['iface']})" for n in nets))
        if not targets:
            log("give targets (e.g. 192.168.1.0/24) or --auto", "err")
            return 2
        try:
            scope = Scope.build(targets, _expand(a.exclude), a.allow_public)
        except ScopeError as e:
            log(str(e), "err")
            return 2
        name = a.name or time.strftime("%Y%m%d-%H%M%S")
        rundir = Path(a.out) / name
        # the web UI pre-creates the run dir (for console.log); refuse only a used one
        if (rundir / "state.json").exists():
            log(f"{rundir} already holds a run (use --resume or another --name)", "err")
            return 2
        rundir.mkdir(parents=True, exist_ok=True)
        st = State(rundir)
        st.meta.update(scope=scope.to_json(), profile=a.profile, version=__version__,
                       args={k: v for k, v in vars(a).items() if k != "cmd"})

    raw = rundir / "raw"
    raw.mkdir(exist_ok=True)
    nmap_cap = has_cap_net_raw(which("nmap"))
    raw_ok = is_root() or nmap_cap
    st.meta["privileged"] = raw_ok

    print(file=sys.stderr)
    log(f"scope    {', '.join(scope.to_json()['include'])}"
        + (f"  (excluding {', '.join(scope.to_json()['exclude'])})" if scope.exclude else ""))
    log(f"size     {scope.size()} addresses   profile={a.profile}: {PROFILES[a.profile]['desc']}")
    log(f"output   {rundir}")
    log(f"mode     {'privileged' if raw_ok else 'unprivileged (sudo recommended)'}"
        + ("" if a.interactsh else ", interactsh off") + ("" if a.default_logins else ", no login attempts"))
    if not a.yes and not a.resume and sys.stdin.isatty():
        warn = " This is a large range." if scope.size() > CONFIRM_ABOVE else ""
        ans = input(f"Only scan networks you own or are authorised to test.{warn} Proceed? [y/N] ")
        if ans.strip().lower() not in ("y", "yes"):
            log("aborted", "warn")
            import shutil
            if not a.resume:
                shutil.rmtree(rundir, ignore_errors=True)
            return 1
    elif not a.yes and not a.resume and scope.size() > CONFIRM_ABOVE:
        log(f"refusing {scope.size()} addresses non-interactively without --yes", "err")
        import shutil
        shutil.rmtree(rundir, ignore_errors=True)
        return 2

    ctx = SimpleNamespace(
        state=st, scope=scope, args=a, profile=PROFILES[a.profile], raw=raw,
        toollog=rundir / "tools.log", raw_ok=raw_ok,
        nmap_priv=["--privileged"] if (nmap_cap and not is_root()) else [],
        own_ips=own_addresses())

    only = set(a.only.split(",")) if a.only else None
    skip = set(filter(None, a.skip.split(",")))
    t_all = time.time()
    try:
        for name, fn in STAGES:
            if (only and name not in only) or name in skip:
                continue
            if a.resume and st.stage_done(name) and not only:
                log(f"{name}: already done, skipping")
                continue
            log(f"{name}", "stage")
            t0 = time.time()
            st.mark(name, "running")
            fn(ctx)
            st.mark(name, "done", seconds=round(time.time() - t0, 1))
        log("intel", "stage")
        intel.enrich(st, a.offline)
        st.meta["finished"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        st.meta["seconds"] = round(time.time() - t_all, 1)
    except KeyboardInterrupt:
        log(f"interrupted. resume with: lanrecce scan --resume {rundir}", "warn")
    finally:
        st.save()
        diff = None
        if a.baseline:
            try:
                diff = report.diff_against(st, Path(a.baseline))
            except Exception as e:
                log(f"baseline diff failed: {e}", "warn")
        path = report.write_all(st, rundir, diff)
        chown_to_sudo_user(rundir)
        if a.out == "runs":
            chown_to_sudo_user(Path("runs"))

    sev = {}
    for f in st.findings.values():
        sev[f.severity] = sev.get(f.severity, 0) + 1
    print(file=sys.stderr)
    log(f"{len(st.hosts)} hosts, {sum(len(h['ports']) for h in st.hosts.values())} open ports, "
        f"findings: " + ", ".join(f"{k}={sev.get(k, 0)}" for k in ("critical", "high", "medium", "low", "info")), "ok")
    log(f"report   {path.resolve()}", "ok")
    return 0


def main(argv=None) -> int:
    a = _parser().parse_args(argv)
    if a.cmd == "doctor":
        return cmd_doctor()
    if a.cmd == "subnets":
        return cmd_subnets()
    if a.cmd == "report":
        return cmd_report(a)
    if a.cmd == "serve":
        from .web import serve
        return serve(a)
    return cmd_scan(a)
