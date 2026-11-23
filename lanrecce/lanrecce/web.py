"""lanrecce web console: `lanrecce serve`.

A scan launcher + results browser, stdlib only (no database: every run is its
directory under runs/, exactly what the CLI writes). Scans run as child
processes of `python -m lanrecce scan ...`, so the CLI and the UI behave
identically and a run started in the UI can be resumed from the shell.

Security model (this endpoint can start network scans):
  * binds 127.0.0.1 by default; binding anything else requires a token
    (LANRECCE_TOKEN / --token), or an explicit --insecure-no-auth
  * mutating requests need the `X-Lanrecce: 1` header: a custom header can't
    be sent cross-site without a CORS preflight, which this server never grants
  * Host-header allowlist when there's no token (blocks DNS rebinding)
  * reports are served with CSP `sandbox`, so hostile text from scanned devices
    can't reach the API even if the report renderer had a bug
  * scope is validated server-side with the same Scope rules as the CLI
"""
from __future__ import annotations

import hmac
import io
import ipaddress
import json
import os
import re
import secrets
import signal
import socket
import subprocess
import sys
import threading
import time
import zipfile
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from . import __version__
from .profiles import PROFILES
from .runner import has_cap_net_raw, have, is_root, log, result_owner, which
from .scope import Scope, ScopeError, local_subnets

STATIC = Path(__file__).parent / "static"
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
STAGES = ["discovery", "ports", "services", "web", "nuclei", "checks"]
DOWNLOADS = {
    "report.html": "text/html; charset=utf-8",
    "findings.json": "application/json",
    "findings.csv": "text/csv; charset=utf-8",
    "findings.nuclei.jsonl": "application/x-ndjson",
    "hosts.json": "application/json",
    "dossier-findings.nessus": "application/xml",
    "dossier-hosts.xml": "application/xml",
    "console.log": "text/plain; charset=utf-8",
    "tools.log": "text/plain; charset=utf-8",
}
REPORT_CSP = ("sandbox allow-scripts allow-popups allow-popups-to-escape-sandbox; "
              "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:")
APP_CSP = ("default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; "
           "img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
MAX_ADDRESSES = 65536


class Scans:
    """Tracks scan child processes. One scan at a time: they compete for the
    same NIC and nuclei rate limit, and it keeps the box predictable."""

    def __init__(self, runs: Path):
        self.runs = runs
        self.lock = threading.Lock()
        self.procs: dict[str, subprocess.Popen] = {}

    def running(self) -> str | None:
        with self.lock:
            for name, p in list(self.procs.items()):
                if p.poll() is None:
                    return name
                del self.procs[name]
        # a scan started by a previous server process?
        for d in self.runs.iterdir() if self.runs.exists() else []:
            if _pid_alive(d):
                return d.name
        return None

    def start(self, name: str, argv: list[str], resume: bool = False) -> None:
        rundir = self.runs / name
        rundir.mkdir(parents=True, exist_ok=True)
        owner = result_owner()
        logf = open(rundir / "console.log", "ab")
        logf.write(f"\n# {time.strftime('%F %T')} lanrecce {' '.join(argv)}\n".encode())
        logf.flush()
        env = dict(os.environ, NO_COLOR="1", PYTHONUNBUFFERED="1",
                   PYTHONPATH=str(Path(__file__).resolve().parent.parent))
        p = subprocess.Popen([sys.executable, "-m", "lanrecce", *argv], stdout=logf,
                             stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, env=env,
                             start_new_session=True)
        logf.close()
        (rundir / ".pid").write_text(str(p.pid))
        if owner:
            for f in (rundir, rundir / "console.log", rundir / ".pid"):
                try:
                    os.chown(f, *owner)
                except OSError:
                    pass
        with self.lock:
            self.procs[name] = p
        threading.Thread(target=self._reap, args=(name, p), daemon=True).start()

    def _reap(self, name, p):
        p.wait()
        try:
            (self.runs / name / ".pid").unlink()
        except OSError:
            pass

    def stop(self, name: str) -> bool:
        pid = _read_pid(self.runs / name)
        if not pid:
            return False
        try:
            os.killpg(pid, signal.SIGINT)  # scan saves state + report, resumable
            return True
        except ProcessLookupError:
            return False


def _read_pid(d: Path) -> int | None:
    try:
        return int((d / ".pid").read_text().strip())
    except (OSError, ValueError):
        return None


def _pid_alive(d: Path) -> bool:
    pid = _read_pid(d)
    if not pid:
        return False
    try:
        cmd = Path(f"/proc/{pid}/cmdline").read_bytes()
    except OSError:
        return False
    return b"lanrecce" in cmd


def _load_state(d: Path) -> dict | None:
    try:
        return json.loads((d / "state.json").read_text())
    except (OSError, ValueError):
        return None


def _status(d: Path, st: dict | None) -> str:
    if _pid_alive(d):
        return "running"
    if st is None:
        return "failed" if (d / "console.log").exists() else "empty"
    if st["meta"].get("finished"):
        return "done"
    return "stopped"


def _summary(d: Path) -> dict:
    st = _load_state(d)
    out = {"name": d.name, "status": _status(d, st), "mtime": d.stat().st_mtime}
    if st:
        m = st["meta"]
        sev = {}
        for f in st["findings"]:
            sev[f["severity"]] = sev.get(f["severity"], 0) + 1
        out.update(started=m.get("started"), finished=m.get("finished"),
                   profile=m.get("profile"), scope=m.get("scope"),
                   hosts=len(st["hosts"]), severity=sev,
                   stage=next((k for k, v in m.get("stages", {}).items()
                               if v.get("status") == "running"), None))
    return out


def tool_info() -> dict:
    return {
        "version": __version__,
        "privileged": is_root() or has_cap_net_raw(which("nmap") or ""),
        "tools": {t: bool(have(t)) for t in ("nmap", "naabu", "httpx", "nuclei")},
        "profiles": {k: v["desc"] for k, v in PROFILES.items()},
        "subnets": local_subnets(include_virtual=True),
        "dossier_url": os.environ.get("LANRECCE_DOSSIER_URL", ""),
    }


def build_scan_argv(body: dict, name: str, runs: Path, allow_public: bool) -> list[str]:
    """Validate a scan request and turn it into CLI args. Raises ValueError."""
    def items(v):
        if isinstance(v, str):
            v = re.split(r"[\s,]+", v)
        return [str(x).strip() for x in (v or []) if str(x).strip()]

    targets, excludes = items(body.get("targets")), items(body.get("exclude"))
    if not targets:
        raise ValueError("no targets")
    for t in targets + excludes:
        if t.startswith("@") or t.startswith("-"):
            raise ValueError(f"invalid target {t!r}")
    try:
        scope = Scope.build(targets, excludes, allow_public)
    except ScopeError as e:
        raise ValueError(str(e)) from None
    if scope.size() > MAX_ADDRESSES:
        raise ValueError(f"{scope.size()} addresses is more than the web UI allows "
                         f"({MAX_ADDRESSES}); split the range or use the CLI")
    profile = body.get("profile") or "standard"
    if profile not in PROFILES:
        raise ValueError("unknown profile")
    argv = ["scan", *targets, "--yes", "--name", name, "-o", str(runs), "-p", profile]
    for x in excludes:
        argv += ["-x", x]
    if allow_public:
        argv.append("--allow-public")
    opts = body.get("options") or {}
    for key, flag in (("default_logins", "--default-logins"), ("interactsh", "--interactsh"),
                      ("offline", "--offline"), ("no_udp", "--no-udp"),
                      ("no_discovery", "--no-discovery"), ("no_dns", "--no-dns")):
        if opts.get(key) is True:
            argv.append(flag)
    ports = str(opts.get("ports") or "").strip()
    if ports:
        if not re.fullmatch(r"(100|1000|full|[0-9,\-]{1,2000})", ports):
            raise ValueError("ports must be 100, 1000, full or a list like 22,80,8000-8100")
        argv += ["--ports", ports]
    sev = str(opts.get("severity") or "").strip()
    if sev:
        if not re.fullmatch(r"(critical|high|medium|low|info)(,(critical|high|medium|low|info))*", sev):
            raise ValueError("bad severity list")
        argv += ["--severity", sev]
    base = str(body.get("baseline") or "").strip()
    if base:
        if not NAME_RE.match(base) or not (runs / base / "state.json").exists():
            raise ValueError("baseline run not found")
        argv += ["--baseline", str(runs / base)]
    return argv


def dossier_zip(d: Path) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for f in ("dossier-findings.nessus", "dossier-hosts.xml"):
            if (d / f).exists():
                z.write(d / f, f"{d.name}-{f}")
    return buf.getvalue()


class App:
    def __init__(self, runs: Path, token: str | None, allowed_hosts: set[str],
                 allow_public: bool):
        self.runs = runs
        self.token = token
        self.allowed_hosts = allowed_hosts
        self.allow_public = allow_public
        self.scans = Scans(runs)


def make_handler(app: App):
    class H(BaseHTTPRequestHandler):
        server_version = f"lanrecce/{__version__}"
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):  # quieter access log
            if os.environ.get("LANRECCE_ACCESS_LOG"):
                super().log_message(fmt, *args)

        # ---- plumbing ------------------------------------------------------
        def _send(self, code, body=b"", ctype="application/json", headers=None):
            if isinstance(body, (dict, list)):
                body = json.dumps(body, default=str).encode()
            elif isinstance(body, str):
                body = body.encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Cache-Control", "no-store")
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _err(self, code, msg):
            self._send(code, {"error": msg})

        def _host_ok(self) -> bool:
            if app.token:
                return True
            host = (self.headers.get("Host") or "").lower()
            host = host[1:].split("]")[0] if host.startswith("[") else host.rsplit(":", 1)[0]
            return host in app.allowed_hosts

        def _authed(self) -> bool:
            if not app.token:
                return True
            auth = self.headers.get("Authorization", "")
            if auth.startswith("Bearer ") and hmac.compare_digest(auth[7:], app.token):
                return True
            c = SimpleCookie(self.headers.get("Cookie", ""))
            return "lr_token" in c and hmac.compare_digest(c["lr_token"].value, app.token)

        def _body(self) -> dict:
            n = int(self.headers.get("Content-Length") or 0)
            if n > 1_000_000:
                raise ValueError("body too large")
            raw = self.rfile.read(n) if n else b""
            ctype = self.headers.get("Content-Type", "")
            if "application/json" in ctype:
                return json.loads(raw or b"{}")
            return {k: v[0] for k, v in parse_qs(raw.decode()).items()}

        def _run_dir(self, name) -> Path | None:
            if not NAME_RE.match(name or ""):
                return None
            d = app.runs / name
            return d if d.is_dir() else None

        def _gate(self, mutating: bool) -> bool:
            if not self._host_ok():
                self._err(HTTPStatus.MISDIRECTED_REQUEST, "host not allowed")
                return False
            path = urlsplit(self.path).path
            if path in ("/login", "/api/health") or path.startswith("/static/"):
                return True
            if not self._authed():
                if path.startswith("/api/") or mutating:
                    self._err(HTTPStatus.UNAUTHORIZED, "login required")
                else:
                    self._send(HTTPStatus.SEE_OTHER, b"", headers={"Location": "/login"})
                return False
            if mutating and self.headers.get("X-Lanrecce") != "1":
                self._err(HTTPStatus.FORBIDDEN, "missing X-Lanrecce header")
                return False
            return True

        # ---- routes ----------------------------------------------------------
        def do_HEAD(self):
            self.do_GET()

        def do_GET(self):
            if not self._gate(False):
                return
            u = urlsplit(self.path)
            parts = [p for p in u.path.split("/") if p]
            q = parse_qs(u.query)
            try:
                if u.path == "/":
                    return self._static("index.html")
                if parts[:1] == ["static"] and len(parts) == 2:
                    return self._static(parts[1])
                if u.path == "/login":
                    return self._static("login.html")
                if u.path == "/api/health":
                    return self._send(200, {"ok": True, "version": __version__})
                if u.path == "/api/info":
                    info = tool_info()
                    info["running"] = app.scans.running()
                    info["auth"] = bool(app.token)
                    info["allow_public"] = app.allow_public
                    return self._send(200, info)
                if u.path == "/api/runs":
                    runs = [_summary(d) for d in app.runs.iterdir()
                            if d.is_dir() and NAME_RE.match(d.name)] if app.runs.exists() else []
                    runs.sort(key=lambda r: r["mtime"], reverse=True)
                    return self._send(200, runs)
                if parts[:2] == ["api", "runs"] and len(parts) >= 3:
                    d = self._run_dir(parts[2])
                    if not d:
                        return self._err(404, "no such run")
                    if len(parts) == 3:
                        st = _load_state(d) or {"meta": {}, "hosts": {}, "findings": []}
                        st["status"] = _status(d, _load_state(d))
                        st["name"] = d.name
                        st["files"] = [f for f in DOWNLOADS if (d / f).exists()]
                        return self._send(200, st)
                    if parts[3] == "log":
                        off = int((q.get("offset") or ["0"])[0])
                        p = d / "console.log"
                        size = p.stat().st_size if p.exists() else 0
                        if off > size:
                            off = 0
                        with open(p, "rb") if p.exists() else io.BytesIO() as fh:
                            fh.seek(off)
                            chunk = fh.read(256_000)
                        return self._send(200, {"offset": off + len(chunk),
                                                "text": chunk.decode("utf-8", "replace"),
                                                "running": _pid_alive(d)})
                    if parts[3] == "dossier.zip":
                        if not (d / "dossier-findings.nessus").exists():
                            return self._err(404, "no Dossier export yet")
                        return self._send(200, dossier_zip(d), "application/zip", {
                            "Content-Disposition": f'attachment; filename="{d.name}-dossier.zip"'})
                if parts[:1] == ["runs"] and len(parts) == 3:
                    d = self._run_dir(parts[1])
                    fname = parts[2]
                    if not d or fname not in DOWNLOADS or not (d / fname).is_file():
                        return self._err(404, "not found")
                    hdr = {}
                    if fname == "report.html":
                        hdr["Content-Security-Policy"] = REPORT_CSP
                    else:
                        hdr["Content-Disposition"] = (
                            f'{"inline" if fname.endswith(".log") else "attachment"}; '
                            f'filename="{d.name}-{fname}"')
                    return self._send(200, (d / fname).read_bytes(), DOWNLOADS[fname], hdr)
                return self._err(404, "not found")
            except (BrokenPipeError, ConnectionResetError):
                pass

        def do_POST(self):
            u = urlsplit(self.path)
            if u.path == "/login":
                return self._login()
            if not self._gate(True):
                return
            parts = [p for p in u.path.split("/") if p]
            try:
                body = self._body()
            except ValueError as e:
                return self._err(400, str(e))
            if u.path == "/api/scans":
                busy = app.scans.running()
                if busy:
                    return self._err(409, f"scan '{busy}' is still running")
                name = (body.get("name") or "").strip() or time.strftime("%Y%m%d-%H%M%S")
                if not NAME_RE.match(name):
                    return self._err(400, "name: letters, digits, . _ - only (max 64)")
                if (app.runs / name / "state.json").exists():
                    return self._err(409, f"run '{name}' already exists")
                try:
                    argv = build_scan_argv(body, name, app.runs, app.allow_public)
                except ValueError as e:
                    return self._err(400, str(e))
                app.runs.mkdir(parents=True, exist_ok=True)
                app.scans.start(name, argv)
                log(f"web: started scan {name}: {' '.join(argv[1:])}")
                return self._send(201, {"name": name})
            if parts[:2] == ["api", "runs"] and len(parts) == 4:
                d = self._run_dir(parts[2])
                if not d:
                    return self._err(404, "no such run")
                if parts[3] == "stop":
                    ok = app.scans.stop(d.name)
                    return self._send(200 if ok else 409, {"stopped": ok})
                if parts[3] == "resume":
                    busy = app.scans.running()
                    if busy:
                        return self._err(409, f"scan '{busy}' is still running")
                    if not (d / "state.json").exists():
                        return self._err(409, "nothing to resume")
                    app.scans.start(d.name, ["scan", "--resume", str(d), "--yes"])
                    return self._send(200, {"resumed": True})
            return self._err(404, "not found")

        def do_DELETE(self):
            if not self._gate(True):
                return
            parts = [p for p in urlsplit(self.path).path.split("/") if p]
            if parts[:2] == ["api", "runs"] and len(parts) == 3:
                d = self._run_dir(parts[2])
                if not d:
                    return self._err(404, "no such run")
                if _pid_alive(d):
                    return self._err(409, "stop the scan first")
                import shutil
                shutil.rmtree(d)
                return self._send(200, {"deleted": d.name})
            return self._err(404, "not found")

        def _login(self):
            if not self._host_ok():
                return self._err(HTTPStatus.MISDIRECTED_REQUEST, "host not allowed")
            try:
                body = self._body()
            except ValueError:
                body = {}
            tok = str(body.get("token") or "")
            if app.token and hmac.compare_digest(tok, app.token):
                return self._send(HTTPStatus.SEE_OTHER, b"", headers={
                    "Location": "/",
                    "Set-Cookie": f"lr_token={app.token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=2592000"})
            time.sleep(1)
            return self._send(HTTPStatus.SEE_OTHER, b"", headers={"Location": "/login?bad=1"})

        def _static(self, fname):
            if not re.fullmatch(r"[a-z0-9_-]+\.(html|js|css|svg)", fname):
                return self._err(404, "not found")
            p = STATIC / fname
            if not p.is_file():
                return self._err(404, "not found")
            ctype = {"html": "text/html; charset=utf-8", "js": "text/javascript; charset=utf-8",
                     "css": "text/css; charset=utf-8", "svg": "image/svg+xml"}[fname.rsplit(".", 1)[1]]
            return self._send(200, p.read_bytes(), ctype, {"Content-Security-Policy": APP_CSP,
                                                           "X-Frame-Options": "DENY"})
    return H


def _is_loopback(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host == "localhost"


def serve(a) -> int:
    runs = Path(a.runs).resolve()
    runs.mkdir(parents=True, exist_ok=True)
    owner = result_owner()
    if owner:  # docker creates a missing bind-mount dir as root; hand it back
        try:
            os.chown(runs, *owner)
        except OSError:
            pass
    token = a.token or os.environ.get("LANRECCE_TOKEN") or None
    if not _is_loopback(a.host) and not token and not a.insecure_no_auth:
        log(f"refusing to listen on {a.host} without a token: anyone on the network could "
            "launch scans. Set LANRECCE_TOKEN (or --token), or bind 127.0.0.1.", "err")
        log(f"generated example: LANRECCE_TOKEN={secrets.token_urlsafe(24)}", "info")
        return 2
    allowed = {"localhost", "127.0.0.1", "::1", a.host.lower(), socket.gethostname().lower()}
    allowed |= {h.strip().lower() for h in os.environ.get("LANRECCE_ALLOWED_HOSTS", "").split(",") if h.strip()}
    app = App(runs, token, allowed, a.allow_public)
    httpd = ThreadingHTTPServer((a.host, a.port), make_handler(app))
    httpd.daemon_threads = True
    shown = "localhost" if _is_loopback(a.host) else a.host
    log(f"lanrecce web console on http://{shown}:{a.port}  (runs: {runs})", "ok")
    log("auth: " + ("token required" if token else "none (loopback only)"))
    if not (is_root() or has_cap_net_raw(which("nmap") or "")):
        log("not privileged: scans will use connect scans and no ARP discovery", "warn")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0
