"""Stage 4: find web services on every open port (httpx)."""
from __future__ import annotations

import json
from urllib.parse import urlsplit

from ..profiles import NON_WEB_PORTS
from ..runner import have, log, run


def _is_web_candidate(p: dict) -> bool:
    svc = (p.get("service") or "").lower()
    if any(k in svc for k in ("http", "ssl", "https", "www", "web", "proxy")):
        return True
    if p["port"] in NON_WEB_PORTS:
        return False
    return svc in ("", "unknown", "tcpwrapped") or p["port"] >= 1024


def run_stage(ctx) -> None:
    st, scope = ctx.state, ctx.scope
    if not have("httpx"):
        log("httpx not installed: web probing skipped (nuclei gets http://ip:port guesses)", "warn")
        for ip, p in st.open_ports("tcp"):
            if "http" in (p.get("service") or ""):
                scheme = "https" if p.get("tunnel") == "ssl" or "https" in p["service"] else "http"
                st.host(ip)["web"].append({"url": f"{scheme}://{ip}:{p['port']}"})
        return
    inputs = sorted({f"{ip}:{p['port']}" for ip, p in st.open_ports("tcp") if _is_web_candidate(p)})
    if not inputs:
        log("no web candidate ports")
        return
    (ctx.raw / "web-candidates.txt").write_text("\n".join(inputs) + "\n")
    log(f"httpx on {len(inputs)} host:port candidates")
    for h in st.hosts.values():
        h["web"] = []

    def on_line(line):
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            return
        url = r.get("url")
        if not url:
            return
        host = urlsplit(url).hostname or ""
        if not scope.allows(host):
            return
        st.host(host)["web"].append({
            "url": url, "status": r.get("status_code"), "title": r.get("title"),
            "server": r.get("webserver"), "tech": r.get("tech") or [],
            "content_length": r.get("content_length"),
            "tls": (r.get("tls") or {}).get("subject_cn"),
        })

    run(["httpx", "-l", str(ctx.raw / "web-candidates.txt"), "-j", "-silent", "-nc",
         "-sc", "-title", "-server", "-td", "-tls-grab", "-timeout", "8", "-retries", "1",
         "-threads", "50", "-duc"],
        logfile=ctx.toollog, stdout_file=ctx.raw / "httpx.jsonl", on_line=on_line)
    n = sum(len(h["web"]) for h in st.hosts.values())
    log(f"{n} web services", "ok")
