"""Running external tools.

Only nmap and naabu benefit from root (ARP discovery, SYN scans, UDP, OS
detection). When lanrecce runs under sudo, every other tool (httpx, nuclei) is
dropped back to the invoking user, so nuclei uses that user's template dir and
nothing in $HOME ends up root-owned.
"""
from __future__ import annotations

import os
import pwd
import shutil
import subprocess
import sys
import time
from pathlib import Path

COLOR = sys.stderr.isatty() and not os.environ.get("NO_COLOR")


def _c(code: str, s: str) -> str:
    return f"\033[{code}m{s}\033[0m" if COLOR else s


def log(msg: str, level: str = "info") -> None:
    tag = {"info": _c("36", "[*]"), "ok": _c("32", "[+]"), "warn": _c("33", "[!]"),
           "err": _c("31", "[x]"), "stage": _c("1;35", "==>")}[level]
    print(f"{tag} {msg}", file=sys.stderr, flush=True)


def is_root() -> bool:
    return os.geteuid() == 0


def sudo_user() -> pwd.struct_passwd | None:
    """The real user behind sudo, if we are root via sudo."""
    if not is_root():
        return None
    uid = os.environ.get("SUDO_UID")
    if not uid:
        return None
    try:
        return pwd.getpwuid(int(uid))
    except (KeyError, ValueError):
        return None


def _user_paths() -> list[str]:
    """Where Go tools usually live, for both us and the sudo user."""
    homes = [Path.home()]
    su = sudo_user()
    if su:
        homes.insert(0, Path(su.pw_dir))
    extra = []
    for h in homes:
        extra += [str(h / "go/bin"), str(h / ".pdtm/go/bin"), str(h / ".local/bin")]
    return extra + ["/usr/local/go/bin", "/usr/local/bin"]


def which(tool: str) -> str | None:
    path = os.pathsep.join([os.environ.get("PATH", "")] + _user_paths())
    return shutil.which(tool, path=path)


def have(tool: str) -> bool:
    return which(tool) is not None


def has_cap_net_raw(binary: str) -> bool:
    """True if a binary was granted cap_net_raw (setcap), so it can do raw scans unprivileged."""
    if not binary or not have("getcap"):
        return False
    out = subprocess.run([which("getcap"), binary], capture_output=True, text=True).stdout
    return "cap_net_raw" in out


def run(cmd: list[str], *, logfile: Path | None = None, stdout_file: Path | None = None,
        input_text: str | None = None, privileged: bool = False, timeout: int | None = None,
        on_line=None) -> subprocess.CompletedProcess:
    """Run a tool. stdout goes to stdout_file (or is returned), stderr to logfile.

    privileged=False drops to the sudo user when we're root via sudo.
    on_line(str) is called for each stdout line as it arrives (streaming).
    """
    exe = which(cmd[0])
    if not exe:
        raise FileNotFoundError(cmd[0])
    cmd = [exe] + cmd[1:]
    kwargs: dict = {}
    su = sudo_user()
    env = dict(os.environ)
    env["PATH"] = os.pathsep.join([env.get("PATH", "")] + _user_paths())
    if su and not privileged:
        kwargs.update(user=su.pw_uid, group=su.pw_gid, extra_groups=[])
        env.update(HOME=su.pw_dir, USER=su.pw_name, LOGNAME=su.pw_name)
    errf = open(logfile, "ab") if logfile else subprocess.DEVNULL
    if logfile:
        errf.write(f"\n$ {' '.join(cmd)}\n".encode())
        errf.flush()
    t0 = time.time()
    try:
        proc = subprocess.Popen(
            cmd, stdin=subprocess.PIPE if input_text is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=errf, env=env, text=True, bufsize=1, **kwargs)
        if input_text is not None:
            proc.stdin.write(input_text)
            proc.stdin.close()
        out_lines = []
        outf = open(stdout_file, "w") if stdout_file else None
        deadline = t0 + timeout if timeout else None
        for line in proc.stdout:
            out_lines.append(line)
            if outf:
                outf.write(line)
                outf.flush()
            if on_line:
                on_line(line)
            if deadline and time.time() > deadline:
                proc.kill()
                log(f"{cmd[0]} hit timeout ({timeout}s); keeping partial output", "warn")
                break
        proc.wait()
        if outf:
            outf.close()
    finally:
        if logfile:
            errf.write(f"# exit after {time.time() - t0:.1f}s\n".encode())
            errf.close()
    return subprocess.CompletedProcess(cmd, proc.returncode, "".join(out_lines), "")


def result_owner() -> tuple[int, int] | None:
    """Who should own the output: the sudo user, or LANRECCE_CHOWN=uid:gid (Docker)."""
    su = sudo_user()
    if su:
        return su.pw_uid, su.pw_gid
    spec = os.environ.get("LANRECCE_CHOWN", "")
    if is_root() and ":" in spec:
        try:
            uid, gid = (int(x) for x in spec.split(":", 1))
            return uid, gid
        except ValueError:
            pass
    return None


def chown_to_sudo_user(path: Path) -> None:
    """Hand the run directory back to the real user after a sudo/Docker run."""
    owner = result_owner()
    if not owner:
        return
    for p in [path, *path.rglob("*")]:
        try:
            os.chown(p, *owner)
        except OSError:
            pass
