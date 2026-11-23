#!/usr/bin/env python3
"""
qvpn-gui - a small Tkinter front-end for davegallant/vpngate.

Lists VPNGate relays (filter by country / ping / score, sort), connects to the
selected server in the background (vpngate connect -d), and shows status,
logs, public IP and lets you disconnect.

Needs: python3-tk, openvpn, go (only for the "Update vpngate" button).
"""

import csv
import io
import json
import os
import shutil
import subprocess
import threading
import tkinter as tk
import urllib.request
from tkinter import messagebox, simpledialog, ttk

GO_PKG = "github.com/davegallant/vpngate@latest"


def find_vpngate():
    for p in (shutil.which("vpngate"),
              os.path.expanduser("~/go/bin/vpngate"),
              "/usr/local/bin/vpngate"):
        if p and os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    return None


class QVPN(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("qvpn - VPNGate")
        self.geometry("820x560")
        self.minsize(700, 450)
        self.sudo_pw = None          # kept in memory only, never written
        self.vpngate = find_vpngate()
        self.servers = []

        self._build_ui()
        if not self.vpngate:
            self.log("vpngate not found - click 'Update vpngate' to install it.")
        else:
            self.log(f"Using {self.vpngate}")
            self.refresh_list()
            self.after(500, self.check_status)

    # ---------------------------------------------------------------- UI
    def _build_ui(self):
        top = ttk.Frame(self, padding=6)
        top.pack(fill="x")

        ttk.Label(top, text="Country").pack(side="left")
        self.country = tk.StringVar()
        ttk.Entry(top, textvariable=self.country, width=12).pack(side="left", padx=(2, 8))

        ttk.Label(top, text="Max ping").pack(side="left")
        self.max_ping = tk.StringVar()
        ttk.Entry(top, textvariable=self.max_ping, width=6).pack(side="left", padx=(2, 8))

        ttk.Label(top, text="Min score").pack(side="left")
        self.min_score = tk.StringVar()
        ttk.Entry(top, textvariable=self.min_score, width=9).pack(side="left", padx=(2, 8))

        ttk.Label(top, text="Sort").pack(side="left")
        self.sort = tk.StringVar(value="score")
        ttk.Combobox(top, textvariable=self.sort, width=9, state="readonly",
                     values=["none", "score", "ping", "country", "hostname"]
                     ).pack(side="left", padx=(2, 8))

        self.force_refresh = tk.BooleanVar()
        ttk.Checkbutton(top, text="Refresh cache", variable=self.force_refresh).pack(side="left")
        ttk.Button(top, text="List", command=self.refresh_list).pack(side="left", padx=6)

        # server table
        mid = ttk.Frame(self, padding=(6, 0))
        mid.pack(fill="both", expand=True)
        cols = ("host", "country", "ip", "ping", "score")
        self.tree = ttk.Treeview(mid, columns=cols, show="headings", selectmode="browse")
        for c, w in zip(cols, (220, 160, 130, 70, 100)):
            self.tree.heading(c, text=c.capitalize())
            self.tree.column(c, width=w, anchor="w")
        sb = ttk.Scrollbar(mid, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self.tree.bind("<Double-1>", lambda e: self.connect())

        # action bar
        act = ttk.Frame(self, padding=6)
        act.pack(fill="x")
        self.reconnect = tk.BooleanVar(value=True)
        ttk.Checkbutton(act, text="Auto-reconnect", variable=self.reconnect).pack(side="left")
        ttk.Button(act, text="Connect", command=self.connect).pack(side="left", padx=4)
        ttk.Button(act, text="Random", command=lambda: self.connect(random=True)).pack(side="left", padx=4)
        ttk.Button(act, text="Disconnect", command=self.disconnect).pack(side="left", padx=4)
        ttk.Button(act, text="Status", command=self.check_status).pack(side="left", padx=4)
        ttk.Button(act, text="Logs", command=self.show_logs).pack(side="left", padx=4)
        ttk.Button(act, text="My IP", command=self.show_ip).pack(side="left", padx=4)
        ttk.Button(act, text="Update vpngate", command=self.update_vpngate).pack(side="right")

        self.status = tk.StringVar(value="Status: unknown")
        ttk.Label(self, textvariable=self.status, padding=(6, 0), font=("TkDefaultFont", 10, "bold")).pack(fill="x")

        self.out = tk.Text(self, height=7, wrap="word", state="disabled",
                           bg="#111", fg="#9f9", insertbackground="#9f9")
        self.out.pack(fill="x", padx=6, pady=6)

    def log(self, msg):
        self.out.configure(state="normal")
        self.out.insert("end", msg.rstrip() + "\n")
        self.out.see("end")
        self.out.configure(state="disabled")

    def ui(self, fn, *a):
        """Run fn on the Tk thread."""
        self.after(0, fn, *a)

    # ---------------------------------------------------------- helpers
    def _filters(self):
        args = []
        if self.country.get().strip():
            args += ["--country", self.country.get().strip()]
        for flag, var in (("--max-ping", self.max_ping), ("--min-score", self.min_score)):
            v = var.get().strip()
            if v:
                if not v.isdigit():
                    raise ValueError(f"{flag} must be a number")
                args += [flag, v]
        return args

    def _ensure_sudo(self):
        """Get root once per session. Returns False if user cancelled."""
        if os.geteuid() == 0:
            return True
        if subprocess.run(["sudo", "-n", "true"], capture_output=True).returncode == 0:
            self.sudo_pw = ""   # passwordless / cached
            return True
        while True:
            pw = simpledialog.askstring("sudo", "Password for sudo (needed for openvpn):",
                                        show="*", parent=self)
            if pw is None:
                return False
            r = subprocess.run(["sudo", "-S", "-k", "-v"], input=pw + "\n",
                               capture_output=True, text=True)
            if r.returncode == 0:
                self.sudo_pw = pw
                return True
            messagebox.showerror("sudo", "Wrong password, try again.", parent=self)

    def _sudo_vpngate(self, args, timeout=60):
        """Run vpngate as root, return CompletedProcess."""
        if os.geteuid() == 0:
            cmd, inp = [self.vpngate] + args, None
        else:
            cmd, inp = ["sudo", "-S", "-p", "", self.vpngate] + args, (self.sudo_pw or "") + "\n"
        return subprocess.run(cmd, input=inp, capture_output=True, text=True, timeout=timeout)

    def _bg(self, fn):
        threading.Thread(target=fn, daemon=True).start()

    # ---------------------------------------------------------- actions
    def refresh_list(self):
        if not self.vpngate:
            return
        try:
            args = [self.vpngate, "list", "-o", "csv", "--sort", self.sort.get()] + self._filters()
        except ValueError as e:
            messagebox.showerror("Filter", str(e), parent=self)
            return
        if self.force_refresh.get():
            args.append("--refresh")
        self.log("Fetching server list...")

        def work():
            try:
                r = subprocess.run(args, capture_output=True, text=True, timeout=90)
            except subprocess.TimeoutExpired:
                self.ui(self.log, "List timed out.")
                return
            if r.returncode != 0:
                self.ui(self.log, "list failed: " + (r.stderr or r.stdout))
                return
            rows = list(csv.DictReader(io.StringIO(r.stdout)))
            self.ui(self._fill_table, rows)

        self._bg(work)

    def _fill_table(self, rows):
        self.tree.delete(*self.tree.get_children())
        for row in rows:
            self.tree.insert("", "end", values=(row["HostName"], row["CountryLong"],
                                                row["IP"], row["Ping"], row["Score"]))
        self.log(f"{len(rows)} servers.")

    def connect(self, random=False):
        if not self.vpngate:
            return
        args = ["connect", "-d"]
        if self.reconnect.get():
            args.append("--reconnect")
        if random:
            try:
                args += ["--random"] + self._filters()
            except ValueError as e:
                messagebox.showerror("Filter", str(e), parent=self)
                return
            label = "a random server"
        else:
            sel = self.tree.selection()
            if not sel:
                messagebox.showinfo("Connect", "Select a server first (or use Random).", parent=self)
                return
            host = self.tree.item(sel[0], "values")[0]
            args.append(host)
            label = host
        if not self._ensure_sudo():
            return
        self.log(f"Connecting to {label}...")
        self.status.set("Status: connecting...")

        def work():
            # drop any existing background connection first
            self._sudo_vpngate(["disconnect"], timeout=30)
            try:
                r = self._sudo_vpngate(args, timeout=120)
            except subprocess.TimeoutExpired:
                self.ui(self.log, "connect timed out")
                return
            self.ui(self.log, (r.stdout + r.stderr).strip() or "connect returned")
            self.after(4000, self.check_status)

        self._bg(work)

    def disconnect(self):
        if not self.vpngate or not self._ensure_sudo():
            return

        def work():
            r = self._sudo_vpngate(["disconnect"], timeout=30)
            self.ui(self.log, (r.stdout + r.stderr).strip() or "disconnected")
            self.ui(self.check_status)

        self._bg(work)

    def check_status(self):
        if not self.vpngate:
            return
        # don't nag for a password just to poll status on startup
        if self.sudo_pw is None and os.geteuid() != 0:
            if subprocess.run(["sudo", "-n", "true"], capture_output=True).returncode != 0:
                self.status.set("Status: unknown (connect or click Status to authenticate)")
                return
            self.sudo_pw = ""

        def work():
            try:
                r = self._sudo_vpngate(["status"], timeout=20)
            except subprocess.TimeoutExpired:
                return
            text = (r.stdout + r.stderr).strip().splitlines()
            line = text[0] if text else "no output"
            self.ui(self.status.set, "Status: " + line)
            if len(text) > 1:
                self.ui(self.log, "\n".join(text))

        self._bg(work)

    def show_logs(self):
        if not self.vpngate or not self._ensure_sudo():
            return

        def work():
            r = self._sudo_vpngate(["logs"], timeout=20)
            txt = (r.stdout + r.stderr).strip() or "(no logs)"
            self.ui(self._log_window, txt)

        self._bg(work)

    def _log_window(self, txt):
        w = tk.Toplevel(self)
        w.title("vpngate logs")
        w.geometry("760x420")
        t = tk.Text(w, wrap="none", bg="#111", fg="#ddd")
        t.insert("1.0", txt)
        t.see("end")
        t.configure(state="disabled")
        t.pack(fill="both", expand=True)

    def show_ip(self):
        self.log("Checking public IP...")

        def work():
            try:
                with urllib.request.urlopen("https://ipinfo.io/json", timeout=10) as resp:
                    d = json.load(resp)
                msg = f"IP {d.get('ip')}  {d.get('city')}, {d.get('country')}  ({d.get('org')})"
            except Exception as e:
                msg = f"IP lookup failed: {e}"
            self.ui(self.log, msg)

        self._bg(work)

    def update_vpngate(self):
        if not shutil.which("go"):
            messagebox.showerror("Update", "Go is not installed (sudo apt install golang).", parent=self)
            return
        self.log("Running go install ...")

        def work():
            env = dict(os.environ, CGO_ENABLED="0")
            r = subprocess.run(["go", "install", GO_PKG], capture_output=True, text=True, env=env)
            if r.returncode == 0:
                self.vpngate = find_vpngate()
                self.ui(self.log, f"vpngate updated: {self.vpngate}")
                self.ui(self.refresh_list)
            else:
                self.ui(self.log, "go install failed:\n" + r.stderr)

        self._bg(work)


if __name__ == "__main__":
    QVPN().mainloop()
