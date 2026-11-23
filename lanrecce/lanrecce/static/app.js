// lanrecce web console. Everything from scans is untrusted: render with
// textContent via el(), never innerHTML.
"use strict";
const SEV = ["critical", "high", "medium", "low", "info"];
const RANK = Object.fromEntries(SEV.map((s, i) => [s, i]));
const STAGES = ["discovery", "ports", "services", "web", "nuclei", "checks", "intel"];
const $ = (s) => document.querySelector(s);

function el(tag, attrs = {}, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v == null || v === false) continue;
    if (k === "class") e.className = v;
    else if (k === "text") e.textContent = v;
    else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else e.setAttribute(k, v === true ? "" : v);
  }
  for (const c of kids.flat()) if (c != null && c !== false) e.append(c);
  return e;
}

async function api(path, opts = {}) {
  const o = { ...opts, headers: { ...(opts.headers || {}) } };
  if (o.method && o.method !== "GET") o.headers["X-Lanrecce"] = "1";
  if (o.json !== undefined) { o.body = JSON.stringify(o.json); o.headers["Content-Type"] = "application/json"; }
  const r = await fetch(path, o);
  if (r.status === 401) { location.href = "/login"; throw new Error("login required"); }
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.error || r.statusText);
  return data;
}

function toast(msg) {
  const t = $("#toast"); t.textContent = msg; t.hidden = false;
  clearTimeout(toast.t); toast.t = setTimeout(() => (t.hidden = true), 4000);
}
const fmtTime = (s) => (s ? s.replace("T", " ").replace(/\+\d{4}$/, "").slice(0, 16) : "");
const ipn = (ip) => ip.split(".").reduce((a, b) => a * 256 + (+b || 0), 0);

// ---- theme -----------------------------------------------------------------
try { const t = localStorage.getItem("lr-theme"); if (t) document.documentElement.dataset.theme = t; } catch (e) {}
function toggleTheme() {
  const r = document.documentElement;
  const dark = r.dataset.theme === "dark" || (!r.dataset.theme && matchMedia("(prefers-color-scheme: dark)").matches);
  r.dataset.theme = dark ? "light" : "dark";
  try { localStorage.setItem("lr-theme", r.dataset.theme); } catch (e) {}
}

// ---- state + routing -------------------------------------------------------
const S = { info: null, runs: [], run: null, logOffset: 0, logText: "", logName: null, open: new Set(),
            filter: { q: "", sev: "", src: "" }, hostQ: "" };

function route() {
  const h = location.hash.replace(/^#\/?/, "").split("/");
  if (h[0] === "run" && h[1]) return { view: "run", name: decodeURIComponent(h[1]), tab: h[2] || "findings" };
  if (h[0] === "new" || !S.runs.length) return { view: "new" };
  return { view: "run", name: S.runs[0].name, tab: "findings" };
}

function sevBadges(sev) {
  return el("span", { class: "sevs" }, SEV.slice(0, 4).filter((s) => sev && sev[s]).map((s) =>
    el("i", { class: s, text: sev[s], title: s })));
}

function renderSide() {
  const cur = route();
  const nav = $("#runs"); nav.textContent = "";
  if (!S.runs.length) nav.append(el("div", { class: "muted small", text: "No runs yet." }));
  for (const r of S.runs) {
    nav.append(el("a", { class: "run-link" + (cur.name === r.name ? " active" : ""), href: `#/run/${encodeURIComponent(r.name)}` },
      el("div", { class: "top" }, el("span", { class: "nm", text: r.name }),
        el("span", { class: `st-${r.status}`, title: r.status }, el("span", { class: "dot" }))),
      el("div", { class: "sub" },
        el("span", { text: r.status === "running" ? (r.stage || "starting") + "…" : `${r.hosts ?? 0} hosts` }),
        sevBadges(r.severity))));
  }
  const f = $("#foot"); f.textContent = "";
  if (S.info) {
    f.append(el("div", { text: S.info.privileged ? "● privileged (ARP/SYN)" : "○ unprivileged scans" }),
      el("button", { class: "theme", text: "◐ theme", onclick: toggleTheme }));
    $("#ver").textContent = "v" + S.info.version;
  }
}

// ---- new scan ----------------------------------------------------------------
function renderNew() {
  const m = $("#main"); m.textContent = "";
  const info = S.info || { subnets: [], profiles: {}, tools: {} };
  const err = el("div", { class: "err" });
  const targets = el("textarea", { name: "targets", placeholder: "192.168.1.0/24\n10.0.5.10-50", required: true });
  const exclude = el("textarea", { name: "exclude", placeholder: "192.168.1.1  (gateway, printers you must not touch…)", style: "min-height:52px" });
  const addTarget = (cidr) => { const v = targets.value.trim(); if (!v.split(/\s+/).includes(cidr)) targets.value = (v ? v + "\n" : "") + cidr; };
  const chips = el("div", { class: "chips" }, info.subnets.map((n) =>
    el("button", { type: "button", class: "chip" + (n.virtual ? " virtual" : ""), title: `${n.iface} · ${n.addr}`,
      text: `+ ${n.cidr} (${n.iface})`, onclick: () => addTarget(n.cidr) })));
  const prof = el("div", { class: "profiles" }, Object.entries(info.profiles).map(([k, d]) =>
    el("label", { class: "profile" }, el("input", { type: "radio", name: "profile", value: k, checked: k === "standard" }),
      el("b", { text: k }), el("span", { text: d }))));
  const cb = (name, label, hint, cls) => el("label", {}, el("input", { type: "checkbox", name }),
    el("span", { class: cls }, label, hint ? el("small", { text: " " + hint }) : null));
  const baseSel = el("select", { name: "baseline" }, el("option", { value: "", text: "— none —" }),
    S.runs.filter((r) => r.status === "done").map((r) => el("option", { value: r.name, text: r.name })));

  const missing = Object.entries(info.tools || {}).filter(([, ok]) => !ok).map(([t]) => t);
  const form = el("form", { class: "card", onsubmit: submit },
    el("div", { class: "grid2" },
      el("div", {}, el("label", {}, "Targets", el("small", { text: "CIDRs, IPs or ranges, one per line" }), targets), chips),
      el("div", {}, el("label", {}, "Exclude", el("small", { text: "never touched, even if inside a target range" }), exclude),
        el("label", {}, "Run name", el("small", { text: "optional; default is a timestamp" }),
          el("input", { type: "text", name: "name", placeholder: "office-q4", pattern: "[A-Za-z0-9][A-Za-z0-9._\\-]{0,63}" })))),
    el("div", { class: "side-h", style: "margin:4px 0 6px", text: "Profile" }), prof,
    el("details", { class: "adv" }, el("summary", { text: "Advanced options" }),
      el("div", { class: "checks" },
        cb("default_logins", "Try default logins", "(nuclei default-login; can lock accounts)", "warn"),
        cb("interactsh", "Allow interactsh", "(out-of-band callbacks to public oast.* servers)"),
        cb("offline", "Offline", "(no KEV/EPSS lookups)"),
        cb("no_udp", "Skip UDP", "(full profile)"),
        cb("no_discovery", "Treat all addresses as up", "(slow; finds hosts that ignore pings)"),
        cb("no_dns", "No reverse DNS")),
      el("div", { class: "grid2", style: "margin-top:12px" },
        el("label", {}, "Ports override", el("small", { text: "100 · 1000 · full · 22,80,8000-8100" }), el("input", { type: "text", name: "ports" })),
        el("label", {}, "nuclei severities", el("small", { text: "e.g. critical,high" }), el("input", { type: "text", name: "severity" }))),
      el("label", {}, "Compare with baseline run", el("small", { text: "marks findings new / fixed" }), baseSel)),
    el("label", { class: "consent" }, el("input", { type: "checkbox", name: "consent", required: true }),
      el("span", { text: "I own these networks or am authorised in writing to test them." })),
    err,
    el("div", { class: "actions" }, el("button", { class: "btn primary", type: "submit", text: "Start scan" })));

  async function submit(ev) {
    ev.preventDefault(); err.textContent = "";
    const fd = new FormData(form);
    const body = {
      targets: fd.get("targets"), exclude: fd.get("exclude"), name: fd.get("name"),
      profile: fd.get("profile"), baseline: fd.get("baseline"),
      options: { ports: fd.get("ports"), severity: fd.get("severity") },
    };
    for (const k of ["default_logins", "interactsh", "offline", "no_udp", "no_discovery", "no_dns"]) body.options[k] = fd.get(k) === "on";
    const btn = form.querySelector("button[type=submit]"); btn.disabled = true;
    try {
      const r = await api("/api/scans", { method: "POST", json: body });
      await refreshRuns(); location.hash = `#/run/${encodeURIComponent(r.name)}/console`;
    } catch (e) { err.textContent = e.message; btn.disabled = false; }
  }

  m.append(el("div", { class: "head" }, el("div", {}, el("h1", { text: "New scan" }),
      el("div", { class: "muted", text: "Discovery → ports → services → web → nuclei → checks → CVE intel → report & Dossier export" }))));
  if (S.info && S.info.running) m.append(el("div", { class: "banner" }, "A scan is running: ",
    el("a", { href: `#/run/${encodeURIComponent(S.info.running)}/console`, text: S.info.running }), ". One scan runs at a time."));
  if (S.info && !S.info.privileged) m.append(el("div", { class: "banner", text:
    "The server isn't privileged: no ARP discovery, SYN scans, OS detection or UDP. Quiet hosts may be missed. Run under Docker Compose (NET_RAW) or sudo." }));
  if (missing.length) m.append(el("div", { class: "banner", text: "Missing tools: " + missing.join(", ") }));
  m.append(form);
}

// ---- run view ------------------------------------------------------------------
async function loadRun(name) {
  S.run = await api(`/api/runs/${encodeURIComponent(name)}`);
  if (S.logName !== name) { S.logName = name; S.logOffset = 0; S.logText = ""; S.open.clear(); }
}

async function loadLog(name) {
  const r = await api(`/api/runs/${encodeURIComponent(name)}/log?offset=${S.logOffset}`);
  if (r.offset < S.logOffset) S.logText = "";
  S.logText = (S.logText + r.text).slice(-400000);
  S.logOffset = r.offset;
}

function renderRun(tab) {
  const R = S.run, m = $("#main"); m.textContent = "";
  const meta = R.meta || {}, scope = meta.scope || { include: [], exclude: [] };
  const sev = {}; R.findings.forEach((f) => (sev[f.severity] = (sev[f.severity] || 0) + 1));
  const enc = encodeURIComponent(R.name);
  const actions = el("div", { class: "actions" });
  if (R.status === "running") actions.append(el("button", { class: "btn", text: "■ Stop", onclick: () => act("stop") }));
  if (R.status === "stopped") actions.append(el("button", { class: "btn primary", text: "▶ Resume", onclick: () => act("resume") }));
  if (R.files.includes("report.html")) actions.append(el("a", { class: "btn", href: `/runs/${enc}/report.html`, target: "_blank", rel: "noopener", text: "Open report ↗" }));
  if (R.status !== "running") actions.append(el("button", { class: "btn danger", text: "Delete", onclick: del }));

  m.append(el("div", { class: "head" },
    el("div", {}, el("h1", {}, R.name + " ", el("span", { class: `pill st-${R.status}` }, R.status === "running" ? el("span", { class: "dot pulse" }) : null, " " + R.status)),
      el("div", { class: "muted", text: [`Scope: ${scope.include.join(", ") || "—"}`,
        scope.exclude.length ? `excluding ${scope.exclude.join(", ")}` : null, meta.profile ? `profile ${meta.profile}` : null,
        meta.started ? `started ${fmtTime(meta.started)}` : null, meta.finished ? `finished ${fmtTime(meta.finished)}` : null,
        meta.privileged === false ? "unprivileged" : null].filter(Boolean).join(" · ") })),
    actions));

  const stages = meta.stages || {};
  m.append(el("div", { class: "pipe" }, STAGES.map((s) => {
    const st = s === "intel" ? (meta.finished ? { status: "done" } : {}) : stages[s] || {};
    return el("div", { class: "stage " + (st.status || "") }, el("b", { text: s }),
      el("span", { class: "muted", text: st.status === "done" ? (st.seconds != null ? `${st.seconds}s` : "done") : st.status === "running" ? "running…" : "—" }));
  })));

  const ports = Object.values(R.hosts).reduce((a, h) => a + Object.keys(h.ports).length, 0);
  m.append(el("div", { class: "tiles" },
    el("div", { class: "tile" }, el("b", { text: Object.keys(R.hosts).length }), el("span", { text: "hosts" })),
    el("div", { class: "tile" }, el("b", { text: ports }), el("span", { text: "open ports" })),
    SEV.map((s) => el("div", { class: "tile " + s }, el("b", { text: sev[s] || 0 }), el("span", { text: s })))));

  const tabs = [["findings", `Findings (${R.findings.length})`], ["hosts", `Hosts (${Object.keys(R.hosts).length})`], ["console", "Console"], ["export", "Export"]];
  m.append(el("div", { class: "tabs" }, tabs.map(([k, l]) => el("a", { class: "tab" + (tab === k ? " active" : ""), href: `#/run/${enc}/${k}`, text: l }))));
  const body = el("div"); m.append(body);
  ({ findings: renderFindings, hosts: renderHosts, console: renderConsole, export: renderExport }[tab] || renderFindings)(body);

  async function act(what) {
    try { await api(`/api/runs/${enc}/${what}`, { method: "POST" }); toast(what === "stop" ? "Stopping… state and report are saved; resume any time." : "Resumed"); tick(); }
    catch (e) { toast(e.message); }
  }
  async function del() {
    if (!confirm(`Delete run "${R.name}" and all its files? This can't be undone.`)) return;
    try { await api(`/api/runs/${enc}`, { method: "DELETE" }); location.hash = "#/new"; await refreshRuns(); }
    catch (e) { toast(e.message); }
  }
}

function renderFindings(box) {
  const R = S.run;
  const q = el("input", { type: "text", placeholder: "Filter: host, title, CVE, template…", value: S.filter.q });
  const sv = el("select", {}, el("option", { value: "", text: "All severities" }), SEV.map((s) => el("option", { value: s, text: s, selected: S.filter.sev === s })));
  const sources = [...new Set(R.findings.map((f) => f.source))];
  const src = el("select", {}, el("option", { value: "", text: "All sources" }), sources.map((s) => el("option", { value: s, text: s, selected: S.filter.src === s })));
  const tbody = el("tbody");
  const draw = () => {
    S.filter = { q: q.value, sev: sv.value, src: src.value };
    const needle = q.value.toLowerCase();
    const rows = R.findings.filter((f) => (!sv.value || f.severity === sv.value) && (!src.value || f.source === src.value) &&
      (!needle || [f.title, f.host, f.rule, f.cve_id, f.matched_at, String(f.port)].join(" ").toLowerCase().includes(needle)));
    tbody.textContent = "";
    for (const f of rows) {
      const k = f.dedup_key;
      const t = el("td", {}, f.title, f.kev ? el("span", { class: "tag kev", text: "KEV" }) : null,
        f.priority === "fire" ? el("span", { class: "tag fire", text: "fire" }) : null,
        f.exploit ? el("span", { class: "tag", text: "exploit" }) : null, f.status === "new" ? el("span", { class: "tag", text: "new" }) : null);
      tbody.append(el("tr", { class: "f", onclick: () => { S.open.has(k) ? S.open.delete(k) : S.open.add(k); draw(); } },
        el("td", {}, el("span", { class: "sev " + f.severity, text: f.severity })), t,
        el("td", { class: "mono", text: f.host }), el("td", { class: "mono", text: f.port ? `${f.port}/${f.proto || "tcp"}` : "" }),
        el("td", { text: f.source }), el("td", { class: "mono", text: f.cvss_score ?? "" }),
        el("td", { class: "mono", text: f.epss != null ? (f.epss * 100).toFixed(1) + "%" : "" })));
      if (S.open.has(k)) tbody.append(el("tr", { class: "detail" }, el("td", { colspan: 7 },
        f.description ? el("p", { text: f.description }) : null,
        f.remediation ? el("p", {}, el("b", { text: "Remediation: " }), f.remediation) : null,
        el("p", { class: "mono muted", text: [["rule", f.rule], ["matched", f.matched_at], ["CVE", f.cve_id], ["CWE", f.cwe],
          ["KEV", f.kev == null ? null : String(f.kev)], ["priority", f.priority]].filter((x) => x[1]).map((x) => `${x[0]}: ${x[1]}`).join("   ") }),
        f.evidence ? el("pre", { text: f.evidence }) : null,
        (f.references || []).length ? el("ul", {}, f.references.slice(0, 8).map((r) => el("li", {},
          /^https?:\/\//.test(r) ? el("a", { href: r, target: "_blank", rel: "noopener noreferrer", text: r }) : r))) : null)));
    }
    if (!rows.length) tbody.append(el("tr", {}, el("td", { colspan: 7, class: "muted",
      text: R.findings.length ? "No findings match the filter." : R.status === "running" ? "No findings yet. They appear here as the scan finds them." : "No findings." })));
  };
  [q, sv, src].forEach((x) => x.addEventListener("input", draw));
  R.findings.sort((a, b) => RANK[a.severity] - RANK[b.severity]);
  box.append(el("div", { class: "filters" }, q, sv, src),
    el("div", { class: "tw" }, el("table", {}, el("thead", {}, el("tr", {}, ["Severity", "Finding", "Host", "Port", "Source", "CVSS", "EPSS"].map((h) => el("th", { text: h })))), tbody)));
  draw();
}

function renderHosts(box) {
  const R = S.run;
  const byHost = {}; R.findings.forEach((f) => { (byHost[f.host] = byHost[f.host] || {})[f.severity] = (byHost[f.host][f.severity] || 0) + 1; });
  const q = el("input", { type: "text", placeholder: "Filter hosts: IP, name, vendor, service…", value: S.hostQ });
  const grid = el("div", { class: "hosts" });
  const draw = () => {
    S.hostQ = q.value; const needle = q.value.toLowerCase(); grid.textContent = "";
    Object.values(R.hosts).sort((a, b) => ipn(a.ip) - ipn(b.ip)).forEach((h) => {
      const ports = Object.values(h.ports).sort((a, b) => a.port - b.port);
      const hay = [h.ip, h.mac, h.vendor, h.os, ...(h.hostnames || []), ...ports.map((p) => [p.port, p.service, p.product, p.version].join(" ")),
        ...(h.web || []).map((w) => [w.url, w.title, ...(w.tech || [])].join(" "))].join(" ").toLowerCase();
      if (needle && !hay.includes(needle)) return;
      grid.append(el("div", { class: "card host" },
        el("h3", { class: "mono" }, h.ip + " ", sevBadges(byHost[h.ip])),
        el("div", { class: "muted small", text: [(h.hostnames || []).join(", "), h.vendor, h.mac, h.self ? "(this machine)" : null].filter(Boolean).join(" · ") || "—" }),
        h.os ? el("div", { class: "muted small", text: "OS: " + h.os }) : null,
        el("div", { class: "ports" }, ports.map((p) => el("div", { class: "mono", text: `${p.port}/${p.proto}  ${p.service || "?"}  ${[p.product, p.version, p.extrainfo].filter(Boolean).join(" ")}` })),
          (h.web || []).map((w) => el("div", { class: "mono", text: `↳ ${w.url} [${w.status ?? ""}] ${w.title || ""} ${(w.tech || []).join(", ")}` })),
          ports.length ? null : el("div", { class: "muted", text: "no open ports found (yet)" }))));
    });
    if (!grid.childElementCount) grid.append(el("div", { class: "muted", text: "No hosts." }));
  };
  q.addEventListener("input", draw);
  box.append(el("div", { class: "filters" }, q), grid); draw();
}

function renderConsole(box) {
  const pre = el("pre", { class: "console", id: "console", text: S.logText || "(no output yet)" });
  box.append(pre, el("div", { class: "muted small" }, "Live output of the scan process. Raw tool stderr: ",
    el("a", { href: `/runs/${encodeURIComponent(S.run.name)}/tools.log`, target: "_blank", text: "tools.log" })));
  pre.scrollTop = pre.scrollHeight;
}

function renderExport(box) {
  const R = S.run, enc = encodeURIComponent(R.name), has = (f) => R.files.includes(f);
  const card = (title, desc, links, cls) => el("div", { class: "card export " + (cls || "") }, el("h3", { text: title }), el("p", { text: desc }),
    el("div", { class: "actions" }, links));
  const dl = (f, label, primary) => has(f) ? el("a", { class: "btn" + (primary ? " primary" : ""), href: `/runs/${enc}/${f}`, text: label }) : el("button", { class: "btn", disabled: true, text: label });
  const dossierUrl = S.info && S.info.dossier_url;
  box.append(el("div", { class: "exports" },
    card("Dossier", "Import both files on Dossier's Import page (drop them together). The .nessus file carries findings with evidence, CVSS, CWE and CVEs. The nmap XML adds every host, port and service version.",
      [has("dossier-findings.nessus") ? el("a", { class: "btn primary", href: `/api/runs/${enc}/dossier.zip`, text: "Download both (.zip)" }) : el("button", { class: "btn", disabled: true, text: "Available when the run finishes" }),
       dl("dossier-findings.nessus", ".nessus"), dl("dossier-hosts.xml", "hosts .xml"),
       dossierUrl ? el("a", { class: "btn", href: dossierUrl, target: "_blank", rel: "noopener", text: "Open Dossier ↗" }) : null], "dossier"),
    card("HTML report", "Self-contained, shareable report with filters and host inventory.", [
      has("report.html") ? el("a", { class: "btn", href: `/runs/${enc}/report.html`, target: "_blank", rel: "noopener", text: "Open ↗" }) : null]),
    card("Data", "Raw findings and inventory for scripts, spreadsheets or recce.", [
      dl("findings.json", "findings.json"), dl("findings.csv", "CSV"), dl("hosts.json", "hosts.json"), dl("findings.nuclei.jsonl", "nuclei JSONL")]),
    card("Logs", "Scan console and every tool's stderr.", [dl("console.log", "console.log"), dl("tools.log", "tools.log")])));
}

// ---- loop ---------------------------------------------------------------------
async function refreshRuns() {
  [S.info, S.runs] = await Promise.all([api("/api/info"), api("/api/runs")]);
  renderSide();
}

let busy = false;
async function tick(force) {
  if (busy) return; busy = true;
  try {
    await refreshRuns();
    const r = route();
    if (r.view === "new") { if (force) renderNew(); }
    else {
      const wasRunning = S.run && S.run.name === r.name && S.run.status === "running";
      const typing = document.activeElement && ["INPUT", "SELECT", "TEXTAREA"].includes(document.activeElement.tagName);
      await loadRun(r.name);
      if (r.tab === "console" || S.run.status === "running") await loadLog(r.name);
      if (force || wasRunning || S.run.status === "running") {
        if (!(typing && !force)) {
          const sc = $("#console"); const atBottom = !sc || sc.scrollTop + sc.clientHeight >= sc.scrollHeight - 20;
          renderRun(r.tab);
          const nc = $("#console"); if (nc && atBottom) nc.scrollTop = nc.scrollHeight;
        }
      }
    }
  } catch (e) {
    if (String(e.message).includes("no such run")) location.hash = "#/new";
    else console.error(e);
  } finally { busy = false; }
}

window.addEventListener("hashchange", () => tick(true));
tick(true);
setInterval(() => tick(false), 2000);
