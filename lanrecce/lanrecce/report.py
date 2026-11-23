"""Reports: report.html (self-contained), findings.json, hosts.json,
findings.csv, findings.nuclei.jsonl (recce-compatible), and the Dossier
import pair dossier-findings.nessus + dossier-hosts.xml (see dossier.py).

Everything in the report came off the network (banners, titles, HTTP bodies),
so it's treated as hostile: data is embedded as JSON and rendered with
textContent only. Nothing from a scanned host is ever parsed as HTML.
"""
from __future__ import annotations

import csv
import json
from collections import Counter
from pathlib import Path

from . import dossier
from .model import SEVERITIES, State


def diff_against(state: State, baseline: Path) -> dict:
    """Mark findings new/open vs a previous run; list ones that disappeared."""
    old = State.load(baseline)
    old_keys = set(old.findings)
    for k, f in state.findings.items():
        f.status = "open" if k in old_keys else "new"
    fixed = [f.to_json() for k, f in old.findings.items() if k not in state.findings]
    for f in fixed:
        f["status"] = "fixed"
    new_hosts = sorted(set(state.hosts) - set(old.hosts))
    gone_hosts = sorted(set(old.hosts) - set(state.hosts))
    return {"baseline": str(baseline), "fixed": fixed, "new_hosts": new_hosts,
            "gone_hosts": gone_hosts}


def write_all(state: State, out: Path, diff: dict | None = None) -> Path:
    findings = [f.to_json() for f in state.sorted_findings()]
    (out / "findings.json").write_text(json.dumps(findings, indent=1))
    (out / "hosts.json").write_text(json.dumps(state.hosts, indent=1))

    cols = ["severity", "priority", "title", "host", "port", "proto", "source", "rule",
            "cve_id", "cvss_score", "kev", "epss", "exploit", "status", "matched_at",
            "description", "remediation"]
    with open(out / "findings.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        w.writerows(findings)

    # Nuclei-shaped JSONL so Dossier's nuclei importer (and recce) can ingest it.
    with open(out / "findings.nuclei.jsonl", "w") as fh:
        for f in findings:
            fh.write(json.dumps({
                "template-id": f["rule"] or f["source"],
                "info": {"name": f["title"], "severity": f["severity"],
                         "description": f["description"], "remediation": f["remediation"],
                         "reference": f["references"],
                         "classification": {"cve-id": [f["cve_id"]] if f["cve_id"] else None,
                                            "cwe-id": [f["cwe"]] if f["cwe"] else None,
                                            "cvss-score": f["cvss_score"]}},
                "type": "network", "host": f["host"], "ip": f["host"],
                "port": str(f["port"] or ""),
                "matched-at": f["matched_at"] or (f"{f['host']}:{f['port']}" if f["port"] else f["host"]),
                "extracted-results": [f["evidence"]] if f["evidence"] else None,
                "lanrecce-source": f["source"],
            }) + "\n")

    # Dossier import files (Nessus findings + nmap host inventory)
    dossier.write(state, out)

    sev = Counter(f["severity"] for f in findings)
    data = {
        "meta": state.meta, "hosts": state.hosts, "findings": findings,
        "summary": {
            "hosts": len(state.hosts),
            "hosts_with_ports": sum(1 for h in state.hosts.values() if h["ports"]),
            "ports": sum(len(h["ports"]) for h in state.hosts.values()),
            "web": sum(len(h["web"]) for h in state.hosts.values()),
            "severity": {s: sev.get(s, 0) for s in SEVERITIES},
            "kev": sum(1 for f in findings if f.get("kev")),
            "fire": sum(1 for f in findings if f.get("priority") == "fire"),
        },
        "diff": diff,
    }
    blob = json.dumps(data, default=str).replace("</", "<\\/").replace("<!--", "<\\!--")
    html = TEMPLATE.replace("/*__DATA__*/null", blob)
    p = out / "report.html"
    p.write_text(html)
    return p


TEMPLATE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:">
<title>LAN Assessment Report</title>
<style>
:root{--bg:#f7f7f5;--panel:#fff;--ink:#1c1c1a;--muted:#6b6b66;--line:#e3e2dc;--accent:#2f5bd3;
--crit:#9b1c1c;--high:#d4471f;--med:#c98a00;--low:#2f7d52;--info:#64748b;--code:#f1f0ec}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]){--bg:#141413;--panel:#1d1d1b;--ink:#ecebe6;
--muted:#9a9992;--line:#2e2e2b;--accent:#7a9cff;--crit:#f05252;--high:#ff7a45;--med:#f2b632;--low:#4fbf85;--info:#94a3b8;--code:#262624}}
:root[data-theme=dark]{--bg:#141413;--panel:#1d1d1b;--ink:#ecebe6;--muted:#9a9992;--line:#2e2e2b;--accent:#7a9cff;
--crit:#f05252;--high:#ff7a45;--med:#f2b632;--low:#4fbf85;--info:#94a3b8;--code:#262624}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
header{padding:28px 16px 8px;max-width:1200px;margin:auto}h1{margin:0 0 4px;font-size:24px}
.meta{color:var(--muted);font-size:13px}main{max-width:1200px;margin:auto;padding:0 16px 60px}
h2{font-size:17px;margin:32px 0 10px}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:10px;margin-top:16px}
.tile{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:12px 14px}
.tile b{display:block;font-size:24px;font-variant-numeric:tabular-nums}.tile span{color:var(--muted);font-size:12px}
.sev{display:inline-block;min-width:66px;text-align:center;padding:1px 8px;border-radius:999px;font-size:11px;font-weight:600;text-transform:uppercase;color:#fff}
.sev.critical{background:var(--crit)}.sev.high{background:var(--high)}.sev.medium{background:var(--med)}.sev.low{background:var(--low)}.sev.info{background:var(--info)}
.tile.critical b{color:var(--crit)}.tile.high b{color:var(--high)}.tile.medium b{color:var(--med)}.tile.low b{color:var(--low)}.tile.info b{color:var(--info)}
.bar{display:flex;height:8px;border-radius:4px;overflow:hidden;margin-top:12px;background:var(--line)}
.controls{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:10px}
input,select{background:var(--panel);color:var(--ink);border:1px solid var(--line);border-radius:8px;padding:6px 10px;font:inherit}
input{flex:1;min-width:180px}
.tw{overflow-x:auto;background:var(--panel);border:1px solid var(--line);border-radius:10px}
table{border-collapse:collapse;width:100%}th,td{text-align:left;padding:7px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-size:12px;color:var(--muted);font-weight:600;cursor:pointer;user-select:none;white-space:nowrap;position:sticky;top:0;background:var(--panel)}
tr.f{cursor:pointer}tr.f:hover td{background:color-mix(in srgb,var(--accent) 6%,transparent)}
td.mono,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px}
tr.detail td{background:var(--bg)}pre{background:var(--code);padding:10px;border-radius:8px;white-space:pre-wrap;word-break:break-word;max-height:420px;overflow:auto;font-size:12px;margin:6px 0}
.tag{display:inline-block;font-size:11px;padding:0 6px;border-radius:4px;border:1px solid var(--line);color:var(--muted);margin:1px 3px 1px 0}
.tag.kev{border-color:var(--crit);color:var(--crit);font-weight:600}.tag.fire{border-color:var(--high);color:var(--high)}
.tag.new{border-color:var(--accent);color:var(--accent);font-weight:600}
.muted{color:var(--muted)}a{color:var(--accent)}
.hosts{display:grid;grid-template-columns:repeat(auto-fill,minmax(330px,1fr));gap:10px}
.host{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:12px 14px;min-width:0}
.host h3{margin:0;font-size:15px}.host .ports{margin-top:6px}
.host .ports div{font-size:12.5px;border-top:1px dashed var(--line);padding:3px 0;overflow-wrap:anywhere}
.pill{font-size:11px;font-weight:600;padding:0 6px;border-radius:999px;color:#fff;margin-left:4px}
button.theme{position:fixed;top:12px;right:12px;background:var(--panel);color:var(--ink);border:1px solid var(--line);border-radius:8px;padding:4px 10px;cursor:pointer}
@media print{button.theme,.controls{display:none}}
</style></head><body>
<button class="theme" id="tt">◐</button>
<header><h1>LAN Assessment Report</h1><div class="meta" id="meta"></div></header>
<main>
<div class="tiles" id="tiles"></div><div class="bar" id="bar"></div>
<div id="diff"></div>
<h2>Findings</h2>
<div class="controls"><input id="q" placeholder="Filter: host, title, CVE, template…">
<select id="fs"><option value="">All severities</option></select>
<select id="fsrc"><option value="">All sources</option></select></div>
<div class="tw"><table id="ft"><thead><tr>
<th data-k="severity">Severity</th><th data-k="title">Finding</th><th data-k="host">Host</th><th data-k="port">Port</th>
<th data-k="source">Source</th><th data-k="cvss_score">CVSS</th><th data-k="epss">EPSS</th></tr></thead><tbody></tbody></table></div>
<h2>Hosts</h2>
<div class="controls"><input id="hq" placeholder="Filter hosts: IP, name, vendor, service…"></div>
<div class="hosts" id="hosts"></div>
</main>
<script id="data" type="application/json">/*__DATA__*/null</script>
<script>
const D=JSON.parse(document.getElementById('data').textContent);
const SEV=['critical','high','medium','low','info'],RANK=Object.fromEntries(SEV.map((s,i)=>[s,i]));
const $=(t,a={},...kids)=>{const e=document.createElement(t);for(const[k,v]of Object.entries(a)){if(k==='class')e.className=v;else if(k==='text')e.textContent=v;else e.setAttribute(k,v)}for(const c of kids)if(c!=null)e.append(c);return e};
const ipn=ip=>ip.split('.').reduce((a,b)=>a*256+(+b||0),0);
try{const t=localStorage.getItem('lr-theme');if(t)document.documentElement.dataset.theme=t}catch(e){}
document.getElementById('tt').onclick=()=>{const r=document.documentElement,d=r.dataset.theme==='dark'||(!r.dataset.theme&&matchMedia('(prefers-color-scheme: dark)').matches);r.dataset.theme=d?'light':'dark';try{localStorage.setItem('lr-theme',r.dataset.theme)}catch(e){}};
const m=D.meta||{},S=D.summary;
document.getElementById('meta').textContent=[`Scope: ${(m.scope&&m.scope.include||[]).join(', ')}`,m.scope&&m.scope.exclude.length?`excluding ${m.scope.exclude.join(', ')}`:null,`profile: ${m.profile}`,`started ${m.started}`,m.finished?`finished ${m.finished}`:'(incomplete run)',m.privileged?'privileged':'unprivileged'].filter(Boolean).join(' · ');
const tiles=document.getElementById('tiles');
[['Live hosts',S.hosts],['Hosts w/ open ports',S.hosts_with_ports],['Open ports',S.ports],['Web services',S.web]].forEach(([l,v])=>tiles.append($('div',{class:'tile'},$('b',{text:v}),$('span',{text:l}))));
SEV.forEach(s=>tiles.append($('div',{class:'tile '+s},$('b',{text:S.severity[s]}),$('span',{text:s}))));
if(S.kev)tiles.append($('div',{class:'tile critical'},$('b',{text:S.kev}),$('span',{text:'on CISA KEV'})));
const tot=SEV.reduce((a,s)=>a+S.severity[s],0)||1,bar=document.getElementById('bar');
SEV.forEach(s=>{if(S.severity[s])bar.append($('div',{style:`width:${S.severity[s]/tot*100}%;background:var(--${{critical:'crit',high:'high',medium:'med',low:'low',info:'info'}[s]})`,title:`${s}: ${S.severity[s]}`}))});
if(D.diff){const d=D.diff,box=document.getElementById('diff');box.append($('h2',{text:'Changes since baseline'}),
$('p',{class:'muted',text:`New findings: ${D.findings.filter(f=>f.status==='new').length} · Fixed: ${d.fixed.length} · New hosts: ${d.new_hosts.length} (${d.new_hosts.join(', ')||'none'}) · Gone hosts: ${d.gone_hosts.length}`}));
if(d.fixed.length){const ul=$('ul');d.fixed.forEach(f=>ul.append($('li',{text:`[${f.severity}] ${f.title} — ${f.host}${f.port?':'+f.port:''}`})));box.append($('details',{},$('summary',{text:'Fixed findings'}),ul))}}
const fs=document.getElementById('fs');SEV.forEach(s=>fs.append($('option',{value:s,text:s})));
const fsrc=document.getElementById('fsrc');[...new Set(D.findings.map(f=>f.source))].forEach(s=>fsrc.append($('option',{value:s,text:s})));
let sortK='severity',sortD=1;const open=new Set();
function cmp(a,b){let x=a[sortK],y=b[sortK];if(sortK==='severity'){x=RANK[x];y=RANK[y]}else if(sortK==='host'){x=ipn(x);y=ipn(y)}
if(x==null)x=-Infinity;if(y==null)y=-Infinity;return(x>y?1:x<y?-1:0)*sortD||RANK[a.severity]-RANK[b.severity]}
function detail(f){const td=$('td',{colspan:7});
if(f.description)td.append($('p',{text:f.description}));
if(f.remediation)td.append($('p',{},$('b',{text:'Remediation: '}),f.remediation));
const facts=[['Rule',f.rule],['Matched',f.matched_at],['CVE',f.cve_id],['CWE',f.cwe],['CVSS vector',f.cvss_vector],['KEV',f.kev==null?null:String(f.kev)],['Priority',f.priority]].filter(x=>x[1]);
if(facts.length)td.append($('p',{class:'mono'},...facts.map(([k,v])=>$('span',{text:`${k}: ${v}   `}))));
if(f.evidence)td.append($('pre',{text:f.evidence}));
if(f.references&&f.references.length){const ul=$('ul');f.references.slice(0,8).forEach(r=>{const ok=/^https?:\/\//.test(r);ul.append($('li',{},ok?$('a',{href:r,target:'_blank',rel:'noopener noreferrer',text:r}):r))});td.append(ul)}
return $('tr',{class:'detail'},td)}
function render(){const q=document.getElementById('q').value.toLowerCase(),sv=fs.value,src=fsrc.value,tb=document.querySelector('#ft tbody');tb.textContent='';
const rows=D.findings.filter(f=>(!sv||f.severity===sv)&&(!src||f.source===src)&&(!q||[f.title,f.host,f.rule,f.cve_id,f.matched_at,String(f.port)].join(' ').toLowerCase().includes(q))).sort(cmp);
for(const f of rows){const k=f.dedup_key,t=$('td');t.append(f.title);
if(f.kev)t.append(' ',$('span',{class:'tag kev',text:'KEV'}));if(f.priority==='fire')t.append($('span',{class:'tag fire',text:'fire'}));
if(f.exploit)t.append($('span',{class:'tag',text:'exploit'}));if(f.status==='new')t.append($('span',{class:'tag new',text:'new'}));
const tr=$('tr',{class:'f'},$('td',{},$('span',{class:'sev '+f.severity,text:f.severity})),t,$('td',{class:'mono',text:f.host}),$('td',{class:'mono',text:f.port?`${f.port}/${f.proto||'tcp'}`:''}),
$('td',{text:f.source}),$('td',{class:'mono',text:f.cvss_score??''}),$('td',{class:'mono',text:f.epss!=null?(f.epss*100).toFixed(1)+'%':''}));
tr.onclick=()=>{open.has(k)?open.delete(k):open.add(k);render()};tb.append(tr);if(open.has(k))tb.append(detail(f))}
if(!rows.length)tb.append($('tr',{},$('td',{colspan:7,class:'muted',text:'No findings match.'})))}
document.querySelectorAll('#ft th').forEach(th=>th.onclick=()=>{const k=th.dataset.k;sortD=sortK===k?-sortD:(k==='severity'?1:-1);sortK=k;render()});
['q','fs','fsrc'].forEach(id=>document.getElementById(id).addEventListener('input',render));render();
const byHost={};D.findings.forEach(f=>{(byHost[f.host]=byHost[f.host]||[]).push(f)});
function renderHosts(){const q=document.getElementById('hq').value.toLowerCase(),box=document.getElementById('hosts');box.textContent='';
Object.values(D.hosts).sort((a,b)=>ipn(a.ip)-ipn(b.ip)).forEach(h=>{const ports=Object.values(h.ports).sort((a,b)=>a.port-b.port);
const hay=[h.ip,h.mac,h.vendor,h.os,...h.hostnames,...ports.map(p=>[p.port,p.service,p.product,p.version].join(' ')),...h.web.map(w=>[w.url,w.title,...(w.tech||[])].join(' '))].join(' ').toLowerCase();
if(q&&!hay.includes(q))return;const fc={};(byHost[h.ip]||[]).forEach(f=>fc[f.severity]=(fc[f.severity]||0)+1);
const title=$('h3',{class:'mono',text:h.ip});SEV.slice(0,4).forEach(s=>{if(fc[s])title.append($('span',{class:'pill sev '+s,text:fc[s]}))});
const card=$('div',{class:'host'},title,$('div',{class:'muted',text:[h.hostnames.join(', '),h.vendor,h.mac,h.self?'(this machine)':null].filter(Boolean).join(' · ')||'—'}));
if(h.os)card.append($('div',{class:'muted',text:'OS: '+h.os}));const pd=$('div',{class:'ports'});
ports.forEach(p=>pd.append($('div',{class:'mono',text:`${p.port}/${p.proto}  ${p.service||'?'}  ${[p.product,p.version,p.extrainfo].filter(Boolean).join(' ')}`})));
h.web.forEach(w=>pd.append($('div',{class:'mono',text:`↳ ${w.url} [${w.status??''}] ${w.title||''} ${(w.tech||[]).join(', ')}`})));
if(!ports.length)pd.append($('div',{class:'muted',text:'no open ports found'}));card.append(pd);box.append(card)})}
document.getElementById('hq').addEventListener('input',renderHosts);renderHosts();
</script></body></html>
"""
