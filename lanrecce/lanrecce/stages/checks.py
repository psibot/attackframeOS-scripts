"""Stage 6: turn nmap service data + NSE output into findings.

These are the classic internal-network issues nuclei doesn't (reliably)
cover: SMB signing / SMBv1, cleartext protocols, unauthenticated data stores,
RDP without NLA, weak TLS, plus vulners CVE matches by version.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone

from ..model import Finding, sev_from_cvss

VULNERS_ROW = re.compile(
    r"^\s*(?P<id>[A-Z0-9][\w:.\-]+)\s+(?P<score>\d+(?:\.\d+)?)\s+(?P<url>https?://\S+)(?P<exp>.*\*EXPLOIT\*)?",
    re.M)

CLEARTEXT = {
    "telnet": ("Telnet service exposed", "medium",
               "Telnet sends credentials and session data in cleartext.",
               "Disable Telnet and use SSH."),
    "ftp": ("FTP service exposed (cleartext)", "low",
            "FTP sends credentials and file contents in cleartext.",
            "Replace with SFTP/FTPS or restrict to trusted hosts."),
    "login": ("rlogin service exposed", "high", "r-services trust host addresses and send cleartext.",
              "Disable rlogin/rsh/rexec."),
    "shell": ("rsh service exposed", "high", "r-services trust host addresses and send cleartext.",
              "Disable rlogin/rsh/rexec."),
    "exec": ("rexec service exposed", "high", "r-services send credentials in cleartext.",
             "Disable rlogin/rsh/rexec."),
    "vnc": ("VNC service exposed", "low", "VNC is often weakly authenticated and unencrypted.",
            "Restrict VNC to a management network or tunnel it over SSH/VPN."),
    "snmp": ("SNMP service exposed", "low", "SNMP v1/v2c uses cleartext community strings.",
             "Use SNMPv3 with authPriv, or restrict to the management network."),
    "tftp": ("TFTP service exposed", "medium", "TFTP has no authentication.",
             "Disable TFTP or restrict it to provisioning VLANs."),
}

# Services that should almost never be reachable from the general LAN.
EXPOSED = {
    2375: ("Docker API exposed without TLS", "critical",
           "The Docker Engine API on 2375 grants root on the host to anyone who can reach it."),
    10250: ("Kubelet API exposed", "high", "The kubelet API can allow command execution in pods."),
    11211: ("Memcached exposed", "medium", "Memcached has no authentication by default."),
    9200: ("Elasticsearch HTTP API exposed", "medium",
           "Elasticsearch without security enabled allows reading/deleting all indices."),
    5984: ("CouchDB exposed", "medium", "CouchDB admin party mode allows full access."),
    623: ("IPMI exposed", "high", "IPMI 2.0 leaks password hashes (RAKP) to unauthenticated clients."),
}


# A built-in check is dropped when nuclei already reported the same issue on
# the same host:port (nuclei's finding carries request/response evidence).
SUPERSEDED_BY = {
    "redis-noauth": {"exposed-redis", "redis-default-logins", "unauth-redis"},
    "mongodb-noauth": {"mongodb-unauth", "unauth-mongodb", "mongodb-detect-unauth"},
    "ftp-anon": {"ftp-anonymous-login"},
    "vnc-noauth": {"vnc-unauth", "unauth-vnc"},
    "smb-signing": {"smb-signing-not-required"},
    "smbv1": {"smb-v1-detection", "smbv1-detect"},
    "exposed-2375": {"docker-api-unauth", "exposed-docker-api"},
    "exposed-11211": {"memcached-stats"},
}


def _dedupe(st) -> None:
    nuclei_hits = {(f.host, f.port, f.rule) for f in st.findings.values() if f.source == "nuclei"}
    for k, f in list(st.findings.items()):
        if f.source == "check" and any((f.host, f.port, t) in nuclei_hits
                                       for t in SUPERSEDED_BY.get(f.rule, ())):
            del st.findings[k]


def _f(ip, port, proto, rule, title, sev, desc, rem=None, ev=None, **kw) -> Finding:
    return Finding(title=title, severity=sev, host=ip, port=port, proto=proto, source="check",
                   rule=rule, description=desc, remediation=rem, evidence=ev, **kw)


def _vulners(ip, p, min_cvss) -> list[Finding]:
    out = p["scripts"].get("vulners")
    if not out:
        return []
    label = " ".join(x for x in (p.get("product"), p.get("version")) if x) or p.get("service") or "service"
    rows = {}
    for m in VULNERS_ROW.finditer(out):
        vid = m.group("id")
        if not vid.upper().startswith("CVE-"):
            continue
        cve = vid.upper()
        score = float(m.group("score"))
        exp = bool(m.group("exp"))
        if cve not in rows or score > rows[cve][0]:
            rows[cve] = (score, exp or rows.get(cve, (0, False))[1])
    res, low = [], []
    for cve, (score, exp) in rows.items():
        if score >= min_cvss or exp:
            res.append(Finding(
                title=f"{cve} in {label}", severity=sev_from_cvss(score), host=ip,
                port=p["port"], proto=p["proto"], source="vulners", rule=cve, cve_id=cve,
                cvss_score=score, exploit=exp,
                description=f"{label} on {ip}:{p['port']} matches {cve} by version "
                            "(vulners). Version matching can over-report: backported "
                            "distro patches are common, so verify before reporting.",
                remediation=f"Update {p.get('product') or 'the service'} to a fixed version.",
                references=[f"https://nvd.nist.gov/vuln/detail/{cve}"],
                evidence=f"{ip}:{p['port']} {label}  cpe={','.join(p.get('cpe') or [])}"))
        else:
            low.append((score, cve))
    if low:
        low.sort(reverse=True)
        res.append(Finding(
            title=f"{len(low)} lower-severity CVEs match {label}", severity="low", host=ip,
            port=p["port"], proto=p["proto"], source="vulners", rule="vulners-low",
            description="Version-matched CVEs below the reporting threshold.",
            remediation=f"Update {p.get('product') or 'the service'}.",
            evidence="\n".join(f"{c}  {s}" for s, c in low[:60])))
    return res


def _cert(ip, p, out) -> list[Finding]:
    res = []
    m = re.search(r"Not valid after:\s*(\S+)", out)
    if m:
        try:
            na = datetime.fromisoformat(m.group(1).replace("Z", "+00:00"))
            if na.tzinfo is None:
                na = na.replace(tzinfo=timezone.utc)
            if na < datetime.now(timezone.utc):
                res.append(_f(ip, p["port"], "tcp", "tls-expired", "Expired TLS certificate", "low",
                              f"Certificate expired {m.group(1)}.", "Renew the certificate.", out[:800]))
        except ValueError:
            pass
    subj = re.search(r"Subject:\s*(.*)", out)
    iss = re.search(r"Issuer:\s*(.*)", out)
    if subj and iss and subj.group(1).strip() == iss.group(1).strip():
        res.append(_f(ip, p["port"], "tcp", "tls-selfsigned", "Self-signed TLS certificate", "info",
                      "Clients can't distinguish this certificate from an attacker's.",
                      "Issue from an internal CA.", out[:800]))
    return res


def run_stage(ctx) -> None:
    st = ctx.state
    min_cvss = ctx.args.min_cvss if ctx.args.min_cvss is not None else ctx.profile["vulners_min_cvss"]
    # drop stale check/vulners findings so re-running is idempotent
    for k in [k for k, f in st.findings.items() if f.source in ("check", "vulners")]:
        del st.findings[k]

    for ip, h in st.hosts.items():
        hs = h.get("scripts") or {}
        smb_port = next((p["port"] for p in h["ports"].values() if p["port"] in (445, 139)), 445)

        s2 = hs.get("smb2-security-mode", "")
        if "not required" in s2:
            st.add(_f(ip, smb_port, "tcp", "smb-signing", "SMB signing not required", "medium",
                      "Without enforced signing, SMB traffic can be relayed (NTLM relay) to "
                      "this host.", "Require SMB signing via GPO (Microsoft network server: "
                      "Digitally sign communications (always)).", s2.strip(), cwe="CWE-345"))
        s1 = hs.get("smb-security-mode", "")
        if "message_signing: disabled" in s1:
            st.add(_f(ip, smb_port, "tcp", "smb1-signing-disabled", "SMBv1 message signing disabled",
                      "medium", "SMBv1 signing is disabled.", "Disable SMBv1 and require signing.",
                      s1.strip()))
        if "account_used: guest" in s1:
            st.add(_f(ip, smb_port, "tcp", "smb-guest", "SMB guest access allowed", "medium",
                      "The host accepts SMB sessions as guest.", "Disable guest access.", s1.strip()))
        for p in h["ports"].values():
            sp = p["scripts"].get("smb-protocols", "")
            if re.search(r"NT LM 0\.12|SMBv1", sp):
                st.add(_f(ip, p["port"], "tcp", "smbv1", "SMBv1 enabled", "high",
                          "SMBv1 is deprecated and the vector for EternalBlue/WannaCry-class bugs.",
                          "Disable SMBv1 (Set-SmbServerConfiguration -EnableSMB1Protocol $false).",
                          sp.strip(), cwe="CWE-327"))

        for p in h["ports"].values():
            port, proto, sc = p["port"], p["proto"], p["scripts"]
            svc = (p.get("service") or "").lower()

            for f in _vulners(ip, p, min_cvss):
                st.add(f)

            if svc in CLEARTEXT and p.get("tunnel") != "ssl":
                t, sev, d, r = CLEARTEXT[svc]
                st.add(_f(ip, port, proto, f"cleartext-{svc}", t, sev, d, r,
                          f"{port}/{proto} {p.get('product') or ''} {p.get('version') or ''}".strip(),
                          cwe="CWE-319"))
            if port in EXPOSED:
                t, sev, d = EXPOSED[port]
                st.add(_f(ip, port, proto, f"exposed-{port}", t, sev, d,
                          "Firewall the port to the hosts that need it.",
                          f"{port}/{proto} {svc} {p.get('product') or ''}".strip()))

            if "Anonymous FTP login allowed" in sc.get("ftp-anon", ""):
                st.add(_f(ip, port, proto, "ftp-anon", "Anonymous FTP login allowed", "medium",
                          "Anyone can log in to FTP and list (possibly write) files.",
                          "Disable anonymous FTP.", sc["ftp-anon"][:1500], cwe="CWE-306"))
            if sc.get("redis-info") and "Version" in sc["redis-info"]:
                st.add(_f(ip, port, proto, "redis-noauth", "Redis accessible without authentication",
                          "high", "Redis answered INFO without a password: data read/write and "
                          "often RCE via CONFIG SET.", "Set requirepass/ACLs and bind to localhost.",
                          sc["redis-info"][:1500], cwe="CWE-306"))
            if sc.get("mongodb-info") and "databases" in sc["mongodb-info"].lower():
                st.add(_f(ip, port, proto, "mongodb-noauth", "MongoDB accessible without authentication",
                          "high", "MongoDB listed databases without credentials.",
                          "Enable authorization and bind to trusted interfaces.",
                          sc["mongodb-info"][:1500], cwe="CWE-306"))
            vnc = sc.get("vnc-info", "")
            if re.search(r"Security types:[\s\S]*?\bNone\b", vnc):
                st.add(_f(ip, port, proto, "vnc-noauth", "VNC without authentication", "critical",
                          "The VNC server offers the 'None' security type: full desktop access.",
                          "Require VNC authentication.", vnc[:1500], cwe="CWE-306"))
            if "VULNERABLE" in sc.get("realvnc-auth-bypass", ""):
                st.add(_f(ip, port, proto, "realvnc-bypass", "RealVNC authentication bypass",
                          "critical", "CVE-2006-2369 authentication bypass.", "Update RealVNC.",
                          sc["realvnc-auth-bypass"][:1500], cve_id="CVE-2006-2369"))
            if "X server access is granted" in sc.get("x11-access", ""):
                st.add(_f(ip, port, proto, "x11-open", "Open X11 server", "high",
                          "Anyone can capture the screen and keystrokes.", "Disable xhost +.",
                          sc["x11-access"][:500]))
            rdp = sc.get("rdp-enum-encryption", "")
            if rdp and re.search(r"CredSSP[^\n]*:\s*(FAILED|NOT SUPPORTED)", rdp, re.I) and \
                    re.search(r"(Native RDP|SSL)[^\n]*:\s*SUCCESS", rdp):
                st.add(_f(ip, port, proto, "rdp-no-nla", "RDP allows connections without NLA",
                          "medium", "Without Network Level Authentication the login screen is "
                          "exposed pre-auth (BlueKeep-class bugs, user enumeration).",
                          "Require NLA.", rdp[:1500]))
            if "SSHv1" in sc.get("sshv1", ""):
                st.add(_f(ip, port, proto, "sshv1", "SSH protocol version 1 supported", "high",
                          "SSHv1 is cryptographically broken.", "Disable protocol 1.",
                          sc["sshv1"][:500], cwe="CWE-327"))
            if sc.get("nfs-showmount") and "/" in sc["nfs-showmount"]:
                st.add(_f(ip, port, proto, "nfs-exports", "NFS exports listed", "medium",
                          "Exported shares are visible; check for world-mountable exports.",
                          "Restrict /etc/exports to specific hosts.", sc["nfs-showmount"][:1500]))
            if sc.get("snmp-info") and proto == "udp":
                st.add(_f(ip, port, proto, "snmp-public", "SNMP responds to default community 'public'",
                          "medium", "Device info (and often config) can be read with the default "
                          "community string.", "Change the community or move to SNMPv3.",
                          sc["snmp-info"][:1500], cwe="CWE-1392"))
            if sc.get("ipmi-version"):
                st.add(_f(ip, port, proto, "ipmi", "IPMI service exposed", "high",
                          "IPMI 2.0 leaks password hashes to unauthenticated clients (RAKP).",
                          "Put BMCs on an isolated management VLAN.", sc["ipmi-version"][:800]))
            ciphers = sc.get("ssl-enum-ciphers", "")
            for old in ("SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"):
                if re.search(rf"^\s*{re.escape(old)}:", ciphers, re.M):
                    sev = "high" if old.startswith("SSL") else "low"
                    st.add(_f(ip, port, proto, f"tls-{old.lower()}", f"Deprecated protocol {old} enabled",
                              sev, f"The service accepts {old}.", "Allow TLS 1.2+ only.",
                              ciphers[:1500], cwe="CWE-327"))
            m = re.search(r"least strength: ([A-F])", ciphers)
            if m and m.group(1) in "DEF":
                st.add(_f(ip, port, proto, "tls-weak-ciphers", f"Weak TLS ciphers (grade {m.group(1)})",
                          "medium", "Weak cipher suites are offered.", "Remove weak suites.",
                          ciphers[:1500]))
            if sc.get("ssl-cert"):
                for f in _cert(ip, p, sc["ssl-cert"]):
                    st.add(f)
    _dedupe(st)
