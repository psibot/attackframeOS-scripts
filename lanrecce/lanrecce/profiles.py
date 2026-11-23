"""Scan profiles, the lanrecce equivalent of recce's engines.

Every profile stays non-destructive: nuclei `dos`/`fuzz`/`intrusive` tags are
always excluded, and NSE scripts are limited to discovery/safe ones. Login
attempts (nuclei default-login templates) only run with --default-logins,
because they can lock out accounts.
"""

# NSE scripts run alongside -sV. nmap only fires a script where its portrule
# matches, so listing many is cheap. vulners is added if installed.
NSE_BASE = [
    "smb2-security-mode", "smb-security-mode", "smb-protocols", "smb-os-discovery",
    "nbstat", "ftp-anon", "ssl-cert", "rdp-enum-encryption", "rdp-ntlm-info",
    "vnc-info", "redis-info", "mongodb-info", "ms-sql-info", "mysql-info",
    "http-title", "http-server-header", "sshv1", "telnet-encryption",
    "nfs-showmount", "rpcinfo", "ldap-rootdse", "ipmi-version",
]
NSE_FULL_EXTRA = ["ssl-enum-ciphers", "x11-access", "realvnc-auth-bypass", "snmp-info"]

NUCLEI_EXCLUDE_TAGS = ["dos", "fuzz", "intrusive"]
NUCLEI_LOGIN_TAGS = ["default-login", "brute", "bruteforce"]

PROFILES = {
    "quick": {
        "desc": "Top 100 TCP ports, nuclei medium+. A few minutes for a /24.",
        "ports": "100",
        "udp": False,
        "nse": NSE_BASE,
        "nuclei_severity": ["critical", "high", "medium"],
        "nuclei_rate": 150, "nuclei_concurrency": 25,
        "nmap_timing": "-T4",
        "vulners_min_cvss": 7.0,
    },
    "standard": {
        "desc": "Top 1000 TCP ports, nuclei low+, full safe NSE set. The default.",
        "ports": "1000",
        "udp": False,
        "nse": NSE_BASE,
        "nuclei_severity": ["critical", "high", "medium", "low"],
        "nuclei_rate": 150, "nuclei_concurrency": 25,
        "nmap_timing": "-T4",
        "vulners_min_cvss": 7.0,
    },
    "full": {
        "desc": "All 65535 TCP ports, top UDP (root), nuclei incl. info, TLS cipher audit.",
        "ports": "full",
        "udp": True,
        "nse": NSE_BASE + NSE_FULL_EXTRA,
        "nuclei_severity": ["critical", "high", "medium", "low", "info"],
        "nuclei_rate": 200, "nuclei_concurrency": 40,
        "nmap_timing": "-T4",
        "vulners_min_cvss": 5.0,
    },
}

# Ports that are never HTTP, so httpx doesn't waste time on them.
NON_WEB_PORTS = {21, 22, 23, 25, 53, 88, 110, 111, 135, 137, 138, 139, 143, 389,
                 445, 465, 514, 587, 636, 993, 995, 1433, 1521, 2049, 3306, 3389,
                 5432, 5900, 5901, 6379, 11211, 27017}

# High-value internal ports that are always scanned on top of the top-N list:
# data stores, container/orchestration APIs, management, ICS/OT.
LAN_EXTRA_PORTS = [
    21, 22, 23, 25, 53, 80, 88, 111, 135, 139, 161, 389, 443, 445, 502, 623, 636,
    873, 1080, 1099, 1433, 1521, 1883, 2049, 2181, 2375, 2376, 2379, 3000, 3128,
    3306, 3389, 4369, 4848, 5000, 5432, 5601, 5672, 5900, 5984, 5985, 5986, 6000,
    6379, 6443, 7001, 8000, 8008, 8009, 8080, 8081, 8086, 8088, 8443, 8500, 8888,
    9000, 9042, 9090, 9092, 9100, 9200, 9300, 9418, 10000, 10250, 10255, 11211,
    15672, 20000, 27017, 44818, 47808, 50000, 50070,
]


def top_ports(n: int) -> list[int]:
    """nmap's top-N TCP ports by frequency (so naabu and nmap agree)."""
    for path in ("/usr/share/nmap/nmap-services", "/usr/local/share/nmap/nmap-services"):
        try:
            rows = []
            with open(path) as fh:
                for line in fh:
                    if line.startswith("#"):
                        continue
                    parts = line.split()
                    if len(parts) >= 3 and parts[1].endswith("/tcp"):
                        rows.append((float(parts[2]), int(parts[1].split("/")[0])))
            rows.sort(reverse=True)
            return [p for _, p in rows[:n]]
        except OSError:
            continue
    return []


def port_spec(spec: str) -> str | None:
    """'100'/'1000' -> explicit nmap-top-N + LAN extras; 'full' -> None (all ports)."""
    if spec == "full":
        return None
    if spec.isdigit():
        ports = set(top_ports(int(spec))) | set(LAN_EXTRA_PORTS)
        return ",".join(map(str, sorted(ports)))
    return spec
