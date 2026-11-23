"""Scope: what we are allowed to touch.

Same rule as recce's recce-scope: enforced in code, fails closed. Every stage
asks `scope.allows(ip)` before handing a target to a tool, so a hostname that
resolves outside the range, or an httpx redirect, can't widen the scan.
"""
from __future__ import annotations

import ipaddress
import json
import subprocess
from dataclasses import dataclass, field

# Ranges that are "local" by definition. Anything else needs --allow-public.
LOCAL_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",   # RFC1918
    "100.64.0.0/10",                                    # CGNAT / Tailscale
    "169.254.0.0/16",                                   # link-local
    "127.0.0.0/8",
    "fc00::/7", "fe80::/10", "::1/128",
)]

# Interface name prefixes that are virtual plumbing, not "the LAN".
VIRTUAL_IFACES = ("lo", "docker", "br-", "veth", "virbr", "vmnet", "vboxnet",
                  "tun", "tap", "wg", "tailscale", "zt", "cni", "flannel", "cali")


class ScopeError(ValueError):
    pass


def _parse(value: str) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    value = value.strip()
    if not value or value.startswith("#"):
        return []
    if "-" in value and "/" not in value:
        # 10.0.0.10-10.0.0.50 or 10.0.0.10-50
        lo, hi = value.split("-", 1)
        lo_ip = ipaddress.ip_address(lo.strip())
        hi = hi.strip()
        if "." not in hi and ":" not in hi:
            hi = lo.rsplit(".", 1)[0] + "." + hi
        hi_ip = ipaddress.ip_address(hi)
        if hi_ip < lo_ip:
            raise ScopeError(f"bad range {value!r}")
        return list(ipaddress.summarize_address_range(lo_ip, hi_ip))
    return [ipaddress.ip_network(value, strict=False)]


@dataclass
class Scope:
    include: list = field(default_factory=list)
    exclude: list = field(default_factory=list)

    @classmethod
    def build(cls, targets: list[str], excludes: list[str], allow_public: bool) -> "Scope":
        s = cls()
        for t in targets:
            try:
                s.include += _parse(t)
            except ValueError as e:
                raise ScopeError(f"cannot parse target {t!r}: {e}") from None
        for x in excludes:
            try:
                s.exclude += _parse(x)
            except ValueError as e:
                raise ScopeError(f"cannot parse exclude {x!r}: {e}") from None
        if not s.include:
            raise ScopeError("no targets in scope")
        if not allow_public:
            for n in s.include:
                if not any(n.version == l.version and n.subnet_of(l) for l in LOCAL_NETS):
                    raise ScopeError(
                        f"{n} is not a private/local range. lanrecce is for networks "
                        "you own or are authorised to test; pass --allow-public if this "
                        "is an authorised engagement.")
        return s

    def allows(self, ip: str) -> bool:
        try:
            a = ipaddress.ip_address(ip.split("%", 1)[0])
        except ValueError:
            return False  # fail closed: hostnames must be resolved first
        if any(a in n for n in self.exclude):
            return False
        return any(a in n for n in self.include)

    def size(self) -> int:
        return sum(n.num_addresses for n in self.include)

    def nmap_targets(self) -> list[str]:
        return [str(n) for n in self.include]

    def nmap_excludes(self) -> list[str]:
        return [str(n) for n in self.exclude]

    def to_json(self) -> dict:
        return {"include": [str(n) for n in self.include],
                "exclude": [str(n) for n in self.exclude]}


def local_subnets(include_virtual: bool = False) -> list[dict]:
    """IPv4 subnets this machine sits on, from `ip -j addr` (Linux)."""
    try:
        out = subprocess.run(["ip", "-j", "-4", "addr"], capture_output=True,
                             text=True, check=True).stdout
        ifaces = json.loads(out)
    except Exception:
        return []
    nets = []
    for iface in ifaces:
        name = iface.get("ifname", "")
        if "UP" not in iface.get("flags", []) or iface.get("operstate") == "DOWN":
            continue
        virtual = name.startswith(VIRTUAL_IFACES)
        if virtual and not include_virtual:
            continue
        for a in iface.get("addr_info", []):
            if a.get("family") != "inet":
                continue
            net = ipaddress.ip_network(f"{a['local']}/{a['prefixlen']}", strict=False)
            if net.prefixlen >= 32 or net.is_loopback:
                continue
            nets.append({"iface": name, "addr": a["local"], "cidr": str(net),
                         "virtual": virtual})
    # de-dup (wired + wifi on the same LAN)
    seen, uniq = set(), []
    for n in nets:
        if n["cidr"] not in seen:
            seen.add(n["cidr"])
            uniq.append(n)
    return uniq


def own_addresses() -> set[str]:
    try:
        out = subprocess.run(["ip", "-j", "addr"], capture_output=True, text=True).stdout
        return {a["local"] for i in json.loads(out) for a in i.get("addr_info", [])}
    except Exception:
        return set()
