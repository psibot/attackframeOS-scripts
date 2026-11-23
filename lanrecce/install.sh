#!/usr/bin/env bash
# install.sh -- set up lanrecce's toolchain on Debian/Ubuntu (Kali works too).
#
#   ./install.sh            nmap + vulners.nse + naabu/httpx/nuclei + templates
#   ./install.sh --setcap   ALSO grant nmap/naabu raw-socket capability so ARP
#                           discovery and SYN scans work without sudo
#
# Go tools go to ~/go/bin (add it to PATH). Re-running is safe; it updates.
set -euo pipefail

SETCAP=0
[[ "${1:-}" == "--setcap" ]] && SETCAP=1

say() { printf '\033[36m[*]\033[0m %s\n' "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }

say "apt packages: nmap, libpcap-dev (naabu), git, curl"
sudo apt-get update -qq
sudo apt-get install -y -qq nmap libpcap-dev git curl ca-certificates libcap2-bin

if ! have go; then
  echo "Go is required for naabu/httpx/nuclei: https://go.dev/dl/ (or: sudo apt install golang)" >&2
  exit 1
fi
export GOTOOLCHAIN=auto
export PATH="$HOME/go/bin:$PATH"

say "ProjectDiscovery tools (naabu, httpx, nuclei)"
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

say "nuclei templates"
nuclei -update-templates -silent || nuclei -ut

say "vulners.nse (nmap version -> CVE matching)"
NSE_DIR="$(dirname "$(nmap --script-help http-title 2>/dev/null | grep -o '/[^ ]*http-title.nse' | head -1)" 2>/dev/null || true)"
NSE_DIR="${NSE_DIR:-/usr/share/nmap/scripts}"
tmp="$(mktemp -d)"
git clone -q --depth 1 https://github.com/vulnersCom/nmap-vulners "$tmp/nmap-vulners"
sudo install -m 0644 "$tmp/nmap-vulners/vulners.nse" "$NSE_DIR/vulners.nse"
rm -rf "$tmp"
sudo nmap --script-updatedb >/dev/null

if [[ $SETCAP -eq 1 ]]; then
  say "granting cap_net_raw,cap_net_admin to nmap and naabu"
  echo "    This lets ANY local user run raw-socket scans with these binaries."
  echo "    Skip it on shared machines and use sudo instead."
  sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip "$(command -v nmap)"
  sudo setcap cap_net_raw,cap_net_admin+eip "$HOME/go/bin/naabu"
fi

say "done. Check with: ./lanrecce.sh doctor"
case ":$PATH:" in *":$HOME/go/bin:"*) ;; *) echo "    add to your shell rc:  export PATH=\"\$HOME/go/bin:\$PATH\"";; esac
