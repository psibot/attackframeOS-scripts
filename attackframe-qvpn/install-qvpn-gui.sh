#!/usr/bin/env bash
# Installs qvpn-gui and adds it to the application menu.
set -e
cd "$(dirname "$0")"

sudo apt-get install -y python3-tk openvpn golang >/dev/null
CGO_ENABLED=0 go install github.com/davegallant/vpngate@latest

mkdir -p ~/.local/bin ~/.local/share/applications
install -m 755 qvpn-gui.py ~/.local/bin/qvpn-gui

cat > ~/.local/share/applications/qvpn-gui.desktop <<EOF
[Desktop Entry]
Type=Application
Name=qvpn (VPNGate)
Comment=Connect to VPNGate relays
Exec=$HOME/.local/bin/qvpn-gui
Icon=network-vpn
Terminal=false
Categories=Network;Utility;
EOF

echo "Done. Launch 'qvpn (VPNGate)' from the menu, or run: qvpn-gui"
