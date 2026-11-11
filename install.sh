#!/usr/bin/env bash
# Installs CyberGhost GUI for the current user (no root needed except for missing packages).
set -euo pipefail
cd "$(dirname "$0")"

need=()
for pkg in python3-gi gir1.2-adw-1 gir1.2-gtk-4.0 network-manager-openvpn network-manager-openvpn-gnome iso-codes; do
  dpkg -s "$pkg" >/dev/null 2>&1 || need+=("$pkg")
done
if ((${#need[@]})); then
  echo "Installing missing packages: ${need[*]}"
  sudo apt install -y "${need[@]}"
fi

install -Dm755 cyberghost_gui.py "$HOME/.local/bin/cyberghost-gui"
install -Dm644 cyberghost-gui.desktop "$HOME/.local/share/applications/cyberghost-gui.desktop"
sed -i "s|^Exec=.*|Exec=$HOME/.local/bin/cyberghost-gui|" "$HOME/.local/share/applications/cyberghost-gui.desktop"
update-desktop-database "$HOME/.local/share/applications" 2>/dev/null || true
echo "Installed. Launch \"CyberGhost VPN\" from the app grid, or run: cyberghost-gui"
