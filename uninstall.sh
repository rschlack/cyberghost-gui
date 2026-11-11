#!/usr/bin/env bash
# Removes the app. Your NetworkManager VPN connection stays unless you remove it in the app first.
rm -f "$HOME/.local/bin/cyberghost-gui" "$HOME/.local/share/applications/cyberghost-gui.desktop"
echo "Uninstalled. Settings remain in ~/.config/cyberghost-gui and ~/.local/share/cyberghost-gui."
