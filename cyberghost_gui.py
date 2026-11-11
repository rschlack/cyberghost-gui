#!/usr/bin/env python3
"""CyberGhost GUI - a GTK4/libadwaita front end for CyberGhost VPN on Ubuntu.

It uses NetworkManager's OpenVPN plugin (nmcli) rather than the official
CyberGhost CLI, which does not support current Ubuntu releases. You import
one OpenVPN configuration from your CyberGhost account once. The app then
reuses that configuration and switches its server to any country you pick.
"""

import json
import os
import re
import shutil
import socket
import subprocess
import sys
import threading
import urllib.request
import zipfile
import concurrent.futures as cf
from pathlib import Path

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gio, GLib, Gtk  # noqa: E402

APP_ID = "com.example.CyberGhostGUI"
APP_NAME = "CyberGhost VPN"
CONN_NAME = "CyberGhost VPN"
CONFIG_DIR = Path(GLib.get_user_config_dir()) / "cyberghost-gui"
DATA_DIR = Path(GLib.get_user_data_dir()) / "cyberghost-gui"
CONFIG_FILE = CONFIG_DIR / "config.json"
ISO_FILE = Path("/usr/share/iso-codes/json/iso_3166-1.json")
DEFAULT_HOST_PREFIX = "87-1-"
HOST_SUFFIX = ".cg-dialup.net"


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def load_config():
    try:
        return json.loads(CONFIG_FILE.read_text())
    except Exception:
        return {}


def save_config(cfg):
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(cfg, indent=2))


def run(args, timeout=90):
    """Run a command and return (ok, combined_output)."""
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        out = (p.stdout + p.stderr).strip()
        return p.returncode == 0, out
    except subprocess.TimeoutExpired:
        return False, "Timed out"
    except FileNotFoundError as e:
        return False, str(e)


def flag(cc):
    cc = cc.upper()
    if len(cc) != 2 or not cc.isalpha():
        return "🏳"
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in cc)


def all_countries():
    names = {}
    try:
        for c in json.loads(ISO_FILE.read_text())["3166-1"]:
            names[c["alpha_2"].lower()] = c.get("common_name", c["name"])
    except Exception:
        pass
    names.setdefault("gb", "United Kingdom")
    return names


def discover_countries(prefix):
    """Return sorted [(code, name)] of countries whose server hostname resolves."""
    names = all_countries()

    def check(code):
        try:
            socket.gethostbyname(f"{prefix}{code}{HOST_SUFFIX}")
            return code
        except OSError:
            return None

    with cf.ThreadPoolExecutor(48) as ex:
        found = [c for c in ex.map(check, names) if c]
    return sorted(((c, names[c]) for c in found), key=lambda x: x[1])


# --------------------------------------------------------------------------- #
# NetworkManager backend
# --------------------------------------------------------------------------- #
class NM:
    def __init__(self, uuid):
        self.uuid = uuid

    def exists(self):
        ok, _ = run(["nmcli", "-g", "connection.uuid", "connection", "show", self.uuid])
        return ok

    def vpn_data(self):
        ok, out = run(["nmcli", "-g", "vpn.data", "connection", "show", self.uuid])
        if not ok:
            return {}
        data = {}
        # nmcli escapes ":" as "\:" in -g output; items are ", " separated
        for item in re.split(r",\s(?=[\w-]+\s=)", out):
            if " = " in item:
                k, v = item.split(" = ", 1)
                data[k.strip()] = v.strip().replace("\\:", ":").replace("\\,", ",")
        return data

    def state(self):
        """Return 'activated', 'activating', 'deactivating' or '' (down)."""
        ok, out = run(["nmcli", "-g", "GENERAL.STATE", "connection", "show", self.uuid])
        return out.strip() if ok else ""

    def set_country(self, code):
        data = self.vpn_data()
        remote = data.get("remote", "")
        host, _, rest = remote.partition(":")
        m = re.match(r"^(.*-)([a-z]{2})(\.cg-dialup\.net)$", host)
        prefix = m.group(1) if m else DEFAULT_HOST_PREFIX
        new_remote = f"{prefix}{code}{HOST_SUFFIX}" + (f":{rest}" if rest else "")
        return run(["nmcli", "connection", "modify", self.uuid,
                    "+vpn.data", f"remote={new_remote}"])

    def host_prefix(self):
        host = self.vpn_data().get("remote", "").partition(":")[0]
        m = re.match(r"^(.*-)([a-z]{2})(\.cg-dialup\.net)$", host)
        return m.group(1) if m else DEFAULT_HOST_PREFIX

    def current_country(self):
        host = self.vpn_data().get("remote", "").partition(":")[0]
        m = re.match(r"^.*-([a-z]{2})\.cg-dialup\.net$", host)
        return m.group(1) if m else None

    def up(self):
        return run(["nmcli", "connection", "up", self.uuid], timeout=120)

    def down(self):
        return run(["nmcli", "connection", "down", self.uuid])

    def set_credentials(self, user, password):
        return run(["nmcli", "connection", "modify", self.uuid,
                    "vpn.user-name", user,
                    "+vpn.data", "password-flags=0",
                    "+vpn.secrets", f"password={password}"])

    def delete(self):
        return run(["nmcli", "connection", "delete", self.uuid])


def import_config(src_path, user, password):
    """Import a CyberGhost OpenVPN zip or .ovpn file into NetworkManager.

    Returns (uuid, None) on success or (None, error_message).
    """
    src = Path(src_path)
    # Keep certificates in a stable location; NetworkManager references them in place.
    if DATA_DIR.exists():
        shutil.rmtree(DATA_DIR)
    DATA_DIR.mkdir(parents=True)
    os.chmod(DATA_DIR, 0o700)

    try:
        if zipfile.is_zipfile(src):
            with zipfile.ZipFile(src) as z:
                for member in z.namelist():
                    name = Path(member).name
                    if not name or member.endswith("/"):
                        continue
                    (DATA_DIR / name).write_bytes(z.read(member))
        else:
            shutil.copy(src, DATA_DIR / src.name)
            # Copy sibling certificate files referenced by the config
            for sib in src.parent.iterdir():
                if sib.suffix in (".crt", ".key", ".pem") and sib.is_file():
                    shutil.copy(sib, DATA_DIR / sib.name)
    except Exception as e:
        return None, f"Could not read the configuration file: {e}"

    ovpns = list(DATA_DIR.glob("*.ovpn")) + list(DATA_DIR.glob("*.conf"))
    if not ovpns:
        return None, "No .ovpn file was found in the selected file."
    for f in DATA_DIR.iterdir():
        os.chmod(f, 0o600)

    ovpn = DATA_DIR / "cyberghost.ovpn"
    if ovpns[0] != ovpn:
        ovpns[0].rename(ovpn)
    text = ovpn.read_text(errors="replace")
    if "cg-dialup.net" not in text:
        return None, "This doesn't look like a CyberGhost OpenVPN configuration."

    ok, out = run(["nmcli", "connection", "import", "type", "openvpn", "file", str(ovpn)])
    if not ok:
        return None, f"NetworkManager could not import the configuration:\n{out}"
    m = re.search(r"\(([0-9a-f-]{36})\)", out)
    if not m:
        return None, f"Unexpected nmcli output:\n{out}"
    uuid = m.group(1)
    nm = NM(uuid)
    run(["nmcli", "connection", "modify", uuid, "connection.id", CONN_NAME,
         "connection.autoconnect", "no"])
    ok, out = nm.set_credentials(user, password)
    if not ok:
        nm.delete()
        return None, f"Could not save the credentials:\n{out}"
    return uuid, None


def fetch_public_ip():
    try:
        req = urllib.request.Request("https://ipinfo.io/json",
                                     headers={"User-Agent": "cyberghost-gui"})
        with urllib.request.urlopen(req, timeout=8) as r:
            d = json.loads(r.read())
        loc = ", ".join(x for x in (d.get("city"), d.get("country")) if x)
        return f"{d.get('ip', '?')}  ·  {loc}" if loc else d.get("ip", "?")
    except Exception:
        return None


# --------------------------------------------------------------------------- #
# Setup dialog
# --------------------------------------------------------------------------- #
class SetupDialog(Adw.Dialog):
    def __init__(self, on_done):
        super().__init__(title="Set up CyberGhost", content_width=520)
        self.on_done = on_done
        self.file_path = None

        tv = Adw.ToolbarView()
        header = Adw.HeaderBar()
        tv.add_top_bar(header)

        page = Adw.PreferencesPage()
        intro = Adw.PreferencesGroup(
            description=(
                "1. Sign in at my.cyberghostvpn.com → VPN → Manage Devices.\n"
                "2. Configure a new device: protocol OpenVPN, any country, "
                "then download the configuration (.zip).\n"
                "3. Copy the username and password shown for that device below.\n\n"
                "You only need one configuration. The app switches its country "
                "for you."
            )
        )
        page.add(intro)

        grp = Adw.PreferencesGroup(title="Configuration")
        self.file_row = Adw.ActionRow(title="OpenVPN configuration",
                                      subtitle="No file selected")
        btn = Gtk.Button(label="Choose…", valign=Gtk.Align.CENTER)
        btn.connect("clicked", self.on_choose)
        self.file_row.add_suffix(btn)
        self.file_row.set_activatable_widget(btn)
        grp.add(self.file_row)

        self.user_row = Adw.EntryRow(title="Username")
        self.pass_row = Adw.PasswordEntryRow(title="Password")
        grp.add(self.user_row)
        grp.add(self.pass_row)
        page.add(grp)

        btn_grp = Adw.PreferencesGroup()
        self.import_btn = Gtk.Button(label="Import", halign=Gtk.Align.CENTER)
        self.import_btn.add_css_class("suggested-action")
        self.import_btn.add_css_class("pill")
        self.import_btn.connect("clicked", self.on_import)
        self.spinner = Adw.Spinner(visible=False)
        box = Gtk.Box(spacing=12, halign=Gtk.Align.CENTER)
        box.append(self.import_btn)
        box.append(self.spinner)
        btn_grp.add(box)
        page.add(btn_grp)

        tv.set_content(page)
        self.set_child(tv)

    def on_choose(self, _btn):
        dlg = Gtk.FileDialog(title="Choose CyberGhost OpenVPN configuration")
        filt = Gtk.FileFilter(name="OpenVPN config (.zip, .ovpn)")
        for p in ("*.zip", "*.ovpn", "*.conf"):
            filt.add_pattern(p)
        store = Gio.ListStore.new(Gtk.FileFilter)
        store.append(filt)
        dlg.set_filters(store)
        downloads = GLib.get_user_special_dir(GLib.UserDirectory.DIRECTORY_DOWNLOAD)
        if downloads:
            dlg.set_initial_folder(Gio.File.new_for_path(downloads))
        dlg.open(self.get_root(), None, self._on_chosen)

    def _on_chosen(self, dlg, res):
        try:
            f = dlg.open_finish(res)
        except GLib.Error:
            return
        self.file_path = f.get_path()
        self.file_row.set_subtitle(Path(self.file_path).name)

    def on_import(self, _btn):
        user = self.user_row.get_text().strip()
        pw = self.pass_row.get_text()
        if not self.file_path or not user or not pw:
            self._error("Please choose a configuration file and enter the "
                        "username and password.")
            return
        self.import_btn.set_sensitive(False)
        self.spinner.set_visible(True)

        def work():
            uuid, err = import_config(self.file_path, user, pw)
            GLib.idle_add(self._done, uuid, err)

        threading.Thread(target=work, daemon=True).start()

    def _done(self, uuid, err):
        self.import_btn.set_sensitive(True)
        self.spinner.set_visible(False)
        if err:
            self._error(err)
            return
        self.close()
        self.on_done(uuid)

    def _error(self, msg):
        d = Adw.AlertDialog(heading="Setup problem", body=msg)
        d.add_response("ok", "OK")
        d.present(self)


# --------------------------------------------------------------------------- #
# Main window
# --------------------------------------------------------------------------- #
class MainWindow(Adw.ApplicationWindow):
    def __init__(self, app):
        super().__init__(application=app, title=APP_NAME,
                         default_width=440, default_height=720)
        self.cfg = load_config()
        self.cfg.setdefault("favorites", [])
        self.nm = NM(self.cfg["uuid"]) if self.cfg.get("uuid") else None
        self.countries = self.cfg.get("countries_cache", [])
        self.selected = self.cfg.get("last_country")
        self.state = ""
        self.busy = False
        self.connected_country = None

        self.toasts = Adw.ToastOverlay()
        tv = Adw.ToolbarView()
        header = Adw.HeaderBar()
        menu = Gio.Menu()
        menu.append("Refresh country list", "win.refresh")
        menu.append("Change username / password", "win.creds")
        menu.append("Import a different configuration", "win.setup")
        menu.append("Remove VPN connection", "win.reset")
        menu.append("About", "win.about")
        header.pack_end(Gtk.MenuButton(icon_name="open-menu-symbolic", menu_model=menu))
        tv.add_top_bar(header)

        for name, cb in (("refresh", self.refresh_countries), ("creds", self.change_creds),
                         ("setup", self.show_setup), ("reset", self.reset),
                         ("about", self.about)):
            a = Gio.SimpleAction.new(name, None)
            a.connect("activate", lambda *_a, f=cb: f())
            self.add_action(a)

        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)

        # Status card
        card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6,
                       margin_top=18, margin_bottom=12, margin_start=16, margin_end=16)
        card.add_css_class("card")
        inner = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6,
                        margin_top=18, margin_bottom=18, margin_start=18, margin_end=18)
        self.status_icon = Gtk.Image(icon_name="network-vpn-disabled-symbolic", pixel_size=48)
        self.status_title = Gtk.Label(label="Disconnected")
        self.status_title.add_css_class("title-2")
        self.status_sub = Gtk.Label(label="", wrap=True, justify=Gtk.Justification.CENTER)
        self.status_sub.add_css_class("dim-label")
        self.ip_label = Gtk.Label(label="", selectable=True)
        self.ip_label.add_css_class("caption")
        self.ip_label.add_css_class("dim-label")
        btn_box = Gtk.Box(spacing=12, halign=Gtk.Align.CENTER, margin_top=8)
        self.main_btn = Gtk.Button(label="Connect")
        self.main_btn.add_css_class("pill")
        self.main_btn.add_css_class("suggested-action")
        self.main_btn.set_size_request(180, -1)
        self.main_btn.connect("clicked", self.on_main_btn)
        self.spinner = Adw.Spinner(visible=False)
        btn_box.append(self.main_btn)
        btn_box.append(self.spinner)
        for w in (self.status_icon, self.status_title, self.status_sub, self.ip_label, btn_box):
            inner.append(w)
        card.append(inner)
        outer.append(card)

        # Search
        self.search = Gtk.SearchEntry(placeholder_text="Search countries",
                                      margin_start=16, margin_end=16, margin_bottom=8)
        self.search.connect("search-changed", lambda *_: self.listbox.invalidate_filter())
        outer.append(self.search)

        # Country list
        self.listbox = Gtk.ListBox(selection_mode=Gtk.SelectionMode.SINGLE,
                                   margin_start=16, margin_end=16, margin_bottom=16)
        self.listbox.add_css_class("boxed-list")
        self.listbox.set_filter_func(self._filter)
        self.listbox.set_sort_func(self._sort)
        self.listbox.connect("row-selected", self._on_row_selected)
        self.listbox.connect("row-activated", lambda *_: self.connect_selected())
        self.list_stack = Gtk.Stack()
        sw = Gtk.ScrolledWindow(vexpand=True, hscrollbar_policy=Gtk.PolicyType.NEVER)
        sw.set_child(self.listbox)
        loading = Adw.StatusPage(title="Finding servers…", child=Adw.Spinner())
        self.list_stack.add_named(sw, "list")
        self.list_stack.add_named(loading, "loading")
        outer.append(self.list_stack)

        tv.set_content(outer)
        self.toasts.set_child(tv)
        self.set_content(self.toasts)

        self.rows = {}
        if self.countries:
            self._populate()
        if not self.nm or not self.nm.exists():
            self.nm = None
            GLib.idle_add(self.show_setup)
        else:
            if not self.countries:
                self.refresh_countries()
        self.poll()
        GLib.timeout_add_seconds(3, self.poll)

    # ---- country list ----------------------------------------------------- #
    def _populate(self):
        child = self.listbox.get_first_child()
        while child:
            nxt = child.get_next_sibling()
            self.listbox.remove(child)
            child = nxt
        self.rows = {}
        for code, name in self.countries:
            row = Adw.ActionRow(title=name, subtitle=code.upper())
            row.code = code
            row.cname = name
            emoji = Gtk.Label(label=flag(code))
            emoji.add_css_class("title-2")
            row.add_prefix(emoji)
            star = Gtk.ToggleButton(icon_name="starred-symbolic" if code in self.cfg["favorites"]
                                    else "non-starred-symbolic",
                                    valign=Gtk.Align.CENTER,
                                    active=code in self.cfg["favorites"],
                                    tooltip_text="Favourite")
            star.add_css_class("flat")
            star.connect("toggled", self._on_star, code)
            row.star = star
            row.add_suffix(star)
            row.set_activatable(True)
            self.listbox.append(row)
            self.rows[code] = row
        if self.selected in self.rows:
            self.listbox.select_row(self.rows[self.selected])
        self.list_stack.set_visible_child_name("list")
        self._update_ui()

    def _filter(self, row):
        q = self.search.get_text().strip().lower()
        return not q or q in row.cname.lower() or q == row.code

    def _sort(self, a, b):
        fa, fb = a.code in self.cfg["favorites"], b.code in self.cfg["favorites"]
        if fa != fb:
            return -1 if fa else 1
        return (a.cname > b.cname) - (a.cname < b.cname)

    def _on_star(self, btn, code):
        favs = self.cfg["favorites"]
        if btn.get_active() and code not in favs:
            favs.append(code)
        elif not btn.get_active() and code in favs:
            favs.remove(code)
        btn.set_icon_name("starred-symbolic" if btn.get_active() else "non-starred-symbolic")
        save_config(self.cfg)
        self.listbox.invalidate_sort()

    def _on_row_selected(self, _lb, row):
        if row:
            self.selected = row.code
            self._update_ui()

    def refresh_countries(self):
        if not self.nm:
            return
        if not self.countries:
            self.list_stack.set_visible_child_name("loading")
        prefix_holder = {}

        def work():
            prefix_holder["p"] = self.nm.host_prefix()
            found = discover_countries(prefix_holder["p"])
            GLib.idle_add(self._countries_found, found)

        threading.Thread(target=work, daemon=True).start()

    def _countries_found(self, found):
        if not found:
            self.toast("Could not reach CyberGhost's servers. Check your internet connection.")
            self.list_stack.set_visible_child_name("list")
            return
        self.countries = [list(x) for x in found]
        self.cfg["countries_cache"] = self.countries
        save_config(self.cfg)
        self._populate()
        self.toast(f"{len(found)} countries available")

    # ---- connection ------------------------------------------------------- #
    def poll(self):
        if self.nm and not self.busy:
            def work():
                st = self.nm.state()
                cc = self.nm.current_country() if st else None
                GLib.idle_add(self._apply_state, st, cc)
            threading.Thread(target=work, daemon=True).start()
        return True

    def _apply_state(self, st, cc):
        if self.busy:
            return
        was = self.state
        self.state = st
        self.connected_country = cc if st else None
        if st == "activated" and was != "activated":
            self._load_ip()
        elif not st and was == "activated":
            self.ip_label.set_label("")
        self._update_ui()

    def _country_name(self, code):
        row = self.rows.get(code)
        return row.cname if row else (code or "").upper()

    def _update_ui(self):
        st = self.state
        sel = self.selected
        if self.busy or st in ("activating", "deactivating"):
            self.spinner.set_visible(True)
            self.main_btn.set_sensitive(False)
            self.status_icon.set_from_icon_name("network-vpn-acquiring-symbolic")
            if st == "deactivating" or self.busy == "down":
                self.status_title.set_label("Disconnecting…")
            else:
                self.status_title.set_label("Connecting…")
                self.status_sub.set_label(f"{flag(sel or '')}  {self._country_name(sel)}")
            return
        self.spinner.set_visible(False)
        self.main_btn.set_sensitive(bool(self.nm))
        if st == "activated":
            cc = self.connected_country
            self.status_icon.set_from_icon_name("network-vpn-symbolic")
            self.status_title.set_label("Connected")
            self.status_sub.set_label(f"{flag(cc or '')}  {self._country_name(cc)}")
            for c in ("suggested-action",):
                self.main_btn.remove_css_class(c)
            if sel and sel != cc:
                self.main_btn.set_label(f"Switch to {self._country_name(sel)}")
                self.main_btn.add_css_class("suggested-action")
                self.main_btn.remove_css_class("destructive-action")
            else:
                self.main_btn.set_label("Disconnect")
                self.main_btn.add_css_class("destructive-action")
        else:
            self.status_icon.set_from_icon_name("network-vpn-disabled-symbolic")
            self.status_title.set_label("Disconnected")
            self.main_btn.remove_css_class("destructive-action")
            self.main_btn.add_css_class("suggested-action")
            if sel:
                self.status_sub.set_label(f"Selected: {flag(sel)}  {self._country_name(sel)}")
                self.main_btn.set_label("Connect")
                self.main_btn.set_sensitive(bool(self.nm))
            else:
                self.status_sub.set_label("Choose a country below")
                self.main_btn.set_label("Connect")
                self.main_btn.set_sensitive(False)

    def on_main_btn(self, _btn):
        if self.state == "activated" and (not self.selected or
                                          self.selected == self.connected_country):
            self.disconnect_vpn()
        else:
            self.connect_selected()

    def connect_selected(self):
        if not self.nm or not self.selected or self.busy:
            return
        code = self.selected
        self.cfg["last_country"] = code
        save_config(self.cfg)
        self.busy = "up"
        self.ip_label.set_label("")
        self._update_ui()

        def work():
            if self.nm.state():
                self.nm.down()
            ok, out = self.nm.set_country(code)
            if ok:
                ok, out = self.nm.up()
            GLib.idle_add(self._after_action, ok, out, f"Connected to {self._country_name(code)}")

        threading.Thread(target=work, daemon=True).start()

    def disconnect_vpn(self):
        if not self.nm or self.busy:
            return
        self.busy = "down"
        self._update_ui()

        def work():
            ok, out = self.nm.down()
            GLib.idle_add(self._after_action, ok, out, "Disconnected")

        threading.Thread(target=work, daemon=True).start()

    def _after_action(self, ok, out, success_msg):
        self.busy = False
        if ok:
            self.toast(success_msg)
        else:
            d = Adw.AlertDialog(heading="VPN error", body=out or "Unknown error")
            d.add_response("ok", "OK")
            d.present(self)
        self.state = "?"  # force refresh of IP on next poll
        self.poll()

    def _load_ip(self):
        self.ip_label.set_label("Checking public IP…")

        def work():
            ip = fetch_public_ip()
            GLib.idle_add(self.ip_label.set_label, f"Public IP: {ip}" if ip else "")

        threading.Thread(target=work, daemon=True).start()

    # ---- menu actions ----------------------------------------------------- #
    def show_setup(self):
        SetupDialog(self._setup_done).present(self)

    def _setup_done(self, uuid):
        if self.nm and self.nm.uuid != uuid:
            self.nm.down()
            self.nm.delete()
        self.nm = NM(uuid)
        self.cfg["uuid"] = uuid
        save_config(self.cfg)
        self.toast("CyberGhost configuration imported")
        self.refresh_countries()
        self.poll()

    def change_creds(self):
        if not self.nm:
            return self.show_setup()
        d = Adw.AlertDialog(heading="Change credentials",
                            body="Enter the device username and password from your CyberGhost account.")
        box = Gtk.ListBox()
        box.add_css_class("boxed-list")
        u = Adw.EntryRow(title="Username")
        p = Adw.PasswordEntryRow(title="Password")
        box.append(u)
        box.append(p)
        d.set_extra_child(box)
        d.add_response("cancel", "Cancel")
        d.add_response("save", "Save")
        d.set_response_appearance("save", Adw.ResponseAppearance.SUGGESTED)

        def on_resp(_d, resp):
            if resp == "save" and u.get_text().strip() and p.get_text():
                ok, out = self.nm.set_credentials(u.get_text().strip(), p.get_text())
                self.toast("Credentials saved" if ok else f"Failed: {out}")

        d.connect("response", on_resp)
        d.present(self)

    def reset(self):
        if not self.nm:
            return
        d = Adw.AlertDialog(heading="Remove VPN connection?",
                            body="This removes the CyberGhost connection from NetworkManager. "
                                 "You can import a configuration again afterwards.")
        d.add_response("cancel", "Cancel")
        d.add_response("remove", "Remove")
        d.set_response_appearance("remove", Adw.ResponseAppearance.DESTRUCTIVE)

        def on_resp(_d, resp):
            if resp == "remove":
                self.nm.down()
                self.nm.delete()
                shutil.rmtree(DATA_DIR, ignore_errors=True)
                self.nm = None
                self.cfg.pop("uuid", None)
                save_config(self.cfg)
                self.state = ""
                self._update_ui()
                self.toast("VPN connection removed")

        d.connect("response", on_resp)
        d.present(self)

    def about(self):
        Adw.AboutDialog(application_name=APP_NAME, application_icon="network-vpn-symbolic",
                        version="1.0",
                        comments="Unofficial front end for CyberGhost VPN using "
                                 "NetworkManager and OpenVPN.").present(self)

    def toast(self, msg):
        self.toasts.add_toast(Adw.Toast(title=msg, timeout=3))


class App(Adw.Application):
    def __init__(self):
        super().__init__(application_id=APP_ID, flags=Gio.ApplicationFlags.DEFAULT_FLAGS)

    def do_activate(self):
        win = self.get_active_window() or MainWindow(self)
        win.present()


if __name__ == "__main__":
    if not shutil.which("nmcli"):
        print("nmcli not found: NetworkManager is required.", file=sys.stderr)
        sys.exit(1)
    sys.exit(App().run(sys.argv))
