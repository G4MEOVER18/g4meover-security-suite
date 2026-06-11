#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
G4MEOVER Security Suite  v2.4
All-in-One Security Suite (offensiv + defensiv) – Python/tkinter, Catppuccin Mocha
Entwickelt von Yanis Ameseder
"""

import tkinter as tk
from tkinter import ttk
import json
import sys
import os
from pathlib import Path

# ─── Pfad-Setup ───────────────────────────────────────────────────────────────
_ROOT = Path(__file__).parent
sys.path.insert(0, str(_ROOT))

# ─── Config laden ─────────────────────────────────────────────────────────────
CONFIG_FILE = _ROOT / "suite_config.json"

VERSION = "2.4"
AUTHOR  = "Yanis Ameseder"
GITHUB  = "https://github.com/G4MEOVER18/g4meover-security-suite"


def _load_config() -> dict:
    if CONFIG_FILE.exists():
        try:
            return json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}


def _save_config(cfg: dict):
    try:
        CONFIG_FILE.write_text(json.dumps(cfg, indent=2, ensure_ascii=False),
                               encoding="utf-8")
    except Exception:
        pass


# ─── Imports ──────────────────────────────────────────────────────────────────
from utils.theme         import DARK, build_style
from utils.tool_detector import detect_all
from utils.icons         import build_icons, get_icon

from modules.dashboard        import DashboardModule
from modules.network          import NetworkModule
from modules.wifi_wpa         import WifiWpaModule
from modules.passwords        import PasswordModule
from modules.web              import WebModule
from modules.osint            import OsintModule
from modules.exploit_research import ExploitResearchModule
from modules.reporting        import ReportingModule
from modules.settings         import SettingsModule
from modules.help             import HelpModule
from modules.pmkid            import PmkidModule
from modules.handshake        import HandshakeModule
from modules.live_capture     import LiveCaptureModule
from modules.wordlist         import WordlistModule
from modules.isolation        import IsolationModule
from modules.hardening_audit   import HardeningAuditModule
from modules.port_exposure     import PortExposureModule
from modules.integrity_monitor import IntegrityMonitorModule
from modules.privesc_audit     import PrivescAuditModule
from modules.av_test           import AvTestModule
from modules.vuln_scan         import VulnScanModule
from modules.secrets_audit     import SecretsAuditModule
from modules.account_audit     import AccountAuditModule
from modules.firewall_audit    import FirewallAuditModule
from modules.attack_sim        import AttackSimModule
from modules.local_hashes      import LocalHashesModule
from modules.log_watcher       import LogWatcherModule


# ─── Hauptfenster ─────────────────────────────────────────────────────────────

class G4MEOVERSuite(tk.Tk):

    def __init__(self):
        super().__init__()
        self.title(f"G4MEOVER Security Suite  v{VERSION}")
        self.geometry("1400x860")
        self.minsize(1100, 700)
        self.configure(bg=DARK["bg"])

        # Fenster-Icon
        ico = _ROOT / "assets" / "g4meover.ico"
        if ico.exists():
            try:
                self.iconbitmap(str(ico))
            except Exception:
                pass

        build_style(self)
        build_icons()  # Tab-Icons nach Tk-Init generieren

        self._cfg   = _load_config()
        self._tools = detect_all(self._cfg)

        # Logo für Header + About-Dialog laden
        self._logo_header = self._load_logo(40)
        self._logo_about  = self._load_logo(72)

        self._target_var = tk.StringVar(value="")
        self._target_var.trace_add("write", self._on_target_change)

        self._build_ui()

    # ── Logo laden ────────────────────────────────────────────────────────────

    def _load_logo(self, size: int):
        """Lädt das G4MEOVER-Icon als PIL PhotoImage in gewünschter Größe."""
        try:
            from PIL import Image, ImageTk
            ico = _ROOT / "assets" / "g4meover.ico"
            if ico.exists():
                img = Image.open(str(ico))
                img = img.resize((size, size), Image.LANCZOS)
                photo = ImageTk.PhotoImage(img)
                return photo
        except Exception:
            pass
        return None

    # ── UI-Aufbau ─────────────────────────────────────────────────────────────

    def _build_ui(self):
        self._build_header()
        self._build_notebook()
        self._build_statusbar()

    def _build_header(self):
        header = tk.Frame(self, bg=DARK["panel"], height=52)
        header.pack(fill="x", side="top")
        header.pack_propagate(False)

        # Trennlinie unten
        tk.Frame(self, bg=DARK["border"], height=1).pack(fill="x", side="top")

        # Logo
        if self._logo_header:
            logo_lbl = tk.Label(header, image=self._logo_header,
                                bg=DARK["panel"], cursor="hand2")
            logo_lbl.pack(side="left", padx=(10, 4), pady=6)
            logo_lbl.bind("<Button-1>", lambda _: self._show_about())

        # Titel
        title_frame = tk.Frame(header, bg=DARK["panel"])
        title_frame.pack(side="left", padx=(2, 0))

        title_lbl = tk.Label(title_frame,
                             text="G4MEOVER",
                             bg=DARK["panel"], fg=DARK["accent"],
                             font=("Segoe UI", 14, "bold"), cursor="hand2")
        title_lbl.pack(side="left")
        title_lbl.bind("<Button-1>", lambda _: self._show_about())

        tk.Label(title_frame, text=" Security Suite",
                 bg=DARK["panel"], fg=DARK["fg"],
                 font=("Segoe UI", 14)).pack(side="left")

        ver_badge = tk.Label(title_frame,
                             text=f" v{VERSION} ",
                             bg=DARK["accent"], fg=DARK["bg"],
                             font=("Segoe UI", 7, "bold"),
                             relief="flat")
        ver_badge.pack(side="left", padx=(6, 0), pady=16)

        # Vertikaler Separator
        tk.Frame(header, bg=DARK["border"], width=1).pack(
            side="left", fill="y", padx=16, pady=10)

        # Globale Ziel-Bar
        tk.Label(header, text="Ziel:",
                 bg=DARK["panel"], fg=DARK["border"],
                 font=("Segoe UI", 9)).pack(side="left", padx=(0, 4))

        ziel_entry = tk.Entry(header, textvariable=self._target_var,
                              bg=DARK["entry"], fg=DARK["fg"],
                              insertbackground=DARK["accent"],
                              relief="flat", font=("Segoe UI", 10), width=28,
                              highlightthickness=1,
                              highlightcolor=DARK["accent"],
                              highlightbackground=DARK["border"])
        ziel_entry.pack(side="left", ipady=5, pady=10)

        tk.Label(header, text="IP / Domain / CIDR",
                 bg=DARK["panel"], fg=DARK["border"],
                 font=("Segoe UI", 7, "italic")).pack(side="left", padx=4)

        ttk.Button(header, text="Alle setzen",
                   command=self._set_all_targets).pack(side="left", padx=4)

        # Rechts: About-Button + Autor
        ttk.Button(header, text="?",
                   command=self._show_about,
                   width=3).pack(side="right", padx=(4, 10), pady=10)

        tk.Label(header, text=f"by {AUTHOR}",
                 bg=DARK["panel"], fg=DARK["border"],
                 font=("Segoe UI", 7)).pack(side="right", padx=4)

    def _build_notebook(self):
        # Äußeres Notebook (Kategorien)
        self._nb = ttk.Notebook(self)
        self._nb.pack(fill="both", expand=True)

        common = dict(cfg=self._cfg, target_var=self._target_var,
                      activity_cb=self._activity_cb, tools=self._tools)
        self._module_location = {}   # module → (group_frame, inner_nb)

        def _add_top(module, icon_key, label):
            ico = get_icon(icon_key)
            if ico:
                self._nb.add(module, text=label, image=ico, compound="left")
            else:
                self._nb.add(module, text=label)

        def _make_group(icon_key, label):
            frame = ttk.Frame(self._nb)
            inner = ttk.Notebook(frame)
            inner.pack(fill="both", expand=True)
            ico = get_icon(icon_key)
            if ico:
                self._nb.add(frame, text=label, image=ico, compound="left")
            else:
                self._nb.add(frame, text=label)
            return frame, inner

        def _add_sub(group, cls, icon_key, label):
            module = cls(group[1], **common)
            ico = get_icon(icon_key)
            if ico:
                group[1].add(module, text=label, image=ico, compound="left")
            else:
                group[1].add(module, text=label)
            self._module_location[module] = group
            return module

        # ── Dashboard (Top-Level) ───────────────────────────────────────────────
        self._dashboard = DashboardModule(
            self._nb, cfg=self._cfg, target_var=self._target_var,
            activity_cb=self._activity_cb, tools=self._tools,
            notebook_select_cb=self._navigate)
        _add_top(self._dashboard, "dashboard", "  Dashboard ")

        # ── Recon ────────────────────────────────────────────────────────────────
        g = _make_group("network", "  Recon ")
        self._network = _add_sub(g, NetworkModule,          "network",  "  Netzwerk     ")
        self._osint   = _add_sub(g, OsintModule,            "osint",    "  OSINT        ")
        self._web     = _add_sub(g, WebModule,              "web",      "  Web-Testing  ")
        self._exploit = _add_sub(g, ExploitResearchModule,  "exploits", "  Exploits     ")
        self._live    = _add_sub(g, LiveCaptureModule,      "network",  "  Live Capture ")

        # ── WLAN ───────────────────────────────────────────────────────────────
        g = _make_group("wifi", "  WLAN ")
        self._wifi      = _add_sub(g, WifiWpaModule,    "wifi",      "  WiFi / WPA  ")
        self._handshake = _add_sub(g, HandshakeModule,  "handshake", "  Handshake   ")
        self._pmkid     = _add_sub(g, PmkidModule,      "pmkid",     "  PMKID       ")
        self._isolation = _add_sub(g, IsolationModule,  "wifi",      "  Isolation   ")

        # ── Passwörter & Secrets ────────────────────────────────────────────────
        g = _make_group("passwords", "  Passwörter ")
        self._passwords = _add_sub(g, PasswordModule,      "passwords", "  Passwörter ")
        self._wordlist  = _add_sub(g, WordlistModule,      "passwords", "  Wordlists  ")
        self._secrets   = _add_sub(g, SecretsAuditModule,  "passwords", "  Secrets    ")

        # ── Härtung (Defensive Audits) ──────────────────────────────────────────
        g = _make_group("settings", "  Härtung ")
        self._hardening = _add_sub(g, HardeningAuditModule, "settings",  "  Hardening ")
        self._account   = _add_sub(g, AccountAuditModule,   "settings",  "  Konten    ")
        self._firewall  = _add_sub(g, FirewallAuditModule,  "network",   "  Firewall  ")
        self._avtest    = _add_sub(g, AvTestModule,         "wifi",      "  AV / EDR  ")

        # ── Angriffstests ────────────────────────────────────────────────────────
        g = _make_group("exploits", "  Angriffstests ")
        self._privesc   = _add_sub(g, PrivescAuditModule, "exploits",  "  Privesc       ")
        self._exposure  = _add_sub(g, PortExposureModule, "network",   "  Exposure      ")
        self._vuln      = _add_sub(g, VulnScanModule,     "exploits",  "  Vuln-Scan     ")
        self._attacksim = _add_sub(g, AttackSimModule,    "exploits",  "  EDR-Tests     ")
        self._localhash = _add_sub(g, LocalHashesModule,  "passwords", "  Passwort-Audit ")

        # ── Forensik / Monitoring ────────────────────────────────────────────────
        g = _make_group("osint", "  Forensik ")
        self._integrity = _add_sub(g, IntegrityMonitorModule, "reporting", "  Integrität  ")
        self._logs      = _add_sub(g, LogWatcherModule,       "osint",     "  Event-Logs  ")

        # ── Top-Level: Reporting / Einstellungen / Hilfe ─────────────────────────
        self._reporting = ReportingModule(self._nb, **common)
        _add_top(self._reporting, "reporting", "  Reporting ")
        self._settings = SettingsModule(self._nb, **common)
        _add_top(self._settings, "settings", "  Einstellungen ")
        self._help = HelpModule(self._nb, **common)
        _add_top(self._help, "help", "  Hilfe ")

        # Audit-Module mit dem Reporting verdrahten → Befunde als Findings
        for _m in (self._hardening, self._exposure, self._integrity,
                   self._privesc, self._avtest, self._vuln,
                   self._secrets, self._account, self._firewall,
                   self._attacksim, self._localhash):
            _m._report_cb = self._reporting.add_finding

        self._nb.bind("<<NotebookTabChanged>>", self._on_tab_change)

    def _navigate(self, key):
        """Springt zu einem Modul – auch in verschachtelten Kategorie-Notebooks.

        key: String-Alias (vom Dashboard) oder direkt ein Modul-Widget.
        """
        aliases = {
            "network": getattr(self, "_network", None),
            "wifi":    getattr(self, "_wifi", None),
            "web":     getattr(self, "_web", None),
            "osint":   getattr(self, "_osint", None),
        }
        module = aliases.get(key) if isinstance(key, str) else key
        if module is None:
            return
        loc = self._module_location.get(module)
        if loc:
            frame, inner = loc
            self._nb.select(frame)
            inner.select(module)
        else:
            self._nb.select(module)

    def _build_statusbar(self):
        tk.Frame(self, bg=DARK["border"], height=1).pack(fill="x", side="bottom")

        status_bar = tk.Frame(self, bg=DARK["panel"], height=24)
        status_bar.pack(fill="x", side="bottom")
        status_bar.pack_propagate(False)

        # Status-Dot (Aktivitätsanzeige)
        self._dot_var = tk.StringVar(value="●")
        self._dot_lbl = tk.Label(status_bar, textvariable=self._dot_var,
                                 bg=DARK["panel"], fg=DARK["border"],
                                 font=("Segoe UI", 8))
        self._dot_lbl.pack(side="left", padx=(8, 2))

        self._status_var = tk.StringVar(value="Bereit.")
        tk.Label(status_bar, textvariable=self._status_var,
                 bg=DARK["panel"], fg=DARK["fg"],
                 font=("Segoe UI", 8),
                 anchor="w").pack(side="left", padx=2, fill="x", expand=True)

        # Rechts: Tool-Zähler
        installed = sum(1 for v in self._tools.values() if v)
        total     = len(self._tools)
        clr       = DARK["green"] if installed >= total * 0.6 else DARK["yellow"]
        badge = tk.Label(status_bar,
                         text=f" {installed}/{total} Tools  ",
                         bg=clr, fg=DARK["bg"],
                         font=("Segoe UI", 7, "bold"))
        badge.pack(side="right", padx=8, pady=4)

        # GitHub-Link
        gh_lbl = tk.Label(status_bar,
                          text="GitHub",
                          bg=DARK["panel"], fg=DARK["border"],
                          font=("Segoe UI", 7, "underline"), cursor="hand2")
        gh_lbl.pack(side="right", padx=(0, 4))
        gh_lbl.bind("<Button-1>", lambda _: self._open_url(GITHUB))

    # ── Callbacks ─────────────────────────────────────────────────────────────

    def _activity_cb(self, text: str):
        if hasattr(self, "_status_var"):
            self._status_var.set(text[:140])
        if hasattr(self, "_dot_lbl"):
            # Dot kurz aufleuchten lassen
            self._dot_lbl.configure(fg=DARK["accent"])
            self.after(600, lambda: self._dot_lbl.configure(fg=DARK["border"]))
        if hasattr(self, "_dashboard"):
            self._dashboard.add_activity(text)

    def _on_target_change(self, *_):
        pass

    def _set_all_targets(self):
        target = self._target_var.get().strip()
        if not target:
            return
        self._activity_cb(f"Ziel gesetzt: {target}")

    def _on_tab_change(self, _):
        pass

    def _open_url(self, url: str):
        import webbrowser
        try:
            webbrowser.open(url)
        except Exception:
            pass

    # ── About-Dialog ──────────────────────────────────────────────────────────

    def _show_about(self):
        win = tk.Toplevel(self)
        win.title("Über G4MEOVER Security Suite")
        win.geometry("500x480")
        win.resizable(False, False)
        win.configure(bg=DARK["bg"])
        win.grab_set()
        win.focus_set()

        # ── Logo + Titel ──────────────────────────────────────────────────────
        top = tk.Frame(win, bg=DARK["panel"])
        top.pack(fill="x")

        if self._logo_about:
            tk.Label(top, image=self._logo_about,
                     bg=DARK["panel"]).pack(pady=(18, 6))

        tk.Label(top, text="G4MEOVER Security Suite",
                 bg=DARK["panel"], fg=DARK["accent"],
                 font=("Segoe UI", 15, "bold")).pack()

        badge_f = tk.Frame(top, bg=DARK["panel"])
        badge_f.pack(pady=(4, 0))
        tk.Label(badge_f, text=f" v{VERSION} ",
                 bg=DARK["accent"], fg=DARK["bg"],
                 font=("Segoe UI", 9, "bold")).pack(side="left", padx=4)
        tk.Label(badge_f, text="All-in-One Security Suite · offensiv + defensiv",
                 bg=DARK["panel"], fg=DARK["border"],
                 font=("Segoe UI", 8, "italic")).pack(side="left")

        tk.Frame(top, bg=DARK["panel"], height=14).pack()

        # ── Autor ─────────────────────────────────────────────────────────────
        tk.Frame(win, bg=DARK["border"], height=1).pack(fill="x")
        mid = tk.Frame(win, bg=DARK["bg"])
        mid.pack(fill="x", padx=24, pady=10)

        tk.Label(mid, text="Entwickelt von",
                 bg=DARK["bg"], fg=DARK["border"],
                 font=("Segoe UI", 8)).pack(anchor="w")
        tk.Label(mid, text=AUTHOR,
                 bg=DARK["bg"], fg=DARK["fg"],
                 font=("Segoe UI", 12, "bold")).pack(anchor="w")

        link_row = tk.Frame(mid, bg=DARK["bg"])
        link_row.pack(anchor="w", pady=(2, 0))

        gh_lbl = tk.Label(link_row, text=GITHUB,
                          bg=DARK["bg"], fg=DARK["accent"],
                          font=("Segoe UI", 8, "underline"), cursor="hand2")
        gh_lbl.pack(side="left")
        gh_lbl.bind("<Button-1>", lambda _: self._open_url(GITHUB))

        # ── Tools ─────────────────────────────────────────────────────────────
        tk.Frame(win, bg=DARK["border"], height=1).pack(fill="x")
        tk.Label(win, text="Integrierte Tools",
                 bg=DARK["bg"], fg=DARK["border"],
                 font=("Segoe UI", 8, "bold")).pack(anchor="w", padx=24, pady=(8, 2))

        tools_frame = tk.Frame(win, bg=DARK["panel"],
                               highlightthickness=1,
                               highlightbackground=DARK["border"])
        tools_frame.pack(fill="x", padx=24, pady=(0, 4))

        tool_info = {
            "nmap":        ("Port-Scanner",              DARK["teal"]),
            "masscan":     ("Schnell-Port-Scanner",      DARK["teal"]),
            "hashcat":     ("GPU Hash-Cracker",          DARK["purple"]),
            "john":        ("Password Cracker",          DARK["purple"]),
            "hydra":       ("Brute-Force Online",        DARK["orange"]),
            "gobuster":    ("Directory Bruteforce",      DARK["accent"]),
            "feroxbuster": ("Dir-Scanner (rekursiv)",    DARK["accent"]),
            "nikto":       ("Web-Schwachstellen",        DARK["yellow"]),
            "sqlmap":      ("SQL-Injection",             DARK["red"]),
            "tshark":      ("Paket-Analyse / Capture",  DARK["green"]),
            "msfconsole":  ("Metasploit Framework",     DARK["red"]),
            "searchsploit":("ExploitDB",                DARK["orange"]),
            "whatweb":     ("Web Fingerprinting",        DARK["teal"]),
        }

        cols = 2
        items = list(tool_info.items())
        for i, (tool, (desc, col)) in enumerate(items):
            ok  = bool(self._tools.get(tool))
            row = i // cols
            c   = i % cols
            cell = tk.Frame(tools_frame, bg=DARK["panel"])
            cell.grid(row=row, column=c, sticky="ew", padx=6, pady=2)

            dot = tk.Label(cell, text="●",
                           bg=DARK["panel"],
                           fg=DARK["green"] if ok else DARK["red"],
                           font=("Segoe UI", 8))
            dot.pack(side="left")
            tk.Label(cell, text=f" {tool}",
                     bg=DARK["panel"], fg=col if ok else DARK["border"],
                     font=("Consolas", 8, "bold" if ok else "normal"),
                     width=13, anchor="w").pack(side="left")
            tk.Label(cell, text=desc,
                     bg=DARK["panel"], fg=DARK["border"],
                     font=("Segoe UI", 7)).pack(side="left")

        tools_frame.columnconfigure(0, weight=1)
        tools_frame.columnconfigure(1, weight=1)

        # ── Disclaimer ────────────────────────────────────────────────────────
        disc = tk.Label(win,
                        text="Nur für autorisierte Sicherheitstests, CTF & Bildung.",
                        bg=DARK["bg"], fg=DARK["border"],
                        font=("Segoe UI", 7, "italic"))
        disc.pack(pady=(6, 0))

        ttk.Button(win, text="Schließen", command=win.destroy,
                   style="Accent.TButton").pack(pady=10)


# ─── Einstiegspunkt ───────────────────────────────────────────────────────────

def main():
    app = G4MEOVERSuite()
    app.protocol("WM_DELETE_WINDOW", lambda: (app.destroy(), sys.exit(0)))
    app.mainloop()


if __name__ == "__main__":
    main()
