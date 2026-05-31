#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
G4MEOVER Security Suite
All-in-One Pentesting GUI – Python/tkinter, Catppuccin Mocha
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
from utils.theme        import DARK, build_style
from utils.tool_detector import detect_all

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


# ─── Hauptfenster ─────────────────────────────────────────────────────────────

class G4MEOVERSuite(tk.Tk):

    def __init__(self):
        super().__init__()
        self.title("G4MEOVER Security Suite  v1.3")
        self.geometry("1400x860")
        self.minsize(1100, 700)
        self.configure(bg=DARK["bg"])

        # Icon setzen (optional)
        ico = _ROOT / "assets" / "g4meover.ico"
        if ico.exists():
            try:
                self.iconbitmap(str(ico))
            except Exception:
                pass

        build_style(self)

        self._cfg   = _load_config()
        self._tools = detect_all(self._cfg)

        self._target_var = tk.StringVar(value="")
        self._target_var.trace_add("write", self._on_target_change)

        self._build_ui()

    # ── UI-Aufbau ─────────────────────────────────────────────────────────────

    def _build_ui(self):
        # ── Kopfzeile ─────────────────────────────────────────────────────────
        header = tk.Frame(self, bg=DARK["panel"], height=46)
        header.pack(fill="x", side="top")
        header.pack_propagate(False)

        title_lbl = tk.Label(header, text="  G4MEOVER Security Suite",
                 bg=DARK["panel"], fg=DARK["accent"],
                 font=("Segoe UI", 13, "bold"), cursor="hand2")
        title_lbl.pack(side="left", padx=8)
        title_lbl.bind("<Button-1>", lambda _: self._show_about())

        # Globale Ziel-Bar
        tk.Label(header, text="Ziel:",
                 bg=DARK["panel"], fg=DARK["border"],
                 font=("Segoe UI", 9)).pack(side="left", padx=(20, 4))
        tk.Entry(header, textvariable=self._target_var,
                 bg=DARK["entry"], fg=DARK["fg"],
                 insertbackground=DARK["fg"], relief="flat",
                 font=("Segoe UI", 10, "bold"), width=28).pack(
            side="left", ipady=4, pady=8)
        tk.Label(header, text="IP / Domain / CIDR",
                 bg=DARK["panel"], fg=DARK["border"],
                 font=("Segoe UI", 7, "italic")).pack(side="left", padx=4)
        ttk.Button(header, text="Alle Module setzen",
                   command=self._set_all_targets).pack(side="left", padx=8)

        ttk.Button(header, text="?", width=3,
                   command=self._show_about).pack(side="right", padx=4, pady=8)
        version_lbl = tk.Label(header, text="v1.3  |  by Yanis Ameseder",
                               bg=DARK["panel"], fg=DARK["border"],
                               font=("Segoe UI", 7))
        version_lbl.pack(side="right", padx=4)

        # ── Notebook ──────────────────────────────────────────────────────────
        self._nb = ttk.Notebook(self)
        self._nb.pack(fill="both", expand=True, padx=0, pady=0)

        common = dict(cfg=self._cfg, target_var=self._target_var,
                      activity_cb=self._activity_cb, tools=self._tools)

        self._dashboard = DashboardModule(
            self._nb, cfg=self._cfg, target_var=self._target_var,
            activity_cb=self._activity_cb, tools=self._tools,
            notebook_select_cb=self._nb.select)

        self._network   = NetworkModule(self._nb, **common)
        self._wifi      = WifiWpaModule(self._nb, **common)
        self._passwords = PasswordModule(self._nb, **common)
        self._web       = WebModule(self._nb, **common)
        self._osint     = OsintModule(self._nb, **common)
        self._exploit   = ExploitResearchModule(self._nb, **common)
        self._reporting = ReportingModule(self._nb, **common)
        self._settings  = SettingsModule(self._nb, **common)
        self._pmkid     = PmkidModule(self._nb, **common)
        self._help      = HelpModule(self._nb, **common)

        tab_defs = [
            (self._dashboard, "  Dashboard  "),
            (self._network,   "  Netzwerk   "),
            (self._wifi,      "  WiFi / WPA "),
            (self._pmkid,     "  PMKID      "),
            (self._passwords, "  Passwörter "),
            (self._web,       "  Web-Testing"),
            (self._osint,     "  OSINT      "),
            (self._exploit,   "  Exploits   "),
            (self._reporting, "  Reporting  "),
            (self._settings,  "  Einstellungen"),
            (self._help,      "  Hilfe  "),
        ]
        for module, label in tab_defs:
            self._nb.add(module, text=label)

        # Tab-Wechsel-Callback für Dashboard Quickstart
        self._nb.bind("<<NotebookTabChanged>>", self._on_tab_change)

        # ── Statuszeile ───────────────────────────────────────────────────────
        status_bar = tk.Frame(self, bg=DARK["panel"], height=22)
        status_bar.pack(fill="x", side="bottom")
        status_bar.pack_propagate(False)

        self._status_var = tk.StringVar(value="Bereit.")
        tk.Label(status_bar, textvariable=self._status_var,
                 bg=DARK["panel"], fg=DARK["border"],
                 font=("Segoe UI", 7)).pack(side="left", padx=8)

        installed = sum(1 for v in self._tools.values() if v)
        tool_lbl  = tk.Label(status_bar,
                             text=f"{installed}/{len(self._tools)} Tools erkannt",
                             bg=DARK["panel"],
                             fg=DARK["green"] if installed > 4 else DARK["yellow"],
                             font=("Segoe UI", 7))
        tool_lbl.pack(side="right", padx=8)

    # ── Callbacks ─────────────────────────────────────────────────────────────

    def _activity_cb(self, text: str):
        self._status_var.set(text[:120])
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

    def _show_about(self):
        """Über-Dialog mit Creator-Info und Tool-Liste."""
        win = tk.Toplevel(self)
        win.title("Über G4MEOVER Security Suite")
        win.geometry("480x420")
        win.resizable(False, False)
        win.configure(bg=DARK["bg"])
        win.grab_set()

        tk.Label(win, text="G4MEOVER Security Suite",
                 bg=DARK["bg"], fg=DARK["accent"],
                 font=("Segoe UI", 16, "bold")).pack(pady=(20, 4))
        tk.Label(win, text="v1.3",
                 bg=DARK["bg"], fg=DARK["border"],
                 font=("Segoe UI", 10)).pack()

        tk.Frame(win, bg=DARK["border"], height=1).pack(fill="x", padx=30, pady=12)

        tk.Label(win, text="Entwickelt von",
                 bg=DARK["bg"], fg=DARK["border"],
                 font=("Segoe UI", 8)).pack()
        tk.Label(win, text="Yanis Ameseder",
                 bg=DARK["bg"], fg=DARK["fg"],
                 font=("Segoe UI", 13, "bold")).pack(pady=(2, 2))
        tk.Label(win, text="g4me.over.18@gmail.com",
                 bg=DARK["bg"], fg=DARK["border"],
                 font=("Segoe UI", 8)).pack()

        tk.Frame(win, bg=DARK["border"], height=1).pack(fill="x", padx=30, pady=12)

        tk.Label(win, text="Integrierte Tools",
                 bg=DARK["bg"], fg=DARK["border"],
                 font=("Segoe UI", 8, "bold")).pack()
        tool_info = tk.Text(win, height=8, width=52,
                            bg=DARK["panel"], fg=DARK["fg"],
                            relief="flat", font=("Consolas", 8),
                            state="normal")
        tool_info.pack(padx=20, pady=4)
        tool_names = {
            "nmap": "Port-Scanner", "masscan": "Schnell-Scanner",
            "gobuster": "Dir-Bruteforce", "feroxbuster": "Dir-Bruteforce (rekursiv)",
            "nikto": "Web-Schwachstellen", "sqlmap": "SQL-Injection",
            "hydra": "Brute-Force Online", "john": "Password Cracker",
            "hashcat": "GPU Hash Cracker", "tshark": "Paket-Analyse",
            "msfconsole": "Metasploit", "searchsploit": "ExploitDB",
            "whatweb": "Web Fingerprinting",
        }
        for t, desc in tool_names.items():
            status = "✓" if self._tools.get(t) else "✗"
            color  = DARK["green"] if self._tools.get(t) else DARK["red"]
            tool_info.insert("end", f"  {status} {t:<14} {desc}\n")
            start = tool_info.index(f"end-{len(desc)+t.__len__()+6}c linestart")
            tool_info.tag_add(f"col_{t}", f"end-{len(desc)+t.__len__()+6+2}c",
                              f"end-{len(desc)+t.__len__()+4}c")
            tool_info.tag_configure(f"col_{t}", foreground=color)
        tool_info.configure(state="disabled")

        ttk.Button(win, text="Schließen", command=win.destroy).pack(pady=10)


# ─── Einstiegspunkt ───────────────────────────────────────────────────────────

def main():
    app = G4MEOVERSuite()
    app.protocol("WM_DELETE_WINDOW", lambda: (app.destroy(), sys.exit(0)))
    app.mainloop()


if __name__ == "__main__":
    main()
