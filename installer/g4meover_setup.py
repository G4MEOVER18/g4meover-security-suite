#!/usr/bin/env python3
"""
G4MEOVER Security Suite – Installer v2.3
Alle Tools sind direkt im Installer eingebettet (offline-fähig).
Nur nmap, Wireshark und hashcat werden per winget/Download nachgeladen.
"""
import sys
import os
import tkinter as tk
from tkinter import ttk, filedialog
import threading
import subprocess
import urllib.request
import json
import shutil
import time
import winreg
from pathlib import Path

VERSION    = "2.3"
SUITE_NAME = "G4MEOVER Security Suite"
AUTHOR     = "Yanis Ameseder"
GITHUB     = "https://github.com/G4MEOVER18/g4meover-security-suite"

# Catppuccin Mocha
BG     = "#1e1e2e"
PANEL  = "#313244"
ACCENT = "#89b4fa"
GREEN  = "#a6e3a1"
RED    = "#f38ba8"
YELLOW = "#f9e2af"
FG     = "#cdd6f4"
BORDER = "#585b70"
MAUVE  = "#cba6f7"

DEFAULT_INSTALL = Path("C:/tools/G4MEOVER")

# Installer-internes Daten-Verzeichnis (PyInstaller: _MEIPASS)
def _data(rel: str) -> Path:
    base = Path(getattr(sys, "_MEIPASS", Path(__file__).parent.parent))
    return base / rel


# ─── Installations-Schritte ───────────────────────────────────────────────────

class InstallStep:
    def __init__(self, name: str, desc: str, default: bool = True):
        self.name    = name
        self.desc    = desc
        self.default = default
        self.var: tk.BooleanVar | None = None

STEPS = [
    InstallStep("G4MEOVER Suite",        "Hauptprogramm (Python-Skripte + Module)"),
    InstallStep("Python-Pakete",         "scapy, pillow, requests, pywin32 (pip install)"),
    InstallStep("gobuster",              "Directory-Bruteforce [eingebettet, ~9 MB]"),
    InstallStep("feroxbuster",           "Rekursiver Dir-Scanner [eingebettet, ~6 MB]"),
    InstallStep("John the Ripper",       "Password Cracker [eingebettet, ~7 MB]"),
    InstallStep("sqlmap",                "SQL-Injection (pip install)"),
    InstallStep("ExploitDB + SearchSploit","47.000+ Exploits [eingebettet, ~10 MB]"),
    InstallStep("nikto",                 "Web-Scanner [eingebettet, ~2 MB]"),
    InstallStep("Hydra (Python)",        "Online-Brute-Force SSH/FTP/HTTP [eingebettet]"),
    InstallStep("Masscan (Python)",      "Schnell-Port-Scanner [eingebettet]"),
    InstallStep("WhatWeb (Python)",      "Web-Fingerprinting [eingebettet]"),
    InstallStep("nmap",                  "Port-Scanner [winget install – Internet nötig]"),
    InstallStep("Wireshark / tshark",    "Paket-Analyse [winget install – Internet nötig]"),
    InstallStep("hashcat",               "GPU Hash-Cracker [Download ~35 MB]"),
    InstallStep("Desktop-Verknüpfung",   "Startet G4MEOVER Suite per Doppelklick"),
    InstallStep("Startmenü-Eintrag",     "G4MEOVER Suite im Windows-Startmenü"),
]


# ─── Installer ────────────────────────────────────────────────────────────────

class InstallerApp(tk.Tk):

    def __init__(self):
        super().__init__()
        self.title(f"{SUITE_NAME} – Setup v{VERSION}")
        self.geometry("860x640")
        self.resizable(False, False)
        self.configure(bg=BG)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        self._install_dir = tk.StringVar(value=str(DEFAULT_INSTALL))
        self._page        = 0
        self._installing  = False

        for step in STEPS:
            step.var = tk.BooleanVar(value=step.default)

        self._build()
        self._show(0)

    def _on_close(self):
        if self._installing:
            return
        self.destroy()

    # ── UI ────────────────────────────────────────────────────────────────────

    def _build(self):
        # Header
        hdr = tk.Frame(self, bg=PANEL, height=72)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        tk.Label(hdr, text=f"  {SUITE_NAME}",
                 bg=PANEL, fg=ACCENT,
                 font=("Segoe UI", 15, "bold")).pack(side="left", padx=16)
        tk.Label(hdr, text=f"v{VERSION}  ·  {AUTHOR}",
                 bg=PANEL, fg=BORDER, font=("Segoe UI", 8)).pack(side="right", padx=16)

        self._pages: list[tk.Frame] = []
        self._content = tk.Frame(self, bg=BG)
        self._content.pack(fill="both", expand=True)

        # ── Seite 0: Willkommen ───────────────────────────────────────────────
        p0 = tk.Frame(self._content, bg=BG); self._pages.append(p0)
        tk.Label(p0, text="Willkommen bei G4MEOVER",
                 bg=BG, fg=FG, font=("Segoe UI", 17, "bold")).pack(pady=(36, 10))
        tk.Label(p0,
            text="Dieser Assistent richtet die G4MEOVER Security Suite ein –\n"
                 "inklusive aller Sicherheitstools, direkt einsatzbereit.\n\n"
                 "Die meisten Tools sind bereits im Installer eingebettet.\n"
                 "Nur nmap, Wireshark und hashcat werden nachgeladen.\n\n"
                 "Empfohlen: Ausführen als Administrator",
            bg=BG, fg=FG, font=("Segoe UI", 11), justify="center").pack(pady=6)
        tk.Label(p0,
            text="⚠  Nur für autorisierte Sicherheitstests und CTF-Challenges!",
            bg=BG, fg=YELLOW, font=("Segoe UI", 9, "bold")).pack(pady=(14, 0))
        tk.Label(p0, text=GITHUB, bg=BG, fg=ACCENT,
                 font=("Segoe UI", 8, "underline")).pack(pady=2)

        # ── Seite 1: Pfad ─────────────────────────────────────────────────────
        p1 = tk.Frame(self._content, bg=BG); self._pages.append(p1)
        tk.Label(p1, text="Installationspfad",
                 bg=BG, fg=FG, font=("Segoe UI", 14, "bold")).pack(pady=(28, 8))
        tk.Label(p1, text="Alle Dateien werden in diesen Ordner installiert:",
                 bg=BG, fg=BORDER, font=("Segoe UI", 9)).pack()
        prow = tk.Frame(p1, bg=BG); prow.pack(fill="x", padx=50, pady=12)
        tk.Entry(prow, textvariable=self._install_dir,
                 bg=PANEL, fg=FG, insertbackground=FG,
                 relief="flat", font=("Consolas", 10)).pack(
            side="left", fill="x", expand=True, ipady=6, padx=(0, 8))
        tk.Button(prow, text="…", bg=PANEL, fg=FG, relief="flat",
                  cursor="hand2", command=self._browse,
                  padx=10, pady=4).pack(side="left")

        # Größen-Info
        info = tk.Frame(p1, bg=PANEL, padx=24, pady=14)
        info.pack(padx=50, pady=10, fill="x")
        sizes = [
            ("Eingebettet (offline):", "~35 MB"),
            ("nmap (winget):",         "~30 MB"),
            ("Wireshark (winget):",    "~120 MB"),
            ("hashcat (Download):",    "~35 MB"),
            ("Gesamt ca.:",            "~220 MB"),
        ]
        for label, val in sizes:
            r = tk.Frame(info, bg=PANEL); r.pack(fill="x", pady=1)
            tk.Label(r, text=label, bg=PANEL, fg=BORDER,
                     font=("Segoe UI", 8), width=24, anchor="w").pack(side="left")
            tk.Label(r, text=val, bg=PANEL, fg=FG,
                     font=("Segoe UI", 8, "bold")).pack(side="left")

        tk.Label(p1,
            text="Tipp: Verwende C:\\tools\\G4MEOVER  oder  D:\\G4MEOVER",
            bg=BG, fg=BORDER, font=("Segoe UI", 8, "italic")).pack(pady=4)

        # ── Seite 2: Auswahl ──────────────────────────────────────────────────
        p2 = tk.Frame(self._content, bg=BG); self._pages.append(p2)
        tk.Label(p2, text="Komponenten",
                 bg=BG, fg=FG, font=("Segoe UI", 14, "bold")).pack(pady=(18, 4))
        tk.Label(p2, text="Wähle welche Komponenten installiert werden:",
                 bg=BG, fg=BORDER, font=("Segoe UI", 9)).pack(pady=(0, 8))

        sf = tk.Frame(p2, bg=BG); sf.pack(fill="both", expand=True, padx=50)
        cv = tk.Canvas(sf, bg=BG, highlightthickness=0)
        sb = ttk.Scrollbar(sf, command=cv.yview)
        cv.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        cv.pack(side="left", fill="both", expand=True)
        inner = tk.Frame(cv, bg=BG)
        cv.create_window((0, 0), window=inner, anchor="nw")
        inner.bind("<Configure>",
                   lambda e: cv.configure(scrollregion=cv.bbox("all")))

        for step in STEPS:
            embedded = "[eingebettet]" in step.desc or "pip install" in step.desc
            color    = GREEN if embedded else YELLOW
            row = tk.Frame(inner, bg=BG); row.pack(fill="x", pady=3)
            tk.Checkbutton(row, variable=step.var,
                           bg=BG, fg=FG, activebackground=BG,
                           activeforeground=ACCENT, selectcolor=PANEL,
                           relief="flat", font=("Segoe UI", 9, "bold"),
                           text=f"  {step.name}").pack(side="left")
            tk.Label(row, text=f"  {step.desc}",
                     bg=BG, fg=color,
                     font=("Segoe UI", 7, "italic")).pack(side="left")

        leg = tk.Frame(p2, bg=BG); leg.pack(pady=6)
        tk.Label(leg, text="  [eingebettet] = offline  ",
                 bg=BG, fg=GREEN, font=("Segoe UI", 7, "italic")).pack(side="left")
        tk.Label(leg, text="  [winget/Download] = Internet nötig",
                 bg=BG, fg=YELLOW, font=("Segoe UI", 7, "italic")).pack(side="left")

        # ── Seite 3: Fortschritt ──────────────────────────────────────────────
        p3 = tk.Frame(self._content, bg=BG); self._pages.append(p3)
        self._status_var = tk.StringVar(value="Initialisiere...")
        tk.Label(p3, text="Installation läuft",
                 bg=BG, fg=FG, font=("Segoe UI", 14, "bold")).pack(pady=(18, 4))
        tk.Label(p3, textvariable=self._status_var,
                 bg=BG, fg=ACCENT, font=("Segoe UI", 9)).pack(pady=(0, 4))
        self._pb = ttk.Progressbar(p3, length=740, mode="determinate")
        self._pb.pack(padx=40, pady=(0, 8))
        self._log = tk.Text(p3, height=15, width=95,
                             bg=PANEL, fg=FG, relief="flat",
                             font=("Consolas", 8), state="disabled")
        self._log.tag_configure("ok",   foreground=GREEN)
        self._log.tag_configure("err",  foreground=RED)
        self._log.tag_configure("head", foreground=ACCENT)
        self._log.tag_configure("warn", foreground=YELLOW)
        self._log.pack(padx=40, fill="both", expand=True)

        # ── Seite 4: Fertig ───────────────────────────────────────────────────
        p4 = tk.Frame(self._content, bg=BG); self._pages.append(p4)
        tk.Label(p4, text="Installation abgeschlossen!",
                 bg=BG, fg=GREEN, font=("Segoe UI", 18, "bold")).pack(pady=(60, 12))
        self._done_lbl = tk.Label(p4, text="",
                                   bg=BG, fg=FG, font=("Segoe UI", 10), justify="center")
        self._done_lbl.pack(pady=8)
        tk.Button(p4, text="Suite jetzt starten",
                  bg=GREEN, fg=BG, relief="flat", cursor="hand2",
                  font=("Segoe UI", 12, "bold"), padx=24, pady=10,
                  command=self._launch).pack(pady=12)

        # Nav-Bar
        nav = tk.Frame(self, bg=PANEL, height=56)
        nav.pack(fill="x", side="bottom")
        nav.pack_propagate(False)
        self._back = tk.Button(nav, text="< Zurück", bg=PANEL, fg=FG,
                               relief="flat", font=("Segoe UI", 10),
                               cursor="hand2", padx=16, pady=8,
                               command=self._prev)
        self._back.pack(side="left", padx=16, pady=8)
        self._pgnum = tk.Label(nav, text="", bg=PANEL, fg=BORDER,
                               font=("Segoe UI", 8))
        self._pgnum.pack(side="right", padx=8)
        self._next = tk.Button(nav, text="Weiter >", bg=ACCENT, fg=BG,
                               relief="flat", font=("Segoe UI", 10, "bold"),
                               cursor="hand2", padx=20, pady=8,
                               command=self._next_page)
        self._next.pack(side="right", padx=16, pady=8)

    # ── Navigation ────────────────────────────────────────────────────────────

    def _show(self, idx: int):
        for p in self._pages:
            p.pack_forget()
        self._pages[idx].pack(fill="both", expand=True)
        self._page = idx
        n = len(self._pages)
        self._pgnum.configure(text=f"Schritt {idx+1} / {n}")
        self._back.configure(state="normal" if idx > 0 else "disabled")
        labels = ["Weiter >", "Weiter >", "Installieren", "...", "Schliessen"]
        self._next.configure(text=labels[min(idx, len(labels)-1)],
                             state="disabled" if idx == 3 else "normal")
        if idx == 4:
            self._back.configure(state="disabled")
            self._next.configure(text="Schliessen", bg=GREEN, fg=BG,
                                  command=self.destroy, state="normal")

    def _next_page(self):
        if self._page == 2:
            self._show(3)
            self._installing = True
            threading.Thread(target=self._install, daemon=True).start()
        elif self._page < len(self._pages) - 1:
            self._show(self._page + 1)

    def _prev(self):
        if self._page > 0 and not self._installing:
            self._show(self._page - 1)

    def _browse(self):
        d = filedialog.askdirectory(initialdir=self._install_dir.get())
        if d:
            self._install_dir.set(d)

    # ── Logging ───────────────────────────────────────────────────────────────

    def _w(self, text: str, tag: str = ""):
        def _do():
            self._log.configure(state="normal")
            self._log.insert("end", text + "\n", tag or ())
            self._log.see("end")
            self._log.configure(state="disabled")
        self.after(0, _do)

    def _prog(self, pct: float, status: str = ""):
        self.after(0, lambda: self._pb.configure(value=pct))
        if status:
            self.after(0, lambda: self._status_var.set(status))

    # ── Installations-Logik ───────────────────────────────────────────────────

    def _selected(self, name: str) -> bool:
        for s in STEPS:
            if s.name == name:
                return bool(s.var and s.var.get())
        return False

    def _install(self):
        base   = Path(self._install_dir.get())
        suite  = base / "suite"
        tools  = base / "tools"
        base.mkdir(parents=True, exist_ok=True)
        suite.mkdir(parents=True, exist_ok=True)
        tools.mkdir(parents=True, exist_ok=True)

        cfg: dict = {}
        total_steps = sum(1 for s in STEPS if s.var and s.var.get())
        done = 0

        def step_done(name: str):
            nonlocal done
            done += 1
            self._prog(done / max(total_steps, 1) * 100, name)

        # ── 1. Suite-Dateien ─────────────────────────────────────────────────
        if self._selected("G4MEOVER Suite"):
            self._w("\n=== G4MEOVER Suite ===", "head")
            # Im gebundeten EXE: Daten in _MEIPASS/suite/
            src = _data("suite")
            if not src.exists():
                src = _data(".")   # Fallback: direkt im Bundle

            if src.exists():
                self._w(f"  Kopiere von {src}...")
                try:
                    if suite.exists():
                        shutil.rmtree(suite)
                    shutil.copytree(str(src), str(suite),
                                    ignore=shutil.ignore_patterns(
                                        "__pycache__", "*.pyc", "build",
                                        ".git", "installer"))
                    self._w("  Suite-Dateien kopiert", "ok")
                except Exception as e:
                    self._w(f"  Fehler: {e}", "err")
            else:
                # Online-Fallback: von GitHub klonen
                self._w("  Klone von GitHub...")
                try:
                    subprocess.run(
                        ["git", "clone", "--depth=1",
                         "https://github.com/G4MEOVER18/g4meover-security-suite.git",
                         str(suite)],
                        check=True, capture_output=True, timeout=180)
                    self._w("  Geklont", "ok")
                except Exception as e:
                    self._w(f"  Fehler: {e}", "err")
            step_done("Suite kopiert")

        # ── 2. Python-Pakete ─────────────────────────────────────────────────
        if self._selected("Python-Pakete"):
            self._w("\n=== Python-Pakete ===", "head")
            pkgs = ["scapy", "pillow", "requests", "pywin32"]
            self._w(f"  pip install {' '.join(pkgs)}")
            try:
                r = subprocess.run(
                    [sys.executable, "-m", "pip", "install", "--quiet"] + pkgs,
                    capture_output=True, text=True, timeout=300)
                if r.returncode == 0:
                    self._w("  Pakete installiert", "ok")
                else:
                    self._w(f"  pip-Fehler: {r.stderr[:200]}", "err")
            except Exception as e:
                self._w(f"  Fehler: {e}", "err")
            step_done("Python-Pakete")

        # ── 3. Eingebettete Binaries ──────────────────────────────────────────
        embedded_tools = [
            ("gobuster",    "gobuster",   "gobuster.exe",  "tool_gobuster"),
            ("feroxbuster", "feroxbuster","feroxbuster.exe","tool_feroxbuster"),
        ]
        for step_name, folder, exe_name, cfg_key in embedded_tools:
            if not self._selected(step_name if step_name != "gobuster" else "gobuster"):
                continue
            # Passenden Step finden
            match = next((s for s in STEPS if s.name.lower().startswith(folder)), None)
            if match and not match.var.get():
                continue
            self._w(f"\n=== {step_name} ===", "head")
            src = _data(f"tools_builtin/{folder}")
            dest = tools / folder
            dest.mkdir(parents=True, exist_ok=True)
            if src.exists():
                for f in src.iterdir():
                    shutil.copy2(f, dest / f.name)
                exe = dest / exe_name
                if exe.exists():
                    cfg[cfg_key] = str(exe)
                    self._w(f"  {exe_name} installiert", "ok")
                else:
                    self._w(f"  EXE nicht gefunden: {exe_name}", "warn")
            else:
                self._w(f"  Quelle nicht gefunden: {src}", "warn")
            step_done(step_name)

        # gobuster
        if self._selected("gobuster"):
            self._w("\n=== gobuster ===", "head")
            src = _data("tools_builtin/gobuster")
            dest = tools / "gobuster"; dest.mkdir(parents=True, exist_ok=True)
            if src.exists():
                for f in src.iterdir():
                    shutil.copy2(f, dest / f.name)
                exe = dest / "gobuster.exe"
                if exe.exists():
                    cfg["tool_gobuster"] = str(exe)
                    self._w("  gobuster.exe installiert", "ok")
            else:
                self._w("  Quelle fehlt – uebersprungen", "warn")
            step_done("gobuster")

        # feroxbuster
        if self._selected("feroxbuster"):
            self._w("\n=== feroxbuster ===", "head")
            src = _data("tools_builtin/feroxbuster")
            dest = tools / "feroxbuster"; dest.mkdir(parents=True, exist_ok=True)
            if src.exists():
                for f in src.iterdir():
                    shutil.copy2(f, dest / f.name)
                exe = dest / "feroxbuster.exe"
                if exe.exists():
                    cfg["tool_feroxbuster"] = str(exe)
                    self._w("  feroxbuster.exe installiert", "ok")
            else:
                self._w("  Quelle fehlt – uebersprungen", "warn")
            step_done("feroxbuster")

        # John the Ripper
        if self._selected("John the Ripper"):
            self._w("\n=== John the Ripper ===", "head")
            src = _data("tools_builtin/john")
            dest = tools / "john"; dest.mkdir(parents=True, exist_ok=True)
            if src.exists():
                for f in src.rglob("*"):
                    rel = f.relative_to(src)
                    if f.is_dir():
                        (dest / rel).mkdir(parents=True, exist_ok=True)
                    else:
                        shutil.copy2(f, dest / rel)
                exe = dest / "john.exe"
                if not exe.exists():
                    for found in dest.rglob("john.exe"):
                        exe = found; break
                if exe.exists():
                    cfg["tool_john"] = str(exe)
                    self._w("  john.exe installiert", "ok")
            else:
                self._w("  Quelle fehlt – uebersprungen", "warn")
            step_done("John the Ripper")

        # sqlmap
        if self._selected("sqlmap"):
            self._w("\n=== sqlmap ===", "head")
            self._w("  pip install sqlmap")
            try:
                r = subprocess.run(
                    [sys.executable, "-m", "pip", "install", "--quiet", "sqlmap"],
                    capture_output=True, text=True, timeout=120)
                if r.returncode == 0:
                    # sqlmap.exe im Scripts-Verzeichnis suchen
                    scripts = Path(sys.executable).parent / "Scripts" / "sqlmap.exe"
                    if scripts.exists():
                        cfg["tool_sqlmap"] = str(scripts)
                    self._w("  sqlmap installiert", "ok")
                else:
                    self._w(f"  Fehler: {r.stderr[:150]}", "err")
            except Exception as e:
                self._w(f"  Fehler: {e}", "err")
            step_done("sqlmap")

        # ExploitDB
        if self._selected("ExploitDB + SearchSploit"):
            self._w("\n=== ExploitDB ===", "head")
            src = _data("tools_builtin/exploitdb")
            dest = tools / "exploitdb"; dest.mkdir(parents=True, exist_ok=True)
            if src.exists():
                for f in src.iterdir():
                    shutil.copy2(f, dest / f.name)
                bat = dest / "searchsploit.bat"
                cfg["tool_searchsploit"] = str(bat)
                csv = dest / "files_exploits.csv"
                self._w(f"  ExploitDB: {csv.stat().st_size//1024}KB CSV + Scripts", "ok")
            else:
                self._w("  Quelle fehlt – uebersprungen", "warn")
            step_done("ExploitDB + SearchSploit")

        # nikto
        if self._selected("nikto"):
            self._w("\n=== nikto ===", "head")
            src = _data("tools_builtin/nikto")
            dest = tools / "nikto"; dest.mkdir(parents=True, exist_ok=True)
            if src.exists():
                for f in src.rglob("*"):
                    rel = f.relative_to(src)
                    if f.is_dir():
                        (dest / rel).mkdir(parents=True, exist_ok=True)
                    else:
                        shutil.copy2(f, dest / rel)
                bat = dest / "nikto.bat"
                if bat.exists():
                    cfg["tool_nikto"] = str(bat)
                    self._w("  nikto installiert", "ok")
            else:
                self._w("  Quelle fehlt – uebersprungen", "warn")
            step_done("nikto")

        # Python-Tools (hydra / masscan / whatweb)
        for step_name, folder, cfg_key in [
            ("Hydra (Python)",    "hydra",    "tool_hydra"),
            ("Masscan (Python)",  "masscan",  "tool_masscan"),
            ("WhatWeb (Python)",  "whatweb",  "tool_whatweb"),
        ]:
            if not self._selected(step_name):
                continue
            self._w(f"\n=== {step_name} ===", "head")
            src = _data(f"tools_builtin/{folder}")
            dest = tools / folder; dest.mkdir(parents=True, exist_ok=True)
            if src.exists():
                for f in src.iterdir():
                    shutil.copy2(f, dest / f.name)
                bat = dest / f"{folder}.bat"
                if bat.exists():
                    cfg[cfg_key] = str(bat)
                    self._w(f"  {folder} installiert", "ok")
            else:
                self._w(f"  Quelle fehlt – uebersprungen", "warn")
            step_done(step_name)

        # ── 4. winget-Tools ───────────────────────────────────────────────────
        winget_tools = [
            ("nmap",           "Insecure.Nmap",          "tool_nmap",
             r"C:\Program Files (x86)\Nmap\nmap.exe"),
            ("Wireshark / tshark","WiresharkFoundation.Wireshark","tool_tshark",
             r"C:\Program Files\Wireshark\tshark.exe"),
        ]
        for step_name, pkg, cfg_key, default_path in winget_tools:
            if not self._selected(step_name):
                continue
            self._w(f"\n=== {step_name} ===", "head")
            self._w(f"  winget install {pkg}")
            try:
                r = subprocess.run(
                    ["winget", "install", "--id", pkg, "-e",
                     "--accept-source-agreements",
                     "--accept-package-agreements", "--silent"],
                    capture_output=True, text=True, timeout=300)
                if r.returncode in (0, -1978335189):
                    if os.path.exists(default_path):
                        cfg[cfg_key] = default_path
                    self._w(f"  {step_name} installiert", "ok")
                else:
                    self._w(f"  Fehler rc={r.returncode}: {r.stderr[:120]}", "err")
            except Exception as e:
                self._w(f"  Fehler: {e}", "err")
            step_done(step_name)

        # ── 5. hashcat (Download) ─────────────────────────────────────────────
        if self._selected("hashcat"):
            self._w("\n=== hashcat ===", "head")
            dest = tools / "hashcat"; dest.mkdir(parents=True, exist_ok=True)

            # Versuche zuerst eingebettet
            src = _data("tools_builtin/hashcat")
            if src.exists():
                self._w("  Kopiere eingebettetes hashcat...")
                for f in src.rglob("*"):
                    rel = f.relative_to(src)
                    if f.is_dir():
                        (dest / rel).mkdir(parents=True, exist_ok=True)
                    else:
                        shutil.copy2(f, dest / rel)
            else:
                # Download von GitHub
                url = ("https://github.com/hashcat/hashcat/releases/download/"
                       "v6.2.6/hashcat-6.2.6.7z")
                self._w(f"  Download: {url.split('/')[-1]}")
                tmp = tools / "hashcat.7z"
                try:
                    req = urllib.request.Request(
                        url, headers={"User-Agent": "G4MEOVER-Installer"})
                    with urllib.request.urlopen(req, timeout=180) as r:
                        total = int(r.headers.get("Content-Length", 0))
                        done_bytes = 0
                        with open(tmp, "wb") as f:
                            while True:
                                buf = r.read(65536)
                                if not buf: break
                                f.write(buf)
                                done_bytes += len(buf)
                    self._w(f"  Download fertig ({done_bytes//1024//1024} MB)", "ok")
                    self._w("  Bitte hashcat-6.2.6.7z manuell entpacken nach: " + str(dest), "warn")
                    tmp_dest = tools / "hashcat.7z"
                    shutil.copy2(tmp, tmp_dest)
                except Exception as e:
                    self._w(f"  Download-Fehler: {e}", "err")

            exe = next(dest.rglob("hashcat.exe"), None)
            if exe:
                cfg["tool_hashcat"] = str(exe)
                self._w("  hashcat.exe gefunden", "ok")
            step_done("hashcat")

        # ── 6. Config schreiben ───────────────────────────────────────────────
        cfg["workspace"] = str(base / "pentest")
        cfg["theme"]     = "catppuccin_mocha"
        cfg_path = suite / "suite_config.json"
        cfg_path.write_text(json.dumps(cfg, indent=2, ensure_ascii=False), "utf-8")
        self._w(f"\n  Config: {cfg_path}", "ok")
        self._w(f"  Tools konfiguriert: {len(cfg)-2}", "ok")

        # ── 7. Desktop-Verknüpfung ────────────────────────────────────────────
        if self._selected("Desktop-Verknüpfung"):
            self._w("\n=== Desktop-Verknüpfung ===", "head")
            desktop = Path(os.path.join(os.environ.get("USERPROFILE", ""), "Desktop"))
            suite_main = suite / "openclaw_suite.py"
            pythonw    = Path(sys.executable).parent / "pythonw.exe"
            if not pythonw.exists():
                pythonw = Path(sys.executable)
            ico = suite / "assets" / "g4meover.ico"
            ico_arg = f'$s.IconLocation="{ico}";' if ico.exists() else ""
            ps = (
                f'$s=(New-Object -COM WScript.Shell).CreateShortcut("{desktop}\\G4MEOVER Suite.lnk");'
                f'$s.TargetPath="{pythonw}";'
                f'$s.Arguments=\\"{suite_main}\\";'
                f'$s.WorkingDirectory="{suite}";'
                f'$s.Description="G4MEOVER Security Suite v{VERSION}";'
                f'{ico_arg}'
                f'$s.Save()'
            )
            try:
                subprocess.run(["powershell", "-Command", ps],
                               capture_output=True, timeout=15)
                self._w("  Desktop-Verknuepfung erstellt", "ok")
            except Exception as e:
                self._w(f"  Fehler: {e}", "err")
            step_done("Desktop-Verknüpfung")

        # ── 8. Startmenü ─────────────────────────────────────────────────────
        if self._selected("Startmenü-Eintrag"):
            self._w("\n=== Startmenue ===", "head")
            try:
                start = Path(os.environ.get("APPDATA", "")) / "Microsoft" / "Windows" / "Start Menu" / "Programs"
                g4_dir = start / "G4MEOVER"
                g4_dir.mkdir(parents=True, exist_ok=True)
                suite_main = suite / "openclaw_suite.py"
                pythonw    = Path(sys.executable).parent / "pythonw.exe"
                if not pythonw.exists():
                    pythonw = Path(sys.executable)
                ps = (
                    f'$s=(New-Object -COM WScript.Shell).CreateShortcut("{g4_dir}\\G4MEOVER Suite.lnk");'
                    f'$s.TargetPath="{pythonw}";'
                    f'$s.Arguments=\\"{suite_main}\\";'
                    f'$s.WorkingDirectory="{suite}";'
                    f'$s.Save()'
                )
                subprocess.run(["powershell", "-Command", ps],
                               capture_output=True, timeout=15)
                self._w("  Startmenue-Eintrag erstellt", "ok")
            except Exception as e:
                self._w(f"  Fehler: {e}", "err")
            step_done("Startmenü-Eintrag")

        # ── Abschluss ─────────────────────────────────────────────────────────
        self._prog(100, "Abgeschlossen")
        self._installing = False
        self._suite_path = str(suite / "openclaw_suite.py")

        msg = (f"G4MEOVER Suite:\n{suite}\n\n"
               f"Tools:\n{tools}\n\n"
               f"{len(cfg)-2} Tool(s) konfiguriert")
        self.after(0, lambda: self._done_lbl.configure(text=msg))
        self.after(0, lambda: self._show(4))

    def _launch(self):
        if hasattr(self, "_suite_path") and os.path.exists(self._suite_path):
            pythonw = Path(sys.executable).parent / "pythonw.exe"
            exe = str(pythonw) if pythonw.exists() else sys.executable
            subprocess.Popen([exe, self._suite_path],
                             cwd=os.path.dirname(self._suite_path))
        self.destroy()


if __name__ == "__main__":
    InstallerApp().mainloop()
