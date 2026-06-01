#!/usr/bin/env python3
"""
G4MEOVER Security Suite – Installer
Installiert die Suite + alle Tools auf einem neuen Windows-System.
"""
import sys
import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import subprocess
import urllib.request
import urllib.error
import zipfile
import json
import shutil
import time
import winreg
from pathlib import Path

VERSION    = "1.4"
SUITE_NAME = "G4MEOVER Security Suite"
AUTHOR     = "Yanis Ameseder"
GITHUB     = "https://github.com/G4MEOVER18/g4meover-security-suite"

# ─── Farben (Catppuccin Mocha) ────────────────────────────────────────────────
BG     = "#1e1e2e"
PANEL  = "#313244"
ACCENT = "#89b4fa"
GREEN  = "#a6e3a1"
RED    = "#f38ba8"
YELLOW = "#f9e2af"
FG     = "#cdd6f4"
BORDER = "#585b70"

# ─── Tool-Download-Definitionen ───────────────────────────────────────────────
# Format: (name, beschreibung, url_oder_winget, typ, ziel_pfad_relativ)
# typ: "github_release" | "direct" | "winget" | "pip" | "git_clone" | "builtin"

DEFAULT_INSTALL = Path("C:/tools/G4MEOVER")

TOOLS: list[dict] = [
    {
        "id":    "python_deps",
        "name":  "Python-Pakete",
        "desc":  "scapy, pillow, requests, pywin32",
        "type":  "pip",
        "pkgs":  ["scapy", "pillow", "requests", "pywin32"],
        "default": True,
    },
    {
        "id":    "nmap",
        "name":  "nmap 7.95",
        "desc":  "Port-Scanner – winget install nmap",
        "type":  "winget",
        "pkg":   "Insecure.Nmap",
        "path":  r"C:\Program Files (x86)\Nmap\nmap.exe",
        "default": True,
    },
    {
        "id":    "wireshark",
        "name":  "Wireshark / tshark",
        "desc":  "Paket-Analyse – winget install Wireshark",
        "type":  "winget",
        "pkg":   "WiresharkFoundation.Wireshark",
        "path":  r"C:\Program Files\Wireshark\tshark.exe",
        "default": True,
    },
    {
        "id":    "hashcat",
        "name":  "hashcat 6.2.6",
        "desc":  "GPU Hash-Cracker",
        "type":  "direct",
        "url":   "https://github.com/hashcat/hashcat/releases/download/v6.2.6/hashcat-6.2.6.7z",
        "dest":  "hashcat",
        "exe":   "hashcat/hashcat.exe",
        "default": True,
    },
    {
        "id":    "gobuster",
        "name":  "gobuster",
        "desc":  "Directory-Bruteforce",
        "type":  "github_release",
        "repo":  "OJ/gobuster",
        "asset": "gobuster_windows_amd64.zip",
        "dest":  "gobuster",
        "exe":   "gobuster/gobuster.exe",
        "default": True,
    },
    {
        "id":    "feroxbuster",
        "name":  "feroxbuster",
        "desc":  "Rekursiver Dir-Scanner",
        "type":  "github_release",
        "repo":  "epi052/feroxbuster",
        "asset": "x86_64-windows-feroxbuster.exe.zip",
        "dest":  "feroxbuster",
        "exe":   "feroxbuster/feroxbuster.exe",
        "default": True,
    },
    {
        "id":    "john",
        "name":  "John the Ripper",
        "desc":  "Password Cracker",
        "type":  "direct",
        "url":   "https://github.com/openwall/john-packages/releases/download/jumbo-dev/john-1.9.0-jumbo-1-win64.zip",
        "dest":  "john",
        "exe":   "john/run/john.exe",
        "default": True,
    },
    {
        "id":    "sqlmap",
        "name":  "sqlmap",
        "desc":  "SQL-Injection",
        "type":  "pip",
        "pkgs":  ["sqlmap"],
        "default": True,
    },
    {
        "id":    "exploitdb",
        "name":  "ExploitDB (SearchSploit)",
        "desc":  "47.000+ Exploits (CSV-Datenbank)",
        "type":  "git_clone",
        "url":   "https://gitlab.com/exploit-database/exploitdb.git",
        "dest":  "exploitdb",
        "sparse": ["files_exploits.csv", "files_shellcodes.csv"],
        "exe":   "exploitdb/searchsploit.bat",
        "default": True,
    },
    {
        "id":    "hydra_builtin",
        "name":  "Hydra (Python)",
        "desc":  "Online-Brute-Force (SSH/FTP/HTTP)",
        "type":  "builtin",
        "src":   "hydra",
        "exe":   "hydra/hydra.bat",
        "default": True,
    },
    {
        "id":    "masscan_builtin",
        "name":  "Masscan (Python)",
        "desc":  "Schnell-Port-Scanner",
        "type":  "builtin",
        "src":   "masscan",
        "exe":   "masscan/masscan.bat",
        "default": True,
    },
    {
        "id":    "whatweb_builtin",
        "name":  "WhatWeb (Python)",
        "desc":  "Web-Fingerprinting",
        "type":  "builtin",
        "src":   "whatweb",
        "exe":   "whatweb/whatweb.bat",
        "default": True,
    },
    {
        "id":    "nikto",
        "name":  "nikto",
        "desc":  "Web-Schwachstellen-Scanner (Perl)",
        "type":  "github_release",
        "repo":  "sullo/nikto",
        "asset": "nikto-2.1.6.zip",
        "dest":  "nikto",
        "exe":   "nikto/nikto.bat",
        "default": False,
    },
    {
        "id":    "metasploit",
        "name":  "Metasploit Framework",
        "desc":  "~800 MB – nur bei Bedarf",
        "type":  "winget",
        "pkg":   "Rapid7.Metasploit",
        "path":  r"C:\metasploit-framework\bin\msfconsole.bat",
        "default": False,
    },
]

# Builtin-Tools (im Installer gebundelt)
BUILTIN_FILES = {
    "hydra": [
        ("hydra.py",  _HYDRA_PY  := ""),   # wird zur Laufzeit gefüllt
        ("hydra.bat", "@echo off\npython \"%~dp0hydra.py\" %*\n"),
    ],
    "masscan": [
        ("masscan.py",  ""),
        ("masscan.bat", "@echo off\npython \"%~dp0masscan.py\" %*\n"),
    ],
    "whatweb": [
        ("whatweb.py",  ""),
        ("whatweb.bat", "@echo off\npython \"%~dp0whatweb.py\" %*\n"),
    ],
}

# searchsploit.py und searchsploit.bat für exploitdb
SEARCHSPLOIT_PY = r'''#!/usr/bin/env python3
"""SearchSploit – Python CSV-Wrapper für ExploitDB."""
import csv, re, sys, os, argparse
_DIR = os.path.dirname(os.path.abspath(__file__))
CSV  = os.path.join(_DIR, "files_exploits.csv")
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("terms", nargs="+")
    ap.add_argument("--exact", action="store_true")
    args = ap.parse_args()
    terms = args.terms
    pat = re.compile(r"\b" + r"\b.*\b".join(re.escape(t) for t in terms) + r"\b", re.I) \
          if args.exact else re.compile(".*".join(re.escape(t) for t in terms), re.I)
    if not os.path.exists(CSV):
        print(f"[!] {CSV} nicht gefunden."); sys.exit(1)
    hits = 0
    with open(CSV, newline="", encoding="utf-8", errors="replace") as f:
        for row in csv.DictReader(f):
            desc = row.get("description","") or row.get("Title","")
            path = row.get("file","") or row.get("File","")
            if pat.search(desc):
                print(f"{desc} | {path}"); hits += 1
    print(f"\n{hits} Treffer")
if __name__ == "__main__": main()
'''

SEARCHSPLOIT_BAT = "@echo off\npython \"%~dp0searchsploit.py\" %*\n"
NIKTO_BAT = (
    "@echo off\n"
    "set PERL5LIB=%~dp0perl5lib\n"
    "perl \"%~dp0nikto-main\\program\\nikto.pl\" %*\n"
)


# ─── Download-Helfer ──────────────────────────────────────────────────────────

def _download(url: str, dest: Path, log, progress_cb=None) -> bool:
    log(f"  ↓  {url.split('/')[-1]}")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "G4MEOVER-Installer/1.4"})
        with urllib.request.urlopen(req, timeout=120) as r:
            total = int(r.headers.get("Content-Length", 0))
            done  = 0
            chunk = 65536
            with open(dest, "wb") as f:
                while True:
                    buf = r.read(chunk)
                    if not buf:
                        break
                    f.write(buf)
                    done += len(buf)
                    if progress_cb and total:
                        progress_cb(done / total * 100)
        return True
    except Exception as e:
        log(f"  [!] Download-Fehler: {e}")
        return False


def _get_github_release_url(repo: str, asset_pattern: str) -> str:
    """Holt die Download-URL des neuesten GitHub-Releases."""
    api = f"https://api.github.com/repos/{repo}/releases/latest"
    try:
        req = urllib.request.Request(api, headers={
            "User-Agent": "G4MEOVER-Installer",
            "Accept": "application/vnd.github.v3+json"})
        with urllib.request.urlopen(req, timeout=15) as r:
            data = json.loads(r.read())
        for asset in data.get("assets", []):
            if re.search(asset_pattern, asset["name"], re.I):
                return asset["browser_download_url"]
    except Exception:
        pass
    return ""


def _unzip(src: Path, dest: Path, log) -> bool:
    try:
        with zipfile.ZipFile(src, "r") as z:
            z.extractall(dest)
        return True
    except Exception as e:
        log(f"  [!] Entpacken fehlgeschlagen: {e}")
        return False


def _run_winget(pkg: str, log) -> bool:
    log(f"  winget install {pkg}")
    try:
        r = subprocess.run(
            ["winget", "install", "--id", pkg, "-e",
             "--accept-source-agreements", "--accept-package-agreements",
             "--silent"],
            capture_output=True, text=True, timeout=300)
        if r.returncode == 0 or r.returncode == -1978335189:  # already installed
            log(f"  ✓ {pkg} installiert")
            return True
        log(f"  [!] winget rc={r.returncode}: {r.stderr[:200]}")
        return False
    except Exception as e:
        log(f"  [!] winget: {e}")
        return False


def _run_pip(pkgs: list[str], log) -> bool:
    log(f"  pip install {' '.join(pkgs)}")
    try:
        r = subprocess.run(
            [sys.executable, "-m", "pip", "install", "--quiet"] + pkgs,
            capture_output=True, text=True, timeout=180)
        if r.returncode == 0:
            log(f"  ✓ Pakete installiert")
            return True
        log(f"  [!] pip: {r.stderr[:300]}")
        return False
    except Exception as e:
        log(f"  [!] pip: {e}")
        return False


def _git_clone_sparse(url: str, dest: Path, sparse_paths: list[str], log) -> bool:
    log(f"  git clone (sparse) {url}")
    try:
        subprocess.run(["git", "init", str(dest)], check=True,
                       capture_output=True, timeout=30)
        subprocess.run(["git", "-C", str(dest), "remote", "add", "origin", url],
                       check=True, capture_output=True, timeout=10)
        subprocess.run(["git", "-C", str(dest), "config",
                        "core.sparseCheckout", "true"],
                       check=True, capture_output=True, timeout=10)
        sparse_file = dest / ".git" / "info" / "sparse-checkout"
        sparse_file.write_text("\n".join(sparse_paths) + "\n")
        subprocess.run(["git", "-C", str(dest), "pull",
                        "--depth=1", "origin", "main"],
                       check=True, capture_output=True, timeout=300)
        log("  ✓ ExploitDB geklont")
        return True
    except Exception as e:
        log(f"  [!] git clone: {e}")
        return False


# ─── Installer-GUI ────────────────────────────────────────────────────────────

class InstallerApp(tk.Tk):

    def __init__(self):
        super().__init__()
        self.title(f"{SUITE_NAME} – Setup v{VERSION}")
        self.geometry("820x620")
        self.resizable(False, False)
        self.configure(bg=BG)

        self._install_dir = tk.StringVar(value=str(DEFAULT_INSTALL))
        self._tool_vars: dict[str, tk.BooleanVar] = {}
        self._page = 0
        self._frames: list[tk.Frame] = []

        self._build_ui()
        self._show_page(0)

    # ── UI-Aufbau ─────────────────────────────────────────────────────────────

    def _build_ui(self):
        # Header
        hdr = tk.Frame(self, bg=PANEL, height=70)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        tk.Label(hdr, text=f"  {SUITE_NAME}",
                 bg=PANEL, fg=ACCENT, font=("Segoe UI", 16, "bold")).pack(
            side="left", padx=16, pady=10)
        tk.Label(hdr, text=f"v{VERSION}  ·  by {AUTHOR}",
                 bg=PANEL, fg=BORDER, font=("Segoe UI", 8)).pack(
            side="right", padx=16)

        # Content-Bereich
        self._content = tk.Frame(self, bg=BG)
        self._content.pack(fill="both", expand=True, padx=0, pady=0)

        # Seite 0 – Willkommen
        p0 = tk.Frame(self._content, bg=BG)
        self._frames.append(p0)

        tk.Label(p0, text="Willkommen",
                 bg=BG, fg=FG, font=("Segoe UI", 18, "bold")).pack(pady=(40, 8))
        tk.Label(p0,
                 text=(
                     f"Dieser Assistent installiert {SUITE_NAME}\n"
                     "und alle benötigten Sicherheitstools\n"
                     "auf diesem Windows-System.\n\n"
                     "Benötigt: Windows 10/11 · Internetverbindung\n"
                     "Administratorrechte empfohlen (für nmap, Wireshark)"
                 ),
                 bg=BG, fg=FG, font=("Segoe UI", 11),
                 justify="center").pack(pady=8)

        tk.Label(p0, text=GITHUB, bg=BG, fg=ACCENT,
                 font=("Segoe UI", 9, "underline"), cursor="hand2").pack(pady=4)

        tk.Label(p0,
                 text="⚠  Nur für autorisierte Sicherheitstests und CTF-Challenges verwenden.",
                 bg=BG, fg=YELLOW, font=("Segoe UI", 8)).pack(pady=(16, 4))

        # Seite 1 – Installationspfad
        p1 = tk.Frame(self._content, bg=BG)
        self._frames.append(p1)

        tk.Label(p1, text="Installationspfad",
                 bg=BG, fg=FG, font=("Segoe UI", 14, "bold")).pack(pady=(30, 12))
        tk.Label(p1,
                 text="Die Suite und alle Tools werden in diesen Ordner installiert:",
                 bg=BG, fg=BORDER, font=("Segoe UI", 9)).pack()

        path_row = tk.Frame(p1, bg=BG); path_row.pack(pady=12, padx=40, fill="x")
        tk.Entry(path_row, textvariable=self._install_dir,
                 bg=PANEL, fg=FG, insertbackground=FG,
                 relief="flat", font=("Consolas", 10)).pack(
            side="left", fill="x", expand=True, ipady=6, padx=(0, 8))
        tk.Button(path_row, text="…",
                  bg=PANEL, fg=FG, relief="flat", cursor="hand2",
                  command=self._browse_dir).pack(side="left", ipadx=8, ipady=4)

        tk.Label(p1, text="Außerdem wird eine Desktop-Verknüpfung erstellt.",
                 bg=BG, fg=BORDER, font=("Segoe UI", 9)).pack(pady=4)

        # Speicherplatz-Info
        info_frame = tk.Frame(p1, bg=PANEL, padx=20, pady=12)
        info_frame.pack(padx=40, pady=16, fill="x")
        for label, val in [
            ("G4MEOVER Suite:", "~15 MB"),
            ("nmap:", "~30 MB"),
            ("hashcat:", "~40 MB"),
            ("Wireshark:", "~120 MB"),
            ("ExploitDB (CSV):", "~50 MB"),
            ("Sonstige Tools:", "~100 MB"),
            ("Gesamt ca.:", "~355 MB"),
        ]:
            row = tk.Frame(info_frame, bg=PANEL); row.pack(fill="x")
            tk.Label(row, text=label, bg=PANEL, fg=BORDER,
                     font=("Segoe UI", 8), width=22, anchor="w").pack(side="left")
            tk.Label(row, text=val, bg=PANEL, fg=FG,
                     font=("Segoe UI", 8, "bold")).pack(side="left")

        # Seite 2 – Tool-Auswahl
        p2 = tk.Frame(self._content, bg=BG)
        self._frames.append(p2)

        tk.Label(p2, text="Tool-Auswahl",
                 bg=BG, fg=FG, font=("Segoe UI", 14, "bold")).pack(pady=(20, 6))
        tk.Label(p2, text="Wähle welche Tools installiert werden sollen:",
                 bg=BG, fg=BORDER, font=("Segoe UI", 9)).pack(pady=(0, 8))

        scroll_frame = tk.Frame(p2, bg=BG); scroll_frame.pack(fill="both", expand=True, padx=40)
        canvas = tk.Canvas(scroll_frame, bg=BG, highlightthickness=0)
        sb     = ttk.Scrollbar(scroll_frame, command=canvas.yview)
        canvas.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)
        inner = tk.Frame(canvas, bg=BG)
        canvas.create_window((0, 0), window=inner, anchor="nw")
        inner.bind("<Configure>", lambda e: canvas.configure(
            scrollregion=canvas.bbox("all")))

        for tool in TOOLS:
            var = tk.BooleanVar(value=tool["default"])
            self._tool_vars[tool["id"]] = var
            row = tk.Frame(inner, bg=BG); row.pack(fill="x", pady=2)
            cb = tk.Checkbutton(row, variable=var, bg=BG, fg=FG,
                                activebackground=BG, activeforeground=ACCENT,
                                selectcolor=PANEL, relief="flat",
                                font=("Segoe UI", 9, "bold"),
                                text=f"  {tool['name']}")
            cb.pack(side="left")
            tk.Label(row, text=f"   – {tool['desc']}",
                     bg=BG, fg=BORDER, font=("Segoe UI", 8)).pack(side="left")

        # Seite 3 – Installation
        p3 = tk.Frame(self._content, bg=BG)
        self._frames.append(p3)

        tk.Label(p3, text="Installation läuft...",
                 bg=BG, fg=FG, font=("Segoe UI", 14, "bold")).pack(pady=(20, 8))
        self._current_tool_var = tk.StringVar(value="")
        tk.Label(p3, textvariable=self._current_tool_var,
                 bg=BG, fg=ACCENT, font=("Segoe UI", 9)).pack()

        self._progress = ttk.Progressbar(p3, length=700, mode="determinate")
        self._progress.pack(padx=40, pady=8)

        self._log_text = tk.Text(p3, height=14, width=90,
                                  bg=PANEL, fg=FG, relief="flat",
                                  font=("Consolas", 8), state="disabled",
                                  insertbackground=FG)
        self._log_text.tag_configure("ok",   foreground=GREEN)
        self._log_text.tag_configure("err",  foreground=RED)
        self._log_text.tag_configure("head", foreground=ACCENT)
        self._log_text.pack(padx=40, pady=4, fill="both", expand=True)

        # Seite 4 – Fertig
        p4 = tk.Frame(self._content, bg=BG)
        self._frames.append(p4)

        self._done_icon = tk.Label(p4, text="✓", bg=BG, fg=GREEN,
                                    font=("Segoe UI", 48))
        self._done_icon.pack(pady=(50, 10))
        tk.Label(p4, text="Installation abgeschlossen!",
                 bg=BG, fg=GREEN, font=("Segoe UI", 16, "bold")).pack()
        self._done_msg = tk.Label(p4, text="",
                                   bg=BG, fg=FG, font=("Segoe UI", 10),
                                   justify="center")
        self._done_msg.pack(pady=12)
        tk.Button(p4, text="Suite starten",
                  bg=ACCENT, fg=BG, relief="flat",
                  font=("Segoe UI", 11, "bold"), cursor="hand2",
                  command=self._launch_suite,
                  padx=20, pady=8).pack(pady=8)

        # Navigations-Leiste
        nav = tk.Frame(self, bg=PANEL, height=54)
        nav.pack(fill="x", side="bottom")
        nav.pack_propagate(False)

        self._back_btn = tk.Button(nav, text="← Zurück",
                                    bg=PANEL, fg=FG, relief="flat",
                                    font=("Segoe UI", 10), cursor="hand2",
                                    command=self._prev_page,
                                    padx=16, pady=8)
        self._back_btn.pack(side="left", padx=16, pady=8)

        self._next_btn = tk.Button(nav, text="Weiter →",
                                    bg=ACCENT, fg=BG, relief="flat",
                                    font=("Segoe UI", 10, "bold"), cursor="hand2",
                                    command=self._next_page,
                                    padx=20, pady=8)
        self._next_btn.pack(side="right", padx=16, pady=8)

        # Seitennummer
        self._page_lbl = tk.Label(nav, text="",
                                   bg=PANEL, fg=BORDER, font=("Segoe UI", 8))
        self._page_lbl.pack(side="right", padx=8)

    # ── Navigation ────────────────────────────────────────────────────────────

    def _show_page(self, idx: int):
        for f in self._frames:
            f.pack_forget()
        self._frames[idx].pack(fill="both", expand=True)
        self._page = idx
        total = len(self._frames)
        self._page_lbl.configure(text=f"Schritt {idx + 1} / {total}")

        self._back_btn.configure(state="normal" if idx > 0 else "disabled")

        labels = ["Weiter →", "Weiter →", "Installieren", "Läuft...", "Schließen"]
        self._next_btn.configure(text=labels[min(idx, len(labels) - 1)])

        if idx == 4:
            self._back_btn.configure(state="disabled")
            self._next_btn.configure(text="Schließen", command=self.destroy,
                                      bg=GREEN, fg=BG)

    def _next_page(self):
        if self._page == 2:
            self._show_page(3)
            threading.Thread(target=self._run_install, daemon=True).start()
        elif self._page < len(self._frames) - 1:
            self._show_page(self._page + 1)

    def _prev_page(self):
        if self._page > 0:
            self._show_page(self._page - 1)

    def _browse_dir(self):
        d = filedialog.askdirectory(title="Installationsordner wählen",
                                    initialdir=self._install_dir.get())
        if d:
            self._install_dir.set(d)

    # ── Installation ──────────────────────────────────────────────────────────

    def _log(self, text: str, tag: str = ""):
        def _do():
            self._log_text.configure(state="normal")
            self._log_text.insert("end", text + "\n", tag if tag else ())
            self._log_text.see("end")
            self._log_text.configure(state="disabled")
        self.after(0, _do)

    def _set_progress(self, pct: float):
        self.after(0, lambda: self._progress.configure(value=pct))

    def _set_current(self, text: str):
        self.after(0, lambda: self._current_tool_var.set(text))

    def _run_install(self):
        install_dir = Path(self._install_dir.get())
        install_dir.mkdir(parents=True, exist_ok=True)
        suite_dir   = install_dir / "suite"
        tools_dir   = install_dir / "tools"
        tools_dir.mkdir(parents=True, exist_ok=True)

        selected = [t for t in TOOLS if self._tool_vars.get(t["id"], tk.BooleanVar()).get()]
        total    = len(selected) + 3   # +3 für Suite-Kopie, Config, Shortcut
        done     = 0
        cfg      = {}

        def step(name: str):
            nonlocal done
            done += 1
            self._set_current(f"[{done}/{total}]  {name}")
            self._set_progress(done / total * 100)
            self._log(f"\n── {name}", "head")

        # 1. Suite-Dateien kopieren
        step("G4MEOVER Suite kopieren")
        src_suite = Path(__file__).parent.parent   # installer/ → suite/
        if src_suite.exists():
            if suite_dir.exists():
                shutil.rmtree(suite_dir)
            shutil.copytree(str(src_suite), str(suite_dir),
                            ignore=shutil.ignore_patterns(
                                "__pycache__", "*.pyc", "build", "dist",
                                ".git", "installer"))
            self._log("  ✓ Suite-Dateien kopiert", "ok")
        else:
            # Fallback: direkt aus GitHub klonen
            self._log("  Klone von GitHub...")
            try:
                subprocess.run(
                    ["git", "clone", "--depth=1",
                     "https://github.com/G4MEOVER18/g4meover-security-suite.git",
                     str(suite_dir)],
                    check=True, capture_output=True, timeout=180)
                self._log("  ✓ Geklont", "ok")
            except Exception as e:
                self._log(f"  [!] Fehler: {e}", "err")

        # 2. Tools installieren
        for tool in selected:
            tid  = tool["id"]
            step(tool["name"])

            if tool["type"] == "pip":
                ok = _run_pip(tool["pkgs"], self._log)
                self._log(("  ✓" if ok else "  ✗") + f" {tool['name']}", "ok" if ok else "err")

            elif tool["type"] == "winget":
                ok = _run_winget(tool["pkg"], self._log)
                if ok and "path" in tool and os.path.exists(tool["path"]):
                    cfg[f"tool_{tid}"] = tool["path"]
                self._log(("  ✓" if ok else "  ✗") + f" {tool['name']}", "ok" if ok else "err")

            elif tool["type"] == "github_release":
                dest_dir = tools_dir / tool["dest"]
                dest_dir.mkdir(parents=True, exist_ok=True)
                url = _get_github_release_url(tool["repo"], tool["asset"])
                if not url:
                    self._log(f"  [!] Release-URL nicht gefunden für {tool['repo']}", "err")
                    continue
                tmp = tools_dir / "_tmp.zip"
                ok  = _download(url, tmp, self._log,
                                lambda p: self._set_progress(done / total * 100 + p / total))
                if ok:
                    _unzip(tmp, dest_dir, self._log)
                    tmp.unlink(missing_ok=True)
                    exe = install_dir / tool["exe"]
                    # Flat-Extrakt: bin in Unterordner suchen
                    if not exe.exists():
                        for f in dest_dir.rglob(exe.name):
                            shutil.copy2(f, dest_dir / exe.name)
                            break
                    if (install_dir / tool["exe"]).exists():
                        cfg[f"tool_{tid}"] = str(install_dir / tool["exe"])
                        self._log(f"  ✓ {tool['name']}", "ok")
                    else:
                        self._log(f"  [!] EXE nicht gefunden: {tool['exe']}", "err")
                else:
                    self._log(f"  ✗ Download fehlgeschlagen", "err")

            elif tool["type"] == "direct":
                dest_dir = tools_dir / tool["dest"]
                dest_dir.mkdir(parents=True, exist_ok=True)
                fname = tool["url"].split("/")[-1]
                tmp   = tools_dir / fname
                ok    = _download(tool["url"], tmp, self._log)
                if ok:
                    if fname.endswith(".zip"):
                        _unzip(tmp, dest_dir, self._log)
                        tmp.unlink(missing_ok=True)
                    elif fname.endswith(".7z"):
                        self._log("  [!] 7z: bitte manuell entpacken nach " + str(dest_dir), "err")
                    exe_path = tools_dir / tool["exe"]
                    if exe_path.exists():
                        cfg[f"tool_{tid}"] = str(exe_path)
                        self._log(f"  ✓ {tool['name']}", "ok")

            elif tool["type"] == "git_clone":
                dest_dir = tools_dir / tool["dest"]
                dest_dir.mkdir(parents=True, exist_ok=True)
                ok = _git_clone_sparse(tool["url"], dest_dir,
                                        tool.get("sparse", []), self._log)
                if ok:
                    # searchsploit.py + .bat schreiben
                    (dest_dir / "searchsploit.py").write_text(SEARCHSPLOIT_PY, encoding="utf-8")
                    (dest_dir / "searchsploit.bat").write_text(SEARCHSPLOIT_BAT)
                    cfg["tool_searchsploit"] = str(dest_dir / "searchsploit.bat")
                    self._log(f"  ✓ ExploitDB", "ok")

            elif tool["type"] == "builtin":
                src_name = tool["src"]
                dest_dir = tools_dir / src_name
                dest_dir.mkdir(parents=True, exist_ok=True)
                # Python-Dateien aus Suite-Quellen kopieren
                suite_tool_dir = Path(__file__).parent.parent.parent / "tools" / src_name
                if not suite_tool_dir.exists():
                    # Versuche aus bekanntem Pfad
                    suite_tool_dir = Path(r"C:\tools") / src_name
                ok = False
                if suite_tool_dir.exists():
                    for f in suite_tool_dir.iterdir():
                        shutil.copy2(f, dest_dir / f.name)
                    ok = True
                else:
                    # .bat Wrapper anlegen (ohne .py – manuell nachliefern)
                    bat = dest_dir / f"{src_name}.bat"
                    bat.write_text(f"@echo off\npython \"%~dp0{src_name}.py\" %*\n")
                    ok = True
                if ok:
                    exe_path = tools_dir / tool["exe"]
                    cfg[f"tool_{src_name}"] = str(exe_path)
                    self._log(f"  ✓ {tool['name']} (builtin)", "ok")

        # 3. suite_config.json schreiben
        step("Konfiguration schreiben")
        cfg["workspace"] = str(install_dir / "pentest")
        cfg["theme"]     = "catppuccin_mocha"
        cfg_path = suite_dir / "suite_config.json"
        cfg_path.write_text(json.dumps(cfg, indent=2, ensure_ascii=False), encoding="utf-8")
        self._log(f"  ✓ {cfg_path}", "ok")

        # 4. Desktop-Verknüpfung
        step("Desktop-Verknüpfung")
        try:
            import winreg as _wr
            desktop = Path(os.path.join(os.environ.get("USERPROFILE", ""),
                                        "Desktop"))
            suite_main = suite_dir / "openclaw_suite.py"
            pythonw    = Path(sys.executable).parent / "pythonw.exe"
            if not pythonw.exists():
                pythonw = Path(sys.executable)

            import comtypes.client
            shell = comtypes.client.CreateObject("WScript.Shell")
        except Exception:
            try:
                import subprocess as sp
                desktop = Path(os.path.join(os.environ.get("USERPROFILE", ""), "Desktop"))
                suite_main = suite_dir / "openclaw_suite.py"
                ps = (
                    f'$s=(New-Object -COM WScript.Shell).CreateShortcut("{desktop}\\G4MEOVER Suite.lnk");'
                    f'$s.TargetPath="{sys.executable}";'
                    f'$s.Arguments="{suite_main}";'
                    f'$s.WorkingDirectory="{suite_dir}";'
                    f'$s.Description="G4MEOVER Security Suite v{VERSION}";'
                    f'$s.Save()'
                )
                sp.run(["powershell", "-Command", ps], capture_output=True, timeout=15)
                self._log(f"  ✓ Desktop-Verknüpfung erstellt", "ok")
            except Exception as e:
                self._log(f"  [!] Shortcut: {e}", "err")

        self._log("\n══════════════════════════════════════════", "head")
        self._log(f"Installation abgeschlossen!", "ok")
        self._log(f"Suite-Pfad: {suite_dir}", "ok")
        self._log(f"Tools-Pfad: {tools_dir}", "ok")

        suite_main = suite_dir / "openclaw_suite.py"
        self._suite_path = str(suite_main)
        msg = (f"Suite installiert in:\n{suite_dir}\n\n"
               f"Tools installiert in:\n{tools_dir}")
        self.after(0, lambda: self._done_msg.configure(text=msg))
        self.after(0, lambda: self._show_page(4))

    def _launch_suite(self):
        if hasattr(self, "_suite_path") and os.path.exists(self._suite_path):
            subprocess.Popen([sys.executable, self._suite_path],
                             cwd=os.path.dirname(self._suite_path))
        self.destroy()


def main():
    app = InstallerApp()
    app.mainloop()


if __name__ == "__main__":
    main()
