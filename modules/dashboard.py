"""Dashboard – Tool-Status, Ziel-Context, Activity-Log, Quickstarts."""
import tkinter as tk
from tkinter import ttk
from datetime import datetime
from modules.base import BaseModule
from utils.theme import DARK

TOOL_DISPLAY = [
    ("nmap",         "nmap  (Port-Scanner)"),
    ("hashcat",      "hashcat  (Hash-Cracker)"),
    ("gobuster",     "gobuster  (Dir-Scanner)"),
    ("feroxbuster",  "feroxbuster  (Dir-Scanner)"),
    ("nikto",        "nikto  (HTTP-Scanner)"),
    ("sqlmap",       "sqlmap  (SQL-Injection)"),
    ("hydra",        "hydra  (Brute-Force)"),
    ("john",         "john  (Password-Cracker)"),
    ("masscan",      "masscan  (Mass-Scanner)"),
    ("tshark",       "tshark  (Packet-Capture)"),
    ("msfconsole",   "msfconsole  (Metasploit)"),
    ("searchsploit", "searchsploit  (ExploitDB)"),
]

TOOL_TIPS = {
    "nmap":         "nmap – Netzwerk-Port-Scanner.\nErkennt offene Ports, Dienste, Betriebssysteme.",
    "hashcat":      "hashcat – GPU-beschleunigter Hash-Cracker.\nSupports MD5, SHA, NTLM, WPA und 300+ weitere.",
    "gobuster":     "gobuster – Directory-Bruteforcer.\nFindet versteckte Pfade/Dateien auf Webservern.",
    "feroxbuster":  "feroxbuster – Rekursiver Directory-Scanner.\nAlternative zu gobuster mit Auto-Calibration.",
    "nikto":        "nikto – Web-Server-Scanner.\nPrüft auf bekannte Schwachstellen und Fehlkonfigurationen.",
    "sqlmap":       "sqlmap – SQL-Injection-Tool.\nErkennt und exploitet SQL-Injection automatisch.",
    "hydra":        "hydra – Online-Brute-Force.\nTestet SSH, FTP, HTTP, RDP und 50+ weitere Protokolle.",
    "john":         "John the Ripper – CPU-Passwort-Cracker.\nKnackt Hashes, ZIP/RAR, Shadow-Dateien und mehr.",
    "masscan":      "masscan – Ultra-schneller Massen-Scanner.\nKann das gesamte IPv4-Internet in Minuten scannen.",
    "tshark":       "tshark – Kommandozeilen-Wireshark.\nPacket-Capture und -Analyse für PCAP-Dateien.",
    "msfconsole":   "Metasploit Framework – Exploit-Arsenal.\nTausende Exploits, Payloads und Post-Exploitation-Module.",
    "searchsploit": "searchsploit – ExploitDB CLI.\nDurchsucht ~50.000 Exploits lokal ohne Internet.",
}


class DashboardModule(BaseModule):

    def __init__(self, parent, cfg, target_var, activity_cb, tools,
                 notebook_select_cb=None):
        self._notebook_select = notebook_select_cb
        self._activity_lines: list[str] = []
        super().__init__(parent, cfg, target_var, activity_cb, tools)

    def _build(self):
        # ── Ziel-Context-Bar ─────────────────────────────────────────────────
        top = tk.Frame(self, bg=DARK["panel"]); top.pack(fill="x", padx=8, pady=(8, 4))
        tk.Label(top, text="Aktuelles Ziel:",
                 bg=DARK["panel"], fg=DARK["border"],
                 font=("Segoe UI", 9)).pack(side="left", padx=(10, 4))
        tk.Entry(top, textvariable=self._target_var,
                 bg=DARK["entry"], fg=DARK["fg"],
                 insertbackground=DARK["fg"], relief="flat",
                 font=("Segoe UI", 10, "bold"), width=32).pack(side="left", ipady=4)
        tk.Label(top, text="  IP / Domain / CIDR",
                 bg=DARK["panel"], fg=DARK["border"],
                 font=("Segoe UI", 8)).pack(side="left")

        main = tk.Frame(self, bg=DARK["bg"]); main.pack(fill="both", expand=True, padx=8, pady=4)

        # ── Linke Spalte: Tool-Status ─────────────────────────────────────────
        left = tk.Frame(main, bg=DARK["bg"]); left.pack(side="left", fill="y", padx=(0, 8))
        fstatus = self._section(left, "Tool-Status")
        self._status_labels: dict[str, tk.Label] = {}
        for tool, label in TOOL_DISPLAY:
            row = tk.Frame(fstatus, bg=DARK["bg"]); row.pack(fill="x", padx=10, pady=1)
            installed = bool(self._tools.get(tool))
            dot   = "●" if installed else "○"
            color = DARK["green"] if installed else DARK["border"]
            lbl = tk.Label(row, text=f"{dot}  {label}",
                           bg=DARK["bg"], fg=color,
                           font=("Segoe UI", 9), anchor="w", width=26)
            lbl.pack(side="left")
            self._status_labels[tool] = lbl
            if tool in TOOL_TIPS:
                from modules.base import _Tooltip
                _Tooltip(lbl, TOOL_TIPS[tool])
            path = self._tools.get(tool, "")
            tk.Label(row, text=path[:38] if path else "nicht gefunden",
                     bg=DARK["bg"], fg=DARK["border"] if not path else DARK["fg"],
                     font=("Segoe UI", 7), anchor="w").pack(side="left")

        ttk.Button(fstatus, text="Tools erneut suchen",
                   command=self._redetect).pack(padx=10, pady=(4, 6), anchor="w")

        # ── Rechte Spalte: Quickstart + Activity ──────────────────────────────
        right = tk.Frame(main, bg=DARK["bg"]); right.pack(side="left", fill="both", expand=True)

        fqs = self._section(right, "Quickstart")
        qs_items = [
            ("Host-Discovery  (nmap -sn)",       2, self._qs_discovery,
             "Öffnet Netzwerk-Tab mit Host-Discovery-Profil. Findet lebende Hosts im Netzwerk."),
            ("Port-Scan Standard  (nmap -sV)",   2, self._qs_portscan,
             "Öffnet Netzwerk-Tab mit Standard-Profil. Erkennt offene Ports und Dienste."),
            ("Web Quick-Scan  (gobuster + nikto)", 5, self._qs_web,
             "Öffnet Web-Testing-Tab für Directory-Scan und HTTP-Schwachstellensuche."),
            ("WPA-Crack starten",                 3, self._qs_wpa,
             "Öffnet WiFi/WPA-Tab zum Laden einer PCAP-Datei und Starten von hashcat."),
            ("OSINT-Recon",                       6, self._qs_osint,
             "Öffnet OSINT-Tab für WhoIs, DNS, Geolokation und Subdomain-Suche."),
        ]
        for text, tab_idx, cmd, tip in qs_items:
            btn = ttk.Button(fqs, text=text, command=cmd)
            btn.pack(fill="x", padx=10, pady=2)
            self._tooltip(btn, tip)

        fact = self._section_expand(right, "Letzte Aktivitäten")
        fact.pack(fill="both", expand=True)
        self._act_text = tk.Text(fact, bg=DARK["panel"], fg=DARK["border"],
                                 font=("Consolas", 8), relief="flat",
                                 wrap="word", height=14, state="disabled")
        sb = ttk.Scrollbar(fact, command=self._act_text.yview)
        self._act_text.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self._act_text.pack(fill="both", expand=True, padx=6, pady=6)

        self._add_activity("G4MEOVER Security Suite gestartet.")

    def add_activity(self, text: str):
        self._add_activity(text)

    def _add_activity(self, text: str):
        ts = datetime.now().strftime("%H:%M:%S")
        line = f"[{ts}]  {text}\n"
        self._activity_lines.append(line)
        if len(self._activity_lines) > 200:
            self._activity_lines.pop(0)
        self._act_text.configure(state="normal")
        self._act_text.insert("end", line)
        self._act_text.see("end")
        self._act_text.configure(state="disabled")

    def refresh_tools(self, tools: dict):
        self._tools = tools
        for tool, label_widget in self._status_labels.items():
            installed = bool(tools.get(tool))
            dot   = "●" if installed else "○"
            color = DARK["green"] if installed else DARK["border"]
            _, desc = next(d for t, d in TOOL_DISPLAY if t == tool), ""
            label_widget.configure(text=f"{dot}  {label_widget.cget('text')[3:]}",
                                   fg=color)

    def _redetect(self):
        from utils.tool_detector import detect_all
        new_tools = detect_all(self.cfg)
        self.refresh_tools(new_tools)
        self._add_activity("Tool-Erkennung abgeschlossen.")

    def _qs_discovery(self):
        if self._notebook_select:
            self._notebook_select(1)

    def _qs_portscan(self):
        if self._notebook_select:
            self._notebook_select(1)

    def _qs_web(self):
        if self._notebook_select:
            self._notebook_select(4)

    def _qs_wpa(self):
        if self._notebook_select:
            self._notebook_select(2)

    def _qs_osint(self):
        if self._notebook_select:
            self._notebook_select(5)
