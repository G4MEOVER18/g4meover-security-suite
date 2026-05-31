"""Einstellungen – Tool-Pfade, API-Keys, Workspace, Proxy."""
import tkinter as tk
from tkinter import ttk, messagebox
import json
from pathlib import Path
from modules.base import BaseModule
from utils.theme import DARK
from utils.tool_detector import TOOL_HINTS, detect_tool

CONFIG_FILE = Path(__file__).parent.parent / "suite_config.json"

TOOL_NAMES = [
    "nmap", "hashcat", "gobuster", "feroxbuster", "nikto",
    "sqlmap", "hydra", "john", "masscan", "tshark",
    "msfconsole", "searchsploit", "whatweb",
]


class SettingsModule(BaseModule):

    def _build(self):
        canvas = tk.Canvas(self, bg=DARK["bg"], highlightthickness=0)
        scrollbar = ttk.Scrollbar(self, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)

        inner = tk.Frame(canvas, bg=DARK["bg"])
        win   = canvas.create_window((0, 0), window=inner, anchor="nw")

        def _on_resize(e):
            canvas.itemconfig(win, width=e.width)
        canvas.bind("<Configure>", _on_resize)
        inner.bind("<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all")))

        self._tool_vars: dict[str, tk.StringVar] = {}
        ft = self._section(inner, "Tool-Pfade")
        self._info_bar(ft, "Vollständige Pfade zu den externen Tools. Leer = deaktiviert. '…'-Button zum Durchsuchen.")
        for tool in TOOL_NAMES:
            row = tk.Frame(ft, bg=DARK["bg"]); row.pack(fill="x", padx=10, pady=1)
            tk.Label(row, text=f"{tool}:", bg=DARK["bg"], fg=DARK["fg"],
                     font=("Segoe UI", 8), width=14, anchor="w").pack(side="left")
            var = tk.StringVar(value=self.cfg.get(f"tool_{tool}", ""))
            self._tool_vars[tool] = var
            entry = tk.Entry(row, textvariable=var,
                     bg=DARK["entry"], fg=DARK["fg"],
                     insertbackground=DARK["fg"], relief="flat",
                     font=("Consolas", 8), width=42)
            entry.pack(side="left", padx=4, ipady=2)
            browse_btn = ttk.Button(row, text="…",
                       command=lambda t=tool, v=var: self._browse_tool(t, v))
            browse_btn.pack(side="left")

        auto_btn = ttk.Button(ft, text="Tools automatisch erkennen",
                   command=self._auto_detect)
        auto_btn.pack(padx=10, pady=6, anchor="w")
        self._tooltip(auto_btn,
            "Sucht automatisch nach installierten Tools in bekannten Standardpfaden und füllt leere Felder aus.")

        fa = self._section(inner, "API-Keys")
        self._info_bar(fa,
            "Shodan: Kostenloses Konto auf shodan.io registrieren → API-Key unter 'My Account'. VirusTotal: virustotal.com → API-Key (kostenlos, 4 Anfragen/min).")
        self._api_vars: dict[str, tk.StringVar] = {}
        for name, key in [("Shodan API-Key:", "shodan_api_key"),
                          ("VirusTotal API-Key:", "virustotal_api_key")]:
            arow = tk.Frame(fa, bg=DARK["bg"]); arow.pack(fill="x", padx=10, pady=2)
            tk.Label(arow, text=name, bg=DARK["bg"], fg=DARK["fg"],
                     font=("Segoe UI", 8), width=18, anchor="w").pack(side="left")
            var = tk.StringVar(value=self.cfg.get(key, ""))
            self._api_vars[key] = var
            tk.Entry(arow, textvariable=var,
                     bg=DARK["entry"], fg=DARK["fg"],
                     insertbackground=DARK["fg"], relief="flat",
                     font=("Consolas", 8), width=44, show="*").pack(side="left", padx=4, ipady=2)

        fw = self._section(inner, "Workspace")
        self._info_bar(fw,
            "Standard-Ausgabeverzeichnis für alle Tool-Ergebnisse (nmap XML, Report-Dateien, Screenshots). Wird automatisch erstellt wenn nicht vorhanden.")
        self._ws_var = tk.StringVar(value=self.cfg.get("workspace",
                                    str(Path.home() / "pentest")))
        wrow = tk.Frame(fw, bg=DARK["bg"]); wrow.pack(fill="x", padx=10, pady=4)
        tk.Entry(wrow, textvariable=self._ws_var,
                 bg=DARK["entry"], fg=DARK["fg"],
                 insertbackground=DARK["fg"], relief="flat",
                 font=("Consolas", 8)).pack(side="left", fill="x", expand=True, ipady=2)
        ttk.Button(wrow, text="…",
                   command=lambda: self._browse_dir(self._ws_var)).pack(side="left", padx=4)

        fp = self._section(inner, "Proxy")
        self._info_bar(fp,
            "Proxy für Web-Module (sqlmap, nikto, Tech-Fingerprint). Format: http://127.0.0.1:8080 (z.B. Burp Suite oder mitmproxy).")
        self._proxy_var = tk.StringVar(value=self.cfg.get("proxy", ""))
        prow = tk.Frame(fp, bg=DARK["bg"]); prow.pack(fill="x", padx=10, pady=4)
        tk.Label(prow, text="HTTP-Proxy:", bg=DARK["bg"], fg=DARK["fg"],
                 font=("Segoe UI", 8), width=12, anchor="w").pack(side="left")
        tk.Entry(prow, textvariable=self._proxy_var,
                 bg=DARK["entry"], fg=DARK["fg"],
                 insertbackground=DARK["fg"], relief="flat",
                 font=("Consolas", 8), width=30).pack(side="left", padx=4, ipady=2)
        tk.Label(prow, text="z.B. http://127.0.0.1:8080",
                 bg=DARK["bg"], fg=DARK["border"],
                 font=("Segoe UI", 7, "italic")).pack(side="left")

        btn_row = tk.Frame(inner, bg=DARK["bg"]); btn_row.pack(fill="x", padx=10, pady=12)
        ttk.Button(btn_row, text="Einstellungen speichern",
                   style="Accent.TButton",
                   command=self._save).pack(side="left")
        ttk.Button(btn_row, text="Zurücksetzen",
                   command=self._load_defaults).pack(side="left", padx=6)

    def _browse_tool(self, tool: str, var: tk.StringVar):
        self._browse_file(var, f"{tool} auswählen",
                          [("Ausführbare Datei", "*.exe *.bat *.sh *"),
                           ("Alle", "*.*")])

    def _auto_detect(self):
        from utils.tool_detector import detect_all
        found = detect_all(self.cfg)
        for tool, var in self._tool_vars.items():
            if found.get(tool):
                var.set(found[tool])
        messagebox.showinfo("Tool-Erkennung",
                            f"{sum(1 for v in found.values() if v)} Tools erkannt.")

    def _save(self):
        cfg = dict(self.cfg)
        for tool, var in self._tool_vars.items():
            val = var.get().strip()
            if val:
                cfg[f"tool_{tool}"] = val
        for key, var in self._api_vars.items():
            cfg[key] = var.get().strip()
        cfg["workspace"] = self._ws_var.get().strip()
        cfg["proxy"]     = self._proxy_var.get().strip()
        try:
            CONFIG_FILE.write_text(json.dumps(cfg, indent=2, ensure_ascii=False),
                                   encoding="utf-8")
            self.cfg.update(cfg)
            messagebox.showinfo("Gespeichert", f"Einstellungen → {CONFIG_FILE}")
        except Exception as e:
            messagebox.showerror("Fehler", str(e))

    def _load_defaults(self):
        for tool, var in self._tool_vars.items():
            detected = detect_tool(tool)
            var.set(detected or "")
