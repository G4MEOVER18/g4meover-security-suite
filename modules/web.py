"""Web-Testing – gobuster/feroxbuster, nikto, sqlmap, Tech-Fingerprint."""
import tkinter as tk
from tkinter import ttk, messagebox
import re
import urllib.request
import urllib.error
import threading
from modules.base import BaseModule
from utils.theme import DARK

STATUS_COLORS = {
    "2": DARK["green"],
    "3": DARK["yellow"],
    "4": DARK["orange"],
    "5": DARK["red"],
}

WORDLISTS_GOBUSTER = [
    ("common.txt   (~4.6k)",        r"C:\tools\gobuster\wordlists\common.txt"),
    ("big.txt      (~20k)",         r"C:\tools\gobuster\wordlists\big.txt"),
    ("raft-medium   (~167k)",       r"C:\tools\gobuster\wordlists\raft-medium-directories.txt"),
    ("directory-list-2.3-medium",   r"C:\tools\gobuster\wordlists\directory-list-2.3-medium.txt"),
]

EXTENSIONS = ".php,.html,.asp,.aspx,.jsp,.txt,.bak,.conf,.log,.xml,.json"


class WebModule(BaseModule):

    def _build(self):
        self._info_bar(self,
            "Web-Testing: Dir-Scanner (gobuster/feroxbuster) · HTTP-Scanner (nikto) · SQL-Injection (sqlmap) · Tech-Fingerprint")

        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True)

        t1 = ttk.Frame(nb); nb.add(t1, text="  Dir-Scanner  ")
        t2 = ttk.Frame(nb); nb.add(t2, text="  HTTP-Scanner (nikto)  ")
        t3 = ttk.Frame(nb); nb.add(t3, text="  SQL-Injection  ")
        t4 = ttk.Frame(nb); nb.add(t4, text="  Tech-Fingerprint  ")

        self._build_dirscan(t1)
        self._build_nikto(t2)
        self._build_sqlmap(t3)
        self._build_techfp(t4)

    # ── Dir-Scanner ────────────────────────────────────────────────────────────

    def _build_dirscan(self, parent):
        self._info_bar(parent,
            "gobuster/feroxbuster: Brute-Force-Suche nach versteckten Verzeichnissen und Dateien auf einem Webserver.")

        left  = tk.Frame(parent, bg=DARK["bg"])
        right = tk.Frame(parent, bg=DARK["bg"])
        left.pack(side="left", fill="y", padx=(8, 4), pady=8)
        left.configure(width=360); left.pack_propagate(False)
        right.pack(side="left", fill="both", expand=True, padx=(4, 8), pady=8)

        fz = self._section(left, "Ziel-URL")
        self._dir_url = tk.StringVar(value=f"http://{self._target_var.get()}")
        self._target_var.trace_add("write",
            lambda *_: self._dir_url.set(f"http://{self._target_var.get()}"))
        self._entry_row(fz, "", self._dir_url)

        ft = self._section(left, "Tool")
        self._dir_tool_cb = ttk.Combobox(ft, state="readonly",
                                          values=["gobuster", "feroxbuster"],
                                          font=("Segoe UI", 9))
        self._dir_tool_cb.current(0)
        self._dir_tool_cb.pack(fill="x", padx=10, pady=4)
        self._tooltip(self._dir_tool_cb,
            "gobuster: Schneller, threaded Go-Scanner (empfohlen)\n"
            "feroxbuster: Ähnlich, aber mit Rekursion und Auto-Calibration")

        fw = self._section(left, "Wortliste")
        self._dir_wl_cb = ttk.Combobox(fw, state="readonly",
                                         values=[w[0] for w in WORDLISTS_GOBUSTER],
                                         font=("Segoe UI", 8))
        self._dir_wl_cb.current(0)
        self._dir_wl_cb.pack(fill="x", padx=10, pady=4)
        wl_cust_row = tk.Frame(fw, bg=DARK["bg"]); wl_cust_row.pack(fill="x", padx=10, pady=2)
        self._dir_wl_custom = tk.StringVar()
        tk.Entry(wl_cust_row, textvariable=self._dir_wl_custom,
                 bg=DARK["entry"], fg=DARK["fg"],
                 insertbackground=DARK["fg"], relief="flat",
                 font=("Segoe UI", 8)).pack(side="left", fill="x", expand=True, ipady=2)
        ttk.Button(wl_cust_row, text="…",
                   command=lambda: self._browse_file(self._dir_wl_custom, "Wortliste",
                                                     [("Wortlisten","*.txt"), ("Alle","*")])
                   ).pack(side="left", padx=(2, 0))

        fo = self._section(left, "Optionen")
        tk.Label(fo, text="Extensions:", bg=DARK["bg"], fg=DARK["fg"],
                 font=("Segoe UI", 8)).pack(anchor="w", padx=10)
        self._dir_ext = tk.StringVar(value=EXTENSIONS)
        tk.Entry(fo, textvariable=self._dir_ext,
                 bg=DARK["entry"], fg=DARK["fg"],
                 insertbackground=DARK["fg"], relief="flat",
                 font=("Consolas", 8)).pack(fill="x", padx=10, pady=2, ipady=2)
        orow = tk.Frame(fo, bg=DARK["bg"]); orow.pack(fill="x", padx=10, pady=4)
        tk.Label(orow, text="Threads:", bg=DARK["bg"], fg=DARK["fg"],
                 font=("Segoe UI", 8)).pack(side="left")
        self._dir_threads = ttk.Spinbox(orow, from_=1, to=100, width=4)
        self._dir_threads.set("20"); self._dir_threads.pack(side="left", padx=4)
        self._dir_status_var = tk.StringVar(value="200,204,301,302,403")
        tk.Label(orow, text="Status:", bg=DARK["bg"], fg=DARK["fg"],
                 font=("Segoe UI", 8)).pack(side="left", padx=(8, 0))
        tk.Entry(orow, textvariable=self._dir_status_var, width=18,
                 bg=DARK["entry"], fg=DARK["fg"],
                 insertbackground=DARK["fg"], relief="flat",
                 font=("Segoe UI", 8)).pack(side="left", padx=4, ipady=2)

        btn = tk.Frame(left, bg=DARK["bg"]); btn.pack(fill="x", padx=10, pady=8)
        self._dir_start = ttk.Button(btn, text="Scan starten", style="Accent.TButton",
                                      command=self._run_dirscan)
        self._dir_start.pack(side="left", fill="x", expand=True)
        self._dir_stop  = ttk.Button(btn, text="Stoppen", style="Danger.TButton",
                                      command=self._stop_tool, state="disabled")
        self._dir_stop.pack(side="left", fill="x", expand=True, padx=(6, 0))

        # Treeview für Ergebnisse
        fres = self._section_expand(right, "Gefundene Pfade")
        fres.pack(fill="both", expand=True)
        cols = ("status", "size", "url")
        self._dir_tree = ttk.Treeview(fres, columns=cols, show="headings",
                                       selectmode="browse", height=12)
        self._dir_tree.heading("status", text="Status")
        self._dir_tree.heading("size",   text="Größe")
        self._dir_tree.heading("url",    text="URL / Pfad")
        self._dir_tree.column("status", width=60, minwidth=50)
        self._dir_tree.column("size",   width=80, minwidth=60)
        self._dir_tree.column("url",    width=500)
        for code, color in STATUS_COLORS.items():
            self._dir_tree.tag_configure(f"s{code}", foreground=color)
        dsb = ttk.Scrollbar(fres, command=self._dir_tree.yview)
        self._dir_tree.configure(yscrollcommand=dsb.set)
        dsb.pack(side="right", fill="y")
        self._dir_tree.pack(fill="both", expand=True, padx=6, pady=4)

        self._dir_count = tk.StringVar(value="")
        tk.Label(right, textvariable=self._dir_count,
                 bg=DARK["bg"], fg=DARK["accent"],
                 font=("Segoe UI", 8)).pack(anchor="w", padx=10)

        self._dir_log = self._log_widget(right, height=5)

    def _run_dirscan(self):
        tool_name = self._dir_tool_cb.get()
        tool = self._require_tool(tool_name, self._dir_log)
        if not tool:
            return
        url = self._dir_url.get().strip()
        if not url:
            messagebox.showerror("Fehler", "Bitte eine Ziel-URL angeben."); return
        wl = self._dir_wl_custom.get().strip()
        if not wl:
            idx = self._dir_wl_cb.current()
            wl = WORDLISTS_GOBUSTER[idx][1] if idx >= 0 else ""
        if not wl:
            messagebox.showerror("Fehler", "Bitte eine Wortliste angeben."); return

        self._dir_tree.delete(*self._dir_tree.get_children())
        self._dir_count.set("")

        if tool_name == "gobuster":
            cmd = [tool, "dir", "-u", url, "-w", wl,
                   "-t", self._dir_threads.get(),
                   "-x", self._dir_ext.get(),
                   "--status-codes", self._dir_status_var.get(),
                   "--no-color"]
        else:
            cmd = [tool, "-u", url, "-w", wl,
                   "-t", self._dir_threads.get(),
                   "-x", self._dir_ext.get(),
                   "--no-recursion"]

        self._dir_found = 0
        self._run_tool(cmd, None, self._dir_log,
                       on_line=self._parse_dir_line,
                       on_done=lambda rc: self._dir_count.set(f"{self._dir_found} Pfad(e) gefunden"),
                       start_btn=self._dir_start, stop_btn=self._dir_stop)

    _DIR_RE = re.compile(r"(/\S+)\s+\(Status:\s*(\d+)\).*?Size:\s*(\d+)", re.I)
    _FEROX_RE = re.compile(r"(\d{3})\s+\d+\w\s+\d+\w\s+(.+)")

    def _parse_dir_line(self, line: str):
        m = self._DIR_RE.search(line)
        if not m:
            m2 = self._FEROX_RE.match(line.strip())
            if m2:
                status, url_part = m2.groups()
                tag = f"s{status[0]}"
                self._dir_tree.insert("", "end",
                                      values=(status, "—", url_part.strip()),
                                      tags=(tag,))
                self._dir_found += 1
            return
        path, status, size = m.groups()
        tag = f"s{status[0]}"
        self._dir_tree.insert("", "end",
                              values=(status, f"{size} B", path),
                              tags=(tag,))
        self._dir_found += 1

    # ── Nikto ─────────────────────────────────────────────────────────────────

    def _build_nikto(self, parent):
        self._info_bar(parent,
            "nikto: HTTP-Server-Scanner. Prüft auf bekannte Schwachstellen, fehlerhafte Konfigurationen und veraltete Software.")

        left  = tk.Frame(parent, bg=DARK["bg"])
        right = tk.Frame(parent, bg=DARK["bg"])
        left.pack(side="left", fill="y", padx=(8, 4), pady=8)
        left.configure(width=320); left.pack_propagate(False)
        right.pack(side="left", fill="both", expand=True, padx=(4, 8), pady=8)

        fz = self._section(left, "Ziel")
        self._nk_host = tk.StringVar(value=self._target_var.get())
        self._target_var.trace_add("write",
            lambda *_: self._nk_host.set(self._target_var.get()))
        self._entry_row(fz, "Host:", self._nk_host)
        self._nk_port = tk.StringVar(value="80")
        self._entry_row(fz, "Port:", self._nk_port)
        self._nk_ssl = tk.BooleanVar()
        ttk.Checkbutton(fz, text="-ssl (HTTPS)", variable=self._nk_ssl).pack(padx=10, anchor="w", pady=4)

        fo = self._section(left, "Optionen")
        self._nk_tuning = tk.StringVar(value="1234578")
        tk.Label(fo, text="-Tuning:", bg=DARK["bg"], fg=DARK["fg"],
                 font=("Segoe UI", 8)).pack(anchor="w", padx=10)
        tk.Entry(fo, textvariable=self._nk_tuning, width=12,
                 bg=DARK["entry"], fg=DARK["fg"],
                 insertbackground=DARK["fg"], relief="flat",
                 font=("Segoe UI", 9)).pack(anchor="w", padx=10, pady=2, ipady=2)
        tk.Label(fo, text="1=Interesting,2=Misc,3=Auth,4=Deflt,5=Inj,\n6=Deny,7=RemFileRet,8=Cmd",
                 bg=DARK["bg"], fg=DARK["border"],
                 font=("Segoe UI", 7), justify="left").pack(padx=10, anchor="w", pady=(0, 4))

        btn = tk.Frame(left, bg=DARK["bg"]); btn.pack(fill="x", padx=10, pady=8)
        self._nk_start = ttk.Button(btn, text="Scan starten", style="Accent.TButton",
                                     command=self._run_nikto)
        self._nk_start.pack(side="left", fill="x", expand=True)
        self._nk_stop  = ttk.Button(btn, text="Stoppen", style="Danger.TButton",
                                     command=self._stop_tool, state="disabled")
        self._nk_stop.pack(side="left", fill="x", expand=True, padx=(6, 0))

        fres = self._section_expand(right, "Findings")
        fres.pack(fill="both", expand=True)
        cols = ("ref", "finding")
        self._nk_tree = ttk.Treeview(fres, columns=cols, show="headings", height=14)
        self._nk_tree.heading("ref",     text="Ref / ID")
        self._nk_tree.heading("finding", text="Finding")
        self._nk_tree.column("ref",     width=100, minwidth=60)
        self._nk_tree.column("finding", width=500)
        nsb = ttk.Scrollbar(fres, command=self._nk_tree.yview)
        self._nk_tree.configure(yscrollcommand=nsb.set)
        nsb.pack(side="right", fill="y")
        self._nk_tree.pack(fill="both", expand=True, padx=6, pady=4)
        self._nk_log = self._log_widget(right, height=5)

    _NK_RE = re.compile(r"\+\s*(OSVDB-\d+|\bSVCL\b|\S+):\s*(.*)")

    def _run_nikto(self):
        nikto = self._require_tool("nikto", self._nk_log)
        if not nikto:
            return
        host = self._nk_host.get().strip()
        if not host:
            messagebox.showerror("Fehler", "Bitte einen Host angeben."); return
        cmd = [nikto, "-h", host, "-p", self._nk_port.get(),
               "-Tuning", self._nk_tuning.get(), "-nointeractive"]
        if self._nk_ssl.get():
            cmd.append("-ssl")
        self._nk_tree.delete(*self._nk_tree.get_children())
        self._run_tool(cmd, None, self._nk_log,
                       on_line=self._parse_nikto_line,
                       start_btn=self._nk_start, stop_btn=self._nk_stop)

    def _parse_nikto_line(self, line: str):
        m = self._NK_RE.match(line.strip())
        if m:
            ref, finding = m.groups()
            self._nk_tree.insert("", "end", values=(ref, finding.strip()))

    # ── sqlmap ─────────────────────────────────────────────────────────────────

    def _build_sqlmap(self, parent):
        self._info_bar(parent,
            "sqlmap: Automatische SQL-Injection-Erkennung. Testet URLs/Parameter auf SQL-Injection und kann Datenbanken extrahieren.")

        left  = tk.Frame(parent, bg=DARK["bg"])
        right = tk.Frame(parent, bg=DARK["bg"])
        left.pack(side="left", fill="y", padx=(8, 4), pady=8)
        left.configure(width=360); left.pack_propagate(False)
        right.pack(side="left", fill="both", expand=True, padx=(4, 8), pady=8)

        fz = self._section(left, "Ziel")
        self._sql_url = tk.StringVar(value=f"http://{self._target_var.get()}/")
        self._target_var.trace_add("write",
            lambda *_: self._sql_url.set(f"http://{self._target_var.get()}/"))
        self._entry_row(fz, "URL:", self._sql_url)
        self._sql_params = tk.StringVar()
        self._entry_row(fz, "Params:", self._sql_params)
        tk.Label(fz, text="z.B. id=1 (leer = automatisch erkennen)",
                 bg=DARK["bg"], fg=DARK["border"],
                 font=("Segoe UI", 7)).pack(anchor="w", padx=10, pady=(0, 4))

        fm = self._section(left, "Methode")
        self._sql_method_cb = ttk.Combobox(fm, state="readonly",
                                            values=["GET", "POST"],
                                            font=("Segoe UI", 9))
        self._sql_method_cb.current(0)
        self._sql_method_cb.pack(fill="x", padx=10, pady=4)
        self._sql_data = tk.StringVar()
        self._entry_row(fm, "POST-Data:", self._sql_data)

        fa = self._section(left, "Aktionen")
        self._sql_dbs   = tk.BooleanVar(value=True)
        self._sql_tbls  = tk.BooleanVar()
        self._sql_dump  = tk.BooleanVar()
        self._sql_shell = tk.BooleanVar()
        action_tips = {
            "--dbs (Datenbanken)": "Listet alle Datenbanken auf dem Server auf.",
            "--tables":            "Listet Tabellen in der aktuellen Datenbank auf.",
            "--dump":              "Extrahiert alle Daten aus gefundenen Tabellen.",
            "--os-shell":         "Versucht eine OS-Shell zu öffnen (nur wenn Injection sehr tiefgreifend).",
        }
        for var, text in [(self._sql_dbs, "--dbs (Datenbanken)"),
                          (self._sql_tbls, "--tables"),
                          (self._sql_dump, "--dump"),
                          (self._sql_shell, "--os-shell")]:
            cb = ttk.Checkbutton(fa, text=text, variable=var)
            cb.pack(padx=10, anchor="w")
            self._tooltip(cb, action_tips.get(text, ""))

        fo = self._section(left, "Optionen")
        orow = tk.Frame(fo, bg=DARK["bg"]); orow.pack(fill="x", padx=10, pady=4)
        tk.Label(orow, text="Level:", bg=DARK["bg"], fg=DARK["fg"],
                 font=("Segoe UI", 8)).pack(side="left")
        self._sql_level = ttk.Spinbox(orow, from_=1, to=5, width=3)
        self._sql_level.set("1"); self._sql_level.pack(side="left", padx=4)
        tk.Label(orow, text="Risk:", bg=DARK["bg"], fg=DARK["fg"],
                 font=("Segoe UI", 8)).pack(side="left", padx=(8, 0))
        self._sql_risk = ttk.Spinbox(orow, from_=1, to=3, width=3)
        self._sql_risk.set("1"); self._sql_risk.pack(side="left", padx=4)
        self._sql_batch = tk.BooleanVar(value=True)
        ttk.Checkbutton(fo, text="--batch (nicht interaktiv)",
                        variable=self._sql_batch).pack(padx=10, anchor="w", pady=(0, 4))

        btn = tk.Frame(left, bg=DARK["bg"]); btn.pack(fill="x", padx=10, pady=8)
        self._sql_start = ttk.Button(btn, text="Scan starten", style="Accent.TButton",
                                      command=self._run_sqlmap)
        self._sql_start.pack(side="left", fill="x", expand=True)
        self._sql_stop  = ttk.Button(btn, text="Stoppen", style="Danger.TButton",
                                      command=self._stop_tool, state="disabled")
        self._sql_stop.pack(side="left", fill="x", expand=True, padx=(6, 0))

        self._sql_log = self._log_widget(right)

    def _run_sqlmap(self):
        sqlmap = self._require_tool("sqlmap", self._sql_log)
        if not sqlmap:
            return
        url = self._sql_url.get().strip()
        if not url:
            messagebox.showerror("Fehler", "Bitte eine URL angeben."); return
        cmd = ["python", sqlmap, "-u", url,
               "--level", self._sql_level.get(),
               "--risk",  self._sql_risk.get()]
        params = self._sql_params.get().strip()
        if params:
            cmd += ["-p", params]
        data = self._sql_data.get().strip()
        if data:
            cmd += ["--data", data]
        if self._sql_dbs.get():   cmd.append("--dbs")
        if self._sql_tbls.get():  cmd.append("--tables")
        if self._sql_dump.get():  cmd.append("--dump")
        if self._sql_shell.get(): cmd.append("--os-shell")
        if self._sql_batch.get(): cmd.append("--batch")
        self._run_tool(cmd, None, self._sql_log,
                       start_btn=self._sql_start, stop_btn=self._sql_stop)

    # ── Tech-Fingerprint ───────────────────────────────────────────────────────

    def _build_techfp(self, parent):
        self._info_bar(parent,
            "Tech-Fingerprint: Erkennt verwendete Technologien (CMS, Frameworks, JS-Libs) anhand von HTTP-Headern und Seiteninhalten.")

        frame = tk.Frame(parent, bg=DARK["bg"]); frame.pack(fill="both", expand=True, padx=14, pady=10)
        tk.Label(frame, text="URL analysieren:",
                 bg=DARK["bg"], fg=DARK["fg"], font=("Segoe UI", 9)).pack(anchor="w")
        urlrow = tk.Frame(frame, bg=DARK["bg"]); urlrow.pack(fill="x", pady=4)
        self._fp_url = tk.StringVar(value=f"http://{self._target_var.get()}")
        self._target_var.trace_add("write",
            lambda *_: self._fp_url.set(f"http://{self._target_var.get()}"))
        tk.Entry(urlrow, textvariable=self._fp_url,
                 bg=DARK["entry"], fg=DARK["fg"],
                 insertbackground=DARK["fg"], relief="flat",
                 font=("Segoe UI", 10)).pack(side="left", fill="x", expand=True, ipady=4)
        ttk.Button(urlrow, text="Analysieren", style="Accent.TButton",
                   command=self._run_techfp).pack(side="left", padx=(8, 0))
        ttk.Button(urlrow, text="WhatWeb",
                   command=self._run_whatweb).pack(side="left", padx=(4, 0))

        self._fp_result = tk.Text(frame, bg=DARK["panel"], fg=DARK["fg"],
                                   font=("Consolas", 9), relief="flat",
                                   height=20, state="disabled")
        self._fp_result.pack(fill="both", expand=True, pady=8)
        for tag, color in [("header", DARK["accent"]), ("value", DARK["fg"]),
                            ("found", DARK["green"]), ("warn", DARK["yellow"])]:
            self._fp_result.tag_configure(tag, foreground=color)

    def _run_techfp(self):
        url = self._fp_url.get().strip()
        if not url:
            return
        self._fp_result.configure(state="normal")
        self._fp_result.delete("1.0", "end")
        self._fp_result.insert("end", f"Analysiere {url} ...\n\n", "header")
        self._fp_result.configure(state="disabled")
        threading.Thread(target=self._exec_techfp, args=(url,), daemon=True).start()

    def _exec_techfp(self, url: str):
        findings: list[tuple[str, str, str]] = []
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=8) as resp:
                headers = dict(resp.headers)
                body    = resp.read(8192).decode("utf-8", errors="ignore")

            for hdr in ["Server", "X-Powered-By", "X-Generator", "X-Drupal-Cache",
                        "X-WordPress-Cache", "X-Shopify-Stage", "Via",
                        "X-Frame-Options", "Strict-Transport-Security",
                        "Content-Security-Policy", "X-Content-Type-Options",
                        "X-XSS-Protection"]:
                val = headers.get(hdr, "")
                if val:
                    tag = "found" if hdr in ("Server","X-Powered-By","X-Generator") else "value"
                    findings.append((hdr, val, tag))

            # Body-Fingerprints
            body_checks = [
                (r"wp-content",         "WordPress erkannt"),
                (r"Drupal",             "Drupal erkannt"),
                (r"Joomla",             "Joomla erkannt"),
                (r"laravel",            "Laravel erkannt"),
                (r"django",             "Django erkannt"),
                (r"react",              "React.js erkannt"),
                (r"angular",            "Angular erkannt"),
                (r"vue\.js|vuejs",      "Vue.js erkannt"),
                (r"jquery",             "jQuery erkannt"),
                (r"bootstrap",          "Bootstrap erkannt"),
                (r"<form.*login|signin","Login-Formular gefunden"),
            ]
            for pattern, label in body_checks:
                if re.search(pattern, body, re.I):
                    findings.append(("Body-Fingerprint", label, "found"))

            # Security Headers Check
            missing = []
            for sh in ["Strict-Transport-Security", "Content-Security-Policy",
                       "X-Frame-Options", "X-Content-Type-Options"]:
                if sh not in headers:
                    missing.append(sh)
            if missing:
                findings.append(("Fehlende Security-Header",
                                  ", ".join(missing), "warn"))

        except Exception as e:
            findings.append(("Fehler", str(e), "warn"))

        self.after(0, self._show_techfp_results, findings)

    def _show_techfp_results(self, findings: list):
        self._fp_result.configure(state="normal")
        self._fp_result.delete("1.0", "end")
        for key, val, tag in findings:
            self._fp_result.insert("end", f"  {key:<30} ", "header")
            self._fp_result.insert("end", f"{val}\n", tag)
        self._fp_result.configure(state="disabled")

    def _run_whatweb(self):
        whatweb = self._tool_path("whatweb")
        url = self._fp_url.get().strip()
        if not url:
            return
        self._fp_result.configure(state="normal")
        self._fp_result.delete("1.0", "end")
        if not whatweb:
            self._fp_result.insert("end", "[!] WhatWeb nicht gefunden. Überprüfe Einstellungen.", "warn")
            self._fp_result.configure(state="disabled")
            return
        import os
        cmd = ["cmd", "/c", whatweb, url] if os.name == "nt" and whatweb.endswith(".bat") \
              else [whatweb, url]
        self._fp_result.insert("end", f"WhatWeb: {url}\n\n", "header")
        self._run_tool(cmd, None, self._fp_result)
