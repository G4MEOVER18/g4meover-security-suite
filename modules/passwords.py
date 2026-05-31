"""Passwort-Cracker – hashcat (alle Modi), John the Ripper, Hydra, Hash-ID."""
import tkinter as tk
from tkinter import ttk, messagebox
import re
import os
from pathlib import Path
from modules.base import BaseModule
from utils.theme import DARK

HASH_TYPES = [
    ("22000  – WPA/WPA2",          "22000"),
    ("0      – MD5",               "0"),
    ("100    – SHA1",              "100"),
    ("1400   – SHA2-256",          "1400"),
    ("1700   – SHA2-512",          "1700"),
    ("1000   – NTLM",              "1000"),
    ("3000   – LM",                "3000"),
    ("5600   – NetNTLMv2",         "5600"),
    ("13100  – Kerberos 5 TGS",    "13100"),
    ("1800   – sha512crypt",       "1800"),
    ("3200   – bcrypt",            "3200"),
    ("16500  – JWT",               "16500"),
    ("11600  – 7-Zip",             "11600"),
    ("13400  – KeePass 1/2",       "13400"),
]

ATTACK_MODES = [
    ("0 – Wortliste",          "0"),
    ("1 – Kombination",        "1"),
    ("3 – Brute-Force (Mask)", "3"),
    ("6 – Wortliste + Maske",  "6"),
    ("7 – Maske + Wortliste",  "7"),
]

HYDRA_PROTOCOLS = [
    "ssh", "ftp", "http-get", "http-post-form",
    "smb", "rdp", "mysql", "mssql", "postgres",
    "smtp", "imap", "pop3", "vnc", "telnet",
]

HASH_SIGNATURES = [
    (re.compile(r"^[0-9a-f]{32}$",    re.I), "MD5"),
    (re.compile(r"^[0-9a-f]{40}$",    re.I), "SHA1"),
    (re.compile(r"^[0-9a-f]{64}$",    re.I), "SHA256"),
    (re.compile(r"^[0-9a-f]{128}$",   re.I), "SHA512"),
    (re.compile(r"^\$2[ayb]\$.{56}$"       ), "bcrypt"),
    (re.compile(r"^\$6\$.{8,}\$.{86}$"     ), "sha512crypt"),
    (re.compile(r"^[0-9a-f]{16}$",    re.I), "LM (halb)"),
    (re.compile(r"^\$krb5tgs\$"            ), "Kerberos 5 TGS"),
    (re.compile(r"^WPA\*"                  ), "WPA hc22000"),
]


class PasswordModule(BaseModule):

    def _build(self):
        self._info_bar(self,
            "Passwort-Cracker: hashcat (GPU-basiert) · John the Ripper (CPU) · Hydra (Online-Brute-Force) · Hash-Identify · Credential-Store")

        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True)

        t1 = ttk.Frame(nb); nb.add(t1, text="  Hashcat  ")
        t2 = ttk.Frame(nb); nb.add(t2, text="  John the Ripper  ")
        t3 = ttk.Frame(nb); nb.add(t3, text="  Hydra (Online)  ")
        t4 = ttk.Frame(nb); nb.add(t4, text="  Hash-Identify  ")
        t5 = ttk.Frame(nb); nb.add(t5, text="  Credential-Store  ")

        self._build_hashcat(t1)
        self._build_john(t2)
        self._build_hydra(t3)
        self._build_hashid(t4)
        self._build_credstore(t5)

        self._credentials: list[dict] = []

    # ── Hashcat ────────────────────────────────────────────────────────────────

    def _build_hashcat(self, parent):
        self._info_bar(parent,
            "hashcat: GPU-beschleunigter Hash-Cracker. Unterstützt 300+ Hash-Typen, Wortlisten-, Brute-Force- und Regelangriffe. Extrem schnell mit NVIDIA/AMD GPUs.")
        left  = tk.Frame(parent, bg=DARK["bg"])
        right = tk.Frame(parent, bg=DARK["bg"])
        left.pack(side="left", fill="y", padx=(8, 4), pady=8)
        left.configure(width=380); left.pack_propagate(False)
        right.pack(side="left", fill="both", expand=True, padx=(4, 8), pady=8)

        fh = self._section(left, "Hash-Datei")
        self._hc_hash_var = tk.StringVar()
        self._entry_row(fh, "", self._hc_hash_var,
                        lambda: self._browse_file(self._hc_hash_var, "Hash-Datei",
                                                  [("Hash", "*.txt *.hash *.hc22000 *.hccapx"), ("Alle", "*")]))

        f2 = self._section(left, "Hash-Typ")
        self._hc_type_cb = ttk.Combobox(f2, state="readonly",
                                          values=[h[0] for h in HASH_TYPES],
                                          font=("Segoe UI", 9))
        self._hc_type_cb.current(0)
        self._hc_type_cb.pack(fill="x", padx=10, pady=6)

        f3 = self._section(left, "Angriffs-Modus")
        self._hc_attack_cb = ttk.Combobox(f3, state="readonly",
                                            values=[a[0] for a in ATTACK_MODES],
                                            font=("Segoe UI", 9))
        self._hc_attack_cb.current(0)
        self._hc_attack_cb.pack(fill="x", padx=10, pady=4)

        fw = self._section(left, "Wortliste")
        self._hc_wl_var = tk.StringVar()
        self._entry_row(fw, "", self._hc_wl_var,
                        lambda: self._browse_file(self._hc_wl_var, "Wortliste",
                                                  [("Wortlisten", "*.txt *.lst"), ("Alle", "*")]))

        fm = self._section(left, "Maske")
        self._hc_mask_var = tk.StringVar(value="?d?d?d?d?d?d?d?d")
        tk.Entry(fm, textvariable=self._hc_mask_var,
                 bg=DARK["entry"], fg=DARK["accent"],
                 font=("Consolas", 10), relief="flat").pack(fill="x", padx=10, pady=4, ipady=3)
        tk.Label(fm, text="?l=a-z  ?u=A-Z  ?d=0-9  ?s=Sonderz.  ?a=alle  ?h=hex",
                 bg=DARK["bg"], fg=DARK["border"],
                 font=("Segoe UI", 7)).pack(padx=10, anchor="w", pady=(0, 4))

        fo = self._section(left, "Optionen")
        orow = tk.Frame(fo, bg=DARK["bg"]); orow.pack(fill="x", padx=10, pady=4)
        tk.Label(orow, text="Workload:", bg=DARK["bg"], fg=DARK["fg"],
                 font=("Segoe UI", 9)).pack(side="left")
        self._hc_wl_cb = ttk.Combobox(orow, state="readonly", width=4,
                                        values=["1","2","3","4"])
        self._hc_wl_cb.current(2); self._hc_wl_cb.pack(side="left", padx=4)
        self._hc_force = tk.BooleanVar()
        ttk.Checkbutton(orow, text="--force", variable=self._hc_force).pack(side="left", padx=8)

        btn_r = tk.Frame(left, bg=DARK["bg"]); btn_r.pack(fill="x", padx=10, pady=8)
        self._hc_start = ttk.Button(btn_r, text="Starten", style="Accent.TButton",
                                     command=self._run_hashcat)
        self._hc_start.pack(side="left", fill="x", expand=True)
        self._hc_stop  = ttk.Button(btn_r, text="Stoppen", style="Danger.TButton",
                                     command=self._stop_tool, state="disabled")
        self._hc_stop.pack(side="left", fill="x", expand=True, padx=(6, 0))

        self._hc_log = self._log_widget(right)

    def _run_hashcat(self):
        hc = self._require_tool("hashcat", self._hc_log)
        if not hc:
            return
        hash_file = self._hc_hash_var.get().strip()
        if not hash_file:
            messagebox.showerror("Fehler", "Bitte eine Hash-Datei angeben."); return
        hash_type = HASH_TYPES[self._hc_type_cb.current()][1]
        attack    = ATTACK_MODES[self._hc_attack_cb.current()][1]
        workload  = self._hc_wl_cb.get()
        cmd = [hc, "-m", hash_type, "-a", attack,
               "--workload-profile", workload, hash_file]
        if attack in ("0", "1", "6", "7"):
            wl = self._hc_wl_var.get().strip()
            if wl: cmd.append(wl)
        if attack in ("3", "6", "7"):
            mask = self._hc_mask_var.get().strip()
            if attack == "6" and wl and mask:
                cmd.append(mask)
            elif attack in ("3", "7"):
                if mask: cmd.append(mask)
        if self._hc_force.get():
            cmd.append("--force")
        cwd = str(Path(hc).parent)
        self._run_tool(cmd, cwd, self._hc_log,
                       start_btn=self._hc_start, stop_btn=self._hc_stop)

    # ── John the Ripper ────────────────────────────────────────────────────────

    def _build_john(self, parent):
        self._info_bar(parent,
            "John the Ripper: CPU-basierter Passwort-Cracker. Erkennt Hash-Typen automatisch, unterstützt Shadow-Dateien, ZIP/RAR, Office-Dokumente und viele mehr.")
        left  = tk.Frame(parent, bg=DARK["bg"])
        right = tk.Frame(parent, bg=DARK["bg"])
        left.pack(side="left", fill="y", padx=(8, 4), pady=8)
        left.configure(width=360); left.pack_propagate(False)
        right.pack(side="left", fill="both", expand=True, padx=(4, 8), pady=8)

        fh = self._section(left, "Hash-Datei")
        self._jtr_hash = tk.StringVar()
        self._entry_row(fh, "", self._jtr_hash,
                        lambda: self._browse_file(self._jtr_hash, "Hash-Datei"))

        fw = self._section(left, "Wortliste")
        self._jtr_wl = tk.StringVar()
        self._entry_row(fw, "", self._jtr_wl,
                        lambda: self._browse_file(self._jtr_wl, "Wortliste",
                                                  [("Wortlisten", "*.txt *.lst"), ("Alle", "*")]))

        fo = self._section(left, "Format & Optionen")
        frow = tk.Frame(fo, bg=DARK["bg"]); frow.pack(fill="x", padx=10, pady=4)
        tk.Label(frow, text="--format=", bg=DARK["bg"], fg=DARK["fg"],
                 font=("Segoe UI", 9)).pack(side="left")
        self._jtr_format = tk.StringVar()
        tk.Entry(frow, textvariable=self._jtr_format, width=16,
                 bg=DARK["entry"], fg=DARK["fg"],
                 insertbackground=DARK["fg"], relief="flat",
                 font=("Segoe UI", 9)).pack(side="left", padx=4, ipady=3)
        tk.Label(frow, text="(leer = auto)", bg=DARK["bg"], fg=DARK["border"],
                 font=("Segoe UI", 7)).pack(side="left")
        self._jtr_rules = tk.BooleanVar()
        ttk.Checkbutton(fo, text="--rules", variable=self._jtr_rules).pack(padx=10, anchor="w")
        self._jtr_show  = tk.BooleanVar()
        ttk.Checkbutton(fo, text="--show (gecrackte anzeigen)",
                        variable=self._jtr_show).pack(padx=10, anchor="w", pady=(0, 4))

        btn = tk.Frame(left, bg=DARK["bg"]); btn.pack(fill="x", padx=10, pady=8)
        self._jtr_start = ttk.Button(btn, text="Starten", style="Accent.TButton",
                                      command=self._run_john)
        self._jtr_start.pack(side="left", fill="x", expand=True)
        self._jtr_stop  = ttk.Button(btn, text="Stoppen", style="Danger.TButton",
                                      command=self._stop_tool, state="disabled")
        self._jtr_stop.pack(side="left", fill="x", expand=True, padx=(6, 0))

        self._jtr_log = self._log_widget(right)

    def _run_john(self):
        john = self._require_tool("john", self._jtr_log)
        if not john:
            return
        hash_file = self._jtr_hash.get().strip()
        if not hash_file:
            messagebox.showerror("Fehler", "Bitte eine Hash-Datei angeben."); return
        cmd = [john]
        if self._jtr_show.get():
            cmd.append("--show")
        else:
            wl = self._jtr_wl.get().strip()
            if wl:
                cmd.append(f"--wordlist={wl}")
            fmt = self._jtr_format.get().strip()
            if fmt:
                cmd.append(f"--format={fmt}")
            if self._jtr_rules.get():
                cmd.append("--rules")
        cmd.append(hash_file)
        self._run_tool(cmd, None, self._jtr_log,
                       start_btn=self._jtr_start, stop_btn=self._jtr_stop)

    # ── Hydra ─────────────────────────────────────────────────────────────────

    def _build_hydra(self, parent):
        self._info_bar(parent,
            "Hydra: Online-Brute-Force-Tool. Testet Benutzername/Passwort-Kombinationen live gegen Dienste wie SSH, FTP, HTTP, RDP, MySQL usw. Gefundene Credentials werden automatisch gespeichert.")
        left  = tk.Frame(parent, bg=DARK["bg"])
        right = tk.Frame(parent, bg=DARK["bg"])
        left.pack(side="left", fill="y", padx=(8, 4), pady=8)
        left.configure(width=380); left.pack_propagate(False)
        right.pack(side="left", fill="both", expand=True, padx=(4, 8), pady=8)

        fz = self._section(left, "Ziel")
        zrow = tk.Frame(fz, bg=DARK["bg"]); zrow.pack(fill="x", padx=10, pady=4)
        self._hy_target_var = tk.StringVar(value=self._target_var.get())
        self._target_var.trace_add("write",
            lambda *_: self._hy_target_var.set(self._target_var.get()))
        tk.Label(zrow, text="Host:", bg=DARK["bg"], fg=DARK["fg"],
                 font=("Segoe UI", 9), width=7).pack(side="left")
        tk.Entry(zrow, textvariable=self._hy_target_var,
                 bg=DARK["entry"], fg=DARK["fg"],
                 insertbackground=DARK["fg"], relief="flat",
                 font=("Segoe UI", 9)).pack(side="left", fill="x", expand=True, ipady=3)
        prow = tk.Frame(fz, bg=DARK["bg"]); prow.pack(fill="x", padx=10, pady=2)
        tk.Label(prow, text="Port:", bg=DARK["bg"], fg=DARK["fg"],
                 font=("Segoe UI", 9), width=7).pack(side="left")
        self._hy_port = tk.StringVar()
        tk.Entry(prow, textvariable=self._hy_port, width=6,
                 bg=DARK["entry"], fg=DARK["fg"],
                 insertbackground=DARK["fg"], relief="flat",
                 font=("Segoe UI", 9)).pack(side="left", padx=4, ipady=3)
        tk.Label(prow, text="(leer = Standard)", bg=DARK["bg"], fg=DARK["border"],
                 font=("Segoe UI", 7)).pack(side="left")

        fp = self._section(left, "Protokoll")
        self._hy_proto_cb = ttk.Combobox(fp, state="readonly",
                                          values=HYDRA_PROTOCOLS,
                                          font=("Segoe UI", 9))
        self._hy_proto_cb.current(0)
        self._hy_proto_cb.pack(fill="x", padx=10, pady=4)
        self._hy_proto_cb.bind("<<ComboboxSelected>>", self._on_hydra_proto)

        self._hy_http_frame = tk.Frame(left, bg=DARK["bg"])
        tk.Label(self._hy_http_frame, text="HTTP-Form-Parameter:",
                 bg=DARK["bg"], fg=DARK["fg"],
                 font=("Segoe UI", 8)).pack(anchor="w", padx=10)
        self._hy_http_path  = tk.StringVar(value="/login")
        self._hy_http_body  = tk.StringVar(value="user=^USER^&pass=^PASS^")
        self._hy_http_fail  = tk.StringVar(value="Invalid")
        for label, var in [("Pfad:", self._hy_http_path),
                            ("Body:", self._hy_http_body),
                            ("Fail-Str:", self._hy_http_fail)]:
            r = tk.Frame(self._hy_http_frame, bg=DARK["bg"]); r.pack(fill="x", padx=10, pady=1)
            tk.Label(r, text=label, bg=DARK["bg"], fg=DARK["border"],
                     font=("Segoe UI", 8), width=8).pack(side="left")
            tk.Entry(r, textvariable=var, bg=DARK["entry"], fg=DARK["fg"],
                     insertbackground=DARK["fg"], relief="flat",
                     font=("Segoe UI", 8)).pack(side="left", fill="x", expand=True, ipady=2)

        fu = self._section(left, "Credentials")
        urow = tk.Frame(fu, bg=DARK["bg"]); urow.pack(fill="x", padx=10, pady=4)
        tk.Label(urow, text="User:", bg=DARK["bg"], fg=DARK["fg"],
                 font=("Segoe UI", 9), width=7).pack(side="left")
        self._hy_user = tk.StringVar()
        tk.Entry(urow, textvariable=self._hy_user, width=14,
                 bg=DARK["entry"], fg=DARK["fg"],
                 insertbackground=DARK["fg"], relief="flat",
                 font=("Segoe UI", 9)).pack(side="left", padx=4, ipady=3)
        tk.Label(urow, text="oder", bg=DARK["bg"], fg=DARK["border"],
                 font=("Segoe UI", 7)).pack(side="left", padx=4)
        self._hy_ulist = tk.StringVar()
        tk.Entry(urow, textvariable=self._hy_ulist,
                 bg=DARK["entry"], fg=DARK["fg"],
                 insertbackground=DARK["fg"], relief="flat",
                 font=("Segoe UI", 8)).pack(side="left", fill="x", expand=True, ipady=2)
        ttk.Button(urow, text="…",
                   command=lambda: self._browse_file(self._hy_ulist, "User-Liste")).pack(side="left", padx=(2,0))

        prow2 = tk.Frame(fu, bg=DARK["bg"]); prow2.pack(fill="x", padx=10, pady=2)
        tk.Label(prow2, text="Pass:", bg=DARK["bg"], fg=DARK["fg"],
                 font=("Segoe UI", 9), width=7).pack(side="left")
        self._hy_pass = tk.StringVar()
        tk.Entry(prow2, textvariable=self._hy_pass, width=14,
                 bg=DARK["entry"], fg=DARK["fg"],
                 insertbackground=DARK["fg"], relief="flat",
                 font=("Segoe UI", 9)).pack(side="left", padx=4, ipady=3)
        tk.Label(prow2, text="oder", bg=DARK["bg"], fg=DARK["border"],
                 font=("Segoe UI", 7)).pack(side="left", padx=4)
        self._hy_plist = tk.StringVar()
        tk.Entry(prow2, textvariable=self._hy_plist,
                 bg=DARK["entry"], fg=DARK["fg"],
                 insertbackground=DARK["fg"], relief="flat",
                 font=("Segoe UI", 8)).pack(side="left", fill="x", expand=True, ipady=2)
        ttk.Button(prow2, text="…",
                   command=lambda: self._browse_file(self._hy_plist, "Passwort-Liste")).pack(side="left", padx=(2,0))

        fo = self._section(left, "Optionen")
        orow = tk.Frame(fo, bg=DARK["bg"]); orow.pack(fill="x", padx=10, pady=4)
        tk.Label(orow, text="Tasks:", bg=DARK["bg"], fg=DARK["fg"],
                 font=("Segoe UI", 9)).pack(side="left")
        self._hy_tasks = ttk.Spinbox(orow, from_=1, to=64, width=4)
        self._hy_tasks.set("4"); self._hy_tasks.pack(side="left", padx=4)
        self._hy_ssl  = tk.BooleanVar()
        ttk.Checkbutton(orow, text="-S (SSL)", variable=self._hy_ssl).pack(side="left", padx=8)
        self._hy_verbose = tk.BooleanVar(value=True)
        ttk.Checkbutton(orow, text="-V verbose", variable=self._hy_verbose).pack(side="left")

        btn = tk.Frame(left, bg=DARK["bg"]); btn.pack(fill="x", padx=10, pady=8)
        self._hy_start = ttk.Button(btn, text="Angriff starten", style="Accent.TButton",
                                     command=self._run_hydra)
        self._hy_start.pack(side="left", fill="x", expand=True)
        self._hy_stop  = ttk.Button(btn, text="Stoppen", style="Danger.TButton",
                                     command=self._stop_tool, state="disabled")
        self._hy_stop.pack(side="left", fill="x", expand=True, padx=(6, 0))

        self._hy_log = self._log_widget(right)
        self._hy_log.tag_configure("found", foreground=DARK["green"],
                                   font=("Consolas", 9, "bold"))

    def _on_hydra_proto(self, _=None):
        if "http-post-form" in self._hy_proto_cb.get():
            self._hy_http_frame.pack(fill="x", padx=4, pady=2)
        else:
            self._hy_http_frame.pack_forget()

    def _run_hydra(self):
        hydra = self._require_tool("hydra", self._hy_log)
        if not hydra:
            return
        host  = self._hy_target_var.get().strip()
        proto = self._hy_proto_cb.get()
        if not host:
            messagebox.showerror("Fehler", "Bitte einen Host angeben."); return

        cmd = [hydra]
        user  = self._hy_user.get().strip()
        ulist = self._hy_ulist.get().strip()
        pw    = self._hy_pass.get().strip()
        plist = self._hy_plist.get().strip()
        if ulist:  cmd += ["-L", ulist]
        elif user: cmd += ["-l", user]
        if plist:  cmd += ["-P", plist]
        elif pw:   cmd += ["-p", pw]

        cmd += ["-t", self._hy_tasks.get()]
        if self._hy_ssl.get():     cmd.append("-S")
        if self._hy_verbose.get(): cmd.append("-V")
        port = self._hy_port.get().strip()
        if port: cmd += ["-s", port]

        if proto == "http-post-form":
            form_str = (f"{self._hy_http_path.get()}:"
                        f"{self._hy_http_body.get()}:"
                        f"F={self._hy_http_fail.get()}")
            cmd += [host, "http-post-form", form_str]
        else:
            cmd += [host, proto]

        self._run_tool(cmd, None, self._hy_log,
                       on_line=self._parse_hydra_line,
                       start_btn=self._hy_start, stop_btn=self._hy_stop)

    # ── Hash-Identify ──────────────────────────────────────────────────────────

    def _build_hashid(self, parent):
        self._info_bar(parent,
            "Hash-Identify: Erkennt den Hash-Typ anhand des Musters (Länge, Zeichenvorrat, Präfix). Gibt den passenden hashcat-Modus an.")
        frame = tk.Frame(parent, bg=DARK["bg"]); frame.pack(fill="both", expand=True, padx=14, pady=12)
        tk.Label(frame, text="Hash eingeben:",
                 bg=DARK["bg"], fg=DARK["fg"],
                 font=("Segoe UI", 9)).pack(anchor="w")
        self._hid_var = tk.StringVar()
        tk.Entry(frame, textvariable=self._hid_var,
                 bg=DARK["entry"], fg=DARK["accent"],
                 insertbackground=DARK["fg"], relief="flat",
                 font=("Consolas", 11)).pack(fill="x", pady=4, ipady=6)
        self._hid_var.trace_add("write", self._identify_hash)

        self._hid_result = tk.Label(frame, text="",
                                     bg=DARK["bg"], fg=DARK["fg"],
                                     font=("Segoe UI", 10),
                                     wraplength=600, justify="left")
        self._hid_result.pack(anchor="w", pady=8)

        tk.Label(frame, text="Bekannte Hash-Formate:",
                 bg=DARK["bg"], fg=DARK["border"],
                 font=("Segoe UI", 8, "italic")).pack(anchor="w", pady=(12, 4))
        for pattern, name in HASH_SIGNATURES:
            tk.Label(frame, text=f"  {name}",
                     bg=DARK["bg"], fg=DARK["border"],
                     font=("Consolas", 8)).pack(anchor="w")

    def _identify_hash(self, *_):
        h = self._hid_var.get().strip()
        if not h:
            self._hid_result.configure(text="")
            return
        matches = []
        for pattern, name in HASH_SIGNATURES:
            if pattern.match(h):
                matches.append(name)
        if matches:
            self._hid_result.configure(
                text=f"Mögliche Typen: {' | '.join(matches)}",
                fg=DARK["green"])
        else:
            self._hid_result.configure(
                text=f"Länge: {len(h)} Zeichen – kein bekanntes Format erkannt",
                fg=DARK["yellow"])

    def _parse_hydra_line(self, line: str):
        if "] login:" in line:
            self._hy_log.tag_configure("found", foreground=DARK["green"],
                                       font=("Consolas", 9, "bold"))
            parts = line.strip().split()
            host = self._hy_target_var.get().strip()
            try:
                login_idx = parts.index("login:")
                pass_idx  = parts.index("password:")
                user = parts[login_idx + 1] if login_idx + 1 < len(parts) else "?"
                pw   = parts[pass_idx  + 1] if pass_idx  + 1 < len(parts) else "?"
                self._add_credential(host, self._hy_proto_cb.get(), user, pw, "hydra")
            except (ValueError, IndexError):
                pass

    # ── Credential-Store ───────────────────────────────────────────────────────

    def _build_credstore(self, parent):
        self._info_bar(parent,
            "Credential-Store: Speichert gefundene Zugangsdaten aus allen Modulen (Hydra, manuell). Doppelklick kopiert das Passwort. Export als CSV möglich.")
        fin = self._section(parent, "Credential manuell hinzufügen")
        crow = tk.Frame(fin, bg=DARK["bg"]); crow.pack(fill="x", padx=10, pady=4)
        self._cs_host  = tk.StringVar()
        self._cs_svc   = tk.StringVar(value="ssh")
        self._cs_user  = tk.StringVar()
        self._cs_pass  = tk.StringVar()
        for label, var, width in [("Host:", self._cs_host, 18),
                                   ("Dienst:", self._cs_svc, 10),
                                   ("User:", self._cs_user, 14),
                                   ("Passwort:", self._cs_pass, 18)]:
            tk.Label(crow, text=label, bg=DARK["bg"], fg=DARK["fg"],
                     font=("Segoe UI", 8)).pack(side="left", padx=(6, 2))
            tk.Entry(crow, textvariable=var, width=width,
                     bg=DARK["entry"], fg=DARK["accent"],
                     insertbackground=DARK["fg"], relief="flat",
                     font=("Consolas", 8)).pack(side="left", ipady=3)
        ttk.Button(crow, text="Hinzufügen",
                   style="Accent.TButton",
                   command=self._cs_add_manual).pack(side="left", padx=8)

        btn_row = tk.Frame(parent, bg=DARK["bg"]); btn_row.pack(fill="x", padx=10, pady=2)
        ttk.Button(btn_row, text="Ausgewähltes löschen",
                   command=self._cs_delete).pack(side="left")
        ttk.Button(btn_row, text="Export CSV",
                   command=self._cs_export_csv).pack(side="left", padx=4)
        ttk.Button(btn_row, text="Alle löschen",
                   style="Danger.TButton",
                   command=self._cs_clear).pack(side="right")
        self._cs_count = tk.StringVar(value="0 Credentials")
        tk.Label(btn_row, textvariable=self._cs_count,
                 bg=DARK["bg"], fg=DARK["accent"],
                 font=("Segoe UI", 8)).pack(side="right", padx=8)

        cols = ("ts", "host", "service", "user", "password", "source")
        self._cs_tree = ttk.Treeview(parent, columns=cols, show="headings",
                                      selectmode="browse")
        for col, w, label in [("ts", 80, "Zeit"), ("host", 140, "Host"),
                               ("service", 80, "Dienst"), ("user", 120, "Benutzername"),
                               ("password", 150, "Passwort"), ("source", 80, "Quelle")]:
            self._cs_tree.heading(col, text=label)
            self._cs_tree.column(col, width=w, minwidth=40)
        self._cs_tree.tag_configure("new", foreground=DARK["green"])
        csb = ttk.Scrollbar(parent, command=self._cs_tree.yview)
        self._cs_tree.configure(yscrollcommand=csb.set)
        csb.pack(side="right", fill="y")
        self._cs_tree.pack(fill="both", expand=True, padx=6, pady=4)
        self._cs_tree.bind("<Double-1>", self._cs_copy_password)

    def _add_credential(self, host: str, service: str, user: str, pw: str,
                         source: str = "manuell"):
        from datetime import datetime
        ts = datetime.now().strftime("%H:%M:%S")
        entry = {"ts": ts, "host": host, "service": service,
                 "user": user, "password": pw, "source": source}
        self._credentials.append(entry)
        self.after(0, self._cs_tree.insert, "", "end",
                   values=(ts, host, service, user, pw, source), tags=("new",))
        self.after(0, self._cs_count.set, f"{len(self._credentials)} Credentials")

    def _cs_add_manual(self):
        h = self._cs_host.get().strip()
        u = self._cs_user.get().strip()
        p = self._cs_pass.get().strip()
        if not h or not u:
            messagebox.showerror("Fehler", "Host und User angeben."); return
        self._add_credential(h, self._cs_svc.get(), u, p, "manuell")

    def _cs_delete(self):
        sel = self._cs_tree.selection()
        if not sel:
            return
        idx = self._cs_tree.index(sel[0])
        self._cs_tree.delete(sel[0])
        if 0 <= idx < len(self._credentials):
            self._credentials.pop(idx)
        self._cs_count.set(f"{len(self._credentials)} Credentials")

    def _cs_clear(self):
        if not messagebox.askyesno("Löschen", "Alle Credentials löschen?"):
            return
        self._credentials.clear()
        self._cs_tree.delete(*self._cs_tree.get_children())
        self._cs_count.set("0 Credentials")

    def _cs_copy_password(self, _):
        sel = self._cs_tree.selection()
        if not sel:
            return
        vals = self._cs_tree.item(sel[0], "values")
        if vals:
            self.clipboard_clear()
            self.clipboard_append(vals[4])

    def _cs_export_csv(self):
        from tkinter import filedialog
        from datetime import datetime
        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV", "*.csv"), ("Alle", "*.*")],
            title="Credentials exportieren")
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            f.write("Zeit,Host,Dienst,Benutzername,Passwort,Quelle\n")
            for c in self._credentials:
                f.write(f"{c['ts']},{c['host']},{c['service']},"
                        f"{c['user']},{c['password']},{c['source']}\n")
        messagebox.showinfo("Export", f"Gespeichert: {path}")
