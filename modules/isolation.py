"""Network Isolation Tester – Segmenttrennung und gefährliche Ports prüfen."""
import tkinter as tk
from tkinter import ttk
import subprocess
import threading
import socket
from datetime import datetime
from modules.base import BaseModule
from utils.theme import DARK


# Gefährliche Ports mit CVE-Referenzen
DANGER_PORTS = [
    (21,   "FTP",         "Klartextübertragung, Brute-Force"),
    (22,   "SSH",         "Brute-Force, Log4Shell (CVE-2021-44228 via SSH-Banner)"),
    (23,   "Telnet",      "Kein Encryption, CVE-2020-10188"),
    (25,   "SMTP",        "Open-Relay, CVE-2020-7247 (OpenSMTPD)"),
    (80,   "HTTP",        "Unverschlüsselt, Webanwendungslücken"),
    (135,  "RPC/DCOM",    "MS03-026, CVE-2003-0352 (Blaster)"),
    (137,  "NetBIOS",     "SMB-Enumeration, Relay-Angriffe"),
    (139,  "NetBIOS-SSN", "EternalBlue-Vorbereitung"),
    (445,  "SMB",         "EternalBlue CVE-2017-0144, EternalRed CVE-2017-7494"),
    (1433, "MS-SQL",      "Brute-Force, CVE-2020-0618"),
    (1521, "Oracle-DB",   "Brute-Force, CVE-2012-1675"),
    (3306, "MySQL",       "Brute-Force, CVE-2012-2122"),
    (3389, "RDP",         "BlueKeep CVE-2019-0708, DejaBlue CVE-2019-1181"),
    (4444, "Meterpreter", "Metasploit-Standard-Payload-Port"),
    (4899, "Radmin",      "Remote-Admin, häufig mit Backdoors kombiniert"),
    (5432, "PostgreSQL",  "Brute-Force, CVE-2019-10164"),
    (5900, "VNC",         "Authentifizierungsumgehung CVE-2006-2369"),
    (5985, "WinRM/HTTP",  "Lateral Movement, PowerShell-Remoting"),
    (5986, "WinRM/HTTPS", "Lateral Movement"),
    (6379, "Redis",       "Unauth. Zugriff CVE-2022-0543, Remote Code Execution"),
    (8080, "HTTP-Alt",    "Proxy/Admin-Panels ohne Encryption"),
    (8443, "HTTPS-Alt",   "Admin-Panels, CVE-2021-21985 (VMware)"),
    (9200, "Elasticsearch","Unauth. Zugriff, Datenleak CVE-2020-7009"),
    (27017,"MongoDB",     "Unauth. Zugriff, Datenleak (Shodan-Massen)"),
]


class IsolationModule(BaseModule):

    def _build(self):
        self._info_bar(self,
            "Network Isolation Tester – Prüft Netzwerksegmentierung, "
            "gefährliche Ports und bekannte CVE-Angriffsflächen.")

        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True)

        t1 = ttk.Frame(nb); nb.add(t1, text="  Segment-Test  ")
        t2 = ttk.Frame(nb); nb.add(t2, text="  Port-Scan (Gefährlich)  ")
        t3 = ttk.Frame(nb); nb.add(t3, text="  CVE-Referenz  ")

        self._build_segment(t1)
        self._build_portscan(t2)
        self._build_cve_ref(t3)

    # ── Tab 1: Segment-Test ───────────────────────────────────────────────────

    def _build_segment(self, parent):
        self._info_bar(parent,
            "Prüft, ob Hosts aus verschiedenen Segmenten unerwartet erreichbar sind (Ping / TCP-Verbindung).")

        paned = tk.PanedWindow(parent, orient="horizontal",
                               bg=DARK["bg"], sashwidth=4)
        paned.pack(fill="both", expand=True, padx=4, pady=4)

        left  = tk.Frame(paned, bg=DARK["bg"]); paned.add(left,  minsize=300, width=340)
        right = tk.Frame(paned, bg=DARK["bg"]); paned.add(right, minsize=400)

        # Eigenes Segment
        fs = self._section(left, "Eigenes Segment (Quelle)")
        self._src_var = tk.StringVar(value="192.168.1.0/24")
        self._entry_row(fs, "CIDR / Host:", self._src_var)

        # Ziel-Segmente
        ft = self._section(left, "Isolierte Ziel-Segmente (eine pro Zeile)")
        self._targets_text = tk.Text(ft, bg=DARK["entry"], fg=DARK["fg"],
                                      font=("Consolas", 9), height=6, relief="flat")
        self._targets_text.pack(fill="x", padx=6, pady=4)
        self._targets_text.insert("1.0",
            "10.0.0.1\n10.10.0.0/24\n172.16.0.1\n")

        # Test-Methode
        fm = self._section(left, "Test-Methode")
        self._method_var = tk.StringVar(value="tcp")
        ttk.Radiobutton(fm, text="TCP-Connect (Port 80/443/22)",
                        variable=self._method_var, value="tcp").pack(anchor="w", padx=10, pady=2)
        ttk.Radiobutton(fm, text="ICMP Ping (via nmap -sn)",
                        variable=self._method_var, value="ping").pack(anchor="w", padx=10, pady=2)

        self._seg_timeout_var = tk.StringVar(value="2")
        self._entry_row(fm, "Timeout (s):", self._seg_timeout_var)

        btn_f = tk.Frame(left, bg=DARK["bg"]); btn_f.pack(fill="x", padx=8, pady=8)
        self._seg_start = ttk.Button(btn_f, text="Test starten",
                                      style="Accent.TButton",
                                      command=self._run_segment_test)
        self._seg_start.pack(side="left")

        self._seg_log = self._log_widget(right)

    def _run_segment_test(self):
        targets_raw = self._targets_text.get("1.0", "end").strip().splitlines()
        targets = [t.strip() for t in targets_raw if t.strip()]
        if not targets:
            self._log(self._seg_log, "[!] Keine Ziele angegeben.\n", "red")
            return
        method  = self._method_var.get()
        timeout = int(self._seg_timeout_var.get() or 2)
        self._log(self._seg_log,
                  f"[*] Segment-Test: {len(targets)} Ziele, Methode={method}\n\n", "cyan")
        self._seg_start.configure(state="disabled")
        threading.Thread(target=self._segment_thread,
                         args=(targets, method, timeout), daemon=True).start()

    def _segment_thread(self, targets: list[str], method: str, timeout: int):
        reachable = []
        not_reachable = []

        for target in targets:
            ts = datetime.now().strftime("%H:%M:%S")
            if method == "tcp":
                result = self._tcp_test(target, timeout)
            else:
                result = self._ping_test(target, timeout)

            if result:
                reachable.append(target)
                self.after(0, self._log, self._seg_log,
                           f"[{ts}] ✗ ISOLIERUNG VERLETZT: {target} ist erreichbar!\n", "red")
            else:
                not_reachable.append(target)
                self.after(0, self._log, self._seg_log,
                           f"[{ts}] ✓ Isoliert:  {target}\n", "green")

        self.after(0, self._log, self._seg_log,
                   f"\n── Ergebnis ─────────────────\n"
                   f"  Isoliert:           {len(not_reachable)}\n"
                   f"  VERLETZUNGEN:       {len(reachable)}\n", "cyan")
        if reachable:
            self.after(0, self._log, self._seg_log,
                       "  Erreichbare Hosts: " + ", ".join(reachable) + "\n", "red")
        self.after(0, self._seg_start.configure, {"state": "normal"})

    def _tcp_test(self, target: str, timeout: int) -> bool:
        """Versucht TCP-Verbindung zu Port 80, 443, 22."""
        host = target.split("/")[0]
        for port in (80, 443, 22):
            try:
                with socket.create_connection((host, port), timeout=timeout):
                    return True
            except Exception:
                pass
        return False

    def _ping_test(self, target: str, timeout: int) -> bool:
        """Ping via subprocess."""
        host = target.split("/")[0]
        try:
            r = subprocess.run(
                ["ping", "-n", "1", "-w", str(timeout * 1000), host],
                capture_output=True, text=True, timeout=timeout + 2,
                creationflags=subprocess.CREATE_NO_WINDOW)
            return r.returncode == 0
        except Exception:
            return False

    # ── Tab 2: Port-Scan (Gefährlich) ─────────────────────────────────────────

    def _build_portscan(self, parent):
        self._info_bar(parent,
            "Scannt Ziel auf bekannt gefährliche Ports mit CVE-Referenzen. "
            "Erkennt sofort kritische Angriffsflächen.")

        paned = tk.PanedWindow(parent, orient="horizontal",
                               bg=DARK["bg"], sashwidth=4)
        paned.pack(fill="both", expand=True, padx=4, pady=4)

        left  = tk.Frame(paned, bg=DARK["bg"]); paned.add(left,  minsize=300, width=340)
        right = tk.Frame(paned, bg=DARK["bg"]); paned.add(right, minsize=400)

        fz = self._section(left, "Ziel")
        self._ps_target_var = tk.StringVar(value=self._target_var.get())
        self._target_var.trace_add("write",
            lambda *_: self._ps_target_var.set(self._target_var.get()))
        self._entry_row(fz, "Host / IP:", self._ps_target_var)

        fm = self._section(left, "Scan-Modus")
        self._ps_mode_var = tk.StringVar(value="fast")
        ttk.Radiobutton(fm, text="Schnell (Python TCP-Connect, kein nmap)",
                        variable=self._ps_mode_var, value="fast").pack(anchor="w", padx=10, pady=2)
        ttk.Radiobutton(fm, text="nmap SYN-Scan (genauer, benötigt Admin)",
                        variable=self._ps_mode_var, value="nmap").pack(anchor="w", padx=10, pady=2)
        self._ps_timeout_var = tk.StringVar(value="1")
        self._entry_row(fm, "Timeout (s):", self._ps_timeout_var)

        # Port-Auswahl
        fp = self._section(left, "Ports")
        self._ps_all_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(fp, text="Alle gefährlichen Ports prüfen",
                        variable=self._ps_all_var).pack(anchor="w", padx=10, pady=2)
        self._ps_custom_var = tk.StringVar(value="")
        self._entry_row(fp, "Eigene (komma):", self._ps_custom_var)

        btn_f = tk.Frame(left, bg=DARK["bg"]); btn_f.pack(fill="x", padx=8, pady=8)
        self._ps_start = ttk.Button(btn_f, text="Scan starten",
                                     style="Danger.TButton",
                                     command=self._run_port_scan)
        self._ps_start.pack(side="left")

        # Ergebnis-Treeview
        result_frame = self._section_expand(right, "Gefundene offene Ports")
        cols = ("port", "service", "status", "cve_hint")
        self._ps_tree = ttk.Treeview(result_frame, columns=cols,
                                      show="headings", height=10)
        for col, w, txt in [("port", 60, "Port"), ("service", 100, "Dienst"),
                             ("status", 70, "Status"), ("cve_hint", 300, "CVE / Risiko")]:
            self._ps_tree.heading(col, text=txt)
            self._ps_tree.column(col, width=w, anchor="w")
        sb = ttk.Scrollbar(result_frame, command=self._ps_tree.yview)
        self._ps_tree.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self._ps_tree.pack(fill="both", expand=True, padx=4, pady=4)

        self._ps_log = self._log_widget(right, height=8)

    def _run_port_scan(self):
        target = self._ps_target_var.get().strip()
        if not target:
            self._log(self._ps_log, "[!] Kein Ziel angegeben.\n", "red")
            return

        # Port-Liste aufbauen
        ports_to_scan = []
        if self._ps_all_var.get():
            ports_to_scan = [(p, svc, cve) for p, svc, cve in DANGER_PORTS]
        custom = self._ps_custom_var.get().strip()
        if custom:
            for pstr in custom.split(","):
                p = int(pstr.strip())
                if not any(x[0] == p for x in ports_to_scan):
                    ports_to_scan.append((p, "custom", "Benutzerdefiniert"))

        mode    = self._ps_mode_var.get()
        timeout = float(self._ps_timeout_var.get() or 1)

        # Treeview leeren
        for item in self._ps_tree.get_children():
            self._ps_tree.delete(item)
        self._log(self._ps_log,
                  f"[*] Port-Scan: {target}  ({len(ports_to_scan)} Ports, Modus={mode})\n\n",
                  "cyan")
        self._ps_start.configure(state="disabled")

        if mode == "fast":
            threading.Thread(target=self._fast_scan_thread,
                             args=(target, ports_to_scan, timeout), daemon=True).start()
        else:
            threading.Thread(target=self._nmap_scan_thread,
                             args=(target, ports_to_scan), daemon=True).start()

    def _fast_scan_thread(self, target: str, ports: list, timeout: float):
        open_count = 0
        for port, service, cve in ports:
            try:
                with socket.create_connection((target, port), timeout=timeout):
                    open_count += 1
                    self.after(0, self._ps_tree.insert, "", "end",
                               values=(port, service, "OFFEN", cve),
                               tags=("open",))
                    self.after(0, self._log, self._ps_log,
                               f"  [OFFEN] {port:5}/{service:<12}  {cve}\n", "red")
            except socket.timeout:
                pass
            except Exception:
                pass

        self.after(0, self._ps_tree.tag_configure, "open",
                   {"foreground": DARK["red"]})
        self.after(0, self._log, self._ps_log,
                   f"\n[✓] Scan abgeschlossen. {open_count} gefährliche Ports offen.\n",
                   "red" if open_count else "green")
        self.after(0, self._ps_start.configure, {"state": "normal"})

    def _nmap_scan_thread(self, target: str, ports: list):
        nmap = self._tool_path("nmap")
        if not nmap:
            self.after(0, self._log, self._ps_log, "[!] nmap nicht gefunden.\n", "red")
            self.after(0, self._ps_start.configure, {"state": "normal"})
            return
        port_str = ",".join(str(p[0]) for p in ports)
        cmd = [nmap, "-sS", "-n", "--open", f"-p{port_str}", target]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=120,
                               creationflags=subprocess.CREATE_NO_WINDOW)
            open_count = 0
            for line in r.stdout.splitlines():
                if "/tcp" in line and "open" in line:
                    parts = line.split()
                    port_svc = parts[0] if parts else ""
                    pnum = int(port_svc.split("/")[0]) if "/" in port_svc else 0
                    # CVE-Info nachschlagen
                    cve_info = next((cve for p, _, cve in DANGER_PORTS if p == pnum), "—")
                    svc = parts[2] if len(parts) > 2 else "—"
                    open_count += 1
                    self.after(0, self._ps_tree.insert, "", "end",
                               values=(pnum, svc, "OFFEN", cve_info),
                               tags=("open",))
                self.after(0, self._log, self._ps_log, line + "\n")
            self.after(0, self._ps_tree.tag_configure, "open",
                       {"foreground": DARK["red"]})
            self.after(0, self._log, self._ps_log,
                       f"\n[✓] {open_count} gefährliche Ports offen.\n",
                       "red" if open_count else "green")
        except Exception as e:
            self.after(0, self._log, self._ps_log, f"[!] {e}\n", "red")
        finally:
            self.after(0, self._ps_start.configure, {"state": "normal"})

    # ── Tab 3: CVE-Referenz ───────────────────────────────────────────────────

    def _build_cve_ref(self, parent):
        self._info_bar(parent,
            "Übersicht über gefährliche Ports, ihre Dienste und bekannte CVEs.")

        frame = tk.Frame(parent, bg=DARK["bg"])
        frame.pack(fill="both", expand=True, padx=8, pady=8)

        cols = ("port", "service", "cve_hint", "severity")
        tree = ttk.Treeview(frame, columns=cols, show="headings")
        for col, w, txt in [("port", 60, "Port"), ("service", 100, "Dienst"),
                             ("cve_hint", 500, "CVE / Risiko"),
                             ("severity", 80, "Risiko")]:
            tree.heading(col, text=txt)
            tree.column(col, width=w, anchor="w")

        _SEVERITY = {
            445: "KRITISCH", 3389: "KRITISCH", 4444: "KRITISCH",
            23: "HOCH", 135: "HOCH", 6379: "HOCH", 9200: "HOCH",
            21: "MITTEL", 3306: "MITTEL", 5432: "MITTEL",
        }

        for port, service, cve in DANGER_PORTS:
            sev = _SEVERITY.get(port, "MITTEL")
            tag = ("crit" if sev == "KRITISCH" else
                   "high" if sev == "HOCH" else "med")
            tree.insert("", "end", values=(port, service, cve, sev), tags=(tag,))

        tree.tag_configure("crit", foreground=DARK["red"])
        tree.tag_configure("high", foreground=DARK["orange"])
        tree.tag_configure("med",  foreground=DARK["yellow"])

        sb = ttk.Scrollbar(frame, command=tree.yview)
        tree.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        tree.pack(fill="both", expand=True)
