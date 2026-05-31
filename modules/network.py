"""Netzwerk-Scanner – nmap-Wrapper mit Treeview und Export."""
import tkinter as tk
from tkinter import ttk, messagebox
import re
import json
import os
from pathlib import Path
from modules.base import BaseModule
from utils.theme import DARK

SCAN_PROFILES = {
    "Host-Discovery   (-sn)":          ["-sn", "-T4"],
    "Quick   (-T4 -F)":                ["-T4", "-F"],
    "Standard   (-T4 -sV -sC)":        ["-T4", "-sV", "-sC"],
    "Stealth   (-sS -T2)":             ["-sS", "-T2", "-p", "22,80,443,445,3389,8080"],
    "Full   (-sV -sC -O -p-)":         ["-T4", "-sV", "-sC", "-O", "-p-", "--open"],
    "Schwachstellen   (--script vuln)": ["-T4", "-sV", "--script", "vuln"],
    "UDP-Scan   (-sU)":                ["-sU", "-T3", "--top-ports", "100"],
    "Custom":                           [],
}

# Regex für nmap-Output-Parsing
_PORT_RE    = re.compile(r"^(\d+)/(\w+)\s+(\w+)\s+(.+)$")
_HOST_RE    = re.compile(r"Nmap scan report for (.+)")
_REASON_RE  = re.compile(r"(\d+)/(\w+)\s+(\w+)\s+(\w+)\s+(.+)")


class NetworkModule(BaseModule):

    def _build(self):
        self._info_bar(self,
            "nmap – Netzwerk-Scanner. Entdeckt Hosts, offene Ports, Dienste und Betriebssysteme im Netzwerk.")

        paned = tk.PanedWindow(self, orient="horizontal",
                               bg=DARK["bg"], sashwidth=4,
                               sashrelief="flat")
        paned.pack(fill="both", expand=True, padx=4, pady=4)

        left  = tk.Frame(paned, bg=DARK["bg"]); paned.add(left,  minsize=320, width=360)
        right = tk.Frame(paned, bg=DARK["bg"]); paned.add(right, minsize=400)

        # ── Linke Seite: Optionen ─────────────────────────────────────────────
        fz = self._section(left, "Ziel")
        self._target_entry_var = tk.StringVar(value=self._target_var.get())
        self._target_var.trace_add("write",
            lambda *_: self._target_entry_var.set(self._target_var.get()))
        self._entry_row(fz, "Ziel:", self._target_entry_var)
        tk.Label(fz, text="IP / Bereich / CIDR  (z.B. 192.168.1.0/24)",
                 bg=DARK["bg"], fg=DARK["border"],
                 font=("Segoe UI", 7, "italic")).pack(anchor="w", padx=10, pady=(0, 4))

        fp = self._section(left, "Scan-Profil")
        self._profile_cb = ttk.Combobox(fp, state="readonly",
                                         values=list(SCAN_PROFILES.keys()),
                                         font=("Segoe UI", 9))
        self._profile_cb.current(2)
        self._profile_cb.pack(fill="x", padx=10, pady=4)
        self._profile_cb.bind("<<ComboboxSelected>>", self._on_profile)
        self._tooltip(self._profile_cb,
            "Scan-Profile:\n"
            "• Host-Discovery: Findet lebende Hosts ohne Port-Scan (schnell)\n"
            "• Quick: Schnellscan der 100 häufigsten Ports\n"
            "• Standard: Diensterkennung + Standard-Scripts\n"
            "• Stealth: SYN-Scan (benötigt Admin/Root), weniger auffällig\n"
            "• Full: Alle 65535 Ports + OS-Erkennung\n"
            "• Schwachstellen: NSE-Scripts für bekannte CVEs\n"
            "• UDP: UDP-Ports (langsam, benötigt Admin)\n"
            "• Custom: Eigene nmap-Flags eingeben")

        self._custom_frame = tk.Frame(left, bg=DARK["bg"])
        tk.Label(self._custom_frame, text="Eigene Flags:",
                 bg=DARK["bg"], fg=DARK["fg"],
                 font=("Segoe UI", 8)).pack(anchor="w", padx=10)
        self._custom_var = tk.StringVar(value="-T4 -sV -p-")
        tk.Entry(self._custom_frame, textvariable=self._custom_var,
                 bg=DARK["entry"], fg=DARK["accent"],
                 insertbackground=DARK["fg"], relief="flat",
                 font=("Consolas", 9)).pack(fill="x", padx=10, pady=2, ipady=3)

        fo = self._section(left, "Optionen")
        opt_row = tk.Frame(fo, bg=DARK["bg"]); opt_row.pack(fill="x", padx=10, pady=4)
        self._os_var   = tk.BooleanVar(value=False)
        self._udp_var  = tk.BooleanVar(value=False)
        self._aggr_var = tk.BooleanVar(value=False)
        os_cb = ttk.Checkbutton(opt_row, text="-O (OS-Detect)",  variable=self._os_var)
        os_cb.pack(side="left")
        self._tooltip(os_cb, "Versucht das Betriebssystem des Ziels zu erkennen (benötigt Admin/Root).")
        udp_cb = ttk.Checkbutton(opt_row, text="-sU (UDP)", variable=self._udp_var)
        udp_cb.pack(side="left", padx=6)
        self._tooltip(udp_cb, "Scannt UDP-Ports zusätzlich. Deutlich langsamer als TCP. Benötigt Admin/Root.")
        aggr_cb = ttk.Checkbutton(opt_row, text="-A (aggressiv)", variable=self._aggr_var)
        aggr_cb.pack(side="left")
        self._tooltip(aggr_cb, "Aktiviert OS-Erkennung, Versions-Scan, Script-Scan und Traceroute. Auffälliger!")

        out_row = tk.Frame(fo, bg=DARK["bg"]); out_row.pack(fill="x", padx=10, pady=(2, 4))
        tk.Label(out_row, text="Ausgabe:", bg=DARK["bg"], fg=DARK["fg"],
                 font=("Segoe UI", 8)).pack(side="left")
        self._out_dir = tk.StringVar(value=self.cfg.get("workspace", str(Path.home() / "pentest")))
        tk.Entry(out_row, textvariable=self._out_dir,
                 bg=DARK["entry"], fg=DARK["fg"],
                 insertbackground=DARK["fg"], relief="flat",
                 font=("Segoe UI", 8)).pack(side="left", fill="x", expand=True, padx=4, ipady=2)
        ttk.Button(out_row, text="…",
                   command=lambda: self._browse_dir(self._out_dir)).pack(side="left")

        # History
        fh = self._section(left, "History")
        self._hist_cb = ttk.Combobox(fh, state="readonly", font=("Segoe UI", 8))
        self._hist_cb.pack(fill="x", padx=10, pady=4)
        self._hist_cb.bind("<<ComboboxSelected>>", self._load_history)
        self._history: list[dict] = []

        # ── Masscan Quick-Scan ────────────────────────────────────────────────
        fm = self._section(left, "Masscan – Quick Port Sweep")
        self._masscan_ports = tk.StringVar(value="1-1024,3306,3389,5432,8080,8443")
        mr1 = tk.Frame(fm, bg=DARK["bg"]); mr1.pack(fill="x", padx=10, pady=(4, 2))
        tk.Label(mr1, text="Ports:", bg=DARK["bg"], fg=DARK["fg"],
                 font=("Segoe UI", 8), width=8, anchor="w").pack(side="left")
        tk.Entry(mr1, textvariable=self._masscan_ports,
                 bg=DARK["entry"], fg=DARK["accent"],
                 insertbackground=DARK["fg"], relief="flat",
                 font=("Consolas", 8)).pack(side="left", fill="x", expand=True, ipady=2)
        self._masscan_rate = tk.StringVar(value="1000")
        mr2 = tk.Frame(fm, bg=DARK["bg"]); mr2.pack(fill="x", padx=10, pady=(0, 4))
        tk.Label(mr2, text="Rate:", bg=DARK["bg"], fg=DARK["fg"],
                 font=("Segoe UI", 8), width=8, anchor="w").pack(side="left")
        tk.Entry(mr2, textvariable=self._masscan_rate,
                 bg=DARK["entry"], fg=DARK["fg"],
                 insertbackground=DARK["fg"], relief="flat",
                 font=("Consolas", 8), width=8).pack(side="left", ipady=2)
        tk.Label(mr2, text="Pkts/s", bg=DARK["bg"], fg=DARK["border"],
                 font=("Segoe UI", 7, "italic")).pack(side="left", padx=4)
        masscan_btn = ttk.Button(fm, text="Masscan starten",
                                 command=self._run_masscan)
        masscan_btn.pack(fill="x", padx=10, pady=(0, 4))
        self._tooltip(masscan_btn,
            "Masscan: Deutlich schnellerer Port-Sweep als nmap.\n"
            "Ergebnisse werden in den Treeview übernommen.")

        # Start/Stop
        btn_row = tk.Frame(left, bg=DARK["bg"]); btn_row.pack(fill="x", padx=10, pady=8)
        self._start_btn = ttk.Button(btn_row, text="nmap starten",
                                     style="Accent.TButton",
                                     command=self._run_scan)
        self._start_btn.pack(side="left", fill="x", expand=True)
        self._tooltip(self._start_btn, "Startet den nmap-Scan mit dem gewählten Profil und Ziel.")
        self._stop_btn  = ttk.Button(btn_row, text="Stoppen",
                                     style="Danger.TButton",
                                     command=self._stop_tool,
                                     state="disabled")
        self._stop_btn.pack(side="left", fill="x", expand=True, padx=(6, 0))
        self._tooltip(self._stop_btn, "Bricht den laufenden Scan ab.")

        # ── Rechte Seite: Treeview + Log ──────────────────────────────────────
        fres = self._section_expand(right, "Ergebnisse")
        fres.pack(fill="both", expand=True)
        tree_cols = ("host", "port", "proto", "state", "service", "version")
        self._tree = ttk.Treeview(fres, columns=tree_cols, show="headings",
                                   selectmode="browse")
        for col, w, label in [
            ("host",    140, "Host"),
            ("port",    60,  "Port"),
            ("proto",   45,  "Proto"),
            ("state",   60,  "Status"),
            ("service", 90,  "Dienst"),
            ("version", 200, "Version / Info"),
        ]:
            self._tree.heading(col, text=label)
            self._tree.column(col, width=w, minwidth=40)
        self._tree.tag_configure("open",     foreground=DARK["green"])
        self._tree.tag_configure("filtered", foreground=DARK["yellow"])
        self._tree.tag_configure("closed",   foreground=DARK["border"])
        self._tree.tag_configure("host",     background=DARK["panel"],
                                             foreground=DARK["accent"])
        tsb = ttk.Scrollbar(fres, command=self._tree.yview)
        self._tree.configure(yscrollcommand=tsb.set)
        tsb.pack(side="right", fill="y")
        self._tree.pack(fill="both", expand=True, padx=6, pady=4)
        self._tree.bind("<Double-1>", self._on_tree_dclick)

        exp_row = tk.Frame(right, bg=DARK["bg"]); exp_row.pack(fill="x", padx=10, pady=(0, 4))
        ttk.Button(exp_row, text="Export JSON",
                   command=self._export_json).pack(side="left")
        ttk.Button(exp_row, text="Export TXT",
                   command=lambda: self._export_txt()).pack(side="left", padx=4)
        self._result_count = tk.StringVar(value="")
        tk.Label(exp_row, textvariable=self._result_count,
                 bg=DARK["bg"], fg=DARK["accent"],
                 font=("Segoe UI", 8)).pack(side="right", padx=4)

        self._log_out = self._log_widget(right, height=6)

    def _on_profile(self, _=None):
        if "Custom" in self._profile_cb.get():
            self._custom_frame.pack(fill="x", padx=4, pady=2,
                                    after=self._profile_cb.master)
        else:
            self._custom_frame.pack_forget()

    def _build_cmd(self) -> list[str]:
        nmap = self._tool_path("nmap")
        if not nmap:
            return []
        profile_key = self._profile_cb.get()
        flags = SCAN_PROFILES.get(profile_key, [])
        if "Custom" in profile_key:
            flags = self._custom_var.get().split()
        if self._os_var.get()   and "-O" not in flags:
            flags.append("-O")
        if self._udp_var.get()  and "-sU" not in flags:
            flags.append("-sU")
        if self._aggr_var.get() and "-A" not in flags:
            flags.append("-A")
        target = self._target_entry_var.get().strip()
        out_dir = self._out_dir.get().strip()
        if out_dir:
            import os; os.makedirs(out_dir, exist_ok=True)
            xml_out = str(Path(out_dir) / f"nmap_{target.replace('/', '_').replace('.', '_')}.xml")
            flags += ["-oX", xml_out]
        return [nmap] + flags + [target]

    def _run_scan(self):
        nmap = self._require_tool("nmap", self._log_out)
        if not nmap:
            return
        target = self._target_entry_var.get().strip()
        if not target:
            messagebox.showerror("Fehler", "Bitte ein Ziel angeben."); return
        self._tree.delete(*self._tree.get_children())
        self._result_count.set("")
        self._current_host = ""
        self._scan_results: list[dict] = []
        cmd = self._build_cmd()
        self._run_tool(cmd, None, self._log_out,
                       on_line=self._parse_nmap_line,
                       on_done=self._on_scan_done,
                       start_btn=self._start_btn,
                       stop_btn=self._stop_btn)

    def _parse_nmap_line(self, line: str):
        hm = _HOST_RE.search(line)
        if hm:
            self._current_host = hm.group(1).strip()
            self._tree.insert("", "end", iid=self._current_host,
                              values=(self._current_host, "", "", "", "HOST", ""),
                              tags=("host",))
            return
        pm = _PORT_RE.match(line.strip())
        if pm and self._current_host:
            port, proto, state, rest = pm.groups()
            parts  = rest.split(None, 1)
            svc    = parts[0] if parts else ""
            ver    = parts[1] if len(parts) > 1 else ""
            tag    = state.lower() if state.lower() in ("open","filtered","closed") else None
            self._tree.insert("", "end",
                              values=(self._current_host, port, proto, state, svc, ver),
                              tags=(tag,) if tag else ())
            self._scan_results.append({
                "host": self._current_host, "port": port,
                "proto": proto, "state": state, "service": svc, "version": ver
            })

    def _on_scan_done(self, rc: int):
        n = len(self._scan_results)
        self._result_count.set(f"{n} offene Port(e)")
        self._save_history()

    def _save_history(self):
        entry = {
            "target": self._target_entry_var.get(),
            "profile": self._profile_cb.get(),
            "results": self._scan_results,
        }
        self._history.insert(0, entry)
        if len(self._history) > 10:
            self._history.pop()
        self._hist_cb.configure(
            values=[f"{h['target']} ({h['profile']})" for h in self._history])

    def _load_history(self, _=None):
        idx = self._hist_cb.current()
        if idx < 0 or idx >= len(self._history):
            return
        entry = self._history[idx]
        self._tree.delete(*self._tree.get_children())
        self._current_host = ""
        for r in entry["results"]:
            if r["host"] != self._current_host:
                self._current_host = r["host"]
                try:
                    self._tree.insert("", "end", iid=self._current_host,
                                      values=(self._current_host, "", "", "", "HOST", ""),
                                      tags=("host",))
                except Exception:
                    pass
            tag = r["state"].lower() if r["state"].lower() in ("open","filtered","closed") else None
            self._tree.insert("", "end",
                              values=(r["host"], r["port"], r["proto"],
                                      r["state"], r["service"], r["version"]),
                              tags=(tag,) if tag else ())

    def _on_tree_dclick(self, event):
        sel = self._tree.selection()
        if not sel:
            return
        vals = self._tree.item(sel[0], "values")
        if not vals or not vals[1]:
            return
        port = vals[1]
        if port in ("80", "443", "8080", "8443"):
            if self._activity_cb:
                self._activity_cb(f"Web-Port {port} → Web-Modul empfohlen")
        elif port == "22":
            if self._activity_cb:
                self._activity_cb(f"SSH Port 22 erkannt → Hydra SSH möglich")

    def _export_json(self):
        if not self._scan_results:
            messagebox.showinfo("Leer", "Keine Ergebnisse vorhanden."); return
        path = self._save_file(tk.StringVar(), "JSON exportieren", ".json",
                               [("JSON", "*.json")])
        if path:
            import json
            with open(path, "w", encoding="utf-8") as f:
                json.dump(self._scan_results, f, indent=2, ensure_ascii=False)

    def _export_txt(self):
        if not self._scan_results:
            messagebox.showinfo("Leer", "Keine Ergebnisse vorhanden."); return
        path = self._save_file(tk.StringVar(), "TXT exportieren", ".txt",
                               [("Text", "*.txt")])
        if path:
            with open(path, "w", encoding="utf-8") as f:
                for r in self._scan_results:
                    f.write("{:<20} {:<6} {:<4} {:<10} {:<12} {}\n".format(
                        r['host'], r['port'], r['proto'],
                        r['state'], r['service'], r['version']))

    def _run_masscan(self):
        masscan = self._require_tool("masscan", self._log_out)
        if not masscan:
            return
        target = self._target_entry_var.get().strip()
        if not target:
            messagebox.showerror("Fehler", "Bitte ein Ziel angeben."); return
        ports  = self._masscan_ports.get().strip() or "1-1024"
        rate   = self._masscan_rate.get().strip() or "1000"
        cmd = [masscan, target, "-p", ports, "--rate", rate]
        if masscan.lower().endswith(".bat"):
            cmd = ["cmd", "/c"] + cmd
        self._run_tool(cmd, None, self._log_out,
                       on_line=self._parse_masscan_line,
                       on_done=lambda rc: self._result_count.set(
                           f"{len(self._scan_results)} Port(e) (inkl. Masscan)"),
                       start_btn=self._start_btn,
                       stop_btn=self._stop_btn)

    _MASSCAN_RE = re.compile(
        r"Discovered open port (\d+)/(\w+) on ([\d.]+)")

    def _parse_masscan_line(self, line: str):
        m = self._MASSCAN_RE.search(line)
        if not m:
            return
        port, proto, host = m.group(1), m.group(2), m.group(3)
        if host != getattr(self, "_current_host", ""):
            self._current_host = host
            try:
                self._tree.insert("", "end", iid=f"ms_{host}",
                                  values=(host, "", "", "", "HOST (masscan)", ""),
                                  tags=("host",))
            except tk.TclError:
                pass
        self._tree.insert("", "end",
                          values=(host, port, proto, "open", "", "masscan"),
                          tags=("open",))
        self._scan_results.append({"host": host, "port": port,
                                   "proto": proto, "state": "open",
                                   "service": "", "version": "masscan"})
