"""PortExposureModule – lokale Angriffsfläche analysieren (read-only).

Zeigt, welche Dienste auf DIESEM System lauschen, welcher Prozess sie öffnet,
ob sie nur lokal oder nach außen erreichbar sind, und ob der Prozess signiert
ist. Optional ein nmap-Self-Scan gegen die eigene IP, um zu sehen, was ein
Angreifer von außen sieht. Es werden keine Ports geschlossen o. Ä.
"""
import tkinter as tk
from tkinter import ttk
import threading
import socket

from modules.base import BaseModule
from utils.theme import DARK


# Bekannte/erwartete lokale Dienste → kurze Klartext-Beschreibung
_KNOWN_PORTS = {
    135: "RPC Endpoint Mapper", 139: "NetBIOS Session", 445: "SMB",
    3389: "RDP", 5985: "WinRM HTTP", 5986: "WinRM HTTPS",
    22: "SSH", 80: "HTTP", 443: "HTTPS", 3306: "MySQL",
    5432: "PostgreSQL", 1433: "MSSQL", 27017: "MongoDB",
    6379: "Redis", 8080: "HTTP-Alt", 18800: "G4MEOVER API",
}

# Listening TCP/UDP + Prozess + Signatur als JSON
_PORTS_PS = r'''
$ErrorActionPreference = 'SilentlyContinue'
$out = New-Object System.Collections.ArrayList
$procCache = @{}

function Get-ProcInfo($procId) {
    if ($procCache.ContainsKey($procId)) { return $procCache[$procId] }
    $info = [PSCustomObject]@{ name = "?"; path = ""; signed = "Unbekannt" }
    try {
        $p = Get-Process -Id $procId -ErrorAction Stop
        $info.name = $p.ProcessName
        $info.path = $p.Path
        if ($p.Path) {
            $sig = Get-AuthenticodeSignature -FilePath $p.Path -ErrorAction SilentlyContinue
            if ($sig.Status -eq 'Valid') { $info.signed = "Signiert: " + $sig.SignerCertificate.Subject.Split(',')[0].Replace('CN=','') }
            elseif ($sig.Status) { $info.signed = "UNSIGNIERT ($($sig.Status))" }
        }
    } catch {}
    $procCache[$procId] = $info
    return $info
}

foreach ($c in Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue) {
    $pi = Get-ProcInfo $c.OwningProcess
    [void]$out.Add([PSCustomObject]@{
        proto = "TCP"; addr = $c.LocalAddress; port = $c.LocalPort
        procId = $c.OwningProcess; pname = $pi.name; path = $pi.path; signed = $pi.signed
    })
}
foreach ($u in Get-NetUDPEndpoint -ErrorAction SilentlyContinue) {
    $pi = Get-ProcInfo $u.OwningProcess
    [void]$out.Add([PSCustomObject]@{
        proto = "UDP"; addr = $u.LocalAddress; port = $u.LocalPort
        procId = $u.OwningProcess; pname = $pi.name; path = $pi.path; signed = $pi.signed
    })
}
$out | ConvertTo-Json -Depth 3 -Compress
'''


def _is_external(addr: str) -> bool:
    """True, wenn die Bind-Adresse nach außen erreichbar ist (nicht nur localhost)."""
    return addr not in ("127.0.0.1", "::1")


class PortExposureModule(BaseModule):
    """Read-only: lauschende Ports + Prozesse + optionaler Self-Scan."""

    def _build(self):
        self._info_bar(
            self,
            "Zeigt lauschende Dienste auf DIESEM System: welcher Prozess, signiert oder nicht, "
            "und ob nur lokal (127.0.0.1) oder nach außen erreichbar. Read-only – es wird nichts geschlossen.")

        bar = tk.Frame(self, bg=DARK["bg"])
        bar.pack(fill="x", padx=10, pady=(6, 2))

        self._scan_btn = ttk.Button(bar, text="Lauschende Ports anzeigen",
                                     style="Accent.TButton", command=self._start_listen_scan)
        self._scan_btn.pack(side="left")

        self._ext_only = tk.BooleanVar(value=False)
        ttk.Checkbutton(bar, text="Nur extern erreichbare",
                        variable=self._ext_only,
                        command=self._refilter).pack(side="left", padx=(10, 0))

        self._report_btn = ttk.Button(bar, text="Auffällige an Reporting",
                                       command=self._send_to_report, state="disabled")
        self._report_btn.pack(side="left", padx=(10, 0))

        self._summary_var = tk.StringVar(value="")
        tk.Label(bar, textvariable=self._summary_var, bg=DARK["bg"], fg=DARK["border"],
                 font=("Segoe UI", 9, "bold")).pack(side="right", padx=8)

        # ── Listener-Tabelle ────────────────────────────────────────────────────
        sec = self._section_expand(self, "Lauschende Dienste")
        cols = ("proto", "addr", "port", "svc", "proc", "pid", "signed", "exposure")
        self._tree = ttk.Treeview(sec, columns=cols, show="headings", selectmode="browse")
        for c, t, w in [("proto", "Proto", 55), ("addr", "Bind-Adresse", 130),
                        ("port", "Port", 60), ("svc", "Dienst", 130),
                        ("proc", "Prozess", 130), ("pid", "PID", 60),
                        ("signed", "Signatur", 280), ("exposure", "Erreichbar", 100)]:
            self._tree.heading(c, text=t)
            self._tree.column(c, width=w, anchor="w")
        sb = ttk.Scrollbar(sec, command=self._tree.yview)
        self._tree.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self._tree.pack(fill="both", expand=True, padx=6, pady=6)
        self._tree.tag_configure("extern", foreground=DARK["orange"])
        self._tree.tag_configure("unsigned", foreground=DARK["red"])
        self._tree.tag_configure("local", foreground=DARK["fg"])

        # ── Self-Scan ───────────────────────────────────────────────────────────
        ssec = self._section(self, "nmap Self-Scan (Außensicht)")
        srow = tk.Frame(ssec, bg=DARK["bg"]); srow.pack(fill="x", padx=10, pady=4)
        self._self_ip = tk.StringVar(value=self._local_ip())
        tk.Label(srow, text="Eigene IP:", bg=DARK["bg"], fg=DARK["fg"],
                 font=("Segoe UI", 9), width=12, anchor="w").pack(side="left")
        tk.Entry(srow, textvariable=self._self_ip, bg=DARK["entry"], fg=DARK["fg"],
                 insertbackground=DARK["fg"], relief="flat",
                 font=("Segoe UI", 9), width=20).pack(side="left", ipady=3)
        self._selfscan_btn = ttk.Button(srow, text="Self-Scan starten",
                                         command=self._start_self_scan)
        self._selfscan_btn.pack(side="left", padx=(8, 0))
        self._stop_btn = ttk.Button(srow, text="Stop", style="Danger.TButton",
                                    command=self._stop_tool, state="disabled")
        self._stop_btn.pack(side="left", padx=(4, 0))

        self._output = self._log_widget(self, height=8)

        self._rows: list[dict] = []

    # ── Helpers ─────────────────────────────────────────────────────────────────

    def _local_ip(self) -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    # ── Listener-Scan ─────────────────────────────────────────────────────────

    def _start_listen_scan(self):
        self._scan_btn.configure(state="disabled")
        for iid in self._tree.get_children():
            self._tree.delete(iid)
        self._summary_var.set("Scanne …")
        threading.Thread(target=self._run_listen_scan, daemon=True).start()

    def _run_listen_scan(self):
        data, err = self._ps_json(_PORTS_PS, timeout=90)
        if not data and err:
            self.after(0, lambda: (self._scan_btn.configure(state="normal"),
                                   self._summary_var.set(f"Fehler: {err}")))
            return
        self.after(0, self._render_listeners, data)

    def _render_listeners(self, data: list[dict]):
        self._rows = data
        self._scan_btn.configure(state="normal")
        self._refilter()

    def _refilter(self):
        for iid in self._tree.get_children():
            self._tree.delete(iid)
        ext_only = self._ext_only.get()
        n_ext = n_unsigned = 0
        # extern + unsigniert zuerst
        def sortkey(r):
            ext = _is_external(r.get("addr", ""))
            uns = "UNSIGNIERT" in (r.get("signed") or "")
            return (0 if ext else 1, 0 if uns else 1, r.get("port", 0))
        for r in sorted(self._rows, key=sortkey):
            addr = r.get("addr", "")
            ext = _is_external(addr)
            if ext_only and not ext:
                continue
            unsigned = "UNSIGNIERT" in (r.get("signed") or "")
            if ext:
                n_ext += 1
            if unsigned:
                n_unsigned += 1
            tag = "unsigned" if unsigned else ("extern" if ext else "local")
            port = r.get("port", 0)
            svc = _KNOWN_PORTS.get(port, "")
            self._tree.insert("", "end", tags=(tag,), values=(
                r.get("proto", ""), addr, port, svc,
                r.get("pname", ""), r.get("procId", ""),
                r.get("signed", ""), "extern" if ext else "lokal"))
        self._summary_var.set(
            f"{len(self._rows)} Listener · {n_ext} extern · {n_unsigned} unsigniert")
        if n_ext or n_unsigned:
            self._report_btn.configure(state="normal")
        if self._activity_cb:
            self._activity_cb(
                f"Port-Exposure: {len(self._rows)} Listener, {n_ext} extern, {n_unsigned} unsigniert")

    def _send_to_report(self):
        sent = 0
        for r in self._rows:
            addr = r.get("addr", "")
            ext = _is_external(addr)
            unsigned = "UNSIGNIERT" in (r.get("signed") or "")
            if not (ext or unsigned):
                continue
            sev = "Hoch" if unsigned else "Mittel"
            port = r.get("port", 0)
            svc = _KNOWN_PORTS.get(port, "unbekannter Dienst")
            title = f"[Exposure] {r.get('proto','')}/{port} {r.get('pname','')}"
            desc = (f"Bind-Adresse {addr} ({'extern erreichbar' if ext else 'lokal'}), "
                    f"Dienst: {svc}, Prozess: {r.get('pname','')} (PID {r.get('procId','')}), "
                    f"Signatur: {r.get('signed','')}.")
            if unsigned:
                desc += "\n\nEmpfehlung: Unsignierten Listener prüfen, ggf. Dienst stoppen/Firewall-Regel setzen."
            elif ext:
                desc += "\n\nEmpfehlung: Falls nicht benötigt, an localhost binden oder per Firewall einschränken."
            if self._report_finding(title, sev, desc):
                sent += 1
        if self._activity_cb:
            self._activity_cb(
                f"{sent} Exposure-Befund(e) an Reporting übergeben" if sent
                else "Reporting nicht verbunden / keine auffälligen Listener")

    # ── nmap Self-Scan ──────────────────────────────────────────────────────────

    def _start_self_scan(self):
        nmap = self._require_tool("nmap", self._output)
        if not nmap:
            return
        ip = self._self_ip.get().strip()
        if not ip:
            self._log(self._output, "[!] Keine IP angegeben.\n", "red")
            return
        cmd = [nmap, "-sV", "-T4", "--top-ports", "200", ip]
        self._run_tool(cmd, cwd=None, log_widget=self._output,
                       start_btn=self._selfscan_btn, stop_btn=self._stop_btn,
                       on_done=lambda rc: self._log(
                           self._output,
                           f"\n[+] Self-Scan beendet (Code {rc}). "
                           f"Vergleiche die offenen Ports mit der Listener-Tabelle oben.\n",
                           "green"))
        if self._activity_cb:
            self._activity_cb(f"nmap Self-Scan gegen {ip} gestartet")
