"""FirewallAuditModule – Windows-Firewall-Regel-Audit (read-only).

Bewertet die Firewall des eigenen Systems:
  - Pro Profil (Domain/Privat/Öffentlich): aktiv? Default-Inbound/-Outbound-Aktion
  - Eingehende Allow-Regeln mit Programm/Port/Profil/Remote-Adresse
  - Hebt nach außen exponierte Regeln hervor (Profil Öffentlich/Any + Remote Any)

Read-only: es werden keine Firewall-Regeln angelegt, geändert oder gelöscht.
"""
import tkinter as tk
from tkinter import ttk
import threading

from modules.base import BaseModule
from utils.theme import DARK, SEVERITY_COLORS


# Profile + eingehende Allow-Regeln als flache JSON-Liste.
# Port-/App-Filter werden per InstanceID gemappt (1 Aufruf statt pro Regel).
_FW_PS = r'''
$ErrorActionPreference = 'SilentlyContinue'
$out = New-Object System.Collections.ArrayList

# Profile
foreach ($p in Get-NetFirewallProfile -ErrorAction SilentlyContinue) {
    [void]$out.Add([PSCustomObject]@{
        type='profile'; name="$($p.Name)"; enabled="$($p.Enabled)"
        inbound="$($p.DefaultInboundAction)"; outbound="$($p.DefaultOutboundAction)" })
}

# Port- und App-Filter per InstanceID indexieren
$portMap = @{}; Get-NetFirewallPortFilter | ForEach-Object { $portMap[$_.InstanceID] = $_ }
$appMap  = @{}; Get-NetFirewallApplicationFilter | ForEach-Object { $appMap[$_.InstanceID] = $_ }
$addrMap = @{}; Get-NetFirewallAddressFilter | ForEach-Object { $addrMap[$_.InstanceID] = $_ }

$rules = Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True -ErrorAction SilentlyContinue
foreach ($ru in $rules) {
    $pf = $portMap[$ru.InstanceID]; $af = $appMap[$ru.InstanceID]; $ad = $addrMap[$ru.InstanceID]
    $port = if ($pf) { "$($pf.Protocol)/$($pf.LocalPort)" } else { 'Any' }
    $app  = if ($af -and $af.Program -and $af.Program -ne 'Any') { Split-Path $af.Program -Leaf } else { 'Any' }
    $remote = if ($ad) { "$($ad.RemoteAddress)" } else { 'Any' }
    [void]$out.Add([PSCustomObject]@{
        type='rule'; name="$($ru.DisplayName)"; profile="$($ru.Profile)"
        port=$port; app=$app; remote=$remote })
}
$out | ConvertTo-Json -Depth 3 -Compress
'''


def _is_exposed(rule: dict) -> bool:
    prof = (rule.get("profile") or "")
    remote = (rule.get("remote") or "")
    public = ("Public" in prof) or ("Any" in prof)
    open_remote = remote in ("Any", "", "0.0.0.0-255.255.255.255")
    return public and open_remote


class FirewallAuditModule(BaseModule):
    """Read-only Audit der Windows-Firewall-Profile und Inbound-Allow-Regeln."""

    def _build(self):
        self._info_bar(
            self,
            "Read-only Audit der Windows-Firewall: Default-Aktionen pro Profil und eingehende "
            "Allow-Regeln. Nach außen exponierte Regeln (Öffentlich + Remote Any) werden hervorgehoben.")

        bar = tk.Frame(self, bg=DARK["bg"]); bar.pack(fill="x", padx=10, pady=(6, 2))
        self._run_btn = ttk.Button(bar, text="Firewall-Audit starten",
                                    style="Accent.TButton", command=self._start)
        self._run_btn.pack(side="left")
        self._report_btn = ttk.Button(bar, text="Befunde an Reporting",
                                       command=self._send_report, state="disabled")
        self._report_btn.pack(side="left", padx=(6, 0))
        self._exposed_only = tk.BooleanVar(value=False)
        ttk.Checkbutton(bar, text="Nur exponierte Regeln", variable=self._exposed_only,
                        command=self._refilter).pack(side="left", padx=(10, 0))
        self._sum = tk.StringVar(value="Noch kein Audit")
        self._sum_lbl = tk.Label(bar, textvariable=self._sum, bg=DARK["bg"],
                                 fg=DARK["border"], font=("Segoe UI", 10, "bold"))
        self._sum_lbl.pack(side="right", padx=8)

        # Profile-Übersicht (kompakt)
        psec = self._section(self, "Firewall-Profile")
        cols_p = ("profile", "enabled", "inbound", "outbound")
        self._ptree = ttk.Treeview(psec, columns=cols_p, show="headings", height=3,
                                   selectmode="browse")
        for c, t, w in [("profile", "Profil", 160), ("enabled", "Aktiv", 100),
                        ("inbound", "Default Eingehend", 180), ("outbound", "Default Ausgehend", 180)]:
            self._ptree.heading(c, text=t)
            self._ptree.column(c, width=w, anchor="w")
        self._ptree.pack(fill="x", padx=6, pady=6)
        self._ptree.tag_configure("bad", foreground=DARK["red"])
        self._ptree.tag_configure("ok", foreground=DARK["green"])

        # Inbound-Allow-Regeln
        rsec = self._section_expand(self, "Eingehende Allow-Regeln")
        cols_r = ("name", "profile", "port", "app", "remote")
        self._rtree = ttk.Treeview(rsec, columns=cols_r, show="headings", selectmode="browse")
        for c, t, w in [("name", "Regel", 360), ("profile", "Profil", 130),
                        ("port", "Port/Proto", 130), ("app", "Programm", 200),
                        ("remote", "Remote", 160)]:
            self._rtree.heading(c, text=t)
            self._rtree.column(c, width=w, anchor="w")
        sb = ttk.Scrollbar(rsec, command=self._rtree.yview)
        self._rtree.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self._rtree.pack(fill="both", expand=True, padx=6, pady=6)
        self._rtree.tag_configure("exposed", foreground=DARK["orange"])
        self._rtree.tag_configure("normal", foreground=DARK["fg"])

        self._profiles: list[dict] = []
        self._rules: list[dict] = []

    def _start(self):
        self._run_btn.configure(state="disabled")
        self._report_btn.configure(state="disabled")
        for iid in self._ptree.get_children():
            self._ptree.delete(iid)
        for iid in self._rtree.get_children():
            self._rtree.delete(iid)
        self._sum.set("Audit läuft …")
        self._sum_lbl.configure(fg=DARK["accent"])
        if self._activity_cb:
            self._activity_cb("Firewall-Audit gestartet")
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        data, err = self._ps_json(_FW_PS, timeout=90)
        if not data and err:
            self.after(0, lambda: (self._run_btn.configure(state="normal"),
                                   self._sum.set(f"Fehler: {err}")))
            return
        self.after(0, self._render, data)

    def _render(self, data: list[dict]):
        self._profiles = [d for d in data if d.get("type") == "profile"]
        self._rules = [d for d in data if d.get("type") == "rule"]
        self._run_btn.configure(state="normal")
        # Profile
        bad_profiles = 0
        for p in self._profiles:
            inbound = p.get("inbound", "")
            enabled = p.get("enabled", "")
            enabled_ok = enabled in ("True", "1", "Enabled")
            # NotConfigured = Windows-Default (Block); nur explizites Allow ist riskant
            inbound_ok = inbound in ("Block", "NotConfigured")
            ok = inbound_ok and enabled_ok
            if not ok:
                bad_profiles += 1
            self._ptree.insert("", "end", tags=("ok" if ok else "bad",), values=(
                p.get("name", ""), enabled, inbound, p.get("outbound", "")))
        self._render_rules()
        exposed = sum(1 for r in self._rules if _is_exposed(r))
        if bad_profiles or exposed:
            self._report_btn.configure(state="normal")
        self._sum.set(f"{len(self._rules)} Inbound-Allow · {exposed} exponiert · "
                      f"{bad_profiles} Profil-Befund(e)")
        self._sum_lbl.configure(fg=DARK["orange"] if (exposed or bad_profiles) else DARK["green"])
        if self._activity_cb:
            self._activity_cb(f"Firewall-Audit: {len(self._rules)} Inbound-Allow, "
                              f"{exposed} exponiert, {bad_profiles} Profil-Befunde")

    def _render_rules(self):
        for iid in self._rtree.get_children():
            self._rtree.delete(iid)
        only = self._exposed_only.get()
        rows = sorted(self._rules, key=lambda r: (0 if _is_exposed(r) else 1, r.get("name", "")))
        for r in rows:
            exp = _is_exposed(r)
            if only and not exp:
                continue
            self._rtree.insert("", "end", tags=("exposed" if exp else "normal",), values=(
                r.get("name", ""), r.get("profile", ""), r.get("port", ""),
                r.get("app", ""), r.get("remote", "")))

    def _refilter(self):
        if self._rules:
            self._render_rules()

    def _send_report(self):
        sent = 0
        for p in self._profiles:
            # Nur explizites Allow ist ein echtes Risiko (NotConfigured = Default Block)
            if p.get("inbound") == "Allow":
                if self._report_finding(
                        f"[Firewall] Profil {p.get('name','')} Default-Inbound = Allow",
                        "Hoch",
                        "Default-Inbound-Aktion erlaubt eingehenden Verkehr.\n\n"
                        "Empfehlung: Default-Inbound-Aktion auf Block setzen."):
                    sent += 1
            if p.get("enabled") not in ("True", "1", "Enabled"):
                if self._report_finding(
                        f"[Firewall] Profil {p.get('name','')} deaktiviert", "Hoch",
                        "Firewall-Profil ist deaktiviert.\n\nEmpfehlung: Profil aktivieren."):
                    sent += 1
        # Exponierte Regeln gebündelt als EIN Befund (sonst Report-Flut)
        exposed = [r for r in self._rules if _is_exposed(r)]
        if exposed:
            sample = "\n".join(f"- {r.get('name','')} ({r.get('port','')}, {r.get('app','')})"
                               for r in exposed[:15])
            more = f"\n… und {len(exposed) - 15} weitere" if len(exposed) > 15 else ""
            if self._report_finding(
                    f"[Firewall] {len(exposed)} nach außen exponierte Inbound-Allow-Regeln",
                    "Niedrig",
                    f"Eingehende Allow-Regeln für Profil Öffentlich/Any mit Remote=Any:\n{sample}{more}\n\n"
                    "Empfehlung: Im Firewall-Tab prüfen; nicht benötigte Regeln entfernen "
                    "oder Remote-Adresse einschränken."):
                sent += 1
        if self._activity_cb:
            self._activity_cb(f"{sent} Firewall-Befund(e) an Reporting übergeben" if sent
                              else "Reporting nicht verbunden / keine Befunde")
