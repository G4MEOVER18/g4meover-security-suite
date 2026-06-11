"""AccountAuditModule – Konten-, Passwort-Policy- & Credential-Schutz (read-only).

Prüft auf dem eigenen System:
  - Lokale Konten: aktiviert? Passwort erforderlich? Passwort läuft ab? letzte Anmeldung
  - Eingebautes Administrator-/Gast-Konto
  - Passwort-Policy (secedit): Mindestlänge, Komplexität, History, max. Alter, Lockout
  - Credential-/LSASS-Schutz: NoLMHash, RunAsPPL (LSASS PPL), WDigest-Klartext,
    LmCompatibilityLevel (NTLMv1), Credential Guard

Read-only – es werden keine Konten oder Richtlinien geändert.
"""
import tkinter as tk
from tkinter import ttk
import threading

from modules.base import BaseModule
from utils.theme import DARK, SEVERITY_COLORS


_ACCOUNT_PS = r'''
$ErrorActionPreference = 'SilentlyContinue'
$r = New-Object System.Collections.ArrayList
function Add-Chk($name,$sev,$status,$detail,$rec){
    [void]$r.Add([PSCustomObject]@{ name=$name; severity=$sev; status=$status; detail=$detail; recommendation=$rec })
}

# ── Lokale Konten ──────────────────────────────────────────────────────────────
$users = Get-LocalUser -ErrorAction SilentlyContinue
foreach ($u in $users) {
    if ($u.Enabled -and -not $u.PasswordRequired) {
        Add-Chk "Konto: $($u.Name)" 'Kritisch' 'Kein Passwort noetig' "Aktives Konto erlaubt leeres Passwort." 'PasswordRequired erzwingen / Passwort setzen.'
    }
    $sid = "$($u.SID)"
    if ($u.Enabled -and $sid.EndsWith('-500')) {
        Add-Chk "Konto: $($u.Name)" 'Mittel' 'Builtin-Admin aktiv' 'Eingebautes Administrator-Konto ist aktiviert.' 'Umbenennen + deaktivieren; dediziertes Admin-Konto nutzen.'
    }
    if ($u.Enabled -and $sid.EndsWith('-501')) {
        Add-Chk "Konto: $($u.Name)" 'Mittel' 'Gast aktiv' 'Gast-Konto ist aktiviert.' 'Gast-Konto deaktivieren.'
    }
    if ($u.Enabled -and $u.PasswordRequired -and ($null -eq $u.PasswordExpires) -and $u.PasswordLastSet) {
        Add-Chk "Konto: $($u.Name)" 'Niedrig' 'Passwort laeuft nie ab' 'Aktives Konto mit nie ablaufendem Passwort.' 'Bei Bedarf Ablauf aktivieren (Heimsysteme oft unkritisch).'
    }
}
$active = @($users | Where-Object { $_.Enabled }).Count
Add-Chk 'Lokale Konten (aktiv)' 'Info' "$active aktiv" "Insgesamt $(@($users).Count) lokale Konten, $active aktiviert." ''

# ── Passwort-Policy via secedit ────────────────────────────────────────────────
try {
    $tmp = "$env:TEMP\secpol_$(Get-Random).inf"
    secedit /export /cfg $tmp /quiet 2>$null | Out-Null
    if (Test-Path $tmp) {
        $cfg = Get-Content $tmp
        function GV($k){ $line = ($cfg | Select-String "^\s*$k\s*=" | Select-Object -First 1); if ($line) { ($line.ToString() -replace '.*=\s*','').Trim() } else { $null } }
        $minLen  = [int](GV 'MinimumPasswordLength')
        $complex = [int](GV 'PasswordComplexity')
        $hist    = [int](GV 'PasswordHistorySize')
        $maxAge  = [int](GV 'MaximumPasswordAge')
        $lockout = [int](GV 'LockoutBadCount')
        Remove-Item $tmp -Force -ErrorAction SilentlyContinue

        if ($minLen -ge 12) { Add-Chk 'Passwort-Mindestlaenge' 'OK' "$minLen Zeichen" 'Mindestlaenge >= 12.' '' }
        elseif ($minLen -ge 8) { Add-Chk 'Passwort-Mindestlaenge' 'Niedrig' "$minLen Zeichen" 'Mindestlaenge 8-11.' 'Auf >= 12 erhoehen.' }
        else { Add-Chk 'Passwort-Mindestlaenge' 'Mittel' "$minLen Zeichen" 'Mindestlaenge < 8.' 'Auf >= 12 setzen.' }

        if ($complex -eq 1) { Add-Chk 'Passwort-Komplexitaet' 'OK' 'An' 'Komplexitaet erzwungen.' '' }
        else { Add-Chk 'Passwort-Komplexitaet' 'Mittel' 'Aus' 'Keine Komplexitaetsanforderung.' 'Passwort-Komplexitaet aktivieren.' }

        if ($lockout -ge 1 -and $lockout -le 10) { Add-Chk 'Konto-Sperrung' 'OK' "$lockout Versuche" 'Lockout nach Fehlversuchen aktiv.' '' }
        else { Add-Chk 'Konto-Sperrung' 'Mittel' 'Aus/hoch' "LockoutBadCount=$lockout (kein/zu hoher Schwellwert)." 'Lockout-Schwelle (z. B. 5-10) setzen gegen Brute-Force.' }

        if ($hist -ge 5) { Add-Chk 'Passwort-Historie' 'OK' "$hist" 'Wiederverwendung eingeschraenkt.' '' }
        else { Add-Chk 'Passwort-Historie' 'Niedrig' "$hist" 'Geringe/keine Passwort-Historie.' 'Historie >= 5 setzen.' }
    } else {
        Add-Chk 'Passwort-Policy' 'Info' 'Nicht lesbar' 'secedit-Export nicht moeglich (Adminrechte noetig).' 'Als Administrator erneut pruefen.'
    }
} catch { Add-Chk 'Passwort-Policy' 'Info' 'Fehler' 'Policy nicht ermittelbar.' '' }

# ── Credential-/LSASS-Schutz ────────────────────────────────────────────────────
$lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$noLM = (Get-ItemProperty $lsa -Name NoLmHash -EA SilentlyContinue).NoLmHash
if ($noLM -eq 1) { Add-Chk 'LM-Hash-Speicherung' 'OK' 'Deaktiviert' 'Keine LM-Hashes gespeichert.' '' }
else { Add-Chk 'LM-Hash-Speicherung' 'Mittel' 'Aktiv' 'Schwache LM-Hashes koennten gespeichert werden.' 'NoLmHash=1 setzen.' }

$ppl = (Get-ItemProperty $lsa -Name RunAsPPL -EA SilentlyContinue).RunAsPPL
if ($ppl -ge 1) { Add-Chk 'LSASS-Schutz (RunAsPPL)' 'OK' 'An' 'LSASS als Protected Process – erschwert Credential-Dumping.' '' }
else { Add-Chk 'LSASS-Schutz (RunAsPPL)' 'Hoch' 'Aus' 'LSASS nicht als PPL geschuetzt (Mimikatz-Risiko).' 'RunAsPPL=1 setzen (LSA Protection).' }

$wdigest = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name UseLogonCredential -EA SilentlyContinue).UseLogonCredential
if ($wdigest -eq 1) { Add-Chk 'WDigest Klartext' 'Hoch' 'Aktiv' 'WDigest speichert Klartext-Credentials im Speicher!' 'UseLogonCredential=0 setzen.' }
else { Add-Chk 'WDigest Klartext' 'OK' 'Aus' 'Keine WDigest-Klartext-Credentials.' '' }

$lmc = (Get-ItemProperty $lsa -Name LmCompatibilityLevel -EA SilentlyContinue).LmCompatibilityLevel
if ($null -eq $lmc) { Add-Chk 'NTLM-Kompatibilitaet' 'Niedrig' 'Standard' 'LmCompatibilityLevel nicht gesetzt (OS-Default).' 'Auf 5 setzen (nur NTLMv2).' }
elseif ($lmc -ge 3) { Add-Chk 'NTLM-Kompatibilitaet' 'OK' "Level $lmc" 'NTLMv2 erzwungen.' '' }
else { Add-Chk 'NTLM-Kompatibilitaet' 'Mittel' "Level $lmc" 'NTLMv1/LM noch erlaubt.' 'LmCompatibilityLevel auf 5 setzen.' }

# Credential Guard
try {
    $dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace 'root\Microsoft\Windows\DeviceGuard' -ErrorAction SilentlyContinue
    if ($dg -and ($dg.SecurityServicesRunning -contains 1)) { Add-Chk 'Credential Guard' 'OK' 'Aktiv' 'Credential Guard laeuft.' '' }
    else { Add-Chk 'Credential Guard' 'Niedrig' 'Aus' 'Credential Guard nicht aktiv.' 'Falls Hardware/Edition es erlaubt: Credential Guard aktivieren.' }
} catch {}

$r | ConvertTo-Json -Depth 3 -Compress
'''


class AccountAuditModule(BaseModule):
    """Read-only Konten-, Policy- & Credential-Schutz-Audit."""

    def _build(self):
        self._info_bar(
            self,
            "Read-only Audit von Konten, Passwort-Policy und Credential-/LSASS-Schutz "
            "(RunAsPPL, WDigest, NTLM-Level, Credential Guard). Vollständig als Administrator.")

        bar = tk.Frame(self, bg=DARK["bg"]); bar.pack(fill="x", padx=10, pady=(6, 2))
        self._run_btn = ttk.Button(bar, text="Konten-Audit starten",
                                    style="Accent.TButton", command=self._start)
        self._run_btn.pack(side="left")
        self._report_btn = ttk.Button(bar, text="Befunde an Reporting",
                                       command=self._send_report, state="disabled")
        self._report_btn.pack(side="left", padx=(6, 0))
        self._sum = tk.StringVar(value="Noch kein Audit")
        self._sum_lbl = tk.Label(bar, textvariable=self._sum, bg=DARK["bg"],
                                 fg=DARK["border"], font=("Segoe UI", 10, "bold"))
        self._sum_lbl.pack(side="right", padx=8)

        sec = self._section_expand(self, "Konten & Credential-Schutz")
        cols = ("check", "status", "detail", "rec")
        self._tree = ttk.Treeview(sec, columns=cols, show="headings", selectmode="browse")
        for c, t, w in [("check", "Prüfung", 220), ("status", "Status", 150),
                        ("detail", "Detail", 420), ("rec", "Empfehlung", 400)]:
            self._tree.heading(c, text=t)
            self._tree.column(c, width=w, anchor="w")
        sb = ttk.Scrollbar(sec, command=self._tree.yview)
        self._tree.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self._tree.pack(fill="both", expand=True, padx=6, pady=6)
        for sev, col in SEVERITY_COLORS.items():
            self._tree.tag_configure(sev, foreground=col)
        self._tree.tag_configure("OK", foreground=DARK["green"])
        self._rows: list[dict] = []

    def _start(self):
        self._run_btn.configure(state="disabled")
        self._report_btn.configure(state="disabled")
        for iid in self._tree.get_children():
            self._tree.delete(iid)
        self._sum.set("Audit läuft …")
        self._sum_lbl.configure(fg=DARK["accent"])
        if self._activity_cb:
            self._activity_cb("Konten-Audit gestartet")
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        data, err = self._ps_json(_ACCOUNT_PS)
        if not data and err:
            self.after(0, lambda: (self._run_btn.configure(state="normal"),
                                   self._sum.set(f"Fehler: {err}")))
            return
        self.after(0, self._render, data)

    def _render(self, data: list[dict]):
        self._rows = data
        order = {"Kritisch": 0, "Hoch": 1, "Mittel": 2, "Niedrig": 3, "Info": 4, "OK": 5}
        weight = {"Kritisch": 5, "Hoch": 3, "Mittel": 2, "Niedrig": 1}
        problems = risk = ok = 0
        for d in sorted(data, key=lambda d: order.get(d.get("severity", "Info"), 9)):
            sev = d.get("severity", "Info")
            self._tree.insert("", "end", tags=(sev,), values=(
                d.get("name", ""), d.get("status", ""),
                d.get("detail", ""), d.get("recommendation", "")))
            if sev == "OK":
                ok += 1
            elif sev in weight:
                problems += 1
                risk += weight[sev]
        self._run_btn.configure(state="normal")
        if problems:
            self._report_btn.configure(state="normal")
            clr = DARK["red"] if risk >= 8 else (DARK["orange"] if risk >= 4 else DARK["yellow"])
            self._sum.set(f"{problems} Befund(e) · Risiko {risk}")
            self._sum_lbl.configure(fg=clr)
        else:
            self._sum.set(f"✓ {ok} Checks ok")
            self._sum_lbl.configure(fg=DARK["green"])
        if self._activity_cb:
            self._activity_cb(f"Konten-Audit: {problems} Befund(e), Risiko {risk}")

    def _send_report(self):
        sent = 0
        for d in self._rows:
            sev = d.get("severity", "Info")
            if sev in ("OK", "Info"):
                continue
            desc = d.get("detail", "")
            rec = d.get("recommendation", "")
            if rec:
                desc = f"{desc}\n\nEmpfehlung: {rec}"
            if self._report_finding(f"[Konto] {d.get('name','')}", sev, desc):
                sent += 1
        if self._activity_cb:
            self._activity_cb(f"{sent} Konten-Befund(e) an Reporting übergeben" if sent
                              else "Reporting nicht verbunden / keine Befunde")
