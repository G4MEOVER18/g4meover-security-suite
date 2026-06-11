"""HardeningAuditModule – Windows Security Baseline-Check (read-only).

Prüft das LOKALE System gegen eine Härtungs-Baseline und vergibt einen
Ampel-Score. Es werden KEINE Änderungen am System vorgenommen – nur gelesen
und bewertet. Härtung führt der Nutzer anschließend manuell durch.
"""
import tkinter as tk
from tkinter import ttk
import threading
from datetime import datetime

from modules.base import BaseModule
from utils.theme import DARK, SEVERITY_COLORS


# ── PowerShell-Audit-Skript ────────────────────────────────────────────────────
# Gibt ein JSON-Array von Check-Objekten aus:
#   { name, severity, status, detail, recommendation }
# severity ∈ OK | Niedrig | Mittel | Hoch | Kritisch | Info
# Jeder Check ist in try/catch gekapselt → ein fehlender Cmdlet bricht das
# Gesamtaudit nicht ab (status = "Info", Hinweis auf evtl. fehlende Adminrechte).
_AUDIT_PS = r'''
$ErrorActionPreference = 'SilentlyContinue'
$results = New-Object System.Collections.ArrayList

function Add-Check($name, $sev, $status, $detail, $rec) {
    [void]$results.Add([PSCustomObject]@{
        name           = $name
        severity       = $sev
        status         = $status
        detail         = $detail
        recommendation = $rec
    })
}

# 1) BitLocker Systemlaufwerk
try {
    $sys = $env:SystemDrive
    $bl  = Get-BitLockerVolume -MountPoint $sys -ErrorAction Stop
    if ($bl.ProtectionStatus -eq 'On') {
        Add-Check "BitLocker ($sys)" "OK" "Aktiv" "Verschluesselung: $($bl.EncryptionPercentage)% ($($bl.VolumeStatus))" ""
    } else {
        Add-Check "BitLocker ($sys)" "Hoch" "Aus" "Systemlaufwerk ist NICHT verschluesselt." "BitLocker fuer das Systemlaufwerk aktivieren (manage-bde -on $sys)."
    }
} catch {
    Add-Check "BitLocker" "Info" "Unbekannt" "Status nicht ermittelbar (Adminrechte noetig)." "Als Administrator erneut pruefen."
}

# 2) Secure Boot
try {
    $sb = Confirm-SecureBootUEFI -ErrorAction Stop
    if ($sb) { Add-Check "Secure Boot" "OK" "Aktiv" "UEFI Secure Boot ist aktiviert." "" }
    else     { Add-Check "Secure Boot" "Mittel" "Aus" "Secure Boot ist deaktiviert." "Im UEFI/BIOS Secure Boot aktivieren." }
} catch {
    Add-Check "Secure Boot" "Info" "Unbekannt" "Nicht ermittelbar (Legacy-BIOS oder Adminrechte noetig)." "Als Administrator pruefen."
}

# 3) TPM
try {
    $tpm = Get-Tpm -ErrorAction Stop
    if ($tpm.TpmPresent -and $tpm.TpmReady) {
        Add-Check "TPM" "OK" "Bereit" "TPM vorhanden und einsatzbereit." ""
    } elseif ($tpm.TpmPresent) {
        Add-Check "TPM" "Mittel" "Nicht bereit" "TPM vorhanden, aber nicht bereit." "TPM im UEFI initialisieren/aktivieren."
    } else {
        Add-Check "TPM" "Hoch" "Fehlt" "Kein TPM gefunden." "TPM 2.0 im UEFI aktivieren (falls vorhanden)."
    }
} catch {
    Add-Check "TPM" "Info" "Unbekannt" "Nicht ermittelbar (Adminrechte noetig)." "Als Administrator pruefen."
}

# 4-7) Microsoft Defender
try {
    $mp = Get-MpComputerStatus -ErrorAction Stop
    if ($mp.RealTimeProtectionEnabled) { Add-Check "Defender Echtzeitschutz" "OK" "An" "Real-Time Protection aktiv." "" }
    else { Add-Check "Defender Echtzeitschutz" "Kritisch" "Aus" "Echtzeitschutz ist deaktiviert!" "Echtzeitschutz sofort aktivieren." }

    if ($mp.IsTamperProtected) { Add-Check "Defender Tamper Protection" "OK" "An" "Manipulationsschutz aktiv." "" }
    else { Add-Check "Defender Tamper Protection" "Mittel" "Aus" "Tamper Protection deaktiviert." "In Windows-Sicherheit Manipulationsschutz aktivieren." }

    $age = [int]$mp.AntivirusSignatureAge
    if ($age -le 3) { Add-Check "Defender Signaturen" "OK" "Aktuell" "Signaturen $age Tag(e) alt." "" }
    elseif ($age -le 7) { Add-Check "Defender Signaturen" "Niedrig" "Etwas alt" "Signaturen $age Tage alt." "Defender-Update ausfuehren." }
    else { Add-Check "Defender Signaturen" "Hoch" "Veraltet" "Signaturen $age Tage alt!" "Sofort Defender-Signaturen aktualisieren." }
} catch {
    Add-Check "Defender" "Info" "Unbekannt" "Defender-Status nicht ermittelbar." "Pruefen ob Defender aktiv / Drittanbieter-AV installiert ist."
}

try {
    $pref = Get-MpPreference -ErrorAction Stop
    if ($pref.MAPSReporting -ge 1) { Add-Check "Defender Cloud-Schutz" "OK" "An" "MAPS/Cloud-Schutz aktiv." "" }
    else { Add-Check "Defender Cloud-Schutz" "Niedrig" "Aus" "Cloud-basierter Schutz deaktiviert." "Cloud-Schutz (MAPS) aktivieren." }

    $asr = @($pref.AttackSurfaceReductionRules_Ids).Count
    if ($asr -ge 1) { Add-Check "ASR-Regeln" "OK" "$asr aktiv" "$asr Attack-Surface-Reduction-Regeln konfiguriert." "" }
    else { Add-Check "ASR-Regeln" "Mittel" "Keine" "Keine ASR-Regeln konfiguriert." "ASR-Regeln per Defender/Intune aktivieren (Block-Modus)." }
} catch { }

# 8) Firewall-Profile
try {
    foreach ($p in Get-NetFirewallProfile -ErrorAction Stop) {
        if ($p.Enabled) { Add-Check "Firewall: $($p.Name)" "OK" "An" "Firewall-Profil aktiv." "" }
        else { Add-Check "Firewall: $($p.Name)" "Hoch" "Aus" "Firewall-Profil $($p.Name) ist deaktiviert!" "Firewall fuer dieses Profil aktivieren." }
    }
} catch {
    Add-Check "Firewall" "Info" "Unbekannt" "Profile nicht ermittelbar." "Als Administrator pruefen."
}

# 9) UAC
try {
    $lua = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -ErrorAction Stop).EnableLUA
    if ($lua -eq 1) { Add-Check "UAC" "OK" "An" "User Account Control aktiviert." "" }
    else { Add-Check "UAC" "Hoch" "Aus" "UAC ist deaktiviert!" "EnableLUA = 1 setzen und neu starten." }
} catch { Add-Check "UAC" "Info" "Unbekannt" "UAC-Status nicht lesbar." "" }

# 10) SMBv1
try {
    $smb1 = (Get-SmbServerConfiguration -ErrorAction Stop).EnableSMB1Protocol
    if (-not $smb1) { Add-Check "SMBv1" "OK" "Aus" "SMBv1 ist deaktiviert." "" }
    else { Add-Check "SMBv1" "Kritisch" "An" "SMBv1 ist aktiviert (WannaCry/EternalBlue-Risiko)!" "SMBv1 deaktivieren: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol" }
} catch { Add-Check "SMBv1" "Info" "Unbekannt" "Nicht ermittelbar (Adminrechte noetig)." "Als Administrator pruefen." }

# 11) LLMNR
try {
    $llmnr = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name EnableMulticast -ErrorAction Stop).EnableMulticast
    if ($llmnr -eq 0) { Add-Check "LLMNR" "OK" "Aus" "LLMNR per Policy deaktiviert." "" }
    else { Add-Check "LLMNR" "Mittel" "An" "LLMNR aktiv (Responder/Spoofing-Risiko)." "LLMNR per GPO deaktivieren (EnableMulticast=0)." }
} catch {
    Add-Check "LLMNR" "Mittel" "An (Default)" "LLMNR nicht per Policy deaktiviert." "LLMNR per GPO deaktivieren (EnableMulticast=0)."
}

# 12) RDP
try {
    $deny = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -ErrorAction Stop).fDenyTSConnections
    if ($deny -eq 1) { Add-Check "RDP" "OK" "Aus" "Remote Desktop ist deaktiviert." "" }
    else { Add-Check "RDP" "Mittel" "An" "RDP ist aktiviert." "Falls nicht benoetigt: RDP deaktivieren. Sonst NLA + Firewall einschraenken." }
} catch { Add-Check "RDP" "Info" "Unbekannt" "RDP-Status nicht lesbar." "" }

# 13) Lokale Administratoren
try {
    $admins = Get-LocalGroupMember -Group "Administratoren" -ErrorAction SilentlyContinue
    if (-not $admins) { $admins = Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop }
    $names = ($admins | ForEach-Object { $_.Name }) -join ", "
    $cnt = @($admins).Count
    if ($cnt -le 2) { Add-Check "Lokale Admins" "OK" "$cnt Konten" "Mitglieder: $names" "" }
    else { Add-Check "Lokale Admins" "Mittel" "$cnt Konten" "Mitglieder: $names" "Anzahl der Admin-Konten reduzieren (Least Privilege)." }
} catch { Add-Check "Lokale Admins" "Info" "Unbekannt" "Nicht ermittelbar." "Als Administrator pruefen." }

# 14) Gast-Konto
try {
    $guest = Get-LocalUser -Name "Gast" -ErrorAction SilentlyContinue
    if (-not $guest) { $guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue }
    if ($guest) {
        if ($guest.Enabled) { Add-Check "Gast-Konto" "Mittel" "Aktiv" "Gast-Konto ist aktiviert." "Gast-Konto deaktivieren." }
        else { Add-Check "Gast-Konto" "OK" "Deaktiviert" "Gast-Konto ist deaktiviert." "" }
    }
} catch { }

# 15) PowerShell ScriptBlock Logging
try {
    $sbl = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name EnableScriptBlockLogging -ErrorAction Stop).EnableScriptBlockLogging
    if ($sbl -eq 1) { Add-Check "PS ScriptBlock-Logging" "OK" "An" "ScriptBlock-Logging aktiv (Forensik)." "" }
    else { Add-Check "PS ScriptBlock-Logging" "Niedrig" "Aus" "Kein PowerShell-ScriptBlock-Logging." "Per GPO aktivieren fuer bessere Nachvollziehbarkeit." }
} catch {
    Add-Check "PS ScriptBlock-Logging" "Niedrig" "Aus" "Kein PowerShell-ScriptBlock-Logging." "Per GPO aktivieren fuer bessere Nachvollziehbarkeit."
}

# 16) Pending Reboot (Windows Update)
try {
    $pr = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
    if ($pr) { Add-Check "Ausstehender Neustart" "Mittel" "Ja" "Ein Neustart fuer Updates steht aus." "System neu starten, um Updates abzuschliessen." }
    else { Add-Check "Ausstehender Neustart" "OK" "Nein" "Kein ausstehender Neustart." "" }
} catch { }

$results | ConvertTo-Json -Depth 3 -Compress
'''


class HardeningAuditModule(BaseModule):
    """Read-only Windows-Härtungs-Audit mit Ampel-Score."""

    def _build(self):
        self._info_bar(
            self,
            "Read-only Audit deines lokalen Windows-Systems gegen eine Härtungs-Baseline. "
            "Es werden KEINE Änderungen vorgenommen – nur geprüft und bewertet. "
            "Für vollständige Ergebnisse als Administrator starten.")

        # ── Steuerleiste ────────────────────────────────────────────────────────
        bar = tk.Frame(self, bg=DARK["bg"])
        bar.pack(fill="x", padx=10, pady=(6, 2))

        self._run_btn = ttk.Button(bar, text="Audit starten",
                                    style="Accent.TButton",
                                    command=self._start_audit)
        self._run_btn.pack(side="left")

        self._copy_btn = ttk.Button(bar, text="Bericht kopieren",
                                     command=self._copy_report, state="disabled")
        self._copy_btn.pack(side="left", padx=(6, 0))

        self._report_btn = ttk.Button(bar, text="Befunde an Reporting",
                                       command=self._send_to_report, state="disabled")
        self._report_btn.pack(side="left", padx=(6, 0))

        # Score-Anzeige
        self._score_var = tk.StringVar(value="Noch kein Audit gelaufen")
        self._score_lbl = tk.Label(bar, textvariable=self._score_var,
                                    bg=DARK["bg"], fg=DARK["border"],
                                    font=("Segoe UI", 10, "bold"))
        self._score_lbl.pack(side="right", padx=8)

        # ── Ergebnis-Treeview ───────────────────────────────────────────────────
        sec = self._section_expand(self, "Ergebnisse")
        cols = ("check", "status", "detail", "rec")
        self._tree = ttk.Treeview(sec, columns=cols, show="headings",
                                  selectmode="browse")
        for c, t, w in [("check", "Prüfung", 190), ("status", "Status", 110),
                        ("detail", "Detail", 420), ("rec", "Empfehlung", 420)]:
            self._tree.heading(c, text=t)
            self._tree.column(c, width=w, anchor="w")
        sb = ttk.Scrollbar(sec, command=self._tree.yview)
        self._tree.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self._tree.pack(fill="both", expand=True, padx=6, pady=6)

        # Severity-Farb-Tags
        for sev, col in SEVERITY_COLORS.items():
            self._tree.tag_configure(sev, foreground=col)
        self._tree.tag_configure("OK", foreground=DARK["green"])

        self._findings: list[dict] = []

    # ── Audit-Lauf ──────────────────────────────────────────────────────────────

    def _start_audit(self):
        self._run_btn.configure(state="disabled")
        self._copy_btn.configure(state="disabled")
        self._score_var.set("Audit läuft …")
        self._score_lbl.configure(fg=DARK["accent"])
        for iid in self._tree.get_children():
            self._tree.delete(iid)
        if self._activity_cb:
            self._activity_cb("Hardening-Audit gestartet")
        threading.Thread(target=self._run_audit, daemon=True).start()

    def _run_audit(self):
        data, err = self._ps_json(_AUDIT_PS)
        if not data and err:
            self.after(0, self._audit_failed, err)
            return
        self.after(0, self._render_results, data)

    def _audit_failed(self, msg: str):
        self._run_btn.configure(state="normal")
        self._score_var.set("Audit fehlgeschlagen")
        self._score_lbl.configure(fg=DARK["red"])
        self._tree.insert("", "end",
                          values=("Fehler", "—", msg, "PowerShell verfügbar? Als Admin starten?"),
                          tags=("Kritisch",))

    def _render_results(self, data: list[dict]):
        self._findings = data
        order = {"Kritisch": 0, "Hoch": 1, "Mittel": 2, "Niedrig": 3, "Info": 4, "OK": 5}
        data_sorted = sorted(data, key=lambda d: order.get(d.get("severity", "Info"), 9))

        ok = problems = 0
        weight = {"Kritisch": 5, "Hoch": 3, "Mittel": 2, "Niedrig": 1}
        risk = 0
        for d in data_sorted:
            sev = d.get("severity", "Info")
            self._tree.insert("", "end", tags=(sev,), values=(
                d.get("name", ""), f"{d.get('status','')}",
                d.get("detail", ""), d.get("recommendation", "")))
            if sev == "OK":
                ok += 1
            elif sev in weight:
                problems += 1
                risk += weight[sev]

        total = ok + problems
        self._run_btn.configure(state="normal")
        if total:
            self._copy_btn.configure(state="normal")
        if problems:
            self._report_btn.configure(state="normal")
        # Score: bestandene Checks und Risiko-Gewicht
        if problems == 0 and total:
            self._score_var.set(f"✓ {ok}/{total} bestanden — keine Befunde")
            self._score_lbl.configure(fg=DARK["green"])
        else:
            clr = DARK["red"] if risk >= 8 else (DARK["orange"] if risk >= 4 else DARK["yellow"])
            self._score_var.set(f"{ok}/{total} bestanden · {problems} Befund(e) · Risiko {risk}")
            self._score_lbl.configure(fg=clr)
        if self._activity_cb:
            self._activity_cb(f"Hardening-Audit fertig: {problems} Befund(e), Risiko {risk}")

    # ── Bericht ───────────────────────────────────────────────────────────────

    def _copy_report(self):
        if not self._findings:
            return
        lines = [f"# Hardening-Audit  {datetime.now().strftime('%Y-%m-%d %H:%M')}", ""]
        for d in self._findings:
            lines.append(f"[{d.get('severity','')}] {d.get('name','')}: {d.get('status','')}")
            if d.get("detail"):
                lines.append(f"    {d['detail']}")
            if d.get("recommendation"):
                lines.append(f"    → {d['recommendation']}")
        text = "\n".join(lines)
        self.clipboard_clear()
        self.clipboard_append(text)
        if self._activity_cb:
            self._activity_cb("Hardening-Bericht in Zwischenablage kopiert")

    def _send_to_report(self):
        sent = 0
        for d in self._findings:
            sev = d.get("severity", "Info")
            if sev == "OK":
                continue
            desc = d.get("detail", "")
            rec = d.get("recommendation", "")
            if rec:
                desc = f"{desc}\n\nEmpfehlung: {rec}"
            if self._report_finding(f"[Hardening] {d.get('name','')}", sev, desc):
                sent += 1
        if self._activity_cb:
            self._activity_cb(
                f"{sent} Hardening-Befund(e) an Reporting übergeben" if sent
                else "Reporting nicht verbunden / keine Befunde")
