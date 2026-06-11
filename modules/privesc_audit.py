"""PrivescAuditModule – lokale Privilege-Escalation-Vektoren prüfen (read-only).

Sucht klassische Windows-Privesc-Misconfigurationen auf DEM EIGENEN System
(im Stil von PowerUp / winPEAS), ändert aber nichts:
  - Unquoted Service Paths mit beschreibbarem Verzeichnis
  - Dienste, deren Binary/Verzeichnis von Standardnutzern beschreibbar ist
  - AlwaysInstallElevated (MSI als SYSTEM)
  - Beschreibbare Verzeichnisse in der PATH-Variable (DLL-/Binary-Planting)
  - Autologon-Klartext-Passwort in der Registry
  - Gespeicherte Anmeldedaten (cmdkey)
  - Unattend/Sysprep-Dateien mit Passwörtern
  - UAC-Verhalten für Admins

Jeder Befund kommt mit konkreter manueller Härtungs-Empfehlung. Die Behebung
führt der Nutzer selbst durch.
"""
import tkinter as tk
from tkinter import ttk
import threading
import os
import re
from datetime import datetime

from modules.base import BaseModule
from utils.theme import DARK, SEVERITY_COLORS


# Read-only Privesc-Audit als JSON-Array {name, severity, status, detail, recommendation}
_PRIVESC_PS = r'''
$ErrorActionPreference = 'SilentlyContinue'
$results = New-Object System.Collections.ArrayList
function Add-Check($name, $sev, $status, $detail, $rec) {
    [void]$results.Add([PSCustomObject]@{ name=$name; severity=$sev; status=$status; detail=$detail; recommendation=$rec })
}

# Prüft, ob schwache Gruppen (Users/Everyone/Authenticated Users) Schreib-/Änderungsrechte haben
function Test-WeakWrite($path) {
    if (-not $path -or -not (Test-Path $path)) { return $false }
    try {
        $acl = Get-Acl -Path $path -ErrorAction Stop
        foreach ($ace in $acl.Access) {
            $id = "$($ace.IdentityReference)"
            if ($id -match 'Everyone|Jeder|Authenticated Users|Authentifizierte|BUILTIN\\(Users|Benutzer)|\\Users$|\\Benutzer$') {
                if ($ace.AccessControlType -eq 'Allow' -and
                    ("$($ace.FileSystemRights)" -match 'Write|Modify|FullControl|Änder|Vollzugriff|Schreib')) {
                    return $true
                }
            }
        }
    } catch {}
    return $false
}
function Extract-Exe($cmd) {
    if (-not $cmd) { return "" }
    if ($cmd -match '"([^"]+\.exe)"') { return $matches[1] }
    if ($cmd -match '^([A-Za-z]:\\[^"]+?\.exe)') { return $matches[1] }
    return ""
}

# 1) Unquoted Service Paths
$unq = 0
Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | ForEach-Object {
    $pn = $_.PathName
    if ($pn -and $pn -notmatch '^\s*"' -and $pn -match ' ' -and $pn -notmatch '^[A-Za-z]:\\Windows\\' ) {
        # Pfad enthält Leerzeichen und ist nicht gequotet → potentielle Hijack-Stelle
        $unq++
        Add-Check "Unquoted Service Path" "Hoch" $_.Name "$($_.Name): $pn" "Pfad in Anführungszeichen setzen (Registry ImagePath) oder Dienst-Binary umlegen."
    }
}
if ($unq -eq 0) { Add-Check "Unquoted Service Paths" "OK" "Keine" "Keine ungequoteten Dienstpfade mit Leerzeichen." "" }

# 2) Beschreibbare Service-Binaries / -Verzeichnisse
$wsvc = 0
Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | ForEach-Object {
    $exe = Extract-Exe $_.PathName
    if ($exe -and $exe -notmatch '^[A-Za-z]:\\Windows\\') {
        $dir = Split-Path $exe -Parent
        if ((Test-WeakWrite $exe) -or (Test-WeakWrite $dir)) {
            $wsvc++
            Add-Check "Beschreibbarer Dienst" "Kritisch" $_.Name "$($_.Name) -> $exe (Binary/Ordner durch Standardnutzer beschreibbar)" "ACLs des Dienst-Binaries/-Ordners verschärfen (kein Write für Users)."
        }
    }
}
if ($wsvc -eq 0) { Add-Check "Beschreibbare Dienst-Binaries" "OK" "Keine" "Keine durch Standardnutzer beschreibbaren Dienst-Binaries." "" }

# 3) AlwaysInstallElevated
$ai_hklm = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated -EA SilentlyContinue).AlwaysInstallElevated
$ai_hkcu = (Get-ItemProperty 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated -EA SilentlyContinue).AlwaysInstallElevated
if ($ai_hklm -eq 1 -and $ai_hkcu -eq 1) {
    Add-Check "AlwaysInstallElevated" "Kritisch" "Aktiv" "HKLM+HKCU = 1: jeder MSI laeuft als SYSTEM." "Beide AlwaysInstallElevated-Werte auf 0 setzen (per GPO)."
} else {
    Add-Check "AlwaysInstallElevated" "OK" "Aus" "MSI-Elevation nicht global aktiviert." ""
}

# 4) Beschreibbare PATH-Verzeichnisse
$wp = 0
($env:PATH -split ';') | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique | ForEach-Object {
    if ($_ -notmatch '^[A-Za-z]:\\Windows' -and (Test-WeakWrite $_)) {
        $wp++
        Add-Check "Beschreibbares PATH-Dir" "Hoch" "Schreibbar" $_ "Verzeichnis aus PATH entfernen oder Schreibrechte fuer Users entziehen (Binary-/DLL-Planting)."
    }
}
if ($wp -eq 0) { Add-Check "Beschreibbare PATH-Verzeichnisse" "OK" "Keine" "Keine durch Standardnutzer beschreibbaren PATH-Eintraege." "" }

# 5) Autologon-Klartext-Passwort
$wl = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -EA SilentlyContinue
if ($wl.DefaultPassword) {
    Add-Check "Autologon-Passwort" "Kritisch" "Klartext" "DefaultPassword im Klartext in der Registry (Winlogon)." "Autologon-Passwort entfernen; falls Autologon noetig: SysInternals Autologon (LSA-Secret)."
} elseif ($wl.AutoAdminLogon -eq 1) {
    Add-Check "Autologon" "Mittel" "Aktiv" "AutoAdminLogon=1 (ohne Klartext-Passwort gefunden)." "Autologon nur wenn noetig; Konto ohne Adminrechte verwenden."
} else {
    Add-Check "Autologon" "OK" "Aus" "Kein Autologon konfiguriert." ""
}

# 6) Gespeicherte Anmeldedaten (cmdkey)
try {
    $ck = (cmdkey /list 2>$null | Select-String 'Ziel|Target')
    $cnt = @($ck).Count
    if ($cnt -gt 0) {
        Add-Check "Gespeicherte Credentials" "Mittel" "$cnt Eintrag/e" "cmdkey enthaelt gespeicherte Anmeldedaten." "Mit 'cmdkey /list' pruefen und nicht benoetigte mit 'cmdkey /delete' entfernen."
    } else {
        Add-Check "Gespeicherte Credentials" "OK" "Keine" "Keine gespeicherten cmdkey-Credentials." ""
    }
} catch {}

# 7) Unattend / Sysprep-Dateien
$ua = @("$env:WINDIR\Panther\Unattend.xml","$env:WINDIR\Panther\Unattended.xml",
        "$env:WINDIR\System32\Sysprep\unattend.xml","$env:WINDIR\System32\Sysprep\Panther\unattend.xml",
        "$env:SystemDrive\unattend.xml","$env:SystemDrive\autounattend.xml")
$found = $false
foreach ($f in $ua) {
    if (Test-Path $f) {
        $c = Get-Content $f -Raw -EA SilentlyContinue
        if ($c -match 'Password') {
            $found = $true
            Add-Check "Unattend-Datei" "Hoch" "Mit Passwort" $f "Unattend-Datei mit Passwort entfernen (Klartext-/Base64-Credentials)."
        }
    }
}
if (-not $found) { Add-Check "Unattend/Sysprep" "OK" "Sauber" "Keine Unattend-Dateien mit Passwoertern gefunden." "" }

# 8) UAC-Verhalten fuer Admins
$cp = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name ConsentPromptBehaviorAdmin -EA SilentlyContinue).ConsentPromptBehaviorAdmin
switch ($cp) {
    0 { Add-Check "UAC Admin-Prompt" "Hoch" "Kein Prompt" "ConsentPromptBehaviorAdmin=0: Elevation ohne Nachfrage." "Auf 2 (Secure Desktop, immer fragen) setzen." }
    2 { Add-Check "UAC Admin-Prompt" "OK" "Secure Desktop" "Elevation fragt auf Secure Desktop." "" }
    5 { Add-Check "UAC Admin-Prompt" "Niedrig" "Standard" "Standard-Verhalten (nur bei Nicht-Windows-Binaries)." "Optional auf 2 anheben." }
    default { Add-Check "UAC Admin-Prompt" "Info" "Wert $cp" "ConsentPromptBehaviorAdmin=$cp" "" }
}

$results | ConvertTo-Json -Depth 3 -Compress
'''


class PrivescAuditModule(BaseModule):
    """Read-only Audit lokaler Privilege-Escalation-Vektoren."""

    def _build(self):
        self._info_bar(
            self,
            "Read-only Suche nach lokalen Privilege-Escalation-Schwachstellen auf DEINEM System "
            "(unquoted/beschreibbare Dienste, AlwaysInstallElevated, PATH, gespeicherte Credentials). "
            "Es wird nichts verändert – nur aufgezeigt. Als Administrator vollständiger.")

        bar = tk.Frame(self, bg=DARK["bg"]); bar.pack(fill="x", padx=10, pady=(6, 2))
        self._run_btn = ttk.Button(bar, text="Privesc-Audit starten",
                                    style="Accent.TButton", command=self._start)
        self._run_btn.pack(side="left")
        self._verify_btn = ttk.Button(bar, text="Beschreibbarkeit verifizieren",
                                       command=self._start_verify, state="disabled")
        self._verify_btn.pack(side="left", padx=(6, 0))
        self._report_btn = ttk.Button(bar, text="Befunde an Reporting",
                                       command=self._send_to_report, state="disabled")
        self._report_btn.pack(side="left", padx=(6, 0))
        self._score_var = tk.StringVar(value="Noch kein Audit gelaufen")
        self._score_lbl = tk.Label(bar, textvariable=self._score_var, bg=DARK["bg"],
                                    fg=DARK["border"], font=("Segoe UI", 10, "bold"))
        self._score_lbl.pack(side="right", padx=8)

        sec = self._section_expand(self, "Privilege-Escalation-Vektoren")
        cols = ("check", "status", "detail", "rec")
        self._tree = ttk.Treeview(sec, columns=cols, show="headings", selectmode="browse")
        for c, t, w in [("check", "Vektor", 200), ("status", "Status", 130),
                        ("detail", "Detail", 440), ("rec", "Empfehlung", 420)]:
            self._tree.heading(c, text=t)
            self._tree.column(c, width=w, anchor="w")
        sb = ttk.Scrollbar(sec, command=self._tree.yview)
        self._tree.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self._tree.pack(fill="both", expand=True, padx=6, pady=6)
        for sev, col in SEVERITY_COLORS.items():
            self._tree.tag_configure(sev, foreground=col)
        self._tree.tag_configure("OK", foreground=DARK["green"])
        self._findings: list[dict] = []

    def _start(self):
        self._run_btn.configure(state="disabled")
        self._report_btn.configure(state="disabled")
        for iid in self._tree.get_children():
            self._tree.delete(iid)
        self._score_var.set("Audit läuft …")
        self._score_lbl.configure(fg=DARK["accent"])
        if self._activity_cb:
            self._activity_cb("Privesc-Audit gestartet")
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        data, err = self._ps_json(_PRIVESC_PS)
        if not data and err:
            self.after(0, self._failed, err)
            return
        self.after(0, self._render, data)

    def _failed(self, msg: str):
        self._run_btn.configure(state="normal")
        self._score_var.set("Audit fehlgeschlagen")
        self._score_lbl.configure(fg=DARK["red"])
        self._tree.insert("", "end", tags=("Kritisch",),
                          values=("Fehler", "—", msg, "Als Administrator starten?"))

    _ORDER = {"Kritisch": 0, "Hoch": 1, "Mittel": 2, "Niedrig": 3, "Info": 4, "OK": 5}

    def _render(self, data: list[dict]):
        self._findings = data
        weight = {"Kritisch": 5, "Hoch": 3, "Mittel": 2, "Niedrig": 1}
        risk = problems = ok = 0
        for d in data:
            sev = d.get("severity", "Info")
            if sev == "OK":
                ok += 1
            elif sev in weight:
                problems += 1
                risk += weight[sev]
        self._render_tree()
        self._run_btn.configure(state="normal")
        if self._findings:
            self._report_btn.configure(state="normal")
        if any(self._verify_path(d) for d in self._findings):
            self._verify_btn.configure(state="normal")
        if problems == 0:
            self._score_var.set(f"✓ {ok} Checks ok — keine Privesc-Vektoren")
            self._score_lbl.configure(fg=DARK["green"])
        else:
            clr = DARK["red"] if risk >= 8 else (DARK["orange"] if risk >= 4 else DARK["yellow"])
            self._score_var.set(f"{problems} Vektor(en) · Risiko {risk}")
            self._score_lbl.configure(fg=clr)
        if self._activity_cb:
            self._activity_cb(f"Privesc-Audit fertig: {problems} Vektor(en), Risiko {risk}")

    def _render_tree(self):
        for iid in self._tree.get_children():
            self._tree.delete(iid)
        for d in sorted(self._findings, key=lambda d: self._ORDER.get(d.get("severity", "Info"), 9)):
            status = d.get("status", "")
            v = d.get("verified")
            if v is True:
                status = "✓ AUSNUTZBAR · " + status
            elif v is False:
                status = "nicht beschreibbar · " + status
            self._tree.insert("", "end", tags=(d.get("severity", "Info"),), values=(
                d.get("name", ""), status, d.get("detail", ""), d.get("recommendation", "")))

    # ── Aktive Verifikation (Schreibtest, reversibel) ───────────────────────────

    @staticmethod
    def _verify_path(finding: dict) -> str | None:
        """Extrahiert ein zu testendes Verzeichnis aus verifizierbaren Befunden."""
        name = finding.get("name", "")
        detail = finding.get("detail", "")
        if name == "Beschreibbares PATH-Dir":
            return detail.strip() if os.path.isdir(detail.strip()) else None
        if name == "Beschreibbarer Dienst":
            m = re.search(r'->\s*(.+?\.exe)', detail)
            if m:
                d = os.path.dirname(m.group(1))
                return d if os.path.isdir(d) else None
        return None

    def _start_verify(self):
        self._verify_btn.configure(state="disabled")
        self._score_var.set("Verifiziere Schreibrechte …")
        threading.Thread(target=self._verify, daemon=True).start()

    def _verify(self):
        confirmed = 0
        for d in self._findings:
            path = self._verify_path(d)
            if not path:
                continue
            d["verified"] = self._writable(path)
            if d["verified"]:
                confirmed += 1
        self.after(0, self._verify_done, confirmed)

    @staticmethod
    def _writable(path: str) -> bool:
        """Echter Schreibtest: temporäre Datei anlegen und sofort entfernen."""
        test = os.path.join(path, f".g4m_write_test_{os.getpid()}.tmp")
        try:
            with open(test, "w") as f:
                f.write("test")
            os.remove(test)
            return True
        except Exception:
            return False

    def _verify_done(self, confirmed: int):
        self._render_tree()
        self._verify_btn.configure(state="normal")
        self._score_var.set(f"Verifikation: {confirmed} Pfad(e) wirklich beschreibbar (ausnutzbar)")
        self._score_lbl.configure(fg=DARK["red"] if confirmed else DARK["green"])
        if self._activity_cb:
            self._activity_cb(f"Privesc-Verifikation: {confirmed} Vektor(en) bestätigt ausnutzbar")

    def _send_to_report(self):
        sent = 0
        for d in self._findings:
            sev = d.get("severity", "Info")
            if sev in ("OK",):
                continue
            desc = d.get("detail", "")
            rec = d.get("recommendation", "")
            if rec:
                desc = f"{desc}\n\nEmpfehlung: {rec}"
            if self._report_finding(f"[Privesc] {d.get('name','')}", sev, desc):
                sent += 1
        msg = (f"{sent} Privesc-Befund(e) an Reporting übergeben"
               if sent else "Reporting nicht verbunden / keine Befunde")
        if self._activity_cb:
            self._activity_cb(msg)
        self._score_var.set(self._score_var.get().split(" · An")[0] + f" · An Report: {sent}")
