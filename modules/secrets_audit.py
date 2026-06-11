"""SecretsAuditModule – Klartext-Geheimnisse auf dem eigenen System finden (read-only).

Sucht typische Orte, an denen Zugangsdaten/Secrets im Klartext oder leicht
wiederherstellbar liegen – damit du sie absichern/entfernen kannst:
  - WLAN-Profile mit Klartext-Schlüssel (netsh ... key=clear)
  - Windows Credential Manager (cmdkey)
  - PuTTY-/WinSCP-Sessions in der Registry (Hosts, gespeicherte Passwörter)
  - PowerShell-Konsolen-History mit Passwort-/Token-Mustern
  - .git-credentials (Klartext-Repo-Zugänge)
  - SSH-Privatschlüssel ohne Passphrase-Hinweis
  - gespeicherte .rdp-Dateien

Read-only: es werden keine Secrets verändert oder gelöscht. Befunde können an
das Reporting übergeben werden.
"""
import tkinter as tk
from tkinter import ttk
import threading

from modules.base import BaseModule
from utils.theme import DARK, SEVERITY_COLORS


# Secret-Hunting als JSON-Liste {category, severity, location, detail, recommendation}
_SECRETS_PS = r'''
$ErrorActionPreference = 'SilentlyContinue'
$r = New-Object System.Collections.ArrayList
function Add-Sec($cat,$sev,$loc,$detail,$rec){
    [void]$r.Add([PSCustomObject]@{ category=$cat; severity=$sev; location=$loc; detail=$detail; recommendation=$rec })
}

# 1) WLAN-Profile mit Klartext-Schluessel
try {
    $profOut = netsh wlan show profiles 2>$null
    $names = $profOut | Select-String -Pattern ':\s*(.+)$' | ForEach-Object {
        $t = ($_ -split ':',2)[1].Trim(); if ($t -and $t -notmatch '^\s*$') { $t }
    } | Where-Object { $_ -and $_ -notmatch 'BSSID|GUID' } | Select-Object -Unique
    $wlanFound = 0
    foreach ($n in $names) {
        $det = netsh wlan show profile name="$n" key=clear 2>$null
        $keyLine = $det | Select-String -Pattern 'Key Content|Schl.sselinhalt' | Select-Object -First 1
        if ($keyLine) {
            $key = ($keyLine -split ':',2)[1].Trim()
            if ($key) { $wlanFound++; Add-Sec 'WLAN-Schluessel' 'Mittel' "WLAN: $n" "Klartext-Schluessel abrufbar (Laenge $($key.Length))." 'Normal fuer gespeicherte WLANs; ungenutzte Profile entfernen (netsh wlan delete profile).' }
        }
    }
    if ($wlanFound -eq 0) { Add-Sec 'WLAN-Schluessel' 'OK' 'WLAN' 'Keine WLAN-Klartext-Schluessel abrufbar.' '' }
} catch {}

# 2) Credential Manager
try {
    $ck = @(cmdkey /list 2>$null | Select-String 'Target|Ziel')
    if ($ck.Count -gt 0) { Add-Sec 'Credential Manager' 'Mittel' 'cmdkey' "$($ck.Count) gespeicherte Anmeldedaten." 'Nicht benoetigte mit cmdkey /delete entfernen.' }
    else { Add-Sec 'Credential Manager' 'OK' 'cmdkey' 'Keine gespeicherten Credentials.' '' }
} catch {}

# 3) PuTTY-Sessions
try {
    $putty = Get-ChildItem 'HKCU:\Software\SimonTatham\PuTTY\Sessions' -ErrorAction SilentlyContinue
    if ($putty) {
        foreach ($s in $putty) {
            $p = Get-ItemProperty $s.PSPath
            $hn = $p.HostName; $un = $p.UserName
            $proxyPw = $p.ProxyPassword
            $sev = if ($proxyPw) { 'Hoch' } else { 'Niedrig' }
            $extra = if ($proxyPw) { ' + gespeichertes Proxy-Passwort (Klartext)!' } else { '' }
            Add-Sec 'PuTTY-Session' $sev "$($s.PSChildName)" "Host: $hn, User: $un$extra" 'Gespeicherte Proxy-Passwoerter entfernen; Sessions pruefen.'
        }
    } else { Add-Sec 'PuTTY-Session' 'OK' 'PuTTY' 'Keine PuTTY-Sessions gefunden.' '' }
} catch {}

# 4) WinSCP-Sessions (gespeicherte Passwoerter)
try {
    $winscp = Get-ChildItem 'HKCU:\Software\Martin Prikryl\WinSCP 2\Sessions' -ErrorAction SilentlyContinue
    $wfound = 0
    if ($winscp) {
        foreach ($s in $winscp) {
            $p = Get-ItemProperty $s.PSPath
            if ($p.Password) { $wfound++; Add-Sec 'WinSCP-Session' 'Hoch' "$($s.PSChildName)" "Host: $($p.HostName), User: $($p.UserName) – gespeichertes Passwort (umkehrbar verschluesselt)." 'WinSCP-Master-Passwort aktivieren oder gespeicherte Passwoerter entfernen.' }
        }
    }
    if ($wfound -eq 0) { Add-Sec 'WinSCP-Session' 'OK' 'WinSCP' 'Keine gespeicherten WinSCP-Passwoerter.' '' }
} catch {}

# 5) PowerShell-History nach Secrets
try {
    $hist = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    if (Test-Path $hist) {
        $hits = Select-String -Path $hist -Pattern 'password|passwort|secret|token|apikey|api_key|-p\s|ConvertTo-SecureString|AccessKey' -AllMatches
        if ($hits) { Add-Sec 'PowerShell-History' 'Hoch' $hist "$(@($hits).Count) Zeile(n) mit moeglichen Secrets." 'History bereinigen; keine Klartext-Secrets in der Shell eingeben.' }
        else { Add-Sec 'PowerShell-History' 'OK' 'PSReadLine' 'Keine verdaechtigen Muster in der History.' '' }
    }
} catch {}

# 6) .git-credentials
try {
    $gc = "$env:USERPROFILE\.git-credentials"
    if (Test-Path $gc) {
        $lines = @(Get-Content $gc)
        Add-Sec 'git-credentials' 'Hoch' $gc "$($lines.Count) Klartext-Repo-Zugang/Zugaenge." 'Auf Git Credential Manager umstellen; Datei entfernen.'
    } else { Add-Sec 'git-credentials' 'OK' '.git-credentials' 'Keine .git-credentials-Datei.' '' }
} catch {}

# 7) SSH-Privatschluessel
try {
    $ssh = "$env:USERPROFILE\.ssh"
    if (Test-Path $ssh) {
        $keys = Get-ChildItem $ssh -File | Where-Object { $_.Name -match '^id_' -and $_.Name -notmatch '\.pub$' }
        foreach ($k in $keys) {
            Add-Sec 'SSH-Key' 'Niedrig' $k.FullName 'Privater SSH-Schluessel vorhanden.' 'Sicherstellen, dass der Schluessel mit einer Passphrase geschuetzt ist.'
        }
        if (-not $keys) { Add-Sec 'SSH-Key' 'OK' '.ssh' 'Keine privaten SSH-Schluessel.' '' }
    }
} catch {}

# 8) Gespeicherte .rdp-Dateien
try {
    $rdp = Get-ChildItem "$env:USERPROFILE" -Recurse -Filter *.rdp -Depth 3 -ErrorAction SilentlyContinue
    $rfound = 0
    foreach ($f in $rdp) {
        $c = Get-Content $f.FullName -Raw -ErrorAction SilentlyContinue
        if ($c -match 'password 51:b:') { $rfound++; Add-Sec 'RDP-Datei' 'Mittel' $f.FullName 'RDP-Datei mit gespeichertem (verschluesseltem) Passwort.' 'Gespeicherte RDP-Passwoerter vermeiden.' }
    }
    if ($rfound -eq 0) { Add-Sec 'RDP-Datei' 'OK' '.rdp' 'Keine .rdp-Dateien mit gespeichertem Passwort.' '' }
} catch {}

$r | ConvertTo-Json -Depth 3 -Compress
'''


class SecretsAuditModule(BaseModule):
    """Read-only Suche nach Klartext-Secrets auf dem eigenen System."""

    def _build(self):
        self._info_bar(
            self,
            "Read-only Suche nach Klartext-Geheimnissen auf deinem System (WLAN-Keys, Credential Manager, "
            "PuTTY/WinSCP, PowerShell-History, .git-credentials, SSH-Keys, .rdp). Es wird nichts verändert.")

        bar = tk.Frame(self, bg=DARK["bg"]); bar.pack(fill="x", padx=10, pady=(6, 2))
        self._run_btn = ttk.Button(bar, text="Secret-Hunting starten",
                                    style="Accent.TButton", command=self._start)
        self._run_btn.pack(side="left")
        self._report_btn = ttk.Button(bar, text="Befunde an Reporting",
                                       command=self._send_report, state="disabled")
        self._report_btn.pack(side="left", padx=(6, 0))
        self._only_hits = tk.BooleanVar(value=False)
        ttk.Checkbutton(bar, text="Nur Fundstellen", variable=self._only_hits,
                        command=self._refilter).pack(side="left", padx=(10, 0))
        self._sum = tk.StringVar(value="Noch kein Lauf")
        self._sum_lbl = tk.Label(bar, textvariable=self._sum, bg=DARK["bg"],
                                 fg=DARK["border"], font=("Segoe UI", 10, "bold"))
        self._sum_lbl.pack(side="right", padx=8)

        sec = self._section_expand(self, "Gefundene Secrets / Speicherorte")
        cols = ("cat", "sev", "loc", "detail", "rec")
        self._tree = ttk.Treeview(sec, columns=cols, show="headings", selectmode="browse")
        for c, t, w in [("cat", "Kategorie", 150), ("sev", "Schwere", 90),
                        ("loc", "Ort", 280), ("detail", "Detail", 380),
                        ("rec", "Empfehlung", 360)]:
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
        self._sum.set("Suche läuft …")
        self._sum_lbl.configure(fg=DARK["accent"])
        if self._activity_cb:
            self._activity_cb("Secret-Hunting gestartet")
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        data, err = self._ps_json(_SECRETS_PS, timeout=150)
        if not data and err:
            self.after(0, lambda: (self._run_btn.configure(state="normal"),
                                   self._sum.set(f"Fehler: {err}")))
            return
        self.after(0, self._store_render, data)

    def _store_render(self, data: list[dict]):
        self._rows = data
        self._run_btn.configure(state="normal")
        self._refilter()

    def _refilter(self):
        for iid in self._tree.get_children():
            self._tree.delete(iid)
        order = {"Kritisch": 0, "Hoch": 1, "Mittel": 2, "Niedrig": 3, "Info": 4, "OK": 5}
        hits = 0
        only = self._only_hits.get()
        for d in sorted(self._rows, key=lambda d: order.get(d.get("severity", "Info"), 9)):
            sev = d.get("severity", "Info")
            is_hit = sev != "OK"
            if is_hit:
                hits += 1
            if only and not is_hit:
                continue
            self._tree.insert("", "end", tags=(sev,), values=(
                d.get("category", ""), sev, d.get("location", ""),
                d.get("detail", ""), d.get("recommendation", "")))
        if hits:
            self._report_btn.configure(state="normal")
            self._sum.set(f"{hits} Fundstelle(n)")
            self._sum_lbl.configure(fg=DARK["orange"] if hits >= 3 else DARK["yellow"])
        else:
            self._sum.set("✓ Keine Klartext-Secrets gefunden")
            self._sum_lbl.configure(fg=DARK["green"])
        if self._activity_cb:
            self._activity_cb(f"Secret-Hunting: {hits} Fundstelle(n)")

    def _send_report(self):
        sent = 0
        for d in self._rows:
            sev = d.get("severity", "Info")
            if sev == "OK":
                continue
            desc = d.get("detail", "")
            rec = d.get("recommendation", "")
            if rec:
                desc = f"{desc}\n\nEmpfehlung: {rec}"
            if self._report_finding(f"[Secret] {d.get('category','')}", sev, desc,
                                    d.get("location", "")):
                sent += 1
        if self._activity_cb:
            self._activity_cb(f"{sent} Secret-Befund(e) an Reporting übergeben" if sent
                              else "Reporting nicht verbunden / keine Funde")
