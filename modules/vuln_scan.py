"""VulnScanModule – Patch-Status & Exposure gegen bekannte Windows-Lücken (read-only).

Prüft das EIGENE System auf:
  1) Patch-Status: installierte Hotfixes, OS-Build/UBR, Alter des letzten Updates.
  2) Bekannte schwere Windows-Schwachstellen (ehemalige „Zero-Days"): über
     read-only Indikatoren wird festgestellt, ob die jeweilige Lücke gemildert/
     gepatcht ist – ohne sie auszunutzen (EternalBlue, Follina, PrintNightmare,
     HiveNightmare/SeriousSAM, SMBGhost, BlueKeep, PetitPotam/WebDAV …).
  3) Aktuelle kritische Microsoft/Windows-CVEs live aus der NIST-NVD-Datenbank,
     als Anhaltspunkt, ob das eigene Patch-Level neue Funde abdeckt.

Wichtig: echte, noch unbekannte Zero-Days kann kein Tool erkennen. Hier geht es
um bekannte CVEs und Patch-Aktualität. Es werden keine Exploits ausgeführt und
nichts am System verändert.
"""
import tkinter as tk
from tkinter import ttk
import threading
import json
import urllib.request
import urllib.parse
from datetime import datetime, timedelta

from modules.base import BaseModule
from utils.theme import DARK, SEVERITY_COLORS


# ── Patch-Status (Summary + Hotfix-Liste) ──────────────────────────────────────
_PATCH_PS = r'''
$ErrorActionPreference = 'SilentlyContinue'
$out = New-Object System.Collections.ArrayList
$cv  = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$os  = Get-CimInstance Win32_OperatingSystem
$hot = @(Get-HotFix | Sort-Object InstalledOn -Descending)
$last = if ($hot.Count -gt 0) { $hot[0].InstalledOn } else { $null }
$lastStr = if ($last) { $last.ToString('yyyy-MM-dd') } else { 'unbekannt' }
[void]$out.Add([PSCustomObject]@{
    type='summary'
    caption=$os.Caption
    build="$($cv.CurrentBuildNumber).$($cv.UBR)"
    display=$cv.DisplayVersion
    last=$lastStr
    count=$hot.Count
})
foreach ($h in $hot) {
    $inst = if ($h.InstalledOn) { $h.InstalledOn.ToString('yyyy-MM-dd') } else { '?' }
    [void]$out.Add([PSCustomObject]@{
        type='hotfix'; id=$h.HotFixID; desc=$h.Description; installed=$inst })
}
$out | ConvertTo-Json -Depth 3 -Compress
'''

# ── Bekannte-CVE-Indikator-Checks (read-only) ──────────────────────────────────
_CVE_PS = r'''
$ErrorActionPreference = 'SilentlyContinue'
$r = New-Object System.Collections.ArrayList
function Add-Vuln($cve,$name,$sev,$status,$detail,$rec){
    [void]$r.Add([PSCustomObject]@{ cve=$cve; name=$name; severity=$sev; status=$status; detail=$detail; recommendation=$rec })
}
$build = [int]((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuildNumber)

# EternalBlue / MS17-010 (SMBv1)
$smb1 = (Get-SmbServerConfiguration).EnableSMB1Protocol
if ($smb1) { Add-Vuln 'CVE-2017-0144' 'EternalBlue (MS17-010 / SMBv1)' 'Kritisch' 'VERWUNDBAR' 'SMBv1 ist aktiviert.' 'SMBv1 deaktivieren: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol' }
else       { Add-Vuln 'CVE-2017-0144' 'EternalBlue (MS17-010 / SMBv1)' 'OK' 'Gepatcht/Aus' 'SMBv1 ist deaktiviert.' '' }

# Follina (MSDT) CVE-2022-30190
$msdt = Test-Path 'Registry::HKEY_CLASSES_ROOT\ms-msdt'
if ($msdt) { Add-Vuln 'CVE-2022-30190' 'Follina (MSDT)' 'Mittel' 'Handler aktiv' 'ms-msdt URL-Handler vorhanden. Mit aktuellen Patches gemildert, ohne Patch ausnutzbar.' 'Juni-2022-Updates (oder neuer) sicherstellen; ggf. ms-msdt-Handler entfernen.' }
else       { Add-Vuln 'CVE-2022-30190' 'Follina (MSDT)' 'OK' 'Handler entfernt' 'ms-msdt-Handler nicht registriert (Workaround/gepatcht).' '' }

# PrintNightmare CVE-2021-34527
$spooler = (Get-Service Spooler -EA SilentlyContinue).Status
$pnp = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint' -EA SilentlyContinue
if ($spooler -eq 'Running') {
    if ($pnp.NoWarningNoElevationOnInstall -eq 1) {
        Add-Vuln 'CVE-2021-34527' 'PrintNightmare' 'Hoch' 'Riskant konfiguriert' 'Spooler laeuft UND NoWarningNoElevationOnInstall=1.' 'Registry-Wert auf 0 setzen; Spooler deaktivieren falls kein Druck noetig.'
    } else {
        Add-Vuln 'CVE-2021-34527' 'PrintNightmare' 'Mittel' 'Spooler aktiv' 'Print Spooler laeuft (Angriffsflaeche); Point-and-Print nicht unsicher konfiguriert.' 'Falls kein Druck noetig: Spooler deaktivieren. Patches aktuell halten.'
    }
} else { Add-Vuln 'CVE-2021-34527' 'PrintNightmare' 'OK' 'Spooler aus' 'Print Spooler ist gestoppt/deaktiviert.' '' }

# HiveNightmare / SeriousSAM CVE-2021-36934
$acl = (icacls C:\Windows\System32\config\SAM 2>$null)
$usersRead = $false
foreach ($l in $acl) { if ($l -match 'BUILTIN\\(Users|Benutzer)' -and $l -match '\(R') { $usersRead = $true } }
if ($usersRead) { Add-Vuln 'CVE-2021-36934' 'HiveNightmare / SeriousSAM' 'Hoch' 'SAM lesbar' 'BUILTIN\Users hat Lesezugriff auf den SAM-Hive.' 'icacls-ACL ruecksetzen + alte Schattenkopien loeschen (KB5005357).' }
else            { Add-Vuln 'CVE-2021-36934' 'HiveNightmare / SeriousSAM' 'OK' 'ACL ok' 'Kein User-Lesezugriff auf den SAM-Hive.' '' }

# SMBGhost CVE-2020-0796 (nur Build 1903/1909)
if ($build -eq 18362 -or $build -eq 18363) {
    $comp = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name DisableCompression -EA SilentlyContinue).DisableCompression
    if ($comp -ne 1) { Add-Vuln 'CVE-2020-0796' 'SMBGhost (SMBv3 Compression)' 'Hoch' 'Potentiell' "Build $build ohne DisableCompression." 'KB4551762 installieren oder DisableCompression=1 setzen.' }
    else             { Add-Vuln 'CVE-2020-0796' 'SMBGhost (SMBv3 Compression)' 'OK' 'Mitigiert' 'SMB-Compression deaktiviert.' '' }
} else { Add-Vuln 'CVE-2020-0796' 'SMBGhost (SMBv3 Compression)' 'OK' 'Nicht betroffen' "Build $build ausserhalb 1903/1909." '' }

# BlueKeep CVE-2019-0708 (alte Builds + RDP)
$rdpDeny = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -EA SilentlyContinue).fDenyTSConnections
if ($build -lt 17763 -and $rdpDeny -eq 0) { Add-Vuln 'CVE-2019-0708' 'BlueKeep (RDP)' 'Kritisch' 'Potentiell' "Altes OS (Build $build) mit aktivem RDP." 'Sofort patchen (KB4500705) + NLA erzwingen.' }
else { Add-Vuln 'CVE-2019-0708' 'BlueKeep (RDP)' 'OK' 'Nicht betroffen' "Build $build / RDP-Status unkritisch." '' }

# PetitPotam / WebDAV-Relay – WebClient-Dienst
$wc = (Get-Service WebClient -EA SilentlyContinue).Status
if ($wc -eq 'Running') { Add-Vuln 'CVE-2021-36942' 'PetitPotam / WebDAV-Relay' 'Mittel' 'WebClient aktiv' 'WebClient-Dienst laeuft (NTLM-Relay ueber WebDAV moeglich).' 'WebClient deaktivieren falls nicht noetig; SMB-Signing/EPA erzwingen.' }
else { Add-Vuln 'CVE-2021-36942' 'PetitPotam / WebDAV-Relay' 'OK' 'WebClient aus' 'WebClient-Dienst nicht aktiv.' '' }

# RPC/DCOM Hardening Indikator (CVE-2021-26414 Workaround-Registry)
$dcom = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Ole\AppCompat' -Name RequireIntegrityActivationAuthenticationLevel -EA SilentlyContinue).RequireIntegrityActivationAuthenticationLevel
if ($dcom -eq 1) { Add-Vuln 'CVE-2021-26414' 'DCOM Hardening' 'OK' 'Erzwungen' 'DCOM-Integritaets-Authentifizierung erzwungen.' '' }
else { Add-Vuln 'CVE-2021-26414' 'DCOM Hardening' 'Niedrig' 'Nicht erzwungen' 'DCOM-Hardening-Registry nicht gesetzt (seit 2022-Patches Standard).' 'Aktuelle kumulative Updates sicherstellen.' }

$r | ConvertTo-Json -Depth 3 -Compress
'''


class VulnScanModule(BaseModule):
    """Read-only Patch- & Schwachstellen-Exposure-Check."""

    def _build(self):
        self._info_bar(
            self,
            "Patch-Status + Exposure gegen bekannte schwere Windows-Lücken (read-only Indikatoren, kein Exploit). "
            "Echte unbekannte Zero-Days kann kein Tool erkennen – hier geht es um bekannte CVEs und Patch-Aktualität.")

        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=6, pady=6)
        t_cve = ttk.Frame(nb)
        t_patch = ttk.Frame(nb)
        t_nvd = ttk.Frame(nb)
        nb.add(t_cve, text="  Bekannte Schwachstellen  ")
        nb.add(t_patch, text="  Patch-Status  ")
        nb.add(t_nvd, text="  Aktuelle CVEs (NVD)  ")
        self._build_cve(t_cve)
        self._build_patch(t_patch)
        self._build_nvd(t_nvd)

    # ── Tab 1: Bekannte CVEs ────────────────────────────────────────────────────

    def _build_cve(self, parent):
        bar = tk.Frame(parent, bg=DARK["bg"]); bar.pack(fill="x", padx=10, pady=(8, 2))
        self._cve_btn = ttk.Button(bar, text="Schwachstellen-Check",
                                    style="Accent.TButton", command=self._start_cve)
        self._cve_btn.pack(side="left")
        self._cve_report_btn = ttk.Button(bar, text="Befunde an Reporting",
                                           command=self._send_cve_report, state="disabled")
        self._cve_report_btn.pack(side="left", padx=(6, 0))
        self._cve_sum = tk.StringVar(value="Noch kein Check gelaufen")
        self._cve_sum_lbl = tk.Label(bar, textvariable=self._cve_sum, bg=DARK["bg"],
                                     fg=DARK["border"], font=("Segoe UI", 10, "bold"))
        self._cve_sum_lbl.pack(side="right", padx=8)

        sec = self._section_expand(parent, "Bekannte Windows-Schwachstellen")
        cols = ("cve", "name", "status", "detail", "rec")
        self._cve_tree = ttk.Treeview(sec, columns=cols, show="headings", selectmode="browse")
        for c, t, w in [("cve", "CVE", 150), ("name", "Schwachstelle", 230),
                        ("status", "Status", 130), ("detail", "Detail", 380),
                        ("rec", "Empfehlung", 380)]:
            self._cve_tree.heading(c, text=t)
            self._cve_tree.column(c, width=w, anchor="w")
        sb = ttk.Scrollbar(sec, command=self._cve_tree.yview)
        self._cve_tree.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self._cve_tree.pack(fill="both", expand=True, padx=6, pady=6)
        for sev, col in SEVERITY_COLORS.items():
            self._cve_tree.tag_configure(sev, foreground=col)
        self._cve_tree.tag_configure("OK", foreground=DARK["green"])
        self._cve_findings: list[dict] = []

    def _start_cve(self):
        self._cve_btn.configure(state="disabled")
        self._cve_report_btn.configure(state="disabled")
        for iid in self._cve_tree.get_children():
            self._cve_tree.delete(iid)
        self._cve_sum.set("Prüfe …")
        self._cve_sum_lbl.configure(fg=DARK["accent"])
        if self._activity_cb:
            self._activity_cb("Schwachstellen-Check gestartet")
        threading.Thread(target=self._run_cve, daemon=True).start()

    def _run_cve(self):
        data, err = self._ps_json(_CVE_PS)
        if not data and err:
            self.after(0, lambda: (self._cve_btn.configure(state="normal"),
                                   self._cve_sum.set(f"Fehler: {err}")))
            return
        self.after(0, self._render_cve, data)

    def _render_cve(self, data: list[dict]):
        self._cve_findings = data
        order = {"Kritisch": 0, "Hoch": 1, "Mittel": 2, "Niedrig": 3, "Info": 4, "OK": 5}
        weight = {"Kritisch": 5, "Hoch": 3, "Mittel": 2, "Niedrig": 1}
        vuln = risk = ok = 0
        for d in sorted(data, key=lambda d: order.get(d.get("severity", "Info"), 9)):
            sev = d.get("severity", "Info")
            self._cve_tree.insert("", "end", tags=(sev,), values=(
                d.get("cve", ""), d.get("name", ""), d.get("status", ""),
                d.get("detail", ""), d.get("recommendation", "")))
            if sev == "OK":
                ok += 1
            elif sev in weight:
                vuln += 1
                risk += weight[sev]
        self._cve_btn.configure(state="normal")
        if vuln:
            self._cve_report_btn.configure(state="normal")
        if vuln == 0:
            self._cve_sum.set(f"✓ {ok} Checks ok — keine bekannten Lücken offen")
            self._cve_sum_lbl.configure(fg=DARK["green"])
        else:
            clr = DARK["red"] if risk >= 8 else (DARK["orange"] if risk >= 4 else DARK["yellow"])
            self._cve_sum.set(f"{vuln} offene(r) Befund(e) · Risiko {risk}")
            self._cve_sum_lbl.configure(fg=clr)
        if self._activity_cb:
            self._activity_cb(f"Schwachstellen-Check: {vuln} offen, Risiko {risk}")

    def _send_cve_report(self):
        sent = 0
        for d in self._cve_findings:
            sev = d.get("severity", "Info")
            if sev == "OK":
                continue
            desc = f"{d.get('cve','')}: {d.get('detail','')}"
            rec = d.get("recommendation", "")
            if rec:
                desc = f"{desc}\n\nEmpfehlung: {rec}"
            if self._report_finding(f"[Vuln] {d.get('name','')}", sev, desc, d.get("cve", "")):
                sent += 1
        if self._activity_cb:
            self._activity_cb(f"{sent} Schwachstellen-Befund(e) an Reporting übergeben" if sent
                              else "Reporting nicht verbunden / keine offenen Befunde")

    # ── Tab 2: Patch-Status ─────────────────────────────────────────────────────

    def _build_patch(self, parent):
        bar = tk.Frame(parent, bg=DARK["bg"]); bar.pack(fill="x", padx=10, pady=(8, 2))
        self._patch_btn = ttk.Button(bar, text="Patch-Status laden",
                                     style="Accent.TButton", command=self._start_patch)
        self._patch_btn.pack(side="left")
        self._patch_sum = tk.StringVar(value="")
        tk.Label(bar, textvariable=self._patch_sum, bg=DARK["bg"], fg=DARK["fg"],
                 font=("Segoe UI", 9, "bold")).pack(side="left", padx=12)

        sec = self._section_expand(parent, "Installierte Updates (Hotfixes)")
        cols = ("id", "desc", "installed")
        self._patch_tree = ttk.Treeview(sec, columns=cols, show="headings", selectmode="browse")
        for c, t, w in [("id", "KB / HotFix", 160), ("desc", "Typ", 160),
                        ("installed", "Installiert am", 140)]:
            self._patch_tree.heading(c, text=t)
            self._patch_tree.column(c, width=w, anchor="w")
        sb = ttk.Scrollbar(sec, command=self._patch_tree.yview)
        self._patch_tree.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self._patch_tree.pack(fill="both", expand=True, padx=6, pady=6)

    def _start_patch(self):
        self._patch_btn.configure(state="disabled")
        for iid in self._patch_tree.get_children():
            self._patch_tree.delete(iid)
        self._patch_sum.set("Lade …")
        threading.Thread(target=self._run_patch, daemon=True).start()

    def _run_patch(self):
        data, err = self._ps_json(_PATCH_PS)
        if not data and err:
            self.after(0, lambda: (self._patch_btn.configure(state="normal"),
                                   self._patch_sum.set(f"Fehler: {err}")))
            return
        self.after(0, self._render_patch, data)

    def _render_patch(self, data: list[dict]):
        self._patch_btn.configure(state="normal")
        summary = next((d for d in data if d.get("type") == "summary"), None)
        hotfixes = [d for d in data if d.get("type") == "hotfix"]
        if summary:
            last = summary.get("last", "unbekannt")
            age_txt = ""
            try:
                age = (datetime.now() - datetime.strptime(last, "%Y-%m-%d")).days
                age_txt = f" · letztes Update vor {age} Tagen"
            except Exception:
                age = None
            self._patch_sum.set(
                f"{summary.get('caption','')}  Build {summary.get('build','')} "
                f"({summary.get('display','')}) · {summary.get('count',0)} Hotfixes · "
                f"zuletzt {last}{age_txt}")
        for h in hotfixes:
            self._patch_tree.insert("", "end", values=(
                h.get("id", ""), h.get("desc", ""), h.get("installed", "")))
        if self._activity_cb:
            self._activity_cb(f"Patch-Status geladen: {len(hotfixes)} Hotfixes")

    # ── Tab 3: Aktuelle CVEs (NVD live) ─────────────────────────────────────────

    def _build_nvd(self, parent):
        self._info_bar(parent,
            "Live aus der NIST-NVD-Datenbank: aktuelle kritische Microsoft/Windows-CVEs. "
            "Abgleichen, ob dein Patch-Level (Tab Patch-Status) diese Funde abdeckt.")
        bar = tk.Frame(parent, bg=DARK["bg"]); bar.pack(fill="x", padx=10, pady=(4, 2))
        tk.Label(bar, text="Zeitraum:", bg=DARK["bg"], fg=DARK["fg"],
                 font=("Segoe UI", 9)).pack(side="left")
        self._nvd_days = tk.IntVar(value=30)
        ttk.Spinbox(bar, from_=7, to=120, textvariable=self._nvd_days, width=5).pack(side="left", padx=4)
        tk.Label(bar, text="Tage · nur CRITICAL", bg=DARK["bg"], fg=DARK["fg"],
                 font=("Segoe UI", 9)).pack(side="left", padx=(0, 12))
        self._nvd_btn = ttk.Button(bar, text="NVD abfragen", style="Accent.TButton",
                                   command=self._start_nvd)
        self._nvd_btn.pack(side="left")
        self._nvd_sum = tk.StringVar(value="")
        tk.Label(bar, textvariable=self._nvd_sum, bg=DARK["bg"], fg=DARK["border"],
                 font=("Segoe UI", 9, "bold")).pack(side="right", padx=8)

        sec = self._section_expand(parent, "Aktuelle kritische CVEs")
        cols = ("cve", "cvss", "published", "desc")
        self._nvd_tree = ttk.Treeview(sec, columns=cols, show="headings", selectmode="browse")
        for c, t, w in [("cve", "CVE-ID", 150), ("cvss", "CVSS", 70),
                        ("published", "Veröffentlicht", 110), ("desc", "Beschreibung", 700)]:
            self._nvd_tree.heading(c, text=t)
            self._nvd_tree.column(c, width=w, anchor="w")
        sb = ttk.Scrollbar(sec, command=self._nvd_tree.yview)
        self._nvd_tree.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self._nvd_tree.pack(fill="both", expand=True, padx=6, pady=6)
        self._nvd_tree.tag_configure("crit", foreground=DARK["red"])

    def _start_nvd(self):
        self._nvd_btn.configure(state="disabled")
        for iid in self._nvd_tree.get_children():
            self._nvd_tree.delete(iid)
        self._nvd_sum.set("Frage NVD ab …")
        threading.Thread(target=self._run_nvd, args=(int(self._nvd_days.get()),), daemon=True).start()

    def _run_nvd(self, days: int):
        try:
            end = datetime.now()
            start = end - timedelta(days=days)
            params = {
                "keywordSearch": "Microsoft Windows",
                "cvssV3Severity": "CRITICAL",
                "pubStartDate": start.strftime("%Y-%m-%dT00:00:00.000"),
                "pubEndDate": end.strftime("%Y-%m-%dT23:59:59.000"),
                "resultsPerPage": "50",
            }
            url = "https://services.nvd.nist.gov/rest/json/cves/2.0?" + urllib.parse.urlencode(params)
            req = urllib.request.Request(url, headers={"User-Agent": "G4MEOVER-SecuritySuite/2.x"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                payload = json.loads(resp.read().decode("utf-8", errors="replace"))
        except Exception as e:
            self.after(0, lambda: (self._nvd_btn.configure(state="normal"),
                                   self._nvd_sum.set(f"NVD-Fehler: {e}")))
            return
        rows = []
        for item in payload.get("vulnerabilities", []):
            c = item.get("cve", {})
            cid = c.get("id", "")
            desc = ""
            for d in c.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value", "")
                    break
            score = ""
            metrics = c.get("metrics", {})
            for key in ("cvssMetricV31", "cvssMetricV30"):
                if metrics.get(key):
                    score = metrics[key][0].get("cvssData", {}).get("baseScore", "")
                    break
            pub = (c.get("published", "")[:10])
            rows.append((cid, str(score), pub, desc[:300]))
        self.after(0, self._render_nvd, rows)

    def _render_nvd(self, rows: list[tuple]):
        self._nvd_btn.configure(state="normal")
        for r in sorted(rows, key=lambda x: x[2], reverse=True):
            self._nvd_tree.insert("", "end", tags=("crit",), values=r)
        self._nvd_sum.set(f"{len(rows)} kritische CVE(s)")
        if self._activity_cb:
            self._activity_cb(f"NVD: {len(rows)} aktuelle kritische Windows-CVEs")
