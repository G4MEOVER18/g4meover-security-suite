"""AvTestModule – AV/EDR-Funktionstest für das eigene System.

Prüft, ob die Verteidigung des EIGENEN Systems greift:
  1) EICAR-Test: legt die offizielle, harmlose EICAR-Antivirus-Testdatei ab und
     beobachtet, ob Microsoft Defender (oder ein Drittanbieter-AV) sie sofort
     erkennt/entfernt. EICAR ist KEIN Schadcode, sondern der von der AV-Industrie
     (EICAR.org) bereitgestellte Standard-Funktionstest.
  2) Schutzschichten-Status: Echtzeitschutz, Verhaltensüberwachung, Cloud, PUA,
     Netzwerkschutz, Controlled Folder Access.
  3) ASR-Regeln: welche Attack-Surface-Reduction-Regeln aktiv sind und ob sie
     im Block- oder nur Audit-Modus laufen.

Abgesehen von der temporären EICAR-Testdatei (die sofort wieder aufgeräumt wird)
werden keine Änderungen am System vorgenommen.
"""
import tkinter as tk
from tkinter import ttk
import threading
import base64
import time
import os
import tempfile
from pathlib import Path

from modules.base import BaseModule
from utils.theme import DARK, SEVERITY_COLORS


# EICAR-Testdatei base64-kodiert ablegen, damit der Klartext-Signaturstring nicht
# in dieser Quelldatei steht (sonst würde Defender die Suite selbst flaggen).
_EICAR_B64 = ("WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5E"
              "QVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo=")


def _eicar_bytes() -> bytes:
    return base64.b64decode(_EICAR_B64)


# Schutzschichten + ASR-Regelstatus als flache JSON-Liste
_DEFENDER_PS = r'''
$ErrorActionPreference = 'SilentlyContinue'
$results = New-Object System.Collections.ArrayList
function Add-Item($type,$n,$state,$detail,$sev){
    [void]$results.Add([PSCustomObject]@{ type=$type; name=$n; state=$state; detail=$detail; sev=$sev })
}
function Add-Layer($n,$on,$detail){
    if ($on) { Add-Item 'layer' $n 'An' $detail 'OK' }
    else     { Add-Item 'layer' $n 'Aus' $detail 'Mittel' }
}
$pref = Get-MpPreference -ErrorAction SilentlyContinue
$st   = Get-MpComputerStatus -ErrorAction SilentlyContinue
if ($st) {
    Add-Layer 'Echtzeitschutz'           $st.RealTimeProtectionEnabled ''
    Add-Layer 'Verhaltensueberwachung'   $st.BehaviorMonitorEnabled ''
    Add-Layer 'Manipulationsschutz'      $st.IsTamperProtected ''
    Add-Layer 'IOAV (Downloads/Anhaenge)' $st.IoavProtectionEnabled ''
    Add-Layer 'Antimalware-Dienst'       $st.AMServiceEnabled ''
}
if ($pref) {
    Add-Layer 'Cloud-Schutz (MAPS)'      ($pref.MAPSReporting -ge 1)            "MAPSReporting=$($pref.MAPSReporting)"
    Add-Layer 'PUA-Schutz'               ($pref.PUAProtection -ge 1)           "PUAProtection=$($pref.PUAProtection)"
    Add-Layer 'Netzwerkschutz'           ($pref.EnableNetworkProtection -ge 1) "EnableNetworkProtection=$($pref.EnableNetworkProtection)"
    Add-Layer 'Controlled Folder Access' ($pref.EnableControlledFolderAccess -ge 1) "=$($pref.EnableControlledFolderAccess)"
    $ids  = @($pref.AttackSurfaceReductionRules_Ids)
    $acts = @($pref.AttackSurfaceReductionRules_Actions)
    for ($i=0; $i -lt $ids.Count; $i++) {
        Add-Item 'asr' $ids[$i] "$($acts[$i])" '' 'Info'
    }
    if ($ids.Count -eq 0) { Add-Item 'asr' '__none__' '' 'Keine ASR-Regeln konfiguriert' 'Mittel' }
}
$results | ConvertTo-Json -Depth 3 -Compress
'''

# Defender-Event-Log auf einen frischen Fund prüfen (Bestätigung des EICAR-Tests)
_DEFENDER_RECENT_PS = r'''
$ErrorActionPreference = 'SilentlyContinue'
$start = (Get-Date).AddMinutes(-2)
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational'; Id=1116,1117; StartTime=$start} -ErrorAction SilentlyContinue |
  Select-Object -First 5 | ForEach-Object {
    $line = ($_.Message -split "`n" | Where-Object { $_ -match 'EICAR|Name|Bedrohung|Threat' } | Select-Object -First 1)
    [PSCustomObject]@{ time=$_.TimeCreated.ToString('HH:mm:ss'); id=$_.Id; info=$line.Trim() }
  } | ConvertTo-Json -Depth 3 -Compress
'''

# ASR-GUID → Klartext
_ASR_NAMES = {
    "56a863a9-875e-4185-98a7-b882c64b5ce5": "Missbrauch verwundbarer signierter Treiber",
    "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c": "Adobe Reader: Kindprozesse",
    "d4f940ab-401b-4efc-aadc-ad5f3c50688a": "Office: Kindprozesse blockieren",
    "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2": "LSASS-Credential-Diebstahl blockieren",
    "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550": "Ausführbarer Inhalt aus Mail/Webmail",
    "01443614-cd74-433a-b99e-2ecdc07bfc25": "Verschleierte Skripte blockieren",
    "5beb7efe-fd9a-4556-801d-275e5ffc04cc": "Potentiell verschleierter Code (JS/VBS/PS)",
    "d3e037e1-3eb8-44c8-a917-57927947596d": "JS/VBS: Download ausführbarer Inhalte",
    "3b576869-a4ec-4529-8536-b80a7769e899": "Office: ausführbare Inhalte erstellen",
    "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84": "Office: Code-Injektion blockieren",
    "26190899-1602-49e8-8b27-eb1d0a1ce869": "Office-Kommunikation: Kindprozesse",
    "e6db77e5-3df2-4cf1-b95a-636979351e5b": "Persistenz über WMI blockieren",
    "d1e49aac-8f56-4280-b9ba-993a6d77406c": "Prozess-Erstellung via PSExec/WMI",
    "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4": "Unvertraute USB-Prozesse blockieren",
    "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b": "Office-Makros: Win32-API-Aufrufe",
    "c1db55ab-c21a-4637-bb3f-a12568109d35": "Erweiterter Ransomware-Schutz",
}
_ASR_ACTIONS = {"0": ("Aus", "Mittel"), "1": ("Block", "OK"),
                "2": ("Audit", "Niedrig"), "6": ("Warnen", "Niedrig")}


class AvTestModule(BaseModule):
    """AV/EDR-Funktionstest: EICAR + Schutzschichten + ASR-Status."""

    def _build(self):
        self._info_bar(
            self,
            "Funktionstest deiner Verteidigung: erkennt Defender die harmlose EICAR-Standard-Testdatei, "
            "und welche Schutzschichten/ASR-Regeln sind aktiv? EICAR ist kein Schadcode. "
            "Nur die temporäre Testdatei wird angelegt (und aufgeräumt).")

        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=6, pady=6)
        t_eicar = ttk.Frame(nb)
        t_def = ttk.Frame(nb)
        nb.add(t_eicar, text="  EICAR-Funktionstest  ")
        nb.add(t_def, text="  Schutzschichten & ASR  ")
        self._build_eicar(t_eicar)
        self._build_defender(t_def)

    # ── Tab 1: EICAR ────────────────────────────────────────────────────────────

    def _build_eicar(self, parent):
        sec = self._section(parent, "EICAR-Erkennungstest")
        tk.Label(sec, text=(
            "Legt die EICAR-Testdatei im TEMP-Ordner ab und prüft nach kurzer Wartezeit, "
            "ob das AV sie blockiert/entfernt hat.\nGreift Defender, gilt der Test als bestanden."),
            bg=DARK["bg"], fg=DARK["fg"], font=("Segoe UI", 8),
            justify="left").pack(anchor="w", padx=10, pady=(2, 6))

        bar = tk.Frame(parent, bg=DARK["bg"]); bar.pack(fill="x", padx=10, pady=2)
        self._eicar_btn = ttk.Button(bar, text="EICAR-Test starten",
                                     style="Accent.TButton", command=self._start_eicar)
        self._eicar_btn.pack(side="left")
        self._eicar_result = tk.StringVar(value="")
        tk.Label(bar, textvariable=self._eicar_result, bg=DARK["bg"], fg=DARK["border"],
                 font=("Segoe UI", 10, "bold")).pack(side="right", padx=8)

        self._output = self._log_widget(parent, height=12)

    def _start_eicar(self):
        self._eicar_btn.configure(state="disabled")
        self._eicar_result.set("Test läuft …")
        if self._activity_cb:
            self._activity_cb("EICAR-Funktionstest gestartet")
        threading.Thread(target=self._run_eicar, daemon=True).start()

    def _run_eicar(self):
        target = Path(tempfile.gettempdir()) / "g4meover_eicar_test.com"
        wrote = removed_fast = False
        try:
            self.after(0, self._log, self._output,
                       f"$ Schreibe EICAR-Testdatei → {target}\n", "cyan")
            try:
                with open(target, "wb") as f:
                    f.write(_eicar_bytes())
                    f.flush()
                wrote = True
            except (PermissionError, OSError) as e:
                # Defender kann den Schreib-/Schließvorgang abfangen
                self.after(0, self._log, self._output,
                           f"[+] Schreibvorgang vom AV blockiert: {e}\n", "green")
                removed_fast = True

            # Kurz warten, dann prüfen ob die Datei noch existiert
            if wrote:
                time.sleep(2.0)
                if not target.exists():
                    removed_fast = True
                    self.after(0, self._log, self._output,
                               "[+] Datei wurde nach dem Schreiben sofort entfernt (Defender aktiv).\n",
                               "green")
                else:
                    self.after(0, self._log, self._output,
                               "[!] Datei existiert noch — kein sofortiger AV-Zugriff.\n", "red")
        except Exception as e:
            self.after(0, self._log, self._output, f"[!] Unerwarteter Fehler: {e}\n", "red")
        finally:
            # Aufräumen, falls noch vorhanden
            try:
                if target.exists():
                    os.remove(target)
                    self.after(0, self._log, self._output,
                               "[i] Testdatei manuell aufgeräumt.\n", "yellow")
            except Exception:
                pass

        # Defender-Event-Log auf Bestätigung prüfen
        recent, _ = self._ps_json(_DEFENDER_RECENT_PS, timeout=40)
        if recent:
            self.after(0, self._log, self._output,
                       f"[+] Defender-Event-Log bestätigt {len(recent)} Fund(e):\n", "green")
            for r in recent:
                self.after(0, self._log, self._output,
                           f"    {r.get('time','')}  ID {r.get('id','')}  {r.get('info','')}\n", "green")

        passed = removed_fast or bool(recent)
        self.after(0, self._finish_eicar, passed)

    def _finish_eicar(self, passed: bool):
        self._eicar_btn.configure(state="normal")
        if passed:
            self._eicar_result.set("✓ AV reagiert — bestanden")
            self._log(self._output,
                      "\n[ERGEBNIS] Test bestanden: Die Verteidigung erkennt bekannte Signaturen.\n", "green")
        else:
            self._eicar_result.set("✗ Keine AV-Reaktion")
            self._log(self._output,
                      "\n[ERGEBNIS] WARNUNG: Kein AV-Zugriff erkannt. Echtzeitschutz aktiv? "
                      "Drittanbieter-AV? Ausnahme für TEMP gesetzt?\n", "red")
        if self._activity_cb:
            self._activity_cb(f"EICAR-Test {'bestanden' if passed else 'OHNE AV-Reaktion'}")

    # ── Tab 2: Defender-Schutzschichten & ASR ───────────────────────────────────

    def _build_defender(self, parent):
        bar = tk.Frame(parent, bg=DARK["bg"]); bar.pack(fill="x", padx=10, pady=(8, 2))
        self._def_btn = ttk.Button(bar, text="Status abfragen",
                                    style="Accent.TButton", command=self._start_defender)
        self._def_btn.pack(side="left")
        self._def_sum = tk.StringVar(value="")
        tk.Label(bar, textvariable=self._def_sum, bg=DARK["bg"], fg=DARK["border"],
                 font=("Segoe UI", 9, "bold")).pack(side="right", padx=8)

        sec = self._section_expand(parent, "Schutzschichten & ASR-Regeln")
        cols = ("kind", "name", "state", "detail")
        self._tree = ttk.Treeview(sec, columns=cols, show="headings", selectmode="browse")
        for c, t, w in [("kind", "Typ", 90), ("name", "Schutz / ASR-Regel", 380),
                        ("state", "Status", 110), ("detail", "Detail", 360)]:
            self._tree.heading(c, text=t)
            self._tree.column(c, width=w, anchor="w")
        sb = ttk.Scrollbar(sec, command=self._tree.yview)
        self._tree.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self._tree.pack(fill="both", expand=True, padx=6, pady=6)
        for sev, col in SEVERITY_COLORS.items():
            self._tree.tag_configure(sev, foreground=col)
        self._tree.tag_configure("OK", foreground=DARK["green"])

    def _start_defender(self):
        self._def_btn.configure(state="disabled")
        for iid in self._tree.get_children():
            self._tree.delete(iid)
        self._def_sum.set("Frage Defender ab …")
        threading.Thread(target=self._run_defender, daemon=True).start()

    def _run_defender(self):
        data, err = self._ps_json(_DEFENDER_PS, timeout=60)
        if not data and err:
            self.after(0, lambda: (self._def_btn.configure(state="normal"),
                                   self._def_sum.set(f"Fehler: {err}")))
            return
        self.after(0, self._render_defender, data)

    def _render_defender(self, data: list[dict]):
        self._def_btn.configure(state="normal")
        layers_off = asr_active = asr_audit = 0
        # Schutzschichten zuerst
        for d in [x for x in data if x.get("type") == "layer"]:
            sev = d.get("sev", "Info")
            if d.get("state") == "Aus":
                layers_off += 1
            self._tree.insert("", "end", tags=(sev,), values=(
                "Schutz", d.get("name", ""), d.get("state", ""), d.get("detail", "")))
        # ASR-Regeln
        for d in [x for x in data if x.get("type") == "asr"]:
            guid = d.get("name", "")
            if guid == "__none__":
                self._tree.insert("", "end", tags=("Mittel",), values=(
                    "ASR", "Keine ASR-Regeln konfiguriert", "—",
                    "ASR-Regeln im Block-Modus aktivieren"))
                continue
            label, sev = _ASR_NAMES.get(guid, guid), "Info"
            action_code = d.get("state", "")
            action_label, sev = _ASR_ACTIONS.get(action_code, (f"Code {action_code}", "Info"))
            if action_label == "Block":
                asr_active += 1
            elif action_label == "Audit":
                asr_audit += 1
            self._tree.insert("", "end", tags=(sev,), values=(
                "ASR", label, action_label, guid))
        self._def_sum.set(
            f"{layers_off} Schicht(en) aus · ASR: {asr_active} Block / {asr_audit} Audit")
        if self._activity_cb:
            self._activity_cb(
                f"Defender-Status: {layers_off} Schichten aus, {asr_active} ASR-Block-Regeln")
