"""AttackSimModule – EDR-/Detection-Tests am eigenen System.

Führt harmlose, **reversible** Simulationen bekannter Angriffstechniken
(MITRE ATT&CK) aus und prüft, ob die Verteidigung (Defender/ASR/AMSI,
Event-Log) sie erkennt oder durchlässt. Es wird KEIN echter Schadcode
ausgeführt; jede Test-Aktion wird sofort wieder rückgängig gemacht.

Tests:
  - AMSI-Funktionstest (T1059) – Microsofts offizieller AMSI-Teststring
  - Run-Key-Persistence (T1547.001) – HKCU-Run-Key anlegen + sofort löschen
  - Scheduled-Task-Persistence (T1053.005) – Task anlegen + sofort löschen
  - LSASS-Zugriff (T1003.001) – nur Handle mit minimalen Rechten öffnen/schließen
  - Verdächtiger Prozess-Spawn (T1059.001) – PowerShell startet Kindprozess

Nur für das EIGENE System gedacht (EDR-/Defender-Validierung).
"""
import tkinter as tk
from tkinter import ttk
import threading

from modules.base import BaseModule
from utils.theme import DARK, SEVERITY_COLORS


# AMSI-Funktionstest: offizieller Microsoft-Teststring (zur Laufzeit zusammengesetzt,
# damit er nicht als Literal in der Quelldatei steht).
_AMSI_PS = r'''
$ErrorActionPreference = 'SilentlyContinue'
$marker = 'AMSI Test ' + 'Sample: ' + '7e72c3ce-' + '861b-4339-' + '8740-0ac1484c1386'
$blocked = $false
try {
    $sb = [ScriptBlock]::Create("`$x = '$marker'; `$x.Length")
    $null = & $sb
} catch { $blocked = $true }
if ($blocked) { '{"detected":true}' } else { '{"detected":false}' }
'''

# Run-Key Persistence: anlegen, prüfen, sofort löschen
_RUNKEY_PS = r'''
$ErrorActionPreference = 'SilentlyContinue'
$name = 'G4MEOVER_EDR_Test'
$path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
$blocked = $false; $written = $false
try {
    New-ItemProperty -Path $path -Name $name -Value 'calc.exe' -PropertyType String -Force -ErrorAction Stop | Out-Null
    $check = Get-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue
    if ($check) { $written = $true }
} catch { $blocked = $true }
# Aufräumen
Remove-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue
"{""written"":$($written.ToString().ToLower()),""blocked"":$($blocked.ToString().ToLower())}"
'''

# Scheduled Task Persistence: anlegen, prüfen, sofort löschen
_TASK_PS = r'''
$ErrorActionPreference = 'SilentlyContinue'
$tn = 'G4MEOVER_EDR_Test'
$written = $false; $blocked = $false
try {
    $a = New-ScheduledTaskAction -Execute 'calc.exe'
    $t = New-ScheduledTaskTrigger -AtLogOn
    Register-ScheduledTask -TaskName $tn -Action $a -Trigger $t -Force -ErrorAction Stop | Out-Null
    if (Get-ScheduledTask -TaskName $tn -ErrorAction SilentlyContinue) { $written = $true }
} catch { $blocked = $true }
Unregister-ScheduledTask -TaskName $tn -Confirm:$false -ErrorAction SilentlyContinue
"{""written"":$($written.ToString().ToLower()),""blocked"":$($blocked.ToString().ToLower())}"
'''

# LSASS-Zugriff: Handle mit minimalen Rechten (QUERY_LIMITED_INFORMATION) öffnen + schließen
_LSASS_PS = r'''
$ErrorActionPreference = 'SilentlyContinue'
$sig = @'
using System;
using System.Runtime.InteropServices;
public class K {
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr OpenProcess(uint a, bool b, uint pid);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool CloseHandle(IntPtr h);
}
'@
$opened = $false; $err = 0
try {
    Add-Type -TypeDefinition $sig -ErrorAction SilentlyContinue
    $p = Get-Process lsass -ErrorAction Stop
    $h = [K]::OpenProcess(0x1000, $false, [uint32]$p.Id)  # QUERY_LIMITED_INFORMATION
    if ($h -ne [IntPtr]::Zero) { $opened = $true; [void][K]::CloseHandle($h) }
    else { $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error() }
} catch { $err = -1 }
"{""opened"":$($opened.ToString().ToLower()),""err"":$err}"
'''

# Verdächtiger Prozess-Spawn: PowerShell startet ein Kindprozess (harmlos: cmd /c echo)
_SPAWN_PS = r'''
$ErrorActionPreference = 'SilentlyContinue'
$spawned = $false; $blocked = $false
try {
    $p = Start-Process cmd.exe -ArgumentList '/c','echo G4MEOVER_EDR_Test' -WindowStyle Hidden -PassThru -ErrorAction Stop
    if ($p) { $spawned = $true; Start-Sleep -Milliseconds 200; if (-not $p.HasExited) { $p.Kill() } }
} catch { $blocked = $true }
"{""spawned"":$($spawned.ToString().ToLower()),""blocked"":$($blocked.ToString().ToLower())}"
'''


# Test-Definitionen: (key, technik, name, ps, ergebnis-interpreter)
class AttackSimModule(BaseModule):
    """EDR-/Detection-Tests mit harmlosen, reversiblen ATT&CK-Simulationen."""

    def _build(self):
        self._info_bar(
            self,
            "EDR-/Detection-Tests am EIGENEN System: harmlose, reversible Simulationen bekannter "
            "Angriffstechniken. Prüft, ob deine Verteidigung sie erkennt/blockt. Kein echter Schadcode; "
            "jede Aktion wird sofort rückgängig gemacht.")

        bar = tk.Frame(self, bg=DARK["bg"]); bar.pack(fill="x", padx=10, pady=(6, 2))
        self._run_btn = ttk.Button(bar, text="Alle Tests ausführen",
                                    style="Accent.TButton", command=self._start_all)
        self._run_btn.pack(side="left")
        self._report_btn = ttk.Button(bar, text="Ergebnisse an Reporting",
                                       command=self._send_report, state="disabled")
        self._report_btn.pack(side="left", padx=(6, 0))
        self._sum = tk.StringVar(value="Noch keine Tests gelaufen")
        self._sum_lbl = tk.Label(bar, textvariable=self._sum, bg=DARK["bg"],
                                 fg=DARK["border"], font=("Segoe UI", 10, "bold"))
        self._sum_lbl.pack(side="right", padx=8)

        sec = self._section_expand(self, "ATT&CK-Detection-Tests")
        cols = ("technik", "test", "ergebnis", "detail")
        self._tree = ttk.Treeview(sec, columns=cols, show="headings", selectmode="browse")
        for c, t, w in [("technik", "ATT&CK", 120), ("test", "Test", 260),
                        ("ergebnis", "Ergebnis", 200), ("detail", "Detail", 480)]:
            self._tree.heading(c, text=t)
            self._tree.column(c, width=w, anchor="w")
        sb = ttk.Scrollbar(sec, command=self._tree.yview)
        self._tree.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self._tree.pack(fill="both", expand=True, padx=6, pady=6)
        for sev, col in SEVERITY_COLORS.items():
            self._tree.tag_configure(sev, foreground=col)
        self._tree.tag_configure("OK", foreground=DARK["green"])
        self._results: list[dict] = []

    # ── Ausführung ──────────────────────────────────────────────────────────────

    def _start_all(self):
        self._run_btn.configure(state="disabled")
        self._report_btn.configure(state="disabled")
        for iid in self._tree.get_children():
            self._tree.delete(iid)
        self._results = []
        self._sum.set("Tests laufen …")
        self._sum_lbl.configure(fg=DARK["accent"])
        if self._activity_cb:
            self._activity_cb("EDR-Detection-Tests gestartet")
        threading.Thread(target=self._run_all, daemon=True).start()

    def _run_all(self):
        # AMSI
        d, _ = self._ps_json(_AMSI_PS, timeout=40)
        det = bool(d and d[0].get("detected"))
        self._emit("T1059", "AMSI-Funktionstest (Script-Scanning)",
                   det, "AMSI hat den Teststring blockiert." if det
                   else "AMSI hat den Teststring NICHT blockiert – Script-Scanning prüfen.",
                   good_when_detected=True)

        # Run-Key
        d, _ = self._ps_json(_RUNKEY_PS, timeout=40)
        blocked = bool(d and d[0].get("blocked"))
        written = bool(d and d[0].get("written"))
        self._emit("T1547.001", "Run-Key-Persistence (angelegt+gelöscht)",
                   blocked, "Anlegen wurde blockiert (ASR/Defender)." if blocked
                   else ("Run-Key konnte angelegt werden – keine Blockade (Standard ohne ASR)."
                         if written else "Anlegen fehlgeschlagen."),
                   good_when_detected=True)

        # Scheduled Task
        d, _ = self._ps_json(_TASK_PS, timeout=50)
        blocked = bool(d and d[0].get("blocked"))
        written = bool(d and d[0].get("written"))
        self._emit("T1053.005", "Scheduled-Task-Persistence (angelegt+gelöscht)",
                   blocked, "Task-Erstellung wurde blockiert." if blocked
                   else ("Task konnte angelegt werden – keine Blockade." if written
                         else "Task-Erstellung fehlgeschlagen (evtl. Adminrechte)."),
                   good_when_detected=True)

        # LSASS
        d, _ = self._ps_json(_LSASS_PS, timeout=40)
        opened = bool(d and d[0].get("opened"))
        self._emit("T1003.001", "LSASS-Handle (minimal, sofort geschlossen)",
                   not opened,
                   "LSASS-Zugriff wurde verweigert (RunAsPPL/Schutz aktiv)." if not opened
                   else "Handle auf LSASS konnte geöffnet werden – Credential-Guard/RunAsPPL prüfen.",
                   good_when_detected=True)

        # Spawn
        d, _ = self._ps_json(_SPAWN_PS, timeout=40)
        blocked = bool(d and d[0].get("blocked"))
        self._emit("T1059.001", "Verdächtiger Prozess-Spawn (cmd via PowerShell)",
                   blocked, "Kindprozess wurde blockiert (ASR)." if blocked
                   else "Kindprozess konnte gestartet werden – ASR-Regel für Prozess-Spawning prüfen.",
                   good_when_detected=True)

        self.after(0, self._finish)

    def _emit(self, technik, test, detected, detail, good_when_detected=True):
        # detected=True bedeutet: Verteidigung hat reagiert (gut)
        if detected:
            ergebnis = "✓ Erkannt/Blockiert"
            sev = "OK"
        else:
            ergebnis = "⚠ Durchgelassen"
            sev = "Mittel"
        self._results.append({"technik": technik, "test": test, "detected": detected,
                              "ergebnis": ergebnis, "detail": detail, "severity": sev})
        self.after(0, self._insert_row, technik, test, ergebnis, detail, sev)

    def _insert_row(self, technik, test, ergebnis, detail, sev):
        self._tree.insert("", "end", tags=(sev,), values=(technik, test, ergebnis, detail))

    def _finish(self):
        self._run_btn.configure(state="normal")
        passed = sum(1 for r in self._results if r["detected"])
        total = len(self._results)
        through = total - passed
        if through:
            self._report_btn.configure(state="normal")
            self._sum.set(f"{passed}/{total} erkannt · {through} durchgelassen")
            self._sum_lbl.configure(fg=DARK["orange"] if through >= 3 else DARK["yellow"])
        else:
            self._sum.set(f"✓ Alle {total} Tests erkannt/blockiert")
            self._sum_lbl.configure(fg=DARK["green"])
        if self._activity_cb:
            self._activity_cb(f"EDR-Tests: {passed}/{total} erkannt, {through} durchgelassen")

    def _send_report(self):
        sent = 0
        for r in self._results:
            if r["detected"]:
                continue
            if self._report_finding(
                    f"[EDR-Test] {r['technik']} durchgelassen: {r['test']}",
                    "Mittel", r["detail"] + "\n\nEmpfehlung: passende ASR-Regel / "
                    "Schutzfunktion aktivieren, damit diese Technik erkannt wird."):
                sent += 1
        if self._activity_cb:
            self._activity_cb(f"{sent} EDR-Befund(e) an Reporting übergeben" if sent
                              else "Reporting nicht verbunden / alle Tests erkannt")
