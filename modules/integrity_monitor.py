"""IntegrityMonitorModule – Persistence-Audit + File-Integrity (read-only).

Zwei Werkzeuge:
  1) Persistence-Audit: listet typische Autostart-/Persistenz-Orte (Run-Keys,
     Autostart-Ordner, Auto-Dienste, geplante Tasks) und markiert unsignierte
     bzw. Nicht-Microsoft-Einträge – genau dort nistet sich Malware ein.
  2) File-Integrity-Monitoring: legt eine SHA256-Baseline eines Verzeichnisses
     an und meldet beim nächsten Lauf neue/geänderte/gelöschte Dateien.

Read-only: es werden weder Autostart-Einträge entfernt noch Dateien verändert.
"""
import tkinter as tk
from tkinter import ttk
import threading
import json
import hashlib
from pathlib import Path
from datetime import datetime

from modules.base import BaseModule
from utils.theme import DARK


# Autostart-/Persistenz-Inventar als JSON. Signatur + Herausgeber je Eintrag.
_PERSIST_PS = r'''
$ErrorActionPreference = 'SilentlyContinue'
$out = New-Object System.Collections.ArrayList

function Test-Sig($exe) {
    if (-not $exe -or -not (Test-Path $exe)) { return "Pfad?" }
    $sig = Get-AuthenticodeSignature -FilePath $exe -ErrorAction SilentlyContinue
    if ($sig.Status -eq 'Valid') {
        $cn = $sig.SignerCertificate.Subject.Split(',')[0].Replace('CN=','')
        return "Signiert: $cn"
    } elseif ($sig.Status) { return "UNSIGNIERT ($($sig.Status))" }
    return "Unbekannt"
}
function Extract-Exe($cmd) {
    if (-not $cmd) { return "" }
    if ($cmd -match '"([^"]+\.exe)"') { return $matches[1] }
    if ($cmd -match '^([^\s]+\.exe)') { return $matches[1] }
    return ""
}

# Registry Run / RunOnce (HKLM + HKCU)
$runKeys = @(
  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
  'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
  'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
  'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
)
foreach ($k in $runKeys) {
    $item = Get-ItemProperty -Path $k -ErrorAction SilentlyContinue
    if ($item) {
        foreach ($p in $item.PSObject.Properties) {
            if ($p.Name -like 'PS*') { continue }
            $exe = Extract-Exe $p.Value
            [void]$out.Add([PSCustomObject]@{
                type="Run-Key"; location=$k.Replace('HKLM:','HKLM').Replace('HKCU:','HKCU')
                name=$p.Name; command="$($p.Value)"; signed=(Test-Sig $exe) })
        }
    }
}

# Autostart-Ordner
$startups = @(
  [Environment]::GetFolderPath('Startup'),
  [Environment]::GetFolderPath('CommonStartup')
)
foreach ($sd in $startups) {
    if ($sd -and (Test-Path $sd)) {
        Get-ChildItem -Path $sd -File -ErrorAction SilentlyContinue | ForEach-Object {
            [void]$out.Add([PSCustomObject]@{
                type="Startup-Ordner"; location=$sd; name=$_.Name
                command=$_.FullName; signed=(Test-Sig $_.FullName) })
        }
    }
}

# Auto-Start-Dienste (nur Nicht-Microsoft-Pfade hervorheben)
Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
  Where-Object { $_.StartMode -eq 'Auto' -and $_.PathName } | ForEach-Object {
    $exe = Extract-Exe $_.PathName
    $sig = Test-Sig $exe
    # Microsoft-signierte System32-Dienste überspringen, um Rauschen zu senken
    if ($sig -like 'Signiert: Microsoft*' -and $exe -like "$env:WINDIR\*") { return }
    [void]$out.Add([PSCustomObject]@{
        type="Dienst (Auto)"; location=$_.Name; name=$_.DisplayName
        command="$($_.PathName)"; signed=$sig })
}

# Geplante Tasks (Nicht-Microsoft)
Get-ScheduledTask -ErrorAction SilentlyContinue |
  Where-Object { $_.State -ne 'Disabled' -and $_.TaskPath -notlike '\Microsoft\*' } | ForEach-Object {
    $act = $_.Actions | Where-Object { $_.Execute } | Select-Object -First 1
    $exe = if ($act) { Extract-Exe $act.Execute } else { "" }
    if (-not $exe -and $act) { $exe = $act.Execute }
    [void]$out.Add([PSCustomObject]@{
        type="Geplanter Task"; location=$_.TaskPath; name=$_.TaskName
        command= if ($act) { "$($act.Execute) $($act.Arguments)" } else { "" }
        signed=(Test-Sig $exe) })
}

$out | ConvertTo-Json -Depth 3 -Compress
'''


class IntegrityMonitorModule(BaseModule):
    """Read-only Persistence-Audit + File-Integrity-Monitoring."""

    def _build(self):
        self._info_bar(
            self,
            "Persistenz-Orte (Autostart) prüfen und Datei-Integrität überwachen. "
            "Unsignierte / Nicht-Microsoft-Einträge werden rot markiert. Read-only.")

        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=6, pady=6)
        self._tab_persist = ttk.Frame(nb)
        self._tab_fim = ttk.Frame(nb)
        nb.add(self._tab_persist, text="  Persistence-Audit  ")
        nb.add(self._tab_fim, text="  Datei-Integrität  ")
        self._build_persist(self._tab_persist)
        self._build_fim(self._tab_fim)

    # ── Tab 1: Persistence ──────────────────────────────────────────────────────

    def _build_persist(self, parent):
        bar = tk.Frame(parent, bg=DARK["bg"]); bar.pack(fill="x", padx=10, pady=(8, 2))
        self._scan_btn = ttk.Button(bar, text="Autostart scannen",
                                     style="Accent.TButton", command=self._start_persist)
        self._scan_btn.pack(side="left")
        self._unsigned_only = tk.BooleanVar(value=False)
        ttk.Checkbutton(bar, text="Nur unsignierte/verdächtige",
                        variable=self._unsigned_only,
                        command=self._refilter_persist).pack(side="left", padx=(10, 0))
        self._report_btn = ttk.Button(bar, text="Verdächtige an Reporting",
                                       command=self._send_persist_report, state="disabled")
        self._report_btn.pack(side="left", padx=(10, 0))
        self._persist_sum = tk.StringVar(value="")
        tk.Label(bar, textvariable=self._persist_sum, bg=DARK["bg"], fg=DARK["border"],
                 font=("Segoe UI", 9, "bold")).pack(side="right", padx=8)

        sec = self._section_expand(parent, "Autostart- / Persistenz-Einträge")
        cols = ("type", "location", "name", "signed", "command")
        self._ptree = ttk.Treeview(sec, columns=cols, show="headings", selectmode="browse")
        for c, t, w in [("type", "Typ", 120), ("location", "Ort", 220),
                        ("name", "Name", 200), ("signed", "Signatur", 250),
                        ("command", "Befehl / Pfad", 420)]:
            self._ptree.heading(c, text=t)
            self._ptree.column(c, width=w, anchor="w")
        sb = ttk.Scrollbar(sec, command=self._ptree.yview)
        self._ptree.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self._ptree.pack(fill="both", expand=True, padx=6, pady=6)
        self._ptree.tag_configure("bad", foreground=DARK["red"])
        self._ptree.tag_configure("ok", foreground=DARK["fg"])
        self._persist_rows: list[dict] = []

    def _start_persist(self):
        self._scan_btn.configure(state="disabled")
        for iid in self._ptree.get_children():
            self._ptree.delete(iid)
        self._persist_sum.set("Scanne …")
        threading.Thread(target=self._run_persist, daemon=True).start()

    def _run_persist(self):
        data, err = self._ps_json(_PERSIST_PS)
        if not data and err:
            self.after(0, lambda: (self._scan_btn.configure(state="normal"),
                                   self._persist_sum.set(f"Fehler: {err}")))
            return
        self.after(0, self._render_persist, data)

    def _render_persist(self, data: list[dict]):
        self._persist_rows = data
        self._scan_btn.configure(state="normal")
        self._refilter_persist()

    @staticmethod
    def _is_suspicious(row: dict) -> bool:
        s = row.get("signed", "") or ""
        return ("UNSIGNIERT" in s) or ("Unbekannt" in s) or ("Pfad?" in s)

    def _refilter_persist(self):
        for iid in self._ptree.get_children():
            self._ptree.delete(iid)
        only_bad = self._unsigned_only.get()
        n_bad = 0
        rows = sorted(self._persist_rows,
                      key=lambda r: (0 if self._is_suspicious(r) else 1, r.get("type", "")))
        for r in rows:
            bad = self._is_suspicious(r)
            if bad:
                n_bad += 1
            if only_bad and not bad:
                continue
            self._ptree.insert("", "end", tags=("bad" if bad else "ok",), values=(
                r.get("type", ""), r.get("location", ""), r.get("name", ""),
                r.get("signed", ""), r.get("command", "")))
        self._persist_sum.set(
            f"{len(self._persist_rows)} Einträge · {n_bad} verdächtig")
        if n_bad:
            self._report_btn.configure(state="normal")
        if self._activity_cb:
            self._activity_cb(
                f"Persistence-Audit: {len(self._persist_rows)} Einträge, {n_bad} verdächtig")

    def _send_persist_report(self):
        sent = 0
        for r in self._persist_rows:
            if not self._is_suspicious(r):
                continue
            title = f"[Persistence] {r.get('type','')}: {r.get('name','')}"
            desc = (f"Ort: {r.get('location','')}\nBefehl/Pfad: {r.get('command','')}\n"
                    f"Signatur: {r.get('signed','')}\n\n"
                    "Empfehlung: Autostart-Eintrag verifizieren; bei unbekanntem/unsigniertem "
                    "Ursprung Datei in Defender/VirusTotal prüfen und ggf. entfernen.")
            if self._report_finding(title, "Hoch", desc):
                sent += 1
        if self._activity_cb:
            self._activity_cb(
                f"{sent} Persistence-Befund(e) an Reporting übergeben" if sent
                else "Reporting nicht verbunden / keine verdächtigen Einträge")

    # ── Tab 2: File-Integrity ───────────────────────────────────────────────────

    def _build_fim(self, parent):
        self._fim_dir = tk.StringVar(value="")
        self._entry_row(parent, "Verzeichnis:", self._fim_dir,
                        browse_fn=lambda: self._browse_dir(self._fim_dir))

        bar = tk.Frame(parent, bg=DARK["bg"]); bar.pack(fill="x", padx=10, pady=4)
        self._baseline_btn = ttk.Button(bar, text="Baseline erstellen",
                                         style="Accent.TButton",
                                         command=self._start_baseline)
        self._baseline_btn.pack(side="left")
        self._check_btn = ttk.Button(bar, text="Gegen Baseline prüfen",
                                      command=self._start_check)
        self._check_btn.pack(side="left", padx=(6, 0))
        tk.Label(bar, text="(Baseline wird im Workspace als JSON gespeichert)",
                 bg=DARK["bg"], fg=DARK["border"],
                 font=("Segoe UI", 8, "italic")).pack(side="left", padx=8)

        self._output = self._log_widget(parent, height=14)

    def _baseline_path(self, target: str) -> Path:
        ws = Path(self.cfg.get("workspace", str(Path.home() / "security-suite")))
        ws.mkdir(parents=True, exist_ok=True)
        safe = hashlib.md5(str(Path(target).resolve()).encode()).hexdigest()[:12]
        return ws / f"fim_baseline_{safe}.json"

    def _hash_dir(self, root: Path) -> dict:
        """SHA256 je Datei. Überspringt unlesbare Dateien."""
        result = {}
        for p in root.rglob("*"):
            if not p.is_file():
                continue
            try:
                h = hashlib.sha256()
                with open(p, "rb") as f:
                    for chunk in iter(lambda: f.read(1 << 20), b""):
                        h.update(chunk)
                result[str(p.relative_to(root))] = h.hexdigest()
            except Exception:
                result[str(p.relative_to(root)) if p.is_relative_to(root) else str(p)] = "<unlesbar>"
        return result

    def _start_baseline(self):
        target = self._fim_dir.get().strip()
        if not target or not Path(target).is_dir():
            self._log(self._output, "[!] Bitte gültiges Verzeichnis wählen.\n", "red")
            return
        self._baseline_btn.configure(state="disabled")
        self._log(self._output, f"$ Baseline für {target} …\n", "cyan")
        threading.Thread(target=self._do_baseline, args=(target,), daemon=True).start()

    def _do_baseline(self, target: str):
        try:
            root = Path(target)
            hashes = self._hash_dir(root)
            bp = self._baseline_path(target)
            bp.write_text(json.dumps(
                {"root": str(root.resolve()),
                 "created": datetime.now().isoformat(timespec="seconds"),
                 "files": hashes}, ensure_ascii=False), encoding="utf-8")
            self.after(0, self._log, self._output,
                       f"[+] Baseline gespeichert: {len(hashes)} Dateien → {bp}\n", "green")
        except Exception as e:
            self.after(0, self._log, self._output, f"[!] {e}\n", "red")
        finally:
            self.after(0, self._baseline_btn.configure, {"state": "normal"})

    def _start_check(self):
        target = self._fim_dir.get().strip()
        if not target or not Path(target).is_dir():
            self._log(self._output, "[!] Bitte gültiges Verzeichnis wählen.\n", "red")
            return
        bp = self._baseline_path(target)
        if not bp.exists():
            self._log(self._output,
                      "[!] Keine Baseline für dieses Verzeichnis. Erst 'Baseline erstellen'.\n", "red")
            return
        self._check_btn.configure(state="disabled")
        self._log(self._output, f"$ Prüfe {target} gegen Baseline …\n", "cyan")
        threading.Thread(target=self._do_check, args=(target, bp), daemon=True).start()

    def _do_check(self, target: str, bp: Path):
        try:
            base = json.loads(bp.read_text(encoding="utf-8"))
            old = base.get("files", {})
            new = self._hash_dir(Path(target))
            old_keys, new_keys = set(old), set(new)
            added = sorted(new_keys - old_keys)
            removed = sorted(old_keys - new_keys)
            changed = sorted(k for k in (old_keys & new_keys) if old[k] != new[k])

            self.after(0, self._log, self._output,
                       f"\n[i] Baseline vom {base.get('created','?')} — "
                       f"{len(added)} neu, {len(changed)} geändert, {len(removed)} gelöscht\n", "yellow")
            for k in added:
                self.after(0, self._log, self._output, f"  [NEU]      {k}\n", "green")
            for k in changed:
                self.after(0, self._log, self._output, f"  [GEÄNDERT] {k}\n", "orange")
            for k in removed:
                self.after(0, self._log, self._output, f"  [GELÖSCHT] {k}\n", "red")
            if not (added or changed or removed):
                self.after(0, self._log, self._output, "[+] Keine Änderungen — integer.\n", "green")
            if self._activity_cb:
                self._activity_cb(
                    f"FIM-Check: {len(added)} neu, {len(changed)} geändert, {len(removed)} gelöscht")
        except Exception as e:
            self.after(0, self._log, self._output, f"[!] {e}\n", "red")
        finally:
            self.after(0, self._check_btn.configure, {"state": "normal"})
