"""LogWatcherModule – Windows-Event-Log auf Angriffsspuren prüfen (read-only).

Liest sicherheitsrelevante Events aus dem lokalen Event-Log und stellt sie
übersichtlich dar. Reine Leseoperation – es werden keine Logs verändert oder
gelöscht. Einige Quellen (Security-Log) erfordern Administratorrechte.
"""
import tkinter as tk
from tkinter import ttk
import threading

from modules.base import BaseModule
from utils.theme import DARK


# Vordefinierte Abfragen. Jede liefert per Get-WinEvent ein JSON-Array.
# Platzhalter __DAYS__ wird durch das Zeitfenster ersetzt.
_QUERIES = {
    "Fehlgeschlagene Logins (4625)": {
        "log": "Security", "needs_admin": True,
        "ps": r'''
$start = (Get-Date).AddDays(-__DAYS__)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=$start} -ErrorAction Stop |
  Select-Object -First 300 | ForEach-Object {
    $x = [xml]$_.ToXml()
    $d = @{}; $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
    [PSCustomObject]@{
        time = $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
        id = $_.Id; sev = 'Hoch'
        src = "$($d['TargetUserName']) @ $($d['IpAddress'])"
        info = "Logon-Typ $($d['LogonType']) · Grund 0x$($d['SubStatus'])" }
  } | ConvertTo-Json -Depth 3 -Compress
'''},
    "Neue Dienste installiert (7045)": {
        "log": "System", "needs_admin": False,
        "ps": r'''
$start = (Get-Date).AddDays(-__DAYS__)
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045; StartTime=$start} -ErrorAction Stop |
  Select-Object -First 200 | ForEach-Object {
    $x = [xml]$_.ToXml()
    $d = @{}; $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
    [PSCustomObject]@{
        time = $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
        id = $_.Id; sev = 'Mittel'
        src = $d['ServiceName']
        info = "$($d['ImagePath'])  [Start: $($d['StartType'])]" }
  } | ConvertTo-Json -Depth 3 -Compress
'''},
    "PowerShell ScriptBlock (4104)": {
        "log": "PS-Operational", "needs_admin": False,
        "ps": r'''
$start = (Get-Date).AddDays(-__DAYS__)
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104; StartTime=$start} -ErrorAction Stop |
  Where-Object { $_.LevelDisplayName -ne 'Verbose' -or $_.Message -match 'Invoke|DownloadString|IEX|FromBase64|-enc|Bypass' } |
  Select-Object -First 200 | ForEach-Object {
    $snippet = ($_.Message -split "`n" | Select-Object -First 1)
    if ($snippet.Length -gt 160) { $snippet = $snippet.Substring(0,160) }
    $sev = if ($_.Message -match 'DownloadString|IEX|FromBase64|-enc|Bypass|Hidden') { 'Hoch' } else { 'Niedrig' }
    [PSCustomObject]@{
        time = $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
        id = $_.Id; sev = $sev; src = 'PowerShell'; info = $snippet }
  } | ConvertTo-Json -Depth 3 -Compress
'''},
    "Defender-Funde (1116/1117)": {
        "log": "Defender", "needs_admin": False,
        "ps": r'''
$start = (Get-Date).AddDays(-__DAYS__)
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational'; Id=1116,1117,1015,1006; StartTime=$start} -ErrorAction Stop |
  Select-Object -First 200 | ForEach-Object {
    $snippet = ($_.Message -split "`n" | Where-Object { $_ -match 'Name|Threat|Pfad|Path' } | Select-Object -First 1)
    if (-not $snippet) { $snippet = ($_.Message -split "`n")[0] }
    [PSCustomObject]@{
        time = $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
        id = $_.Id; sev = 'Kritisch'; src = 'Defender'; info = $snippet.Trim() }
  } | ConvertTo-Json -Depth 3 -Compress
'''},
}


class LogWatcherModule(BaseModule):
    """Read-only Event-Log-Audit für Angriffsspuren."""

    def _build(self):
        self._info_bar(
            self,
            "Liest sicherheitsrelevante Windows-Events (Login-Fehlschläge, neue Dienste, "
            "verdächtige PowerShell, Defender-Funde). Read-only. Security-Log braucht Adminrechte.")

        bar = tk.Frame(self, bg=DARK["bg"]); bar.pack(fill="x", padx=10, pady=(6, 2))
        tk.Label(bar, text="Kategorie:", bg=DARK["bg"], fg=DARK["fg"],
                 font=("Segoe UI", 9)).pack(side="left")
        self._cat = tk.StringVar(value=list(_QUERIES)[0])
        ttk.Combobox(bar, textvariable=self._cat, values=list(_QUERIES),
                     state="readonly", width=34).pack(side="left", padx=(4, 12))

        tk.Label(bar, text="Letzte", bg=DARK["bg"], fg=DARK["fg"],
                 font=("Segoe UI", 9)).pack(side="left")
        self._days = tk.IntVar(value=7)
        ttk.Spinbox(bar, from_=1, to=90, textvariable=self._days,
                    width=4).pack(side="left", padx=4)
        tk.Label(bar, text="Tage", bg=DARK["bg"], fg=DARK["fg"],
                 font=("Segoe UI", 9)).pack(side="left", padx=(0, 12))

        self._query_btn = ttk.Button(bar, text="Abfragen", style="Accent.TButton",
                                      command=self._start_query)
        self._query_btn.pack(side="left")

        self._sum = tk.StringVar(value="")
        tk.Label(bar, textvariable=self._sum, bg=DARK["bg"], fg=DARK["border"],
                 font=("Segoe UI", 9, "bold")).pack(side="right", padx=8)

        sec = self._section_expand(self, "Events")
        cols = ("time", "id", "sev", "src", "info")
        self._tree = ttk.Treeview(sec, columns=cols, show="headings", selectmode="browse")
        for c, t, w in [("time", "Zeit", 150), ("id", "ID", 60), ("sev", "Schwere", 90),
                        ("src", "Quelle / Konto", 240), ("info", "Information", 560)]:
            self._tree.heading(c, text=t)
            self._tree.column(c, width=w, anchor="w")
        sb = ttk.Scrollbar(sec, command=self._tree.yview)
        self._tree.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self._tree.pack(fill="both", expand=True, padx=6, pady=6)
        for sev, col in [("Kritisch", DARK["red"]), ("Hoch", DARK["orange"]),
                         ("Mittel", DARK["yellow"]), ("Niedrig", DARK["fg"])]:
            self._tree.tag_configure(sev, foreground=col)

    def _start_query(self):
        cat = self._cat.get()
        self._query_btn.configure(state="disabled")
        for iid in self._tree.get_children():
            self._tree.delete(iid)
        self._sum.set("Lese Event-Log …")
        if self._activity_cb:
            self._activity_cb(f"Event-Log-Abfrage: {cat}")
        threading.Thread(target=self._run_query, args=(cat, int(self._days.get())),
                         daemon=True).start()

    def _run_query(self, cat: str, days: int):
        q = _QUERIES[cat]
        ps = q["ps"].replace("__DAYS__", str(days))
        data, err = self._ps_json(ps)
        self.after(0, self._render, data, q, err)

    def _render(self, data: list[dict], q: dict, err: str):
        self._query_btn.configure(state="normal")
        if not data:
            if err:
                hint = "Security-Log: als Administrator starten." if q.get("needs_admin") else \
                       "Log evtl. nicht aktiviert oder leer."
                self._tree.insert("", "end", tags=("Niedrig",),
                                  values=("—", "—", "Info", "Keine Daten", hint))
                self._sum.set("Keine Events / kein Zugriff")
            else:
                self._sum.set("0 Events — unauffällig")
            return
        # Neueste zuerst
        for d in sorted(data, key=lambda x: x.get("time", ""), reverse=True):
            sev = d.get("sev", "Niedrig")
            self._tree.insert("", "end", tags=(sev,), values=(
                d.get("time", ""), d.get("id", ""), sev,
                d.get("src", ""), d.get("info", "")))
        self._sum.set(f"{len(data)} Event(s)")
        if self._activity_cb:
            self._activity_cb(f"Event-Log: {len(data)} Treffer")
