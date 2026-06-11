"""BaseModule – Basisklasse für alle G4MEOVER-Module."""
import tkinter as tk
from tkinter import ttk, filedialog
import subprocess
import threading
import os
import re
import json
from datetime import datetime
from pathlib import Path
from utils.theme import DARK

_ANSI = re.compile(r'\x1b\[[0-9;]*[mKHFABCDJh]|\r')


class _Tooltip:
    """Einfaches Hover-Tooltip für tkinter-Widgets."""
    def __init__(self, widget: tk.Widget, text: str):
        self._widget = widget
        self._text = text
        self._win: tk.Toplevel | None = None
        widget.bind("<Enter>", self._show)
        widget.bind("<Leave>", self._hide)
        widget.bind("<ButtonPress>", self._hide)

    def _show(self, _event=None):
        if self._win or not self._text:
            return
        x = self._widget.winfo_rootx() + 20
        y = self._widget.winfo_rooty() + self._widget.winfo_height() + 4
        self._win = tw = tk.Toplevel(self._widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{x}+{y}")
        tk.Label(tw, text=self._text, justify="left",
                 bg="#45475a", fg="#cdd6f4",
                 font=("Segoe UI", 8), relief="flat",
                 padx=8, pady=4, wraplength=360).pack()

    def _hide(self, _event=None):
        if self._win:
            self._win.destroy()
            self._win = None


def strip_ansi(text: str) -> str:
    return _ANSI.sub('', text)


class BaseModule(ttk.Frame):
    """Gemeinsame Basis für alle Pentesting-Module."""

    def __init__(self, parent, cfg: dict, target_var: tk.StringVar,
                 activity_cb=None, tools: dict | None = None):
        super().__init__(parent)
        self.configure(style="TFrame")
        self.cfg = cfg
        self._target_var = target_var       # globaler Ziel-Context
        self._activity_cb = activity_cb     # → Dashboard-Activity-Log
        self._tools = tools or {}           # tool_name → path
        self._running_proc: subprocess.Popen | None = None
        self._report_cb = None              # → ReportingModule.add_finding (lazy gesetzt)
        self._build()

    # ── Überschreiben in Unterklassen ─────────────────────────────────────────

    def _build(self):
        """Wird im Konstruktor aufgerufen. Unterklassen bauen hier die UI auf."""
        pass

    # ── Gemeinsame Widget-Helfer ───────────────────────────────────────────────

    def _tooltip(self, widget: tk.Widget, text: str) -> "_Tooltip":
        """Hängt ein Hover-Tooltip an ein Widget."""
        return _Tooltip(widget, text)

    def _info_bar(self, parent, text: str):
        """Zeigt eine blaue Info-Zeile am oberen Rand eines Frames."""
        tk.Label(parent, text=f"ℹ  {text}",
                 bg=DARK["panel"], fg=DARK["accent"],
                 font=("Segoe UI", 8), anchor="w",
                 padx=10, pady=3).pack(fill="x")

    def _section(self, parent, title: str) -> ttk.LabelFrame:
        lf = ttk.LabelFrame(parent, text=f"  {title}  ", padding=(0, 4, 0, 6))
        lf.pack(fill="x", padx=8, pady=4)
        return lf

    def _section_expand(self, parent, title: str) -> ttk.LabelFrame:
        """Section die fill=both + expand hat (für Log-Widgets)."""
        lf = ttk.LabelFrame(parent, text=f"  {title}  ", padding=(0, 4, 0, 6))
        lf.pack(fill="both", expand=True, padx=8, pady=4)
        return lf

    def _log_widget(self, parent, height=8) -> tk.Text:
        frame = self._section_expand(parent, "Output")
        txt = tk.Text(frame, bg=DARK["panel"], fg=DARK["fg"],
                      font=("Consolas", 9), relief="flat",
                      wrap="word", height=height)
        sb = ttk.Scrollbar(frame, command=txt.yview)
        txt.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        txt.pack(fill="both", expand=True, padx=6, pady=6)
        for tag, color in [("green", DARK["green"]), ("red", DARK["red"]),
                           ("yellow", DARK["yellow"]), ("cyan", DARK["accent"]),
                           ("orange", DARK["orange"]), ("purple", DARK["purple"])]:
            txt.tag_configure(tag, foreground=color)
        return txt

    def _entry_row(self, parent, label: str, var: tk.StringVar,
                   browse_fn=None, placeholder="") -> tk.Entry:
        row = tk.Frame(parent, bg=DARK["bg"]); row.pack(fill="x", padx=10, pady=4)
        if label:
            tk.Label(row, text=label, bg=DARK["bg"], fg=DARK["fg"],
                     font=("Segoe UI", 9), width=16, anchor="w").pack(side="left")
        e = tk.Entry(row, textvariable=var, bg=DARK["entry"], fg=DARK["fg"],
                     insertbackground=DARK["fg"], relief="flat", font=("Segoe UI", 9))
        e.pack(side="left", fill="x", expand=True, ipady=4)
        if browse_fn:
            ttk.Button(row, text="…", command=browse_fn).pack(side="left", padx=(4, 0))
        return e

    # ── Logging ───────────────────────────────────────────────────────────────

    def _log(self, widget: tk.Text, text: str, tag: str | None = None):
        """Schreibt in lokales Log + sendet an Dashboard-Activity-Log."""
        line_count = int(widget.index("end-1c").split(".")[0])
        if line_count > 2000:
            widget.delete("1.0", "1001.0")
        widget.insert("end", text, tag or "")
        widget.see("end")
        if self._activity_cb and text.strip():
            ts = datetime.now().strftime("%H:%M:%S")
            self._activity_cb(f"[{ts}] {self.__class__.__name__}: {text.strip()[:80]}")

    def _log_clear(self, widget: tk.Text):
        widget.delete("1.0", "end")

    # ── Tool-Runner ───────────────────────────────────────────────────────────

    def _run_tool(self, cmd: list[str], cwd: str | None,
                  log_widget: tk.Text,
                  on_line=None, on_done=None,
                  start_btn=None, stop_btn=None):
        """Startet ein externes Tool in einem Background-Thread."""
        if start_btn:
            start_btn.configure(state="disabled")
        if stop_btn:
            stop_btn.configure(state="normal")
        self._log(log_widget, f"$ {' '.join(cmd)}\n\n", "cyan")
        threading.Thread(
            target=self._exec_tool,
            args=(cmd, cwd, log_widget, on_line, on_done, start_btn, stop_btn),
            daemon=True
        ).start()

    def _exec_tool(self, cmd, cwd, log_widget,
                   on_line, on_done, start_btn, stop_btn):
        try:
            self._running_proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, cwd=cwd,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            for line in self._running_proc.stdout:
                line = strip_ansi(line)
                if not line.strip():
                    continue
                tag = self._auto_tag(line)
                self.after(0, self._log, log_widget, line + "\n", tag)
                if on_line:
                    self.after(0, on_line, line)
            self._running_proc.wait()
            rc = self._running_proc.returncode
        except Exception as e:
            self.after(0, self._log, log_widget, f"\n[!] {e}\n", "red")
            rc = -1
        finally:
            self._running_proc = None
            if start_btn:
                self.after(0, start_btn.configure, {"state": "normal"})
            if stop_btn:
                self.after(0, stop_btn.configure, {"state": "disabled"})
        if on_done:
            self.after(0, on_done, rc)

    def _stop_tool(self):
        if self._running_proc:
            self._running_proc.terminate()

    def _auto_tag(self, line: str) -> str | None:
        """Automatisches Farb-Tagging anhand von Schlüsselwörtern."""
        ll = line.lower()
        if any(k in ll for k in ("error", "failed", "fatal", "no such")):
            return "red"
        if any(k in ll for k in ("warning", "warn")):
            return "yellow"
        if any(k in ll for k in ("open", "found", "success", "cracked", "+")):
            return "green"
        if any(k in ll for k in ("filtered", "closed")):
            return "orange"
        return None

    # ── Datei-Dialoge ─────────────────────────────────────────────────────────

    def _browse_file(self, var: tk.StringVar, title: str,
                     filetypes: list | None = None):
        path = filedialog.askopenfilename(
            title=title,
            filetypes=filetypes or [("Alle", "*")])
        if path:
            var.set(path)

    def _browse_dir(self, var: tk.StringVar, title="Verzeichnis auswählen"):
        d = filedialog.askdirectory(title=title)
        if d:
            var.set(d)

    def _save_file(self, var: tk.StringVar, title: str,
                   default_ext: str, filetypes: list | None = None):
        path = filedialog.asksaveasfilename(
            title=title, defaultextension=default_ext,
            filetypes=filetypes or [("Alle", "*")])
        if path:
            var.set(path)
        return path

    # ── Tool-Check ────────────────────────────────────────────────────────────

    def _tool_path(self, name: str) -> str:
        """Gibt Pfad zurück oder '' wenn nicht installiert."""
        return self._tools.get(name, "")

    def _require_tool(self, name: str, log_widget: tk.Text) -> str | None:
        """Gibt Pfad zurück oder loggt Fehler und gibt None zurück."""
        path = self._tool_path(name)
        if not path:
            self._log(log_widget,
                      f"[!] {name} nicht gefunden. Bitte in Einstellungen konfigurieren.\n",
                      "red")
        return path or None

    # ── PowerShell-Helper (read-only Audits) ────────────────────────────────────

    def _ps_json(self, ps_script: str, timeout: int = 120) -> tuple[list, str]:
        """Führt ein PowerShell-Skript aus und parst dessen JSON-Ausgabe.

        Erzwingt UTF-8 (PS-Ausgabe + Python-Dekodierung), damit Umlaute und
        beliebige Event-Log-Inhalte nicht den cp1252-Decoder sprengen.
        Rückgabe: (data, error). error == '' bei Erfolg; data ist immer eine Liste.
        """
        full = ("[Console]::OutputEncoding = [System.Text.Encoding]::UTF8\n"
                + ps_script)
        try:
            proc = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive",
                 "-ExecutionPolicy", "Bypass", "-Command", full],
                capture_output=True, text=True,
                encoding="utf-8", errors="replace",
                creationflags=subprocess.CREATE_NO_WINDOW, timeout=timeout)
        except Exception as e:
            return [], str(e)
        out = (proc.stdout or "").strip()
        if not out:
            return [], (proc.stderr or "").strip()
        try:
            data = json.loads(out)
        except Exception as e:
            return [], f"JSON-Fehler: {e}"
        if isinstance(data, dict):
            data = [data]
        return data, ""

    def _report_finding(self, title: str, severity: str,
                        description: str = "", evidence: str = "") -> bool:
        """Schickt ein Finding ans Reporting-Modul, falls verdrahtet.

        Rückgabe: True wenn übergeben, False wenn kein Reporting verbunden.
        """
        if self._report_cb:
            self._report_cb(title, severity, description, evidence)
            return True
        return False
