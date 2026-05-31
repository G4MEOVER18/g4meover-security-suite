"""Reporting-Modul – Session-Timeline, Findings-Manager, Report-Generator."""
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import json
import re
from datetime import datetime
from pathlib import Path
from modules.base import BaseModule
from utils.theme import DARK, SEVERITY_COLORS


SEVERITY_LEVELS = ["Kritisch", "Hoch", "Mittel", "Niedrig", "Info"]

REPORT_TEMPLATE = """\
# Pentest-Report

**Erstellt:** {date}
**Ziel:** {target}
**Operator:** G4MEOVER Security Suite

---

## Zusammenfassung

{summary}

---

## Methodik

Die Untersuchung umfasste folgende Phasen:
- Netzwerk-Reconnaissance (nmap)
- Web-Applikationstests (gobuster, nikto, sqlmap)
- Passwort-Angriffe (hashcat, hydra)
- OSINT-Recherche

---

## Findings

{findings}

---

## Empfehlungen

{recommendations}

---

## Anhang: Session-Timeline

{timeline}
"""


class ReportingModule(BaseModule):

    def __init__(self, parent, cfg, target_var, activity_cb=None, tools=None):
        self._findings:  list[dict]  = []
        self._timeline:  list[dict]  = []
        super().__init__(parent, cfg, target_var, activity_cb, tools)

    def _build(self):
        self._info_bar(self,
            "Reporting: Findings dokumentieren · Session-Timeline · Pentest-Berichte als Markdown, HTML und TXT exportieren · Screenshots erstellen")

        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=4, pady=4)

        t1 = tk.Frame(nb, bg=DARK["bg"]); nb.add(t1, text="  Findings  ")
        t2 = tk.Frame(nb, bg=DARK["bg"]); nb.add(t2, text="  Timeline  ")
        t3 = tk.Frame(nb, bg=DARK["bg"]); nb.add(t3, text="  Report generieren  ")

        self._build_findings(t1)
        self._build_timeline(t2)
        self._build_generator(t3)

    # ═══════════════════════════════════════════════════════════════════════════
    # Tab 1 – Findings-Manager
    # ═══════════════════════════════════════════════════════════════════════════

    def _build_findings(self, parent):
        self._info_bar(parent,
            "Findings-Manager: Dokumentiert Schwachstellen mit Titel, Schweregrad (Kritisch/Hoch/Mittel/Niedrig/Info), Beschreibung und Beweis.")
        fin = self._section(parent, "Neues Finding")
        self._f_title = tk.StringVar()
        self._entry_row(fin, "Titel:", self._f_title)

        sev_row = tk.Frame(fin, bg=DARK["bg"]); sev_row.pack(fill="x", padx=10, pady=2)
        tk.Label(sev_row, text="Schweregrad:", bg=DARK["bg"], fg=DARK["fg"],
                 font=("Segoe UI", 8), width=12, anchor="w").pack(side="left")
        self._f_sev = ttk.Combobox(sev_row, state="readonly",
                                    values=SEVERITY_LEVELS, width=14,
                                    font=("Segoe UI", 8))
        self._f_sev.current(2)
        self._f_sev.pack(side="left", padx=4)

        tk.Label(fin, text="Beschreibung:", bg=DARK["bg"], fg=DARK["fg"],
                 font=("Segoe UI", 8)).pack(anchor="w", padx=10, pady=(4, 0))
        self._f_desc = tk.Text(fin, bg=DARK["entry"], fg=DARK["fg"],
                                insertbackground=DARK["fg"], relief="flat",
                                font=("Consolas", 8), height=4, wrap="word")
        self._f_desc.pack(fill="x", padx=10, pady=2)

        tk.Label(fin, text="Beweis (URL / Screenshot-Pfad):", bg=DARK["bg"], fg=DARK["fg"],
                 font=("Segoe UI", 8)).pack(anchor="w", padx=10)
        self._f_evidence = tk.StringVar()
        self._entry_row(fin, "", self._f_evidence)

        btn_row = tk.Frame(fin, bg=DARK["bg"]); btn_row.pack(fill="x", padx=10, pady=4)
        ttk.Button(btn_row, text="Finding hinzufügen",
                   style="Accent.TButton",
                   command=self._add_finding).pack(side="left")
        ttk.Button(btn_row, text="Ausgewähltes löschen",
                   style="Danger.TButton",
                   command=self._delete_finding).pack(side="left", padx=4)

        # Findings-Treeview
        cols = ("sev", "title", "evidence")
        self._find_tree = ttk.Treeview(parent, columns=cols, show="headings",
                                        selectmode="browse")
        for col, w, label in [("sev", 80, "Schweregrad"), ("title", 300, "Titel"),
                               ("evidence", 200, "Beweis")]:
            self._find_tree.heading(col, text=label)
            self._find_tree.column(col, width=w, minwidth=40)
        for sev, color in SEVERITY_COLORS.items():
            self._find_tree.tag_configure(sev, foreground=color)
        fsb = ttk.Scrollbar(parent, command=self._find_tree.yview)
        self._find_tree.configure(yscrollcommand=fsb.set)
        fsb.pack(side="right", fill="y")
        self._find_tree.pack(fill="both", expand=True, padx=6, pady=4)
        self._find_tree.bind("<Double-1>", self._on_finding_dclick)

    def _add_finding(self):
        title = self._f_title.get().strip()
        if not title:
            messagebox.showerror("Fehler", "Titel angeben."); return
        sev  = self._f_sev.get()
        desc = self._f_desc.get("1.0", "end").strip()
        evid = self._f_evidence.get().strip()
        ts   = datetime.now().strftime("%Y-%m-%d %H:%M")
        finding = {"title": title, "severity": sev, "description": desc,
                   "evidence": evid, "timestamp": ts}
        self._findings.append(finding)
        self._find_tree.insert("", "end",
                               values=(sev, title, evid or "—"),
                               tags=(sev,))
        self._f_title.set("")
        self._f_desc.delete("1.0", "end")
        self._f_evidence.set("")

    def _delete_finding(self):
        sel = self._find_tree.selection()
        if not sel:
            return
        idx = self._find_tree.index(sel[0])
        self._find_tree.delete(sel[0])
        if 0 <= idx < len(self._findings):
            self._findings.pop(idx)

    def _on_finding_dclick(self, _):
        sel = self._find_tree.selection()
        if not sel:
            return
        idx = self._find_tree.index(sel[0])
        if 0 <= idx < len(self._findings):
            f = self._findings[idx]
            self._f_title.set(f["title"])
            self._f_sev.set(f["severity"])
            self._f_desc.delete("1.0", "end")
            self._f_desc.insert("1.0", f["description"])
            self._f_evidence.set(f["evidence"])

    # ═══════════════════════════════════════════════════════════════════════════
    # Tab 2 – Session-Timeline
    # ═══════════════════════════════════════════════════════════════════════════

    def _build_timeline(self, parent):
        self._info_bar(parent,
            "Session-Timeline: Automatisch protokollierte Tool-Ausführungen dieser Sitzung. Wird in den Report eingebettet.")
        btn_row = tk.Frame(parent, bg=DARK["bg"]); btn_row.pack(fill="x", padx=10, pady=6)
        ttk.Button(btn_row, text="Eintrag hinzufügen",
                   command=self._add_timeline_entry).pack(side="left")
        ttk.Button(btn_row, text="Löschen",
                   command=self._del_timeline_entry).pack(side="left", padx=4)

        cols = ("time", "module", "action", "status")
        self._tl_tree = ttk.Treeview(parent, columns=cols, show="headings",
                                      selectmode="browse")
        for col, w, label in [("time", 100, "Zeit"), ("module", 120, "Modul"),
                               ("action", 360, "Aktion"), ("status", 70, "Status")]:
            self._tl_tree.heading(col, text=label)
            self._tl_tree.column(col, width=w, minwidth=40)
        self._tl_tree.tag_configure("ok",    foreground=DARK["green"])
        self._tl_tree.tag_configure("error", foreground=DARK["red"])
        tlsb = ttk.Scrollbar(parent, command=self._tl_tree.yview)
        self._tl_tree.configure(yscrollcommand=tlsb.set)
        tlsb.pack(side="right", fill="y")
        self._tl_tree.pack(fill="both", expand=True, padx=6, pady=4)

        # Manueller Eintrag
        me = self._section(parent, "Manueller Eintrag")
        mrow = tk.Frame(me, bg=DARK["bg"]); mrow.pack(fill="x", padx=10, pady=4)
        self._tl_mod = tk.StringVar(value="Manuell")
        tk.Entry(mrow, textvariable=self._tl_mod,
                 bg=DARK["entry"], fg=DARK["fg"],
                 insertbackground=DARK["fg"], relief="flat",
                 font=("Segoe UI", 8), width=14).pack(side="left", ipady=2)
        self._tl_action = tk.StringVar()
        tk.Entry(mrow, textvariable=self._tl_action,
                 bg=DARK["entry"], fg=DARK["fg"],
                 insertbackground=DARK["fg"], relief="flat",
                 font=("Segoe UI", 8), width=36).pack(side="left", padx=4, ipady=2)
        ttk.Button(mrow, text="+", command=self._add_timeline_entry).pack(side="left")

    def _add_timeline_entry(self, module: str = None, action: str = None,
                             status: str = "ok"):
        module = module or self._tl_mod.get()
        action = action or self._tl_action.get().strip()
        if not action:
            return
        ts = datetime.now().strftime("%H:%M:%S")
        entry = {"time": ts, "module": module, "action": action, "status": status}
        self._timeline.append(entry)
        self._tl_tree.insert("", "end",
                              values=(ts, module, action, status),
                              tags=(status,))
        self._tl_tree.see(self._tl_tree.get_children()[-1])
        self._tl_action.set("")

    def _del_timeline_entry(self):
        sel = self._tl_tree.selection()
        if not sel:
            return
        idx = self._tl_tree.index(sel[0])
        self._tl_tree.delete(sel[0])
        if 0 <= idx < len(self._timeline):
            self._timeline.pop(idx)

    def add_timeline_event(self, module: str, action: str, status: str = "ok"):
        self.after(0, self._add_timeline_entry, module, action, status)

    # ═══════════════════════════════════════════════════════════════════════════
    # Tab 3 – Report-Generator
    # ═══════════════════════════════════════════════════════════════════════════

    def _build_generator(self, parent):
        self._info_bar(parent,
            "Report-Generator: Fasst alle Findings + Timeline zusammen. Export als Markdown (.md), HTML (mit CSS-Styling) oder Plain-Text.")
        fmeta = self._section(parent, "Metadaten")
        self._rpt_summary = tk.Text(fmeta, bg=DARK["entry"], fg=DARK["fg"],
                                     insertbackground=DARK["fg"], relief="flat",
                                     font=("Consolas", 8), height=4, wrap="word")
        tk.Label(fmeta, text="Zusammenfassung:", bg=DARK["bg"], fg=DARK["fg"],
                 font=("Segoe UI", 8)).pack(anchor="w", padx=10, pady=(4, 0))
        self._rpt_summary.pack(fill="x", padx=10, pady=2)

        tk.Label(fmeta, text="Empfehlungen:", bg=DARK["bg"], fg=DARK["fg"],
                 font=("Segoe UI", 8)).pack(anchor="w", padx=10)
        self._rpt_recs = tk.Text(fmeta, bg=DARK["entry"], fg=DARK["fg"],
                                  insertbackground=DARK["fg"], relief="flat",
                                  font=("Consolas", 8), height=4, wrap="word")
        self._rpt_recs.pack(fill="x", padx=10, pady=(0, 6))

        btn_row = tk.Frame(parent, bg=DARK["bg"]); btn_row.pack(fill="x", padx=10, pady=8)
        ttk.Button(btn_row, text="Markdown (.md) generieren",
                   style="Accent.TButton",
                   command=lambda: self._generate("md")).pack(side="left")
        ttk.Button(btn_row, text="HTML (.html) generieren",
                   command=lambda: self._generate("html")).pack(side="left", padx=4)
        ttk.Button(btn_row, text="Text (.txt) generieren",
                   command=lambda: self._generate("txt")).pack(side="left")
        ttk.Button(btn_row, text="Screenshot",
                   command=self._take_screenshot).pack(side="right")

        self._rpt_preview = tk.Text(parent, bg=DARK["panel"], fg=DARK["fg"],
                                     font=("Consolas", 8), relief="flat",
                                     wrap="word", state="disabled")
        sb = ttk.Scrollbar(parent, command=self._rpt_preview.yview)
        self._rpt_preview.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self._rpt_preview.pack(fill="both", expand=True, padx=6, pady=4)

    def _build_findings_section(self) -> str:
        if not self._findings:
            return "_Keine Findings vorhanden._"
        lines = []
        for i, f in enumerate(self._findings, 1):
            lines.append(f"### {i}. {f['title']}")
            lines.append(f"**Schweregrad:** {f['severity']}  ")
            lines.append(f"**Zeitpunkt:** {f['timestamp']}  ")
            if f['description']:
                lines.append(f"\n{f['description']}\n")
            if f['evidence']:
                lines.append(f"**Beweis:** `{f['evidence']}`\n")
            lines.append("---")
        return "\n".join(lines)

    def _build_timeline_section(self) -> str:
        if not self._timeline:
            return "_Keine Timeline-Einträge vorhanden._"
        lines = ["| Zeit | Modul | Aktion | Status |",
                 "|------|-------|--------|--------|"]
        for t in self._timeline:
            lines.append(
                f"| {t['time']} | {t['module']} | {t['action']} | {t['status']} |")
        return "\n".join(lines)

    def _generate(self, fmt: str):
        summary = self._rpt_summary.get("1.0", "end").strip()
        recs    = self._rpt_recs.get("1.0", "end").strip()
        content = REPORT_TEMPLATE.format(
            date=datetime.now().strftime("%Y-%m-%d %H:%M"),
            target=self._target_var.get() or "—",
            summary=summary or "_Keine Zusammenfassung._",
            findings=self._build_findings_section(),
            recommendations=recs or "_Keine Empfehlungen._",
            timeline=self._build_timeline_section(),
        )

        if fmt == "html":
            content = self._md_to_html(content)
            ext, ftypes = ".html", [("HTML", "*.html")]
        elif fmt == "txt":
            content = re.sub(r"[#*`|_]", "", content)
            ext, ftypes = ".txt", [("Text", "*.txt")]
        else:
            ext, ftypes = ".md", [("Markdown", "*.md")]

        path = filedialog.asksaveasfilename(
            defaultextension=ext, filetypes=ftypes,
            title="Report speichern",
            initialfilename=f"pentest_report_{datetime.now().strftime('%Y%m%d')}{ext}")
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)

        self._rpt_preview.configure(state="normal")
        self._rpt_preview.delete("1.0", "end")
        self._rpt_preview.insert("1.0", content[:5000])
        self._rpt_preview.configure(state="disabled")

    def _md_to_html(self, md: str) -> str:
        import re as _re
        html = md
        html = _re.sub(r"^# (.+)$",    r"<h1>\1</h1>",    html, flags=_re.M)
        html = _re.sub(r"^## (.+)$",   r"<h2>\1</h2>",    html, flags=_re.M)
        html = _re.sub(r"^### (.+)$",  r"<h3>\1</h3>",    html, flags=_re.M)
        html = _re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", html)
        html = _re.sub(r"`(.+?)`",     r"<code>\1</code>",  html)
        html = html.replace("\n", "<br>\n")
        style = ("body{font-family:monospace;background:#1e1e2e;color:#cdd6f4;"
                 "padding:2rem;max-width:900px;margin:auto}"
                 "h1,h2,h3{color:#cba6f7}code{background:#313244;padding:2px 6px;"
                 "border-radius:4px}strong{color:#f38ba8}"
                 "table{border-collapse:collapse;width:100%}"
                 "td,th{border:1px solid #45475a;padding:6px 12px;text-align:left}"
                 "th{background:#313244;color:#cba6f7}"
                 ".critical{color:#f38ba8}.high{color:#fab387}"
                 ".medium{color:#f9e2af}.low{color:#a6e3a1}.info{color:#89dceb}")
        return f"<html><head><meta charset='utf-8'><style>{style}</style></head><body>{html}</body></html>"

    def _take_screenshot(self):
        from tkinter import filedialog
        path = filedialog.asksaveasfilename(
            defaultextension=".png",
            filetypes=[("PNG", "*.png"), ("Alle", "*.*")],
            title="Screenshot speichern",
            initialfilename=f"g4meover_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png")
        if not path:
            return
        try:
            from PIL import ImageGrab
            x = self.winfo_rootx()
            y = self.winfo_rooty()
            w = x + self.winfo_width()
            h = y + self.winfo_height()
            img = ImageGrab.grab(bbox=(x, y, w, h))
            img.save(path)
            messagebox.showinfo("Screenshot", f"Gespeichert: {path}")
        except ImportError:
            try:
                import subprocess, os
                self.update()
                flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
                subprocess.run(
                    ["powershell", "-Command",
                     f"Add-Type -AssemblyName System.Windows.Forms; "
                     f"[System.Windows.Forms.Screen]::PrimaryScreen | Out-Null; "
                     f"$bmp = New-Object System.Drawing.Bitmap("
                     f"[System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Width,"
                     f"[System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Height); "
                     f"$g = [System.Drawing.Graphics]::FromImage($bmp); "
                     f"$g.CopyFromScreen(0,0,0,0,$bmp.Size); "
                     f"$bmp.Save('{path}')"],
                    creationflags=flags, check=True)
                messagebox.showinfo("Screenshot", f"Gespeichert: {path}")
            except Exception as e:
                messagebox.showerror("Screenshot", f"Fehler: {e}\nTipp: pip install pillow")
