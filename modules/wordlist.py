"""Wordlist-Manager – Wortlisten laden, kombinieren, bereinigen, mutieren."""
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import subprocess
import os
from pathlib import Path
from modules.base import BaseModule
from utils.theme import DARK


# Häufig genutzte hashcat-Regeln (falls vorhanden)
_RULE_PRESETS = [
    ("Keine Regeln",          ""),
    ("best64.rule",           "best64.rule"),
    ("toggles1.rule",         "toggles1.rule"),
    ("dive.rule",             "dive.rule"),
    ("rockyou-30000.rule",    "rockyou-30000.rule"),
    ("d3ad0ne.rule",          "d3ad0ne.rule"),
    ("T0XlC.rule",            "T0XlC.rule"),
]


class WordlistModule(BaseModule):

    def _build(self):
        self._info_bar(self,
            "Wordlist-Manager – Wortlisten laden, kombinieren, deduplizieren, "
            "nach Länge filtern und Hashcat-Regeln anwenden.")

        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True)

        t1 = ttk.Frame(nb); nb.add(t1, text="  Manager  ")
        t2 = ttk.Frame(nb); nb.add(t2, text="  Kombinieren  ")
        t3 = ttk.Frame(nb); nb.add(t3, text="  Regeln / Mutationen  ")
        t4 = ttk.Frame(nb); nb.add(t4, text="  Crunch / Custom  ")

        self._build_manager(t1)
        self._build_combine(t2)
        self._build_rules(t3)
        self._build_crunch(t4)

        self._loaded_files: list[str] = []

    # ── Tab 1: Manager ────────────────────────────────────────────────────────

    def _build_manager(self, parent):
        self._info_bar(parent,
            "Wortliste laden und analysieren: Zeilen, eindeutige Einträge, Datei-Größe, Längen-Verteilung.")

        paned = tk.PanedWindow(parent, orient="horizontal",
                               bg=DARK["bg"], sashwidth=4)
        paned.pack(fill="both", expand=True, padx=4, pady=4)

        left  = tk.Frame(paned, bg=DARK["bg"]); paned.add(left,  minsize=280, width=320)
        right = tk.Frame(paned, bg=DARK["bg"]); paned.add(right, minsize=380)

        # Datei-Auswahl
        fv = self._section(left, "Wortliste")
        self._wl_path_var = tk.StringVar()
        self._entry_row(fv, "Datei:", self._wl_path_var,
                        browse_fn=lambda: self._browse_file(
                            self._wl_path_var, "Wortliste öffnen",
                            [("Text", "*.txt *.lst *.dict"), ("Alle", "*")]))

        # Filter
        ff = self._section(left, "Längen-Filter")
        self._min_len_var = tk.StringVar(value="0")
        self._max_len_var = tk.StringVar(value="0")
        self._entry_row(ff, "Min. Länge:", self._min_len_var)
        self._entry_row(ff, "Max. Länge:", self._max_len_var)
        tk.Label(ff, text="0 = kein Limit",
                 bg=DARK["bg"], fg=DARK["border"],
                 font=("Segoe UI", 7, "italic")).pack(anchor="w", padx=10, pady=(0, 4))

        # Optionen
        fo = self._section(left, "Optionen")
        self._dedup_var = tk.BooleanVar(value=True)
        self._sort_var  = tk.BooleanVar(value=False)
        self._lower_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(fo, text="Duplikate entfernen", variable=self._dedup_var).pack(anchor="w", padx=10, pady=2)
        ttk.Checkbutton(fo, text="Sortieren (A-Z)",     variable=self._sort_var).pack(anchor="w", padx=10, pady=2)
        ttk.Checkbutton(fo, text="Kleinschreibung",     variable=self._lower_var).pack(anchor="w", padx=10, pady=(2, 6))

        # Ausgabe
        fs = self._section(left, "Ausgabe")
        self._mgr_out_var = tk.StringVar()
        self._entry_row(fs, "Speichern:", self._mgr_out_var,
                        browse_fn=self._choose_mgr_out)

        # Buttons
        btn_f = tk.Frame(left, bg=DARK["bg"]); btn_f.pack(fill="x", padx=8, pady=8)
        ttk.Button(btn_f, text="Analysieren",
                   command=self._analyse_wordlist).pack(side="left", padx=(0, 4))
        ttk.Button(btn_f, text="Verarbeiten & Speichern",
                   style="Accent.TButton",
                   command=self._process_wordlist).pack(side="left")

        # Stats-Panel
        self._stats_frame = tk.Frame(left, bg=DARK["panel"],
                                     highlightthickness=1,
                                     highlightbackground=DARK["border"])
        self._stats_frame.pack(fill="x", padx=8, pady=4)
        self._stats_labels: dict[str, tk.StringVar] = {}
        for key in ("Datei", "Zeilen gesamt", "Eindeutig", "Dateigröße", "Kürzeste", "Längste"):
            row = tk.Frame(self._stats_frame, bg=DARK["panel"])
            row.pack(fill="x", padx=8, pady=1)
            tk.Label(row, text=f"{key}:", bg=DARK["panel"], fg=DARK["border"],
                     font=("Segoe UI", 8), width=14, anchor="w").pack(side="left")
            var = tk.StringVar(value="—")
            self._stats_labels[key] = var
            tk.Label(row, textvariable=var, bg=DARK["panel"], fg=DARK["fg"],
                     font=("Consolas", 8)).pack(side="left")

        # Output
        self._mgr_log = self._log_widget(right, height=20)

    def _analyse_wordlist(self):
        path = self._wl_path_var.get().strip()
        if not path or not Path(path).exists():
            messagebox.showerror("Fehler", "Datei nicht gefunden."); return
        threading.Thread(target=self._analyse_thread, args=(path,), daemon=True).start()

    def _analyse_thread(self, path: str):
        try:
            p = Path(path)
            size = p.stat().st_size
            lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
            total   = len(lines)
            unique  = len(set(lines))
            lengths = [len(l) for l in lines if l]
            shortest = min(lengths) if lengths else 0
            longest  = max(lengths) if lengths else 0

            self.after(0, self._stats_labels["Datei"].set, p.name)
            self.after(0, self._stats_labels["Zeilen gesamt"].set, f"{total:,}")
            self.after(0, self._stats_labels["Eindeutig"].set, f"{unique:,}")
            self.after(0, self._stats_labels["Dateigröße"].set, f"{size / 1024 / 1024:.2f} MB")
            self.after(0, self._stats_labels["Kürzeste"].set, str(shortest))
            self.after(0, self._stats_labels["Längste"].set, str(longest))

            self.after(0, self._log, self._mgr_log,
                       f"[✓] {p.name}:  {total:,} Zeilen, {unique:,} eindeutig, "
                       f"{size / 1024 / 1024:.2f} MB, "
                       f"Längen {shortest}–{longest}\n", "green")
        except Exception as e:
            self.after(0, self._log, self._mgr_log, f"[!] {e}\n", "red")

    def _process_wordlist(self):
        path = self._wl_path_var.get().strip()
        out  = self._mgr_out_var.get().strip()
        if not path or not Path(path).exists():
            messagebox.showerror("Fehler", "Eingabedatei nicht gefunden."); return
        if not out:
            messagebox.showerror("Fehler", "Ausgabedatei angeben."); return
        min_l = int(self._min_len_var.get() or 0)
        max_l = int(self._max_len_var.get() or 0)
        dedup = self._dedup_var.get()
        sort  = self._sort_var.get()
        lower = self._lower_var.get()
        threading.Thread(target=self._process_thread,
                         args=(path, out, min_l, max_l, dedup, sort, lower),
                         daemon=True).start()

    def _process_thread(self, path, out, min_l, max_l, dedup, sort, lower):
        try:
            lines = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
            if lower:
                lines = [l.lower() for l in lines]
            if min_l > 0:
                lines = [l for l in lines if len(l) >= min_l]
            if max_l > 0:
                lines = [l for l in lines if len(l) <= max_l]
            if dedup:
                seen = set(); result = []
                for l in lines:
                    if l not in seen:
                        seen.add(l); result.append(l)
                lines = result
            if sort:
                lines.sort()
            Path(out).write_text("\n".join(lines), encoding="utf-8")
            self.after(0, self._log, self._mgr_log,
                       f"[✓] Gespeichert: {out}  ({len(lines):,} Einträge)\n", "green")
        except Exception as e:
            self.after(0, self._log, self._mgr_log, f"[!] {e}\n", "red")

    def _choose_mgr_out(self):
        p = filedialog.asksaveasfilename(
            title="Ausgabe speichern",
            defaultextension=".txt",
            filetypes=[("Text", "*.txt"), ("Alle", "*")])
        if p:
            self._mgr_out_var.set(p)

    # ── Tab 2: Kombinieren ────────────────────────────────────────────────────

    def _build_combine(self, parent):
        self._info_bar(parent,
            "Mehrere Wortlisten zusammenführen, deduplizieren und sortieren.")

        left  = tk.Frame(parent, bg=DARK["bg"])
        right = tk.Frame(parent, bg=DARK["bg"])
        left.pack(side="left", fill="y", padx=(8, 4), pady=8)
        left.configure(width=340); left.pack_propagate(False)
        right.pack(side="left", fill="both", expand=True, padx=(4, 8), pady=8)

        fl = self._section(left, "Eingabe-Dateien")
        self._comb_listbox = tk.Listbox(fl, bg=DARK["entry"], fg=DARK["fg"],
                                         selectbackground=DARK["accent"],
                                         font=("Segoe UI", 9), height=8,
                                         relief="flat", activestyle="none")
        self._comb_listbox.pack(fill="both", expand=True, padx=6, pady=4)
        btn_row = tk.Frame(fl, bg=DARK["bg"]); btn_row.pack(fill="x", padx=6, pady=(0, 4))
        ttk.Button(btn_row, text="+ Hinzufügen",
                   command=self._comb_add_file).pack(side="left", padx=(0, 4))
        ttk.Button(btn_row, text="- Entfernen",
                   command=self._comb_remove).pack(side="left")

        fo = self._section(left, "Optionen")
        self._comb_dedup = tk.BooleanVar(value=True)
        self._comb_sort  = tk.BooleanVar(value=False)
        ttk.Checkbutton(fo, text="Duplikate entfernen", variable=self._comb_dedup).pack(anchor="w", padx=10, pady=2)
        ttk.Checkbutton(fo, text="Sortieren (A-Z)",     variable=self._comb_sort).pack(anchor="w", padx=10, pady=(2, 6))

        fs = self._section(left, "Ausgabe")
        self._comb_out_var = tk.StringVar()
        self._entry_row(fs, "Datei:", self._comb_out_var,
                        browse_fn=lambda: self._choose_out(self._comb_out_var))
        ttk.Button(left, text="Zusammenführen",
                   style="Accent.TButton",
                   command=self._combine_wordlists).pack(fill="x", padx=8, pady=8)

        self._comb_log = self._log_widget(right)

    def _comb_add_file(self):
        files = filedialog.askopenfilenames(
            title="Wortlisten hinzufügen",
            filetypes=[("Text", "*.txt *.lst *.dict"), ("Alle", "*")])
        for f in files:
            self._comb_listbox.insert("end", f)

    def _comb_remove(self):
        sel = self._comb_listbox.curselection()
        for i in reversed(sel):
            self._comb_listbox.delete(i)

    def _combine_wordlists(self):
        files = list(self._comb_listbox.get(0, "end"))
        if not files:
            messagebox.showerror("Fehler", "Keine Dateien ausgewählt."); return
        out = self._comb_out_var.get().strip()
        if not out:
            messagebox.showerror("Fehler", "Ausgabedatei angeben."); return
        dedup = self._comb_dedup.get()
        sort  = self._comb_sort.get()
        threading.Thread(target=self._combine_thread,
                         args=(files, out, dedup, sort), daemon=True).start()

    def _combine_thread(self, files, out, dedup, sort):
        try:
            all_lines = []
            for f in files:
                try:
                    lines = Path(f).read_text(encoding="utf-8", errors="replace").splitlines()
                    all_lines.extend(lines)
                    self.after(0, self._log, self._comb_log,
                               f"[+] {f}  ({len(lines):,} Zeilen)\n")
                except Exception as e:
                    self.after(0, self._log, self._comb_log,
                               f"[!] {f}: {e}\n", "red")
            if dedup:
                seen = set(); result = []
                for l in all_lines:
                    if l not in seen:
                        seen.add(l); result.append(l)
                all_lines = result
            if sort:
                all_lines.sort()
            Path(out).write_text("\n".join(all_lines), encoding="utf-8")
            self.after(0, self._log, self._comb_log,
                       f"\n[✓] Zusammengeführt: {out}  ({len(all_lines):,} Einträge)\n",
                       "green")
        except Exception as e:
            self.after(0, self._log, self._comb_log, f"[!] {e}\n", "red")

    # ── Tab 3: Regeln / Mutationen ────────────────────────────────────────────

    def _build_rules(self, parent):
        self._info_bar(parent,
            "hashcat --stdout: Wortliste + Regel-Datei → mutierte Kandidaten generieren.")

        left  = tk.Frame(parent, bg=DARK["bg"])
        right = tk.Frame(parent, bg=DARK["bg"])
        left.pack(side="left", fill="y", padx=(8, 4), pady=8)
        left.configure(width=340); left.pack_propagate(False)
        right.pack(side="left", fill="both", expand=True, padx=(4, 8), pady=8)

        fw = self._section(left, "Wortliste")
        self._rules_wl_var = tk.StringVar()
        self._entry_row(fw, "Datei:", self._rules_wl_var,
                        browse_fn=lambda: self._browse_file(
                            self._rules_wl_var, "Wortliste",
                            [("Text", "*.txt *.lst"), ("Alle", "*")]))

        fr = self._section(left, "Regel-Datei")
        self._rule_preset_var = tk.StringVar()
        preset_cb = ttk.Combobox(fr, textvariable=self._rule_preset_var,
                                  state="readonly", font=("Segoe UI", 9),
                                  values=[r[0] for r in _RULE_PRESETS])
        preset_cb.current(0)
        preset_cb.pack(fill="x", padx=10, pady=4)
        preset_cb.bind("<<ComboboxSelected>>", self._on_rule_preset)

        self._rule_path_var = tk.StringVar()
        self._entry_row(fr, "Eigene:", self._rule_path_var,
                        browse_fn=lambda: self._browse_file(
                            self._rule_path_var, "Rule-Datei",
                            [("Rule", "*.rule"), ("Alle", "*")]))
        tk.Label(fr, text="Eigene Regel überschreibt Preset",
                 bg=DARK["bg"], fg=DARK["border"],
                 font=("Segoe UI", 7, "italic")).pack(anchor="w", padx=10, pady=(0, 4))

        fo = self._section(left, "Optionen")
        self._rules_limit_var = tk.StringVar(value="0")
        self._entry_row(fo, "Max. Kandidaten:", self._rules_limit_var)
        tk.Label(fo, text="0 = alle",
                 bg=DARK["bg"], fg=DARK["border"],
                 font=("Segoe UI", 7, "italic")).pack(anchor="w", padx=10)

        fs = self._section(left, "Ausgabe")
        self._rules_out_var = tk.StringVar()
        self._entry_row(fs, "Datei:", self._rules_out_var,
                        browse_fn=lambda: self._choose_out(self._rules_out_var))

        btn_f = tk.Frame(left, bg=DARK["bg"]); btn_f.pack(fill="x", padx=8, pady=8)
        self._rules_start = ttk.Button(btn_f, text="Generieren",
                                        style="Accent.TButton",
                                        command=self._run_rules)
        self._rules_start.pack(side="left", padx=(0, 4))
        self._rules_stop = ttk.Button(btn_f, text="Stopp",
                                       style="Danger.TButton",
                                       command=self._stop_tool, state="disabled")
        self._rules_stop.pack(side="left")

        self._rules_log = self._log_widget(right)

    def _on_rule_preset(self, _event=None):
        idx = [r[0] for r in _RULE_PRESETS].index(self._rule_preset_var.get())
        if idx == 0:
            self._rule_path_var.set("")
        # Preset-Namen nur setzen wenn kein eigener Pfad angegeben
        if not self._rule_path_var.get():
            self._rule_path_var.set(_RULE_PRESETS[idx][1])

    def _run_rules(self):
        hc = self._tool_path("hashcat")
        if not hc:
            self._log(self._rules_log, "[!] hashcat nicht gefunden.\n", "red"); return
        wl = self._rules_wl_var.get().strip()
        if not wl or not Path(wl).exists():
            messagebox.showerror("Fehler", "Wortliste nicht gefunden."); return
        rule = self._rule_path_var.get().strip()
        out  = self._rules_out_var.get().strip()
        if not out:
            messagebox.showerror("Fehler", "Ausgabedatei angeben."); return

        cmd = [hc, "--stdout", "-a", "0", wl]
        if rule:
            # Regel-Datei suchen: erst absolut, dann in hashcat-Verzeichnis
            rule_path = Path(rule)
            if not rule_path.is_absolute():
                hc_dir = Path(hc).parent
                rule_path = hc_dir / "rules" / rule
            cmd += ["-r", str(rule_path)]

        self._log(self._rules_log, f"$ {' '.join(cmd)}\n\n", "cyan")

        limit = int(self._rules_limit_var.get() or 0)
        self._run_tool(
            cmd=cmd, cwd=str(Path(hc).parent),
            log_widget=self._rules_log,
            on_done=lambda rc: self._rules_on_done(rc, out, limit),
            start_btn=self._rules_start, stop_btn=self._rules_stop)

    def _rules_on_done(self, rc, out, limit):
        self._log(self._rules_log,
                  f"[!] Ausgabe automatisch in Datei speichern nicht unterstützt "
                  f"(hashcat --stdout schreibt in Terminal).\n"
                  f"Tipp: Starte in PowerShell:  hashcat --stdout ... > {out}\n",
                  "yellow")

    # ── Tab 4: Crunch / Custom ────────────────────────────────────────────────

    def _build_crunch(self, parent):
        self._info_bar(parent,
            "Crunch: Eigene Zeichenmengen und Längen-Kombinationen generieren. "
            "Alternativ: Muster-basierte Wortliste via Python.")

        left  = tk.Frame(parent, bg=DARK["bg"])
        right = tk.Frame(parent, bg=DARK["bg"])
        left.pack(side="left", fill="y", padx=(8, 4), pady=8)
        left.configure(width=340); left.pack_propagate(False)
        right.pack(side="left", fill="both", expand=True, padx=(4, 8), pady=8)

        # Crunch-Optionen
        fc = self._section(left, "Crunch-Parameter")
        self._crunch_min_var = tk.StringVar(value="6")
        self._crunch_max_var = tk.StringVar(value="8")
        self._crunch_cs_var  = tk.StringVar(value="abcdefghijklmnopqrstuvwxyz0123456789")
        self._crunch_pat_var = tk.StringVar(value="")
        self._entry_row(fc, "Min. Länge:", self._crunch_min_var)
        self._entry_row(fc, "Max. Länge:", self._crunch_max_var)
        self._entry_row(fc, "Zeichensatz:", self._crunch_cs_var)
        self._entry_row(fc, "Muster (@=%l,,%u,%%d):", self._crunch_pat_var)
        tk.Label(fc, text="@=Kleinb.  ,=Großb.  %%=Ziffer  ^=Sonderz.",
                 bg=DARK["bg"], fg=DARK["border"],
                 font=("Segoe UI", 7, "italic")).pack(anchor="w", padx=10, pady=(0, 4))

        fs = self._section(left, "Ausgabe")
        self._crunch_out_var = tk.StringVar()
        self._entry_row(fs, "Datei:", self._crunch_out_var,
                        browse_fn=lambda: self._choose_out(self._crunch_out_var))

        # Python-Generator (kein crunch nötig)
        fp = self._section(left, "Python-Generator (kein crunch nötig)")
        self._pycrunch_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(fp, text="Python-intern generieren",
                        variable=self._pycrunch_var).pack(anchor="w", padx=10, pady=(4, 2))
        self._pycrunch_limit_var = tk.StringVar(value="1000000")
        self._entry_row(fp, "Max. Kandidaten:", self._pycrunch_limit_var)

        btn_f = tk.Frame(left, bg=DARK["bg"]); btn_f.pack(fill="x", padx=8, pady=8)
        ttk.Button(btn_f, text="Generieren", style="Accent.TButton",
                   command=self._run_crunch).pack(side="left")

        self._crunch_log = self._log_widget(right)

    def _run_crunch(self):
        out = self._crunch_out_var.get().strip()
        if not out:
            messagebox.showerror("Fehler", "Ausgabedatei angeben."); return

        if self._pycrunch_var.get():
            # Python-interne Generierung (kein crunch benötigt)
            threading.Thread(target=self._pycrunch_thread, args=(out,), daemon=True).start()
            return

        # Externe crunch-Binary
        crunch = "crunch"
        min_l  = self._crunch_min_var.get().strip()
        max_l  = self._crunch_max_var.get().strip()
        cs     = self._crunch_cs_var.get().strip()
        pat    = self._crunch_pat_var.get().strip()
        cmd    = ["crunch", min_l, max_l, cs, "-o", out]
        if pat:
            cmd += ["-t", pat]
        self._log(self._crunch_log, f"$ {' '.join(cmd)}\n\n", "cyan")
        self._run_tool(cmd, None, self._crunch_log)

    def _pycrunch_thread(self, out: str):
        import itertools
        cs    = self._crunch_cs_var.get().strip()
        min_l = int(self._crunch_min_var.get() or 1)
        max_l = int(self._crunch_max_var.get() or min_l)
        limit = int(self._pycrunch_limit_var.get() or 1_000_000)
        if not cs:
            self.after(0, self._log, self._crunch_log, "[!] Zeichensatz leer.\n", "red")
            return
        self.after(0, self._log, self._crunch_log,
                   f"[*] Generiere Kombinationen (Länge {min_l}–{max_l}, max {limit:,})\n", "cyan")
        try:
            count = 0
            with open(out, "w", encoding="utf-8") as fh:
                for length in range(min_l, max_l + 1):
                    for combo in itertools.product(cs, repeat=length):
                        fh.write("".join(combo) + "\n")
                        count += 1
                        if count % 100_000 == 0:
                            self.after(0, self._log, self._crunch_log,
                                       f"  … {count:,} generiert\n")
                        if count >= limit:
                            break
                    else:
                        continue
                    break
            self.after(0, self._log, self._crunch_log,
                       f"[✓] Fertig: {out}  ({count:,} Einträge)\n", "green")
        except Exception as e:
            self.after(0, self._log, self._crunch_log, f"[!] {e}\n", "red")

    # ── Hilfsfunktionen ───────────────────────────────────────────────────────

    def _choose_out(self, var: tk.StringVar):
        p = filedialog.asksaveasfilename(
            title="Ausgabe speichern",
            defaultextension=".txt",
            filetypes=[("Text", "*.txt"), ("Alle", "*")])
        if p:
            var.set(p)
