"""LocalHashesModule – Lokaler Passwort-Audit über NTLM-Hashes (eigenes System).

Workflow (nur EIGENES System, Adminrechte erforderlich):
  1) SAM- und SYSTEM-Hive sichern (reg save) – nur als Administrator
  2) NTLM-Hashes der lokalen Konten extrahieren (impacket secretsdump)
  3) Hashes gegen eine Wordlist testen (hashcat -m 1000)
  4) Geknackte Passwörter im Klartext anzeigen → schwache Konto-Passwörter finden
  5) Hive-Sicherungen + Hash-Datei werden wieder gelöscht

Zeigt, welche lokalen Konten ein in einer Wordlist enthaltenes (schwaches)
Passwort haben. Dient dem Härten der eigenen Konten.
"""
import tkinter as tk
from tkinter import ttk
import threading
import subprocess
import os
import re
import tempfile
import shutil
from pathlib import Path

from modules.base import BaseModule
from utils.theme import DARK


def _is_admin() -> bool:
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _find_secretsdump() -> str | None:
    """Sucht secretsdump (impacket) im PATH / in den Python-Scripts."""
    for cand in ("secretsdump.py", "secretsdump.exe", "secretsdump"):
        p = shutil.which(cand)
        if p:
            return p
    # Python-Scripts-Verzeichnis
    import sys
    scripts = Path(sys.executable).parent / "Scripts"
    for cand in ("secretsdump.py", "secretsdump.exe"):
        if (scripts / cand).exists():
            return str(scripts / cand)
    return None


class LocalHashesModule(BaseModule):
    """Lokaler NTLM-Hash-Passwort-Audit für die eigenen Konten."""

    def _build(self):
        self._info_bar(
            self,
            "Lokaler Passwort-Audit des EIGENEN Systems: extrahiert NTLM-Hashes der lokalen Konten "
            "und testet sie gegen eine Wordlist, um schwache Passwörter zu finden. "
            "Benötigt Administratorrechte. Hive-Sicherungen werden danach gelöscht.")

        # Status-Zeile (Admin / Tools)
        st = tk.Frame(self, bg=DARK["bg"]); st.pack(fill="x", padx=10, pady=(6, 0))
        self._admin = _is_admin()
        self._sdump = _find_secretsdump()
        self._hashcat = self._tool_path("hashcat")
        admin_txt = "Administrator ✓" if self._admin else "KEINE Adminrechte ✗"
        sdump_txt = "secretsdump ✓" if self._sdump else "impacket fehlt ✗"
        hc_txt = "hashcat ✓" if self._hashcat else "hashcat fehlt ✗"
        tk.Label(st, text=f"Voraussetzungen:  {admin_txt}   ·   {sdump_txt}   ·   {hc_txt}",
                 bg=DARK["bg"],
                 fg=DARK["green"] if (self._admin and self._sdump and self._hashcat) else DARK["yellow"],
                 font=("Segoe UI", 9, "bold")).pack(side="left")
        if not self._sdump:
            ttk.Button(st, text="impacket installieren (pip)",
                       command=self._install_impacket).pack(side="right")

        # Wordlist-Auswahl
        self._wordlist = tk.StringVar(value=self.cfg.get("default_wordlist", ""))
        self._entry_row(self, "Wordlist:", self._wordlist,
                        browse_fn=lambda: self._browse_file(
                            self._wordlist, "Wordlist wählen",
                            [("Wortlisten", "*.txt;*.lst;*.dict"), ("Alle", "*")]))

        bar = tk.Frame(self, bg=DARK["bg"]); bar.pack(fill="x", padx=10, pady=4)
        self._run_btn = ttk.Button(bar, text="Passwort-Audit starten",
                                    style="Accent.TButton", command=self._start)
        self._run_btn.pack(side="left")
        self._stop_btn = ttk.Button(bar, text="Stop", style="Danger.TButton",
                                    command=self._stop_tool, state="disabled")
        self._stop_btn.pack(side="left", padx=(6, 0))
        self._show = tk.BooleanVar(value=True)
        ttk.Checkbutton(bar, text="Passwörter im Klartext", variable=self._show,
                        command=self._render_cracked).pack(side="left", padx=(10, 0))
        self._sum = tk.StringVar(value="")
        tk.Label(bar, textvariable=self._sum, bg=DARK["bg"], fg=DARK["border"],
                 font=("Segoe UI", 9, "bold")).pack(side="right", padx=8)

        # Ergebnis: geknackte Konten
        sec = self._section(self, "Geknackte Konten (schwache Passwörter)")
        cols = ("user", "password")
        self._tree = ttk.Treeview(sec, columns=cols, show="headings", height=6,
                                  selectmode="browse")
        self._tree.heading("user", text="Konto")
        self._tree.column("user", width=220, anchor="w")
        self._tree.heading("password", text="Passwort (Klartext)")
        self._tree.column("password", width=320, anchor="w")
        self._tree.pack(fill="x", padx=6, pady=6)
        self._tree.tag_configure("crack", foreground=DARK["red"])

        self._output = self._log_widget(self, height=12)
        self._cracked: list[tuple[str, str]] = []

    # ── impacket-Installation ───────────────────────────────────────────────────

    def _install_impacket(self):
        self._log(self._output, "$ pip install impacket\n", "cyan")
        threading.Thread(target=self._do_install, daemon=True).start()

    def _do_install(self):
        try:
            import sys
            p = subprocess.run([sys.executable, "-m", "pip", "install", "impacket"],
                               capture_output=True, text=True, encoding="utf-8",
                               errors="replace", timeout=300)
            self.after(0, self._log, self._output,
                       (p.stdout or "")[-1500:] + "\n", None)
            self._sdump = _find_secretsdump()
            self.after(0, self._log, self._output,
                       "[+] impacket installiert.\n" if self._sdump
                       else "[!] secretsdump weiterhin nicht gefunden.\n",
                       "green" if self._sdump else "red")
        except Exception as e:
            self.after(0, self._log, self._output, f"[!] {e}\n", "red")

    # ── Audit-Lauf ──────────────────────────────────────────────────────────────

    def _start(self):
        if not self._admin:
            self._log(self._output, "[!] Administratorrechte nötig. Suite als Admin starten.\n", "red")
            return
        if not self._sdump:
            self._log(self._output, "[!] impacket/secretsdump fehlt (Button oben nutzen).\n", "red")
            return
        if not self._hashcat:
            self._log(self._output, "[!] hashcat nicht konfiguriert (Einstellungen).\n", "red")
            return
        wl = self._wordlist.get().strip()
        if not wl or not Path(wl).is_file():
            self._log(self._output, "[!] Bitte gültige Wordlist wählen.\n", "red")
            return
        self._run_btn.configure(state="disabled")
        self._stop_btn.configure(state="normal")
        for iid in self._tree.get_children():
            self._tree.delete(iid)
        self._cracked = []
        self._sum.set("Audit läuft …")
        if self._activity_cb:
            self._activity_cb("Lokaler Passwort-Audit gestartet")
        threading.Thread(target=self._run, args=(wl,), daemon=True).start()

    def _run(self, wordlist: str):
        workdir = Path(tempfile.mkdtemp(prefix="g4m_pwaudit_"))
        sam = workdir / "sam.save"
        system = workdir / "system.save"
        hashfile = workdir / "ntlm.txt"
        try:
            # 1) Hives sichern
            self.after(0, self._log, self._output, "[*] Sichere SAM/SYSTEM-Hives …\n", "cyan")
            for hive, dst in (("HKLM\\SAM", sam), ("HKLM\\SYSTEM", system)):
                r = subprocess.run(["reg", "save", hive, str(dst), "/y"],
                                   capture_output=True, text=True, encoding="utf-8",
                                   errors="replace", creationflags=subprocess.CREATE_NO_WINDOW)
                if r.returncode != 0:
                    self.after(0, self._log, self._output,
                               f"[!] reg save {hive} fehlgeschlagen: {r.stdout}{r.stderr}\n", "red")
                    return

            # 2) Hashes extrahieren (secretsdump LOCAL)
            self.after(0, self._log, self._output, "[*] Extrahiere NTLM-Hashes (secretsdump) …\n", "cyan")
            import sys
            sd = self._sdump
            cmd = ([sys.executable, sd] if sd.endswith(".py") else [sd])
            cmd += ["-sam", str(sam), "-system", str(system), "LOCAL"]
            r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                              errors="replace", creationflags=subprocess.CREATE_NO_WINDOW, timeout=120)
            out = (r.stdout or "") + (r.stderr or "")
            # Zeilen wie: User:RID:LMHASH:NTHASH:::
            hash_lines = re.findall(r'^[^\s:]+:\d+:[0-9a-fA-F]{32}:[0-9a-fA-F]{32}:::', out, re.M)
            if not hash_lines:
                self.after(0, self._log, self._output,
                           "[!] Keine Hashes extrahiert.\n" + out[-800:] + "\n", "red")
                return
            hashfile.write_text("\n".join(hash_lines) + "\n", encoding="utf-8")
            self.after(0, self._log, self._output,
                       f"[+] {len(hash_lines)} Konto-Hashes extrahiert.\n", "green")

            # 3) hashcat -m 1000 (NTLM)
            self.after(0, self._log, self._output, "[*] Starte hashcat (NTLM, -m 1000) …\n", "cyan")
            potfile = workdir / "out.pot"
            hc = subprocess.run(
                [self._hashcat, "-m", "1000", "-a", "0", str(hashfile), wordlist,
                 "--potfile-path", str(potfile), "--quiet"],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                creationflags=subprocess.CREATE_NO_WINDOW, timeout=1800)
            self.after(0, self._log, self._output,
                       (hc.stdout or "")[-600:] + "\n", None)

            # 4) geknackte: hashcat --show
            show = subprocess.run(
                [self._hashcat, "-m", "1000", str(hashfile), "--show",
                 "--potfile-path", str(potfile)],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                creationflags=subprocess.CREATE_NO_WINDOW)
            # Map NThash → user
            user_by_nt = {}
            for line in hash_lines:
                parts = line.split(":")
                if len(parts) >= 4:
                    user_by_nt[parts[3].lower()] = parts[0]
            cracked = []
            for line in (show.stdout or "").splitlines():
                # Format: NTHASH:plaintext
                m = re.match(r'^([0-9a-fA-F]{32}):(.*)$', line.strip())
                if m:
                    nt, pw = m.group(1).lower(), m.group(2)
                    cracked.append((user_by_nt.get(nt, nt), pw))
            self.after(0, self._store_cracked, cracked, len(hash_lines))
        except Exception as e:
            self.after(0, self._log, self._output, f"[!] {e}\n", "red")
        finally:
            # 5) Aufräumen (Hives + Hashes enthalten sensible Daten)
            try:
                shutil.rmtree(workdir, ignore_errors=True)
                self.after(0, self._log, self._output,
                           "[i] Hive-Sicherungen + Hash-Datei gelöscht.\n", "yellow")
            except Exception:
                pass
            self.after(0, lambda: (self._run_btn.configure(state="normal"),
                                   self._stop_btn.configure(state="disabled")))

    def _store_cracked(self, cracked, total):
        self._cracked = cracked
        self._render_cracked()
        self._sum.set(f"{len(cracked)}/{total} Konten geknackt")
        if cracked and self._report_cb:
            users = ", ".join(u for u, _ in cracked)
            self._report_finding(
                f"[Passwort-Audit] {len(cracked)} schwache lokale Konto-Passwörter",
                "Hoch",
                f"Folgende lokale Konten haben ein in der Wordlist enthaltenes Passwort: {users}.\n\n"
                "Empfehlung: Starke, einzigartige Passwörter setzen.")
        if self._activity_cb:
            self._activity_cb(f"Passwort-Audit: {len(cracked)}/{total} Konten geknackt")

    def _render_cracked(self):
        for iid in self._tree.get_children():
            self._tree.delete(iid)
        show = self._show.get()
        for user, pw in self._cracked:
            shown = pw if show else "•" * min(len(pw), 12)
            self._tree.insert("", "end", tags=("crack",), values=(user, shown))
