"""WiFi / WPA-Modul – PCAP-Konvertierung + Hashcat WPA-Launcher."""
import tkinter as tk
from tkinter import ttk, messagebox
import re
import os
import sys
import json
import threading
import urllib.request
from pathlib import Path
from modules.base import BaseModule
from utils.theme import DARK
from utils.oui_mini import detect_vendor

_BSSID_CACHE: dict[str, str] = {}


def _online_vendor_lookup(oui6: str) -> str:
    """Fragt macvendors.com nach dem Hersteller eines OUI-Präfixes."""
    if oui6 in _BSSID_CACHE:
        return _BSSID_CACHE[oui6]
    mac_fmt = f"{oui6[:2]}:{oui6[2:4]}:{oui6[4:6]}"
    try:
        url = f"https://api.macvendors.com/{urllib.request.quote(mac_fmt)}"
        req = urllib.request.Request(url, headers={"User-Agent": "G4MEOVER/1.0"})
        with urllib.request.urlopen(req, timeout=5) as r:
            vendor = r.read().decode().strip()
    except Exception:
        vendor = ""
    _BSSID_CACHE[oui6] = vendor
    return vendor

# ─── Konstanten ───────────────────────────────────────────────────────────────

MASK_PRESETS: dict[str, list[tuple[str, str]]] = {
    "WPA – Nur Ziffern": [
        ("8 Stellen  [100 Mio]",          "?d?d?d?d?d?d?d?d"),
        ("9 Stellen  [1 Mrd]",            "?d?d?d?d?d?d?d?d?d"),
        ("10 Ziffern – Telefon-DE",        "?d?d?d?d?d?d?d?d?d?d"),
        ("12 Ziffern – Speedport",         "?d?d?d?d?d?d?d?d?d?d?d?d"),
        ("6 Stellen  [1 Mio]",            "?d?d?d?d?d?d"),
        ("7 Stellen  [10 Mio]",           "?d?d?d?d?d?d?d"),
    ],
    "WPA – Hex (Router)": [
        ("8-stellig hex  [4 Mrd]",        "?h?h?h?h?h?h?h?h"),
        ("10-stellig hex",                "?h?h?h?h?h?h?h?h?h?h"),
        ("12-stellig hex – EasyBox",      "?h?h?h?h?h?h?h?h?h?h?h?h"),
        ("16-stellig hex – FritzBox neu", "?h?h?h?h?h?h?h?h?h?h?h?h?h?h?h?h"),
    ],
    "WPA – Klein + Ziffern": [
        ("8 Kleinbuchstaben",              "?l?l?l?l?l?l?l?l"),
        ("6 Klein + 2 Ziffern",           "?l?l?l?l?l?l?d?d"),
        ("4 Klein + 4 Ziffern",           "?l?l?l?l?d?d?d?d"),
        ("2 Ziffern + 6 Klein",           "?d?d?l?l?l?l?l?l"),
    ],
    "Router DE – Provider": [
        ("Speedport/Telekom  12 Ziffern", "?d?d?d?d?d?d?d?d?d?d?d?d"),
        ("EasyBox alt  8 Ziffern",        "?d?d?d?d?d?d?d?d"),
        ("EasyBox 803/804  8 hex",        "?h?h?h?h?h?h?h?h"),
        ("FritzBox  8 alph.",             "?l?l?l?l?l?l?l?l"),
        ("O2/Alice abwechselnd",          "?l?d?l?d?l?d?l?d"),
    ],
}

QUICKSTART_PROFILES = {
    "WPA – Schnell (8-10 Ziffern)": {
        "attack": "3", "mask": "?d?d?d?d?d?d?d?d", "workload": "3",
    },
    "WPA – Wortliste rockyou": {
        "attack": "0",
        "wordlist": r"G:\Tools\SECURITY_TOOLS\Wordlists\rockyou.txt\rockyou.txt",
        "workload": "3",
    },
    "WPA – Router DE (Provider-Masken)": {
        "attack": "3", "mask": "?d?d?d?d?d?d?d?d?d?d?d?d", "workload": "3",
    },
    "WPA – Hybrid (Wortliste + 4 Ziffern)": {
        "attack": "6",
        "wordlist": r"G:\Tools\SECURITY_TOOLS\Wordlists\rockyou.txt\rockyou.txt",
        "mask": "?d?d?d?d", "workload": "3",
    },
}

_SPEED_RE  = re.compile(r"Speed\.#\*\.+:\s+([\d.]+)\s+(\S*H/s)", re.I)
_STATUS_RE = re.compile(r"Status\.+:\s+(\w+)", re.I)
_PROG_RE   = re.compile(r"Progress\.+:\s+([\d]+)/([\d]+)", re.I)
_CAND_RE   = re.compile(r"Candidates\.#\d+\.+:\s+(.+)")
_RECOV_RE  = re.compile(r"Recovered\.+:\s+(\d+)/(\d+)")

BENCHMARK_KS = [
    ("8 Ziffern  (12345678)",     10**8),
    ("10 Ziffern (Telefon-DE)",   10**10),
    ("8 Kleinbuchstaben",         26**8),
    ("6 Klein + 2 Ziffern",       26**6 * 10**2 * 28),
    ("8 Hex (Router)",            16**8),
    ("12 Ziffern (Speedport)",    10**12),
    ("16 Hex (FritzBox neu)",     16**16),
    ("8 beliebig druckbar",       95**8),
]


def _fmt_time(seconds: float) -> str:
    if seconds < 60:       return f"{seconds:.0f} Sek"
    if seconds < 3600:     return f"{seconds/60:.1f} Min"
    if seconds < 86400:    return f"{seconds/3600:.1f} Std"
    if seconds < 2592000:  return f"{seconds/86400:.1f} Tage"
    return "sehr lang"


class WifiWpaModule(BaseModule):

    def _build(self):
        self._info_bar(self,
            "WiFi/WPA-Cracking: PCAP → hc22000-Konvertierung · PCAP-Inspektor (ESSID/BSSID/OUI) · hashcat-Launcher (GPU) · Potfile-Viewer · GPU-Benchmark")

        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=4, pady=4)

        t1 = tk.Frame(nb, bg=DARK["bg"]); nb.add(t1, text="  PCAP konvertieren  ")
        t2 = tk.Frame(nb, bg=DARK["bg"]); nb.add(t2, text="  Hashcat Launcher  ")
        t3 = tk.Frame(nb, bg=DARK["bg"]); nb.add(t3, text="  Potfile  ")
        t4 = tk.Frame(nb, bg=DARK["bg"]); nb.add(t4, text="  GPU-Benchmark  ")

        self._build_convert(t1)
        self._build_launcher(t2)
        self._build_potfile(t3)
        self._build_bench(t4)

        self._hc_file_var = tk.StringVar()

    # ═══════════════════════════════════════════════════════════════════════════
    # Tab 1 – PCAP Konvertierung
    # ═══════════════════════════════════════════════════════════════════════════

    def _build_convert(self, parent):
        self._info_bar(parent,
            "PCAP → hc22000: Konvertiert WPA-Handshake-PCAP-Dateien (Airodump, Wireshark) ins hashcat-Format. PCAP-Inspektor zeigt ESSID, BSSID, Hersteller und empfehlt eine Angriffs-Maske.")
        f1 = self._section(parent, "Eingabe")
        self._pcap_var = tk.StringVar()
        self._entry_row(f1, "PCAP/PCAPNG:", self._pcap_var,
                        browse_fn=lambda: self._browse_file(self._pcap_var,
                            "PCAP öffnen", [("PCAP", "*.pcap *.pcapng"), ("Alle", "*.*")]))

        f2 = self._section(parent, "Ausgabe")
        self._hc22k_var = tk.StringVar()
        self._entry_row(f2, "hc22000-Datei:", self._hc22k_var,
                        browse_fn=lambda: self._save_file(self._hc22k_var,
                            "hc22000 speichern", ".hc22000",
                            [("hc22000", "*.hc22000"), ("Alle", "*.*")]))

        btn_row = tk.Frame(parent, bg=DARK["bg"])
        btn_row.pack(fill="x", padx=10, pady=6)
        self._conv_btn = ttk.Button(btn_row, text="Konvertieren (Python-nativ)",
                                    style="Accent.TButton",
                                    command=self._run_convert)
        self._conv_btn.pack(side="left", fill="x", expand=True)

        self._conv_log = self._log_widget(parent, height=6)

        # ── PCAP-Inspektor ────────────────────────────────────────────────────
        fi = self._section(parent, "PCAP-Inspektor – Erkannte Handshakes")
        tree_cols = ("essid", "bssid", "typ", "hersteller", "empfehlung")
        self._insp_tree = ttk.Treeview(fi, columns=tree_cols, show="headings",
                                        selectmode="browse", height=6)
        for col, w, label in [
            ("essid",       160, "ESSID"),
            ("bssid",       140, "BSSID (AP)"),
            ("typ",          70, "Typ"),
            ("hersteller",  140, "Hersteller"),
            ("empfehlung",  160, "Masken-Empfehlung"),
        ]:
            self._insp_tree.heading(col, text=label)
            self._insp_tree.column(col, width=w, minwidth=40)
        self._insp_tree.tag_configure("match", foreground=DARK["green"])
        isb = ttk.Scrollbar(fi, command=self._insp_tree.yview)
        self._insp_tree.configure(yscrollcommand=isb.set)
        isb.pack(side="right", fill="y")
        self._insp_tree.pack(fill="both", expand=True, padx=6, pady=4)

        ttk.Button(parent, text="Maske übernehmen → Launcher",
                   command=self._insp_load_to_launcher).pack(padx=10, pady=(0, 6), anchor="w")

    def _run_convert(self):
        pcap = self._pcap_var.get().strip()
        out  = self._hc22k_var.get().strip()
        if not pcap:
            messagebox.showerror("Fehler", "Bitte PCAP-Datei wählen."); return
        if not out:
            base = Path(pcap).with_suffix(".hc22000")
            self._hc22k_var.set(str(base))
            out = str(base)
        self._log_clear(self._conv_log)
        self._conv_btn.configure(state="disabled")
        threading.Thread(target=self._exec_convert, args=(pcap, out), daemon=True).start()

    def _exec_convert(self, pcap: str, out: str):
        def log(msg):
            self.after(0, self._log, self._conv_log, msg, None)
        try:
            hc_dir = Path(__file__).parent.parent.parent / "hashcat-tool"
            sys.path.insert(0, str(hc_dir))
            from pcap_converter import convert_pcap_to_hc22000
            count, summaries = convert_pcap_to_hc22000(pcap, out, status_cb=log)
            self.after(0, self._show_inspector, summaries, out)
        except ImportError:
            log("[!] pcap_converter nicht gefunden – scapy installiert?")
        except Exception as e:
            log(f"[!] Fehler: {e}")
        finally:
            self.after(0, lambda: self._conv_btn.configure(state="normal"))

    def _show_inspector(self, summaries: list[dict], out_path: str):
        self._insp_tree.delete(*self._insp_tree.get_children())
        self._hc_file_var.set(out_path)
        for s in summaries:
            vendor, maskfile = detect_vendor(s["essid"], s["ap_mac"])
            rec = maskfile or "—"
            tag = "match" if vendor != "Unbekannt" else ""
            iid = self._insp_tree.insert("", "end",
                values=(s["essid"], s["ap_mac"], s["pair_type"], vendor, rec),
                tags=(tag,) if tag else ())
            if vendor == "Unbekannt":
                threading.Thread(
                    target=self._fetch_vendor_online,
                    args=(iid, s["ap_mac"], s["essid"]),
                    daemon=True,
                ).start()

    def _fetch_vendor_online(self, iid: str, ap_mac: str, essid: str):
        oui6 = ap_mac.replace(":", "").upper()[:6]
        vendor = _online_vendor_lookup(oui6)
        if not vendor:
            return
        # Maskenempfehlung aus bekanntem Hersteller ableiten
        rec = self._vendor_to_mask(vendor, essid)
        def update():
            try:
                vals = list(self._insp_tree.item(iid, "values"))
                vals[3] = vendor
                if rec:
                    vals[4] = rec
                self._insp_tree.item(iid, values=vals, tags=("match",))
                self._log(self._conv_log,
                    f"[OUI] {ap_mac} → {vendor}" + (f" → {rec}" if rec else ""), "green")
            except Exception:
                pass
        self.after(0, update)

    @staticmethod
    def _vendor_to_mask(vendor: str, essid: str) -> str:
        """Leitet eine Hashcat-Maskenempfehlung aus dem Hersteller ab."""
        v = vendor.lower()
        if any(k in v for k in ("avm", "fritzbox", "fritz")):
            return "router_de.hcmask"
        if any(k in v for k in ("telekom", "speedport", "t-home")):
            return "router_de.hcmask"
        if any(k in v for k in ("vodafone", "easybox")):
            return "router_de.hcmask"
        if any(k in v for k in ("o2", "telefonica")):
            return "router_de.hcmask"
        if any(k in v for k in ("unitymedia", "kabel deutschland", "unity")):
            return "router_de.hcmask"
        if any(k in v for k in ("tp-link", "tplink")):
            return "?d?d?d?d?d?d?d?d"
        if any(k in v for k in ("asus",)):
            return "?d?d?d?d?d?d?d?d"
        if any(k in v for k in ("netgear",)):
            return "?l?l?l?l?l?l?l?l"
        return ""

    def _insp_load_to_launcher(self):
        sel = self._insp_tree.selection()
        if not sel:
            return
        vals = self._insp_tree.item(sel[0], "values")
        vendor, maskrec = vals[3], vals[4]
        self._log(self._conv_log, f"[→] {vendor} – Empfehlung: {maskrec}", "green")

    # ═══════════════════════════════════════════════════════════════════════════
    # Tab 2 – Hashcat Launcher
    # ═══════════════════════════════════════════════════════════════════════════

    def _build_launcher(self, parent):
        self._info_bar(parent,
            "hashcat WPA-Launcher: Startet hashcat mit hc22000-Datei. Quickstart-Profile für typische Passwortmuster (Speedport, FritzBox, EasyBox usw.). Live-Stats und Session-Management.")
        paned = tk.PanedWindow(parent, orient="horizontal",
                               bg=DARK["bg"], sashwidth=4, sashrelief="flat")
        paned.pack(fill="both", expand=True, padx=4, pady=4)
        left  = tk.Frame(paned, bg=DARK["bg"]); paned.add(left,  minsize=300, width=340)
        right = tk.Frame(paned, bg=DARK["bg"]); paned.add(right, minsize=400)

        # ── Linke Seite ───────────────────────────────────────────────────────
        fh = self._section(left, "Handshake-Datei (.hc22000)")
        self._hc_file_var2 = tk.StringVar()
        self._entry_row(fh, "Datei:", self._hc_file_var2,
                        browse_fn=lambda: self._browse_file(self._hc_file_var2,
                            "hc22000 öffnen",
                            [("hc22000/HC", "*.hc22000 *.hc"), ("Alle", "*.*")]))

        # Quickstart
        fq = self._section(left, "Quickstart-Profile")
        self._qs_cb = ttk.Combobox(fq, state="readonly",
                                    values=list(QUICKSTART_PROFILES.keys()),
                                    font=("Segoe UI", 9))
        self._qs_cb.current(0)
        self._qs_cb.pack(fill="x", padx=10, pady=4)
        ttk.Button(fq, text="Profil laden",
                   command=self._apply_quickstart).pack(padx=10, pady=(0, 6), anchor="w")

        # Angriffs-Modus
        fa = self._section(left, "Angriff")
        self._wpa_attack_var = tk.StringVar(value="3")
        modes = [("0 – Wortliste", "0"), ("3 – Maske (Brute-Force)", "3"),
                 ("6 – Wortliste + Maske", "6"), ("7 – Maske + Wortliste", "7")]
        for txt, val in modes:
            ttk.Radiobutton(fa, text=txt, variable=self._wpa_attack_var,
                            value=val, command=self._on_wpa_attack).pack(anchor="w", padx=10, pady=1)

        self._f_attack_ref = fa

        # Wortliste-Frame
        self._wl_frame = tk.Frame(left, bg=DARK["bg"])
        self._wpa_wl_var = tk.StringVar()
        self._entry_row(self._wl_frame, "Wortliste:", self._wpa_wl_var,
                        browse_fn=lambda: self._browse_file(self._wpa_wl_var,
                            "Wortliste", [("Text", "*.txt"), ("Alle", "*.*")]))

        # Masken-Frame
        self._mask_frame = tk.Frame(left, bg=DARK["bg"])
        fmp = self._section(self._mask_frame, "Maske")
        self._wpa_mask_var = tk.StringVar(value="?d?d?d?d?d?d?d?d")
        tk.Entry(fmp, textvariable=self._wpa_mask_var,
                 bg=DARK["entry"], fg=DARK["accent"],
                 insertbackground=DARK["fg"], relief="flat",
                 font=("Consolas", 9)).pack(fill="x", padx=10, pady=4, ipady=3)

        fmp2 = self._section(self._mask_frame, "Masken-Vorlagen")
        self._preset_cat = ttk.Combobox(fmp2, state="readonly",
                                         values=list(MASK_PRESETS.keys()),
                                         font=("Segoe UI", 8))
        self._preset_cat.current(0)
        self._preset_cat.pack(fill="x", padx=10, pady=2)
        self._preset_cat.bind("<<ComboboxSelected>>", self._update_preset_list)
        self._preset_list = tk.Listbox(fmp2, bg=DARK["entry"], fg=DARK["fg"],
                                        selectbackground=DARK["accent"],
                                        font=("Consolas", 8), height=5, relief="flat")
        self._preset_list.pack(fill="x", padx=10, pady=2)
        self._preset_list.bind("<Double-1>", self._apply_preset)
        self._update_preset_list()

        self._mask_frame.pack(fill="x", after=fa, padx=4, pady=2)
        self._wl_frame.pack_forget()

        # Optionen
        fo = self._section(left, "Optionen")
        opt_row = tk.Frame(fo, bg=DARK["bg"]); opt_row.pack(fill="x", padx=10, pady=2)
        tk.Label(opt_row, text="Workload:", bg=DARK["bg"], fg=DARK["fg"],
                 font=("Segoe UI", 8)).pack(side="left")
        self._wpa_wl_cb = ttk.Combobox(opt_row, state="readonly",
                                         values=["1 – schonend", "2 – default", "3 – aggressiv", "4 – maximum"],
                                         width=18, font=("Segoe UI", 8))
        self._wpa_wl_cb.current(2)
        self._wpa_wl_cb.pack(side="left", padx=4)
        self._wpa_force = tk.BooleanVar()
        ttk.Checkbutton(opt_row, text="--force", variable=self._wpa_force).pack(side="left", padx=4)

        sess_row = tk.Frame(fo, bg=DARK["bg"]); sess_row.pack(fill="x", padx=10, pady=2)
        tk.Label(sess_row, text="Session:", bg=DARK["bg"], fg=DARK["fg"],
                 font=("Segoe UI", 8)).pack(side="left")
        self._sess_var = tk.StringVar(value="wpa_session")
        tk.Entry(sess_row, textvariable=self._sess_var,
                 bg=DARK["entry"], fg=DARK["fg"],
                 insertbackground=DARK["fg"], relief="flat",
                 font=("Segoe UI", 8), width=16).pack(side="left", padx=4, ipady=2)

        btn_row = tk.Frame(left, bg=DARK["bg"]); btn_row.pack(fill="x", padx=10, pady=8)
        self._start_btn = ttk.Button(btn_row, text="Crack starten",
                                     style="Accent.TButton",
                                     command=self._run_hashcat)
        self._start_btn.pack(side="left", fill="x", expand=True)
        self._resume_btn = ttk.Button(btn_row, text="Fortsetzen",
                                      command=self._resume_hashcat)
        self._resume_btn.pack(side="left", padx=4)
        self._stop_btn2 = ttk.Button(btn_row, text="Stoppen",
                                     style="Danger.TButton",
                                     command=self._stop_tool,
                                     state="disabled")
        self._stop_btn2.pack(side="left")

        # ── Rechte Seite – Live-Stats ─────────────────────────────────────────
        fstats = self._section(right, "Live-Statistiken")
        stats_grid = tk.Frame(fstats, bg=DARK["bg"]); stats_grid.pack(fill="x", padx=10, pady=4)
        self._stat_vars: dict[str, tk.StringVar] = {}
        for row_i, (lbl, key) in enumerate([
            ("Status:", "status"), ("Speed:", "speed"),
            ("Fortschritt:", "progress"), ("Kandidat:", "candidate"),
            ("Gefunden:", "recovered"),
        ]):
            tk.Label(stats_grid, text=lbl, bg=DARK["bg"], fg=DARK["border"],
                     font=("Segoe UI", 8), anchor="w", width=12).grid(
                row=row_i, column=0, sticky="w", pady=1)
            var = tk.StringVar(value="—")
            tk.Label(stats_grid, textvariable=var, bg=DARK["bg"], fg=DARK["accent"],
                     font=("Consolas", 9), anchor="w").grid(
                row=row_i, column=1, sticky="w", padx=6, pady=1)
            self._stat_vars[key] = var

        self._hc_log = self._log_widget(right, height=16)

    def _on_wpa_attack(self):
        mode = self._wpa_attack_var.get()
        self._wl_frame.pack_forget()
        self._mask_frame.pack_forget()
        if mode in ("0",):
            self._wl_frame.pack(fill="x", after=self._f_attack_ref, padx=4, pady=2)
        elif mode in ("3",):
            self._mask_frame.pack(fill="x", after=self._f_attack_ref, padx=4, pady=2)
        else:
            self._wl_frame.pack(fill="x", after=self._f_attack_ref, padx=4, pady=2)
            self._mask_frame.pack(fill="x", after=self._wl_frame, padx=4, pady=2)

    def _update_preset_list(self, _=None):
        cat = self._preset_cat.get()
        self._preset_list.delete(0, "end")
        for label, _ in MASK_PRESETS.get(cat, []):
            self._preset_list.insert("end", label)

    def _apply_preset(self, _=None):
        sel = self._preset_list.curselection()
        if not sel:
            return
        cat = self._preset_cat.get()
        items = MASK_PRESETS.get(cat, [])
        idx = sel[0]
        if idx < len(items):
            self._wpa_mask_var.set(items[idx][1])

    def _apply_quickstart(self):
        profile = QUICKSTART_PROFILES.get(self._qs_cb.get(), {})
        if "attack" in profile:
            self._wpa_attack_var.set(profile["attack"])
            self._on_wpa_attack()
        if "wordlist" in profile:
            self._wpa_wl_var.set(profile["wordlist"])
        if "mask" in profile:
            self._wpa_mask_var.set(profile["mask"])
        if "workload" in profile:
            idx = int(profile["workload"]) - 1
            self._wpa_wl_cb.current(max(0, min(3, idx)))

    def _build_hashcat_cmd(self, resume=False) -> list[str]:
        hc = self._tool_path("hashcat")
        if not hc:
            return []
        hc_file = self._hc_file_var2.get().strip()
        if not hc_file and hasattr(self, "_hc_file_var"):
            hc_file = self._hc_file_var.get().strip()
        if not hc_file:
            return []
        wl_val = self._wpa_wl_cb.get()[0]
        sess   = self._sess_var.get().strip() or "wpa_session"
        if resume:
            return [hc, "--session", sess, "--restore"]
        mode = self._wpa_attack_var.get()
        cmd  = [hc, "-m", "22000", "-a", mode, "--status",
                "--status-timer", "3", "--session", sess,
                f"--workload-profile={wl_val}",
                "-o", f"{sess}_cracked.txt", hc_file]
        if mode == "0":
            cmd.append(self._wpa_wl_var.get().strip() or "rockyou.txt")
        elif mode == "3":
            cmd.append(self._wpa_mask_var.get().strip())
        elif mode in ("6", "7"):
            if mode == "6":
                cmd += [self._wpa_wl_var.get().strip(), self._wpa_mask_var.get().strip()]
            else:
                cmd += [self._wpa_mask_var.get().strip(), self._wpa_wl_var.get().strip()]
        if self._wpa_force.get():
            cmd.append("--force")
        return cmd

    def _run_hashcat(self):
        if not self._require_tool("hashcat", self._hc_log):
            return
        hc_file = self._hc_file_var2.get().strip() or self._hc_file_var.get().strip()
        if not hc_file:
            messagebox.showerror("Fehler", "Bitte hc22000-Datei wählen."); return
        for key in self._stat_vars:
            self._stat_vars[key].set("—")
        cmd = self._build_hashcat_cmd()
        if not cmd:
            return
        cwd = str(Path(self._tool_path("hashcat")).parent)
        self._run_tool(cmd, cwd, self._hc_log,
                       on_line=self._parse_hc_line,
                       start_btn=self._start_btn,
                       stop_btn=self._stop_btn2)

    def _resume_hashcat(self):
        if not self._require_tool("hashcat", self._hc_log):
            return
        cmd = self._build_hashcat_cmd(resume=True)
        if not cmd:
            messagebox.showerror("Fehler", "Session-Name fehlt."); return
        cwd = str(Path(self._tool_path("hashcat")).parent)
        self._run_tool(cmd, cwd, self._hc_log,
                       on_line=self._parse_hc_line,
                       start_btn=self._start_btn,
                       stop_btn=self._stop_btn2)

    def _parse_hc_line(self, line: str):
        m = _SPEED_RE.search(line)
        if m:
            self._stat_vars["speed"].set(f"{m.group(1)} {m.group(2)}")
        m = _STATUS_RE.search(line)
        if m:
            self._stat_vars["status"].set(m.group(1))
        m = _PROG_RE.search(line)
        if m:
            done, total = int(m.group(1)), int(m.group(2))
            pct = done / total * 100 if total else 0
            self._stat_vars["progress"].set(f"{done:,} / {total:,}  ({pct:.2f}%)")
        m = _CAND_RE.search(line)
        if m:
            self._stat_vars["candidate"].set(m.group(1).strip())
        m = _RECOV_RE.search(line)
        if m:
            self._stat_vars["recovered"].set(f"{m.group(1)} / {m.group(2)}")

    # ═══════════════════════════════════════════════════════════════════════════
    # Tab 3 – Potfile-Viewer
    # ═══════════════════════════════════════════════════════════════════════════

    def _build_potfile(self, parent):
        self._info_bar(parent,
            "Potfile-Viewer: Zeigt bereits gecrackte Hashes aus der hashcat.potfile-Datei. Enthält alle bisher gefundenen WPA-Passwörter dieser hashcat-Installation.")
        f1 = self._section(parent, "Potfile")
        self._pot_var = tk.StringVar()
        default_pot = r"C:\tools\hashcat\hashcat.potfile"
        if os.path.exists(default_pot):
            self._pot_var.set(default_pot)
        self._entry_row(f1, "Potfile:", self._pot_var,
                        browse_fn=lambda: self._browse_file(self._pot_var,
                            "Potfile öffnen", [("Potfile", "*.potfile *.pot"), ("Alle", "*.*")]))

        filt_row = tk.Frame(parent, bg=DARK["bg"]); filt_row.pack(fill="x", padx=10, pady=4)
        tk.Label(filt_row, text="Filter:", bg=DARK["bg"], fg=DARK["fg"],
                 font=("Segoe UI", 8)).pack(side="left")
        self._pot_filter = tk.StringVar()
        self._pot_filter.trace_add("write", lambda *_: self._load_potfile())
        tk.Entry(filt_row, textvariable=self._pot_filter,
                 bg=DARK["entry"], fg=DARK["fg"],
                 insertbackground=DARK["fg"], relief="flat",
                 font=("Segoe UI", 8), width=20).pack(side="left", padx=4, ipady=2)
        ttk.Button(filt_row, text="Laden", command=self._load_potfile).pack(side="left")
        self._pot_count = tk.StringVar(value="")
        tk.Label(filt_row, textvariable=self._pot_count,
                 bg=DARK["bg"], fg=DARK["accent"],
                 font=("Segoe UI", 8)).pack(side="right", padx=4)

        cols = ("hash", "plain")
        self._pot_tree = ttk.Treeview(parent, columns=cols, show="headings",
                                       selectmode="browse")
        self._pot_tree.heading("hash",  text="Hash")
        self._pot_tree.heading("plain", text="Passwort")
        self._pot_tree.column("hash",  width=320, minwidth=100)
        self._pot_tree.column("plain", width=200, minwidth=80)
        self._pot_tree.tag_configure("wpa", foreground=DARK["green"])
        psb = ttk.Scrollbar(parent, command=self._pot_tree.yview)
        self._pot_tree.configure(yscrollcommand=psb.set)
        psb.pack(side="right", fill="y")
        self._pot_tree.pack(fill="both", expand=True, padx=6, pady=4)

    def _load_potfile(self):
        path = self._pot_var.get().strip()
        if not path or not os.path.exists(path):
            return
        filt = self._pot_filter.get().lower()
        self._pot_tree.delete(*self._pot_tree.get_children())
        count = 0
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line or ":" not in line:
                        continue
                    idx = line.rfind(":")
                    h, p = line[:idx], line[idx+1:]
                    if filt and filt not in h.lower() and filt not in p.lower():
                        continue
                    tag = "wpa" if h.startswith("WPA*") else ""
                    self._pot_tree.insert("", "end", values=(h[:60], p),
                                          tags=(tag,) if tag else ())
                    count += 1
            self._pot_count.set(f"{count} Einträge")
        except Exception as e:
            messagebox.showerror("Fehler", str(e))

    # ═══════════════════════════════════════════════════════════════════════════
    # Tab 4 – GPU-Benchmark
    # ═══════════════════════════════════════════════════════════════════════════

    def _build_bench(self, parent):
        info = tk.Label(parent,
            text="Misst die Hashcat-Speed für -m 22000 und schätzt Cracking-Zeiten.",
            bg=DARK["bg"], fg=DARK["border"], font=("Segoe UI", 8))
        info.pack(anchor="w", padx=14, pady=(8, 2))

        btn_row = tk.Frame(parent, bg=DARK["bg"]); btn_row.pack(fill="x", padx=10, pady=4)
        self._bench_btn = ttk.Button(btn_row, text="Benchmark starten",
                                     style="Accent.TButton",
                                     command=self._run_bench)
        self._bench_btn.pack(side="left")
        self._bench_speed = tk.StringVar(value="")
        tk.Label(btn_row, textvariable=self._bench_speed,
                 bg=DARK["bg"], fg=DARK["green"],
                 font=("Consolas", 10, "bold")).pack(side="left", padx=10)

        cols = ("angriff", "keyspace", "zeit")
        self._bench_tree = ttk.Treeview(parent, columns=cols, show="headings", height=10)
        for col, w, label in [("angriff", 260, "Angriff"), ("keyspace", 120, "Keyspace"),
                               ("zeit", 140, "Geschätzte Zeit")]:
            self._bench_tree.heading(col, text=label)
            self._bench_tree.column(col, width=w, minwidth=60)
        bsb = ttk.Scrollbar(parent, command=self._bench_tree.yview)
        self._bench_tree.configure(yscrollcommand=bsb.set)
        bsb.pack(side="right", fill="y")
        self._bench_tree.pack(fill="both", expand=True, padx=6, pady=4)
        for label, ks in BENCHMARK_KS:
            self._bench_tree.insert("", "end", values=(label, f"{ks:,}", "—"))

        self._bench_log = self._log_widget(parent, height=4)

    def _run_bench(self):
        if not self._require_tool("hashcat", self._bench_log):
            return
        hc  = self._tool_path("hashcat")
        cwd = str(Path(hc).parent)
        cmd = [hc, "-b", "-m", "22000", "--force"]
        self._bench_btn.configure(state="disabled")
        self._bench_speed.set("Läuft …")
        threading.Thread(target=self._exec_bench,
                         args=(cmd, cwd), daemon=True).start()

    def _exec_bench(self, cmd: list, cwd: str):
        import subprocess
        try:
            flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT,
                                    cwd=cwd, text=True, encoding="utf-8",
                                    errors="replace",
                                    creationflags=flags)
            khs = 0.0
            for line in proc.stdout:
                line = line.rstrip()
                self.after(0, self._log, line, None, self._bench_log)
                m = _SPEED_RE.search(line)
                if m:
                    val, unit = float(m.group(1)), m.group(2).upper()
                    if "GH" in unit:   khs = val * 1_000_000
                    elif "MH" in unit: khs = val * 1_000
                    elif "TH" in unit: khs = val * 1_000_000_000
                    else:              khs = val
            proc.wait()
            self.after(0, self._update_bench, khs)
        except Exception as e:
            self.after(0, self._log, f"[!] {e}", "error", self._bench_log)
        finally:
            self.after(0, lambda: self._bench_btn.configure(state="normal"))

    def _update_bench(self, khs: float):
        if khs <= 0:
            self._bench_speed.set("Keine Speed-Daten")
            return
        self._bench_speed.set(f"{khs:,.0f} kH/s")
        items = self._bench_tree.get_children()
        for i, (label, ks) in enumerate(BENCHMARK_KS):
            if i < len(items):
                secs = ks / (khs * 1000) if khs > 0 else 0
                self._bench_tree.item(items[i], values=(label, f"{ks:,}", _fmt_time(secs)))
