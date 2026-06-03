"""tshark Live-Capture – Netzwerk-Pakete in Echtzeit aufzeichnen und analysieren."""
import tkinter as tk
from tkinter import ttk, filedialog
import subprocess
import threading
from pathlib import Path
from modules.base import BaseModule, strip_ansi
from utils.theme import DARK


class LiveCaptureModule(BaseModule):

    def _build(self):
        self._info_bar(self,
            "tshark Live-Capture – Netzwerk-Pakete in Echtzeit mitschneiden, "
            "filtern und auf PCAP speichern.")

        paned = tk.PanedWindow(self, orient="horizontal",
                               bg=DARK["bg"], sashwidth=4, sashrelief="flat")
        paned.pack(fill="both", expand=True, padx=4, pady=4)

        left  = tk.Frame(paned, bg=DARK["bg"]); paned.add(left,  minsize=300, width=340)
        right = tk.Frame(paned, bg=DARK["bg"]); paned.add(right, minsize=400)

        self._pkt_count  = 0
        self._cap_proc   = None

        # ── Interface ─────────────────────────────────────────────────────────
        fi = self._section(left, "Interface")
        self._iface_var = tk.StringVar()
        row_i = tk.Frame(fi, bg=DARK["bg"]); row_i.pack(fill="x", padx=10, pady=4)
        self._iface_cb = ttk.Combobox(row_i, textvariable=self._iface_var,
                                       state="readonly", font=("Segoe UI", 9))
        self._iface_cb.pack(side="left", fill="x", expand=True)
        ttk.Button(row_i, text="⟳", width=3,
                   command=self._refresh_ifaces).pack(side="left", padx=(4, 0))

        # ── Capture-Filter (BPF) ──────────────────────────────────────────────
        ff = self._section(left, "Capture-Filter (BPF)")
        self._bpf_var = tk.StringVar()
        self._entry_row(ff, "Filter:", self._bpf_var)
        tk.Label(ff, text="z.B.  tcp port 80  /  host 192.168.1.1  /  not arp",
                 bg=DARK["bg"], fg=DARK["border"],
                 font=("Segoe UI", 7, "italic")).pack(anchor="w", padx=10, pady=(0, 4))

        # ── Display-Filter (Post-Capture) ─────────────────────────────────────
        fd = self._section(left, "Display-Filter auf PCAP")
        self._disp_var = tk.StringVar()
        self._entry_row(fd, "Filter:", self._disp_var)
        self._pcap_r_var = tk.StringVar()
        self._entry_row(fd, "PCAP:", self._pcap_r_var,
                        browse_fn=lambda: self._browse_file(
                            self._pcap_r_var, "PCAP öffnen",
                            [("PCAP", "*.pcap *.pcapng"), ("Alle", "*")]))
        ttk.Button(fd, text="Filter anwenden",
                   command=self._apply_display_filter).pack(anchor="w", padx=10, pady=(0, 6))

        # ── Optionen ──────────────────────────────────────────────────────────
        fo = self._section(left, "Optionen")
        self._count_var = tk.StringVar(value="0")
        self._entry_row(fo, "Paket-Limit:", self._count_var)
        tk.Label(fo, text="0 = unbegrenzt",
                 bg=DARK["bg"], fg=DARK["border"],
                 font=("Segoe UI", 7, "italic")).pack(anchor="w", padx=10)
        self._pcap_w_var = tk.StringVar()
        self._entry_row(fo, "Speichern in:", self._pcap_w_var,
                        browse_fn=self._choose_save_pcap)

        # ── Buttons ───────────────────────────────────────────────────────────
        btn_f = tk.Frame(left, bg=DARK["bg"]); btn_f.pack(fill="x", padx=8, pady=8)
        self._start_btn = ttk.Button(btn_f, text="▶ Start",
                                      style="Accent.TButton",
                                      command=self._start_capture)
        self._start_btn.pack(side="left", padx=(0, 4))
        self._stop_btn = ttk.Button(btn_f, text="■ Stop",
                                     style="Danger.TButton",
                                     command=self._stop_capture,
                                     state="disabled")
        self._stop_btn.pack(side="left")
        ttk.Button(btn_f, text="Leeren",
                   command=self._clear).pack(side="right")

        # ── Paket-Zähler ──────────────────────────────────────────────────────
        self._pkt_var = tk.StringVar(value="Pakete: 0")
        tk.Label(left, textvariable=self._pkt_var,
                 bg=DARK["bg"], fg=DARK["teal"],
                 font=("Consolas", 9, "bold")).pack(anchor="w", padx=12, pady=(0, 4))

        # ── Output ────────────────────────────────────────────────────────────
        self._output = self._log_widget(right, height=32)

        # Interfaces beim Start laden
        self.after(600, self._refresh_ifaces)

    # ── Interface laden ───────────────────────────────────────────────────────

    def _refresh_ifaces(self):
        tshark = self._tool_path("tshark")
        if not tshark:
            return
        try:
            r = subprocess.run([tshark, "-D"],
                               capture_output=True, text=True, timeout=5,
                               creationflags=subprocess.CREATE_NO_WINDOW)
            ifaces = []
            for line in r.stdout.strip().splitlines():
                line = line.strip()
                if not line:
                    continue
                # Format: "1. \Device\NPF_{GUID} (Name)" oder "1. eth0"
                parts = line.split(". ", 1)
                ifaces.append(parts[1] if len(parts) == 2 else line)
            self._iface_cb["values"] = ifaces
            if ifaces and not self._iface_var.get():
                self._iface_cb.current(0)
        except Exception:
            pass

    # ── Capture starten/stoppen ───────────────────────────────────────────────

    def _start_capture(self):
        tshark = self._tool_path("tshark")
        if not tshark:
            self._log(self._output, "[!] tshark nicht gefunden.\n", "red")
            return
        iface = self._iface_var.get().strip()
        if not iface:
            self._log(self._output, "[!] Kein Interface ausgewählt.\n", "red")
            return

        # Nur den Interface-Namen (vor " (") übergeben wenn nötig
        iface_name = iface.split(" (")[0].strip()

        cmd = [
            tshark, "-i", iface_name, "-l", "-n",
            "-T", "fields",
            "-e", "frame.number",
            "-e", "frame.time_relative",
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "frame.protocols",
            "-e", "frame.len",
            "-E", "separator=|",
        ]
        bpf = self._bpf_var.get().strip()
        if bpf:
            cmd += ["-f", bpf]
        count = self._count_var.get().strip()
        if count and count != "0":
            cmd += ["-c", count]
        pcap = self._pcap_w_var.get().strip()
        if pcap:
            cmd += ["-w", pcap]

        self._pkt_count = 0
        self._pkt_var.set("Pakete: 0")
        self._log(self._output,
                  f"{'Nr':>6}  {'Zeit':>9}  {'Quelle':<18}  {'Ziel':<18}  {'Protokoll':<22}  Bytes\n",
                  "cyan")
        self._log(self._output, "─" * 95 + "\n", "cyan")
        self._start_btn.configure(state="disabled")
        self._stop_btn.configure(state="normal")
        threading.Thread(target=self._capture_thread, args=(cmd,), daemon=True).start()

    def _capture_thread(self, cmd):
        try:
            self._cap_proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, creationflags=subprocess.CREATE_NO_WINDOW)
            for line in self._cap_proc.stdout:
                line = strip_ansi(line).rstrip()
                if not line:
                    continue
                parts = line.split("|")
                if len(parts) >= 5:
                    nr    = parts[0][:6]   if len(parts) > 0 else ""
                    t     = parts[1][:9]   if len(parts) > 1 else ""
                    src   = parts[2][:18]  if len(parts) > 2 else ""
                    dst   = parts[3][:18]  if len(parts) > 3 else ""
                    proto = parts[4][:22]  if len(parts) > 4 else ""
                    sz    = parts[5]       if len(parts) > 5 else ""
                    fmt   = f"{nr:>6}  {t:>9}  {src:<18}  {dst:<18}  {proto:<22}  {sz}\n"
                    pl = proto.lower()
                    tag = ("green"  if "http" in pl or "dns" in pl else
                           "yellow" if "tls" in pl or "ssl" in pl else
                           "orange" if "icmp" in pl else
                           "purple" if "arp"  in pl else None)
                    self._pkt_count += 1
                    self.after(0, self._log, self._output, fmt, tag)
                    self.after(0, self._pkt_var.set, f"Pakete: {self._pkt_count}")
                else:
                    self.after(0, self._log, self._output, line + "\n")
            self._cap_proc.wait()
        except Exception as e:
            self.after(0, self._log, self._output, f"[!] {e}\n", "red")
        finally:
            self._cap_proc = None
            self.after(0, self._start_btn.configure, {"state": "normal"})
            self.after(0, self._stop_btn.configure,  {"state": "disabled"})
            self.after(0, self._log, self._output, "\n[✓] Capture beendet.\n", "green")

    def _stop_capture(self):
        if self._cap_proc:
            self._cap_proc.terminate()

    # ── Display-Filter auf PCAP ───────────────────────────────────────────────

    def _apply_display_filter(self):
        tshark = self._tool_path("tshark")
        if not tshark:
            self._log(self._output, "[!] tshark nicht gefunden.\n", "red")
            return
        pcap = self._pcap_r_var.get().strip()
        if not pcap:
            self._log(self._output, "[!] Keine PCAP-Datei angegeben.\n", "yellow")
            return
        df = self._disp_var.get().strip()
        cmd = [tshark, "-r", pcap, "-n"]
        if df:
            cmd += ["-Y", df]
        cmd += ["-T", "text"]
        self._log(self._output,
                  f"\n[Display-Filter: {df or '(keiner)'}  →  {pcap}]\n", "cyan")
        threading.Thread(target=self._disp_thread, args=(cmd,), daemon=True).start()

    def _disp_thread(self, cmd):
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=60,
                               creationflags=subprocess.CREATE_NO_WINDOW)
            for line in (r.stdout or "").splitlines():
                self.after(0, self._log, self._output, line + "\n")
            if r.stderr:
                self.after(0, self._log, self._output, r.stderr[:500] + "\n", "red")
            self.after(0, self._log, self._output, "[✓] Fertig.\n", "green")
        except Exception as e:
            self.after(0, self._log, self._output, f"[!] {e}\n", "red")

    # ── Hilfsfunktionen ───────────────────────────────────────────────────────

    def _choose_save_pcap(self):
        path = filedialog.asksaveasfilename(
            title="PCAP speichern als",
            defaultextension=".pcap",
            filetypes=[("PCAP", "*.pcap"), ("PCAPNG", "*.pcapng"), ("Alle", "*")])
        if path:
            self._pcap_w_var.set(path)

    def _clear(self):
        self._output.delete("1.0", "end")
        self._pkt_count = 0
        self._pkt_var.set("Pakete: 0")
