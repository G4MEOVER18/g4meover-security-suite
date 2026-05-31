"""OSINT-Modul – WhoIs, DNS, Geolokation, Subdomain-Enum, OUI-Lookup."""
import tkinter as tk
from tkinter import ttk, messagebox
import threading
import json
import re
import socket
from datetime import datetime
from modules.base import BaseModule
from utils.theme import DARK
from utils.oui_mini import detect_vendor

_IP_RE     = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
_EMAIL_RE  = re.compile(r"^[\w.+-]+@[\w.-]+\.\w{2,}$")
_DOMAIN_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9]?\.[a-zA-Z]{2,}$")

DNS_TYPES  = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA", "PTR"]


class OsintModule(BaseModule):

    def _build(self):
        self._info_bar(self,
            "OSINT – Open Source Intelligence: WhoIs · DNS · IP-Geolokation · Subdomain-Enumeration · Shodan · OUI/BSSID-Lookup")

        # ── Ziel-Eingabe ──────────────────────────────────────────────────────
        top = tk.Frame(self, bg=DARK["panel"]); top.pack(fill="x", padx=6, pady=(6, 4))
        tk.Label(top, text="Ziel (Domain / IP / Email / Username / MAC):",
                 bg=DARK["panel"], fg=DARK["fg"],
                 font=("Segoe UI", 9, "bold")).pack(side="left", padx=(10, 6))
        self._osint_target = tk.StringVar(value=self._target_var.get())
        self._target_var.trace_add("write",
            lambda *_: self._osint_target.set(self._target_var.get()))
        tk.Entry(top, textvariable=self._osint_target,
                 bg=DARK["entry"], fg=DARK["fg"],
                 insertbackground=DARK["fg"], relief="flat",
                 font=("Segoe UI", 10, "bold"), width=36).pack(side="left", ipady=4)
        ttk.Button(top, text="Alle starten",
                   style="Accent.TButton",
                   command=self._run_all).pack(side="left", padx=8)

        # ── Notebook mit Ergebnis-Tabs ─────────────────────────────────────
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=4, pady=4)

        self._tabs: dict[str, tk.Frame] = {}
        for name in ["WhoIs", "DNS", "Geolokation", "Subdomains", "Shodan", "OUI/BSSID"]:
            f = tk.Frame(nb, bg=DARK["bg"])
            nb.add(f, text=f"  {name}  ")
            self._tabs[name] = f

        self._build_whois(self._tabs["WhoIs"])
        self._build_dns(self._tabs["DNS"])
        self._build_geo(self._tabs["Geolokation"])
        self._build_subdomains(self._tabs["Subdomains"])
        self._build_shodan(self._tabs["Shodan"])
        self._build_oui(self._tabs["OUI/BSSID"])

        # ── Globales Log + Export ─────────────────────────────────────────
        self._osint_log = self._log_widget(self, height=5)
        exp_row = tk.Frame(self, bg=DARK["bg"]); exp_row.pack(fill="x", padx=10, pady=(0, 4))
        ttk.Button(exp_row, text="Export TXT",
                   command=self._export_txt).pack(side="left")
        ttk.Button(exp_row, text="Export Markdown",
                   command=self._export_md).pack(side="left", padx=4)

        self._report_data: dict[str, str] = {}

    # ═══════════════════════════════════════════════════════════════════════════
    # WhoIs Tab
    # ═══════════════════════════════════════════════════════════════════════════

    def _build_whois(self, parent):
        self._info_bar(parent,
            "WhoIs: Zeigt Registrar, Eigentümer, Erstelldatum und Nameserver einer Domain oder IP-Adresse.")
        btn = ttk.Button(parent, text="WhoIs abrufen", command=self._run_whois)
        btn.pack(anchor="w", padx=10, pady=6)
        self._tooltip(btn, "Ruft WhoIs-Informationen über die eingegebene Domain oder IP ab.")
        self._whois_text = self._text_area(parent)

    def _run_whois(self):
        target = self._osint_target.get().strip()
        if not target:
            messagebox.showerror("Fehler", "Kein Ziel angegeben."); return
        self._whois_text.configure(state="normal")
        self._whois_text.delete("1.0", "end")
        self._whois_text.configure(state="disabled")
        threading.Thread(target=self._exec_whois, args=(target,), daemon=True).start()

    def _exec_whois(self, target: str):
        def log(t): self.after(0, self._append_text, self._whois_text, t)
        try:
            import subprocess, os
            flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
            result = subprocess.run(
                ["whois", target], capture_output=True, text=True,
                timeout=20, creationflags=flags)
            out = result.stdout or result.stderr or "Keine Ausgabe."
            log(out)
            self._report_data["WhoIs"] = out
            self.after(0, self._log, self._osint_log, f"[WhoIs] {target} abgefragt.\n", "green")
        except FileNotFoundError:
            self._exec_whois_socket(target)
        except Exception as e:
            log(f"[!] Fehler: {e}")

    def _exec_whois_socket(self, target: str):
        def log(t): self.after(0, self._append_text, self._whois_text, t)
        try:
            host = target.split("/")[0].strip(".")
            whois_server = "whois.iana.org"
            sock = socket.create_connection((whois_server, 43), timeout=10)
            sock.send(f"{host}\r\n".encode())
            response = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
            sock.close()
            out = response.decode("utf-8", errors="replace")
            log(out)
            self._report_data["WhoIs"] = out
        except Exception as e:
            log(f"[!] WhoIs-Fehler (socket): {e}\n"
                "Tipp: 'whois' Tool installieren (winget install whois)")

    # ═══════════════════════════════════════════════════════════════════════════
    # DNS Tab
    # ═══════════════════════════════════════════════════════════════════════════

    def _build_dns(self, parent):
        self._info_bar(parent,
            "DNS-Lookup: Ruft A/AAAA/MX/TXT/NS/CNAME-Records ab. Gibt Aufschluss über Mailserver, IP-Adressen und Subdomains.")
        btn_row = tk.Frame(parent, bg=DARK["bg"]); btn_row.pack(fill="x", padx=10, pady=6)
        ttk.Button(btn_row, text="DNS abfragen",
                   command=self._run_dns).pack(side="left")
        tk.Label(btn_row, text="Typen:", bg=DARK["bg"], fg=DARK["fg"],
                 font=("Segoe UI", 8)).pack(side="left", padx=(12, 4))
        self._dns_type_vars: dict[str, tk.BooleanVar] = {}
        for t in DNS_TYPES[:6]:
            v = tk.BooleanVar(value=True)
            self._dns_type_vars[t] = v
            ttk.Checkbutton(btn_row, text=t, variable=v).pack(side="left", padx=1)

        cols = ("type", "name", "value", "ttl")
        self._dns_tree = ttk.Treeview(parent, columns=cols, show="headings",
                                       selectmode="browse")
        for col, w, label in [("type", 60, "Typ"), ("name", 200, "Name"),
                               ("value", 300, "Wert"), ("ttl", 60, "TTL")]:
            self._dns_tree.heading(col, text=label)
            self._dns_tree.column(col, width=w, minwidth=40)
        self._dns_tree.tag_configure("A",    foreground=DARK["green"])
        self._dns_tree.tag_configure("MX",   foreground=DARK["accent"])
        self._dns_tree.tag_configure("TXT",  foreground=DARK["yellow"])
        self._dns_tree.tag_configure("NS",   foreground=DARK["teal"])
        dsb = ttk.Scrollbar(parent, command=self._dns_tree.yview)
        self._dns_tree.configure(yscrollcommand=dsb.set)
        dsb.pack(side="right", fill="y")
        self._dns_tree.pack(fill="both", expand=True, padx=6, pady=4)

    def _run_dns(self):
        target = self._osint_target.get().strip()
        if not target:
            return
        self._dns_tree.delete(*self._dns_tree.get_children())
        threading.Thread(target=self._exec_dns, args=(target,), daemon=True).start()

    def _exec_dns(self, target: str):
        selected = [t for t, v in self._dns_type_vars.items() if v.get()]
        results  = []
        try:
            import dns.resolver  # type: ignore
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            for qtype in selected:
                try:
                    ans = resolver.resolve(target, qtype)
                    for r in ans:
                        results.append((qtype, str(ans.name), str(r), str(ans.ttl)))
                except Exception:
                    pass
        except ImportError:
            results = self._dns_socket_fallback(target, selected)
        def update():
            for row in results:
                self._dns_tree.insert("", "end", values=row, tags=(row[0],))
            self._report_data["DNS"] = "\n".join(
                f"{r[0]}\t{r[2]}" for r in results)
            self._log(self._osint_log, f"[DNS] {len(results)} Records für {target}.", "info")
        self.after(0, update)

    def _dns_socket_fallback(self, target: str, types: list) -> list:
        results = []
        if "A" in types:
            try:
                ips = socket.getaddrinfo(target, None, socket.AF_INET)
                for ip in set(r[4][0] for r in ips):
                    results.append(("A", target, ip, "—"))
            except Exception:
                pass
        if "AAAA" in types:
            try:
                ips = socket.getaddrinfo(target, None, socket.AF_INET6)
                for ip in set(r[4][0] for r in ips):
                    results.append(("AAAA", target, ip, "—"))
            except Exception:
                pass
        return results

    # ═══════════════════════════════════════════════════════════════════════════
    # Geolokation Tab
    # ═══════════════════════════════════════════════════════════════════════════

    def _build_geo(self, parent):
        self._info_bar(parent,
            "IP-Geolokation via ip-api.com (kostenlos, kein API-Key). Zeigt Land, Stadt, ISP und GPS-Koordinaten einer IP-Adresse.")
        ttk.Button(parent, text="Geoloation abrufen (ip-api.com)",
                   command=self._run_geo).pack(anchor="w", padx=10, pady=6)
        self._geo_frame = tk.Frame(parent, bg=DARK["bg"]); self._geo_frame.pack(fill="x", padx=10)
        self._geo_fields: dict[str, tk.StringVar] = {}
        for label, key in [
            ("IP-Adresse:",   "query"),
            ("Land:",         "country"),
            ("Region:",       "regionName"),
            ("Stadt:",        "city"),
            ("PLZ:",          "zip"),
            ("ISP:",          "isp"),
            ("Organisation:", "org"),
            ("AS:",           "as"),
            ("Koordinaten:",  "_coords"),
            ("Zeitzone:",     "timezone"),
        ]:
            row = tk.Frame(self._geo_frame, bg=DARK["bg"]); row.pack(fill="x", pady=1)
            tk.Label(row, text=label, bg=DARK["bg"], fg=DARK["border"],
                     font=("Segoe UI", 8), width=14, anchor="w").pack(side="left")
            var = tk.StringVar(value="—")
            tk.Label(row, textvariable=var, bg=DARK["bg"], fg=DARK["fg"],
                     font=("Consolas", 9), anchor="w").pack(side="left", padx=4)
            self._geo_fields[key] = var

    def _run_geo(self):
        target = self._osint_target.get().strip()
        if not target:
            return
        threading.Thread(target=self._exec_geo, args=(target,), daemon=True).start()

    def _exec_geo(self, target: str):
        import urllib.request
        try:
            url = f"http://ip-api.com/json/{target}?fields=66846719"
            with urllib.request.urlopen(url, timeout=10) as r:
                data = json.loads(r.read().decode())
            def update():
                for key, var in self._geo_fields.items():
                    if key == "_coords":
                        lat = data.get("lat", "?")
                        lon = data.get("lon", "?")
                        var.set(f"{lat}, {lon}")
                    else:
                        var.set(str(data.get(key, "—")))
                txt = json.dumps(data, indent=2, ensure_ascii=False)
                self._report_data["Geolokation"] = txt
                self._log(self._osint_log,
                          f"[Geo] {data.get('city', '?')}, {data.get('country', '?')}",
                          "green")
            self.after(0, update)
        except Exception as e:
            self.after(0, self._log, self._osint_log, f"[Geo] Fehler: {e}", "red")

    # ═══════════════════════════════════════════════════════════════════════════
    # Subdomains Tab
    # ═══════════════════════════════════════════════════════════════════════════

    def _build_subdomains(self, parent):
        self._info_bar(parent,
            "Subdomain-Enumeration: crt.sh (Certificate Transparency Logs) + DNS-Brute-Force zur Erkennung von Subdomains.")
        btn_row = tk.Frame(parent, bg=DARK["bg"]); btn_row.pack(fill="x", padx=10, pady=6)
        crt_btn = ttk.Button(btn_row, text="crt.sh abfragen", command=self._run_crtsh)
        crt_btn.pack(side="left")
        self._tooltip(crt_btn,
            "Durchsucht crt.sh (Certificate Transparency Logs) nach allen ausgestellten TLS-Zertifikaten für diese Domain → findet Subdomains ohne aktives Scannen.")
        brute_btn = ttk.Button(btn_row, text="DNS-Brute-Force", command=self._run_dnsbrute)
        brute_btn.pack(side="left", padx=4)
        self._tooltip(brute_btn,
            "Probiert ~25 häufige Subdomain-Präfixe (www, mail, ftp, api...) per DNS-Auflösung.")
        self._sub_count = tk.StringVar(value="")
        tk.Label(btn_row, textvariable=self._sub_count,
                 bg=DARK["bg"], fg=DARK["accent"],
                 font=("Segoe UI", 8)).pack(side="right", padx=4)

        cols = ("subdomain", "ip", "source")
        self._sub_tree = ttk.Treeview(parent, columns=cols, show="headings",
                                       selectmode="browse")
        for col, w, label in [("subdomain", 280, "Subdomain"),
                               ("ip", 140, "IP-Adresse"), ("source", 80, "Quelle")]:
            self._sub_tree.heading(col, text=label)
            self._sub_tree.column(col, width=w, minwidth=60)
        ssb = ttk.Scrollbar(parent, command=self._sub_tree.yview)
        self._sub_tree.configure(yscrollcommand=ssb.set)
        ssb.pack(side="right", fill="y")
        self._sub_tree.pack(fill="both", expand=True, padx=6, pady=4)

    def _run_crtsh(self):
        target = self._osint_target.get().strip()
        if not target:
            return
        self._sub_tree.delete(*self._sub_tree.get_children())
        threading.Thread(target=self._exec_crtsh, args=(target,), daemon=True).start()

    def _exec_crtsh(self, domain: str):
        import urllib.request
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            req = urllib.request.Request(url, headers={"User-Agent": "G4MEOVER/1.0"})
            with urllib.request.urlopen(req, timeout=15) as r:
                data = json.loads(r.read().decode())
            seen = set()
            rows = []
            for entry in data:
                for name in entry.get("name_value", "").split("\n"):
                    name = name.strip().lower()
                    if name and name not in seen and domain in name:
                        seen.add(name)
                        rows.append((name, "—", "crt.sh"))
            def update():
                for row in rows:
                    self._sub_tree.insert("", "end", values=row)
                self._sub_count.set(f"{len(rows)} Subdomains")
                self._report_data["Subdomains"] = "\n".join(r[0] for r in rows)
                self._log(self._osint_log, f"[crt.sh] {len(rows)} Subdomains gefunden.", "info")
            self.after(0, update)
        except Exception as e:
            self.after(0, self._log, f"[crt.sh] Fehler: {e}", "error", self._osint_log)

    def _run_dnsbrute(self):
        target = self._osint_target.get().strip()
        if not target:
            return
        threading.Thread(target=self._exec_dnsbrute, args=(target,), daemon=True).start()

    def _exec_dnsbrute(self, domain: str):
        common = ["www", "mail", "ftp", "smtp", "pop", "imap", "vpn", "dev",
                  "test", "staging", "api", "admin", "portal", "blog", "shop",
                  "cdn", "static", "ns1", "ns2", "mx", "webmail", "remote"]
        found = []
        for sub in common:
            full = f"{sub}.{domain}"
            try:
                ip = socket.gethostbyname(full)
                found.append((full, ip, "DNS-Brute"))
            except Exception:
                pass
        def update():
            for row in found:
                try:
                    self._sub_tree.insert("", "end", values=row)
                except Exception:
                    pass
            c = int(self._sub_count.get().split()[0]) if self._sub_count.get() else 0
            self._sub_count.set(f"{c + len(found)} Subdomains")
            self._log(self._osint_log, f"[DNS-Brute] {len(found)} Treffer.", "info")
        self.after(0, update)

    # ═══════════════════════════════════════════════════════════════════════════
    # Shodan Tab
    # ═══════════════════════════════════════════════════════════════════════════

    def _build_shodan(self, parent):
        self._info_bar(parent,
            "Shodan: Suchmaschine für vernetzte Geräte. Zeigt offene Ports, Dienste, Banner und bekannte Schwachstellen. Benötigt kostenlosen API-Key (shodan.io).")
        fkey = self._section(parent, "API-Key")
        krow = tk.Frame(fkey, bg=DARK["bg"]); krow.pack(fill="x", padx=10, pady=4)
        tk.Label(krow, text="Shodan API-Key:", bg=DARK["bg"], fg=DARK["fg"],
                 font=("Segoe UI", 8), width=16, anchor="w").pack(side="left")
        self._shodan_key = tk.StringVar(value=self.cfg.get("shodan_api_key", ""))
        tk.Entry(krow, textvariable=self._shodan_key,
                 bg=DARK["entry"], fg=DARK["fg"],
                 insertbackground=DARK["fg"], relief="flat",
                 font=("Consolas", 8), width=36, show="*").pack(side="left", padx=4, ipady=2)

        btn_row = tk.Frame(parent, bg=DARK["bg"]); btn_row.pack(fill="x", padx=10, pady=4)
        ttk.Button(btn_row, text="Host-Info abfragen",
                   style="Accent.TButton",
                   command=self._run_shodan_host).pack(side="left")
        ttk.Button(btn_row, text="Shodan-Suche",
                   command=self._run_shodan_search).pack(side="left", padx=4)
        ttk.Button(btn_row, text="API-Key testen",
                   command=self._test_shodan_key).pack(side="left")

        finfo = self._section(parent, "Host-Informationen")
        self._shodan_fields: dict[str, tk.StringVar] = {}
        for label, key in [
            ("IP:",          "ip_str"),
            ("Hostname:",    "_hostname"),
            ("ISP:",         "isp"),
            ("Organisation:","org"),
            ("ASN:",         "asn"),
            ("Land:",        "country_name"),
            ("Stadt:",       "city"),
            ("OS:",          "_os"),
            ("Tags:",        "_tags"),
        ]:
            row = tk.Frame(finfo, bg=DARK["bg"]); row.pack(fill="x", padx=10, pady=1)
            tk.Label(row, text=label, bg=DARK["bg"], fg=DARK["border"],
                     font=("Segoe UI", 8), width=14, anchor="w").pack(side="left")
            var = tk.StringVar(value="—")
            tk.Label(row, textvariable=var, bg=DARK["bg"], fg=DARK["fg"],
                     font=("Consolas", 8), anchor="w").pack(side="left", padx=4)
            self._shodan_fields[key] = var

        fports = self._section(parent, "Offene Ports / Dienste")
        cols = ("port", "proto", "product", "version", "cpe")
        self._shodan_tree = ttk.Treeview(parent, columns=cols, show="headings", height=8)
        for col, w, label in [("port", 70, "Port"), ("proto", 60, "Proto"),
                               ("product", 140, "Produkt"), ("version", 120, "Version"),
                               ("cpe", 200, "CPE")]:
            self._shodan_tree.heading(col, text=label)
            self._shodan_tree.column(col, width=w, minwidth=40)
        self._shodan_tree.tag_configure("open", foreground=DARK["green"])
        ssb = ttk.Scrollbar(parent, command=self._shodan_tree.yview)
        self._shodan_tree.configure(yscrollcommand=ssb.set)
        ssb.pack(side="right", fill="y")
        self._shodan_tree.pack(fill="both", expand=True, padx=6, pady=4)

    def _get_shodan_key(self) -> str:
        key = self._shodan_key.get().strip()
        if not key:
            messagebox.showwarning("API-Key fehlt",
                "Shodan API-Key in OSINT-Tab oder Einstellungen eingeben.\n"
                "Kostenloser Key: https://account.shodan.io")
        return key

    def _run_shodan_host(self):
        key = self._get_shodan_key()
        if not key:
            return
        target = self._osint_target.get().strip()
        if not target:
            return
        self._shodan_tree.delete(*self._shodan_tree.get_children())
        for var in self._shodan_fields.values():
            var.set("Lade …")
        threading.Thread(target=self._exec_shodan_host, args=(target, key), daemon=True).start()

    def _exec_shodan_host(self, target: str, key: str):
        import urllib.request, urllib.parse, urllib.error
        try:
            url = f"https://api.shodan.io/shodan/host/{urllib.parse.quote(target)}?key={key}"
            req = urllib.request.Request(url, headers={"User-Agent": "G4MEOVER/1.0"})
            with urllib.request.urlopen(req, timeout=15) as r:
                data = json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            err = e.read().decode("utf-8", errors="replace")
            self.after(0, self._log, self._osint_log,
                       f"[Shodan] HTTP {e.code}: {err[:120]}\n", "red")
            self.after(0, lambda: [v.set("Fehler") for v in self._shodan_fields.values()])
            return
        except Exception as e:
            self.after(0, self._log, self._osint_log, f"[Shodan] {e}\n", "red")
            return

        def update():
            self._shodan_fields["ip_str"].set(data.get("ip_str", "—"))
            hostnames = data.get("hostnames", [])
            self._shodan_fields["_hostname"].set(", ".join(hostnames[:3]) or "—")
            self._shodan_fields["isp"].set(data.get("isp", "—"))
            self._shodan_fields["org"].set(data.get("org", "—"))
            self._shodan_fields["asn"].set(data.get("asn", "—"))
            self._shodan_fields["country_name"].set(data.get("country_name", "—"))
            self._shodan_fields["city"].set(data.get("city", "—"))
            self._shodan_fields["_os"].set(data.get("os", "—") or "—")
            tags = data.get("tags", [])
            self._shodan_fields["_tags"].set(", ".join(tags) or "—")

            for svc in data.get("data", []):
                port    = str(svc.get("port", "?"))
                proto   = svc.get("transport", "tcp")
                product = svc.get("product", "")
                version = svc.get("version", "")
                cpe     = ", ".join(svc.get("cpe", []))
                self._shodan_tree.insert("", "end",
                    values=(port, proto, product, version, cpe),
                    tags=("open",))

            self._report_data["Shodan"] = json.dumps(data, indent=2, ensure_ascii=False)
            self._log(self._osint_log,
                      f"[Shodan] {data.get('ip_str')} – "
                      f"{len(data.get('data', []))} Ports gefunden.\n", "green")
        self.after(0, update)

    def _run_shodan_search(self):
        key = self._get_shodan_key()
        if not key:
            return
        query = self._osint_target.get().strip()
        if not query:
            return
        threading.Thread(target=self._exec_shodan_search, args=(query, key), daemon=True).start()

    def _exec_shodan_search(self, query: str, key: str):
        import urllib.request, urllib.parse
        try:
            enc = urllib.parse.quote(query)
            url = f"https://api.shodan.io/shodan/host/search?key={key}&query={enc}&facets=port,country"
            req = urllib.request.Request(url, headers={"User-Agent": "G4MEOVER/1.0"})
            with urllib.request.urlopen(req, timeout=15) as r:
                data = json.loads(r.read().decode())
        except Exception as e:
            self.after(0, self._log, self._osint_log, f"[Shodan Search] {e}\n", "red")
            return

        total = data.get("total", 0)
        def update():
            self._shodan_tree.delete(*self._shodan_tree.get_children())
            for match in data.get("matches", [])[:50]:
                ip      = match.get("ip_str", "?")
                port    = str(match.get("port", "?"))
                product = match.get("product", "")
                version = match.get("version", "")
                self._shodan_tree.insert("", "end",
                    values=(f"{ip}:{port}", "tcp", product, version, ""),
                    tags=("open",))
            self._log(self._osint_log,
                      f"[Shodan Search] {total} Treffer für '{query}'.\n", "green")
        self.after(0, update)

    def _test_shodan_key(self):
        key = self._shodan_key.get().strip()
        if not key:
            messagebox.showwarning("Kein Key", "API-Key eingeben."); return
        threading.Thread(target=self._exec_shodan_keytest, args=(key,), daemon=True).start()

    def _exec_shodan_keytest(self, key: str):
        import urllib.request
        try:
            url = f"https://api.shodan.io/api-info?key={key}"
            with urllib.request.urlopen(url, timeout=10) as r:
                data = json.loads(r.read().decode())
            plan = data.get("plan", "?")
            qs   = data.get("query_credits", "?")
            self.after(0, messagebox.showinfo, "Shodan OK",
                       f"Plan: {plan}\nQuery-Credits: {qs}")
        except Exception as e:
            self.after(0, messagebox.showerror, "Shodan Fehler", str(e))

    # ═══════════════════════════════════════════════════════════════════════════
    # OUI / BSSID Tab
    # ═══════════════════════════════════════════════════════════════════════════

    def _build_oui(self, parent):
        self._info_bar(parent,
            "OUI/BSSID-Lookup: Ermittelt den Gerätehersteller anhand der MAC-Adresse (BSSID). Nützlich für WLAN-Analyse und Geräteerkennung.")
        fip = self._section(parent, "MAC / BSSID Lookup")
        self._oui_mac_var = tk.StringVar()
        self._entry_row(fip, "MAC-Adresse:", self._oui_mac_var)
        self._oui_ssid_var = tk.StringVar()
        self._entry_row(fip, "SSID (opt.):", self._oui_ssid_var)
        ttk.Button(fip, text="Hersteller ermitteln",
                   command=self._run_oui).pack(padx=10, pady=4, anchor="w")

        fres = self._section(parent, "Ergebnis")
        self._oui_vendor = tk.StringVar(value="—")
        self._oui_mask   = tk.StringVar(value="—")
        for label, var in [("Hersteller:", self._oui_vendor),
                           ("Masken-Empfehlung:", self._oui_mask)]:
            row = tk.Frame(fres, bg=DARK["bg"]); row.pack(fill="x", padx=10, pady=2)
            tk.Label(row, text=label, bg=DARK["bg"], fg=DARK["border"],
                     font=("Segoe UI", 8), width=20, anchor="w").pack(side="left")
            tk.Label(row, textvariable=var, bg=DARK["bg"], fg=DARK["accent"],
                     font=("Consolas", 9), anchor="w").pack(side="left")

    def _run_oui(self):
        mac  = self._oui_mac_var.get().strip()
        ssid = self._oui_ssid_var.get().strip()
        if not mac and not ssid:
            messagebox.showerror("Fehler", "MAC oder SSID angeben."); return
        vendor, maskfile = detect_vendor(ssid, mac)
        self._oui_vendor.set(vendor)
        self._oui_mask.set(maskfile or "—")

    # ═══════════════════════════════════════════════════════════════════════════
    # Hilfsmethoden
    # ═══════════════════════════════════════════════════════════════════════════

    def _run_all(self):
        self._run_whois()
        self._run_dns()
        self._run_geo()
        self._run_crtsh()

    def _text_area(self, parent) -> tk.Text:
        t = tk.Text(parent, bg=DARK["panel"], fg=DARK["fg"],
                    font=("Consolas", 8), relief="flat", wrap="word",
                    state="disabled")
        sb = ttk.Scrollbar(parent, command=t.yview)
        t.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        t.pack(fill="both", expand=True, padx=6, pady=4)
        return t

    def _append_text(self, widget: tk.Text, text: str):
        widget.configure(state="normal")
        widget.insert("end", text)
        widget.see("end")
        widget.configure(state="disabled")

    def _export_txt(self):
        from tkinter import filedialog
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text", "*.txt"), ("Alle", "*.*")],
            title="OSINT-Report speichern")
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            f.write(f"OSINT-Report – {datetime.now().strftime('%Y-%m-%d %H:%M')}\n")
            f.write(f"Ziel: {self._osint_target.get()}\n")
            f.write("=" * 60 + "\n\n")
            for section, content in self._report_data.items():
                f.write(f"## {section}\n{content}\n\n")
        self._log(self._osint_log, f"[Export] {path}", "info")

    def _export_md(self):
        from tkinter import filedialog
        path = filedialog.asksaveasfilename(
            defaultextension=".md",
            filetypes=[("Markdown", "*.md"), ("Alle", "*.*")],
            title="OSINT-Report speichern")
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            f.write(f"# OSINT-Report: {self._osint_target.get()}\n\n")
            f.write(f"*Erstellt: {datetime.now().strftime('%Y-%m-%d %H:%M')}*\n\n")
            for section, content in self._report_data.items():
                f.write(f"## {section}\n\n```\n{content}\n```\n\n")
        self._log(self._osint_log, f"[Export] {path}", "info")
