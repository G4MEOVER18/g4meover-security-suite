"""Hilfe-Tab – Schritt-für-Schritt-Anleitungen für alle G4MEOVER-Module."""
import tkinter as tk
from tkinter import ttk
from modules.base import BaseModule
from utils.theme import DARK

# ─── Anleitungen ──────────────────────────────────────────────────────────────

GUIDES: dict[str, dict] = {
    "WiFi / WPA-Cracking": {
        "icon": "📡",
        "kurz": "WPA-Handshake capturieren und mit hashcat cracken",
        "schritte": [
            ("1. PCAP aufnehmen",
             "Starte airodump-ng oder Wireshark im Monitor-Mode.\n"
             "Warte auf einen Handshake (Client muss sich neu verbinden).\n"
             "Alternativ: Deauthentication-Angriff mit aireplay-ng -0 1 -a <BSSID> <Interface>"),
            ("2. PCAP konvertieren",
             "WiFi/WPA-Tab → 'PCAP konvertieren'\n"
             "PCAP-Datei wählen → 'Konvertieren (Python-nativ)'\n"
             "Der PCAP-Inspektor zeigt ESSID, Hersteller und Maskenempfehlung.\n"
             "Ausgabe: .hc22000-Datei (hashcat-kompatibles Format)"),
            ("3. Maske wählen",
             "Im PCAP-Inspektor: Zeile auswählen → 'Maske übernehmen → Launcher'\n"
             "Oder im Hashcat-Launcher manuell wählen:\n"
             "  • Speedport/Telekom: 12 Ziffern (?d×12)\n"
             "  • FritzBox: 8 Kleinbuchstaben (?l×8)\n"
             "  • EasyBox: 8 Hex-Zeichen (?h×8)"),
            ("4. Hashcat starten",
             "Hashcat-Launcher → hc22000-Datei wählen\n"
             "Quickstart-Profil oder eigene Maske setzen\n"
             "Workload: 3 (Aggressiv) für maximale Geschwindigkeit\n"
             "'Crack starten' – Live-Statistiken werden angezeigt.\n"
             "Gefundene Passwörter: Potfile-Tab"),
        ],
        "tipps": [
            "PMKID-Angriff (kein Client nötig): hcxdumptool -o pmkid.pcapng -i <if> --enable_status=1",
            "Wordliste zuerst probieren (rockyou.txt), dann Masken",
            "Benchmark zeigt realistische Crack-Zeiten für deine GPU",
        ],
        "tab_name": "WiFi / WPA",
    },
    "Netzwerk-Scanner (nmap)": {
        "icon": "🔍",
        "kurz": "Hosts und offene Ports im Netzwerk entdecken",
        "schritte": [
            ("1. Ziel setzen",
             "Globale Ziel-Bar oben: IP, CIDR (192.168.1.0/24) oder Domain eingeben.\n"
             "'Alle Module setzen' überträgt das Ziel in alle Tabs.\n"
             "Alternativ direkt im Netzwerk-Tab eintragen."),
            ("2. Scan-Profil wählen",
             "Quick (-T4 -F): Schneller Scan der Top-100-Ports\n"
             "Standard (-T4 -A -p-): Alle Ports + Diensterkennung\n"
             "Stealth (-sS -T2): Langsamer, weniger auffällig\n"
             "Full (-sV -sC -O -p- --open): Vollständig mit Scripts\n"
             "Vuln (--script vuln): Automatische Schwachstellenprüfung"),
            ("3. Scan starten & Ergebnisse auswerten",
             "Grüne Zeilen = offene Ports\n"
             "Doppelklick auf Port 80/443 → Web-Testing-Tab\n"
             "Doppelklick auf Port 22 → Hydra SSH-Tab\n"
             "Export: JSON oder TXT für Reporting"),
        ],
        "tipps": [
            "Tipp: ping-less: nmap -Pn <ziel> wenn ICMP blockiert",
            "UDP-Scan: nmap -sU -p 53,161,500 <ziel>",
            "NSE-Scripts: nmap --script=http-headers,ssl-cert <ziel>",
        ],
        "tab_name": "Netzwerk",
    },
    "Web-Testing": {
        "icon": "🌐",
        "kurz": "Webanwendungen auf Schwachstellen testen",
        "schritte": [
            ("1. Ziel-URL eingeben",
             "Web-Testing-Tab → URL eingeben (z.B. http://10.0.0.1)\n"
             "Globales Ziel wird automatisch übernommen."),
            ("2. Directory-Bruteforce",
             "gobuster/feroxbuster → Wordlist wählen\n"
             "common.txt: Schnell (~5000 Pfade)\n"
             "big.txt: Gründlich (~20000 Pfade)\n"
             "Extensions: .php .asp .aspx für Windows-Server"),
            ("3. HTTP-Scan (nikto)",
             "Nikto: One-Click Scanner für bekannte Web-Schwachstellen\n"
             "Prüft: veraltete Software, Default-Credentials, Fehlkonfigurationen"),
            ("4. SQL-Injection",
             "sqlmap → URL + Parameter angeben\n"
             "--dbs: Datenbanken auflisten\n"
             "--tables -D <db>: Tabellen zeigen\n"
             "--dump -T <table>: Daten extrahieren"),
        ],
        "tipps": [
            "Tech-Fingerprint zeigt Framework/CMS ohne aktiven Scan",
            "Proxy-Einstellung: Burp Suite (127.0.0.1:8080) für Traffic-Analyse",
            "robots.txt und sitemap.xml manuell prüfen",
        ],
        "tab_name": "Web-Testing",
    },
    "Passwort-Cracking": {
        "icon": "🔑",
        "kurz": "Hashes cracken und Online-Brute-Force",
        "schritte": [
            ("1. Hash identifizieren",
             "Passwörter-Tab → Hash-Identify\n"
             "Hash einfügen → Typ wird erkannt (MD5, SHA-256, NTLM, bcrypt…)\n"
             "Hashcat-Modus wird automatisch vorgeschlagen."),
            ("2. Hash cracken (offline)",
             "hashcat: Hash-Datei + Wordlist oder Maske\n"
             "john: Einfacher für viele Hash-Typen, gute Wordlist-Regeln\n"
             "Beispiel: hashcat -m 0 hash.txt rockyou.txt (MD5 + Wordlist)"),
            ("3. Online-Brute-Force (Hydra)",
             "Protokoll wählen: SSH, FTP, HTTP, RDP, SMB…\n"
             "Ziel-IP + Port + User-Liste + Passwort-Liste\n"
             "Gefundene Credentials → automatisch im Credential-Store"),
        ],
        "tipps": [
            "NTLM (Windows): hashcat -m 1000",
            "WPA (PMKID): hashcat -m 22000",
            "bcrypt ist sehr langsam – Masken-Angriff kaum praktikabel",
            "Credential-Store: alle gefundenen Zugangsdaten zentral gespeichert",
        ],
        "tab_name": "Passwörter",
    },
    "OSINT & Recon": {
        "icon": "🕵️",
        "kurz": "Passive Informationssammlung über Ziel-Domain oder IP",
        "schritte": [
            ("1. Ziel eingeben",
             "OSINT-Tab → Domain, IP-Adresse oder E-Mail eingeben"),
            ("2. Automatische Recon-Pipeline",
             "'Alle starten' führt alle Checks nacheinander aus:\n"
             "• WhoIs: Registrar, Datum, Nameserver\n"
             "• DNS: A/AAAA/MX/TXT/NS Records\n"
             "• Subdomains: crt.sh Certificate Transparency\n"
             "• IP-Geolokation: Land/Stadt/ISP\n"
             "• Shodan (API-Key nötig): offene Ports, Banner"),
            ("3. Ergebnisse auswerten",
             "Nameserver → eigene DNS-Zone?\n"
             "MX-Records → Mail-Server für weitere Tests\n"
             "Subdomains → unbekannte Angriffsfläche\n"
             "Shodan → bekannte CVEs für die Software-Version"),
        ],
        "tipps": [
            "Shodan-Key: kostenlos unter account.shodan.io",
            "crt.sh findet auch interne Subdomains (VPN, dev, staging…)",
            "OUI/BSSID-Lookup: MAC-Hersteller für WiFi-Targeting",
        ],
        "tab_name": "OSINT",
    },
    "Exploit-Research": {
        "icon": "💥",
        "kurz": "Exploits für gefundene Software/Dienste suchen",
        "schritte": [
            ("1. Searchsploit (lokal)",
             "Exploit-Research-Tab → Searchsploit\n"
             "Suchbegriff: Software + Version (z.B. 'apache 2.4')\n"
             "~47.000 Exploits in der lokalen Datenbank\n"
             "Doppelklick → Details anzeigen"),
            ("2. CVE-Suche (NIST NVD)",
             "CVE-ID direkt eingeben (CVE-2021-44228)\n"
             "Oder Stichwort → CVSS-Score + Beschreibung\n"
             "Rot (≥9): Kritisch – sofort patchen!\n"
             "Orange (≥7): Hoch"),
            ("3. Metasploit Quick-Launcher",
             "Metasploit-Tab → MSF-Konsole starten\n"
             "search <term>: Modul suchen\n"
             "use <modul>: Modul laden\n"
             "set RHOSTS <ziel>: Ziel setzen\n"
             "run / exploit: Ausführen"),
        ],
        "tipps": [
            "EDB-ID aus Searchsploit → searchsploit -x <id> für Details",
            "Metasploit: show options zeigt alle nötigen Parameter",
            "CVSS ≥ 9.0 = Remote Code Execution möglich (meistens)",
        ],
        "tab_name": "Exploits",
    },
    "Reporting": {
        "icon": "📋",
        "kurz": "Findings dokumentieren und Report erstellen",
        "schritte": [
            ("1. Finding eintragen",
             "Reporting-Tab → Findings-Manager\n"
             "Titel, Schweregrad (Kritisch/Hoch/Mittel/Niedrig/Info)\n"
             "Beschreibung + Beweis (Screenshot, Output) einfügen"),
            ("2. Timeline prüfen",
             "Alle Tool-Ausführungen der Sitzung werden automatisch erfasst\n"
             "Modul, Befehl, Zeit und Status sind protokolliert"),
            ("3. Report exportieren",
             "Markdown (.md): Direkt lesbar, für Git-Repos\n"
             "HTML (.html): Mit CSS-Formatierung, Farb-Klassen je Schweregrad\n"
             "TXT (.txt): Einfachster Export für alle Tools"),
        ],
        "tipps": [
            "Screenshot-Funktion: aktuellen Tab als PNG speichern",
            "HTML-Report: im Browser öffnen für professionelles Layout",
            "Schweregrad-Farben: Rot=Kritisch, Orange=Hoch, Gelb=Mittel, Blau=Info",
        ],
        "tab_name": "Reporting",
    },
    "Einstellungen & Setup": {
        "icon": "⚙️",
        "kurz": "Tool-Pfade, API-Keys und Workspace konfigurieren",
        "schritte": [
            ("1. Tool-Pfade prüfen",
             "Einstellungen-Tab → Tool-Pfade\n"
             "'Tools automatisch erkennen' findet installierte Tools\n"
             "Fehlende Tools: Pfad manuell eintragen oder Tool installieren"),
            ("2. API-Keys eintragen",
             "Shodan API-Key: account.shodan.io (kostenlos)\n"
             "VirusTotal API-Key: virustotal.com (kostenlos, 4 req/min)\n"
             "Ohne Keys sind OSINT-Features eingeschränkt"),
            ("3. Workspace einrichten",
             "Standard: C:\\Users\\Public\\pentest\\\n"
             "Hier werden alle Tool-Ausgaben gespeichert\n"
             "Verzeichnis wird automatisch erstellt"),
        ],
        "tipps": [
            "Proxy: Burp Suite (127.0.0.1:8080) für Web-Testing",
            "hashcat: C:\\tools\\Pentesting\\hashcat-6.2.6 (1)\\hashcat-6.2.6\\hashcat.exe",
            "searchsploit: C:\\tools\\exploitdb\\searchsploit.bat (Python-Wrapper)",
        ],
        "tab_name": "Einstellungen",
    },
}

PENTEST_WORKFLOW = """╔══════════════════════════════════════════════════════════════════╗
║            TYPISCHER PENTEST-WORKFLOW MIT G4MEOVER               ║
╚══════════════════════════════════════════════════════════════════╝

Phase 1 – RECON (passiv)
  1. OSINT-Tab: WhoIs, DNS, Subdomains, Shodan
  2. Ziel-Domain/-IP in globale Ziel-Bar eintragen

Phase 2 – SCANNING (aktiv)
  3. Netzwerk-Tab: Quick-Scan → offene Ports entdecken
  4. Web-Tab: Directory-Scan + nikto für Web-Services

Phase 3 – EXPLOITATION
  5. Exploit-Tab: CVE-Suche für gefundene Software-Versionen
  6. Searchsploit: Exploit-Code suchen und prüfen
  7. Metasploit: Modul laden und ausführen
  8. Web-Tab: sqlmap für SQL-Injection-Tests
  9. Passwörter-Tab: Hydra für Login-Seiten

Phase 4 – POST-EXPLOITATION
  10. Gefundene Hashes: hashcat/john zum Cracken
  11. WiFi: PCAP-Handshake → hashcat WPA-Cracking

Phase 5 – REPORTING
  12. Reporting-Tab: Findings eintragen
  13. Report exportieren (HTML für Kunden, MD für Archiv)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
HINWEIS: Nur auf Systemen verwenden für die du eine Genehmigung hast!
"""


class HelpModule(BaseModule):

    def _build(self):
        self._info_bar(self,
            "Hilfe: Schritt-für-Schritt-Anleitungen für alle Module · Tipps & Tricks · Typischer Pentest-Workflow")

        paned = tk.PanedWindow(self, orient="horizontal",
                               bg=DARK["bg"], sashwidth=5, sashrelief="flat")
        paned.pack(fill="both", expand=True, padx=4, pady=4)

        # ── Linke Navigation ──────────────────────────────────────────────────
        left = tk.Frame(paned, bg=DARK["panel"])
        paned.add(left, minsize=220, width=260)

        tk.Label(left, text="Module / Themen",
                 bg=DARK["panel"], fg=DARK["accent"],
                 font=("Segoe UI", 9, "bold")).pack(pady=(10, 4))

        self._guide_list = tk.Listbox(
            left, bg=DARK["panel"], fg=DARK["fg"],
            selectbackground=DARK["accent"], selectforeground=DARK["bg"],
            font=("Segoe UI", 9), relief="flat",
            activestyle="none", borderwidth=0, highlightthickness=0,
        )
        self._guide_list.pack(fill="both", expand=True, padx=6, pady=(0, 4))

        # Workflow-Button
        ttk.Button(left, text="Pentest-Workflow",
                   command=self._show_workflow).pack(fill="x", padx=6, pady=(0, 8))

        for name, data in GUIDES.items():
            self._guide_list.insert("end", f"  {data['icon']}  {name}")
        self._guide_list.bind("<<ListboxSelect>>", self._on_select)

        # ── Rechter Inhalt ────────────────────────────────────────────────────
        right = tk.Frame(paned, bg=DARK["bg"])
        paned.add(right, minsize=500)

        self._title_label = tk.Label(
            right, text="← Thema auswählen",
            bg=DARK["bg"], fg=DARK["accent"],
            font=("Segoe UI", 14, "bold"), anchor="w"
        )
        self._title_label.pack(fill="x", padx=14, pady=(12, 4))

        self._kurz_label = tk.Label(
            right, text="",
            bg=DARK["bg"], fg=DARK["border"],
            font=("Segoe UI", 9, "italic"), anchor="w"
        )
        self._kurz_label.pack(fill="x", padx=14, pady=(0, 8))

        self._content = tk.Text(
            right, bg=DARK["panel"], fg=DARK["fg"],
            font=("Segoe UI", 9), relief="flat",
            wrap="word", state="disabled",
            spacing1=2, spacing3=4,
            padx=14, pady=10,
        )
        sb = ttk.Scrollbar(right, command=self._content.yview)
        self._content.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self._content.pack(fill="both", expand=True, padx=4, pady=4)

        self._content.tag_configure("step_title",
            foreground=DARK["accent"], font=("Segoe UI", 10, "bold"))
        self._content.tag_configure("step_body",
            foreground=DARK["fg"], font=("Segoe UI", 9), lmargin1=20, lmargin2=20)
        self._content.tag_configure("tipp_head",
            foreground=DARK["yellow"], font=("Segoe UI", 9, "bold"))
        self._content.tag_configure("tipp",
            foreground=DARK["yellow"], font=("Consolas", 8), lmargin1=20, lmargin2=20)
        self._content.tag_configure("code",
            foreground=DARK["green"], font=("Consolas", 8),
            background=DARK["entry"], lmargin1=20, lmargin2=20)

        # Beim Start ersten Eintrag zeigen
        self._guide_list.selection_set(0)
        self._on_select(None)

    def _on_select(self, _event):
        sel = self._guide_list.curselection()
        if not sel:
            return
        name = list(GUIDES.keys())[sel[0]]
        self._show_guide(name)

    def _show_guide(self, name: str):
        data = GUIDES[name]
        self._title_label.configure(text=f"{data['icon']}  {name}")
        self._kurz_label.configure(text=data["kurz"])

        self._content.configure(state="normal")
        self._content.delete("1.0", "end")

        self._content.insert("end", "Schritt-für-Schritt\n\n", "step_title")
        for step_title, step_body in data["schritte"]:
            self._content.insert("end", f"  ▶  {step_title}\n", "step_title")
            self._content.insert("end", f"{step_body}\n\n", "step_body")

        if data.get("tipps"):
            self._content.insert("end", "  Tipps & Tricks\n", "tipp_head")
            for t in data["tipps"]:
                self._content.insert("end", f"  • {t}\n", "tipp")

        self._content.configure(state="disabled")
        self._content.see("1.0")

    def _show_workflow(self):
        self._title_label.configure(text="Pentest-Workflow")
        self._kurz_label.configure(text="Typische Vorgehensweise bei einem Penetrationstest")
        self._content.configure(state="normal")
        self._content.delete("1.0", "end")
        self._content.insert("end", PENTEST_WORKFLOW, "code")
        self._content.configure(state="disabled")
        self._content.see("1.0")
