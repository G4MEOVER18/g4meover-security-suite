<div align="center">

# G4MEOVER Security Suite

**All-in-One Pentesting-GUI für Windows · Python 3.12 · Catppuccin Mocha**

[![Version](https://img.shields.io/badge/Version-1.4-blue?style=flat-square)](https://github.com/G4MEOVER18/g4meover-security-suite/releases)
[![Python](https://img.shields.io/badge/Python-3.12-blue?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Plattform](https://img.shields.io/badge/Plattform-Windows%2011-lightgrey?style=flat-square&logo=windows)](.)
[![Lizenz](https://img.shields.io/badge/Lizenz-MIT-green?style=flat-square)](LICENSE)
[![Stars](https://img.shields.io/github/stars/G4MEOVER18/g4meover-security-suite?style=flat-square&color=yellow)](https://github.com/G4MEOVER18/g4meover-security-suite/stargazers)

*Entwickelt von **Yanis Ameseder***

</div>

---

Die **G4MEOVER Security Suite** vereint 13+ Sicherheitstools unter einer einheitlichen, dunklen Oberfläche im **Catppuccin Mocha**-Design. Entwickelt als persönliches Pentesting-Arsenal für Windows – von der Reconnaissance bis zum Report, alles in einem Fenster.

---

## Screenshots

### Dashboard
![Dashboard](assets/screenshots/01_dashboard.png)
*Tool-Status-Badges für alle 13 Tools, Activity-Log der letzten Aktionen, Quickstart-Buttons und globale Ziel-Eingabe im Header.*

---

### Netzwerk-Scanner
![Netzwerk](assets/screenshots/02_netzwerk.png)
*nmap mit 7 Scan-Profilen (Quick, Stealth, Full, Vuln...) und Masscan Quick-Sweep. Farbkodierter Treeview, Export JSON/TXT, History der letzten 10 Scans.*

---

### WiFi / WPA
![WiFi WPA](assets/screenshots/03_wifi_wpa.png)
*PCAP → hc22000-Konvertierung (Streaming), PCAP-Inspektor mit BSSID/OUI-Hersteller-Lookup (online + lokal), Hashcat-Launcher mit Live-Statistiken, Potfile-Viewer.*

---

### Handshake-Sniffer
![Handshake](assets/screenshots/04_handshake.png)
*WPA/WPA2 4-Way-Handshake-Capture. Netzwerk-Scan via Windows WLAN-API, passiver Capture mit tshark oder Scapy, **Deauth-Angriff** (Broadcast oder gezielt), automatische PCAP → hc22000 Konvertierung.*

---

### PMKID-Extraktor
![PMKID](assets/screenshots/05_pmkid.png)
*Extrahiert PMKIDs aus bestehenden PCAP-Dateien (kein Handshake nötig) oder per Live-Capture. Direkte Übergabe an hashcat -m 22000.*

---

### Passwort-Cracker
![Passwörter](assets/screenshots/06_passwoerter.png)
*Hashcat (GPU, alle Modi), John the Ripper und Hydra (Online-Brute-Force: SSH, FTP, HTTP, RDP, SMB). Gefundene Credentials grün hervorgehoben.*

---

### Web-Testing
![Web](assets/screenshots/07_web.png)
*Directory-Bruteforce (gobuster/feroxbuster, Status-Code-Farben), nikto HTTP-Scanner, SQLMap SQL-Injection, WhatWeb Tech-Fingerprinting (CMS, Framework, Server, WAF).*

---

### OSINT
![OSINT](assets/screenshots/08_osint.png)
*WhoIs, DNS (A/MX/TXT/NS/CNAME), Subdomain-Enumeration via crt.sh, IP-Geolokation, Shodan-Integration, Reverse-IP, OUI/BSSID-Hersteller.*

---

### Exploits & CVE
![Exploits](assets/screenshots/09_exploits.png)
*SearchSploit-Wrapper (47.000+ ExploitDB-Einträge, kein Ruby), NIST NVD CVE-Suche mit CVSS-Score-Badges (grün/gelb/orange/rot), optionaler Metasploit-Launcher.*

---

### Reporting
![Reporting](assets/screenshots/10_reporting.png)
*Findings-Manager (Kritisch/Hoch/Mittel/Niedrig/Info), Session-Timeline, automatischer Report-Generator (Markdown, HTML, TXT).*

---

### Einstellungen
![Einstellungen](assets/screenshots/11_einstellungen.png)
*Tool-Pfade für alle 13 Tools, API-Keys (Shodan, VirusTotal), Workspace-Verzeichnis, Proxy und automatische Tool-Erkennung.*

---

### Hilfe-System
![Hilfe](assets/screenshots/12_hilfe.png)
*Interaktive Schritt-für-Schritt-Anleitungen für jedes Modul mit Tipps, Befehlsbeispielen und vollständigem Pentest-Workflow.*

---

## Funktionen

| Tab | Tools | Funktion |
|-----|-------|----------|
| **Dashboard** | — | Tool-Status, Activity-Log, Quickstart |
| **Netzwerk** | nmap, masscan | Host-Discovery, Port-Scan, OS-Erkennung |
| **WiFi / WPA** | hashcat, tshark | PCAP-Konvertierung, WPA-Cracking, BSSID-Lookup |
| **Handshake** | tshark, Scapy | 4-Way-Handshake-Sniffer + Deauth-Angriff |
| **PMKID** | tshark, hashcat | PMKID-Extraktion, Live-Sniffing |
| **Passwörter** | hashcat, john, hydra | Hash-Cracking (GPU), Online-Brute-Force |
| **Web-Testing** | gobuster, nikto, sqlmap, whatweb | Dir-Scan, HTTP-Audit, SQL-Inj., Fingerprinting |
| **OSINT** | — | WhoIs, DNS, Subdomain-Enum, Shodan, Geo-IP |
| **Exploits** | searchsploit, metasploit | CVE-Suche, ExploitDB, MSF-Launcher |
| **Reporting** | — | Findings, Markdown-/HTML-Report |
| **Einstellungen** | — | Pfade, API-Keys, Proxy |
| **Hilfe** | — | Schritt-für-Schritt-Guides |

---

## Installation

```bash
git clone https://github.com/G4MEOVER18/g4meover-security-suite.git
cd g4meover-security-suite
pip install scapy pillow requests
python openclaw_suite.py
```

### Empfohlene externe Tools

| Tool | Download | Funktion |
|------|----------|----------|
| nmap | [nmap.org](https://nmap.org/download.html) | Port-Scanner |
| hashcat | [hashcat.net](https://hashcat.net/hashcat/) | GPU Hash-Cracker |
| gobuster | [GitHub](https://github.com/OJ/gobuster/releases) | Dir-Bruteforce |
| feroxbuster | [GitHub](https://github.com/epi052/feroxbuster/releases) | Rekursiver Dir-Scanner |
| nikto | [GitHub](https://github.com/sullo/nikto) | Web-Scanner |
| sqlmap | [sqlmap.org](https://sqlmap.org/) | SQL-Injection |
| john | [openwall.com](https://www.openwall.com/john/) | Password Cracker |
| tshark | [Wireshark](https://www.wireshark.org/download.html) | Paket-Analyse / Capture |
| metasploit | [metasploit.com](https://www.metasploit.com/download) | Exploit-Framework |

> Python-Alternativen für **hydra**, **masscan** und **whatweb** sind bereits enthalten.

### Handshake-Sniffer & Deauth

Für Monitor-Mode und Packet-Injection (Deauth-Angriff) wird ein kompatibler WLAN-Adapter benötigt:
- **Alfa AWUS036ACH** (Realtek RTL8812AU) – empfohlen
- **TP-Link TL-WN722N v1** (Atheros AR9271)
- **Panda PAU09** (Ralink RT5572)

Passiver Handshake-Capture funktioniert auch ohne Monitor-Mode, sofern ein Client sich gerade verbindet.

---

## EXE bauen

```batch
copy mein-logo.ico assets\g4meover.ico
build_exe.bat
```

Ausgabe: `dist\G4MEOVER_Suite.exe` (~12 MB, kein Konsolenfenster, eigenes Icon)

---

## KI-Integration

```bash
python pentest_api_server.py   # Port 18800
```

| Endpoint | Parameter | Funktion |
|----------|-----------|----------|
| `/searchsploit` | `?query=apache` | ExploitDB durchsuchen |
| `/cve` | `?query=CVE-2021-44228` | NIST CVE-Lookup |
| `/nmap` | `?target=192.168.1.1` | Nmap ausführen |
| `/bssid` | `?mac=AA:BB:CC` | Hersteller-Lookup |

Ollama-kompatible Tool-Definitionen in `ai_core_client.py`.

---

## Konfiguration

```bash
cp suite_config.example.json suite_config.json
# Pfade und API-Keys anpassen
```

`suite_config.json` ist in `.gitignore` – deine Daten bleiben lokal.

---

## Disclaimer

> Dieses Tool ist **ausschließlich für autorisierte Sicherheitstests, CTF-Challenges und Bildungszwecke** bestimmt. Die Nutzung gegen Systeme ohne ausdrückliche schriftliche Genehmigung ist illegal. Der Entwickler übernimmt keinerlei Haftung für Missbrauch.

---

## Unterstützung

Wenn dir dieses Projekt gefällt, kannst du die Entwicklung unterstützen:

<div align="center">

### PayPal
[![PayPal](https://img.shields.io/badge/PayPal-Spenden-00457C?style=for-the-badge&logo=paypal&logoColor=white)](https://paypal.me/Freakbank1)

### Bitcoin
```
39vZWmnUwDReQ15BwqQXzyqVQ6U8LardEf
```

</div>

---

<div align="center">

**G4MEOVER Security Suite** · Entwickelt von Yanis Ameseder · MIT Lizenz

[GitHub](https://github.com/G4MEOVER18/g4meover-security-suite) · [Issues](https://github.com/G4MEOVER18/g4meover-security-suite/issues) · [Releases](https://github.com/G4MEOVER18/g4meover-security-suite/releases)

</div>
