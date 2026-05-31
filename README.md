# G4MEOVER Security Suite

<p align="center">
  <b>All-in-One Pentesting GUI für Windows · Python 3.12 · Catppuccin Mocha</b>
</p>

<p align="center">
  <img alt="Version" src="https://img.shields.io/badge/version-1.3-blue?style=flat-square">
  <img alt="Python" src="https://img.shields.io/badge/python-3.12-blue?style=flat-square&logo=python">
  <img alt="Platform" src="https://img.shields.io/badge/platform-Windows-lightgrey?style=flat-square">
  <img alt="License" src="https://img.shields.io/badge/license-MIT-green?style=flat-square">
</p>

---

Entwickelt von **Yanis Ameseder** als persönliches Pentesting-Arsenal unter Windows.
Kombiniert 13+ Sicherheitstools in einer einheitlichen, dunklen GUI.

## Features

| Tab | Tools |
|-----|-------|
| Dashboard | Tool-Status, Activity-Log, Quickstart |
| Netzwerk | nmap + masscan (Port-Sweep) |
| WiFi / WPA | PCAP → hc22000, Hashcat, BSSID-Lookup |
| Passwörter | Hashcat (GPU), John the Ripper, Hydra |
| Web-Testing | Gobuster, Feroxbuster, Nikto, SQLMap, WhatWeb |
| OSINT | WhoIs, DNS, IP-Geo, Shodan, crt.sh |
| Exploits | SearchSploit (ExploitDB), CVE-Suche, Metasploit |
| Reporting | Findings-Manager, Markdown/HTML Export |
| Einstellungen | Tool-Pfade, API-Keys, Workspace |
| Hilfe | Schritt-für-Schritt-Anleitungen |

## Voraussetzungen

```
Python 3.12+
tkinter (in Python-Standard-Installation enthalten)
```

Optional (werden automatisch erkannt):
- nmap, masscan, gobuster, feroxbuster, nikto, sqlmap
- hashcat, john, hydra, tshark, metasploit
- searchsploit (ExploitDB), whatweb

## Installation

```bash
git clone https://github.com/G4MEOVER/g4meover-security-suite.git
cd g4meover-security-suite
python openclaw_suite.py
```

## EXE bauen

```batch
build_exe.bat
```
Lege vorher dein Logo als `assets\g4meover.ico` ab.

## API-Server für KI-Integration

```bash
python pentest_api_server.py
# Läuft auf http://0.0.0.0:18800
# Endpoints: /searchsploit, /cve, /nmap, /bssid, /tools
```

## Disclaimer

Dieses Tool ist **ausschließlich für autorisierte Sicherheitstests und CTF-Challenges** bestimmt.
Jegliche missbräuchliche Nutzung liegt in der alleinigen Verantwortung des Benutzers.

---

*G4MEOVER Security Suite – by Yanis Ameseder*
