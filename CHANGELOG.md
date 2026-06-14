# Changelog

Alle nennenswerten Änderungen an der G4MEOVER Security Suite werden in dieser Datei dokumentiert.

Das Format orientiert sich an [Keep a Changelog](https://keepachangelog.com/de/1.1.0/),
die Versionierung folgt [Semantic Versioning](https://semver.org/lang/de/).

## [2.4.0] – 2026-06-14

### Hinzugefügt
- `LICENSE` (MIT) inkl. Klausel zu separat installierten Drittanbieter-Tools.
- `requirements.txt` mit gepinnten Laufzeit-Abhängigkeiten (pillow, scapy).
- `CHANGELOG.md` mit vollständiger Versionshistorie.
- Zentrale Projekt-Metadaten in `utils/meta.py` (Single Source of Truth für
  Version, Autor, Kontakt und Spenden-Infos).
- Kontakt-E-Mail und Spenden-Optionen (PayPal, Bitcoin) im About-Dialog sowie
  im neuen Bereich „Über & Kontakt" des Hilfe-Moduls.

### Geändert
- README vollständig auf v2.4 aktualisiert: alle 27 Module (offensiv + defensiv),
  korrigierte Installationsanweisung, Kontakt- und Support-Abschnitt.
- Konfigurations-Handling abgesichert: beschädigte `suite_config.json` wird beim
  Start als `.corrupt` gesichert statt verworfen; Speichern erfolgt atomar
  (temporäre Datei + Replace) und meldet Fehler sichtbar.

### Behoben
- Falsche Abhängigkeitsangabe `requests` aus der Installationsanleitung entfernt
  (wird nicht verwendet, der Code nutzt `urllib`).

## [2.4] – 2026-06-11
### Geändert
- Tab-Konsolidierung in thematische Kategorien (Recon, WLAN, Passwörter,
  Härtung, Angriffstests, Forensik).
- Aktive Tests der Module am eigenen System.

## [2.3] – 2026-06-11
### Hinzugefügt
- Phase 6: Defensive- & Audit-Säule – Hardening-, Konten-, Firewall- und
  AV/EDR-Audits, Privilege-Escalation- und Vuln-Checks, Port-Exposure,
  EDR-Simulation, lokales Passwort-Audit, Integritäts-Monitor, Event-Log-Forensik.
- Automatische Übergabe aller Audit-Befunde an das Reporting-Modul.

## [1.5] – 2026-06-03
### Hinzugefügt
- Phase 5: Live Capture, Wordlist-Manager, Isolation-Tester.
- VirusTotal-Integration.

## [1.4] – 2026-06-01
### Hinzugefügt
- Handshake-Sniffer (4-Way-Handshake-Capture + Deauth).
- Windows-Installer mit gebündelten Tools.
- Spenden-Optionen.

### Geändert
- UI-Overhaul: Tab-Icons, Logo im Header, überarbeitetes Catppuccin-Mocha-Theme.
- Screenshots aller Tabs aktualisiert.

### Behoben
- Handshake-Interface-Erkennung (tshark-Pfad aus Config + Fallback).

## [1.3] – 2026-05-31
### Hinzugefügt
- Erste öffentliche Version der G4MEOVER Security Suite.
- PMKID-Sniffer, deutschsprachiges README, Screenshots, Anwendungs-Icon.

[2.4.0]: https://github.com/G4MEOVER18/g4meover-security-suite/releases/tag/v2.4.0
