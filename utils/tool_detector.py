"""Erkennt installierte Sicherheitstools beim Start."""
import os
import shutil
from pathlib import Path

TOOL_HINTS: dict[str, list[str]] = {
    "nmap": [
        r"C:\Program Files (x86)\Nmap\nmap.EXE",
        r"C:\Program Files (x86)\Nmap\nmap.exe",
        r"C:\Program Files\Nmap\nmap.exe",
    ],
    "hashcat": [
        r"C:\tools\Pentesting\hashcat-6.2.6 (1)\hashcat-6.2.6\hashcat.exe",
        r"C:\tools\Pentesting\hashcat\hashcat.exe",
        r"C:\tools\hashcat\hashcat.exe",
        r"C:\hashcat\hashcat.exe",
    ],
    "gobuster": [
        r"C:\tools\gobuster\gobuster.exe",
        r"C:\tools\Pentesting\gobuster\gobuster.exe",
    ],
    "feroxbuster": [
        r"C:\tools\feroxbuster\feroxbuster.exe",
        r"C:\tools\Pentesting\feroxbuster\feroxbuster.exe",
    ],
    "nikto": [
        r"C:\tools\nikto\nikto.bat",
        r"C:\tools\nikto\nikto-main\program\nikto.pl",
        r"C:\tools\Pentesting\nikto\program\nikto.pl",
    ],
    "sqlmap": [
        r"C:\Users\Yanis\AppData\Local\Programs\Python\Python312\Scripts\sqlmap.exe",
        r"C:\tools\sqlmap\sqlmap.py",
    ],
    "hydra": [
        r"C:\tools\hydra\hydra.bat",
        r"C:\tools\hydra\hydra.exe",
        r"C:\tools\Pentesting\hydra\hydra.bat",
        r"C:\tools\hydra\hydra.py",
    ],
    "john": [
        r"C:\tools\john\john-1.9.0-jumbo-1-win64\run\john.exe",
        r"C:\tools\john\run\john.exe",
        r"C:\tools\Pentesting\john\john-1.9.0-jumbo-1-win64\run\john.exe",
    ],
    "masscan": [
        r"C:\tools\masscan\masscan.bat",
        r"C:\tools\masscan\masscan.exe",
        r"C:\tools\Pentesting\masscan\masscan.bat",
    ],
    "tshark": [
        r"C:\Program Files\Wireshark\tshark.exe",
    ],
    "msfconsole": [
        r"C:\metasploit-framework\metasploit-framework\bin\msfconsole.bat",
        r"C:\metasploit-framework\bin\msfconsole.bat",
    ],
    "searchsploit": [
        r"C:\tools\exploitdb\searchsploit.bat",
        r"C:\tools\Pentesting\exploitdb\searchsploit.bat",
    ],
    "whatweb": [
        r"C:\tools\whatweb\whatweb.bat",
        r"C:\tools\whatweb\whatweb.py",
        r"C:\tools\Pentesting\whatweb\whatweb.bat",
    ],
}


def detect_tool(name: str, extra_hints: list[str] | None = None) -> str:
    """Gibt den Pfad zum Tool zurück oder '' wenn nicht gefunden."""
    found = shutil.which(name)
    if found:
        return found
    hints = TOOL_HINTS.get(name, []) + (extra_hints or [])
    for h in hints:
        if os.path.exists(h):
            return h
    return ""


def detect_all(cfg: dict) -> dict[str, str]:
    """Erkennt alle Tools. cfg-Einträge haben Vorrang."""
    results = {}
    for tool in TOOL_HINTS:
        cfg_val = cfg.get(f"tool_{tool}", "")
        if cfg_val and os.path.exists(cfg_val):
            results[tool] = cfg_val
        else:
            results[tool] = detect_tool(tool)
    return results
