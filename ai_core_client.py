#!/usr/bin/env python3
"""
G4MEOVER Pentest-API Client für AI-CORE (192.168.0.14)
Stellt Tool-Calling-Funktionen bereit die der Pentesting-LLM verwenden kann.

Verwendung auf AI-CORE:
  from ai_core_client import PentestTools
  tools = PentestTools("http://192.168.0.21:18800")
  results = tools.searchsploit("apache 2.4")
"""
import json
import urllib.request
import urllib.parse
from typing import Any


GAMINGNODE_API = "http://192.168.0.21:18800"


class PentestTools:
    """Client für die G4MEOVER Pentest-API auf dem GamingNode."""

    def __init__(self, base_url: str = GAMINGNODE_API, timeout: int = 30):
        self.base = base_url.rstrip("/")
        self.timeout = timeout

    def _get(self, endpoint: str, params: dict) -> Any:
        qs = urllib.parse.urlencode({k: v for k, v in params.items() if v is not None})
        url = f"{self.base}/{endpoint}?{qs}" if qs else f"{self.base}/{endpoint}"
        req = urllib.request.Request(url, headers={"User-Agent": "G4MEOVER-AICore/1.0"})
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            return json.loads(r.read())

    def searchsploit(self, query: str, exact: bool = False, limit: int = 50) -> list[dict]:
        """Sucht Exploits in der lokalen ExploitDB-Datenbank."""
        return self._get("searchsploit", {"query": query, "exact": int(exact), "limit": limit})

    def cve(self, query: str) -> list[dict]:
        """Sucht CVEs in der NIST NVD-Datenbank."""
        return self._get("cve", {"query": query})

    def nmap(self, target: str, profile: str = "quick") -> dict:
        """Scannt Netzwerk-Ziel mit nmap."""
        return self._get("nmap", {"target": target, "profile": profile})

    def bssid_vendor(self, mac: str) -> dict:
        """Sucht Hersteller einer BSSID/MAC-Adresse."""
        return self._get("bssid", {"mac": mac})

    def health(self) -> bool:
        """Prüft ob der API-Server erreichbar ist."""
        try:
            self._get("", {})
            return True
        except Exception:
            return False


# ── Ollama Tool-Definitions (für Modelfiles / System-Prompts) ─────────────────

OLLAMA_TOOLS_JSON = json.dumps([
    {
        "type": "function",
        "function": {
            "name": "searchsploit",
            "description": "Sucht in der ExploitDB-Datenbank nach Exploits für Software/Dienste",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Suchbegriff (z.B. 'apache 2.4', 'windows smb', 'log4j')"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Max. Ergebnisse (Standard: 20)"
                    }
                },
                "required": ["query"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "cve_lookup",
            "description": "Sucht CVE-Einträge in der NIST NVD-Datenbank mit CVSS-Score",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "CVE-ID (CVE-2021-44228) oder Stichwort (z.B. 'log4shell')"
                    }
                },
                "required": ["query"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "nmap_scan",
            "description": "Scannt ein Netzwerk-Ziel auf offene Ports und Dienste",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "IP-Adresse, Domain oder CIDR (z.B. '192.168.1.1')"
                    },
                    "profile": {
                        "type": "string",
                        "enum": ["quick", "standard", "stealth", "vuln"],
                        "description": "Scan-Profil: quick=schnell, standard=vollständig, vuln=Schwachstellen"
                    }
                },
                "required": ["target"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "bssid_lookup",
            "description": "Ermittelt den Hersteller einer WLAN-MAC-Adresse (BSSID)",
            "parameters": {
                "type": "object",
                "properties": {
                    "mac": {
                        "type": "string",
                        "description": "MAC-Adresse im Format aa:bb:cc:dd:ee:ff"
                    }
                },
                "required": ["mac"]
            }
        }
    }
], ensure_ascii=False, indent=2)


def _handle_tool_call(tools: PentestTools, tool_name: str, args: dict) -> str:
    """Führt einen Tool-Call aus und gibt das Ergebnis als JSON-String zurück."""
    try:
        if tool_name == "searchsploit":
            result = tools.searchsploit(args["query"], limit=args.get("limit", 20))
        elif tool_name == "cve_lookup":
            result = tools.cve(args["query"])
        elif tool_name == "nmap_scan":
            result = tools.nmap(args["target"], args.get("profile", "quick"))
        elif tool_name == "bssid_lookup":
            result = tools.bssid_vendor(args["mac"])
        else:
            result = {"error": f"Unbekanntes Tool: {tool_name}"}
    except Exception as e:
        result = {"error": str(e)}
    return json.dumps(result, ensure_ascii=False)


if __name__ == "__main__":
    import sys
    tools = PentestTools()
    print(f"Verbinde mit {GAMINGNODE_API} …")
    if not tools.health():
        print("[!] API-Server nicht erreichbar. Starte zuerst:")
        print("    python pentest_api_server.py")
        sys.exit(1)

    print("[+] Verbindung OK\n")

    if len(sys.argv) >= 3:
        cmd = sys.argv[1]
        arg = sys.argv[2]
        if cmd == "search":
            results = tools.searchsploit(arg)
            for r in results[:10]:
                print(f"[{r.get('id','?'):>5}] {r.get('title','?')}")
                print(f"       Pfad: {r.get('path','?')}")
        elif cmd == "cve":
            results = tools.cve(arg)
            for r in results:
                sev = r.get('severity', '?')
                print(f"  {r.get('id')} CVSS={r.get('cvss')} [{sev}]")
                print(f"  {r.get('description','?')[:100]}")
    else:
        print("Verwendung: python ai_core_client.py search <query>")
        print("            python ai_core_client.py cve <CVE-ID>")
        print()
        print(f"Ollama Tool-Definitions (für Modelfile):")
        print(OLLAMA_TOOLS_JSON[:300] + "…")
