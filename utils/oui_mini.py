"""OUI-Mini-Datenbank – bekannte Router-Hersteller."""
import re

SSID_VENDOR_PATTERNS = [
    (re.compile(r"fritz",            re.I), "AVM FritzBox",       "router_de.hcmask"),
    (re.compile(r"speedport",        re.I), "Telekom Speedport",  "router_de.hcmask"),
    (re.compile(r"easybox",          re.I), "Vodafone EasyBox",   "router_de.hcmask"),
    (re.compile(r"o2.wlan|o2.box",   re.I), "O2/Telefónica",      "router_de.hcmask"),
    (re.compile(r"vodafone",         re.I), "Vodafone Kabel",     "router_de.hcmask"),
    (re.compile(r"congstar",         re.I), "Congstar",           "router_de.hcmask"),
    (re.compile(r"telekom",          re.I), "Telekom",            "router_de.hcmask"),
    (re.compile(r"unitymedia",       re.I), "Unitymedia",         "router_de.hcmask"),
    (re.compile(r"kabel.?d|kdwlan",  re.I), "Kabel Deutschland",  "router_de.hcmask"),
    (re.compile(r"1und1|1&1",        re.I), "1&1",                "router_de.hcmask"),
    (re.compile(r"alice",            re.I), "Alice/O2",           "router_de.hcmask"),
    (re.compile(r"cisco",            re.I), "Cisco",              None),
    (re.compile(r"asus",             re.I), "ASUS",               None),
    (re.compile(r"tp.?link",         re.I), "TP-Link",            None),
    (re.compile(r"netgear",          re.I), "Netgear",            None),
    (re.compile(r"linksys",          re.I), "Linksys/Cisco",      None),
    (re.compile(r"dlink|d.link",     re.I), "D-Link",             None),
    (re.compile(r"zyxel",            re.I), "ZyXEL",              None),
    (re.compile(r"huawei",           re.I), "Huawei",             None),
    (re.compile(r"mikrotik",         re.I), "MikroTik",           None),
    (re.compile(r"ubiquiti|unifi",   re.I), "Ubiquiti",           None),
]

OUI_VENDORS: dict[str, tuple[str, str | None]] = {
    "3C4405": ("AVM FritzBox",       "router_de.hcmask"),
    "5C5B35": ("AVM FritzBox",       "router_de.hcmask"),
    "1C7B21": ("AVM FritzBox",       "router_de.hcmask"),
    "686B6F": ("AVM FritzBox",       "router_de.hcmask"),
    "7CF05F": ("AVM FritzBox",       "router_de.hcmask"),
    "6C0756": ("AVM FritzBox",       "router_de.hcmask"),
    "BC0542": ("AVM FritzBox",       "router_de.hcmask"),
    "E0CB4E": ("AVM FritzBox",       "router_de.hcmask"),
    "F4F5E8": ("Telekom Speedport",  "router_de.hcmask"),
    "7C2664": ("Telekom Speedport",  "router_de.hcmask"),
    "C4E984": ("Vodafone EasyBox",   "router_de.hcmask"),
    "4CAD97": ("Vodafone EasyBox",   "router_de.hcmask"),
    "E46F13": ("O2/Telefónica",      "router_de.hcmask"),
    "002369": ("Unitymedia",         "router_de.hcmask"),
    "587BEF": ("Unitymedia",         "router_de.hcmask"),
    "000C42": ("MikroTik",           None),
    "B4FBE4": ("TP-Link",            None),
    "50C7BF": ("TP-Link",            None),
    "A0F3C1": ("ASUS",               None),
    "2C4D54": ("Netgear",            None),
    "001E2A": ("Cisco",              None),
}


def detect_vendor(essid: str, ap_mac: str) -> tuple[str, str | None]:
    """SSID-Pattern → OUI-Fallback. Gibt (Hersteller, profile_key) zurück."""
    for pattern, vendor, profile in SSID_VENDOR_PATTERNS:
        if pattern.search(essid):
            return vendor, profile
    oui = ap_mac.replace(":", "").upper()[:6]
    if oui in OUI_VENDORS:
        return OUI_VENDORS[oui]
    return "Unbekannt", None
