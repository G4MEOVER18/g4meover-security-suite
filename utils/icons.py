"""
utils/icons.py – 24x24 Tab-Icons für die G4MEOVER Security Suite.

Generiert PIL-basierte Icons (rounded rectangle + zentriertes Symbol)
im Catppuccin Mocha Theme und cached sie als tk.PhotoImage, damit
der GC sie nicht vorzeitig löscht.
"""

from __future__ import annotations
import io
import base64
import tkinter as tk
from PIL import Image, ImageDraw, ImageFont, ImageTk

# ─── Catppuccin Mocha Farben ─────────────────────────────────────────────────

_BG     = "#1e1e2e"   # base background
_PANEL  = "#181825"   # panel / tab background
_BORDER = "#45475a"   # border / subdued

_ACCENT  = "#89b4fa"  # blue  – Dashboard
_TEAL    = "#94e2d5"  # teal  – Netzwerk
_GREEN   = "#a6e3a1"  # green – WiFi / PMKID
_PURPLE  = "#cba6f7"  # purple– Handshake / Passwörter
_YELLOW  = "#f9e2af"  # yellow– Web-Testing
_ORANGE  = "#fab387"  # orange– OSINT / Reporting
_RED     = "#f38ba8"  # red   – Exploits
_MAROON  = "#eba0ac"  # sub-red – Einstellungen
_SKY     = "#89dceb"  # sky   – Hilfe

# ─── Icon-Definitionen ────────────────────────────────────────────────────────
# Jeder Eintrag: (tab_key, symbol, accent_color)

_ICON_DEFS: list[tuple[str, str, str]] = [
    ("dashboard",    "⬡",  _ACCENT),
    ("network",      "⊞",  _TEAL),
    ("wifi",         "≋",  _GREEN),
    ("handshake",    "⊕",  _PURPLE),
    ("pmkid",        "⊛",  _GREEN),
    ("passwords",    "⊗",  _PURPLE),
    ("web",          "⊚",  _YELLOW),
    ("osint",        "⊜",  _ORANGE),
    ("exploits",     "⚡",  _RED),
    ("reporting",    "☰",  _ORANGE),
    ("settings",     "⚙",  _MAROON),
    ("help",         "?",  _SKY),
]

# ─── Interne Helfer ───────────────────────────────────────────────────────────

SIZE    = 24   # Gesamtgrösse des Icons
RADIUS  = 5    # Ecken-Radius des rounded rectangle
PADDING = 2    # Abstand zwischen Rand und Rechteck


def _hex_to_rgb(hex_color: str) -> tuple[int, int, int]:
    """#rrggbb -> (r, g, b)."""
    h = hex_color.lstrip("#")
    return int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)


def _mix(hex_fg: str, hex_bg: str, alpha: float) -> tuple[int, int, int]:
    """Lineares Alpha-Blending von fg über bg (alpha 0..1)."""
    fr, fg, fb = _hex_to_rgb(hex_fg)
    br, bg, bb = _hex_to_rgb(hex_bg)
    return (
        int(fr * alpha + br * (1 - alpha)),
        int(fg * alpha + bg * (1 - alpha)),
        int(fb * alpha + bb * (1 - alpha)),
    )


def _rounded_rect(draw: ImageDraw.ImageDraw,
                  xy: tuple[int, int, int, int],
                  radius: int,
                  fill: tuple[int, int, int],
                  outline: tuple[int, int, int] | None = None) -> None:
    """Zeichnet ein ausgefülltes Rounded Rectangle (kompatibel mit älteren PIL)."""
    x0, y0, x1, y1 = xy
    # Ecken
    draw.ellipse([x0, y0, x0 + radius * 2, y0 + radius * 2], fill=fill)
    draw.ellipse([x1 - radius * 2, y0, x1, y0 + radius * 2], fill=fill)
    draw.ellipse([x0, y1 - radius * 2, x0 + radius * 2, y1], fill=fill)
    draw.ellipse([x1 - radius * 2, y1 - radius * 2, x1, y1], fill=fill)
    # Mittelfläche
    draw.rectangle([x0 + radius, y0, x1 - radius, y1], fill=fill)
    draw.rectangle([x0, y0 + radius, x1, y1 - radius], fill=fill)
    if outline:
        draw.arc([x0, y0, x0 + radius * 2, y0 + radius * 2], 180, 270, fill=outline)
        draw.arc([x1 - radius * 2, y0, x1, y0 + radius * 2], 270, 0,   fill=outline)
        draw.arc([x0, y1 - radius * 2, x0 + radius * 2, y1], 90,  180, fill=outline)
        draw.arc([x1 - radius * 2, y1 - radius * 2, x1, y1], 0,   90,  fill=outline)
        draw.line([x0 + radius, y0, x1 - radius, y0], fill=outline)
        draw.line([x0 + radius, y1, x1 - radius, y1], fill=outline)
        draw.line([x0, y0 + radius, x0, y1 - radius], fill=outline)
        draw.line([x1, y0 + radius, x1, y1 - radius], fill=outline)


def _make_icon(symbol: str, accent_hex: str) -> Image.Image:
    """
    Erstellt ein 24x24 RGBA-Image:
      - Transparenter Hintergrund
      - Abgerundetes Rechteck in gedimmtem Accent-Farbton
      - Zentriertes Symbol in vollem Accent
    """
    img  = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # Hintergrund-Rechteck: Accent mit ~25 % Deckkraft über Panel-Farbe
    rect_rgb = _mix(accent_hex, _PANEL, 0.25)
    _rounded_rect(
        draw,
        (PADDING, PADDING, SIZE - PADDING - 1, SIZE - PADDING - 1),
        radius=RADIUS,
        fill=rect_rgb,
    )

    # Accent-Umrandung (1 px, dezent)
    border_rgb = _mix(accent_hex, _PANEL, 0.55)
    _rounded_rect(
        draw,
        (PADDING, PADDING, SIZE - PADDING - 1, SIZE - PADDING - 1),
        radius=RADIUS,
        fill=rect_rgb,      # gleich, Outline-Logik nur für die Linien relevant
        outline=border_rgb,
    )

    # Symbol zentriert zeichnen
    accent_rgb = _hex_to_rgb(accent_hex)

    # Versuche einen Unicode-fähigen Font zu laden; falle auf Default zurück
    font: ImageFont.FreeTypeFont | ImageFont.ImageFont
    font_size = 12
    for font_name in (
        "seguisym.ttf",      # Segoe UI Symbol (Windows)
        "segoeuisl.ttf",
        "segoeui.ttf",
        "arial.ttf",
        "DejaVuSans.ttf",
    ):
        try:
            font = ImageFont.truetype(font_name, font_size)
            break
        except (IOError, OSError):
            continue
    else:
        font = ImageFont.load_default()

    # Textgrösse ermitteln (PIL ≥ 9.2 hat getbbox, ältere getsize)
    try:
        bbox = font.getbbox(symbol)
        tw = bbox[2] - bbox[0]
        th = bbox[3] - bbox[1]
        tx = (SIZE - tw) // 2 - bbox[0]
        ty = (SIZE - th) // 2 - bbox[1]
    except AttributeError:
        tw, th = font.getsize(symbol)  # type: ignore[attr-defined]
        tx = (SIZE - tw) // 2
        ty = (SIZE - th) // 2

    draw.text((tx, ty), symbol, fill=accent_rgb + (255,), font=font)

    return img


def _img_to_photoimage(img: Image.Image) -> ImageTk.PhotoImage:
    """Konvertiert ein PIL RGBA-Image in ein tk.PhotoImage."""
    return ImageTk.PhotoImage(img)


# ─── Öffentlicher Cache ───────────────────────────────────────────────────────

# Globaler Dict-Cache: key -> PhotoImage
# Muss global bleiben, damit der GC die Bilder nicht löscht!
_ICON_CACHE: dict[str, ImageTk.PhotoImage] = {}


def get_icon(key: str) -> "ImageTk.PhotoImage | None":
    """Gibt das gecachte PhotoImage für den Tab-Key zurück (oder None)."""
    return _ICON_CACHE.get(key)


def build_icons() -> dict[str, "ImageTk.PhotoImage"]:
    """
    Generiert alle Icons und befüllt den Cache.
    Muss nach tk.Tk() aufgerufen werden.
    """
    for key, symbol, accent in _ICON_DEFS:
        if key not in _ICON_CACHE:
            try:
                img   = _make_icon(symbol, accent)
                photo = _img_to_photoimage(img)
                _ICON_CACHE[key] = photo
            except Exception:
                pass
    return _ICON_CACHE


# Tab-Label → Icon-Key Mapping
_LABEL_TO_KEY: dict[str, str] = {
    "Dashboard":     "dashboard",
    "Netzwerk":      "network",
    "WiFi / WPA":    "wifi",
    "Handshake":     "handshake",
    "PMKID":         "pmkid",
    "Passwörter":    "passwords",
    "Web-Testing":   "web",
    "OSINT":         "osint",
    "Exploits":      "exploits",
    "Reporting":     "reporting",
    "Einstellungen": "settings",
    "Hilfe":         "help",
}


def icon_for_label(label: str) -> "ImageTk.PhotoImage | None":
    """Gibt das Icon für einen Tab-Label-String zurück (stripped)."""
    key = _LABEL_TO_KEY.get(label.strip())
    return _ICON_CACHE.get(key) if key else None
