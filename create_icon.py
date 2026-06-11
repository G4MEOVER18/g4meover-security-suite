"""Erstellt g4meover.ico mit Pillow – Catppuccin Mocha Farbschema."""
from PIL import Image, ImageDraw, ImageFont
import math, os

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets", "g4meover.ico")

# Catppuccin Mocha
BG      = (30,  30,  46)   # base
PANEL   = (49,  50,  68)   # surface0
ACCENT  = (137, 180, 250)  # blue
GREEN   = (166, 227, 161)  # green
RED     = (243, 139, 168)  # red
YELLOW  = (249, 226, 175)  # yellow
MAUVE   = (203, 166, 247)  # mauve
FG      = (205, 214, 244)  # text


def draw_icon(size: int) -> Image.Image:
    img  = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    s    = size
    pad  = max(2, s // 16)

    # ── Hintergrund: abgerundetes Quadrat ─────────────────────────────────────
    r = s // 6
    draw.rounded_rectangle([0, 0, s - 1, s - 1], radius=r, fill=PANEL)

    # ── Äußerer Ring (Radar-Stil) ──────────────────────────────────────────────
    cx, cy = s / 2, s / 2
    ring_r = s * 0.42
    draw.ellipse([cx - ring_r, cy - ring_r, cx + ring_r, cy + ring_r],
                 outline=ACCENT, width=max(1, s // 32))

    # ── Mittlerer Ring ────────────────────────────────────────────────────────
    ring2 = s * 0.28
    draw.ellipse([cx - ring2, cy - ring2, cx + ring2, cy + ring2],
                 outline=(*ACCENT[:3], 140), width=max(1, s // 48))

    # ── Kreuz / Fadenkreuz ────────────────────────────────────────────────────
    lw  = max(1, s // 40)
    gap = s * 0.12
    # horizontal
    draw.line([(pad, cy), (cx - gap, cy)], fill=ACCENT, width=lw)
    draw.line([(cx + gap, cy), (s - pad, cy)], fill=ACCENT, width=lw)
    # vertical
    draw.line([(cx, pad), (cx, cy - gap)], fill=ACCENT, width=lw)
    draw.line([(cx, cy + gap), (cx, s - pad)], fill=ACCENT, width=lw)

    # ── Radarstrahl (Sektor) ───────────────────────────────────────────────────
    if s >= 32:
        from PIL import ImageDraw as ID
        overlay = Image.new("RGBA", (s, s), (0, 0, 0, 0))
        od = ImageDraw.Draw(overlay)
        sweep_color = (*GREEN[:3], 60)
        od.pieslice([cx - ring_r, cy - ring_r, cx + ring_r, cy + ring_r],
                    start=-30, end=30, fill=sweep_color)
        img = Image.alpha_composite(img, overlay)
        draw = ImageDraw.Draw(img)

    # ── Zentraler Punkt ───────────────────────────────────────────────────────
    dot = max(2, s // 12)
    draw.ellipse([cx - dot, cy - dot, cx + dot, cy + dot], fill=RED)

    # ── "G4" Text (nur bei größeren Größen) ───────────────────────────────────
    if s >= 64:
        fs = max(8, s // 7)
        try:
            font = ImageFont.truetype("C:/Windows/Fonts/consolab.ttf", fs)
        except Exception:
            try:
                font = ImageFont.truetype("C:/Windows/Fonts/cour.ttf", fs)
            except Exception:
                font = ImageFont.load_default()
        text = "G4"
        bbox = draw.textbbox((0, 0), text, font=font)
        tw, th = bbox[2] - bbox[0], bbox[3] - bbox[1]
        tx = cx - tw / 2
        ty = cy + ring2 + s * 0.04
        # Schatten
        draw.text((tx + 1, ty + 1), text, font=font, fill=(0, 0, 0, 180))
        draw.text((tx, ty), text, font=font, fill=MAUVE)

    # ── 3 Punkte (Aktivitäts-Indikator) ──────────────────────────────────────
    if s >= 48:
        dot_r = max(1, s // 28)
        colors = [GREEN, YELLOW, RED]
        for i, col in enumerate(colors):
            dx = cx - (len(colors) - 1) * (dot_r * 2.5) / 2 + i * dot_r * 2.5
            dy = cy - ring2 - dot_r * 3
            draw.ellipse([dx - dot_r, dy - dot_r, dx + dot_r, dy + dot_r], fill=col)

    return img


sizes = [16, 24, 32, 48, 64, 128, 256]
frames = [draw_icon(s) for s in sizes]

os.makedirs(os.path.dirname(OUT), exist_ok=True)
frames[0].save(OUT, format="ICO", sizes=[(s, s) for s in sizes],
               append_images=frames[1:])
print(f"Icon erstellt: {OUT}")
print(f"Größen: {sizes}")
