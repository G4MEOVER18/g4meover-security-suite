"""
In-Process Screenshot-Script für G4MEOVER Suite.
Läuft im selben Python-Prozess → kein Fokus-Problem, tabs werden garantiert gewechselt.
Aufruf: python take_screenshots.py
"""
import sys
import os
import time
from pathlib import Path

ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT))
os.chdir(str(ROOT))

from PIL import ImageGrab, Image
import win32gui

OUT = ROOT / "assets" / "screenshots"
OUT.mkdir(parents=True, exist_ok=True)

TABS = [
    (0,  "01_dashboard"),
    (1,  "02_netzwerk"),
    (2,  "03_wifi_wpa"),
    (3,  "04_handshake"),
    (4,  "05_pmkid"),
    (5,  "06_passwoerter"),
    (6,  "07_web"),
    (7,  "08_osint"),
    (8,  "09_exploits"),
    (9,  "10_reporting"),
    (10, "11_einstellungen"),
    (11, "12_hilfe"),
]

_app = None
_tab_queue = list(TABS)
_done = []

def _next_screenshot():
    global _tab_queue
    if not _tab_queue:
        _app.destroy()
        return

    idx, name = _tab_queue.pop(0)

    # Tab direkt per API wechseln – kein Mausklick, kein Fokus nötig
    try:
        _app._nb.select(idx)
    except Exception as e:
        print(f"  [!] Tab {idx} Fehler: {e}")

    # UI rendern lassen
    _app.update()
    _app.update_idletasks()

    # Screenshot via win32gui (exakte Fenstergrenzen)
    try:
        hwnd = win32gui.FindWindow(None, _app.title())
        if not hwnd:
            # Fallback: alle Fenster durchsuchen
            wins = []
            win32gui.EnumWindows(
                lambda h, _: wins.append(h)
                if "G4MEOVER" in win32gui.GetWindowText(h) else None, None)
            hwnd = wins[0] if wins else 0

        if hwnd:
            rect = win32gui.GetWindowRect(hwnd)
            img = ImageGrab.grab(bbox=rect)
        else:
            # Fallback: tkinter-Koordinaten
            x = _app.winfo_rootx()
            y = _app.winfo_rooty()
            w = _app.winfo_width()
            h = _app.winfo_height()
            img = ImageGrab.grab(bbox=(x, y, x + w, y + h))

        img = img.resize((1280, 720), Image.LANCZOS)
        path = OUT / (name + ".png")
        img.save(str(path))
        _done.append(name)
        print(f"  ✓  {name}.png  ({img.size})")
    except Exception as e:
        print(f"  [!] Screenshot {name}: {e}")

    # Nächsten Tab nach 1.8s planen
    _app.after(1800, _next_screenshot)


def main():
    global _app
    from openclaw_suite import G4MEOVERSuite

    print("G4MEOVER Screenshot-Tool")
    print(f"Ausgabe: {OUT}")
    print(f"Tabs:    {len(TABS)}")
    print()

    _app = G4MEOVERSuite()
    _app.geometry("1400x860+0+0")      # Position oben-links, kein Monitor-Versatz
    _app.lift()
    _app.attributes("-topmost", True)  # Sicherstellen dass Fenster vorne ist
    _app.update()

    # 4s warten bis vollständig geladen, dann loslegen
    _app.after(4000, _next_screenshot)
    _app.mainloop()

    print(f"\n{len(_done)}/{len(TABS)} Screenshots gespeichert.")


if __name__ == "__main__":
    main()
