"""
Startet die Suite, macht automatisiert Screenshots aller Tabs
und speichert sie nach assets/screenshots/
"""
import subprocess, time, os, sys
from pathlib import Path
from PIL import ImageGrab

try:
    import win32gui, win32con, win32api
    HAS_WIN32 = True
except ImportError:
    HAS_WIN32 = False

EXE   = Path(__file__).parent / "dist" / "G4MEOVER_Suite.exe"
OUT   = Path(__file__).parent / "assets" / "screenshots"
OUT.mkdir(parents=True, exist_ok=True)

TABS = [
    ("dashboard",   0),
    ("netzwerk",    1),
    ("wifi_wpa",    2),
    ("passwoerter", 3),
    ("web",         4),
    ("osint",       5),
    ("exploits",    6),
    ("reporting",   7),
    ("einstellungen",8),
    ("hilfe",       9),
]

def find_window(title_part: str):
    result = []
    def cb(hwnd, _):
        if win32gui.IsWindowVisible(hwnd):
            t = win32gui.GetWindowText(hwnd)
            if title_part.lower() in t.lower():
                result.append(hwnd)
    win32gui.EnumWindows(cb, None)
    return result[0] if result else None

def screenshot_window(hwnd, name: str):
    rect = win32gui.GetWindowRect(hwnd)
    x1, y1, x2, y2 = rect
    # kleiner Rand abschneiden
    img = ImageGrab.grab(bbox=(x1, y1, x2, y2))
    path = OUT / f"{name}.png"
    img.save(str(path))
    print(f"  Screenshot: {path.name}  ({img.width}x{img.height})")
    return path

def click_tab(hwnd, tab_index: int):
    """Sendet Ctrl+Tab oder klickt direkt auf Tab-Position."""
    # Tab per Tastatur wechseln: Ctrl+Tab bringt nicht zuverlässig zum richtigen Tab
    # Stattdessen: direkt per Maus auf Tab-Header klicken
    # Tab-Header befinden sich ca. bei y=50 (unterhalb des Headers)
    rect = win32gui.GetWindowRect(hwnd)
    x1 = rect[0]
    y_tab = rect[1] + 70          # Tab-Leiste
    # Tab-Breite ca. 110px, erster Tab bei ~30px
    x_tab = x1 + 30 + tab_index * 118
    win32api.SetCursorPos((x_tab, y_tab))
    time.sleep(0.1)
    win32api.mouse_event(win32con.MOUSEEVENTF_LEFTDOWN, 0, 0)
    time.sleep(0.05)
    win32api.mouse_event(win32con.MOUSEEVENTF_LEFTUP, 0, 0)
    time.sleep(1.2)   # warten bis Tab geladen

def main():
    if not EXE.exists():
        print(f"EXE nicht gefunden: {EXE}")
        sys.exit(1)

    print("Starte Suite...")
    proc = subprocess.Popen([str(EXE)])
    time.sleep(5)   # Ladezeit

    if not HAS_WIN32:
        print("win32gui nicht verfügbar – nur Vollbild-Screenshot")
        img = ImageGrab.grab()
        img.save(str(OUT / "suite_fullscreen.png"))
        proc.terminate()
        return

    hwnd = find_window("G4MEOVER Security Suite")
    if not hwnd:
        print("Fenster nicht gefunden!")
        proc.terminate()
        sys.exit(1)

    # Fenster maximieren für bessere Screenshots
    win32gui.ShowWindow(hwnd, win32con.SW_MAXIMIZE)
    time.sleep(0.8)

    print(f"Fenster gefunden (HWND {hwnd}), mache Screenshots...")

    for name, idx in TABS:
        click_tab(hwnd, idx)
        screenshot_window(hwnd, name)

    proc.terminate()
    print(f"\nAlle Screenshots in: {OUT}")

if __name__ == "__main__":
    main()
