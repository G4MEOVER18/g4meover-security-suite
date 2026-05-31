@echo off
:: G4MEOVER Security Suite – EXE Build Script
:: Voraussetzung: pip install pyinstaller
:: Ausgabe: dist\G4MEOVER_Suite.exe

title G4MEOVER Suite Builder

echo.
echo ============================================================
echo   G4MEOVER Security Suite v1.3 – EXE Builder
echo   by Yanis Ameseder
echo ============================================================
echo.

:: PyInstaller prüfen
python -m PyInstaller --version >nul 2>&1
if errorlevel 1 (
    echo [!] PyInstaller nicht gefunden. Installiere...
    pip install pyinstaller
    if errorlevel 1 (
        echo [FEHLER] PyInstaller konnte nicht installiert werden.
        pause & exit /b 1
    )
)

:: Logo prüfen
if not exist "assets\g4meover.ico" (
    echo [!] Kein Logo gefunden (assets\g4meover.ico^).
    echo     EXE wird ohne Icon gebaut.
    echo     Lege dein Logo als assets\g4meover.ico ab und baue erneut.
    echo.
    :: Spec temporaer anpassen (kein Icon)
    python -m PyInstaller openclaw_suite.py ^
        --name "G4MEOVER_Suite" ^
        --onefile ^
        --windowed ^
        --version-file version_info.txt ^
        --add-data "modules;modules" ^
        --add-data "utils;utils" ^
        --add-data "suite_config.json;." ^
        --hidden-import tkinter ^
        --hidden-import tkinter.ttk ^
        --hidden-import tkinter.messagebox ^
        --hidden-import tkinter.filedialog
) else (
    python -m PyInstaller G4MEOVER_Suite.spec --clean
)

if errorlevel 1 (
    echo.
    echo [FEHLER] Build fehlgeschlagen. Prüfe die Ausgabe oben.
    pause & exit /b 1
)

echo.
echo ============================================================
echo   Build erfolgreich!
echo   EXE: dist\G4MEOVER_Suite.exe
echo ============================================================
echo.

:: EXE-Ordner öffnen
explorer dist

pause
