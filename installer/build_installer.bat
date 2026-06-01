@echo off
:: G4MEOVER Security Suite – Installer Build Script
:: Ausgabe: dist\G4MEOVER_Setup.exe

title G4MEOVER Installer Builder
cd /d "%~dp0"

echo.
echo ============================================================
echo   G4MEOVER Security Suite v1.4 – Installer Builder
echo   by Yanis Ameseder
echo ============================================================
echo.

:: PyInstaller prüfen
python -m PyInstaller --version >nul 2>&1
if errorlevel 1 (
    echo [!] PyInstaller nicht gefunden. Installiere...
    pip install pyinstaller
    if errorlevel 1 (echo [FEHLER] & pause & exit /b 1)
)

:: Builtin-Tools prüfen
if not exist "..\..\..\tools\hydra\hydra.py" (
    echo [!] C:\tools\hydra\hydra.py nicht gefunden
    echo     Builtin-Tools werden ohne hydra.py gebaut.
)

echo [*] Baue Installer-EXE...
echo.

python -m PyInstaller G4MEOVER_Setup.spec --clean --noconfirm --distpath ..\dist\installer

if errorlevel 1 (
    echo.
    echo [FEHLER] Build fehlgeschlagen.
    pause & exit /b 1
)

echo.
echo ============================================================
echo   Installer gebaut: dist\installer\G4MEOVER_Setup.exe
echo ============================================================
echo.

explorer "..\dist\installer"
pause
