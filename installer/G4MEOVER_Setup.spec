# -*- mode: python ; coding: utf-8 -*-
# PyInstaller Spec für den G4MEOVER Installer
# Enthält die Suite-Dateien + alle builtin-Tools als Daten

import os
ROOT = os.path.abspath(os.path.join(SPECPATH, '..'))

block_cipher = None

a = Analysis(
    [os.path.join(SPECPATH, 'g4meover_setup.py')],
    pathex=[ROOT],
    binaries=[],
    datas=[
        # ── Komplette Suite einbetten ────────────────────────────────────────
        (os.path.join(ROOT, 'openclaw_suite.py'),         'suite'),
        (os.path.join(ROOT, 'modules'),                   'suite/modules'),
        (os.path.join(ROOT, 'utils'),                     'suite/utils'),
        (os.path.join(ROOT, 'suite_config.example.json'), 'suite'),
        (os.path.join(ROOT, 'assets'),                    'suite/assets'),

        # ── Builtin-Tools einbetten ──────────────────────────────────────────
        # gobuster (~9.9 MB)
        (r'C:\tools\gobuster\gobuster.exe',
                                                    'tools_builtin/gobuster'),
        # feroxbuster (~6 MB)
        (r'C:\tools\feroxbuster\feroxbuster.exe',
                                                    'tools_builtin/feroxbuster'),
        # John the Ripper – nur die EXE (~7 MB)
        (r'C:\tools\john\john-1.9.0-jumbo-1-win64\run\john.exe',
                                                    'tools_builtin/john'),
        # nikto – komplettes Verzeichnis mit nikto-main/ (~2 MB)
        (r'C:\tools\nikto',                         'tools_builtin/nikto'),
        # ExploitDB – CSV-Datenbank + searchsploit-Scripts (~16 MB)
        (r'C:\tools\exploitdb',                     'tools_builtin/exploitdb'),
        # Hydra, Masscan, WhatWeb – Python-Implementierungen
        (r'C:\tools\hydra',                         'tools_builtin/hydra'),
        (r'C:\tools\masscan',                       'tools_builtin/masscan'),
        (r'C:\tools\whatweb',                       'tools_builtin/whatweb'),
    ],
    hiddenimports=[
        'tkinter', 'tkinter.ttk', 'tkinter.filedialog',
        'tkinter.messagebox', 'tkinter.scrolledtext',
        'urllib.request', 'urllib.parse', 'urllib.error',
        'zipfile', 'threading', 'subprocess', 'json', 'shutil',
        'winreg', 'pathlib',
    ],
    hookspath=[],
    runtime_hooks=[],
    excludes=['numpy', 'pandas', 'matplotlib'],
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='G4MEOVER_Setup',
    debug=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    icon=os.path.join(ROOT, 'assets', 'g4meover.ico'),
    version=os.path.join(ROOT, 'version_info.txt'),
    uac_admin=True,
)
