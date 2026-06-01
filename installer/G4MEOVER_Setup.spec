# -*- mode: python ; coding: utf-8 -*-
# PyInstaller Spec für den G4MEOVER Installer
# Enthält die Suite-Dateien + builtin-Tools als Daten

import os
ROOT = os.path.abspath(os.path.join(SPECPATH, '..'))

block_cipher = None

a = Analysis(
    [os.path.join(SPECPATH, 'g4meover_setup.py')],
    pathex=[ROOT],
    binaries=[],
    datas=[
        # Komplette Suite einbetten
        (os.path.join(ROOT, 'openclaw_suite.py'),        '.'),
        (os.path.join(ROOT, 'modules'),                  'modules'),
        (os.path.join(ROOT, 'utils'),                    'utils'),
        (os.path.join(ROOT, 'suite_config.example.json'),'.'),
        (os.path.join(ROOT, 'assets'),                   'assets'),
        # Builtin-Tools einbetten
        (r'C:\tools\hydra',    'tools_builtin/hydra'),
        (r'C:\tools\masscan',  'tools_builtin/masscan'),
        (r'C:\tools\whatweb',  'tools_builtin/whatweb'),
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
    uac_admin=True,         # Fordert Admin-Rechte an
)
