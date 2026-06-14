# -*- mode: python ; coding: utf-8 -*-
# PyInstaller Spec-Datei für G4MEOVER Security Suite
# Verwendung: pyinstaller G4MEOVER_Suite.spec

block_cipher = None

a = Analysis(
    ['openclaw_suite.py'],
    pathex=['.'],
    binaries=[],
    datas=[
        ('modules',        'modules'),
        ('utils',          'utils'),
        # suite_config.json wird BEWUSST NICHT gebündelt – sie kann API-Keys
        # enthalten und PyInstaller-Archive sind trivial entpackbar. Die App
        # startet ohne Config (_load_config gibt {} zurück); Tools werden
        # automatisch erkannt, Keys trägt der Nutzer in den Einstellungen ein.
        ('assets',         'assets'),
    ],
    hiddenimports=[
        'modules.dashboard',
        'modules.network',
        'modules.wifi_wpa',
        'modules.handshake',
        'modules.pmkid',
        'modules.passwords',
        'modules.web',
        'modules.osint',
        'modules.exploit_research',
        'modules.live_capture',
        'modules.wordlist',
        'modules.isolation',
        'modules.hardening_audit',
        'modules.port_exposure',
        'modules.integrity_monitor',
        'modules.privesc_audit',
        'modules.av_test',
        'modules.vuln_scan',
        'modules.secrets_audit',
        'modules.account_audit',
        'modules.firewall_audit',
        'modules.log_watcher',
        'modules.reporting',
        'modules.settings',
        'modules.help',
        'utils.theme',
        'utils.icons',
        'utils.tool_detector',
        'utils.oui_mini',
        'tkinter',
        'tkinter.ttk',
        'tkinter.filedialog',
        'tkinter.messagebox',
        'tkinter.scrolledtext',
        'subprocess',
        'threading',
        'json',
        'urllib.request',
        'urllib.parse',
        'urllib.error',
        'PIL',
        'PIL.Image',
        'PIL.ImageDraw',
        'PIL.ImageFont',
        'PIL.ImageTk',
        'scapy',
        'scapy.all',
        'scapy.layers.dot11',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['numpy', 'pandas', 'matplotlib', 'scipy'],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
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
    name='G4MEOVER_Suite',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,        # kein schwarzes Konsolenfenster
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='assets\\g4meover.ico',         # Logo hier einfügen
    version='version_info.txt',
)
