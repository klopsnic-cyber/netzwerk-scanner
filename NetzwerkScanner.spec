# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller-Spezifikation für den Netzwerk-Scanner.
Bauen:  pyinstaller NetzwerkScanner.spec   (auf einem Mac!)
Ergebnis: dist/Netzwerk-Scanner.app
"""

block_cipher = None

import os as _os

datas = [
    ("data/Netzwerkdoku-Vorlage.xlsx", "data"),
    ("data/oui.csv", "data"),
]
# Fenster-Symbol (für laufende App) mitnehmen, falls erzeugt.
if _os.path.exists("assets/app_icon.png"):
    datas.append(("assets/app_icon.png", "assets"))

# App-Icon (.icns), falls von build.sh erzeugt.
_ICON = "assets/Netzwerk-Scanner.icns" if _os.path.exists("assets/Netzwerk-Scanner.icns") else None

a = Analysis(
    ["app.py"],
    pathex=[],
    binaries=[],
    datas=datas,
    hiddenimports=["openpyxl", "tkinter"],
    hookspath=[],
    runtime_hooks=[],
    excludes=["numpy", "pandas", "matplotlib", "PIL", "scipy"],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="Netzwerk-Scanner",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,          # GUI-App (kein Terminalfenster)
    disable_windowed_traceback=False,
    argv_emulation=True,     # Datei-Doppelklick / Öffnen-Events auf macOS
    target_arch=(_os.environ.get("APP_TARGET_ARCH") or None),  # z.B. "universal2"
    codesign_identity=None,
    entitlements_file=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="Netzwerk-Scanner",
)

app = BUNDLE(
    coll,
    name="Netzwerk-Scanner.app",
    icon=_ICON,
    bundle_identifier="de.tomedo.netzwerkscanner",
    info_plist={
        "CFBundleName": "Netzwerk-Scanner",
        "CFBundleDisplayName": "Netzwerk-Scanner",
        "CFBundleShortVersionString": "1.0.0",
        "CFBundleVersion": "1.0.0",
        "LSMinimumSystemVersion": "11.0",
        "NSHighResolutionCapable": True,
        # Erklärungstext für die macOS-"Lokales Netzwerk"-Abfrage:
        "NSLocalNetworkUsageDescription":
            "Der Netzwerk-Scanner sucht Geräte im lokalen Netzwerk, "
            "um die Netzwerkdokumentation automatisch zu erstellen.",
        "NSBonjourServices": ["_workstation._tcp", "_device-info._tcp"],
    },
)
