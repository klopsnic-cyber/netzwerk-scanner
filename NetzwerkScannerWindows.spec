# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller-Spezifikation für die Windows-Version des Netzwerk-Scanners.
MUSS auf Windows gebaut werden (siehe .github/workflows/build-windows.yml -
läuft automatisch bei jedem "vX.Y.Z"-Tag, baut PyInstaller cross-platform
nicht selbst).

Bauen (auf Windows):  pyinstaller NetzwerkScannerWindows.spec
Ergebnis: dist/Netzwerk-Scanner/Netzwerk-Scanner.exe
"""

import os as _os

datas = [
    ("data/Netzwerkdoku-Vorlage.xlsx", "data"),
]
if _os.path.exists("assets/app_icon.png"):
    datas.append(("assets/app_icon.png", "assets"))

_ICON = "assets/Netzwerk-Scanner.ico" if _os.path.exists("assets/Netzwerk-Scanner.ico") else None

a = Analysis(
    ["app.py"],
    pathex=[],
    binaries=[],
    datas=datas,
    hiddenimports=["openpyxl", "tkinter", "msoffcrypto", "olefile",
                   "cryptography", "cryptography.hazmat.backends.openssl"],
    hookspath=[],
    runtime_hooks=[],
    excludes=["numpy", "pandas", "matplotlib", "PIL", "scipy"],
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data)

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
    console=False,          # GUI-App (kein Konsolenfenster)
    icon=_ICON,
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
