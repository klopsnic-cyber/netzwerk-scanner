"""
Hersteller-Erkennung über die MAC-Adresse (OUI = erste 3 Bytes).

Die IEEE-Listen (MA-L 6, MA-M 7, MA-S 9 Hexstellen) werden beim Build per
assets/make_oui_data.py in oui_data.py eingebettet -> Lookup komplett offline.
Eine optionale data/oui.csv neben der App überschreibt (nur MA-L). Fehlt die
eingebettete Liste, greift eine kleine Liste häufiger Hersteller.
"""

from __future__ import annotations

import csv
import os
import sys
from typing import Dict, Optional

_CACHE: Optional[Dict[str, str]] = None

# Fallback für den Fall, dass data/oui.csv fehlt (Auswahl gängiger Hersteller).
_FALLBACK = {
    "000C29": "VMware", "005056": "VMware", "001C14": "VMware",
    "080027": "Oracle VirtualBox", "525400": "QEMU/KVM",
    "F0DEF1": "Wistron", "B827EB": "Raspberry Pi Foundation",
    "DCA632": "Raspberry Pi (Trading)", "E45F01": "Raspberry Pi (Trading)",
    "001B63": "Apple", "3C0754": "Apple", "A45E60": "Apple", "F0189E": "Apple",
    "AC87A3": "Apple", "D89E3F": "Apple", "F81EDF": "Apple",
    "001A11": "Google", "3C5AB4": "Google", "F4F5D8": "Google",
    "FCFBFB": "Cisco", "00000C": "Cisco", "001B0D": "Cisco",
    "0018F3": "ASUSTek", "2C56DC": "ASUSTek",
    "001E8C": "ASUSTek", "D850E6": "ASUSTek",
    "E0CB4E": "ASUSTek", "9C5C8E": "ASUSTek",
    "001CC0": "Intel", "3CA9F4": "Intel", "94C691": "Intel",
    "A0A8CD": "Intel", "001B21": "Intel", "0021CC": "Flextronics",
    "B499BA": "Hewlett Packard", "3863BB": "Hewlett Packard",
    "001321": "Hewlett Packard", "00110A": "Hewlett Packard",
    "9CB654": "Hewlett Packard Enterprise",
    "001560": "Hewlett Packard", "A0481C": "Hewlett Packard",
    "F4CE46": "Hewlett Packard", "94577B": "Hewlett Packard",
    "00219B": "Dell", "0024E8": "Dell", "F8BC12": "Dell",
    "18DBF2": "Dell", "B885B3": "Dell", "D4BED9": "Dell",
    "001AA0": "Dell", "782BCB": "Dell", "A41F72": "Dell",
    "0004AC": "IBM", "00096B": "IBM",
    "000E0C": "Intel", "001E67": "Intel",
    "00040F": "AVM (Fritz!Box)", "3810D5": "AVM (Fritz!Box)",
    "5C4979": "AVM (Fritz!Box)", "C0C1C0": "AVM (Fritz!Box)",
    "E0286D": "AVM (Fritz!Box)", "244C07": "AVM (Fritz!Box)",
    "001F3F": "AVM (Fritz!Box)",
    "000B82": "Grandstream", "000413": "Snom",
    "0080F0": "Panasonic", "001BA9": "Brother",
    "008077": "Brother", "30055C": "Brother", "0080BA": "Brother",
    "0000AA": "Xerox", "9C934E": "Xerox",
    "00000E": "Fujitsu", "00E018": "Asus",
    "3CD92B": "Hewlett Packard", "6C3BE5": "Hewlett Packard",
    "001279": "Hewlett Packard (Drucker)",
    "0017C8": "Kyocera", "00C0EE": "Kyocera",
    "002673": "Ricoh", "00265E": "Ricoh",
    "0000F0": "Samsung", "0007AB": "Samsung", "0012FB": "Samsung",
    "F0A225": "Samsung", "8425DB": "Samsung",
    "001D0F": "TP-Link", "50C7BF": "TP-Link", "A42BB0": "TP-Link",
    "C46E1F": "TP-Link", "EC086B": "TP-Link",
    "001217": "Cisco-Linksys", "002129": "Cisco",
    "0018E7": "Cameo (Netgear)", "000FB5": "Netgear",
    "008EF2": "Netgear", "204E7F": "Netgear", "A040A0": "Netgear",
    "001DD8": "Microsoft", "0017FA": "Microsoft", "7C1E52": "Microsoft",
    "000D3A": "Microsoft", "485073": "Microsoft",
    "001132": "Synology",
    "24513F": "QNAP", "245EBE": "QNAP",
    "B8AC6F": "Dell", "F04DA2": "Dell",
}


def _resource_dir() -> str:
    """Verzeichnis, in dem gebündelte Daten liegen (PyInstaller-kompatibel)."""
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return sys._MEIPASS  # type: ignore[attr-defined]
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _oui_path() -> str:
    return os.path.join(_resource_dir(), "data", "oui.csv")


def _load() -> Dict[str, str]:
    global _CACHE
    if _CACHE is not None:
        return _CACHE
    table: Dict[str, str] = dict(_FALLBACK)

    # 1) Fest eingebettete, vollständige IEEE-Liste (immer verfügbar, offline,
    #    überlebt jede Weitergabe). Das ist die Hauptquelle.
    try:
        from . import oui_data
        table.update(oui_data.load())
    except Exception as e:
        print(f"Hinweis: eingebettete Hersteller-Liste unbrauchbar ({e})", file=sys.stderr)

    # 2) Optionale externe data/oui.csv (z.B. aktuellere Liste) überschreibt.
    path = _oui_path()
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8", errors="ignore", newline="") as f:
                reader = csv.reader(f)
                header = next(reader, None)
                # IEEE-Format: Registry,Assignment,Organization Name,Organization Address
                # Spaltenpositionen robust ermitteln.
                assign_idx, name_idx = 1, 2
                if header:
                    for i, col in enumerate(header):
                        c = col.strip().lower()
                        if c == "assignment":
                            assign_idx = i
                        elif "organization name" in c:
                            name_idx = i
                for row in reader:
                    if len(row) <= max(assign_idx, name_idx):
                        continue
                    prefix = row[assign_idx].strip().upper().replace("-", "").replace(":", "")
                    name = row[name_idx].strip()
                    if len(prefix) == 6 and name:
                        table[prefix] = name
        except Exception:
            pass
    _CACHE = table
    return table


def lookup_vendor(mac: str) -> str:
    """Herstellername zur MAC ('' wenn unbekannt). Längster Präfix gewinnt (MA-S 9, MA-M 7, MA-L 6)."""
    clean = (mac or "").upper().replace(":", "").replace("-", "").replace(".", "")
    t = _load()
    for n in (9, 7, 6):
        if len(clean) >= n and clean[:n] in t:
            name = t[clean[:n]]
            # MA-M/MA-S-Block ohne Unterblock-Eintrag: nur "IEEE Registration Authority" -> irreführend
            return "" if name == "IEEE Registration Authority" else name
    return ""


def database_size() -> int:
    return len(_load())
