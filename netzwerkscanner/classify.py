"""
Heuristische Geräteklassifizierung.

Aus offenen Ports, Hostname, Hersteller und Bannern werden – so gut es
geht – Gerätetyp, Betriebssystem, Windows-Funktion abgeleitet. Alles nur als *Hinweis*; unsichere Felder bleiben leer.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .scanner import Host


def _has(h: "Host", *ports: int) -> bool:
    return any(p in h.open_ports for p in ports)


def _word(name: str, *words: str) -> bool:
    """Kürzel/Wort als eigenes Namensteil ("nas01", "srv-dc", "mein-print"), nicht als Teilwort
    ("Jonas-MBP", "blueprint-pc", "DR-ORGANISATION"). Trenner: - _ . Leerzeichen."""
    return any(re.search(rf"(^|[-_.\s]){w}\d*($|[-_.\s])", name) for w in words)


def _v(vendor: str, *keys: str) -> bool:
    return any(k in vendor for k in keys)


_PRINTER_V = ("brother", "hewlett", "kyocera", "canon", "epson", "lexmark", "ricoh", "xerox", "konica")
_VOIP_V = ("yealink", "snom", "gigaset", "grandstream", "polycom", "cisco", "auerswald", "panasonic")


def classify_device(h: "Host") -> None:
    name = (h.hostname or "").lower()
    vendor = (h.vendor or "").lower()
    ports = set(h.open_ports)
    apple = "apple" in vendor
    mac_hint = ("macbook" in name or "imac" in name or _word(name, "mac", "mbp")
                or _has(h, 548, 445, 22, 5900))

    # --- Betriebssystem-Hinweis ---------------------------------------
    if not h.os_hint:
        # Mac-Name/Apple-Hersteller zuerst: Macs haben oft SMB (445) offen und sind trotzdem keine Windows-PCs
        if _has(h, 62078):
            h.os_hint = "iOS"
        elif "macbook" in name or "imac" in name or _word(name, "mac", "mbp") or (apple and mac_hint):
            h.os_hint = "macOS"
        elif (_has(h, 135) and _has(h, 445)) or _has(h, 3389, 5985):
            h.os_hint = "Windows"
        elif "windows" in " ".join(str(b) for b in h.services.values()).lower():
            h.os_hint = "Windows"
        elif _has(h, 548):
            h.os_hint = "macOS"
        elif _has(h, 22) and not _has(h, 445):
            h.os_hint = "Linux/Unix"

    # --- Gerätetyp -----------------------------------------------------
    device = ""
    nas_v = _v(vendor, "synology", "qnap")
    # Druckerhersteller nur ohne PC/Server-Merkmale: HP baut auch PCs, HPE/Aruba Server und Switches
    pc_like = (h.os_hint in ("Windows", "macOS", "Linux/Unix") or _has(h, 22, 135, 445, 3389)
               or _word(name, "pc", "srv", "dc", "ilo") or "server" in name
               or _v(vendor, "enterprise", "aruba"))
    print_strong = _has(h, 9100) or (not pc_like and (_v(vendor, *_PRINTER_V) or _word(vendor, "hp", "oki")))
    # 631/515 allein: kein Drucker, wenn SMB/AFP offen (Mac/NAS mit Druckerfreigabe) oder Apple/NAS-Hersteller
    print_weak = _has(h, 515, 631) and not _has(h, 445, 548) and not apple and not nas_v
    # iPhone/iPad vor allem anderen ("phone" im Namen ist kein VoIP-Telefon)
    if "iphone" in name or "ipad" in name or _has(h, 62078):
        device = "iPhone / iPad"
    # NAS-Hersteller vor Drucker (Synology & Co. haben oft 631 offen)
    elif nas_v:
        device = "NAS / Fileserver"
    elif print_strong or print_weak or _word(name, "print", "printer", "drucker"):
        device = "Drucker"
    elif _word(name, "nas") or _has(h, 2049):
        device = "NAS / Fileserver"
    # Router / Gateway
    elif _v(vendor, "avm", "fritz", "netgear", "tp-link", "cisco", "ubiquiti", "draytek") or "router" in name or "gateway" in name:
        device = "Router / Gateway"
    # VoIP: "phone" nur mit VoIP-Hersteller oder SIP-Port (5060/5061)
    elif _v(vendor, *_VOIP_V) or "voip" in name or (_word(name, "phone", "telefon") and _has(h, 5060, 5061)):
        device = "VoIP-Telefon"
    # Kartenleser / Medizingerät (Praxis-Kontext)
    elif any(k in name for k in ("kartenleser", "egk", "konnektor", "cherry")) or _word(name, "orga"):
        device = "Kartenleser / TI-Komponente"
    # Server
    elif _has(h, 1433, 3306, 5432, 1521) or "sql" in name or "server" in name or _word(name, "srv", "dc"):
        device = "Server"
    # Virtuelle Maschine
    elif _v(vendor, "vmware", "virtualbox", "qemu", "kvm") or (h.mac or "").upper().startswith("00:15:5D"):
        device = "Virtuelle Maschine"
    # Client-PC
    elif h.os_hint == "Windows":
        device = "PC / Workstation (Windows)"
    elif h.os_hint == "macOS":
        device = "Mac"
    elif apple:
        device = "Apple-Gerät"  # Apple TV/HomePod/... ohne Mac-Hinweise
    # .1/.254 nur als letzter Hinweis: ein Windows-Server oder Mac auf .1 bleibt, was er ist
    elif h.ip.endswith(".1") or h.ip.endswith(".254"):
        device = "Router / Gateway"
    elif _has(h, 80, 443):
        device = "Netzwerkgerät (Web-Oberfläche)"
    h.device_type = device

    # --- Windows-Funktion (Praxis: EKG, SQL, Server …) -----------------
    win = []
    if 1433 in ports:
        win.append("MS-SQL-Server")
    if 3306 in ports:
        win.append("MySQL/MariaDB")
    if 5432 in ports:
        win.append("PostgreSQL")
    if 3389 in ports:
        win.append("RDP")
    if 5985 in ports:
        win.append("WinRM")
    if _has(h, 88, 389, 3268):
        win.append("Domänencontroller (AD)")
    h.win_function = ", ".join(win)
