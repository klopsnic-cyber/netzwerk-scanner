"""
Heuristische Geräteklassifizierung.

Aus offenen Ports, Hostname, Hersteller und Bannern werden – so gut es
geht – Gerätetyp, Betriebssystem, Windows-Funktion und Softwarestand
abgeleitet. Alles nur als *Hinweis*; unsichere Felder bleiben leer.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .scanner import Host


def _has(h: "Host", *ports: int) -> bool:
    return any(p in h.open_ports for p in ports)


def classify_device(h: "Host") -> None:
    name = (h.hostname or "").lower()
    vendor = (h.vendor or "").lower()
    ports = set(h.open_ports)

    # --- Betriebssystem-Hinweis ---------------------------------------
    if not h.os_hint:
        if _has(h, 135, 139, 445, 3389, 5985):
            h.os_hint = "Windows"
        elif _has(h, 548) or "apple" in vendor or "mac" in name:
            h.os_hint = "macOS"
        elif _has(h, 22) and not _has(h, 445):
            h.os_hint = "Linux/Unix"

    # --- Gerätetyp -----------------------------------------------------
    device = ""
    # Drucker
    if _has(h, 9100, 515, 631) or any(k in vendor for k in ("brother", "kyocera", "ricoh", "xerox", "canon", "epson", "lexmark")) or "print" in name:
        device = "Drucker"
    # NAS
    elif any(k in vendor for k in ("synology", "qnap")) or "nas" in name or _has(h, 2049):
        device = "NAS / Fileserver"
    # Router / Gateway
    elif any(k in vendor for k in ("avm", "fritz", "netgear", "tp-link", "cisco", "ubiquiti", "draytek")) or "router" in name or "gateway" in name or h.ip.endswith(".1") or h.ip.endswith(".254"):
        device = "Router / Gateway"
    # VoIP
    elif any(k in vendor for k in ("grandstream", "snom", "yealink", "gigaset")) or "voip" in name or "phone" in name:
        device = "VoIP-Telefon"
    # Kartenleser / Medizingerät (Praxis-Kontext)
    elif any(k in name for k in ("kartenleser", "egk", "konnektor", "cherry", "orga")):
        device = "Kartenleser / TI-Komponente"
    # Server
    elif _has(h, 1433, 3306, 5432, 1521) or "sql" in name or "server" in name or "srv" in name or "dc" in name:
        device = "Server"
    # Virtuelle Maschine
    elif any(k in vendor for k in ("vmware", "virtualbox", "qemu", "kvm")):
        device = "Virtuelle Maschine"
    # Client-PC
    elif h.os_hint == "Windows":
        device = "PC / Workstation (Windows)"
    elif h.os_hint == "macOS":
        device = "Mac"
    elif _has(h, 80, 443) and not device:
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

    # --- Softwarestand aus Bannern -------------------------------------
    sw = []
    for port, banner in h.services.items():
        b = str(banner)
        # Nur echte Banner (nicht die reinen Dienstnamen) übernehmen
        if b and b not in ("HTTP", "HTTPS", "SSH", "FTP", "SMTP", "IMAP", "POP3") and not b.isdigit():
            sw.append(f"{port}: {b}")
    h.software = " | ".join(sw[:4])
