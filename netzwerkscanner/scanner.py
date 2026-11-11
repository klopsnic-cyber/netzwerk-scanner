"""
Kern des Netzwerkscanners.

Ablauf eines Scans:
  1. Lokales Subnetz erkennen (oder vom Benutzer vorgegeben).
  2. Paralleler Ping-Sweep über alle Hosts.
  3. ARP-Tabelle auslesen -> MAC-Adressen (nur gleiches L2-Subnetz).
  4. Namensauflösung: Reverse-DNS, mDNS/Bonjour (.local), NetBIOS.
  5. Port-Scan + Banner-Grabbing (Tiefe wählbar).
  6. Hersteller-Lookup (OUI) und Geräteklassifizierung.

Es werden ausschließlich Standardbibliotheken plus optional 'zeroconf'
benutzt, damit das Bündeln mit PyInstaller einfach bleibt.
"""

from __future__ import annotations

import concurrent.futures
import errno
import ipaddress
import os
import platform
import re
import selectors
import socket
import subprocess
import threading
import time
from dataclasses import asdict, dataclass, field, fields
from typing import Callable, Dict, List, Optional, Tuple

from .oui import lookup_vendor
from .classify import classify_device

# Windows: ping/arp ohne aufblitzendes Konsolenfenster starten (GUI-Build hat keine Konsole).
NO_WINDOW = {"creationflags": subprocess.CREATE_NO_WINDOW} if os.name == "nt" else {}
WINDOWS = os.name == "nt"


def _systemprogramm(*kandidaten: str) -> str:
    """Erster vorhandener fester Pfad, sonst der letzte Kandidat (Name über PATH).
    Als gebaute App fehlt oft /sbin bzw. /usr/sbin im PATH; unter Windows soll keine
    gleichnamige Datei aus dem Arbeitsordner statt des Systemprogramms starten."""
    for pfad in kandidaten[:-1]:
        if os.path.exists(pfad):
            return pfad
    return kandidaten[-1]


_SYS32 = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32")
if WINDOWS:
    PING = _systemprogramm(os.path.join(_SYS32, "ping.exe"), "ping")
    ARP = _systemprogramm(os.path.join(_SYS32, "arp.exe"), "arp")
    POWERSHELL = _systemprogramm(os.path.join(_SYS32, "WindowsPowerShell", "v1.0", "powershell.exe"), "powershell")
    IFCONFIG = ""
else:
    PING = _systemprogramm("/sbin/ping", "/bin/ping", "ping")
    # Ohne festen Pfad fand die gebaute .app "arp" nicht -> alle MACs leer.
    ARP = _systemprogramm("/usr/sbin/arp", "/sbin/arp", "arp")
    POWERSHELL = ""
    IFCONFIG = _systemprogramm("/sbin/ifconfig", "ifconfig")

# macOS-GUI-Apps starten mit nur 256 Dateihandles; 128 parallele Pings/Sockets reißen das,
# und die betroffenen Hosts fielen still aus dem Ergebnis. Soft-Limit anheben (best effort).
try:
    import resource
    _soft, _hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    _want = 4096 if _hard == resource.RLIM_INFINITY else min(4096, _hard)
    if _soft < _want:
        resource.setrlimit(resource.RLIMIT_NOFILE, (_want, _hard))
except (ImportError, ValueError, OSError):
    pass

# ---------------------------------------------------------------------------
# Datenmodell
# ---------------------------------------------------------------------------

@dataclass
class Host:
    ip: str
    mac: str = ""
    vendor: str = ""            # Hersteller (aus OUI)
    hostname: str = ""          # Netzwerkname
    device_type: str = ""       # Gerätetyp (geraten)
    open_ports: List[int] = field(default_factory=list)
    services: Dict[int, str] = field(default_factory=dict)  # port -> banner/dienst
    os_hint: str = ""           # z.B. "Windows", aus Ports/Bannern
    software: str = ""          # Softwarestand-Hinweise (Banner)
    win_function: str = ""      # Windows-Funktion (geraten, z.B. SQL/RDP)
    # Manuelle Nacharbeit-Felder (bleiben leer, bis in der GUI bearbeitet).
    # Kennwort bewusst NICHT hier - Klartext-Passwörter sollen nicht in der
    # App/JSON landen, das bleibt manuelle Excel-Nacharbeit wie bisher.
    standort: str = ""
    user: str = ""
    angebunden_an: str = ""
    eingerichtet_von: str = ""
    scan_warning: str = ""      # leer = kein Problem; sonst kurzer Hinweistext
    ignored: bool = False       # True = beim Export ausgeschlossen

    def sort_key(self):
        try:
            return int(ipaddress.ip_address(self.ip))
        except ValueError:
            return 0

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Host":
        valid = {f.name for f in fields(cls)}
        data = {k: v for k, v in d.items() if k in valid}
        # JSON kennt keine int-Keys/hat kein "fehlendes Feld" -> defensiv normalisieren
        # (z.B. bei einer von Hand editierten oder aus einer alten Version stammenden Session-Datei).
        data["open_ports"] = [int(p) for p in (data.get("open_ports") or [])]
        data["services"] = {int(k): v for k, v in (data.get("services") or {}).items()}
        return cls(**data)


def _add_warning(existing: str, new: str) -> str:
    """Hängt eine weitere Warnung an, statt eine vorherige zu überschreiben."""
    return f"{existing}; {new}" if existing else new


# Ports, die "gründlich" geprüft werden. Dienst-Name dient als Hinweis.
COMMON_PORTS: Dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 88: "Kerberos", 110: "POP3", 111: "RPC", 135: "MS-RPC",
    139: "NetBIOS", 143: "IMAP", 161: "SNMP", 389: "LDAP", 443: "HTTPS",
    445: "SMB", 515: "LPD/Drucker", 548: "AFP", 631: "IPP/Drucker",
    993: "IMAPS", 995: "POP3S", 1433: "MS-SQL", 1521: "Oracle",
    2049: "NFS", 3268: "LDAP-GC", 3306: "MySQL/MariaDB", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 5985: "WinRM", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 9100: "RAW/Drucker", 32400: "Plex",
    62078: "Apple-Gerät (iOS)",
}

# Reduzierter Portsatz für den schnellen Modus.
QUICK_PORTS = [22, 80, 135, 139, 443, 445, 515, 631, 3389, 9100, 62078]

# Ports, an denen ein Banner-Grab sinnvoll ist.
BANNER_PORTS = {21, 22, 25, 80, 110, 143, 443, 8080, 8443}


class ScanConfig:
    def __init__(self, depth: str = "gruendlich", port_timeout: float = 0.6,
                 ping_timeout: float = 1.0, max_workers: int = 128):
        # depth: "schnell" | "standard" | "gruendlich"
        self.depth = depth
        self.port_timeout = port_timeout
        self.ping_timeout = ping_timeout
        self.max_workers = max_workers

    @property
    def ports(self) -> List[int]:
        if self.depth == "schnell":
            return QUICK_PORTS
        return list(COMMON_PORTS.keys())

    @property
    def do_banner(self) -> bool:
        return self.depth == "gruendlich"


# ---------------------------------------------------------------------------
# Subnetz-Erkennung
# ---------------------------------------------------------------------------

def _brauchbare_ip(ip: str) -> bool:
    try:
        a = ipaddress.IPv4Address(ip)
    except ValueError:
        return False
    return not (a.is_loopback or a.is_unspecified or a.is_link_local)


def local_ip_for(target_ip: str) -> str:
    """Eigene IPv4-Adresse, über die das System `target_ip` erreichen würde
    (richtige Netzwerkkarte auch bei VPN/mehreren Karten). Es wird kein Paket
    gesendet – connect() auf UDP wählt nur die Route. "" wenn keine Route/IP."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect((target_ip, 9))
            ip = s.getsockname()[0]
    except (OSError, ValueError):
        return ""
    return ip if _brauchbare_ip(ip) else ""


def get_local_ip() -> str:
    """Primäre lokale IPv4-Adresse (Default-Route). "" wenn keine brauchbare IP
    da ist (kein Netz, keine Default-Route) – NICHT still 127.0.0.1."""
    return local_ip_for("8.8.8.8")


def guess_local_network(prefix: int = 24) -> str:
    """Rät das lokale Netz aus der eigenen IP, z.B. '192.168.1.0/24'.
    "" wenn keine brauchbare eigene IP ermittelbar ist (GUI zeigt dann einen Hinweis)."""
    ip = get_local_ip()
    if not ip:
        return ""
    return str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))


MAX_ADRESSEN = 1024  # = /22 (1022 nutzbare Adressen)


def hosts_in_network(cidr: str) -> List[str]:
    """Alle Host-Adressen des Netzes. ValueError mit verständlicher deutscher Meldung
    bei ungültiger Angabe, IPv6 oder zu großem Netz (keine stille Kappung)."""
    try:
        net = ipaddress.ip_network(cidr.strip(), strict=False)
    except ValueError:
        raise ValueError(f"Ungültige Netzangabe „{cidr}“ – bitte z. B. 192.168.1.0/24 eingeben.") from None
    if net.version != 4:
        raise ValueError("Nur IPv4-Netze werden unterstützt (z. B. 192.168.1.0/24).")
    if net.num_addresses > MAX_ADRESSEN:
        beispiel = ipaddress.ip_network(f"{net.network_address}/24", strict=False)
        raise ValueError(
            f"Netz zu groß: /{net.prefixlen} hat {net.num_addresses - 2} Adressen, "
            f"maximal /22 (1022). Bitte ein kleineres Netz wählen, z. B. {beispiel}.")
    return [str(h) for h in net.hosts()]


# ---------------------------------------------------------------------------
# Ping-Sweep
# ---------------------------------------------------------------------------

def _ping_cmd(ip: str, timeout: float) -> List[str]:
    system = platform.system().lower()
    if system == "windows":
        return [PING, "-n", "1", "-w", str(int(timeout * 1000)), ip]
    if system == "darwin":
        # -t Gesamt-Timeout in Sekunden auf macOS
        return [PING, "-c", "1", "-t", str(max(1, int(timeout))), ip]
    # Linux
    return [PING, "-c", "1", "-W", str(max(1, int(timeout))), ip]


def ping(ip: str, timeout: float = 1.0) -> bool:
    """True bei Ping-Antwort. FileNotFoundError (ping fehlt) und andere OSError
    (z. B. keine Dateihandles mehr) werden weitergegeben – der Aufrufer meldet sie."""
    try:
        res = subprocess.run(
            _ping_cmd(ip, timeout),
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=timeout + 1.5, **NO_WINDOW,
        )
    except subprocess.TimeoutExpired:
        return False
    # Windows-ping meldet Exit 0 auch bei "Zielhost nicht erreichbar" (Antwort vom Router);
    # nur eine echte Antwort enthält "TTL=" (sprachunabhängig).
    return res.returncode == 0 and (os.name != "nt" or b"TTL=" in res.stdout.upper())


# Ports für die aktive Erreichbarkeitsprüfung, falls ein Gerät Ping blockt.
# Ein offener ODER aktiv abgelehnter Port beweist, dass der Host JETZT online
# ist. Funktioniert auch netzübergreifend (über Router), anders als ARP.
LIVENESS_PORTS = (
    80, 443, 22, 445, 139, 135, 3389,  # Web, SSH, Windows/SMB/RDP
    62078,                             # iPhone (lockdownd)
    548, 5000,                         # Apple (AFP/AirPlay)
    9100, 631, 515,                    # Drucker
    53, 8080,                          # Gateway/DNS, Web-Alt
)

# Gesamt-Timeout für alle Ports zusammen. Gemessen: schlafende iPhones/iPads (WLAN-Stromsparen)
# antworten erst nach 1–1,5 s; Windows meldet ein abgelehntes connect() (RST) ebenfalls erst
# nach ~1 s. Mit 0.6 s fielen solche Geräte aus dem Ergebnis.
TCP_TIMEOUT = 1.5
_ABGELEHNT = {errno.ECONNREFUSED, 10061}  # 10061 = WSAECONNREFUSED
_LAEUFT = {errno.EINPROGRESS, errno.EWOULDBLOCK, errno.EALREADY, 10035}  # 10035 = WSAEWOULDBLOCK


def tcp_reachable(ip: str, timeout: Optional[float] = None, ports=LIVENESS_PORTS) -> bool:
    """True, wenn der Host auf mind. einem TCP-Port jetzt reagiert
    (Verbindung offen oder aktiv abgelehnt = Host lebt gerade).

    Alle Ports gleichzeitig (nicht blockierend) mit EINEM Gesamt-Timeout statt
    nacheinander. selectors statt select.select: bei vielen parallelen Prüfungen
    liegen die Dateinummern über 1024, das verträgt select() auf macOS/Linux nicht.
    OSError beim Anlegen (z. B. EMFILE) wird weitergegeben, nicht verschluckt."""
    timeout = TCP_TIMEOUT if timeout is None else timeout
    socks: List[socket.socket] = []
    sel = selectors.DefaultSelector()
    try:
        for port in ports:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socks.append(s)
            s.setblocking(False)
            rc = s.connect_ex((ip, port))
            if rc == 0 or rc in _ABGELEHNT:
                return True
            if rc in _LAEUFT:
                sel.register(s, selectors.EVENT_WRITE)
            # sonst (z. B. Netz/Host unerreichbar): dieser Port zählt nicht
        deadline = time.monotonic() + timeout
        while sel.get_map():
            rest = deadline - time.monotonic()
            if rest <= 0:
                break
            for key, _ in sel.select(rest):
                s = key.fileobj
                err = s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                if err == 0 or err in _ABGELEHNT:
                    return True
                sel.unregister(s)
        return False
    finally:
        sel.close()
        for s in socks:
            s.close()


_PING_FEHLT = "Ping-Programm nicht gefunden – Erreichbarkeit nur per TCP geprüft"


def probe(ip: str, timeout: float = 1.0, problems: Optional[List[str]] = None) -> bool:
    """Ist der Host JETZT aktiv erreichbar? Erst Ping (auch subnetzübergreifend),
    dann als Rückfall ein aktiver TCP-Kontakt. Keine ARP-Cache-Auswertung –
    es werden nur Geräte gemeldet, die zur Scan-Zeit tatsächlich antworten."""
    try:
        if ping(ip, timeout):
            return True
    except FileNotFoundError:
        if problems is not None:
            problems.append(_PING_FEHLT)  # Dubletten entfernt scan() am Ende
    return tcp_reachable(ip)


# ---------------------------------------------------------------------------
# ARP-Tabelle -> MAC
# ---------------------------------------------------------------------------

_MAC_RE = re.compile(r"([0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{1,2}){5})")

def normalize_mac(mac: str) -> str:
    parts = mac.split(":")
    if len(parts) != 6:
        return mac.upper()
    return ":".join(p.zfill(2).upper() for p in parts)


_UNGUELTIGE_MACS = {"00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF"}


def parse_arp_output(out: str, windows: bool) -> Dict[str, str]:
    """Wertet die Ausgabe von 'arp -a' (Windows) bzw. 'arp -an' (macOS/Linux) aus -> {ip: mac}."""
    table: Dict[str, str] = {}
    for line in out.splitlines():
        if windows:
            m = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})", line)
            ip, mac = (m.group(1), m.group(2).replace("-", ":")) if m else (None, None)
        else:
            ipm = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)", line)
            macm = _MAC_RE.search(line)
            ip, mac = (ipm.group(1), macm.group(1)) if ipm and macm and "incomplete" not in line.lower() else (None, None)
        if ip:
            mac = normalize_mac(mac)
            if mac not in _UNGUELTIGE_MACS:
                table[ip] = mac
    return table


def _programmfehler(was: str, prog: str, e: BaseException) -> str:
    """Kurzer deutscher Hinweis für last_problems."""
    if isinstance(e, subprocess.TimeoutExpired):
        return f"{was}: {prog} antwortet nicht"
    if isinstance(e, FileNotFoundError):
        return f"{was}: {prog} nicht gefunden"
    return f"{was}: {prog} fehlgeschlagen ({e})"


def read_arp_table(problems: Optional[List[str]] = None) -> Dict[str, str]:
    """Liest die ARP-Tabelle des Systems -> {ip: mac}.

    macOS/Linux: 'arp -an' – OHNE -n löst arp jeden Eintrag per DNS auf; in Praxisnetzen
    mit vielen Geräten dauerte das länger als das Timeout, die Tabelle kam leer zurück und
    KEIN Gerät bekam eine MAC. Ausgabe als Bytes lesen und tolerant dekodieren
    (Windows-Konsole nutzt die OEM-Codepage) – ein Dekodierfehler leerte sonst ebenfalls alles.
    Fehler (Timeout, Programm fehlt) landen in `problems` statt still {}."""
    cmd = [ARP, "-a"] if WINDOWS else [ARP, "-an"]
    try:
        out = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=30, **NO_WINDOW).stdout
    except (OSError, subprocess.SubprocessError) as e:
        if problems is not None:
            problems.append(_programmfehler("MAC-Adressen nicht lesbar", "arp", e))
        return {}
    return parse_arp_output(out.decode("latin-1"), WINDOWS)


def _arp_anstossen(ip: str):
    """Löst eine ARP-Auflösung aus, ohne auf Antwort zu warten (UDP-Paket an den Discard-Port)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(b"", (ip, 9))
    except OSError:
        pass


def read_arp_for(ips: List[str], local_net: Optional[ipaddress.IPv4Network], versuche: int = 3,
                 problems: Optional[List[str]] = None) -> Dict[str, str]:
    """ARP-Tabelle lesen; fehlen Geräte aus dem eigenen Subnetz, ARP für sie neu anstoßen
    und erneut lesen (Einträge können zwischen Ping und Auslesen schon verfallen sein,
    unter Windows z. B. nach ~30 s)."""
    table = read_arp_table(problems)
    for _ in range(versuche - 1):
        fehlend = [ip for ip in ips if ip not in table and local_net is not None
                   and ipaddress.ip_address(ip) in local_net]
        if not fehlend:
            break
        for ip in fehlend:
            _arp_anstossen(ip)
        time.sleep(1.0)
        table.update(read_arp_table(problems))
    return table


def own_interface(ip: str, problems: Optional[List[str]] = None) -> Tuple[str, Optional[int]]:
    """(MAC, Präfixlänge) der eigenen Netzwerkkarte mit dieser IP. Die eigene MAC steht nie
    in der eigenen ARP-Tabelle. Präfix None = nicht ermittelbar. Unter Windows MAC und
    Präfix in EINEM PowerShell-Aufruf (Start dauert 1–3 s, läuft parallel zum ARP-Lesen)."""
    try:
        ip = str(ipaddress.IPv4Address(ip))  # nur geprüfte IP in den PowerShell-Befehl
    except ValueError:
        return "", None
    try:
        if WINDOWS:
            ps = ("$a = Get-NetIPAddress -IPAddress '%s' -ErrorAction Stop | Select-Object -First 1; "
                  "(Get-NetAdapter -InterfaceIndex $a.InterfaceIndex).MacAddress; "
                  "'PREFIX=' + $a.PrefixLength" % ip)
            out = subprocess.run([POWERSHELL, "-NoProfile", "-NonInteractive", "-Command", ps],
                                 stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=8,
                                 **NO_WINDOW).stdout.decode("latin-1")
            m = re.search(r"([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})", out)
            p = re.search(r"PREFIX=(\d+)", out)
            return (normalize_mac(m.group(1).replace("-", ":")) if m else "",
                    int(p.group(1)) if p else None)
        out = subprocess.run([IFCONFIG], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                             timeout=10).stdout.decode("latin-1")
        return parse_ifconfig(out, ip)
    except (OSError, subprocess.SubprocessError) as e:
        if problems is not None:
            problems.append(_programmfehler("Eigene MAC nicht lesbar",
                                            "PowerShell" if WINDOWS else "ifconfig", e))
        return "", None


def own_mac(ip: str) -> str:
    """MAC der eigenen Netzwerkkarte zur IP."""
    return own_interface(ip)[0]


def _praefix(maske: str) -> Optional[int]:
    """'0xffffff00' (macOS) oder '255.255.255.0' (Linux) -> 24."""
    try:
        wert = int(maske, 16) if maske.lower().startswith("0x") else int(ipaddress.IPv4Address(maske))
    except ValueError:
        return None
    return bin(wert).count("1")


def parse_ifconfig(out: str, ip: str) -> Tuple[str, Optional[int]]:
    """Sucht in 'ifconfig'-Ausgabe die Schnittstelle mit dieser IPv4 -> (MAC, Präfixlänge)."""
    for block in re.split(r"\n(?=\S)", out):
        zeile = re.search(r"\binet (?:addr:)?%s\b[^\n]*" % re.escape(ip), block)
        if zeile:
            m = re.search(r"\b(?:ether|HWaddr)\s+([0-9a-fA-F:]{11,17})", block)
            nm = re.search(r"(?:netmask|Mask:)\s*(0x[0-9a-fA-F]{8}|\d+\.\d+\.\d+\.\d+)", zeile.group(0))
            return (normalize_mac(m.group(1)) if m else "",
                    _praefix(nm.group(1)) if nm else None)
    return "", None


def parse_ifconfig_mac(out: str, ip: str) -> str:
    """Sucht in 'ifconfig'-Ausgabe die Schnittstelle mit dieser IPv4 und liefert ihre MAC."""
    return parse_ifconfig(out, ip)[0]


# ---------------------------------------------------------------------------
# Namensauflösung
# ---------------------------------------------------------------------------

def reverse_dns(ip: str, timeout: float = 3.0) -> str:
    """PTR-Name zur IP, höchstens `timeout` Sekunden.

    Nicht socket.gethostbyaddr: das läuft auf macOS hinter einer globalen Sperre (nacheinander)
    und wartet ohne PTR-Eintrag ~30 s – bei 22 Geräten dauerte ein Scan so über 13 Minuten.
    getnameinfo läuft parallel; hängt der Resolver, geben wir nach `timeout` auf
    (der Hilfsthread endet von selbst, sobald der Resolver antwortet)."""
    ergebnis = [""]

    def frage():
        try:
            ergebnis[0] = socket.getnameinfo((ip, 0), socket.NI_NAMEREQD)[0]
        except OSError:
            pass  # kein PTR-Eintrag - normal, kein Fehler

    t = threading.Thread(target=frage, daemon=True)
    t.start()
    t.join(timeout)
    return ergebnis[0]


# --- mDNS / Bonjour (.local-Namen) ----------------------------------------

def _dns_encode_name(name: str) -> bytes:
    out = b""
    for label in name.split("."):
        if label:
            out += bytes([len(label)]) + label.encode("ascii", "ignore")
    return out + b"\x00"


def _dns_read_name(data: bytes, offset: int):
    """Liest einen DNS-Namen (inkl. Kompressions-Zeiger). Gibt (name, ende)."""
    labels = []
    jumped = False
    end = offset
    for _ in range(128):  # Schutz gegen Endlosschleifen
        if offset >= len(data):
            break
        length = data[offset]
        if length == 0:
            offset += 1
            if not jumped:
                end = offset
            break
        if length & 0xC0 == 0xC0:  # Zeiger
            if offset + 1 >= len(data):
                break
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                end = offset + 2
            offset = ptr
            jumped = True
            continue
        offset += 1
        labels.append(data[offset:offset + length].decode("utf-8", "replace"))  # Bonjour-Namen sind UTF-8
        offset += length
    return ".".join(labels), end


def _parse_ptr(data: bytes) -> str:
    try:
        qdcount = int.from_bytes(data[4:6], "big")
        ancount = int.from_bytes(data[6:8], "big")
        offset = 12
        for _ in range(qdcount):
            _, offset = _dns_read_name(data, offset)
            offset += 4
        for _ in range(ancount):
            _, offset = _dns_read_name(data, offset)
            rtype = int.from_bytes(data[offset:offset + 2], "big")
            offset += 8  # type(2)+class(2)+ttl(4)
            rdlength = int.from_bytes(data[offset:offset + 2], "big")
            offset += 2
            if rtype == 12:  # PTR
                name, _ = _dns_read_name(data, offset)
                return name
            offset += rdlength
    except Exception:
        return ""
    return ""


def mdns_name(ip: str, timeout: float = 1.0) -> str:
    """Fragt den Bonjour/.local-Namen per Multicast-DNS (PTR) ab.

    Findet Namen vieler Apple-, Linux- und IoT-Geräte, die kein Reverse-DNS
    und kein NetBIOS haben. Keine Antwort (Timeout) ist normal und liefert
    "". Andere Exceptions (Socket-/Sendefehler) werden bewusst NICHT
    geschluckt, sondern propagiert - der Aufrufer wertet das als echten
    Fehlschlag statt als "kein Name gefunden".
    """
    rev = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
    query = b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    query += _dns_encode_name(rev)
    query += b"\x00\x0c" + b"\x80\x01"  # QTYPE=PTR, QCLASS=IN + Unicast-Antwort
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        except Exception:
            pass
        s.settimeout(timeout)
        s.sendto(query, ("224.0.0.251", 5353))
        deadline = time.time() + timeout
        result = ""
        while time.time() < deadline:
            try:
                data, _ = s.recvfrom(2048)
            except socket.timeout:
                break  # keine Antwort - normal, kein Fehler
            name = _parse_ptr(data)
            if name:
                result = name
                break
        if result:
            # ".local"-Suffix und Endpunkt entfernen -> kompakter Name
            return result.rstrip(".").removesuffix(".local")
        return ""
    finally:
        s.close()


def netbios_name(ip: str, timeout: float = 1.0) -> str:
    """Fragt den NetBIOS-Namen (NBSTAT) per UDP/137 ab – Windows-Geräte und Samba.

    Keine Antwort (Timeout, z.B. bei jedem Nicht-Windows-Gerät) ist normal
    und liefert "". Andere Exceptions werden bewusst propagiert.
    """
    # NBSTAT-Anfrage (Node Status)
    tid = b"\x42\x42"
    query = tid + b"\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    query += b"\x20" + b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" + b"\x00"
    query += b"\x00\x21\x00\x01"
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        sock.sendto(query, (ip, 137))
        try:
            data, _ = sock.recvfrom(1024)
        except (socket.timeout, ConnectionResetError):
            return ""  # keine Antwort (Windows: ICMP port unreachable) - normal, kein Fehler
        return parse_nbstat(data)
    finally:
        sock.close()


def parse_nbstat(data: bytes) -> str:
    """Rechnername aus einer NBSTAT-Antwort (ohne Socket, für Tests). "" wenn keiner drin.
    Antwort beantwortet auch Samba (NAS, Mac, Linux) – daher KEIN Rückschluss auf Windows."""
    if len(data) < 57:
        return ""
    num_names = data[56]
    offset = 57
    for _ in range(num_names):
        if offset + 18 > len(data):
            break
        name = data[offset:offset + 15].decode("ascii", "ignore").strip()
        flags = data[offset + 16]  # Byte 15 ist das Suffix, 16/17 die Flags
        offset += 18
        # Unique + kein Gruppenname -> Rechnername
        if flags & 0x80 == 0 and name and name != "__MSBROWSE__":
            return name
    return ""


# ---------------------------------------------------------------------------
# Port-Scan + Banner
# ---------------------------------------------------------------------------

def scan_port(ip: str, port: int, timeout: float = 0.6) -> bool:
    """True, wenn der Port offen ist. connect_ex() liefert für einen
    geschlossenen/abgelehnten Port einen Fehlercode zurück (kein Exception) -
    ein hier auftretender Exception ist daher immer ein echtes Problem
    (z.B. Ressourcen-Erschöpfung) und wird bewusst NICHT geschluckt."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        return s.connect_ex((ip, port)) == 0
    finally:
        s.close()


def grab_banner(ip: str, port: int, timeout: float = 1.0) -> str:
    """Versucht ein Text-Banner zu lesen (HTTP/SSH/SMTP…).

    Der Port ist beim Aufruf bereits als offen bekannt; bleibt eine Antwort
    schlicht aus (Timeout/Verbindungsabbruch), ist das normal (nicht jeder
    Dienst sendet sofort ein Banner) und liefert "". Andere Exceptions
    werden bewusst propagiert.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        if s.connect_ex((ip, port)) != 0:
            return ""
        if port in (80, 8080):
            s.sendall(b"HEAD / HTTP/1.0\r\nHost: %b\r\n\r\n" % ip.encode())
        elif port in (443, 8443):
            return ""  # TLS – ohne ssl-Handshake kein Klartext
        data = s.recv(256)
        text = data.decode("latin-1", "ignore").strip()
        # Für HTTP nur die Server-Zeile herausziehen
        m = re.search(r"Server:\s*([^\r\n]+)", text, re.I)
        if m:
            return m.group(1).strip()
        return text.splitlines()[0].strip() if text else ""
    except (socket.timeout, ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
        return ""
    finally:
        s.close()


# ---------------------------------------------------------------------------
# Orchestrierung
# ---------------------------------------------------------------------------

ProgressCb = Optional[Callable[[float, str], None]]


# Bekannte lokal verwaltete MAC-Präfixe, die KEINE zufälligen Handy-Adressen sind.
_VM_PRAEFIXE = (
    ("52:54:00", "Virtuelle Maschine (QEMU/KVM)"),
    ("02:42:", "Docker-Container"),
)
_MAC_DOPPELT = "MAC mehrfach vergeben (Repeater/Proxy-ARP?)"


def vendor_for_mac(mac: str) -> str:
    """Hersteller zur MAC; ohne OUI-Treffer VM-Präfix bzw. „Private MAC (zufällig)“."""
    vendor = lookup_vendor(mac)
    if vendor:
        return vendor
    for praefix, name in _VM_PRAEFIXE:
        if mac.startswith(praefix):
            return name
    if int(mac[1], 16) & 2:  # „lokal verwaltet“-Bit: Handy/Tablet mit privater WLAN-Adresse
        return "Private MAC (zufällig)"
    return ""


class Scanner:
    def __init__(self, config: Optional[ScanConfig] = None):
        self.config = config or ScanConfig()
        self._cancel = threading.Event()
        self.last_problems: List[str] = []  # Hinweise des letzten Scans (für die GUI)
        self.cancelled = False              # True = letzter Scan wurde abgebrochen

    def cancel(self):
        self._cancel.set()

    def reset(self):
        self._cancel.clear()
        self.cancelled = False
        self.last_problems = []

    def _report(self, cb: ProgressCb, frac: float, msg: str):
        if cb:
            cb(frac, msg)

    def _abbrechen(self, ex: concurrent.futures.Executor):
        self._cancel.set()
        ex.shutdown(wait=False, cancel_futures=True)

    def scan(self, cidr: str, progress: ProgressCb = None,
             on_host: Optional[Callable[[Host], None]] = None) -> List[Host]:
        """Scannt das Netz. ValueError (deutscher Text) bei ungültigem/zu großem Netz.
        Nach dem Scan: self.last_problems (Hinweise), self.cancelled."""
        self.reset()
        cfg = self.config
        targets = hosts_in_network(cidr)
        total = len(targets)
        problems = self.last_problems
        self._report(progress, 0.0, f"Starte Ping-Sweep über {total} Adressen …")

        # --- Phase 1: Aktive Erreichbarkeitsprüfung (parallel) ------------
        # Als "lebend" gilt NUR, wer zur Scan-Zeit aktiv antwortet:
        # Ping ODER offener/abgelehnter TCP-Port. Keine (evtl. veralteten)
        # ARP-Cache-Einträge. Funktioniert auch netzübergreifend über Router.
        alive: List[str] = []
        done = 0
        fehlgeschlagen = 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=cfg.max_workers) as ex:
            try:
                futures = {ex.submit(probe, ip, cfg.ping_timeout, problems): ip for ip in targets}
                for fut in concurrent.futures.as_completed(futures):
                    if self._cancel.is_set():
                        self._abbrechen(ex)
                        break
                    ip = futures[fut]
                    done += 1
                    try:
                        if fut.result():
                            alive.append(ip)
                    except Exception:  # z. B. EMFILE: Adresse nicht prüfbar - zählen statt verschweigen
                        fehlgeschlagen += 1
                    self._report(progress, 0.4 * done / max(total, 1),
                                 f"Prüfe {done}/{total} – {len(alive)} erreichbar")
            except BaseException:  # Strg+C o. Ä.: Rest nicht mehr starten
                self._abbrechen(ex)
                raise
        if fehlgeschlagen:
            problems.append(f"{fehlgeschlagen} Adressen konnten nicht geprüft werden (Systemfehler)")

        if self._cancel.is_set():
            self.last_problems[:] = list(dict.fromkeys(problems))
            self.cancelled = True
            return []

        # Eigene IP/Karte FÜR DIESES NETZ (nicht Default-Route – wichtig bei VPN/mehreren Karten).
        # ARP-Tabelle NUR zur MAC-/Hersteller-Zuordnung der erreichbaren Geräte
        # (nur im selben Subnetz verfügbar; sonst bleibt die MAC leer).
        scan_net = ipaddress.ip_network(cidr.strip(), strict=False)
        own = local_ip_for(targets[0]) if targets else ""
        if not own:
            problems.append("Eigene Netzwerkkarte für dieses Netz nicht ermittelbar")
        self._report(progress, 0.4, "Lese MAC-Adressen …")
        local_net = None
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
            eigen = ex.submit(own_interface, own, problems) if own else None
            if own and ipaddress.ip_address(own) in scan_net:
                local_net = scan_net  # nicht auf PowerShell warten
            elif eigen:
                praefix = eigen.result()[1] or 24
                local_net = ipaddress.ip_network(f"{own}/{praefix}", strict=False)
            arp = read_arp_for(alive, local_net, problems=problems)
            mac = eigen.result()[0] if eigen else ""
        if own in targets and mac:
            arp[own] = mac

        # Eigene IP immer aufnehmen
        if own not in alive and own in targets:
            alive.append(own)
        alive = sorted(set(alive), key=lambda x: int(ipaddress.ip_address(x)))

        # Gleiche MAC bei mehreren IPs (Repeater/Proxy-ARP): Hersteller wäre geraten/falsch.
        zaehler: Dict[str, int] = {}
        for ip in alive:
            if arp.get(ip):
                zaehler[arp[ip]] = zaehler.get(arp[ip], 0) + 1
        doppelt = {m for m, n in zaehler.items() if n > 1}
        self._report(progress, 0.4, f"{len(alive)} Geräte erreichbar – ermittle Details …")

        # --- Phase 2: Details je Host (parallel) --------------------------
        hosts: List[Host] = []
        n_alive = len(alive)
        done = 0

        def enrich(ip: str) -> Host:
            h = Host(ip=ip)
            if self._cancel.is_set():
                return h
            h.mac = arp.get(ip, "")
            if h.mac in doppelt:
                h.scan_warning = _add_warning(h.scan_warning, _MAC_DOPPELT)
                if ip == own:
                    h.vendor = vendor_for_mac(h.mac)  # eigene MAC kommt sicher von der eigenen Karte
            elif h.mac:
                h.vendor = vendor_for_mac(h.mac)
            # Namen: Reverse-DNS -> mDNS/Bonjour -> NetBIOS; jeder Resolver einzeln,
            # ein Fehler in einem verhindert die anderen nicht.
            fehler = []
            for name, frage in (("DNS", lambda: reverse_dns(ip)),
                                ("mDNS", lambda: mdns_name(ip, cfg.ping_timeout)),
                                ("NetBIOS", lambda: netbios_name(ip, cfg.ping_timeout))):
                if h.hostname:
                    break
                try:
                    h.hostname = frage()
                except Exception:
                    fehler.append(name)
            if fehler:
                h.scan_warning = _add_warning(h.scan_warning,
                                              f"Namensauflösung fehlgeschlagen ({', '.join(fehler)})")
            # Ports
            try:
                for port in cfg.ports:
                    if self._cancel.is_set():
                        break
                    if scan_port(ip, port, cfg.port_timeout):
                        h.open_ports.append(port)
                        h.services[port] = COMMON_PORTS.get(port, str(port))
                        if cfg.do_banner and port in BANNER_PORTS:
                            b = grab_banner(ip, port, cfg.port_timeout + 0.4)
                            if b:
                                h.services[port] = b
            except Exception:
                h.scan_warning = _add_warning(h.scan_warning, "Portscan fehlgeschlagen")
            # Ableitungen
            classify_device(h)
            return h

        with concurrent.futures.ThreadPoolExecutor(max_workers=min(cfg.max_workers, 64)) as ex:
            try:
                futures = {ex.submit(enrich, ip): ip for ip in alive}
                for fut in concurrent.futures.as_completed(futures):
                    if self._cancel.is_set():
                        self._abbrechen(ex)
                        break
                    done += 1
                    try:
                        h = fut.result()
                    except Exception:
                        h = Host(ip=futures[fut],
                                 scan_warning="Scan fehlgeschlagen (unerwarteter Fehler)")
                    hosts.append(h)
                    if on_host:
                        on_host(h)
                    self._report(progress, 0.4 + 0.6 * done / max(n_alive, 1),
                                 f"Details {done}/{n_alive} – {h.ip}")
            except BaseException:
                self._abbrechen(ex)
                raise

        hosts.sort(key=lambda x: x.sort_key())
        self.last_problems[:] = list(dict.fromkeys(problems))  # Dubletten raus (z. B. ping fehlt)
        hinweis = (" Hinweis: " + "; ".join(self.last_problems)) if self.last_problems else ""
        if self._cancel.is_set():
            self.cancelled = True
            self._report(progress, 1.0, f"Abgebrochen – {len(hosts)} Geräte (unvollständig).{hinweis}")
        else:
            self._report(progress, 1.0, f"Fertig – {len(hosts)} Geräte.{hinweis}")
        return hosts
