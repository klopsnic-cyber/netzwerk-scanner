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
import platform
import re
import socket
import struct
import subprocess
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from .oui import lookup_vendor
from .classify import classify_device

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

    def sort_key(self):
        try:
            return int(ipaddress.ip_address(self.ip))
        except ValueError:
            return 0


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
}

# Reduzierter Portsatz für den schnellen Modus.
QUICK_PORTS = [22, 80, 135, 139, 443, 445, 515, 631, 3389, 9100]

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

def get_local_ip() -> str:
    """Ermittelt die primäre lokale IPv4-Adresse (ohne echten Traffic)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()


def guess_local_network(prefix: int = 24) -> str:
    """Rät das lokale /24-Netz aus der eigenen IP, z.B. '192.168.1.0/24'."""
    ip = get_local_ip()
    try:
        net = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
        return str(net)
    except ValueError:
        return "192.168.1.0/24"


def hosts_in_network(cidr: str, limit: int = 1024) -> List[str]:
    net = ipaddress.ip_network(cidr, strict=False)
    hosts = [str(h) for h in net.hosts()]
    return hosts[:limit]


# ---------------------------------------------------------------------------
# Ping-Sweep
# ---------------------------------------------------------------------------

def _ping_cmd(ip: str, timeout: float) -> List[str]:
    system = platform.system().lower()
    if system == "windows":
        return ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip]
    if system == "darwin":
        # -t Gesamt-Timeout in Sekunden auf macOS
        return ["ping", "-c", "1", "-t", str(max(1, int(timeout))), ip]
    # Linux
    return ["ping", "-c", "1", "-W", str(max(1, int(timeout))), ip]


def ping(ip: str, timeout: float = 1.0) -> bool:
    try:
        res = subprocess.run(
            _ping_cmd(ip, timeout),
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=timeout + 1.5,
        )
        return res.returncode == 0
    except Exception:
        return False


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


def tcp_reachable(ip: str, timeout: float = 0.5, ports=LIVENESS_PORTS) -> bool:
    """True, wenn der Host auf mind. einem TCP-Port jetzt reagiert
    (Verbindung offen oder aktiv abgelehnt = Host lebt gerade)."""
    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            rc = s.connect_ex((ip, port))
            if rc == 0 or rc == errno.ECONNREFUSED:
                return True
        except Exception:
            pass
        finally:
            s.close()
    return False


def probe(ip: str, timeout: float = 1.0) -> bool:
    """Ist der Host JETZT aktiv erreichbar? Erst Ping (auch subnetzübergreifend),
    dann als Rückfall ein aktiver TCP-Kontakt. Keine ARP-Cache-Auswertung –
    es werden nur Geräte gemeldet, die zur Scan-Zeit tatsächlich antworten."""
    if ping(ip, timeout):
        return True
    return tcp_reachable(ip, min(timeout, 0.5))


# ---------------------------------------------------------------------------
# ARP-Tabelle -> MAC
# ---------------------------------------------------------------------------

_MAC_RE = re.compile(r"([0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{1,2}){5})")


def normalize_mac(mac: str) -> str:
    parts = mac.split(":")
    if len(parts) != 6:
        return mac.upper()
    return ":".join(p.zfill(2).upper() for p in parts)


def read_arp_table() -> Dict[str, str]:
    """Liest die ARP-Tabelle des Systems -> {ip: mac}."""
    table: Dict[str, str] = {}
    system = platform.system().lower()
    try:
        if system == "windows":
            out = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=10).stdout
            for line in out.splitlines():
                m = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17})", line)
                if m:
                    table[m.group(1)] = normalize_mac(m.group(2).replace("-", ":"))
        else:
            out = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=10).stdout
            for line in out.splitlines():
                ipm = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)", line)
                macm = _MAC_RE.search(line)
                if ipm and macm and "incomplete" not in line.lower():
                    table[ipm.group(1)] = normalize_mac(macm.group(1))
    except Exception:
        pass
    return table


# ---------------------------------------------------------------------------
# Namensauflösung
# ---------------------------------------------------------------------------

def reverse_dns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


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
        labels.append(data[offset:offset + length].decode("latin-1", "ignore"))
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
    und kein NetBIOS haben.
    """
    try:
        rev = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
        query = b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        query += _dns_encode_name(rev)
        query += b"\x00\x0c" + b"\x80\x01"  # QTYPE=PTR, QCLASS=IN + Unicast-Antwort
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
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
                break
            name = _parse_ptr(data)
            if name:
                result = name
                break
        s.close()
        if result:
            # ".local"-Suffix und Endpunkt entfernen -> kompakter Name
            return result.rstrip(".").removesuffix(".local")
        return ""
    except Exception:
        return ""


def netbios_name(ip: str, timeout: float = 1.0) -> str:
    """Fragt den NetBIOS-Namen (NBSTAT) per UDP/137 ab – für Windows-Geräte."""
    try:
        # NBSTAT-Anfrage (Node Status)
        tid = b"\x42\x42"
        query = tid + b"\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        query += b"\x20" + b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" + b"\x00"
        query += b"\x00\x21\x00\x01"
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(query, (ip, 137))
        data, _ = sock.recvfrom(1024)
        sock.close()
        num_names = data[56]
        offset = 57
        for _ in range(num_names):
            name = data[offset:offset + 15].decode("ascii", "ignore").strip()
            flags = data[offset + 15]
            offset += 18
            # Unique + kein Gruppenname -> Rechnername
            if flags & 0x80 == 0 and name and name != "__MSBROWSE__":
                return name
        return ""
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Port-Scan + Banner
# ---------------------------------------------------------------------------

def scan_port(ip: str, port: int, timeout: float = 0.6) -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        return s.connect_ex((ip, port)) == 0
    except Exception:
        return False
    finally:
        s.close()


def grab_banner(ip: str, port: int, timeout: float = 1.0) -> str:
    """Versucht ein Text-Banner zu lesen (HTTP/SSH/SMTP…)."""
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
    except Exception:
        return ""
    finally:
        s.close()


# ---------------------------------------------------------------------------
# Orchestrierung
# ---------------------------------------------------------------------------

ProgressCb = Optional[Callable[[float, str], None]]


class Scanner:
    def __init__(self, config: Optional[ScanConfig] = None):
        self.config = config or ScanConfig()
        self._cancel = threading.Event()

    def cancel(self):
        self._cancel.set()

    def reset(self):
        self._cancel.clear()

    def _report(self, cb: ProgressCb, frac: float, msg: str):
        if cb:
            cb(frac, msg)

    def scan(self, cidr: str, progress: ProgressCb = None,
             on_host: Optional[Callable[[Host], None]] = None) -> List[Host]:
        self.reset()
        cfg = self.config
        targets = hosts_in_network(cidr)
        total = len(targets)
        self._report(progress, 0.0, f"Starte Ping-Sweep über {total} Adressen …")

        # --- Phase 1: Aktive Erreichbarkeitsprüfung (parallel) ------------
        # Als "lebend" gilt NUR, wer zur Scan-Zeit aktiv antwortet:
        # Ping ODER offener/abgelehnter TCP-Port. Keine (evtl. veralteten)
        # ARP-Cache-Einträge. Funktioniert auch netzübergreifend über Router.
        alive: List[str] = []
        done = 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=cfg.max_workers) as ex:
            futures = {ex.submit(probe, ip, cfg.ping_timeout): ip for ip in targets}
            for fut in concurrent.futures.as_completed(futures):
                if self._cancel.is_set():
                    break
                ip = futures[fut]
                done += 1
                try:
                    if fut.result():
                        alive.append(ip)
                except Exception:
                    pass
                self._report(progress, 0.4 * done / max(total, 1),
                             f"Prüfe {done}/{total} – {len(alive)} erreichbar")

        if self._cancel.is_set():
            return []

        # ARP-Tabelle NUR zur MAC-/Hersteller-Zuordnung der erreichbaren Geräte
        # (nur im selben Subnetz verfügbar; sonst bleibt die MAC leer).
        arp = read_arp_table()

        # Eigene IP immer aufnehmen
        own = get_local_ip()
        if own not in alive and own in targets:
            alive.append(own)
        alive = sorted(set(alive), key=lambda x: int(ipaddress.ip_address(x)))
        self._report(progress, 0.4, f"{len(alive)} Geräte erreichbar – ermittle Details …")

        # --- Phase 2: Details je Host (parallel) --------------------------
        hosts: List[Host] = []
        lock = threading.Lock()
        n_alive = len(alive)
        done = 0

        def enrich(ip: str) -> Host:
            h = Host(ip=ip)
            h.mac = arp.get(ip, "")
            if h.mac:
                h.vendor = lookup_vendor(h.mac)
            # Namen: Reverse-DNS -> mDNS/Bonjour -> NetBIOS
            h.hostname = reverse_dns(ip)
            if not h.hostname:
                h.hostname = mdns_name(ip, cfg.ping_timeout)
            if not h.hostname:
                nb = netbios_name(ip, cfg.ping_timeout)
                if nb:
                    h.hostname = nb
                    h.os_hint = "Windows"
            # Ports
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
            # Ableitungen
            classify_device(h)
            return h

        with concurrent.futures.ThreadPoolExecutor(max_workers=min(cfg.max_workers, 64)) as ex:
            futures = {ex.submit(enrich, ip): ip for ip in alive}
            for fut in concurrent.futures.as_completed(futures):
                if self._cancel.is_set():
                    break
                done += 1
                try:
                    h = fut.result()
                except Exception:
                    h = Host(ip=futures[fut])
                with lock:
                    hosts.append(h)
                if on_host:
                    on_host(h)
                self._report(progress, 0.4 + 0.6 * done / max(n_alive, 1),
                             f"Details {done}/{n_alive} – {h.ip}")

        hosts.sort(key=lambda x: x.sort_key())
        self._report(progress, 1.0, f"Fertig – {len(hosts)} Geräte.")
        return hosts
