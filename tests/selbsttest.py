# Selbsttest (ohne Netz): .venv/bin/python tests/selbsttest.py  (Exit 1 bei Fehler)
# Läuft auf macOS und Windows; build.sh und der GitHub-Workflow rufen ihn auf.
import errno
import os
import socket
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from netzwerkscanner import scanner, update  # noqa: E402
from netzwerkscanner.classify import classify_device  # noqa: E402
from netzwerkscanner.oui import lookup_vendor  # noqa: E402
from netzwerkscanner.scanner import (  # noqa: E402
    Host, hosts_in_network, parse_arp_output, parse_ifconfig, parse_ifconfig_mac,
    parse_nbstat, vendor_for_mac, _parse_ptr)

T0 = time.monotonic()

MAC_OS = """? (192.168.222.1) at 0:1a:2b:3c:4d:5e on en5 ifscope [ethernet]
? (192.168.222.20) at a4:83:e7:1:2:3 on en5 ifscope [ethernet]
? (192.168.222.30) at (incomplete) on en5 ifscope [ethernet]
? (192.168.222.255) at ff:ff:ff:ff:ff:ff on en5 ifscope [ethernet]
? (224.0.0.251) at 1:0:5e:0:0:fb on en0 ifscope permanent [ethernet]
"""
t = parse_arp_output(MAC_OS, windows=False)
assert t["192.168.222.1"] == "00:1A:2B:3C:4D:5E", t
assert t["192.168.222.20"] == "A4:83:E7:01:02:03", t
assert "192.168.222.30" not in t and "192.168.222.255" not in t, t

WINDOWS_DE = """
Schnittstelle: 192.168.1.50 --- 0xc
  Internetadresse       Physische Adresse     Typ
  192.168.1.1           00-1a-2b-3c-4d-5e     dynamisch
  192.168.1.23          b8-27-eb-aa-bb-cc     dynamisch
  192.168.1.255         ff-ff-ff-ff-ff-ff     statisch
  224.0.0.22            01-00-5e-00-00-16     statisch
""".encode("cp850").decode("latin-1")  # so wie read_arp_table die Konsole liest
t = parse_arp_output(WINDOWS_DE, windows=True)
assert t["192.168.1.1"] == "00:1A:2B:3C:4D:5E", t
assert t["192.168.1.23"] == "B8:27:EB:AA:BB:CC", t
assert "192.168.1.255" not in t, t

LINUX = "? (10.0.0.1) at 00:11:22:33:44:55 [ether] on eth0\n? (10.0.0.9) at <incomplete> on eth0\n"
t = parse_arp_output(LINUX, windows=False)
assert t == {"10.0.0.1": "00:11:22:33:44:55"}, t

IFCONFIG = """lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
\tinet 127.0.0.1 netmask 0xff000000
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tether 3c:22:fb:0:1:2
\tinet 10.1.1.5 netmask 0xffffff00 broadcast 10.1.1.255
en5: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tether 00:e0:4c:68:0a:bb
\tinet 192.168.222.12 netmask 0xffffff00 broadcast 192.168.222.255
"""
assert parse_ifconfig_mac(IFCONFIG, "192.168.222.12") == "00:E0:4C:68:0A:BB"
assert parse_ifconfig_mac(IFCONFIG, "10.1.1.5") == "3C:22:FB:00:01:02"
assert parse_ifconfig_mac(IFCONFIG, "192.168.222.1") == ""

# --- parse_ifconfig: Netzmaske macOS-Hex und Linux-Dotted ---------------
assert parse_ifconfig(IFCONFIG, "10.1.1.5") == ("3C:22:FB:00:01:02", 24)
LIN = ("eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
       "        inet 172.16.4.7  netmask 255.255.252.0  broadcast 172.16.7.255\n"
       "        ether 00:11:22:33:44:55  txqueuelen 1000  (Ethernet)\n")
assert parse_ifconfig(LIN, "172.16.4.7") == ("00:11:22:33:44:55", 22)
assert parse_ifconfig(LIN, "1.2.3.4") == ("", None)

# --- hosts_in_network ---------------------------------------------------
assert len(hosts_in_network("192.168.1.0/24")) == 254
assert len(hosts_in_network("10.0.0.0/22")) == 1022
for bad in ("10.0.0.0/16", "fe80::/64", "Unsinn", ""):
    try:
        hosts_in_network(bad)
    except ValueError:
        pass
    else:
        raise AssertionError(f"ValueError erwartet für {bad!r}")

# --- NBSTAT (RFC 1002): 12 Header + 34 Name + 10 (Typ/Klasse/TTL/Länge) = 56, dann Anzahl ---
def nbstat(namen):
    kopf = b"\x00\x01\x84\x00\x00\x00\x00\x01\x00\x00\x00\x00"
    frage = b"\x20" + b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" + b"\x00" + b"\x00\x21\x00\x01\x00\x00\x00\x00\x00\x00"
    eintraege = b"".join(n.ljust(15).encode("ascii") + bytes([suffix]) + bytes([flags, 0])
                         for n, suffix, flags in namen)
    return kopf + frage + bytes([len(namen)]) + eintraege
assert parse_nbstat(nbstat([("PRAXIS-PC", 0x00, 0x04)])) == "PRAXIS-PC"
# Gruppenname (Flag 0x80) zuerst: wird übersprungen, danach der Rechnername
assert parse_nbstat(nbstat([("WORKGROUP", 0x00, 0x84), ("SRV01", 0x20, 0x04)])) == "SRV01"
assert parse_nbstat(nbstat([("WORKGROUP", 0x00, 0x84)])) == ""
assert parse_nbstat(b"") == "" and parse_nbstat(b"\x00" * 40) == ""
assert parse_nbstat(nbstat([("PC", 0, 4)])[:62]) == ""  # abgeschnitten

# --- mDNS-PTR inkl. UTF-8 ----------------------------------------------
def ptr(label: str) -> bytes:
    rdata = bytes([len(label.encode())]) + label.encode() + b"\x05local\x00"
    return (b"\x00\x00\x84\x00\x00\x00\x00\x01\x00\x00\x00\x00" + b"\x011\x00"
            + b"\x00\x0c\x00\x01\x00\x00\x00\x78" + len(rdata).to_bytes(2, "big") + rdata)
assert _parse_ptr(ptr("Nics-MacBook-Pro")) == "Nics-MacBook-Pro.local"
assert _parse_ptr(ptr("Bürö-Mäc")) == "Bürö-Mäc.local"
assert _parse_ptr(b"\x00\x01") == ""

# --- classify -----------------------------------------------------------
def dev(ports=(), vendor="", name="", ip="10.0.0.50", mac=""):
    h = Host(ip=ip, vendor=vendor, hostname=name, open_ports=list(ports), mac=mac)
    classify_device(h)
    return h.device_type

FAELLE = [
    (dict(vendor="Synology Inc.", ports=[631, 445, 5000]), "NAS / Fileserver"),
    (dict(vendor="Apple, Inc.", ports=[631, 548]), "Mac"),
    (dict(vendor="Brother Industries", ports=[631, 80]), "Drucker"),
    (dict(ports=[9100]), "Drucker"),
    (dict(vendor="HP Inc."), "Drucker"),
    (dict(name="blueprint-pc"), ""),
    (dict(name="Orga-6141"), "Kartenleser / TI-Komponente"),
    (dict(name="DR-ORGANISATION"), ""),
    (dict(name="Galaxy-Phone", vendor="Samsung Electronics"), ""),
    (dict(vendor="Yealink"), "VoIP-Telefon"),
    (dict(name="Phone-1", ports=[5060]), "VoIP-Telefon"),
    (dict(vendor="Apple, Inc.", ports=[62078]), "iPhone / iPad"),
    (dict(vendor="Apple, Inc.", name="Wohnzimmer"), "Apple-Gerät"),
    (dict(vendor="Apple, Inc.", name="Nics-MacBook-Pro"), "Mac"),
    (dict(ports=[135, 445]), "PC / Workstation (Windows)"),
    (dict(name="srv-dc01"), "Server"),
    # HP baut auch PCs, HPE/Aruba Server/Switches – Hersteller allein ist kein Drucker
    (dict(vendor="Hewlett Packard", ports=[135, 445, 3389], name="praxis-pc3"), "PC / Workstation (Windows)"),
    (dict(vendor="Hewlett Packard Enterprise", name="ilo-srv01"), "Server"),
    (dict(vendor="HP Inc.", ports=[9100, 80]), "Drucker"),
]
for kw, erwartet in FAELLE:
    ist = dev(**kw)
    assert ist == erwartet, f"classify {kw}: {ist!r} != {erwartet!r}"

# --- OUI ----------------------------------------------------------------
assert "Kingtron" in lookup_vendor("34:29:8F:78:FB:0A")
for schreibweise in ("00:07:32:aa:bb:cc", "00-07-32-AA-BB-CC", "000732aabbcc", "0007.32aa.bbcc"):
    assert "AAEON" in lookup_vendor(schreibweise).upper(), schreibweise
assert lookup_vendor("aa:bb:cc:dd:ee:ff") == "" and lookup_vendor("") == ""

# --- vendor_for_mac: Docker, Private MAC ---------------------------------
assert vendor_for_mac("02:42:AC:11:00:02") == "Docker-Container"
assert vendor_for_mac("DA:A1:19:12:34:56") == "Private MAC (zufällig)"  # lokal verwaltet, kein OUI
assert vendor_for_mac("A0:BB:CC:DD:EE:FF") == ""  # global, unbekannt

# --- Exporter-Roundtrip --------------------------------------------------
import openpyxl  # noqa: E402
import msoffcrypto  # noqa: E402
from netzwerkscanner.exporter import export  # noqa: E402

hosts = [Host(ip="10.0.0.2", hostname="=1+1", vendor="X", open_ports=[80]),
         Host(ip="10.0.0.3", hostname="pc3"),
         Host(ip="10.0.0.4", hostname="ignoriert", ignored=True)]
with tempfile.TemporaryDirectory() as tmp:
    pfad = os.path.join(tmp, "plain.xlsx")
    export(hosts, pfad)
    ws = openpyxl.load_workbook(pfad).active
    zellen = {c.value: c for r in ws.iter_rows(min_row=6, max_row=12) for c in r if c.value}
    assert zellen["=1+1"].data_type == "s", "Formel muss Text bleiben"
    assert "ignoriert" not in zellen and "pc3" in zellen
    geraete = [t for t in ws.tables.values() if t.ref.split(":")[0].lstrip("ABCDEFGHIJKLMNOPQRSTUVWXYZ") == "5"]
    assert geraete, "Gerätetabelle fehlt"
    for t in geraete:
        assert t.ref.endswith("7"), t.ref  # Kopf Zeile 5 + 2 Hosts -> bis Zeile 7
        assert t.autoFilter is None or t.autoFilter.ref == t.ref, (t.ref, t.autoFilter.ref)

    pfad2 = os.path.join(tmp, "geheim.xlsx")
    export(hosts, pfad2, passwort="Pa55wort!")
    with open(pfad2, "rb") as f:
        of = msoffcrypto.OfficeFile(f)
        assert of.is_encrypted()
        of.load_key(password="Pa55wort!")
        out = os.path.join(tmp, "dec.xlsx")
        with open(out, "wb") as g:
            of.decrypt(g)
    assert openpyxl.load_workbook(out).active.max_row >= 7
    assert not os.path.exists(pfad2 + ".tmp")

# --- Host.from_dict (unbekannte Felder werden ignoriert, JSON-Keys normalisiert) ---
h = Host.from_dict({"ip": "1.2.3.4", "zukunft": 1, "open_ports": ["80"], "services": {"80": "http"}})
assert h.open_ports == [80] and h.services == {80: "http"}
try:
    Host.from_dict({"mac": "x"})  # ip fehlt -> kaputter Eintrag
except TypeError:
    pass
else:
    raise AssertionError("from_dict ohne ip sollte TypeError werfen")

# --- Versionsvergleich ---------------------------------------------------
for tag in ("v1.2.3", "1.2.3", "release-1.2.3"):
    assert update._parse_version(tag) == (1, 2, 3), tag
assert update._parse_version("1.3.0-rc1") is None
assert update._parse_version("1.3.0-rc1", allow_pre=True) == (1, 3, 0)
assert update._parse_version("blubb") is None

# --- tcp_reachable-Fehlerweg: EMFILE wird gemeldet, nicht still False ----
class _Voll:
    def __init__(self, *a, **k):
        raise OSError(errno.EMFILE, "Too many open files")

_orig_socket, _orig_ping = scanner.socket.socket, scanner.ping
scanner.socket.socket = _Voll
scanner.ping = lambda *a, **k: False
try:
    try:
        scanner.tcp_reachable("10.255.255.1")
    except OSError as e:
        assert e.errno == errno.EMFILE
    else:
        raise AssertionError("tcp_reachable muss OSError weitergeben")
    sc = scanner.Scanner(scanner.ScanConfig())
    sc.scan("10.255.255.0/30")
    assert any("nicht geprüft" in p for p in sc.last_problems), sc.last_problems
finally:
    scanner.socket.socket, scanner.ping = _orig_socket, _orig_ping

dauer = time.monotonic() - T0
# --- Handeingaben bei Repeater-MAC nur per IP (gui._note_mac) -----------
from netzwerkscanner.gui import App, GONE_WARNING  # noqa: E402,F401
from netzwerkscanner.scanner import _MAC_DOPPELT  # noqa: E402
assert App._note_mac(Host(ip="10.0.0.10", mac="AA:00:00:00:00:01", scan_warning=_MAC_DOPPELT)) == ""
assert App._note_mac(Host(ip="10.0.0.11", mac="00:11:22:33:44:55")) == "00:11:22:33:44:55"

print(f"OK – Selbsttest grün ({dauer:.1f} s): MAC/ARP/ifconfig, Netz, NBSTAT, mDNS, classify, OUI, Export, Update, Fehlerweg")
