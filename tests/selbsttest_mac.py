# Selbsttest MAC-Auswertung: .venv/bin/python tests/selbsttest_mac.py  (Exit 1 bei Fehler)
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from netzwerkscanner.scanner import parse_arp_output, parse_ifconfig_mac  # noqa: E402

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

print("OK – MAC-Auswertung macOS, Windows, Linux, eigene MAC")
