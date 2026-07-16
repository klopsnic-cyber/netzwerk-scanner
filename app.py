#!/usr/bin/env python3
"""
Einstiegspunkt für den Netzwerk-Scanner.

  python3 app.py            -> grafische Oberfläche (GUI)
  python3 app.py --cli NETZ -> Terminal-Scan, z.B. --cli 192.168.1.0/24
                               (umgeht die macOS-Local-Network-Berechtigung)
"""

import argparse
import sys


def run_cli(cidr: str, depth: str, out: str, template: str,
            kunde: str, kundennr: str, datum: str):
    from netzwerkscanner import exporter
    from netzwerkscanner.scanner import ScanConfig, Scanner

    def prog(frac, msg):
        sys.stdout.write(f"\r[{int(frac*100):3d}%] {msg[:70]:<70}")
        sys.stdout.flush()

    scanner = Scanner(ScanConfig(depth=depth))
    hosts = scanner.scan(cidr, progress=prog)
    print()
    print(f"{len(hosts)} Geräte gefunden.")
    for h in hosts:
        print(f"  {h.ip:<15} {h.vendor:<18} {h.device_type:<22} {h.hostname}")
    out = out or exporter.suggested_filename(kunde)
    path = exporter.export(hosts, out, template_path=template or None,
                           kundenname=kunde, kundennummer=kundennr,
                           installationsdatum=datum)
    print(f"\nExportiert nach: {path}")


def main():
    parser = argparse.ArgumentParser(description="Netzwerk-Scanner für die Tomedo-Netzwerkdoku")
    parser.add_argument("--cli", metavar="CIDR", help="Terminal-Scan statt GUI (z.B. 192.168.1.0/24)")
    parser.add_argument("--depth", default="gruendlich",
                        choices=["schnell", "standard", "gruendlich"])
    parser.add_argument("--out", default="", help="Ziel-Excel-Datei")
    parser.add_argument("--template", default="", help="Abweichende Vorlage")
    parser.add_argument("--kunde", default="")
    parser.add_argument("--kundennr", default="")
    parser.add_argument("--datum", default="")
    args = parser.parse_args()

    if args.cli:
        run_cli(args.cli, args.depth, args.out, args.template,
                args.kunde, args.kundennr, args.datum)
    else:
        from netzwerkscanner.gui import main as gui_main
        gui_main()


if __name__ == "__main__":
    main()
