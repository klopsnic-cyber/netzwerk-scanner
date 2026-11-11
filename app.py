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
            kunde: str, kundennr: str, datum: str, passwort: str = "") -> int:
    from netzwerkscanner import exporter
    from netzwerkscanner.scanner import ScanConfig, Scanner, hosts_in_network

    try:
        hosts_in_network(cidr)
    except ValueError as e:
        print(f"Fehler: {e}", file=sys.stderr)
        return 2

    def prog(frac, msg):
        sys.stdout.write(f"\r[{int(frac*100):3d}%] {msg[:70]:<70}")
        sys.stdout.flush()

    scanner = Scanner(ScanConfig(depth=depth))
    try:
        hosts = scanner.scan(cidr, progress=prog)
    except KeyboardInterrupt:
        print("\nAbgebrochen")
        return 130
    print()
    print(f"{len(hosts)} Geräte gefunden.")
    for h in hosts:
        print(f"  {h.ip:<15} {h.vendor:<18} {h.device_type:<22} {h.hostname}")
    for p in scanner.last_problems:
        print(f"Hinweis: {p}")
    out = out or exporter.suggested_filename(kunde)
    path = exporter.export(hosts, out, template_path=template or None,
                           kundenname=kunde, kundennummer=kundennr,
                           installationsdatum=datum, passwort=passwort)
    print(f"\nExportiert nach: {path}")
    return 0


def main():
    if (sys.stdout is None or sys.stderr is None) and any(a.startswith("--cli") for a in sys.argv[1:]):
        sys.exit(2)  # Windows-GUI-Build hat keine Konsole: --cli nur per "python app.py" möglich
    parser = argparse.ArgumentParser(description="Netzwerk-Scanner für die Tomedo-Netzwerkdoku")
    parser.add_argument("--cli", metavar="CIDR", help="Terminal-Scan statt GUI (z.B. 192.168.1.0/24)")
    parser.add_argument("--depth", default="gruendlich",
                        choices=["schnell", "standard", "gruendlich"])
    parser.add_argument("--out", default="", help="Ziel-Excel-Datei")
    parser.add_argument("--template", default="", help="Abweichende Vorlage")
    parser.add_argument("--kunde", default="")
    parser.add_argument("--kundennr", default="")
    parser.add_argument("--datum", default="")
    parser.add_argument("--passwort", default="", help="Verschlüsselt die exportierte .xlsx mit diesem Kennwort")
    args = parser.parse_args()

    if args.cli:
        sys.exit(run_cli(args.cli, args.depth, args.out, args.template,
                         args.kunde, args.kundennr, args.datum, args.passwort))
    else:
        from netzwerkscanner.gui import main as gui_main
        gui_main()


if __name__ == "__main__":
    main()
