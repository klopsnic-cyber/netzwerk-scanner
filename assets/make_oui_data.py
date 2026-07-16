#!/usr/bin/env python3
"""
Erzeugt netzwerkscanner/oui_data.py aus data/oui.csv.

Die offizielle IEEE-OUI-Liste wird kompakt (Prefix -> Hersteller), gzip-komprimiert
und base64-kodiert fest in den Programmcode eingebettet. Dadurch funktioniert die
Hersteller-Erkennung immer offline und überlebt jede Art der Weitergabe (DMG, etc.),
ohne von einer separaten Datei abzuhängen.

Aufruf:  python3 assets/make_oui_data.py
"""
from __future__ import annotations

import base64
import csv
import gzip
import io
import os
import sys
import textwrap

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CSV = os.path.join(ROOT, "data", "oui.csv")
OUT = os.path.join(ROOT, "netzwerkscanner", "oui_data.py")


def build_mapping(path):
    table = {}
    with open(path, "r", encoding="utf-8", errors="ignore", newline="") as f:
        reader = csv.reader(f)
        header = next(reader, None)
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
            if len(prefix) >= 6 and name:
                table[prefix[:6]] = name
    return table


def main():
    if not os.path.exists(CSV):
        print(f"HINWEIS: {CSV} fehlt – oui_data.py wird nicht neu erzeugt.")
        return
    table = build_mapping(CSV)
    # Kompakt serialisieren: "PREFIX\tName\n"
    lines = "".join(f"{p}\t{n}\n" for p, n in sorted(table.items()))
    packed = gzip.compress(lines.encode("utf-8"), 9)
    b64 = base64.b64encode(packed).decode("ascii")
    chunks = textwrap.wrap(b64, 76)
    with open(OUT, "w", encoding="utf-8") as f:
        f.write('"""Eingebettete IEEE-OUI-Herstellerliste (Prefix -> Hersteller).\n')
        f.write("Automatisch aus data/oui.csv erzeugt – nicht von Hand bearbeiten.\n")
        f.write(f"Einträge: {len(table)}\n\"\"\"\n\n")
        f.write("import base64 as _b64, gzip as _gz\n\n")
        f.write(f"COUNT = {len(table)}\n\n")
        f.write("_B64 = (\n")
        for c in chunks:
            f.write(f'    "{c}"\n')
        f.write(")\n\n")
        f.write("def load():\n")
        f.write('    """Gibt {Prefix: Hersteller} zurück (dekomprimiert)."""\n')
        f.write("    raw = _gz.decompress(_b64.b64decode(_B64)).decode('utf-8')\n")
        f.write("    t = {}\n")
        f.write("    for line in raw.splitlines():\n")
        f.write("        if '\\t' in line:\n")
        f.write("            p, n = line.split('\\t', 1)\n")
        f.write("            t[p] = n\n")
        f.write("    return t\n")
    print(f"oui_data.py erzeugt: {len(table)} Hersteller, "
          f"{len(b64)//1024} KB base64 -> {os.path.getsize(OUT)//1024} KB Datei")


if __name__ == "__main__":
    main()
