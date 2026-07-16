# Netzwerk-Scanner (Tomedo-Netzwerkdoku)

Ein IP-Scanner für macOS, der das lokale Netzwerk durchsucht und die
gefundenen Geräte automatisch in die Excel-Vorlage `Netzwerkdoku-Vorlage.xlsx`
einträgt. Felder, die sich technisch nicht ermitteln lassen, bleiben leer und
werden von Hand ergänzt.

## Was der Scanner automatisch füllt

| Spalte | Automatisch? | Quelle |
|---|---|---|
| IP-Adresse | ✅ | Ping-Sweep |
| Hersteller | ✅ | MAC-Adresse → IEEE-OUI-Datenbank (offline) |
| Gerätetyp | 🟡 geraten | offene Ports + Hostname + Hersteller |
| Netzwerkname | ✅ | Reverse-DNS / mDNS / NetBIOS |
| MAC-Adresse | ✅ | ARP-Tabelle (nur gleiches Subnetz) |
| Standort | ➖ leer | manuell |
| User | ➖ leer | manuell |
| Kennwort | ➖ leer | manuell |
| angebunden an | ➖ leer | manuell |
| Windows Funktion | 🟡 geraten | erkannte Dienste (SQL, RDP, AD …) |
| Sonstiges | 🟡 | Liste offener Ports |
| Softwarestand | 🟡 geraten | Banner (Server-Version u.ä.) |
| eingerichtet von | ➖ leer | manuell |

> Hinweis: MAC-Adresse und Hersteller sind nur für Geräte im selben
> IP-Subnetz verfügbar (technische Grenze von ARP).

## Fertige App bauen (auf einem Mac)

macOS-Programme lassen sich nur auf einem Mac bauen. Einmalig:

```bash
cd IP-Scanner
chmod +x build.sh
./build.sh
```

Das Skript legt eine virtuelle Umgebung an, lädt die Hersteller-Datenbank,
baut `dist/Netzwerk-Scanner.app` und packt sie in `Netzwerk-Scanner.dmg`.

Optional für ein schöneres DMG-Fenster: `brew install create-dmg`.

### Erster Start
Die App ist nicht bei Apple signiert. Beim ersten Öffnen:
**Rechtsklick auf die App → „Öffnen" → „Öffnen"** bestätigen. macOS fragt
außerdem einmalig nach der Erlaubnis **„Lokales Netzwerk"** – diese erlauben,
sonst werden keine Geräte gefunden.

## Ohne Bauen testen (direkt starten)

Wer nichts installieren möchte, startet direkt mit Python (ab Werk auf macOS
vorhanden):

```bash
cd IP-Scanner
pip3 install openpyxl
python3 app.py                       # grafische Oberfläche
python3 app.py --cli 192.168.1.0/24  # reiner Terminal-Scan (umgeht die
                                     # macOS-Local-Network-Abfrage)
```

## Bedienung

1. Netzbereich prüfen (wird automatisch erkannt, z.B. `192.168.1.0/24`).
2. Optional Kundenname / Tomedo-Nummer / Datum eintragen.
3. **Scan starten** – Geräte erscheinen live in der Tabelle.
4. **In Excel exportieren** – erzeugt eine ausgefüllte Kopie der Vorlage.

## Projektstruktur

```
IP-Scanner/
├── app.py                     # Einstiegspunkt (GUI + --cli)
├── netzwerkscanner/
│   ├── scanner.py             # Ping-Sweep, ARP, Ports, Namen
│   ├── oui.py                 # Hersteller-Lookup (OUI)
│   ├── classify.py            # Gerätetyp-Heuristik
│   ├── exporter.py            # Excel-Ausgabe in die Vorlage
│   └── gui.py                 # Tkinter-Oberfläche
├── data/
│   ├── Netzwerkdoku-Vorlage.xlsx
│   └── oui.csv                # wird von build.sh geladen
├── build.sh                   # baut .app + .dmg (nur macOS)
├── NetzwerkScanner.spec       # PyInstaller-Konfiguration
└── requirements.txt
```

## Rechtlicher Hinweis
Nur im eigenen bzw. ausdrücklich freigegebenen Netzwerk verwenden.
Ein Port-Scan in fremden Netzen kann unzulässig sein.
```
