# Netzwerk-Scanner (Tomedo-Netzwerkdoku)

Ein IP-Scanner für macOS und Windows, der das lokale Netzwerk durchsucht und
die gefundenen Geräte automatisch in die Excel-Vorlage
`Netzwerkdoku-Vorlage.xlsx` einträgt. Felder, die sich technisch nicht
ermitteln lassen, bleiben leer und werden von Hand ergänzt.

## Windows-Version

Wird automatisch per GitHub Actions gebaut (`.github/workflows/build-windows.yml`,
läuft auf einem echten Windows-Runner - PyInstaller kann nicht von macOS aus
für Windows cross-kompilieren) und bei jedem Release als
`Netzwerk-Scanner-Windows.zip` angehängt: <https://github.com/klopsnic-cyber/netzwerk-scanner/releases/latest>.
Entpacken, `Netzwerk-Scanner.exe` starten - kein Installer nötig.

Unterschiede zur Mac-Version: Der Update-Button installiert Updates nicht
automatisch (das Ersetzen der laufenden Datei ist auf Windows riskanter, da
Windows die Datei sperrt solange sie läuft) - er öffnet stattdessen die
Release-Seite zum manuellen Herunterladen.

Merkmale: modernes Oberflächen-Theme mit eigenem App-Icon und Gerätetyp-Symbolen,
aktive Erreichbarkeitsprüfung (nur Geräte, die zur Scan-Zeit antworten – kein
veralteter ARP-Cache, funktioniert auch netzübergreifend), Namensauflösung per
Reverse-DNS, mDNS/Bonjour und NetBIOS, sortierbare und filterbare Tabelle,
manuelle Nacharbeit-Felder direkt in der App editierbar, Doppelklick öffnet
die Web-Oberfläche eines Geräts, Sitzungswiederherstellung nach Neustart, und
die Excel-Vorlage ist fest eingebaut (keine externe Datei nötig).

## Was der Scanner automatisch füllt

| Spalte | Automatisch? | Quelle |
|---|---|---|
| IP-Adresse | ✅ | Ping-Sweep |
| Hersteller | ✅ | MAC-Adresse → IEEE-OUI-Datenbank (offline) |
| Gerätetyp | 🟡 geraten | offene Ports + Hostname + Hersteller |
| Netzwerkname | ✅ | Reverse-DNS / mDNS / NetBIOS |
| MAC-Adresse | ✅ | ARP-Tabelle (nur gleiches Subnetz) |
| Standort | 🟢 in der App editierbar | Rechtsklick → „Bearbeiten…" |
| User | 🟢 in der App editierbar | Rechtsklick → „Bearbeiten…" |
| Kennwort | ➖ leer / manuell (Excel) | aus Sicherheitsgründen nicht in der App editierbar |
| angebunden an | 🟢 in der App editierbar | Rechtsklick → „Bearbeiten…" |
| Windows Funktion | 🟡 geraten | erkannte Dienste (SQL, RDP, AD …) |
| Sonstiges | 🟡 | Liste offener Ports |
| Softwarestand | 🟡 geraten | Banner (Server-Version u.ä.) |
| eingerichtet von | 🟢 in der App editierbar | Rechtsklick → „Bearbeiten…" |

> Hinweis: MAC-Adresse und Hersteller sind nur für Geräte im selben
> IP-Subnetz verfügbar (technische Grenze von ARP).

> Hinweis: Das Kennwort wird bewusst nicht in der App gespeichert oder
> editierbar gemacht (keine Klartext-Passwörter in App/JSON) und muss wie
> bisher von Hand in der exportierten Excel-Datei ergänzt werden.

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

### Wichtig: Für die Weitergabe an ANDERE Macs

Damit die App auch auf anderen Macs läuft (Intel **und** Apple Silicon, auch
ältere macOS-Versionen), muss mit dem **offiziellen Python von python.org**
gebaut werden – nicht mit Homebrew-Python. Homebrew-Binaries sind nur für den
Bau-Mac gedacht und stürzen auf anderen Macs ab
(`libexpat: Symbol not found … built for macOS 26 which is newer than running OS`).

Einmalig einrichten:

1. Installer laden: <https://www.python.org/downloads/macos/> → aktuelle
   **Python 3.12** „macOS 64-bit universal2 installer" (z.B. 3.12.x) und installieren.
2. `./build.sh` erneut ausführen.

`build.sh` erkennt python.org-Python automatisch, baut dann **universal2**
(Intel + Apple Silicon) mit macOS-Mindestversion 11 und meldet:
`-> portabler Build (universal2, macOS 11+)`. Findet es nur Homebrew-Python,
warnt es und baut eine App, die nur auf dem Bau-Mac läuft.

Beim ersten Öffnen auf einem fremden Mac ggf. die Gatekeeper-Quarantäne lösen:

```bash
xattr -dr com.apple.quarantine /Applications/Netzwerk-Scanner.app
```

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
2. Optional Kundenname / Tomedo-Nummer / Datum eintragen; optional ein
   Passwort für die exportierte Excel-Datei (siehe unten).
3. **Scan starten** – Geräte erscheinen live in der Tabelle.
4. **In Excel exportieren** – erzeugt eine ausgefüllte Kopie der Vorlage.

### Exportierte Excel-Datei verschlüsseln (optional)

Wird im Feld „Passwort" ein Kennwort eingetragen, wird die exportierte
`.xlsx`-Datei damit verschlüsselt (ECMA-376 Agile/AES-256 – dasselbe Format
wie Excel „Datei → Informationen → Mit Kennwort verschlüsseln"). Die Datei
lässt sich dann ohne das Kennwort gar nicht erst öffnen. Bleibt das Feld
leer, wird ganz normal unverschlüsselt exportiert. Das Passwort wird nicht
in der Sitzung gespeichert (wie beim Geräte-Kennwortfeld, aus dem gleichen
Grund: keine Klartext-Passwörter in App/JSON).

### Tabelle bearbeiten (Rechtsklick)

Rechtsklick auf eine Zeile öffnet ein Kontextmenü:

- **Bearbeiten…** – Dialog für Standort, User, „angebunden an" und
  „eingerichtet von". Änderungen fließen direkt in den Excel-Export.
- **Ignorieren** – blendet die Zeile gedimmt aus und schließt das Gerät vom
  Excel-Export aus, z.B. für den scannenden Mac selbst oder fremde
  Nachbargeräte bei falsch gewähltem Netzbereich. Der Gerätezähler zeigt dann
  „X Geräte (Y ignoriert)". Über „Nicht mehr ignorieren" rückgängig zu machen.

### Filtern

Das Eingabefeld über der Tabelle filtert live nach IP, Hersteller, Gerätetyp,
Netzwerkname oder MAC-Adresse.

### Warnhinweise

Schlägt bei einem Gerät die Namensauflösung oder der Portscan mit einem
echten Fehler fehl (nicht bei normalem „nichts gefunden"), erscheint statt
des Geräte-Symbols ein ⚠ in der Tabelle; beim Hover über die Zeile steht eine
kurze Erklärung in der Statuszeile. Beim Hover über eine Zeile mit
Web-Oberfläche (offener Port 80/443/8080/8443) wird der Mauszeiger zu einer
Hand – Doppelklick öffnet die Web-Oberfläche im Browser.

### Update-Check

Beim Start prüft die App im Hintergrund die
[GitHub-Releases](https://github.com/klopsnic-cyber/netzwerk-scanner/releases)
dieses (öffentlichen) Repos; der Button oben rechts lässt sich auch jederzeit
manuell anklicken. Ist eine neuere Version verfügbar, zeigt der Button
„Update verfügbar: vX.Y.Z" – ein Klick fragt kurz nach, lädt dann die `.dmg`
herunter und ersetzt automatisch das laufende `.app`-Bundle; die App startet
danach neu. Schlägt das fehl (kein Netz, kein Schreibrecht z.B. bei
Nicht-Admin-Konten, o.ä.), bleibt die alte Version unangetastet lauffähig und
es wird alternativ die Release-Seite im Browser zum manuellen Download
angeboten. Kein Internet/GitHub nicht erreichbar beim stillen Start-Check →
der Check schlägt einfach still fehl, die App läuft normal weiter.

Neue Version veröffentlichen: `__version__` in `netzwerkscanner/__init__.py`
erhöhen, `./build.sh` neu bauen, dann:

```bash
gh release create vX.Y.Z Netzwerk-Scanner.dmg --title "vX.Y.Z" --notes "…"
```

### Sitzung wiederherstellen

Der letzte Scan (inkl. Kundendaten und aller bearbeiteten/ignorierten Felder)
wird beim Schließen der App automatisch gesichert
(`~/Library/Application Support/Netzwerk-Scanner/last_session.json`) und
beim nächsten Start zur Wiederherstellung angeboten. Läuft beim Schließen
noch ein Scan, wird dieser zuerst sauber abgebrochen.

## Projektstruktur

```
IP-Scanner/
├── app.py                     # Einstiegspunkt (GUI + --cli)
├── netzwerkscanner/
│   ├── scanner.py             # Ping-Sweep, ARP, Ports, Namen
│   ├── oui.py                 # Hersteller-Lookup (OUI)
│   ├── classify.py            # Gerätetyp-Heuristik
│   ├── exporter.py            # Excel-Ausgabe in die Vorlage
│   ├── update.py               # Update-Check gegen GitHub Releases
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
