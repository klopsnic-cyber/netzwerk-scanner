# CLAUDE.md — Projektgedächtnis: Netzwerk-Scanner

Diese Datei ist das Gedächtnis für Claude. Sie wird auf jedem Rechner
automatisch gelesen und enthält Zweck, Aufbau und die wichtigen Entscheidungen
des Projekts. Bitte bei größeren Änderungen aktuell halten.

## Was das Projekt ist
Ein macOS-IP-Scanner (Python + Tkinter) für die Praxis-/Tomedo-Netzwerkdoku.
Er durchsucht das lokale Netz, erkennt Geräte und füllt die Excel-Vorlage
`Netzwerkdoku-Vorlage.xlsx` automatisch. Ausgeliefert als `.app`/`.dmg`.

- GitHub: https://github.com/klopsnic-cyber/netzwerk-scanner (öffentlich, seit 2026-08-24 –
  Repo wurde vor Öffentlich-Schalten auf Secrets/Kundendaten geprüft, war sauber)
- Nutzer: Nic (klopsnic@googlemail.com), spricht Deutsch, wünscht knappe Antworten.
- Zielrechner sind Praxis-Macs (Apple Silicon + Intel möglich, teils ältere macOS).

## Projektstruktur
```
app.py                     Einstiegspunkt (GUI; --cli für Terminal-Scan)
netzwerkscanner/
  scanner.py               Erreichbarkeit (Ping+TCP), ARP, Ports, Namen (DNS/mDNS/NetBIOS)
  oui.py                   Hersteller-Lookup; lädt primär die eingebettete Liste
  oui_data.py              EINGEBETTETE IEEE-OUI-Liste (gzip+base64, ~39.7k Einträge)
  classify.py              Gerätetyp-/OS-/Windows-Funktion-Heuristik
  exporter.py              Schreibt in die Excel-Vorlage
  update.py                Update-Check gegen GitHub Releases (öffentliches Repo, kein Token)
  template_data.py         EINGEBETTETE Excel-Vorlage (base64)
  gui.py                   Tkinter-Oberfläche, modernes Theme (clam), Gerätesymbole
assets/
  make_icon.py             Erzeugt App-Icon (Pillow) -> .iconset
  make_oui_data.py         Erzeugt oui_data.py aus data/oui.csv
build.sh                   Baut .app + .dmg (nur auf Mac)
NetzwerkScanner.spec       PyInstaller-Konfiguration
```

## Bauen & Ausführen
- Direkt testen (Dev): `.venv/bin/python app.py`  (oder `python3 app.py`)
- Bauen: `./build.sh`  → `dist/Netzwerk-Scanner.app` + `Netzwerk-Scanner.dmg`
- Terminal-Scan: `python3 app.py --cli 192.168.1.0/24`

## WICHTIGE ENTSCHEIDUNGEN / LEKTIONEN (nicht rückgängig machen)

1. **Nur mit python.org-Python bauen, NICHT mit Homebrew-Python.**
   Homebrew-Python (z.B. 3.14) ist an die aktuelle macOS-Version gebunden und
   stürzt auf älteren Macs ab: `libexpat … Symbol not found … built for macOS 26`.
   python.org-Python 3.12 (universal2) ist portabel (Intel+ARM, macOS 11+).
   `build.sh` bevorzugt automatisch `/Library/Frameworks/Python.framework/...`
   und setzt dann `APP_TARGET_ARCH=universal2` + `MACOSX_DEPLOYMENT_TARGET=11.0`.
   Erfolgsmeldung im Build: `-> portabler Build (universal2, macOS 11+)`.

2. **Tk 8.6 nötig.** Apples System-Python (3.9, CommandLineTools) nutzt das
   defekte System-Tk 8.5 → leeres Fenster. `build.sh` prüft `tkinter.TkVersion>=8.6`.

3. **Ad-hoc-Signatur OHNE `--deep`.** `codesign --deep` scheitert an
   `_tcl_data/opt0.4`. `build.sh` macht `codesign --force --sign - App.app`
   (PyInstaller signiert die inneren Binärdateien bereits). Ohne gültige Signatur
   crasht die App auf anderen Apple-Silicon-Macs mit `_struct is NULL`.

4. **Weitergabe nur über die `.dmg`.** Die nackte `.app` per AirDrop/ZIP
   zerstört Signatur und Ausführ-Rechte. DMG bewahrt beides.
   Auf dem Zielrechner: DMG → App nach „Programme" → Rechtsklick → Öffnen.
   NICHT chmod/xattr/codesign am Zielrechner ausführen.

5. **Hersteller/OUI ist eingebettet** (`oui_data.py`), damit es offline und in
   jeder weitergegebenen App funktioniert. `build.sh` lädt die aktuelle IEEE-Liste
   und regeneriert `oui_data.py` per `assets/make_oui_data.py`. `data/oui.csv`
   wird NICHT mehr ins App-Bundle gepackt (steckt im Code).

6. **Excel-Vorlage ist eingebettet** (`template_data.py`, base64). Kein externer
   Dateizwang. In der GUI wählbar, Standard = „eingebaut".

7. **Scanner zeigt nur JETZT erreichbare Geräte** (aktiv: Ping ODER offener/
   abgelehnter TCP-Port). KEINE veralteten ARP-Cache-Einträge als „Geräte".
   Funktioniert auch subnetzübergreifend. ARP dient nur der MAC-/Hersteller-
   Zuordnung (nur im selben Subnetz verfügbar). Namen: Reverse-DNS → mDNS/Bonjour
   → NetBIOS.

8. **Excel-Spalten (Zeile 5 Kopf, Daten ab Zeile 6):** IP, Hersteller, Gerätetyp,
   Netzwerkname, MAC automatisch; Windows-Funktion/Sonstiges(offene Ports) geraten;
   **Softwarestand bleibt LEER** (manuell, auf Wunsch des Nutzers); Standort, User,
   Kennwort, „angebunden an", „eingerichtet von" bleiben leer.

9. **macOS „Lokales Netzwerk"-Berechtigung** (Sequoia+): App fragt beim ersten
   Scan; muss erlaubt werden, sonst keine Geräte. Info.plist enthält
   `NSLocalNetworkUsageDescription`. Root/sudo ist NICHT nötig (Ping + ARP-Cache).

10. **Update-Check statt Auto-Update.** `update.py` fragt beim Start die
    GitHub-Releases-API ab (öffentliches Repo, kein Token nötig) und vergleicht
    Tag gegen `__version__`. Bei neuerer Version nur ein Hinweis-Button, der
    die Release-Seite im Browser öffnet – KEIN automatisches Herunterladen/
    Ersetzen der laufenden .app (Risiko bei ad-hoc-Signatur/Gatekeeper, siehe
    Punkt 3+4). Release veröffentlichen: Version in `__init__.py` erhöhen,
    `./build.sh`, dann `gh release create vX.Y.Z Netzwerk-Scanner.dmg`.

## Eingebettete Daten neu erzeugen
- OUI: `python3 assets/make_oui_data.py` (nach Aktualisieren von `data/oui.csv`)
- Vorlage: aus data/Netzwerkdoku-Vorlage.xlsx per base64 nach template_data.py
- Icon: `python3 assets/make_icon.py assets/` + `iconutil -c icns …`

## Git-Workflow
```
git add -A
git commit -m "kurze Beschreibung"
git push
```
Repo-Remote `origin` zeigt auf klopsnic-cyber/netzwerk-scanner (main).
