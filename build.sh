#!/usr/bin/env bash
#
# Baut aus dem Python-Projekt eine macOS-App und eine .dmg.
# MUSS auf einem Mac laufen (macOS-Binaries lassen sich nur dort erzeugen).
#
# Aufruf:   ./build.sh
#
set -euo pipefail
cd "$(dirname "$0")"

APP_NAME="Netzwerk-Scanner"
DMG_NAME="Netzwerk-Scanner.dmg"
VENV=".venv"

echo "==> 1/5  Python-Umgebung vorbereiten"
if [ ! -d "$VENV" ]; then
  python3 -m venv "$VENV"
fi
# shellcheck disable=SC1091
source "$VENV/bin/activate"
pip install --upgrade pip >/dev/null
pip install -r requirements.txt

echo "==> 2/5  OUI-Herstellerdatenbank laden (für Offline-Betrieb)"
mkdir -p data
if [ ! -s data/oui.csv ]; then
  # Offizielle IEEE-Liste; bei Fehlschlag greift die eingebaute Fallback-Liste.
  if curl -fsSL --retry 3 -o data/oui.csv "https://standards-oui.ieee.org/oui/oui.csv"; then
    echo "    OUI-Datenbank geladen ($(wc -l < data/oui.csv) Zeilen)."
  else
    echo "    WARNUNG: OUI-Download fehlgeschlagen – Fallback-Liste wird genutzt."
    printf 'Registry,Assignment,Organization Name,Organization Address\n' > data/oui.csv
  fi
else
  echo "    data/oui.csv bereits vorhanden."
fi

echo "==> 3/5  App mit PyInstaller bauen"
rm -rf build dist
pyinstaller --noconfirm NetzwerkScanner.spec

echo "==> 4/5  .dmg erstellen"
rm -f "$DMG_NAME"
if command -v create-dmg >/dev/null 2>&1; then
  create-dmg \
    --volname "$APP_NAME" \
    --window-size 520 320 \
    --icon-size 100 \
    --icon "$APP_NAME.app" 130 150 \
    --app-drop-link 390 150 \
    "$DMG_NAME" "dist/$APP_NAME.app" || {
      echo "    create-dmg meldete einen Fehler – nutze hdiutil als Fallback."
      hdiutil create -volname "$APP_NAME" -srcfolder "dist/$APP_NAME.app" \
        -ov -format UDZO "$DMG_NAME"
    }
else
  echo "    'create-dmg' nicht installiert (brew install create-dmg für ein schöneres Fenster)."
  echo "    Nutze hdiutil."
  hdiutil create -volname "$APP_NAME" -srcfolder "dist/$APP_NAME.app" \
    -ov -format UDZO "$DMG_NAME"
fi

echo "==> 5/5  Fertig"
echo "    App:  dist/$APP_NAME.app"
echo "    DMG:  $DMG_NAME"
echo
echo "Hinweis: Beim ersten Start bittet macOS ggf. um Rechtsklick > Öffnen"
echo "(unsignierte App) und um Erlaubnis für 'Lokales Netzwerk'."
