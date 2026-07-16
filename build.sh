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

echo "==> 1/6  Python-Umgebung vorbereiten"

# Ein Python mit modernem Tk 8.6 finden. Apples System-Python (3.9 unter
# /Library/Developer/CommandLineTools) nutzt das defekte Tk 8.5 und erzeugt
# leere Fenster -> deshalb bevorzugen wir Homebrew-Python.
pick_python() {
  local cand ver
  for cand in \
      /opt/homebrew/bin/python3.13 /opt/homebrew/bin/python3.12 \
      /opt/homebrew/bin/python3.11 /opt/homebrew/bin/python3 \
      /usr/local/bin/python3 \
      python3.13 python3.12 python3.11 python3; do
    command -v "$cand" >/dev/null 2>&1 || continue
    ver=$("$cand" -c 'import tkinter; print(tkinter.TkVersion)' 2>/dev/null) || continue
    # Tk >= 8.6 akzeptieren (8.5 ist Apples defektes System-Tk)
    if [ "$(printf '%s\n8.6\n' "$ver" | sort -V | head -1)" = "8.6" ]; then
      echo "$cand"; return 0
    fi
  done
  return 1
}

PYBIN="$(pick_python || true)"
if [ -z "${PYBIN:-}" ]; then
  echo "    FEHLER: Kein Python mit funktionierendem Tk 8.6 gefunden."
  echo "    Bitte einmalig ausführen:  brew install python-tk"
  echo "    (installiert Homebrew-Python samt Tk 8.6) und danach ./build.sh erneut."
  exit 1
fi
TKVER=$("$PYBIN" -c 'import tkinter; print(tkinter.TkVersion)')
echo "    Python: $PYBIN  (Tk $TKVER)"

# Falls eine alte Umgebung mit dem falschen (System-)Python existiert: neu bauen.
if [ -d "$VENV" ] && ! "$VENV/bin/python" -c 'import tkinter; assert tkinter.TkVersion>=8.6' >/dev/null 2>&1; then
  echo "    Alte Umgebung nutzt defektes Tk -> wird neu erstellt."
  rm -rf "$VENV"
fi
if [ ! -d "$VENV" ]; then
  "$PYBIN" -m venv "$VENV"
fi
# shellcheck disable=SC1091
source "$VENV/bin/activate"
pip install --upgrade pip >/dev/null
pip install -r requirements.txt

echo "==> 2/6  OUI-Herstellerdatenbank laden (für Offline-Betrieb)"
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

echo "==> 3/6  App-Icon erzeugen"
pip install pillow >/dev/null 2>&1 || true
python assets/make_icon.py assets/ || echo "    (Icon übersprungen)"
if [ -d assets/Netzwerk-Scanner.iconset ]; then
  iconutil -c icns assets/Netzwerk-Scanner.iconset -o assets/Netzwerk-Scanner.icns \
    && echo "    assets/Netzwerk-Scanner.icns erstellt." \
    || echo "    WARNUNG: iconutil fehlgeschlagen – App wird ohne eigenes Icon gebaut."
fi

echo "==> 4/6  App mit PyInstaller bauen"
rm -rf build dist
pyinstaller --noconfirm NetzwerkScanner.spec

echo "==> 5/6  .dmg erstellen"
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

echo "==> 6/6  Fertig"
echo "    App:  dist/$APP_NAME.app"
echo "    DMG:  $DMG_NAME"
echo
echo "Hinweis: Beim ersten Start bittet macOS ggf. um Rechtsklick > Öffnen"
echo "(unsignierte App) und um Erlaubnis für 'Lokales Netzwerk'."
