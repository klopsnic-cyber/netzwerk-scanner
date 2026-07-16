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

# Python für den Build wählen. Wichtig für die WEITERGABE an andere Macs:
#   - python.org-Python ist "universal2" (Intel + Apple Silicon) und für eine
#     niedrige macOS-Mindestversion gebaut -> läuft auch auf älteren Macs.
#   - Homebrew-Python ist NUR für dieses macOS/diese Architektur gebaut und
#     stürzt auf anderen Macs ab (z.B. "libexpat: Symbol not found").
# Deshalb bevorzugen wir python.org-Python; Homebrew nur als Notlösung.
PYBIN=""
PORTABLE=0
have_tk86() {
  local ver
  ver=$("$1" -c 'import tkinter; print(tkinter.TkVersion)' 2>/dev/null) || return 1
  [ "$(printf '%s\n8.6\n' "$ver" | sort -V | head -1)" = "8.6" ]
}
# 1) python.org (portabel, universal2) – bevorzugt
for cand in \
    /Library/Frameworks/Python.framework/Versions/3.13/bin/python3 \
    /Library/Frameworks/Python.framework/Versions/3.12/bin/python3 \
    /Library/Frameworks/Python.framework/Versions/3.11/bin/python3 \
    /Library/Frameworks/Python.framework/Versions/3.10/bin/python3; do
  if command -v "$cand" >/dev/null 2>&1 && have_tk86 "$cand"; then
    PYBIN="$cand"; PORTABLE=1; break
  fi
done
# 2) Notlösung: Homebrew/andere (App läuft dann NUR auf diesem Mac-Typ)
if [ -z "$PYBIN" ]; then
  for cand in \
      /opt/homebrew/bin/python3.13 /opt/homebrew/bin/python3.12 \
      /opt/homebrew/bin/python3.11 /opt/homebrew/bin/python3 \
      /usr/local/bin/python3 python3.13 python3.12 python3.11 python3; do
    if command -v "$cand" >/dev/null 2>&1 && have_tk86 "$cand"; then
      PYBIN="$cand"; break
    fi
  done
fi
if [ -z "$PYBIN" ]; then
  echo "    FEHLER: Kein geeignetes Python mit Tk 8.6 gefunden."
  echo "    Empfohlen für portable Apps: python.org-Installer laden (siehe README)."
  exit 1
fi
TKVER=$("$PYBIN" -c 'import tkinter; print(tkinter.TkVersion)')
echo "    Python: $PYBIN  (Tk $TKVER)"
if [ "$PORTABLE" = "1" ]; then
  export APP_TARGET_ARCH="universal2"
  export MACOSX_DEPLOYMENT_TARGET="11.0"
  echo "    -> portabler Build (universal2, macOS 11+): läuft auf Intel & Apple Silicon."
else
  echo "    ================================================================"
  echo "    WARNUNG: Kein python.org-Python gefunden – es wird Homebrew/System"
  echo "    genutzt. Die App läuft dann NUR auf einem Mac mit gleicher"
  echo "    Architektur UND gleicher (oder neuerer) macOS-Version wie hier."
  echo "    Für eine an andere Macs verteilbare App bitte python.org-Python"
  echo "    installieren (Anleitung in der README) und ./build.sh erneut starten."
  echo "    ================================================================"
fi

# Alte Umgebung neu bauen, wenn sie auf ein anderes Basis-Python zeigt
# (z.B. Wechsel Homebrew -> python.org) oder defektes Tk nutzt.
TARGET_BASE=$("$PYBIN" -c 'import sys; print(sys.base_prefix)')
if [ -d "$VENV" ]; then
  VENV_BASE=$("$VENV/bin/python" -c 'import sys; print(sys.base_prefix)' 2>/dev/null || echo "x")
  if [ "$VENV_BASE" != "$TARGET_BASE" ] || \
     ! "$VENV/bin/python" -c 'import tkinter; assert tkinter.TkVersion>=8.6' >/dev/null 2>&1; then
    echo "    Umgebung passt nicht zum gewählten Python -> wird neu erstellt."
    rm -rf "$VENV"
  fi
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

# App-Bundle neu versiegeln (OHNE --deep: das scheitert an Tcl-Datenordnern).
# PyInstaller hat die inneren Binärdateien bereits ad-hoc signiert; hier wird
# nur die äußere Bundle-Signatur konsistent gemacht. Auf Apple Silicon MUSS
# die Signatur gültig sein, sonst laden Bausteine wie _struct nicht.
echo "    App ad-hoc signieren …"
codesign --force --sign - "dist/$APP_NAME.app" \
  && echo "    Signatur ok." \
  || echo "    WARNUNG: Signieren fehlgeschlagen (PyInstaller-Signatur bleibt)."
codesign --verify --verbose=1 "dist/$APP_NAME.app" 2>&1 | sed 's/^/    /' || true

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
