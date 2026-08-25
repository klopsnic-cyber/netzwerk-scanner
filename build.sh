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

# 'cryptography' (für die Excel-Verschlüsselung) hat eine kompilierte
# Rust-Erweiterung - "pip install" liefert normal nur die Architektur DIESES
# Macs aus. Für einen portablen Build brauchen wir das universal2-Wheel
# (Intel + Apple Silicon in einer Datei), sonst crasht die App auf der
# jeweils anderen Architektur (gleiches Problem wie bei Python selbst,
# siehe Punkt 1 oben).
if [ "$PORTABLE" = "1" ]; then
  echo "    Erzwinge universal2-Wheel für 'cryptography' (Intel + Apple Silicon)…"
  PYVER=$("$PYBIN" -c 'import sys; print(f"{sys.version_info[0]}.{sys.version_info[1]}")')
  TMPWHL=$(mktemp -d)
  if pip download cryptography --no-deps --only-binary=:all: \
      --platform macosx_11_0_universal2 --python-version "$PYVER" --implementation cp \
      -d "$TMPWHL" >/dev/null 2>&1; then
    pip install --force-reinstall --no-deps "$TMPWHL"/cryptography-*.whl
  else
    echo "    WARNUNG: Kein universal2-Wheel für 'cryptography' gefunden -"
    echo "    Verschlüsselungsfunktion läuft dann nur auf $(uname -m)-Macs."
  fi
  rm -rf "$TMPWHL"

  # 'cffi' (transitive Abhängigkeit von cryptography, wird von dessen
  # Serialisierungs-Code tatsächlich gebraucht) hat KEIN universal2-Wheel auf
  # PyPI. Lösung: beide Einzel-Architektur-Wheels laden und die kompilierte
  # Erweiterung selbst per 'lipo' zusammenführen (Standardtechnik für genau
  # diesen Fall - so bauen z.B. auch python.org/Homebrew ihre universal2-Pakete).
  echo "    Erzwinge universal2 für 'cffi' (per lipo aus Einzel-Architektur-Wheels)…"
  CFFI_VER=$(python -c "import cffi; print(cffi.__version__)" 2>/dev/null || true)
  if [ -n "$CFFI_VER" ]; then
    TMPCFFI=$(mktemp -d)
    OK=1
    pip download "cffi==$CFFI_VER" --no-deps --only-binary=:all: \
      --platform macosx_11_0_arm64 --python-version "$PYVER" --implementation cp \
      -d "$TMPCFFI/arm64" >/dev/null 2>&1 || OK=0
    pip download "cffi==$CFFI_VER" --no-deps --only-binary=:all: \
      --platform macosx_11_0_x86_64 --python-version "$PYVER" --implementation cp \
      -d "$TMPCFFI/x86_64" >/dev/null 2>&1 || OK=0
    if [ "$OK" = "1" ]; then
      unzip -o -q "$TMPCFFI"/arm64/*.whl -d "$TMPCFFI/arm64/x"
      unzip -o -q "$TMPCFFI"/x86_64/*.whl -d "$TMPCFFI/x86_64/x"
      ARM_SO=$(find "$TMPCFFI/arm64/x" -name "_cffi_backend*.so" | head -1)
      X86_SO=$(find "$TMPCFFI/x86_64/x" -name "_cffi_backend*.so" | head -1)
      TARGET_SO=$(find "$VENV" -name "_cffi_backend*.so" | head -1)
      if [ -n "$ARM_SO" ] && [ -n "$X86_SO" ] && [ -n "$TARGET_SO" ]; then
        lipo -create "$ARM_SO" "$X86_SO" -output "$TARGET_SO"
        echo "    universal2 _cffi_backend erzeugt ($(lipo -archs "$TARGET_SO"))."
      else
        echo "    WARNUNG: _cffi_backend*.so nicht gefunden - Verschlüsselung läuft"
        echo "    dann nur auf $(uname -m)-Macs."
      fi
    else
      echo "    WARNUNG: cffi==$CFFI_VER nicht für beide Architekturen verfügbar -"
      echo "    Verschlüsselungsfunktion läuft dann nur auf $(uname -m)-Macs."
    fi
    rm -rf "$TMPCFFI"
  fi
fi

echo "==> 2/6  OUI-Herstellerliste aktualisieren (fest eingebettet)"
mkdir -p data
# Offizielle IEEE-Liste laden (nur um die eingebettete Liste zu aktualisieren).
if curl -fsSL --retry 3 -o data/oui.csv "https://standards-oui.ieee.org/oui/oui.csv"; then
  echo "    IEEE-Liste geladen ($(wc -l < data/oui.csv) Zeilen)."
  python assets/make_oui_data.py || echo "    (Einbettung übersprungen)"
else
  echo "    Kein Download möglich – vorhandene eingebettete Liste wird verwendet."
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
