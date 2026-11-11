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
# Alles exakt gepinnt (requirements*.txt) -> reproduzierbare Builds.
pip install pip==26.3 >/dev/null
pip install -r requirements.txt -r requirements-build.txt

# 'cryptography' (für die Excel-Verschlüsselung) hat eine kompilierte
# Rust-Erweiterung - "pip install" liefert normal nur die Architektur DIESES
# Macs aus. Für einen portablen Build brauchen wir das universal2-Wheel
# (Intel + Apple Silicon in einer Datei), sonst crasht die App auf der
# jeweils anderen Architektur (gleiches Problem wie bei Python selbst,
# siehe Punkt 1 oben).
if [ "$PORTABLE" = "1" ]; then
  echo "    Erzwinge universal2-Wheel für 'cryptography' (Intel + Apple Silicon)…"
  PYVER=$("$PYBIN" -c 'import sys; print(f"{sys.version_info[0]}.{sys.version_info[1]}")')
  CRYPTO_VER=$(python -c "import importlib.metadata as m; print(m.version('cryptography'))")
  TMPWHL=$(mktemp -d)
  if pip download "cryptography==$CRYPTO_VER" --no-deps --only-binary=:all: \
      --platform macosx_11_0_universal2 --python-version "$PYVER" --implementation cp \
      -d "$TMPWHL" >/dev/null 2>&1; then
    pip install --force-reinstall --no-deps "$TMPWHL"/cryptography-*.whl
  else
    echo "    FEHLER: Kein universal2-Wheel für cryptography==$CRYPTO_VER gefunden -" >&2
    echo "    die App liefe nur auf $(uname -m)-Macs. Abbruch." >&2
    exit 1
  fi
  rm -rf "$TMPWHL"

  # 'cffi' (transitive Abhängigkeit von cryptography, wird von dessen
  # Serialisierungs-Code tatsächlich gebraucht) hat KEIN universal2-Wheel auf
  # PyPI. Lösung: beide Einzel-Architektur-Wheels laden und die kompilierte
  # Erweiterung selbst per 'lipo' zusammenführen (Standardtechnik für genau
  # diesen Fall - so bauen z.B. auch python.org/Homebrew ihre universal2-Pakete).
  echo "    Erzwinge universal2 für 'cffi' (per lipo aus Einzel-Architektur-Wheels)…"
  CFFI_VER=$(python -c "import cffi; print(cffi.__version__)" 2>/dev/null || true)
  [ -n "$CFFI_VER" ] || { echo "    FEHLER: cffi nicht installiert. Abbruch." >&2; exit 1; }
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
      echo "    FEHLER: _cffi_backend*.so nicht gefunden - lipo-Merge unmöglich. Abbruch." >&2
      exit 1
    fi
  else
    echo "    FEHLER: cffi==$CFFI_VER nicht für beide Architekturen verfügbar. Abbruch." >&2
    exit 1
  fi
  rm -rf "$TMPCFFI"
fi

echo "==> 2/6  OUI-Herstellerliste aktualisieren (fest eingebettet)"
mkdir -p data
# Offizielle IEEE-Listen (MA-L, MA-M, MA-S) laden. Erst in eine Temp-Datei,
# streng prüfen (HTTP ok, CSV-Kopfzeile, Mindestzeilen), dann ersetzen.
# IEEE lehnt automatische Abrufe teils ab (liefert HTML) - dann bleibt die
# vorhandene Datei in data/; der Build bricht deshalb NICHT ab.
# Bewusst KEIN gefälschter User-Agent/Referer.
fetch_ieee() {  # url ziel mindestzeilen
  local tmp lines
  tmp=$(mktemp)
  if curl -fsSL --retry 3 -o "$tmp" "$1" \
     && head -1 "$tmp" | grep -q '^Registry,Assignment,' \
     && lines=$(wc -l < "$tmp") && [ "$lines" -ge "$3" ]; then
    mv "$tmp" "$2" && chmod 644 "$2"
    echo "    $2 aktualisiert ($((lines)) Zeilen)."
  else
    rm -f "$tmp"
    if [ -f "$2" ]; then
      echo "    HINWEIS: IEEE-Download abgelehnt/ungültig – vorhandene $2 vom $(stat -f %Sm -t %d.%m.%Y "$2") wird genutzt."
    else
      echo "    HINWEIS: IEEE-Download abgelehnt/ungültig und keine $2 vorhanden."
    fi
  fi
}
fetch_ieee "https://standards-oui.ieee.org/oui/oui.csv"     data/oui.csv   30000
fetch_ieee "https://standards-oui.ieee.org/oui28/mam.csv"   data/mam.csv   3000
fetch_ieee "https://standards-oui.ieee.org/oui36/oui36.csv" data/oui36.csv 4000
if [ -f data/oui.csv ] && [ -f data/mam.csv ] && [ -f data/oui36.csv ]; then
  python assets/make_oui_data.py data/oui.csv data/mam.csv data/oui36.csv \
    || echo "    (Einbettung übersprungen – vorhandene oui_data.py bleibt)"
else
  echo "    Nicht alle IEEE-Dateien da – vorhandene eingebettete Liste wird verwendet."
fi

echo "==> 3/6  App-Icon erzeugen"
python assets/make_icon.py assets/ || echo "    (Icon übersprungen)"
if [ -d assets/Netzwerk-Scanner.iconset ]; then
  iconutil -c icns assets/Netzwerk-Scanner.iconset -o assets/Netzwerk-Scanner.icns \
    && echo "    assets/Netzwerk-Scanner.icns erstellt." \
    || echo "    WARNUNG: iconutil fehlgeschlagen – App wird ohne eigenes Icon gebaut."
fi

echo "==> 4/6  Selbsttest + App mit PyInstaller bauen"
python tests/selbsttest.py || { echo "    FEHLER: Selbsttest rot – Build abgebrochen." >&2; exit 1; }
rm -rf build dist
pyinstaller --noconfirm NetzwerkScanner.spec

# Portabler Build: JEDE Mach-O-Datei im Bundle muss arm64 UND x86_64 enthalten,
# sonst crasht die App auf der jeweils anderen Mac-Architektur.
if [ "$PORTABLE" = "1" ]; then
  echo "    Prüfe Architekturen aller Mach-O-Dateien …"
  BAD=0; N=0
  while IFS= read -r f; do
    N=$((N + 1))
    archs=" $(lipo -archs "$f" 2>/dev/null) "
    case "$archs" in *" arm64 "*) ;; *) echo "    FEHLT arm64:  $f" >&2; BAD=1;; esac
    case "$archs" in *" x86_64 "*) ;; *) echo "    FEHLT x86_64: $f" >&2; BAD=1;; esac
  done < <(find "dist/$APP_NAME.app" -type f -print0 | xargs -0 file --no-pad -F '|' \
             | grep '|.*Mach-O' | cut -d'|' -f1 | grep -v ' (for architecture ' | sort -u)
  [ "$N" -gt 0 ] || { echo "    FEHLER: keine Mach-O-Dateien gefunden?" >&2; exit 1; }
  [ "$BAD" = "0" ] || { echo "    FEHLER: Bundle nicht universal2 – Abbruch." >&2; exit 1; }
  echo "    $N Mach-O-Dateien, alle arm64 + x86_64."
fi

# App-Bundle neu versiegeln (OHNE --deep: das scheitert an Tcl-Datenordnern).
# PyInstaller hat die inneren Binärdateien bereits ad-hoc signiert; hier wird
# nur die äußere Bundle-Signatur konsistent gemacht. Auf Apple Silicon MUSS
# die Signatur gültig sein, sonst laden Bausteine wie _struct nicht.
echo "    App ad-hoc signieren …"
# Ohne gültige Signatur crasht die App auf Apple Silicon (Punkt 3) und das Auto-Update lehnt sie ab
# -> lieber hier abbrechen als ein kaputtes Release ausliefern.
codesign --force --sign - "dist/$APP_NAME.app" \
  || { echo "    FEHLER: Signieren fehlgeschlagen." >&2; exit 1; }
codesign --verify --verbose=1 "dist/$APP_NAME.app" \
  || { echo "    FEHLER: Signatur ungültig." >&2; exit 1; }
echo "    Signatur ok."

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
