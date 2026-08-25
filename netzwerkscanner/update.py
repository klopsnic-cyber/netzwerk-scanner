"""Update-Check + Installation gegen GitHub Releases (öffentliches Repo,
kein Token nötig).

install_update() lädt die .dmg herunter und ersetzt das laufende .app-Bundle
an Ort und Stelle (egal ob /Applications oder woanders gestartet). Jeder
Fehlerfall (kein Netz, keine Schreibrechte, kaputte .dmg, kein .app im Bundle
- z.B. Dev-Modus) wirft eine Exception UNBEVOR etwas am Zielbundle verändert
wird bzw. mit sauberem Rollback danach; der Aufrufer fängt das ab und bietet
als Rückfall den manuellen Download über die Release-Seite an.
"""

from __future__ import annotations

import json
import os
import shutil
import ssl
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from typing import Callable, Optional, TypedDict

from . import __version__

REPO = "klopsnic-cyber/netzwerk-scanner"
API_URL = f"https://api.github.com/repos/{REPO}/releases/latest"

ProgressCb = Optional[Callable[[float, str], None]]

# Die App wird mit python.org-Python gebaut (siehe CLAUDE.md Punkt 1, für
# Intel+ARM-Portabilität nötig). Dieses Python bringt anders als Apples
# System-Python KEIN eigenes Root-Zertifikatsbündel mit - ohne den manuellen
# Schritt "Install Certificates.command" schlägt JEDE HTTPS-Anfrage mit
# CERTIFICATE_VERIFY_FAILED fehl (reproduziert). macOS liefert aber immer ein
# System-Bündel unter /etc/ssl/cert.pem mit; das nutzen wir explizit statt
# uns auf Pythons (kaputten) Default zu verlassen.
def _ssl_context() -> ssl.SSLContext:
    cafile = "/etc/ssl/cert.pem"
    if os.path.exists(cafile):
        return ssl.create_default_context(cafile=cafile)
    return ssl.create_default_context()


class UpdateInfo(TypedDict):
    version: str
    url: str
    notes: str
    asset_url: str  # Download-Link der .dmg, "" wenn keine im Release


def _parse_version(tag: str) -> tuple:
    parts = tag.lstrip("vV").split(".")
    result = []
    for p in parts:
        try:
            result.append(int(p))
        except ValueError:
            break
    return tuple(result)


def _fetch_latest_release(timeout: float) -> Optional[UpdateInfo]:
    """Fragt die neueste GitHub-Release ab. None bei "kein Update" (Tag <=
    eigene Version). Wirft bei Netzwerk-/API-Fehlern (kein Internet, GitHub
    nicht erreichbar, Rate-Limit, kaputte Antwort) - der Aufrufer entscheidet,
    ob das still ignoriert oder dem Nutzer angezeigt wird."""
    req = urllib.request.Request(
        API_URL, headers={"Accept": "application/vnd.github+json",
                           "User-Agent": f"Netzwerk-Scanner/{__version__}"})
    with urllib.request.urlopen(req, timeout=timeout, context=_ssl_context()) as resp:
        data = json.load(resp)

    tag = data.get("tag_name", "")
    if _parse_version(tag) <= _parse_version(__version__):
        return None

    asset_url = ""
    for asset in data.get("assets", []):
        if asset.get("name", "").endswith(".dmg"):
            asset_url = asset.get("browser_download_url", "")
            break

    return UpdateInfo(version=tag.lstrip("vV"), url=data.get("html_url", ""),
                       notes=(data.get("body") or "").strip(), asset_url=asset_url)


def check_for_update(timeout: float = 5.0) -> Optional[UpdateInfo]:
    """Fragt die neueste GitHub-Release ab. None bei Fehler ODER kein Update -
    für den stillen Check beim App-Start (ein Netzwerkfehler ist dort normal,
    kein Grund die App zu stören). Für den manuellen "Jetzt prüfen"-Klick
    stattdessen check_for_update_or_raise() nutzen, damit ein echter
    Fehlschlag nicht fälschlich als "kein Update" erscheint."""
    try:
        return _fetch_latest_release(timeout)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError):
        return None


def check_for_update_or_raise(timeout: float = 5.0) -> Optional[UpdateInfo]:
    """Wie check_for_update(), wirft aber bei Netzwerk-/API-Fehlern statt
    still None zu liefern."""
    return _fetch_latest_release(timeout)


def current_app_bundle() -> str:
    """Pfad zum .app-Bundle der laufenden Instanz, "" wenn nicht als gebaute
    .app gestartet (z.B. Dev-Modus über 'python3 app.py')."""
    if not getattr(sys, "frozen", False):
        return ""
    marker = ".app/Contents/MacOS/"
    idx = sys.executable.find(marker)
    if idx == -1:
        return ""
    return sys.executable[:idx + 4]  # bis inkl. ".app"


def install_update(info: UpdateInfo, progress: ProgressCb = None) -> str:
    """Lädt die .dmg herunter und ersetzt das laufende .app-Bundle.

    Gibt den (neuen) Bundle-Pfad zum Neustart zurück. Wirft bei JEDEM Fehler
    eine Exception - der Aufrufer soll das abfangen und als Rückfall die
    Release-Seite im Browser anbieten.
    """
    target = current_app_bundle()
    if not target:
        raise RuntimeError("Kein installiertes .app-Bundle gefunden (Dev-Modus?)")
    if not info["asset_url"]:
        raise RuntimeError("Kein .dmg-Anhang im Release gefunden")
    if not os.access(os.path.dirname(target), os.W_OK):
        raise PermissionError(f"Keine Schreibrechte für {os.path.dirname(target)}")

    def report(frac, msg):
        if progress:
            progress(frac, msg)

    # --- Herunterladen ------------------------------------------------
    report(0.0, "Lade Update herunter …")
    tmp_dmg = os.path.join(tempfile.gettempdir(), "netzwerk-scanner-update.dmg")
    req = urllib.request.Request(
        info["asset_url"],
        headers={"User-Agent": f"Netzwerk-Scanner/{__version__}",
                 "Accept": "application/octet-stream"})
    with urllib.request.urlopen(req, timeout=30, context=_ssl_context()) as resp, open(tmp_dmg, "wb") as f:
        total = int(resp.headers.get("Content-Length", 0)) or None
        done = 0
        last_reported = -1.0
        while True:
            chunk = resp.read(65536)
            if not chunk:
                break
            f.write(chunk)
            done += len(chunk)
            if total:
                frac = done / total
                if frac - last_reported >= 0.02 or done == total:
                    report(0.7 * frac, f"Lade Update herunter … {done // 1024}/{total // 1024} KB")
                    last_reported = frac

    try:
        # --- .dmg mounten, .app finden ---------------------------------
        report(0.7, "Bereite Installation vor …")
        mount_point = tempfile.mkdtemp(prefix="netzwerk-scanner-mount-")
        try:
            subprocess.run(["hdiutil", "attach", tmp_dmg, "-nobrowse", "-quiet",
                            "-mountpoint", mount_point], check=True, timeout=60)
            try:
                apps = [n for n in os.listdir(mount_point) if n.endswith(".app")]
                if not apps:
                    raise RuntimeError("Keine .app in der heruntergeladenen .dmg gefunden")
                source_app = os.path.join(mount_point, apps[0])

                # --- Kopieren in ein Staging-Verzeichnis neben dem Ziel -
                report(0.8, "Installiere …")
                staging = target + ".update"
                if os.path.exists(staging):
                    shutil.rmtree(staging)
                subprocess.run(["ditto", source_app, staging], check=True, timeout=120)
            finally:
                subprocess.run(["hdiutil", "detach", mount_point, "-quiet"],
                               timeout=30, check=False)
        finally:
            shutil.rmtree(mount_point, ignore_errors=True)

        # --- Sicherer Austausch: alt beiseite, neu rein, bei Fehler zurück
        report(0.95, "Ersetze Anwendung …")
        backup = target + ".old"
        if os.path.exists(backup):
            shutil.rmtree(backup)
        os.rename(target, backup)
        try:
            os.rename(staging, target)
        except Exception:
            os.rename(backup, target)  # Rollback: alte Version bleibt lauffähig
            raise
        shutil.rmtree(backup, ignore_errors=True)
    finally:
        try:
            os.remove(tmp_dmg)
        except OSError:
            pass

    report(1.0, "Fertig.")
    return target
