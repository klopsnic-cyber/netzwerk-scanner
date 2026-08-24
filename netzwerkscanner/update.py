"""Update-Check gegen GitHub Releases (öffentliches Repo, kein Token nötig).

Bewusst simpel: kein Auto-Download/Auto-Replace der laufenden .app (riskant
bei ad-hoc-Signatur/Gatekeeper). Stattdessen wird bei einer neueren Version
die GitHub-Release-Seite im Browser geöffnet - der Nutzer lädt die .dmg wie
gewohnt (siehe CLAUDE.md Punkt 4: nur über die .dmg weitergeben/updaten).
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Optional, TypedDict

from . import __version__

REPO = "klopsnic-cyber/netzwerk-scanner"
API_URL = f"https://api.github.com/repos/{REPO}/releases/latest"


class UpdateInfo(TypedDict):
    version: str
    url: str
    notes: str


def _parse_version(tag: str) -> tuple:
    parts = tag.lstrip("vV").split(".")
    result = []
    for p in parts:
        try:
            result.append(int(p))
        except ValueError:
            break
    return tuple(result)


def check_for_update(timeout: float = 5.0) -> Optional[UpdateInfo]:
    """Fragt die neueste GitHub-Release ab. None bei Fehler oder kein Update.

    Netzwerkfehler (kein Internet, GitHub down, o.ä.) sind hier normal -
    kein Grund die App zu stören, daher wird jede Exception geschluckt.
    """
    req = urllib.request.Request(
        API_URL, headers={"Accept": "application/vnd.github+json",
                           "User-Agent": f"Netzwerk-Scanner/{__version__}"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.load(resp)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError):
        return None

    tag = data.get("tag_name", "")
    if _parse_version(tag) <= _parse_version(__version__):
        return None
    return UpdateInfo(version=tag.lstrip("vV"), url=data.get("html_url", ""),
                       notes=(data.get("body") or "").strip())
