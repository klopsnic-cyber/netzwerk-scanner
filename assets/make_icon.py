#!/usr/bin/env python3
"""
Erzeugt das App-Icon (Radar-/Netzwerk-Motiv) als macOS-.iconset.

Aufruf:  python3 assets/make_icon.py [ZIELVERZEICHNIS]
Ergebnis: <Ziel>/Netzwerk-Scanner.iconset/  (+ preview.png)
build.sh macht daraus mit 'iconutil' die Netzwerk-Scanner.icns.

Benötigt Pillow (nur zum Bauen). Ohne Pillow bricht das Skript sauber ab,
build.sh baut dann ohne eigenes Icon weiter.
"""
from __future__ import annotations

import math
import os
import sys

try:
    from PIL import Image, ImageDraw
except Exception:
    print("Pillow nicht verfügbar – überspringe Icon-Erzeugung.")
    sys.exit(0)

# Farbpalette (modernes Blau/Teal)
BG_TOP = (36, 130, 249)      # helles Blau
BG_BOT = (23, 78, 190)       # dunkleres Blau
RING = (255, 255, 255)
NODE = (120, 230, 200)       # Teal-Grün
NODE_HI = (255, 214, 92)     # Akzent-Gelb (aktives Gerät)

SS = 4  # Supersampling für glatte Kanten


def _vgradient(size, top, bot):
    img = Image.new("RGB", (1, size), 0)
    for y in range(size):
        t = y / max(size - 1, 1)
        img.putpixel((0, y), tuple(int(top[i] + (bot[i] - top[i]) * t) for i in range(3)))
    return img.resize((size, size))


def _rounded_mask(size, radius):
    m = Image.new("L", (size, size), 0)
    d = ImageDraw.Draw(m)
    d.rounded_rectangle([0, 0, size - 1, size - 1], radius=radius, fill=255)
    return m


def render(px: int) -> Image.Image:
    s = px * SS
    # Hintergrund mit abgerundeter Maske (macOS-Squircle-Näherung)
    bg = _vgradient(s, BG_TOP, BG_BOT).convert("RGBA")
    mask = _rounded_mask(s, int(s * 0.225))
    icon = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    icon.paste(bg, (0, 0), mask)

    d = ImageDraw.Draw(icon)
    cx, cy = s * 0.5, s * 0.54
    maxr = s * 0.34

    # Radar-Ringe
    for i in range(1, 5):
        r = maxr * i / 4
        w = max(1, int(s * 0.006))
        alpha = 90 + i * 15
        d.ellipse([cx - r, cy - r, cx + r, cy + r], outline=RING + (alpha,), width=w)

    # Radar-Sweep (weicher Keil)
    sweep = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    sd = ImageDraw.Draw(sweep)
    start, end = -60, -12
    sd.pieslice([cx - maxr, cy - maxr, cx + maxr, cy + maxr], start, end,
                fill=RING + (60,))
    icon = Image.alpha_composite(icon, sweep)
    d = ImageDraw.Draw(icon)

    # Verbindungslinien + Knoten (Netzwerk)
    nodes = [
        (cx + maxr * 0.62, cy - maxr * 0.30, NODE_HI, 0.055),
        (cx - maxr * 0.55, cy - maxr * 0.10, NODE, 0.045),
        (cx + maxr * 0.10, cy + maxr * 0.66, NODE, 0.045),
        (cx - maxr * 0.20, cy + maxr * 0.20, NODE, 0.040),
        (cx + maxr * 0.36, cy + maxr * 0.30, NODE, 0.040),
    ]
    for nx, ny, col, _ in nodes:
        d.line([cx, cy, nx, ny], fill=RING + (70,), width=max(1, int(s * 0.004)))
    # Mittelpunkt
    cr = s * 0.028
    d.ellipse([cx - cr, cy - cr, cx + cr, cy + cr], fill=RING + (235,))
    # Knoten
    for nx, ny, col, rr in nodes:
        r = s * rr
        d.ellipse([nx - r, ny - r, nx + r, ny + r], fill=col + (255,))
        d.ellipse([nx - r, ny - r, nx + r, ny + r], outline=(255, 255, 255, 180),
                  width=max(1, int(s * 0.004)))

    return icon.resize((px, px), Image.LANCZOS)


def main():
    out_dir = sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(os.path.abspath(__file__))
    iconset = os.path.join(out_dir, "Netzwerk-Scanner.iconset")
    os.makedirs(iconset, exist_ok=True)

    # macOS-Iconset benötigt diese Größen/Namen
    specs = [
        (16, "icon_16x16.png"), (32, "icon_16x16@2x.png"),
        (32, "icon_32x32.png"), (64, "icon_32x32@2x.png"),
        (128, "icon_128x128.png"), (256, "icon_128x128@2x.png"),
        (256, "icon_256x256.png"), (512, "icon_256x256@2x.png"),
        (512, "icon_512x512.png"), (1024, "icon_512x512@2x.png"),
    ]
    cache = {}
    for size, name in specs:
        if size not in cache:
            cache[size] = render(size)
        cache[size].save(os.path.join(iconset, name))
    # Vorschau + PNG für tk-Fenstersymbol
    render(512).save(os.path.join(out_dir, "preview.png"))
    render(256).save(os.path.join(out_dir, "app_icon.png"))
    # .ico für die Windows-Version (Pillow kann das auf jedem Betriebssystem
    # erzeugen, wird also auch vom macOS-build.sh mitgebaut).
    render(512).save(os.path.join(out_dir, "Netzwerk-Scanner.ico"),
                     sizes=[(16, 16), (32, 32), (48, 48), (128, 128), (256, 256)])
    print(f"Iconset erzeugt: {iconset}")


if __name__ == "__main__":
    main()
