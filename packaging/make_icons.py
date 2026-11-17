"""Draw the ColdPerimeter application icon and write every format needed.

The icon is the same idea as the mark in the interface: a closed perimeter
around an ice crystal, that is, a refrigeration controller that is isolated.

Run from the repository root (needs Pillow):

    python packaging/make_icons.py

Writes:
    packaging/icons/coldperimeter.png    1024 px master
    packaging/icons/coldperimeter.icns   macOS bundle icon
    packaging/icons/coldperimeter.ico    Windows executable icon
    coldperimeter/gui/static/icon.png    256 px favicon for the interface
"""

from __future__ import annotations

import math
from pathlib import Path

from PIL import Image, ImageDraw

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "packaging" / "icons"
STATIC = ROOT / "coldperimeter" / "gui" / "static"

NAVY_TOP = (20, 56, 76)
NAVY_BOTTOM = (10, 30, 42)
GLACIER = (92, 192, 222)
FROST = (234, 246, 250)

SUPERSAMPLE = 4
SMALL = 48  # at and below this size, draw a simplified icon


def _tile(draw: ImageDraw.ImageDraw, box: tuple[float, float, float, float], radius: float, scale: float) -> None:
    """Rounded square with a vertical navy gradient (drawn as horizontal bands)."""
    left, top, right, bottom = box
    mask = Image.new("L", draw.im.size, 0)
    ImageDraw.Draw(mask).rounded_rectangle(box, radius=radius, fill=255)
    gradient = Image.new("RGBA", draw.im.size)
    g = ImageDraw.Draw(gradient)
    height = bottom - top
    for y in range(int(top), int(bottom) + 1):
        t = (y - top) / height
        colour = tuple(round(a + (b - a) * t) for a, b in zip(NAVY_TOP, NAVY_BOTTOM))
        g.line([(left, y), (right, y)], fill=colour + (255,))
    draw._image.paste(gradient, (0, 0), mask)  # type: ignore[attr-defined]


def _stroke(draw: ImageDraw.ImageDraw, a: tuple[float, float], b: tuple[float, float], width: float, fill) -> None:
    """Line with round caps."""
    draw.line([a, b], fill=fill, width=round(width))
    r = width / 2
    for x, y in (a, b):
        draw.ellipse([x - r, y - r, x + r, y + r], fill=fill)


def _flake(draw: ImageDraw.ImageDraw, cx: float, cy: float, arm: float, width: float, branches: bool) -> None:
    for k in range(6):
        angle = math.radians(90 + 60 * k)
        tip = (cx + arm * math.cos(angle), cy - arm * math.sin(angle))
        _stroke(draw, (cx, cy), tip, width, FROST)
        if not branches:
            continue
        base = 0.58
        bx, by = cx + arm * base * math.cos(angle), cy - arm * base * math.sin(angle)
        for side in (-1, 1):
            branch = angle + side * math.radians(48)
            length = arm * 0.36
            end = (bx + length * math.cos(branch), by - length * math.sin(branch))
            _stroke(draw, (bx, by), end, width * 0.82, FROST)


def draw_icon(size: int, macos_margin: bool = True) -> Image.Image:
    """Return a ``size`` x ``size`` RGBA icon."""
    s = size * SUPERSAMPLE
    image = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)
    small = size <= SMALL

    # macOS icons leave a transparent margin (824 of 1024); tiny sizes fill the tile.
    margin = (100 / 1024) * s if macos_margin and not small else (0.03 * s if small else 0)
    tile = (margin, margin, s - margin, s - margin)
    tile_size = s - 2 * margin
    _tile(draw, tile, radius=tile_size * 0.225, scale=s)

    # The perimeter: thicker at small sizes so it stays visible.
    inset = tile_size * (0.17 if small else 0.195)
    ring_width = tile_size * (0.11 if small else 0.068)
    ring = (margin + inset, margin + inset, s - margin - inset, s - margin - inset)
    draw.rounded_rectangle(ring, radius=tile_size * 0.12, outline=GLACIER + (255,), width=round(ring_width))

    # The ice crystal inside it.
    arm = tile_size * (0.19 if small else 0.18)
    width = tile_size * (0.075 if small else 0.042)
    _flake(draw, s / 2, s / 2, arm, width, branches=not small)

    return image.resize((size, size), Image.Resampling.LANCZOS)


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)

    master = draw_icon(1024)
    master.save(OUT / "coldperimeter.png")

    icns_sizes = [16, 32, 64, 128, 256, 512, 1024]
    master.save(
        OUT / "coldperimeter.icns",
        append_images=[draw_icon(n) for n in icns_sizes if n != 1024],
    )

    ico_sizes = [16, 24, 32, 48, 64, 128, 256]
    windows = [draw_icon(n, macos_margin=False) for n in ico_sizes]
    windows[-1].save(
        OUT / "coldperimeter.ico",
        sizes=[(n, n) for n in ico_sizes],
        append_images=windows[:-1],
    )

    draw_icon(256, macos_margin=False).save(STATIC / "icon.png")

    # Contact sheet for reviewing every size at a glance (not committed).
    sheet_sizes = [16, 24, 32, 48, 64, 128, 256]
    sheet = Image.new("RGBA", (sum(sheet_sizes) + 20 * (len(sheet_sizes) + 1), 296), (237, 242, 244, 255))
    x = 20
    for n in sheet_sizes:
        sheet.alpha_composite(draw_icon(n, macos_margin=False), (x, 20))
        x += n + 20
    sheet.save(OUT / "preview-sizes.png")


if __name__ == "__main__":
    main()
