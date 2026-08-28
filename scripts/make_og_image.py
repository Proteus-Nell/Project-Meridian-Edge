#!/usr/bin/env python3
"""Regenerate client/public/og.png, the Open Graph / Twitter link preview card.

The card exists so that a link someone pastes into a chat app unfurls as
something other than a bare URL. It is generated rather than hand-drawn so the
committed PNG has provenance: change the constants here, re-run, commit the
result.

    python scripts/make_og_image.py

Requires Pillow (a local authoring tool only - it is deliberately not a client
or server dependency, and CI never runs this).

Design notes: 1200x630 is the size every unfurler crops from, and the layout is
centred because the card is usually seen as a thumbnail. The figure is the
medallion's glyph-globe, the emblem /settings emblem globe selects; the favicon
carries the gaia glyph the app now wears by default, which is a filled
silhouette rather than something these draw primitives can trace. Everything is
drawn at SUPERSAMPLE times final size and downsampled, because Pillow's draw
primitives are not anti-aliased.
"""

from __future__ import annotations

import math
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "client" / "public" / "og.png"

WIDTH, HEIGHT = 1200, 630
SUPERSAMPLE = 4

# The `dark` scheme's slots, copied from :root in client/src/style.css.
BG = "#0d1117"
ACCENT = "#58a6ff"
TEXT = "#c9d1d9"
MUTED = "#8b949e"

# Matches WORDMARK in client/src/terminal/banner.ts.
WORDMARK = "M E R I D I A N   E D G E"
# Compressed from the banner's opening lines: an unfurl gets one line, not five.
TAGLINE = "Messages are encrypted on your device."
FOOTER = "Post-quantum by design: ML-KEM-768 + ML-DSA-65"

# Monospace, to match the app. Consolas first (this is a Windows-authored repo),
# then the usual Linux/macOS locations so a regeneration elsewhere still works.
FONT_CANDIDATES: dict[str, tuple[str, ...]] = {
    "bold": (
        "C:/Windows/Fonts/consolab.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf",
        "/System/Library/Fonts/Menlo.ttc",
    ),
    "regular": (
        "C:/Windows/Fonts/consola.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
        "/System/Library/Fonts/Menlo.ttc",
    ),
}


def load_font(weight: str, size: int) -> ImageFont.FreeTypeFont:
    """First candidate that exists, at the supersampled size."""
    for candidate in FONT_CANDIDATES[weight]:
        if Path(candidate).exists():
            return ImageFont.truetype(candidate, size * SUPERSAMPLE)
    raise SystemExit(
        f"no {weight} monospace font found; add one to FONT_CANDIDATES[{weight!r}]"
    )


def centred(draw: ImageDraw.ImageDraw, text: str, font: ImageFont.FreeTypeFont) -> float:
    """Left x that centres `text` on the canvas."""
    return (WIDTH * SUPERSAMPLE - draw.textlength(text, font=font)) / 2


def draw_globe(draw: ImageDraw.ImageDraw, cx: float, cy: float, r: float) -> None:
    """Globe with meridians: outline, one meridian pair, equator, two parallels.

    The parallels are elliptical arcs rather than straight lines - that is what
    makes the circle read as a sphere instead of a target. Each one is clipped to
    the sphere's half-width at its latitude, so it meets the outline exactly.
    """
    stroke = round(7 * SUPERSAMPLE)
    inner = round(6 * SUPERSAMPLE)

    draw.ellipse((cx - r, cy - r, cx + r, cy + r), outline=ACCENT, width=stroke)
    # Meridian pair: one ellipse, full height, drawn as an outline.
    draw.ellipse(
        (cx - r * 0.41, cy - r, cx + r * 0.41, cy + r), outline=ACCENT, width=inner
    )
    draw.line((cx - r, cy, cx + r, cy), fill=ACCENT, width=inner)

    for offset in (-r * 0.49, r * 0.49):
        y = cy + offset
        half = math.sqrt(max(r * r - offset * offset, 0.0))
        bow = r * 0.22
        box = (cx - half, y - bow, cx + half, y + bow)
        # Above the equator the parallel bows down (PIL's 0-180 is the lower
        # half, angles running clockwise from 3 o'clock); below, it bows up.
        start, end = (0, 180) if offset < 0 else (180, 360)
        draw.arc(box, start=start, end=end, fill=ACCENT, width=inner)


def main() -> int:
    canvas = Image.new("RGB", (WIDTH * SUPERSAMPLE, HEIGHT * SUPERSAMPLE), BG)
    draw = ImageDraw.Draw(canvas)

    draw_globe(
        draw,
        cx=WIDTH * SUPERSAMPLE / 2,
        cy=205 * SUPERSAMPLE,
        r=112 * SUPERSAMPLE,
    )

    wordmark_font = load_font("bold", 44)
    tagline_font = load_font("regular", 27)
    footer_font = load_font("regular", 21)

    for text, font, colour, top in (
        (WORDMARK, wordmark_font, ACCENT, 385),
        (TAGLINE, tagline_font, TEXT, 468),
        (FOOTER, footer_font, MUTED, 538),
    ):
        draw.text(
            (centred(draw, text, font), top * SUPERSAMPLE), text, font=font, fill=colour
        )

    canvas.resize((WIDTH, HEIGHT), Image.LANCZOS).save(OUT, "PNG", optimize=True)
    print(f"wrote {OUT.relative_to(ROOT)} ({OUT.stat().st_size:,} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
