"""Generate ServerKit icon set from the brand SVG.

Outputs:
  agent/internal/setupui/serverkit.ico       — main app/installer icon (embedded into the exe)
  agent/internal/tray/icons/connected.ico    — tray (full color)
  agent/internal/tray/icons/disconnected.ico — tray (yellow tint)
  agent/internal/tray/icons/error.ico        — tray (red tint)
  agent/internal/tray/icons/stopped.ico      — tray (gray)

Run from repo root:
  python agent/packaging/icons/generate_icons.py
"""
from __future__ import annotations

import io
from pathlib import Path

import cairosvg
from PIL import Image, ImageEnhance

REPO = Path(__file__).resolve().parents[3]
SVG = REPO / "frontend" / "src" / "assets" / "ServerKitLogo.svg"
SETUPUI_DIR = REPO / "agent" / "internal" / "setupui"
TRAY_DIR = REPO / "agent" / "internal" / "tray" / "icons"

SETUPUI_DIR.mkdir(parents=True, exist_ok=True)
TRAY_DIR.mkdir(parents=True, exist_ok=True)

APP_SIZES = [16, 24, 32, 48, 64, 128, 256]
TRAY_SIZES = [16, 24, 32, 48, 64]


def render_png(size: int) -> Image.Image:
    png_bytes = cairosvg.svg2png(
        url=str(SVG), output_width=size, output_height=size
    )
    return Image.open(io.BytesIO(png_bytes)).convert("RGBA")


def tint(img: Image.Image, rgb: tuple[int, int, int], strength: float = 0.65) -> Image.Image:
    """Apply a hue shift by blending non-transparent pixels toward `rgb`."""
    base = img.copy()
    overlay = Image.new("RGBA", base.size, rgb + (0,))
    alpha = base.split()[3]
    overlay.putalpha(alpha)
    blended = Image.blend(base, overlay, strength)
    blended.putalpha(alpha)
    return blended


def desaturate(img: Image.Image) -> Image.Image:
    enhancer = ImageEnhance.Color(img)
    return enhancer.enhance(0.0)


def write_ico(images: list[Image.Image], out: Path) -> None:
    primary = images[-1]
    primary.save(out, format="ICO", sizes=[(im.width, im.height) for im in images])
    print(f"  wrote {out.relative_to(REPO)} ({len(images)} sizes)")


def main() -> None:
    print("Rendering brand PNGs…")
    app_pngs = [render_png(s) for s in APP_SIZES]
    tray_pngs = [render_png(s) for s in TRAY_SIZES]

    print("Building serverkit.ico…")
    write_ico(app_pngs, SETUPUI_DIR / "serverkit.ico")

    print("Building wizard header PNG…")
    header = render_png(96)
    header_path = SETUPUI_DIR / "serverkit_header.png"
    header.save(header_path, format="PNG")
    print(f"  wrote {header_path.relative_to(REPO)}")

    print("Building tray icons…")
    write_ico(tray_pngs, TRAY_DIR / "connected.ico")
    write_ico([tint(p, (245, 158, 11)) for p in tray_pngs], TRAY_DIR / "disconnected.ico")
    write_ico([tint(p, (220, 38, 38)) for p in tray_pngs], TRAY_DIR / "error.ico")
    write_ico([desaturate(p) for p in tray_pngs], TRAY_DIR / "stopped.ico")

    print("Done.")


if __name__ == "__main__":
    main()
