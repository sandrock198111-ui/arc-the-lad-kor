"""Anchor a save state's VRAM on COMM.IMG instead of on the resident strips.

extract_savestate_vram.py anchors on strip A, which only works while the strips hold
pixels.  The diagnostics that blank the strips produce states it cannot read, and
those are exactly the states worth reading.

DuckStation writes a structural ``GPU-VRAM`` marker immediately before the raw
1024x512x16-bit array.  COMM.IMG is uploaded at VRAM x 320..767, y 0..511.  It is
therefore a useful content cross-check, but it cannot locate the origin by itself:
mistaking its x=320 anchor for x=0 shifts the apparent origin by 640 bytes.

    python 02_scripts/extract_savestate_vram_by_font.py <state.sav> [more.sav ...]

Writes <name>.vram.bin and <name>.vram.png next to 01_work/analysis/savestate_vram/.
"""
from __future__ import annotations

import struct
import sys
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

from extract_savestate_vram import inflate, locate_vram, section  # noqa: E402

VRAM_W, VRAM_H = 1024, 512
VRAM_SIZE = VRAM_W * VRAM_H * 2
FONT_ROW_BYTES = 896                       # 1792 px at 4bpp
FONT_ROWS = 512
COMM_VRAM_X = 320
COMM_VRAM_X_BYTES = COMM_VRAM_X * 2
OUTDIR = ROOT / "01_work/analysis/savestate_vram"


def load_font() -> bytes:
    """The COMM.IMG that was actually on the disc when the state was made."""
    staged = ROOT / "01_work/package_test/files/COMM.IMG"
    if staged.exists():
        return staged.read_bytes()
    import zipfile
    with zipfile.ZipFile(ROOT / "03_output/arc1_v151_free_the_sprite_cell_A4358FEE.zip") as z:
        return z.read("COMM.IMG")


GLYPH_BYTES = 126                          # columns 0..20, the only part that is font


def score(blob: bytes, base: int, font: bytes) -> int:
    """Match the glyph columns only.

    A whole VRAM row is 896 bytes and most of it is not font -- the game writes its
    own graphics into the rest of the same rows, so full-row matching scores near
    zero even at the right base.  Columns 0..20 are the glyph grid and survive.
    """
    hits = 0
    for y in range(0, FONT_ROWS, 8):
        at = base + y * VRAM_W * 2 + COMM_VRAM_X_BYTES
        if blob[at:at + GLYPH_BYTES] == font[y * FONT_ROW_BYTES:][:GLYPH_BYTES]:
            hits += 1
    return hits


def locate(blob: bytes, font: bytes) -> int:
    base = locate_vram(blob)
    hits = score(blob, base, font)
    if hits < 24:
        raise SystemExit(f"COMM.IMG does not line up at VRAM x=320 (best {hits}/64 rows)")
    return base


def png(path: Path, vram: bytes) -> None:
    """VRAM as 16bpp RGB555, so the frame buffer is readable by eye."""
    rows = bytearray()
    for y in range(VRAM_H):
        rows.append(0)
        line = bytearray()
        for x in range(VRAM_W):
            pixel = vram[(y * VRAM_W + x) * 2] | (vram[(y * VRAM_W + x) * 2 + 1] << 8)
            line += bytes(((pixel & 31) << 3, ((pixel >> 5) & 31) << 3, ((pixel >> 10) & 31) << 3))
        rows += line

    def chunk(tag: bytes, data: bytes) -> bytes:
        body = tag + data
        return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body))

    header = struct.pack(">IIBBBBB", VRAM_W, VRAM_H, 8, 2, 0, 0, 0)
    path.write_bytes(b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header)
                     + chunk(b"IDAT", zlib.compress(bytes(rows), 6)) + chunk(b"IEND", b""))


def main() -> None:
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    font = load_font()
    OUTDIR.mkdir(parents=True, exist_ok=True)
    for arg in sys.argv[1:]:
        path = Path(arg)
        blob = inflate(path)
        base = locate(blob, font)
        vram = blob[base:base + VRAM_SIZE]
        (OUTDIR / f"{path.stem}.vram.bin").write_bytes(vram)
        png(OUTDIR / f"{path.stem}.vram.png", vram)

        print(f"{path.name}")
        print(f"  VRAM  GPU+{base - section(blob, 'GPU')}")
        glyph = sum(1 for y in range(FONT_ROWS)
                    if vram[y * VRAM_W * 2 + COMM_VRAM_X_BYTES:]
                    [:GLYPH_BYTES] == font[y * FONT_ROW_BYTES:][:GLYPH_BYTES])
        print(f"  글자 열(0~20)이 파일과 같은 줄 {glyph}/512")
        changed = [y for y in range(FONT_ROWS)
                   if vram[y * VRAM_W * 2 + COMM_VRAM_X_BYTES:][:FONT_ROW_BYTES]
                   != font[y * FONT_ROW_BYTES:(y + 1) * FONT_ROW_BYTES]]
        print(f"  COMM.IMG 폭 전체(0~1791)로 보면 바뀐 줄 {len(changed)}/512")


if __name__ == "__main__":
    main()
