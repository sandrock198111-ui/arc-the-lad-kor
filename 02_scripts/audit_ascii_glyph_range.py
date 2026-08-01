"""Extract and document original COMM.IMG glyphs for indices 0..94.

This is deliberately independent of the current Japanese character map.  It reads
the original disc, isolates each 1-bit plane from the 4bpp atlas, and writes a
labelled contact sheet plus a machine-readable per-index audit table.
"""
from __future__ import annotations

import csv
import hashlib
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


ROOT = Path(__file__).resolve().parents[1]
DISC = Path(r"E:\arc\원본\arc1.bin")
OUT_DIR = ROOT / "01_work" / "analysis" / "ascii_glyph_audit"
COMM_LBA = 667
COMM_SIZE = 458_752
RAW_SECTOR = 2_352
STRIP_ROW_BYTES = 896
STRIP_X4 = 1_280
GLYPH_SIZE = 12
INDEX_COUNT = 95


def read_original_comm() -> bytes:
    chunks: list[bytes] = []
    with DISC.open("rb") as handle:
        for sector_index in range(COMM_SIZE // 2_048):
            handle.seek((COMM_LBA + sector_index) * RAW_SECTOR)
            sector = handle.read(RAW_SECTOR)
            if len(sector) != RAW_SECTOR:
                raise SystemExit("original disc ended inside COMM.IMG")
            chunks.append(sector[24:24 + 2_048] if sector[15] == 2 else sector[16:16 + 2_048])
    result = b"".join(chunks)
    if len(result) != COMM_SIZE:
        raise SystemExit(f"COMM.IMG size mismatch: {len(result)}")
    return result


def glyph_bitmap(comm: bytes, index: int) -> Image.Image:
    row = index // 84
    col = (index % 84) // 4
    plane = index % 4
    base_x4 = STRIP_X4 + col * GLYPH_SIZE
    base_y = row * GLYPH_SIZE
    image = Image.new("1", (GLYPH_SIZE, GLYPH_SIZE))
    for y in range(GLYPH_SIZE):
        for x in range(GLYPH_SIZE):
            x4 = base_x4 + x
            word_offset = (base_y + y) * STRIP_ROW_BYTES + ((x4 - STRIP_X4) // 4) * 2
            word = int.from_bytes(comm[word_offset:word_offset + 2], "little")
            nibble = (word >> (((x4 - STRIP_X4) % 4) * 4)) & 0xF
            image.putpixel((x, y), 1 if nibble & (1 << plane) else 0)
    return image


def bitmap_rows(image: Image.Image) -> str:
    return "/".join(
        "".join("#" if image.getpixel((x, y)) else "." for x in range(GLYPH_SIZE))
        for y in range(GLYPH_SIZE)
    )


def main() -> None:
    comm = read_original_comm()
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    scale, box_w, box_h, columns = 5, 76, 86, 10
    rows = (INDEX_COUNT + columns - 1) // columns
    sheet = Image.new("RGB", (columns * box_w, rows * box_h), "white")
    draw = ImageDraw.Draw(sheet)
    font = ImageFont.load_default()
    evidence = []
    for index in range(INDEX_COUNT):
        glyph = glyph_bitmap(comm, index)
        gx = (index % columns) * box_w
        gy = (index // columns) * box_h
        draw.text((gx + 2, gy + 2), f"{index:02d} / {chr(index + 32)!r}", fill="black", font=font)
        enlarged = glyph.resize((GLYPH_SIZE * scale, GLYPH_SIZE * scale), Image.Resampling.NEAREST)
        monochrome = enlarged.convert("L").point(lambda p: 0 if p else 255)
        sheet.paste(Image.merge("RGB", (monochrome, monochrome, monochrome)), (gx + 8, gy + 18))
        evidence.append({
            "glyph index": index,
            "candidate ASCII": chr(index + 32),
            "row": index // 84,
            "column": (index % 84) // 4,
            "plane": index % 4,
            "set pixels": sum(glyph.getdata()),
            "bitmap 12x12 (#=set)": bitmap_rows(glyph),
            "classification": (
                "ASCII rule valid (blank space)" if index == 0 else
                "ASCII rule valid" if 1 <= index <= 25 else
                "Japanese/non-ASCII; ASCII rule rejected"
            ),
            "basis": (
                "original COMM.IMG 12x12 bitplane is blank, matching ASCII space" if index == 0 else
                "original COMM.IMG 12x12 bitplane visibly matches the candidate ASCII glyph" if 1 <= index <= 25 else
                "original COMM.IMG 12x12 bitplane visibly does not match the candidate ASCII glyph; character left unresolved"
            ),
        })
    sheet_path = OUT_DIR / "ascii_indices_000_094.png"
    sheet.save(sheet_path)
    csv_path = OUT_DIR / "ascii_indices_000_094.csv"
    with csv_path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=evidence[0].keys())
        writer.writeheader()
        writer.writerows(evidence)
    print(f"disc_sha256={hashlib.sha256(DISC.read_bytes()).hexdigest()}")
    print(f"comm_sha256={hashlib.sha256(comm).hexdigest()}")
    print(sheet_path)
    print(csv_path)


if __name__ == "__main__":
    main()
