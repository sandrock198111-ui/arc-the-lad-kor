from __future__ import annotations

import argparse
import struct
import zlib
from pathlib import Path


def png_chunk(kind: bytes, data: bytes) -> bytes:
    return (
        struct.pack(">I", len(data))
        + kind
        + data
        + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Convert a DuckStation 256x192 BGRA save-state thumbnail to PNG."
    )
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()

    width, height = 256, 192
    bgra = args.source.read_bytes()
    if len(bgra) != width * height * 4:
        raise ValueError(f"unexpected thumbnail size: {len(bgra)}")

    rows = bytearray()
    for y in range(height):
        rows.append(0)
        row = bgra[y * width * 4 : (y + 1) * width * 4]
        for x in range(0, len(row), 4):
            blue, green, red, alpha = row[x : x + 4]
            rows.extend((red, green, blue, alpha))

    png = bytearray(b"\x89PNG\r\n\x1a\n")
    png.extend(png_chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)))
    png.extend(png_chunk(b"IDAT", zlib.compress(bytes(rows), 9)))
    png.extend(png_chunk(b"IEND", b""))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(png)
    print(f"wrote {args.output}")


if __name__ == "__main__":
    main()
