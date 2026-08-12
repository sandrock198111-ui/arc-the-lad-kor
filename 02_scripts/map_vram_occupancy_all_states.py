"""Fold every save state on this machine into one VRAM occupancy map.

Three times now a place in VRAM looked free and turned out to be in use: strip C at
y 380, the 140 blank font cells, and texture page 5,0 where the cache writes.  Every
one of those was chosen from a handful of save states that happened not to contain
the scene that used it.

There are 280 save-state files here now from multiple builds and game sections.
Many are overlapping checkpoints, so this is a larger regression sample, not full-game
coverage.  Folded together they answer only which halfwords this sample never captured.

The current cache needs five 12x12 4bpp physical cells, i.e. a 15x12 rectangle in
16-bit VRAM coordinates.  A band that is clean across 280 states is stronger
negative evidence than one clean across two, but absence in snapshots is never by
itself proof of ownership.

    python 02_scripts/map_vram_occupancy_all_states.py [--limit N]

Writes 01_work/analysis/vram_occupancy_map/ with a per-row report and a PNG.
"""
from __future__ import annotations

import struct
import sys
import zipfile
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

from extract_savestate_vram import inflate, locate_vram  # noqa: E402

STATES = Path.home() / "AppData/Local/DuckStation/savestates"
OUT = ROOT / "01_work/analysis/vram_occupancy_map"
VRAM_W, VRAM_H = 1024, 512
VRAM_SIZE = VRAM_W * VRAM_H * 2
GLYPH_BYTES = 126
FONT_ROW = 896
COMM_VRAM_X = 320
COMM_VRAM_X_BYTES = COMM_VRAM_X * 2


def fonts() -> list[bytes]:
    """Every COMM.IMG a state could have been made with, for anchoring."""
    out = []
    for name in ("00_original/arc.zip",
                 "03_output/arc1_v151_free_the_sprite_cell_A4358FEE.zip",
                 "03_output/arc1_v163_text_clut_classifier_773E3B82.zip",
                 "03_output/arc1_v161_bounded_exe_text_B2EA377E.zip"):
        path = ROOT / name
        if path.exists():
            with zipfile.ZipFile(path) as z:
                if "COMM.IMG" in z.namelist():
                    out.append(z.read("COMM.IMG"))
    return out


def locate(blob: bytes, _candidates: list[bytes]) -> int | None:
    """Return the byte immediately after DuckStation's ``GPU-VRAM`` marker.

    DuckStation serializes the marker and then writes exactly the 1024x512x16-bit
    VRAM array.  COMM.IMG cannot choose between this origin and an origin shifted
    640 bytes to its own x=320 anchor, because both models point at the same font
    bytes.  The structural marker removes that ambiguity.

    ``_candidates`` remains in the signature because callers use the same font set
    to classify provenance after locating VRAM; it is deliberately not an origin
    oracle here.
    """
    try:
        return locate_vram(blob)
    except ValueError:
        return None


def png(path: Path, counts: list[int], states: int) -> None:
    rows = bytearray()
    peak = max(counts) or 1
    for y in range(VRAM_H):
        rows.append(0)
        for x in range(VRAM_W):
            n = counts[y * VRAM_W + x]
            v = 0 if not n else 40 + int(215 * n / peak)
            rows += bytes((v, 0, 0) if n else (0, 40, 0))

    def chunk(tag: bytes, data: bytes) -> bytes:
        body = tag + data
        return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body))

    header = struct.pack(">IIBBBBB", VRAM_W, VRAM_H, 8, 2, 0, 0, 0)
    path.write_bytes(b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header)
                     + chunk(b"IDAT", zlib.compress(bytes(rows), 6)) + chunk(b"IEND", b""))


def main() -> None:
    limit = None
    if "--limit" in sys.argv:
        limit = int(sys.argv[sys.argv.index("--limit") + 1])
    files = sorted(STATES.glob("*.sav"))[:limit]
    candidates = fonts()
    counts = [0] * (VRAM_W * VRAM_H)
    read = skipped = 0

    for i, path in enumerate(files, 1):
        try:
            blob = inflate(path)
            base = locate(blob, candidates)
            if base is None:
                skipped += 1
                continue
            vram = blob[base:base + VRAM_SIZE]
        except Exception:
            skipped += 1
            continue
        read += 1
        for y in range(VRAM_H):
            row = vram[y * VRAM_W * 2:(y + 1) * VRAM_W * 2]
            at = y * VRAM_W
            for x in range(VRAM_W):
                if row[x * 2] or row[x * 2 + 1]:
                    counts[at + x] += 1
        if i % 20 == 0:
            print(f"  {i}/{len(files)} 처리, 읽음 {read} 건너뜀 {skipped}", flush=True)

    OUT.mkdir(parents=True, exist_ok=True)
    png(OUT / "occupancy.png", counts, read)
    lines = [f"세이브스테이트 {read}장 (건너뜀 {skipped})", ""]
    lines.append("텍스처 페이지 15,1 (x 960~1023) 의 y별 점유")
    for y in range(256, 512):
        n = sum(1 for x in range(960, 1024) if counts[y * VRAM_W + x])
        worst = max(counts[y * VRAM_W + x] for x in range(960, 1024))
        lines.append(f"  y {y:3}  쓰인 halfword {n:3}/64   최대 {worst}장에서 사용")
    (OUT / "page15_rows.txt").write_text("\n".join(lines), encoding="utf-8")

    clean = [y for y in range(256, 512)
             if not any(counts[y * VRAM_W + x] for x in range(960, 1024))]
    print()
    print(f"세이브스테이트 {read}장 folded (건너뜀 {skipped})")
    print(f"페이지 15,1 에서 단 한 장에서도 안 쓰인 줄 {len(clean)}/256")
    if clean:
        runs, start, prev = [], clean[0], clean[0]
        for y in clean[1:]:
            if y != prev + 1:
                runs.append((start, prev))
                start = y
            prev = y
        runs.append((start, prev))
        for a, b in runs:
            mark = "  <- 12줄 띠가 들어간다" if b - a + 1 >= 12 else ""
            print(f"   y {a}~{b}  ({b-a+1}줄){mark}")
    print(f"\n지도 {OUT/'occupancy.png'}")


if __name__ == "__main__":
    main()
