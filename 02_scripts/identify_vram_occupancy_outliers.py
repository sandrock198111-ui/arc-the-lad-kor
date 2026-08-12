"""Name the save states behind rare page-15 VRAM occupancy.

``map_vram_occupancy_all_states.py`` deliberately folds all states into one map,
so it cannot answer which state caused a rare occupied row.  This companion is
read-only: it repeats the same VRAM-location rule, records the per-state result,
and fails closed by labelling a fallback-only location instead of treating it as
font-anchored evidence.

    python 02_scripts/identify_vram_occupancy_outliers.py

Writes a CSV and a short text report below
``01_work/analysis/vram_occupancy_map``.
"""
from __future__ import annotations

import csv
import hashlib
import struct
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))

from extract_savestate_vram import inflate, locate_ram, section  # noqa: E402
from extract_duckstation_savestate import decompress  # noqa: E402
from map_vram_occupancy_all_states import (  # noqa: E402
    COMM_VRAM_X_BYTES,
    FONT_ROW,
    GLYPH_BYTES,
    VRAM_H,
    VRAM_SIZE,
    VRAM_W,
    fonts,
    locate,
)

STATES = Path.home() / "AppData/Local/DuckStation/savestates"
OUT = ROOT / "01_work/analysis/vram_occupancy_map"
CSV_OUT = OUT / "page15_state_provenance.csv"
REPORT = OUT / "page15_outliers.txt"
X0, X1 = 960, 1024
Y0, Y1 = 481, 511
QUESTION_Y0, QUESTION_Y1 = 489, 511
RAM_SIZE = 2 * 1024 * 1024
FRAME_HOOK_OFFSET = 0x0011C4AC
STOCK_FRAME_HOOK = 0x0C047205       # jal 0x8011C814
CACHE_X0, CACHE_X1 = 961, 976
CACHE_Y0, CACHE_Y1 = 480, 492


def row(vram: bytes, y: int) -> bytes:
    start = (y * VRAM_W + X0) * 2
    return vram[start:start + (X1 - X0) * 2]


def nonzero_halfwords(data: bytes) -> int:
    return sum(data[i] != 0 or data[i + 1] != 0 for i in range(0, len(data), 2))


def rectangle(vram: bytes, x0: int, x1: int, y0: int, y1: int) -> bytes:
    return b"".join(
        vram[(y * VRAM_W + x0) * 2:(y * VRAM_W + x1) * 2]
        for y in range(y0, y1)
    )


def font_anchor_score(vram: bytes, candidates: list[bytes]) -> tuple[int, int]:
    """Return (candidate number, matching sampled rows), or (-1, 0)."""
    best = (-1, 0)
    for number, font in enumerate(candidates):
        hits = sum(
            vram[y * VRAM_W * 2 + COMM_VRAM_X_BYTES:
                 y * VRAM_W * 2 + COMM_VRAM_X_BYTES + GLYPH_BYTES]
            == font[y * FONT_ROW:y * FONT_ROW + GLYPH_BYTES]
            for y in range(0, VRAM_H, 16)
        )
        if hits > best[1]:
            best = (number, hits)
    return best


def main() -> None:
    candidates = fonts()
    files = sorted(STATES.glob("*.sav"))
    records: list[dict[str, object]] = []
    owners: dict[int, list[str]] = defaultdict(list)
    skipped: list[str] = []
    hook_counts: Counter[int] = Counter()
    stock_states = 0
    stock_thumbnail_hashes: set[str] = set()
    stock_cache_nonzero: list[tuple[str, int]] = []
    vram_origin_offsets: Counter[int] = Counter()

    for number, path in enumerate(files, 1):
        try:
            blob = inflate(path)
            base = locate(blob, candidates)
            if base is None:
                skipped.append(f"{path.name}: no VRAM base")
                continue
            vram_origin_offsets[base - section(blob, "GPU")] += 1
            vram = blob[base:base + VRAM_SIZE]
            candidate, score = font_anchor_score(vram, candidates)
            method = f"font[{candidate}]/{score}" if score >= 24 else f"fallback/{score}"
            ram_base = locate_ram(blob)
            ram = blob[ram_base:ram_base + RAM_SIZE]
            if len(ram) != RAM_SIZE:
                raise ValueError("RAM payload is incomplete")
            frame_hook = struct.unpack_from("<I", ram, FRAME_HOOK_OFFSET)[0]
            hook_counts[frame_hook] += 1
            cache_nonzero = nonzero_halfwords(
                rectangle(vram, CACHE_X0, CACHE_X1, CACHE_Y0, CACHE_Y1)
            )
            if frame_hook == STOCK_FRAME_HOOK:
                stock_states += 1
                stock_thumbnail_hashes.add(hashlib.sha256(decompress(path, "first")).hexdigest())
                if cache_nonzero:
                    stock_cache_nonzero.append((path.name, cache_nonzero))
        except BaseException as exc:  # inflate/section helpers use SystemExit on bad input.
            skipped.append(f"{path.name}: {exc}")
            continue

        counts = [nonzero_halfwords(row(vram, y)) for y in range(Y0, Y1)]
        question_count = sum(counts[QUESTION_Y0 - Y0:QUESTION_Y1 - Y0])
        if question_count:
            for y in range(QUESTION_Y0, QUESTION_Y1):
                if counts[y - Y0]:
                    owners[y].append(path.name)
            region = b"".join(row(vram, y) for y in range(QUESTION_Y0, QUESTION_Y1))
            stat = path.stat()
            records.append({
                "filename": path.name,
                "modified": stat.st_mtime_ns,
                "anchor": method,
                "frame_hook": f"{frame_hook:08X}",
                "vram_base_minus_gpu": base - section(blob, "GPU"),
                "current_cache_nonzero_halfwords": cache_nonzero,
                "nonzero_halfwords_y489_510": question_count,
                "region_sha256": hashlib.sha256(region).hexdigest().upper(),
                "row_counts_y481_510": " ".join(map(str, counts)),
            })

        if number % 25 == 0:
            print(f"{number}/{len(files)}", flush=True)

    OUT.mkdir(parents=True, exist_ok=True)
    fields = [
        "filename",
        "modified",
        "anchor",
        "frame_hook",
        "vram_base_minus_gpu",
        "current_cache_nonzero_halfwords",
        "nonzero_halfwords_y489_510",
        "region_sha256",
        "row_counts_y481_510",
    ]
    with CSV_OUT.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(records)

    lines = [
        f"input states: {len(files)}",
        f"states touching x{X0}..{X1-1}, y{QUESTION_Y0}..{QUESTION_Y1-1}: {len(records)}",
        f"skipped: {len(skipped)}",
        ("GPU-VRAM marker offsets: "
         + " ".join(f"GPU+{offset}={count}" for offset, count in sorted(vram_origin_offsets.items()))),
        f"frame hooks: {' '.join(f'{hook:08X}={count}' for hook, count in hook_counts.most_common())}",
        f"stock-frame-hook states: {stock_states}",
        f"distinct stock thumbnails: {len(stock_thumbnail_hashes)}",
        (f"stock states with pixels in exact current cache rectangle "
         f"x{CACHE_X0}..{CACHE_X1-1},y{CACHE_Y0}..{CACHE_Y1-1}: "
         f"{len(stock_cache_nonzero)}"),
        "",
    ]
    for record in records:
        lines.append(
            f"{record['filename']}  {record['anchor']}  "
            f"nonzero={record['nonzero_halfwords_y489_510']}  "
            f"sha256={record['region_sha256']}"
        )
    if stock_cache_nonzero:
        lines.extend(("", "stock cache conflicts:"))
        lines.extend(f"{name}: {count}" for name, count in stock_cache_nonzero)
    lines.extend(("", "per-row owner counts:"))
    for y in range(QUESTION_Y0, QUESTION_Y1):
        lines.append(f"y{y}: {len(owners[y])}")
    if skipped:
        lines.extend(("", "skipped:"))
        lines.extend(skipped)
    REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
