#!/usr/bin/env python3
"""Audit V323's page-15/1 skill-range upload destination in save states.

The destination is physical VRAM halfwords x=960..984, y=447..479.  This
script deliberately translates every active textured packet to physical VRAM
coordinates, including 4/8/16-bpp aliases, instead of checking only tpage 0x1f.
Old experimental builds are reported but are not mixed into the current
static-Hangul lineage verdict.
"""

from __future__ import annotations

import csv
import struct
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))

from compression import zstd  # noqa: E402
from analyze_arc1_v163_runtime import RAM_SIZE, trace_active_text_ot  # noqa: E402
from extract_savestate_vram import VRAM_SIZE, VRAM_W, locate_ram, locate_vram  # noqa: E402


STATES = Path.home() / "AppData/Local/DuckStation/savestates"
OUT = ROOT / "01_work/analysis/arc1_v323_skill_range_relocation"

TARGET_X0 = 960
TARGET_X1 = 985  # exclusive, 25 halfwords = 100 4bpp texels
TARGET_Y0 = 447
TARGET_Y1 = 480  # exclusive, 33 rows

CURRENT_LINEAGE = {
    "JOHAB16P",
    "V319R",
    "V320R",
    "V320C",
    "V321",
    "V322",
}


def inflate(path: Path) -> tuple[str, bytes]:
    raw = path.read_bytes()
    if raw[:5] == b"DUCCT":
        state_at = struct.unpack_from("<I", raw, 0xC4)[0]
        expected = None
    elif raw[:5] == b"DUCCU":
        state_at = struct.unpack_from("<I", raw, 0xD4)[0]
        expected = struct.unpack_from("<I", raw, 0xD0)[0]
    else:
        raise ValueError("unsupported state container")
    if raw[state_at : state_at + 4] != b"\x28\xB5\x2F\xFD":
        raise ValueError("state zstd marker differs")
    blob = zstd.decompress(raw[state_at:])
    if expected is not None and len(blob) != expected:
        raise ValueError(f"inflated length {len(blob)} != {expected}")
    game_id = raw[8:40].split(b"\0", 1)[0].decode("ascii", "replace")
    return game_id, blob


def overlaps(a0: int, a1: int, b0: int, b1: int) -> bool:
    return a0 < b1 and a1 > b0


def packet_physical_bounds(packet: dict[str, object]) -> tuple[int, int, int, int] | None:
    try:
        tpage = int(packet["tpage"])
        u = int(packet["u"])
        v = int(packet["v"])
        width = int(packet["width"])
        height = int(packet["height"])
    except (KeyError, TypeError, ValueError):
        return None
    if width <= 0 or height <= 0:
        return None
    depth = (tpage >> 7) & 3
    if depth > 2:
        return None
    texels_per_halfword = (4, 2, 1)[depth]
    page_x = tpage & 0x0F
    page_y = (tpage >> 4) & 1
    x0 = page_x * 64 + u // texels_per_halfword
    x1 = page_x * 64 + (u + width + texels_per_halfword - 1) // texels_per_halfword
    y0 = page_y * 256 + v
    y1 = y0 + height
    return x0, x1, y0, y1


def target_nonzero_halfwords(vram: bytes) -> int:
    return sum(
        struct.unpack_from("<H", vram, (y * VRAM_W + x) * 2)[0] != 0
        for y in range(TARGET_Y0, TARGET_Y1)
        for x in range(TARGET_X0, TARGET_X1)
    )


def main() -> None:
    files = sorted(STATES.glob("*.sav"))
    by_build: dict[str, Counter[str]] = defaultdict(Counter)
    failures: list[str] = []
    rows: list[dict[str, object]] = []
    for number, path in enumerate(files, 1):
        try:
            game_id, blob = inflate(path)
            ram_at = locate_ram(blob)
            vram_at = locate_vram(blob)
            ram = blob[ram_at : ram_at + RAM_SIZE]
            vram = blob[vram_at : vram_at + VRAM_SIZE]
            if len(ram) != RAM_SIZE or len(vram) != VRAM_SIZE:
                raise ValueError("incomplete RAM or VRAM payload")
            _context, _parity, packets = trace_active_text_ot(ram)
            readers = 0
            reader_examples: list[str] = []
            for packet in packets:
                bounds = packet_physical_bounds(packet)
                if bounds is None:
                    continue
                x0, x1, y0, y1 = bounds
                if overlaps(x0, x1, TARGET_X0, TARGET_X1) and overlaps(
                    y0, y1, TARGET_Y0, TARGET_Y1
                ):
                    readers += 1
                    if len(reader_examples) < 4:
                        reader_examples.append(
                            f"{packet.get('kind')}@{packet.get('address')}:"
                            f"tp={packet.get('tpage')},uv={packet.get('u')},{packet.get('v')},"
                            f"wh={packet.get('width')}x{packet.get('height')}"
                        )
            nonzero = target_nonzero_halfwords(vram)
            lineage = "current" if game_id in CURRENT_LINEAGE else "historical"
            by_build[game_id]["states"] += 1
            by_build[game_id]["reader_states"] += int(readers > 0)
            by_build[game_id]["reader_packets"] += readers
            by_build[game_id]["nonzero_states"] += int(nonzero > 0)
            by_build[game_id]["nonzero_halfwords"] += nonzero
            rows.append(
                {
                    "file": path.name,
                    "game_id": game_id,
                    "lineage": lineage,
                    "reader_packets": readers,
                    "nonzero_halfwords": nonzero,
                    "reader_examples": " | ".join(reader_examples),
                }
            )
        except BaseException as exc:
            failures.append(f"{path.name}: {exc}")
        if number % 100 == 0:
            print(f"state scan {number}/{len(files)}", flush=True)

    OUT.mkdir(parents=True, exist_ok=True)
    with (OUT / "page15_target_states.csv").open(
        "w", encoding="utf-8-sig", newline=""
    ) as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=(
                "file",
                "game_id",
                "lineage",
                "reader_packets",
                "nonzero_halfwords",
                "reader_examples",
            ),
        )
        writer.writeheader()
        writer.writerows(rows)

    current = [row for row in rows if row["lineage"] == "current"]
    current_reader_states = sum(int(row["reader_packets"] > 0) for row in current)
    current_nonzero_states = sum(int(row["nonzero_halfwords"] > 0) for row in current)
    report = [
        "V323 page15/1 physical target audit",
        f"target_halfwords=x[{TARGET_X0},{TARGET_X1}) y[{TARGET_Y0},{TARGET_Y1})",
        f"states_total={len(files)}",
        f"states_read={len(rows)}",
        f"states_failed={len(failures)}",
        f"current_lineage_ids={','.join(sorted(CURRENT_LINEAGE))}",
        f"current_lineage_states={len(current)}",
        f"current_reader_states={current_reader_states}",
        f"current_nonzero_states={current_nonzero_states}",
        "build,states,reader_states,reader_packets,nonzero_states,nonzero_halfwords",
    ]
    for game_id, counts in sorted(by_build.items()):
        report.append(
            f"{game_id},{counts['states']},{counts['reader_states']},"
            f"{counts['reader_packets']},{counts['nonzero_states']},"
            f"{counts['nonzero_halfwords']}"
        )
    report.extend(f"failure={line}" for line in failures)
    (OUT / "page15_target_report.txt").write_text(
        "\n".join(report) + "\n", encoding="utf-8"
    )
    print("\n".join(report[:9]))
    if current_reader_states or current_nonzero_states:
        raise SystemExit("current-lineage target collision observed")


if __name__ == "__main__":
    main()
