"""Read-only comparison of COMM.IMG artwork protection across key builds.

This audit answers one narrow question: did the v159-v163 font rebuild put pixels
back into cells that v110 had restored to the original game artwork?

Nothing under 03_output is modified.  Results are written below 01_work/analysis.
"""
from __future__ import annotations

import csv
import hashlib
import sys
import zipfile
from collections import defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))

from audit_dynamic_cache_requirements import (  # noqa: E402
    glyph_index, read_lut, source_ranges, text_units,
)
ORIGINAL = ROOT / "00_original/arc.zip"
ASSIGNMENTS = ROOT / "01_work/analysis/dynamic_cache_v153_widthsafe/glyph_assignments.csv"
OUT = ROOT / "01_work/analysis/arc1_v163_comm_art_regression"

ARCHIVES = {
    "v110": ROOT / "03_output/ui_hud_e7_v110_restore_all_game_art_patch_only.zip",
    "v151": ROOT / "03_output/arc1_v151_free_the_sprite_cell_A4358FEE.zip",
    "v163": ROOT / "03_output/arc1_v163_text_clut_classifier_773E3B82.zip",
}

COMM = "COMM.IMG"
ROW_BYTES = 896
CELL = 12
CELL_BYTES = CELL // 2
FONT_COLS = 21
FONT_ROWS = 21
PLANES = 4
INDICES_PER_ROW = FONT_COLS * PLANES
RANGE_CELLS = {(row, col) for row in range(10, 14) for col in range(2, 6)}


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def member(path: Path, name: str) -> bytes:
    with zipfile.ZipFile(path) as archive:
        return archive.read(name)


def cell_offsets(row: int, col: int):
    for dy in range(CELL):
        start = (row * CELL + dy) * ROW_BYTES + col * CELL_BYTES
        yield from range(start, start + CELL_BYTES)


def plane_bits(font: bytes, index: int) -> tuple[int, ...]:
    row, rem = divmod(index, INDICES_PER_ROW)
    col, plane = divmod(rem, PLANES)
    bits = []
    for dy in range(CELL):
        for dx in range(CELL):
            px = col * CELL + dx
            value = font[(row * CELL + dy) * ROW_BYTES + px // 2]
            nibble = value & 0x0F if px % 2 == 0 else value >> 4
            bits.append((nibble >> plane) & 1)
    return tuple(bits)


def main() -> None:
    if not ORIGINAL.exists():
        raise SystemExit(f"missing original archive: {ORIGINAL}")
    for label, path in ARCHIVES.items():
        if not path.exists():
            raise SystemExit(f"missing {label} archive: {path}")

    pristine = member(ORIGINAL, COMM)
    builds = {label: member(path, COMM) for label, path in ARCHIVES.items()}
    if any(len(data) != len(pristine) for data in builds.values()):
        raise SystemExit("COMM.IMG size mismatch")

    with zipfile.ZipFile(ORIGINAL) as archive:
        pristine_members = {
            info.filename: archive.read(info.filename) for info in archive.infolist()
        }
    original_lut = read_lut(pristine_members["PSX.EXE"])
    original_used: set[int] = set()
    for _, payload in text_units(pristine_members, source_ranges()):
        for token in __import__("plan_bulk_insertion").tokens(payload):
            index = glyph_index(token, original_lut)
            if index is not None:
                original_used.add(index)

    static_by_cell: dict[tuple[int, int], list[tuple[str, int, int, bool]]] = defaultdict(list)
    static_records = []
    if ASSIGNMENTS.exists():
        with ASSIGNMENTS.open(encoding="utf-8-sig", newline="") as handle:
            for record in csv.DictReader(handle):
                if record.get("kind") != "static" or not record.get("physical_index"):
                    continue
                index = int(record["physical_index"])
                row, rem = divmod(index, INDICES_PER_ROW)
                col, plane = divmod(rem, PLANES)
                one_byte = bool(record.get("code_1byte"))
                static_by_cell[(row, col)].append((record["char"], index, plane, one_byte))
                static_records.append((record["char"], index, row, col, plane, one_byte))

    rows = []
    summaries = {}
    for label, data in builds.items():
        changed = sum(a != b for a, b in zip(pristine, data))
        nonzero_changed = sum(a != 0 and a != b for a, b in zip(pristine, data))
        font_changed_cells = 0
        font_nonzero_changed_cells = 0
        range_changed_cells = 0
        static_cells_changed = 0
        for row in range(FONT_ROWS):
            for col in range(FONT_COLS):
                offsets = list(cell_offsets(row, col))
                cell_changed = sum(pristine[i] != data[i] for i in offsets)
                cell_nonzero_changed = sum(
                    pristine[i] != 0 and pristine[i] != data[i] for i in offsets
                )
                if cell_changed:
                    font_changed_cells += 1
                if cell_nonzero_changed:
                    font_nonzero_changed_cells += 1
                if (row, col) in RANGE_CELLS and cell_changed:
                    range_changed_cells += 1
                if (row, col) in static_by_cell and cell_changed:
                    static_cells_changed += 1
                rows.append({
                    "build": label,
                    "row": row,
                    "column": col,
                    "changed_bytes": cell_changed,
                    "original_nonzero_changed_bytes": cell_nonzero_changed,
                    "known_range_overlay_cell": int((row, col) in RANGE_CELLS),
                    "static_assignments": " | ".join(
                        f"{char}:{index}:p{plane}:{'1B' if one_byte else '2B'}"
                        for char, index, plane, one_byte
                        in static_by_cell.get((row, col), [])
                    ),
                })
        summaries[label] = {
            "archive_sha256": digest(ARCHIVES[label].read_bytes()),
            "comm_sha256": digest(data),
            "changed_bytes": changed,
            "original_nonzero_changed_bytes": nonzero_changed,
            "font_changed_cells": font_changed_cells,
            "font_original_nonzero_changed_cells": font_nonzero_changed_cells,
            "range_overlay_changed_cells": range_changed_cells,
            "static_assignment_cells_changed": static_cells_changed,
        }

    # The strongest control is direct equality: v110 restored these sixteen cells to
    # the pristine disc.  Count exactly how many v163 changed again.
    v110 = builds["v110"]
    v163 = builds["v163"]
    range_v110_not_original = []
    range_v163_not_original = []
    range_v163_not_v110 = []
    for cell in sorted(RANGE_CELLS):
        offsets = list(cell_offsets(*cell))
        if any(v110[i] != pristine[i] for i in offsets):
            range_v110_not_original.append(cell)
        if any(v163[i] != pristine[i] for i in offsets):
            range_v163_not_original.append(cell)
        if any(v163[i] != v110[i] for i in offsets):
            range_v163_not_v110.append(cell)

    # Enumerate static assignments whose destination plane itself differs from the
    # original.  This ties the regression to the allocator rather than proximity.
    static_plane_changes = []
    for cell, assignments in sorted(static_by_cell.items()):
        for char, index, plane, one_byte in assignments:
            before = plane_bits(pristine, index)
            after = plane_bits(v163, index)
            if before != after:
                static_plane_changes.append(
                    (char, index, cell[0], cell[1], plane, one_byte,
                     index in original_used, cell in RANGE_CELLS)
                )

    tier1 = [record for record in static_records if record[1] in original_used]
    tier2_only = [record for record in static_records if record[1] not in original_used]
    one_byte = [record for record in static_records if record[5]]
    one_byte_tier2_only = [record for record in one_byte if record[1] not in original_used]
    range_assignments = [record for record in static_records
                         if (record[2], record[3]) in RANGE_CELLS]

    OUT.mkdir(parents=True, exist_ok=True)
    with (OUT / "cells.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)

    lines = [
        "Arc the Lad v163 COMM.IMG artwork-protection regression audit",
        "",
        f"original_archive_sha256={digest(ORIGINAL.read_bytes())}",
        f"original_comm_sha256={digest(pristine)}",
        f"static_assignments={sum(len(v) for v in static_by_cell.values())}",
        f"static_assignment_cells={len(static_by_cell)}",
        f"static_assignments_original_text_confirmed={len(tier1)}",
        f"static_assignments_original_nonblank_only={len(tier2_only)}",
        f"one_byte_static_assignments={len(one_byte)}",
        f"one_byte_original_nonblank_only={len(one_byte_tier2_only)}",
        "one_byte_original_nonblank_only_chars=" + "".join(r[0] for r in one_byte_tier2_only),
        f"known_range_overlay_static_assignments={len(range_assignments)}",
        "known_range_overlay_assignments=" + " ".join(
            f"{r[0]}:{r[1]}:p{r[4]}:{'1B' if r[5] else '2B'}:"
            f"{'T1' if r[1] in original_used else 'T2'}" for r in range_assignments
        ),
        "",
    ]
    for label in ("v110", "v151", "v163"):
        lines.append(f"[{label}]")
        lines.extend(f"{key}={value}" for key, value in summaries[label].items())
        lines.append("")
    lines += [
        "[known_range_overlay_control]",
        f"v110_cells_not_equal_original={len(range_v110_not_original)} {range_v110_not_original}",
        f"v163_cells_not_equal_original={len(range_v163_not_original)} {range_v163_not_original}",
        f"v163_cells_not_equal_v110={len(range_v163_not_v110)} {range_v163_not_v110}",
        "",
        "[v163_static_plane_changes]",
        f"count={len(static_plane_changes)}",
    ]
    lines.extend(
        f"{char} index={index} row={row} col={col} plane={plane} "
        f"width={'1B' if one_byte else '2B'} "
        f"tier={'original_text' if original_text else 'original_nonblank_only'} "
        f"range_overlay={int(range_overlay)}"
        for char, index, row, col, plane, one_byte, original_text, range_overlay
        in static_plane_changes
    )
    (OUT / "report.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines[:46]))
    print(f"full report: {OUT / 'report.txt'}")
    print(f"cell detail: {OUT / 'cells.csv'}")


if __name__ == "__main__":
    main()
