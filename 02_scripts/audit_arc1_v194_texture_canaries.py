#!/usr/bin/env python3
"""Release canaries for the v194 font/cache layout.

This audit turns the v182 skill-range regression into a build-time failure.
It accepts one or more patch ZIPs and checks that:

* no new original-blank COMM.IMG cell is occupied;
* the seven deliberate punctuation/button cells remain byte-identical to v194;
* the two former Hangul cells and the live skill-range source are restored;
* the level-up banner and EA9B/함 dynamic lookup remain intact; and
* bounded dynamic-cache pressure does not exceed the 28-slot cache.

The v194 archive is an immutable byte baseline, guarded by its SHA-256.  This
script does not modify archives or any source file.
"""
from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))

import build_arc1_v171_ui_asset_recovery as v171  # noqa: E402
import build_arc1_v193_restore_skill_range_levelup_dynamic as v193  # noqa: E402
import plan_arc1_v171_ui_asset_recovery as plan171  # noqa: E402


ORIGINAL = ROOT / "00_original/arc.zip"
BASELINE = ROOT / "03_output/arc1_v194_remove_last_blank_cell_hangul_63FE7FD6.zip"
BASELINE_SHA256 = "63FE7FD64A1FCCC005139AE6AC71A62D3DE2109D930B40EF43D747269EE9D744"
PSX, COMM = "PSX.EXE", "COMM.IMG"
ROW_BYTES = 896
CELL = 12
ATLAS_WIDTH = ROW_BYTES * 2
LOOKUP_SLOT = 408  # EA 9B
EXPECTED_LOOKUP = plan171.DYNAMIC_TAG + 224
EXPECTED_BLANK_CHANGED = (
    (12, 11),
    (12, 18),
    (19, 15),
    (19, 16),
    (19, 17),
    (19, 18),
    (19, 19),
)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def cell_bytes(font: bytes, row: int, col: int) -> bytes:
    """Return one complete 12x12 physical cell (all four bitplanes)."""
    start_x = col * 6  # two 4bpp pixels per byte
    return b"".join(
        font[(row * CELL + y) * ROW_BYTES + start_x:
             (row * CELL + y) * ROW_BYTES + start_x + 6]
        for y in range(CELL)
    )


def blank_changed_cells(original: bytes, current: bytes) -> tuple[tuple[int, int], ...]:
    result: list[tuple[int, int]] = []
    for row in range(512 // CELL):
        for col in range(ATLAS_WIDTH // CELL):
            old = cell_bytes(original, row, col)
            new = cell_bytes(current, row, col)
            if old != new and not any(old):
                result.append((row, col))
    return tuple(result)


def inspect(path: Path, original: bytes, baseline_font: bytes) -> list[str]:
    with ZipFile(path) as archive:
        names = archive.namelist()
        if PSX not in names or COMM not in names:
            raise AssertionError("PSX.EXE or COMM.IMG is missing")
        members = {name: archive.read(name) for name in names}
        exe = members[PSX]
        font = members[COMM]

    changed_blank = blank_changed_cells(original, font)
    if changed_blank != EXPECTED_BLANK_CHANGED:
        raise AssertionError(
            f"original-blank cell set differs: {changed_blank}; "
            f"expected {EXPECTED_BLANK_CHANGED}"
        )
    for row, col in EXPECTED_BLANK_CHANGED:
        if cell_bytes(font, row, col) != cell_bytes(baseline_font, row, col):
            raise AssertionError(f"approved UI cell changed: row={row} col={col}")

    for row, col, label in ((11, 3, "skill-range/LV cell"), (14, 16, "old 함 cell")):
        if cell_bytes(font, row, col) != cell_bytes(original, row, col):
            raise AssertionError(f"{label} is no longer original-exact")

    range_diff = v193.range_differences(original, font)
    if range_diff != [v193.EXPECTED_INHERITED_RANGE_DIFF]:
        raise AssertionError(f"live skill-range texture source differs: {range_diff[:12]}")

    payload = exe[v193.LEVELUP_PAYLOAD_OFFSET:v193.LEVELUP_PAYLOAD_OFFSET + len(v193.NEW_LEVELUP)]
    if payload != v193.NEW_LEVELUP:
        raise AssertionError("level-up payload is not 레벨 상승!!")

    lookup_at = v171.old.file_at(v171.PACKED_LOOKUP_RAM)
    lookup = plan171.unpack_fixed(exe[lookup_at:lookup_at + 568], 413, 11)
    if lookup[LOOKUP_SLOT] != EXPECTED_LOOKUP:
        raise AssertionError(
            f"EA9B lookup is {lookup[LOOKUP_SLOT]}, expected {EXPECTED_LOOKUP}"
        )

    maximum, owner, units = v193.dynamic_pressure(members)
    if maximum > v171.CACHE_N:
        raise AssertionError(f"dynamic pressure exceeds cache: {maximum}/{v171.CACHE_N}")

    return [
        f"PASS {path}",
        f"sha256={digest(path.read_bytes())}",
        "original_blank_changed=7/7 exact approved UI cells",
        "ordinary_Hangul_in_original_blank_cells=0",
        "skill_range_source=original-exact except inherited pixel (54,128 9->11)",
        "levelup=레벨 상승!!",
        "EA9B=dynamic source 224=함",
        f"dynamic_pressure={maximum}/{v171.CACHE_N}",
        f"pressure_owner={owner}",
        f"pressure_units={units}",
    ]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("archives", nargs="+", type=Path, help="patch ZIP(s) to audit")
    args = parser.parse_args()

    if digest(BASELINE.read_bytes()) != BASELINE_SHA256:
        raise SystemExit("v194 baseline archive hash differs")
    with ZipFile(ORIGINAL) as archive:
        original = archive.read(COMM)
    with ZipFile(BASELINE) as archive:
        baseline_font = archive.read(COMM)

    failed = False
    for path in args.archives:
        try:
            lines = inspect(path.resolve(), original, baseline_font)
        except Exception as exc:  # release gate: print every requested result
            failed = True
            print(f"FAIL {path}: {exc}")
        else:
            print("\n".join(lines))
    if failed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
