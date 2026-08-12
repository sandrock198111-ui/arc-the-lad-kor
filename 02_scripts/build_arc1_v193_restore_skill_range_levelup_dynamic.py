#!/usr/bin/env python3
"""Build v193: restore the skill-range texture and keep level-up Korean.

v182 placed a compact ``LV``, ``상`` and ``승`` in a cell that is transparent
in the original COMM.IMG.  Runtime packet tracing later proved that the four
arms of a levelled skill-range cursor sample that exact cell.  A zero cell was
therefore part of the cursor artwork, not free font storage.

This build restores the complete cell from the original atlas.  The level-up
banner is changed in-place from the three private static glyphs to
``레벨 상승!!``.  ``레``, ``벨`` and ``상`` already have proven dynamic-cache
owners, while ``승`` and the exclamation mark remain proven static glyphs.  No
cache data, resident routine, lookup table, DAT member or pointer is changed.
"""
from __future__ import annotations

import csv
import hashlib
import struct
import sys
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))

import build_arc1_v171_ui_asset_recovery as v171  # noqa: E402
import plan_arc1_v171_ui_asset_recovery as plan171  # noqa: E402
import plan_arc1_v190_dynamic_owner_repair as plan190  # noqa: E402
from audit_comm_physical_cell_safety import (  # noqa: E402
    active_slot_units,
    body_units,
    exe_units,
)
from audit_dynamic_cache_requirements import source_ranges  # noqa: E402
from plan_bulk_insertion import tokens  # noqa: E402


BASE = ROOT / "03_output/arc1_v192_choice_speaker_rows_899DDD9A.zip"
BASE_SHA256 = "899DDD9A4D22B80AD9229605461C25ABA0FE79FAC6B1533D2A9AE1ABC5B22A35"
ORIGINAL = ROOT / "00_original/arc.zip"
ORIGINAL_SHA256 = "AE9F4366A1E7DA3805BB3BED3DDA9567E4CD4E669AF890E4E2A620D7861F11DD"

OUT_DIR = ROOT / "03_output"
OUT_STEM = "arc1_v193_restore_skill_range_levelup_dynamic"
ANALYSIS = ROOT / "01_work/analysis" / OUT_STEM
REPORT = ANALYSIS / "build_report.txt"
PIXEL_AUDIT = ANALYSIS / "skill_range_pixel_audit.csv"

PSX, COMM = "PSX.EXE", "COMM.IMG"
ROW_BYTES = 896
CELL = 12
CELL_ROW, CELL_COL = 11, 3

LEVELUP_POINTER_OFFSET = 0x82518
LEVELUP_PAYLOAD_OFFSET = 0x854C8
LEVELUP_POINTER = 0x8019FCC8
OLD_LEVELUP = bytes.fromhex("DF CF 9C DF D0 DF D1 DF E3 DF E3 00")
NEW_LEVELUP = bytes.fromhex("DF E8 E1 EA 9C CD 8E DF E3 DF E3 00")

# The live range packets sample two 33x33 sprite rectangles at U=0 and U=32.
# Their union is x=0..64/y=128..160.  v181 has one accepted low-bit change at
# the upper edge; v182 added the visible Hangul in row 11 column 3.
RANGE_X0, RANGE_X1 = 0, 64
RANGE_Y0, RANGE_Y1 = 128, 160
EXPECTED_INHERITED_RANGE_DIFF = (54, 128, 9, 11)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def clone(info: ZipInfo) -> ZipInfo:
    result = ZipInfo(info.filename, info.date_time)
    for attr in (
        "compress_type", "comment", "extra", "create_system", "create_version",
        "extract_version", "flag_bits", "volume", "internal_attr", "external_attr",
    ):
        setattr(result, attr, getattr(info, attr))
    return result


def pixel(data: bytes | bytearray, x: int, y: int) -> int:
    value = data[y * ROW_BYTES + x // 2]
    return (value >> (4 * (x & 1))) & 0x0F


def restore_cell(target: bytearray, original: bytes, row: int, col: int) -> None:
    for y in range(CELL):
        at = (row * CELL + y) * ROW_BYTES + col * (CELL // 2)
        target[at:at + CELL // 2] = original[at:at + CELL // 2]


def range_differences(
    original: bytes, current: bytes | bytearray
) -> list[tuple[int, int, int, int]]:
    return [
        (x, y, pixel(original, x, y), pixel(current, x, y))
        for y in range(RANGE_Y0, RANGE_Y1 + 1)
        for x in range(RANGE_X0, RANGE_X1 + 1)
        if pixel(original, x, y) != pixel(current, x, y)
    ]


def read_manifest() -> list[dict[str, str]]:
    with plan190.SOURCE_MANIFEST.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def dynamic_pressure(members: dict[str, bytes]) -> tuple[int, str, int]:
    """Return exact bounded maximum, its owner label and measured owner count."""
    exe = members[PSX]
    lookup_at = v171.old.file_at(v171.PACKED_LOOKUP_RAM)
    lookup_bytes = exe[lookup_at:lookup_at + 568]
    lookup = plan171.unpack_fixed(lookup_bytes, plan190.LOOKUP_N, plan190.LOOKUP_BITS)
    manifest = read_manifest()
    direct = {
        int(row["old_physical_index"]): int(row["source_id"])
        for row in manifest if row["old_physical_index"]
    }
    units = (
        list(body_units(members, source_ranges()))
        + list(active_slot_units(members, source_ranges()))
        + list(exe_units(members))
    )
    measured: list[tuple[int, str]] = []
    for label, payload in units:
        active = {
            source
            for token in tokens(payload)
            if (
                source := plan190.source_for_token(token, lookup, direct)
            ) is not None
        }
        if active:
            measured.append((len(active), label))
    measured.sort(reverse=True)
    return (*measured[0], len(units)) if measured else (0, "", len(units))


def levelup_dynamic_sources(exe: bytes) -> tuple[int, ...]:
    lookup_at = v171.old.file_at(v171.PACKED_LOOKUP_RAM)
    lookup = plan171.unpack_fixed(
        exe[lookup_at:lookup_at + 568], plan190.LOOKUP_N, plan190.LOOKUP_BITS
    )
    manifest = read_manifest()
    direct = {
        int(row["old_physical_index"]): int(row["source_id"])
        for row in manifest if row["old_physical_index"]
    }
    return tuple(sorted({
        source
        for token in tokens(NEW_LEVELUP[:-1])
        if (
            source := plan190.source_for_token(token, lookup, direct)
        ) is not None
    }))


def main() -> None:
    if digest(BASE.read_bytes()) != BASE_SHA256:
        raise SystemExit("v192 base archive hash differs")
    if digest(ORIGINAL.read_bytes()) != ORIGINAL_SHA256:
        raise SystemExit("original archive hash differs")

    with ZipFile(BASE) as archive:
        infos = archive.infolist()
        members = {info.filename: archive.read(info.filename) for info in infos}
    with ZipFile(ORIGINAL) as archive:
        original_font = archive.read(COMM)
    before = dict(members)

    exe = bytearray(members[PSX])
    font = bytearray(members[COMM])
    if bytes(exe[LEVELUP_PAYLOAD_OFFSET:LEVELUP_PAYLOAD_OFFSET + len(OLD_LEVELUP)]) != OLD_LEVELUP:
        raise SystemExit("v192 level-up payload differs")
    if struct.unpack_from("<I", exe, LEVELUP_POINTER_OFFSET)[0] != LEVELUP_POINTER:
        raise SystemExit("v192 level-up pointer differs")

    # v182's three private planes are the only new visible corruption inside
    # this complete cell.  Restore all four planes together; partial-plane
    # restoration is unsafe because the GPU combines them as one 4bpp pixel.
    restore_cell(font, original_font, CELL_ROW, CELL_COL)
    exe[LEVELUP_PAYLOAD_OFFSET:LEVELUP_PAYLOAD_OFFSET + len(NEW_LEVELUP)] = NEW_LEVELUP
    members[PSX], members[COMM] = bytes(exe), bytes(font)

    cell_start_y = CELL_ROW * CELL
    cell_start_x = CELL_COL * CELL
    if any(
        pixel(members[COMM], cell_start_x + x, cell_start_y + y)
        != pixel(original_font, cell_start_x + x, cell_start_y + y)
        for y in range(CELL) for x in range(CELL)
    ):
        raise SystemExit("restored skill-range cell is not original-exact")
    range_after = range_differences(original_font, members[COMM])
    if range_after != [EXPECTED_INHERITED_RANGE_DIFF]:
        raise SystemExit(f"skill-range source still differs unexpectedly: {range_after[:8]}")

    if levelup_dynamic_sources(members[PSX]) != (32, 144, 247):
        raise SystemExit("level-up dynamic sources are not exactly 상/레/벨")
    maximum, maximum_owner, owner_units = dynamic_pressure(members)
    if maximum != 26 or maximum > v171.CACHE_N:
        raise SystemExit(f"bounded dynamic pressure is {maximum}/{v171.CACHE_N}")

    psx_diffs = [
        offset for offset, (left, right) in enumerate(zip(before[PSX], members[PSX]))
        if left != right
    ]
    allowed_psx = set(range(LEVELUP_PAYLOAD_OFFSET, LEVELUP_PAYLOAD_OFFSET + len(NEW_LEVELUP)))
    if not psx_diffs or any(offset not in allowed_psx for offset in psx_diffs):
        raise SystemExit("PSX.EXE changed outside the level-up payload")
    comm_diffs = sum(left != right for left, right in zip(before[COMM], members[COMM]))
    if comm_diffs != 46:
        raise SystemExit(f"COMM.IMG changed {comm_diffs} bytes, expected 46")
    if any(len(members[name]) != len(before[name]) for name in members):
        raise SystemExit("archive member length changed")
    changed = sorted(name for name in members if members[name] != before[name])
    if changed != [COMM, PSX]:
        raise SystemExit(f"changed member set differs: {changed}")

    ANALYSIS.mkdir(parents=True, exist_ok=True)
    with PIXEL_AUDIT.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(("x", "y", "original_nibble", "v193_nibble", "status"))
        writer.writerow((*EXPECTED_INHERITED_RANGE_DIFF, "accepted_v181_single_pixel"))

    temporary = OUT_DIR / f"{OUT_STEM}_building.zip"
    if temporary.exists():
        raise SystemExit(f"refusing to overwrite temporary output: {temporary}")
    with ZipFile(temporary, "w", ZIP_DEFLATED) as archive:
        for info in infos:
            archive.writestr(clone(info), members[info.filename])
    with ZipFile(temporary) as archive:
        if archive.namelist() != [info.filename for info in infos]:
            raise SystemExit("archive member order changed")
        for name, expected in members.items():
            if archive.read(name) != expected:
                raise SystemExit(f"archive roundtrip differs: {name}")
    stamp = digest(temporary.read_bytes())
    output = OUT_DIR / f"{OUT_STEM}_{stamp[:8]}.zip"
    if output.exists():
        raise SystemExit(f"refusing to overwrite existing output: {output}")
    temporary.replace(output)

    report = [
        "v193 restore skill-range source and keep Korean level-up via existing dynamic cache",
        f"base={BASE.name}",
        f"base_sha256={BASE_SHA256}",
        f"output={output.name}",
        f"sha256={stamp}",
        "root_cause=v182 wrote LV/상/승 into transparent pixels sampled by cross arms",
        "restored_cell=row11,col3 all four planes original-exact PASS",
        "range_source=x0..64,y128..160; v182 Hangul removed PASS",
        "range_source_remaining_diff=1 inherited v181 pixel at x54,y128",
        "levelup_payload=레벨 상승!!",
        f"levelup_payload_hex={NEW_LEVELUP.hex(' ').upper()}",
        "levelup_dynamic_sources=상:32,레:144,벨:247",
        "levelup_static_sources=승 and ! unchanged",
        f"bounded_max_simultaneous_dynamic={maximum}/{v171.CACHE_N}",
        f"bounded_max_owner={maximum_owner}",
        f"bounded_owner_units={owner_units}",
        "dynamic_cache_layout=byte-identical to v192 PASS",
        "lookup_table=byte-identical to v192 PASS",
        "resident_code=byte-identical to v192 PASS",
        "all_DAT_members=byte-identical to v192 PASS",
        f"PSX_payload_changed_bytes={len(psx_diffs)}",
        f"COMM_restored_bytes={comm_diffs}",
        "decoder 0x801FF348 / 568 bytes",
        "frame routine 0x801FF668 / 584 bytes",
        "huffman 0x801FF580 / 232 bytes",
        "resident_used=5356/5356",
        "resident_free=0",
        "heap_boundary=0x801FF8B0 unchanged",
        "startup_copy=5356 unchanged",
        f"changed_members={','.join(changed)}",
        "archive_member_order=PASS",
        "archive_member_lengths=PASS",
        "archive_roundtrip=PASS",
        "emulator_run=NO",
        "runtime=PENDING user cold boot",
        "rollback=v192",
    ]
    REPORT.write_text("\n".join(report) + "\n", encoding="utf-8")
    print("\n".join(report))
    print(REPORT)


if __name__ == "__main__":
    main()
