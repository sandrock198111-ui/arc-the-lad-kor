#!/usr/bin/env python3
"""Build v194: remove the last Hangul stored in an original-blank cell.

v193 repairs the runtime-proven skill-range collision.  A complete atlas audit
then leaves one more ordinary Hangul placement of the same unsafe class:
v181 put ``함`` at physical index 1240 (row 14, column 16, plane 0), although
that complete cell is transparent in the original game.

The dynamic library already contains the exact same 12x12 ``함`` bitmap as
source 224.  This build changes only lookup entry EA 9B from static physical
1240 to dynamic source 224 and restores the complete cell from the original.
The seven remaining original-blank changed cells are direct punctuation/button
assets and are deliberately outside this repair.
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
import build_arc1_v193_restore_skill_range_levelup_dynamic as v193  # noqa: E402
import plan_arc1_v171_ui_asset_recovery as plan171  # noqa: E402
import plan_arc1_v190_dynamic_owner_repair as plan190  # noqa: E402
import verify_arc1_v191_yagun_choice_local_fixes as runtime  # noqa: E402


BASE = ROOT / "03_output/arc1_v193_restore_skill_range_levelup_dynamic_946B3F5E.zip"
BASE_SHA256 = "946B3F5ECB1606425D40E34DCFB2FE89A0A1E366A5E45176979A0A0DB29141D4"
ORIGINAL = ROOT / "00_original/arc.zip"
ORIGINAL_SHA256 = v193.ORIGINAL_SHA256
OUT_DIR = ROOT / "03_output"
OUT_STEM = "arc1_v194_remove_last_blank_cell_hangul"
ANALYSIS = ROOT / "01_work/analysis" / OUT_STEM
REPORT = ANALYSIS / "build_report.txt"

PSX, COMM = "PSX.EXE", "COMM.IMG"
ROW, COL, PHYSICAL = 14, 16, 1240
LOOKUP_SLOT = 408                         # EA 9B
OLD_LOOKUP = PHYSICAL
SOURCE = 224
NEW_LOOKUP = plan171.DYNAMIC_TAG + SOURCE
PACKED_N = 568


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


def atlas_rows(font: bytes | bytearray, index: int) -> tuple[int, ...]:
    bits = v171.plane_bitmap(font, index)
    return tuple(
        sum(bits[y * v193.CELL + x] << (v193.CELL - 1 - x) for x in range(v193.CELL))
        for y in range(v193.CELL)
    )


def blank_refilled_cells(original: bytes, current: bytes) -> list[tuple[int, int]]:
    result: list[tuple[int, int]] = []
    for row in range(512 // v193.CELL):
        for col in range(1792 // v193.CELL):
            old = b"".join(
                original[(row * v193.CELL + y) * v193.ROW_BYTES + col * 6:][:6]
                for y in range(v193.CELL)
            )
            new = b"".join(
                current[(row * v193.CELL + y) * v193.ROW_BYTES + col * 6:][:6]
                for y in range(v193.CELL)
            )
            if old != new and not any(old):
                result.append((row, col))
    return result


def main() -> None:
    if digest(BASE.read_bytes()) != BASE_SHA256:
        raise SystemExit("v193 base archive hash differs")
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
    lookup_at = v171.old.file_at(v171.PACKED_LOOKUP_RAM)
    lookup = plan171.unpack_fixed(exe[lookup_at:lookup_at + PACKED_N], plan190.LOOKUP_N, 11)
    if lookup[LOOKUP_SLOT] != OLD_LOOKUP:
        raise SystemExit(f"EA 9B lookup is {lookup[LOOKUP_SLOT]}, expected 1240")

    sources, manifest = plan190.decode_old_sources()
    source_row = manifest[SOURCE]
    if source_row["char"] != "\ud568" or int(source_row["old_physical_index"]) != 1449:
        raise SystemExit("dynamic source 224 provenance differs")
    if atlas_rows(font, PHYSICAL) != tuple(sources[SOURCE]):
        raise SystemExit("physical 1240 and dynamic source 224 bitmaps differ")

    lookup[LOOKUP_SLOT] = NEW_LOOKUP
    lookup_blob = plan171.pack_fixed(lookup, 11)
    if len(lookup_blob) != PACKED_N:
        raise SystemExit("repacked lookup length changed")
    exe[lookup_at:lookup_at + PACKED_N] = lookup_blob
    v193.restore_cell(font, original_font, ROW, COL)
    members[PSX], members[COMM] = bytes(exe), bytes(font)

    check_lookup = plan171.unpack_fixed(
        members[PSX][lookup_at:lookup_at + PACKED_N], plan190.LOOKUP_N, 11
    )
    if check_lookup[LOOKUP_SLOT] != NEW_LOOKUP:
        raise SystemExit("EA 9B dynamic lookup readback differs")
    if runtime.runtime_decoder(members[PSX])(bytes.fromhex("EA 9B")) != "\ud568":
        raise SystemExit("EA 9B no longer decodes as 함")
    if atlas_rows(members[COMM], PHYSICAL) != (0,) * v193.CELL:
        raise SystemExit("physical 1240 did not return to the original blank bitmap")

    maximum, maximum_owner, owner_units = v193.dynamic_pressure(members)
    if maximum != 26 or maximum > v171.CACHE_N:
        raise SystemExit(f"bounded dynamic pressure is {maximum}/{v171.CACHE_N}")
    blank_cells = blank_refilled_cells(original_font, members[COMM])
    expected_blank_cells = [
        (12, 11), (12, 18),
        (19, 15), (19, 16), (19, 17), (19, 18), (19, 19),
    ]
    if blank_cells != expected_blank_cells:
        raise SystemExit(f"remaining original-blank changed cells differ: {blank_cells}")

    psx_diffs = [
        i for i, pair in enumerate(zip(before[PSX], members[PSX])) if pair[0] != pair[1]
    ]
    # slot 408 begins at bit 408*11 = 4488, i.e. packed byte 561.
    if psx_diffs != [lookup_at + 561, lookup_at + 562]:
        raise SystemExit(f"packed lookup diff offsets differ: {psx_diffs}")
    comm_diffs = sum(a != b for a, b in zip(before[COMM], members[COMM]))
    if comm_diffs != 32:
        raise SystemExit(f"COMM restore count is {comm_diffs}, not 32")
    changed = sorted(name for name in members if members[name] != before[name])
    if changed != [COMM, PSX]:
        raise SystemExit(f"changed member set differs: {changed}")
    if any(len(members[name]) != len(before[name]) for name in members):
        raise SystemExit("member length changed")
    if members[PSX][v193.LEVELUP_PAYLOAD_OFFSET:v193.LEVELUP_PAYLOAD_OFFSET + 12] != v193.NEW_LEVELUP:
        raise SystemExit("v193 level-up repair regressed")
    if v193.range_differences(original_font, members[COMM]) != [v193.EXPECTED_INHERITED_RANGE_DIFF]:
        raise SystemExit("v193 skill-range repair regressed")

    temporary = OUT_DIR / f"{OUT_STEM}_building.zip"
    if temporary.exists():
        raise SystemExit(f"refusing to overwrite temporary output: {temporary}")
    with ZipFile(temporary, "w", ZIP_DEFLATED) as archive:
        for info in infos:
            archive.writestr(clone(info), members[info.filename])
    with ZipFile(temporary) as archive:
        if archive.namelist() != [info.filename for info in infos]:
            raise SystemExit("member order changed")
        for name, expected in members.items():
            if archive.read(name) != expected:
                raise SystemExit(f"archive roundtrip differs: {name}")
    stamp = digest(temporary.read_bytes())
    output = OUT_DIR / f"{OUT_STEM}_{stamp[:8]}.zip"
    if output.exists():
        raise SystemExit(f"refusing to overwrite existing output: {output}")
    temporary.replace(output)

    report = [
        "v194 remove last ordinary Hangul from an original-blank atlas cell",
        f"base={BASE.name}",
        f"base_sha256={BASE_SHA256}",
        f"output={output.name}",
        f"sha256={stamp}",
        "EA9B=함 preserved through dynamic source 224 PASS",
        "source224_equals_old_physical1240=12x12 exact PASS",
        "row14_col16=original-exact transparent PASS",
        "remaining_original_blank_changed_cells=7 direct punctuation/button assets",
        f"bounded_max_simultaneous_dynamic={maximum}/{v171.CACHE_N}",
        f"bounded_max_owner={maximum_owner}",
        f"bounded_owner_units={owner_units}",
        "v193_skill_range_restore=preserved PASS",
        "v193_levelup_레벨_상승=preserved PASS",
        "all_DAT_members=byte-identical to v193 PASS",
        f"PSX_lookup_changed_bytes={len(psx_diffs)}",
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
        "rollback=v193; v192 before both repairs",
    ]
    ANALYSIS.mkdir(parents=True, exist_ok=True)
    REPORT.write_text("\n".join(report) + "\n", encoding="utf-8")
    print("\n".join(report))
    print(REPORT)


if __name__ == "__main__":
    main()
