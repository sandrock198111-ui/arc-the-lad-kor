#!/usr/bin/env python3
"""Independent static verifier for Arc the Lad 1 V338 TEST_ONLY.

The verifier does not call the V338 builder.  It reopens V337/V338, derives
the complete byte diff, re-parses all known text regions, re-reads 4bpp font
planes, and checks the level-up helper as an exact R3000 instruction payload.
"""

from __future__ import annotations

import csv
import hashlib
import json
import struct
import sys
from pathlib import Path
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

BASE = ROOT / "03_output/arc1_v337_damage_remap_branch_fix_TEST_ONLY_2AB80515.zip"
FULL = ROOT / "03_output/arc1_v338_v197_v210_catchup_TEST_ONLY_29CEF6F5.zip"
DELTA = ROOT / "03_output/arc1_v338_v197_v210_catchup_TEST_ONLY_delta_from_v337_DF2B9665.zip"
ANALYSIS = ROOT / "01_work/analysis/arc1_v338_v197_v210_catchup"
ORIGINAL_CSV = ROOT / "05_docs/script_original_full.csv"
ATLAS_MAPPING = ROOT / "01_work/analysis/arc1_v319_pilgi16_integration/atlas_mapping.csv"

HASHES = {
    BASE: "2AB80515D70E84F34F83A919FC63F16AFDEDA57342FAE4F40180E841DCF3E856",
    FULL: "29CEF6F5ADF4461C9263B39586222F7B88EEEE3DF0D6BEDFE5F0C5695509A777",
    DELTA: "DF2B9665D92E37813D5CDD737C0637838449B894024AA369C55ADE79560E94CA",
}

PSX = "PSX.EXE"
COMM = "COMM.IMG"
RAM_TO_FILE = 0x8011A800
EXPECTED_CHANGED = {
    "21/S2014.DAT": 24,
    "21/S2022.DAT": 8,
    "4/S4011.DAT": 28,
    "4/S4021.DAT": 24,
    "4/S4022.DAT": 46,
    "4/S4031.DAT": 16,
    COMM: 60,
    PSX: 71,
}

REGION_COUNT = 8595
BASE_REGION_FP = "B5738225DEF9DAB650974520C0424E35CCB53FFC59EB403B498FF0F7E30BC764"
FULL_REGION_FP = "82A58955B8A066A12AE43D4033CB1CEBA12011A2FF55CD3A718080BEAA227BF7"

SOLDIER_STEM = bytes.fromhex("82 34")
SOLDIER_CODES = {1: 0x4A, 2: 0x0B, 3: 0x27}
SOLDIER_BASE_COUNTS = {1: 18, 2: 11, 3: 1}
COLON = bytes.fromhex("DD 02")
SPACE = 0xA1

REFIT_OLD = bytes.fromhex("DD B4 31 DD 06")
REFIT_NEW = bytes.fromhex("DE 52 31 DD 06")

MISSED_MEMBER = "4/S4031.DAT"
MISSED_AT = 0x478EC
MISSED_OLD = bytes.fromhex("8E DD 2D 54 26 1E 4B 27 29 1F 2D 35 DF 61 DF 61 3C")
MISSED_NEW = bytes.fromhex("37 DD 90 A1 5F DD A0 A1 6B DD 01 49 21 21 21 D1 A1")

QUANTITY_AT = 0x80A40
LEVEL_ENDS = (0x81A1E, 0x813E5, 0x815A3, 0x8060B, 0x80785, 0x81613)
LEVEL_POINTER_SLOTS = (0x8251C, 0x82520, 0x82524, 0x82528, 0x8252C, 0x82530)
LEVEL_PARTICLE = 0x03
LEVEL_PARTICLE_PHYSICAL = LEVEL_PARTICLE - 1
LEVEL_SEPARATOR_AT = 0x854D4
LEVEL_SUFFIX_PTR_AT = 0x82538
LEVEL_SUFFIX_NEW_AT = 0x854F0
LEVEL_CALL_AT = 0x45C64
LEVEL_CALL_DELAY_AT = 0x45C68
GLOBAL_CONVERTER_JAL = 0x0C057930
HELPER_RAM = 0x801FF858
HELPER_AT = 0x8F380
HELPER_CAPACITY = 0x58
HELPER_WORDS = (
    0x90820000, 0x3C098020, 0x1040000E, 0x2443FFD0, 0x2C68000A,
    0x11000008, 0x2529F8A4, 0x01234821, 0x91220000, 0x00000000,
    0xA0820000, 0x24840001, 0x1000FFF3, 0x00000000, 0x244200E1,
    0x1000FFFA, 0x00000000, 0x03E00008, 0x00000000,
)
DIGIT_TABLE = bytes((0x91, 0x4A, 0x0B, 0x27, 0x57, 0x9E, 0x9F, 0x9A, 0x10, 0x08))
FORBIDDEN_AT = 0x8F3D8
FORBIDDEN_SIZE = 0x428

QUESTION_PLANES = (208, 222)
QUESTION_BEFORE = (
    0x0000, 0x0000, 0x7C00, 0xC600, 0xC600, 0x0C00, 0x1800, 0x1800,
    0x1800, 0x0000, 0x1800, 0x1800, 0x0000, 0x0000, 0x0000, 0x0000,
)
QUESTION_AFTER = tuple(row >> 2 for row in QUESTION_BEFORE)

ROW_BYTES = 896
COLS = 15
PLANES = 4
CELL = 16
SLOT_BASE = 0x45000
SLOT_SIZE = 0x80
EXE_POOL = (0x78000, 0x83000)


class VerifyError(RuntimeError):
    pass


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest().upper()


def read_zip(path: Path) -> tuple[list[str], dict[str, bytes]]:
    with ZipFile(path) as archive:
        names = [item.filename for item in archive.infolist() if not item.is_dir()]
        return names, {name: archive.read(name) for name in names}


def word(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def changed_offsets(before: bytes, after: bytes) -> set[int]:
    if len(before) != len(after):
        raise VerifyError("member length changed")
    return {i for i, (old, new) in enumerate(zip(before, after, strict=True)) if old != new}


def region_fingerprint(regions: list[tuple[str, int, int]]) -> str:
    digest = hashlib.sha256()
    for name, start, end in regions:
        digest.update(name.encode("utf-8"))
        digest.update(struct.pack("<II", start, end))
    return digest.hexdigest().upper()


def source_ranges() -> list[tuple[str, int, int]]:
    result: list[tuple[str, int, int]] = []
    with ORIGINAL_CSV.open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        key = "offset" if "offset" in (reader.fieldnames or []) else "byte offset"
        for row in reader:
            raw = bytes.fromhex(row["raw bytes as hex"].replace(" ", ""))
            result.append((row["source file"], int(row[key], 0), len(raw)))
    return result


def disk_slot(value: int) -> int | None:
    if 0x81 <= value <= 0xA8:
        return value - 0x81
    if 0xAA <= value <= 0xD0:
        return value - 0x82
    return None


def independent_text_regions(members: dict[str, bytes]) -> list[tuple[str, int, int]]:
    ranges = source_ranges()
    result: list[tuple[str, int, int]] = []
    for name, offset, size in ranges:
        if name in members and offset + size <= len(members[name]):
            result.append((name, offset, offset + size))

    active: dict[str, set[int]] = {}
    for name, offset, _ in ranges:
        if name not in members or offset + 2 > len(members[name]):
            continue
        head = members[name][offset:offset + 2]
        if len(head) != 2 or head[0] != 0xE2:
            continue
        slot = disk_slot(head[1])
        if slot is None:
            continue
        slots = active.setdefault(name, set())
        if slot in slots:
            raise VerifyError(f"duplicate active slot: {name}:{slot}")
        slots.add(slot)
    for name, slots in active.items():
        data = members[name]
        for slot in sorted(slots):
            start = SLOT_BASE + slot * SLOT_SIZE
            block = data[start:start + SLOT_SIZE]
            if 0 not in block:
                raise VerifyError(f"active slot lacks NUL: {name}:{slot}")
            end = block.index(0)
            if end:
                result.append((name, start, start + end))

    exe = members[PSX]
    start = EXE_POOL[0]
    for cursor in range(EXE_POOL[0], EXE_POOL[1]):
        if exe[cursor] != 0:
            continue
        if cursor > start:
            result.append((PSX, start, cursor))
        start = cursor + 1
    return result


def aligned_pointer_refs(data: bytes, address: int) -> list[int]:
    return [at for at in range(0, len(data) - 3, 4) if word(data, at) == address]


def atlas_row(index: int) -> dict[str, str]:
    with ATLAS_MAPPING.open(encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    if index >= len(rows) or int(rows[index]["index"]) != index:
        raise VerifyError(f"atlas row missing: {index}")
    return rows[index]


def tokens(data: bytes, start: int, end: int):
    at = start
    while at < end:
        value = data[at]
        if value == 0:
            return
        width = 1 if value < 0xDD or at + 1 >= end else 2
        yield at, data[at:at + width]
        at += width


def controls(data: bytes, start: int, end: int) -> tuple[tuple[int, bytes], ...]:
    return tuple(
        (at - start, token)
        for at, token in tokens(data, start, end)
        if len(token) == 2 and 0xE1 <= token[0] <= 0xE8
    )


def count_in_regions(members: dict[str, bytes], regions: list[tuple[str, int, int]], needle: bytes) -> int:
    return sum(members[name][start:end].count(needle) for name, start, end in regions)


def read_plane(data: bytes, index: int) -> tuple[int, ...]:
    cell, plane = divmod(index, PLANES)
    col, row = cell % COLS, cell // COLS
    bit = 1 << plane
    rows: list[int] = []
    for y in range(CELL):
        value = 0
        base = (row * CELL + y) * ROW_BYTES + col * (CELL // 2)
        for x in range(CELL):
            packed = data[base + x // 2]
            nibble = (packed >> (0 if x % 2 == 0 else 4)) & 0xF
            if nibble & bit:
                value |= 1 << (15 - x)
        rows.append(value)
    return tuple(rows)


def jal(address: int) -> int:
    return 0x0C000000 | ((address >> 2) & 0x03FFFFFF)


def direct_targets(exe: bytes, lo: int, hi: int) -> list[tuple[int, int, str]]:
    text_size = word(exe, 0x1C)
    hits: list[tuple[int, int, str]] = []
    for at in range(0x800, min(len(exe), 0x800 + text_size), 4):
        ins = word(exe, at)
        op = ins >> 26
        pc = at + RAM_TO_FILE
        target = None
        kind = ""
        if op in (2, 3):
            target = ((pc + 4) & 0xF0000000) | ((ins & 0x03FFFFFF) << 2)
            kind = "jal" if op == 3 else "j"
        elif op in (4, 5, 6, 7):
            immediate = ins & 0xFFFF
            if immediate & 0x8000:
                immediate -= 0x10000
            target = (pc + 4 + immediate * 4) & 0xFFFFFFFF
            kind = "branch"
        if target is not None and lo <= target < hi:
            hits.append((pc, target, kind))
    return hits


def verify_expected_write_csv(actual: dict[str, set[int]], before: dict[str, bytes], after: dict[str, bytes]) -> None:
    path = ANALYSIS / "expected_writes.csv"
    rows = list(csv.DictReader(path.open(encoding="utf-8-sig", newline="")))
    declared: dict[str, set[int]] = {}
    for row in rows:
        name = row["member"]
        offset = int(row["offset"], 16)
        if int(row["before"], 16) != before[name][offset] or int(row["after"], 16) != after[name][offset]:
            raise VerifyError(f"Expected-Write byte drift: {name}:0x{offset:X}")
        declared.setdefault(name, set()).add(offset)
    if declared != actual:
        raise VerifyError("Expected-Write CSV does not equal complete archive diff")


def main() -> None:
    for path, expected in HASHES.items():
        if not path.is_file() or sha256(path) != expected:
            raise VerifyError(f"archive hash mismatch: {path}")

    base_names, base = read_zip(BASE)
    full_names, full = read_zip(FULL)
    delta_names, delta = read_zip(DELTA)
    if len(base_names) != 164 or full_names != base_names:
        raise VerifyError("full archive member topology drift")
    if any(len(base[name]) != len(full[name]) for name in base_names):
        raise VerifyError("member size drift")

    actual = {
        name: changed_offsets(base[name], full[name])
        for name in base_names if base[name] != full[name]
    }
    if {name: len(offsets) for name, offsets in actual.items()} != EXPECTED_CHANGED:
        raise VerifyError("changed member/byte census mismatch")
    expected_delta_names = [name for name in base_names if name in EXPECTED_CHANGED]
    if delta_names != expected_delta_names or any(delta[name] != full[name] for name in delta_names):
        raise VerifyError("delta archive mismatch")
    verify_expected_write_csv(actual, base, full)

    before_regions = independent_text_regions(base)
    after_regions = independent_text_regions(full)
    if len(before_regions) != REGION_COUNT or region_fingerprint(before_regions) != BASE_REGION_FP:
        raise VerifyError("V337 region census drift")
    if len(after_regions) != REGION_COUNT or region_fingerprint(after_regions) != FULL_REGION_FP:
        raise VerifyError("V338 region census drift")
    expected_after = [
        (name, start, end - 1 if name == PSX and end - 1 in LEVEL_ENDS else end)
        for name, start, end in before_regions
    ]
    if after_regions != expected_after:
        raise VerifyError("unexpected text boundary movement")
    for (bn, bs, be), (an, ass, ae) in zip(before_regions, after_regions, strict=True):
        if controls(base[bn], bs, be) != controls(full[an], ass, ae):
            raise VerifyError(f"control topology changed: {bn}:0x{bs:X}")

    for digit, code in SOLDIER_CODES.items():
        old = SOLDIER_STEM + bytes((code,)) + COLON + bytes((SPACE,))
        new = SOLDIER_STEM + bytes((SPACE, code)) + COLON
        if count_in_regions(base, before_regions, old) != SOLDIER_BASE_COUNTS[digit]:
            raise VerifyError(f"V337 soldier {digit} census drift")
        if count_in_regions(full, after_regions, old) != 0:
            raise VerifyError(f"unspaced soldier {digit} remains")
        expected_new = SOLDIER_BASE_COUNTS[digit] + (1 if digit == 2 else 0)
        if count_in_regions(full, after_regions, new) != expected_new:
            raise VerifyError(f"spaced soldier {digit} readback mismatch")
    existing = SOLDIER_STEM + bytes((SPACE, SOLDIER_CODES[2])) + COLON + bytes((SPACE,))
    if count_in_regions(base, before_regions, existing) != 1 or count_in_regions(full, after_regions, existing) != 1:
        raise VerifyError("pre-existing soldier 2 label changed")

    if count_in_regions(base, before_regions, REFIT_OLD) != 5:
        raise VerifyError("V337 refit wording census drift")
    if count_in_regions(full, after_regions, REFIT_OLD) != 0 or count_in_regions(full, after_regions, REFIT_NEW) != 5:
        raise VerifyError("V338 refit wording readback mismatch")
    if base[MISSED_MEMBER][MISSED_AT:MISSED_AT + len(MISSED_OLD)] != MISSED_OLD:
        raise VerifyError("missed source anchor drift")
    if full[MISSED_MEMBER][MISSED_AT:MISSED_AT + len(MISSED_NEW)] != MISSED_NEW:
        raise VerifyError("missed translation readback mismatch")
    if base[MISSED_MEMBER][MISSED_AT + 17] != 0 or full[MISSED_MEMBER][MISSED_AT + 17] != 0:
        raise VerifyError("missed translation terminator moved")

    changed_planes = []
    for index in range(COLS * (256 // CELL) * PLANES):
        old_rows = read_plane(base[COMM], index)
        new_rows = read_plane(full[COMM], index)
        if old_rows != new_rows:
            changed_planes.append(index)
    if changed_planes != list(QUESTION_PLANES):
        raise VerifyError(f"unexpected COMM plane changes: {changed_planes}")
    for index in QUESTION_PLANES:
        if read_plane(base[COMM], index) != QUESTION_BEFORE or read_plane(full[COMM], index) != QUESTION_AFTER:
            raise VerifyError(f"question plane {index} mismatch")
        cell = index // PLANES
        for sibling in range(cell * PLANES, cell * PLANES + PLANES):
            if sibling != index and read_plane(base[COMM], sibling) != read_plane(full[COMM], sibling):
                raise VerifyError(f"question sibling plane changed: {sibling}")
    if sum(row.bit_count() for row in QUESTION_BEFORE) != sum(row.bit_count() for row in QUESTION_AFTER):
        raise VerifyError("question shift lost ink")

    old_exe, new_exe = base[PSX], full[PSX]
    if word(old_exe, QUANTITY_AT) != 0x24420002 or word(new_exe, QUANTITY_AT) != 0x24420001:
        raise VerifyError("quantity Y correction mismatch")
    identity = atlas_row(LEVEL_PARTICLE_PHYSICAL)
    if identity["unicode"] != "U+C774" or identity["char"] != "이":
        raise VerifyError("direct code 03 does not resolve to 이")
    for slot, at in zip(LEVEL_POINTER_SLOTS, LEVEL_ENDS, strict=True):
        if old_exe[at:at + 2] != b"\x03\x00" or new_exe[at:at + 2] != b"\x00\x00":
            raise VerifyError(f"level stat suffix mismatch: 0x{at:X}")
        ram = word(old_exe, slot)
        start = ram - RAM_TO_FILE
        if old_exe.index(0, start) != at + 1 or new_exe.index(0, start) != at:
            raise VerifyError(f"level stat decoded boundary mismatch: 0x{slot:X}")
        if aligned_pointer_refs(old_exe, ram) != [slot] or aligned_pointer_refs(new_exe, ram) != [slot]:
            raise VerifyError(f"level stat pointer ownership mismatch: 0x{slot:X}")
    if old_exe[LEVEL_SEPARATOR_AT:LEVEL_SEPARATOR_AT + 2] != b"\x9C\x00":
        raise VerifyError("old level separator anchor drift")
    if new_exe[LEVEL_SEPARATOR_AT:LEVEL_SEPARATOR_AT + 2] != b"\xA1\x00":
        raise VerifyError("new level separator mismatch")
    if word(new_exe, LEVEL_SUFFIX_PTR_AT) != 0x8019FCF0:
        raise VerifyError("level suffix pointer mismatch")
    if aligned_pointer_refs(old_exe, 0x8019B0A7) != [LEVEL_SUFFIX_PTR_AT]:
        raise VerifyError("old level suffix pointer ownership drift")
    if aligned_pointer_refs(old_exe, 0x8019FCF0):
        raise VerifyError("new level suffix target was already referenced")
    if aligned_pointer_refs(new_exe, 0x8019B0A7) or aligned_pointer_refs(new_exe, 0x8019FCF0) != [LEVEL_SUFFIX_PTR_AT]:
        raise VerifyError("new level suffix pointer ownership mismatch")
    if new_exe[LEVEL_SUFFIX_NEW_AT:LEVEL_SUFFIX_NEW_AT + 4] != bytes.fromhex("A1 8B 69 00"):
        raise VerifyError("level suffix payload mismatch")
    if word(old_exe, LEVEL_CALL_AT) != GLOBAL_CONVERTER_JAL or word(new_exe, LEVEL_CALL_AT) != jal(HELPER_RAM):
        raise VerifyError("level converter call mismatch")
    if word(new_exe, LEVEL_CALL_DELAY_AT) != 0:
        raise VerifyError("level converter delay slot is not nop")

    helper = b"".join(struct.pack("<I", value) for value in HELPER_WORDS) + DIGIT_TABLE + b"\x00\x00"
    if len(helper) != HELPER_CAPACITY or new_exe[HELPER_AT:HELPER_AT + HELPER_CAPACITY] != helper:
        raise VerifyError("resident level converter payload mismatch")
    if any(old_exe[HELPER_AT:HELPER_AT + HELPER_CAPACITY]):
        raise VerifyError("V337 helper source was not blank")
    if new_exe[FORBIDDEN_AT:FORBIDDEN_AT + FORBIDDEN_SIZE] != old_exe[FORBIDDEN_AT:FORBIDDEN_AT + FORBIDDEN_SIZE]:
        raise VerifyError("forbidden scene-loader/BSS cave changed")
    if direct_targets(new_exe, HELPER_RAM, HELPER_RAM + HELPER_CAPACITY) != [
        (LEVEL_CALL_AT + RAM_TO_FILE, HELPER_RAM, "jal")
    ]:
        raise VerifyError("resident helper inbound flow mismatch")
    old_global = sum(word(old_exe, at) == GLOBAL_CONVERTER_JAL for at in range(0x800, len(old_exe) - 3, 4))
    new_global = sum(word(new_exe, at) == GLOBAL_CONVERTER_JAL for at in range(0x800, len(new_exe) - 3, 4))
    if (old_global, new_global) != (3, 2):
        raise VerifyError("unrelated global converter callers changed")
    for value in range(1, 256):
        converted = DIGIT_TABLE[value - 0x30] if 0x30 <= value <= 0x39 else (value + 0xE1) & 0xFF
        if 0x30 <= value <= 0x39 and converted not in DIGIT_TABLE:
            raise VerifyError("digit mapping simulation failed")

    report = {
        "result": "PASS",
        "archives": {path.name: HASHES[path] for path in HASHES},
        "members": len(full_names),
        "changed_bytes": EXPECTED_CHANGED,
        "text_regions": {"v337": BASE_REGION_FP, "v338": FULL_REGION_FP, "count": REGION_COUNT},
        "soldier_repairs": 30,
        "refit_repairs": 5,
        "quantity_y_delta": 1,
        "question_planes": list(QUESTION_PLANES),
        "level_helper": {"ram": hex(HELPER_RAM), "bytes": HELPER_CAPACITY, "inbound": 1},
        "runtime": "PENDING user cold boot",
    }
    (ANALYSIS / "independent_verification.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (ANALYSIS / "independent_verification.txt").write_text(
        "V338 independent static verification: PASS\n"
        "164 members; 8 changed members; Expected-Write exact\n"
        "text regions=8595; only six approved level-stat ends shorten by one byte\n"
        "soldier spacing=30; refit wording=5; missed S4031 fixed room=PASS\n"
        "quantity Y +1; question planes 208/222 only; sibling planes=PASS\n"
        "level helper exact 88B; single inbound JAL; delay slot/forbidden cave=PASS\n"
        "runtime=PENDING user cold boot\n",
        encoding="utf-8",
    )
    print("V338 independent static verification: PASS")
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
