#!/usr/bin/env python3
"""Independent static/runtime-sample verifier for Arc the Lad 1 V339.

This verifier does not import or call the V339 builder.  It independently
reopens V338/V339/original archives, re-derives the complete byte diff, parses
all 155 name strings, checks the exact MIPS helper and call graph, reads both
12px source and 16px destination planes, and repeats the exact-rectangle
non-text packet audit over the locally available DuckStation states.
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
sys.path.insert(0, str(ROOT / "06_tools/python_packages"))
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

from analyze_arc1_v163_runtime import (  # noqa: E402
    FONT_CLUT_MAX, FONT_CLUT_MIN, RAM_SIZE, trace_active_text_ot,
)
from audit_comm_physical_cell_safety import is_font_tpage  # noqa: E402
from extract_savestate_vram import inflate, locate_ram  # noqa: E402


BASE = ROOT / "03_output/arc1_v338_v197_v210_catchup_TEST_ONLY_29CEF6F5.zip"
FULL = ROOT / "03_output/arc1_v339_ui_banner_geometry_TEST_ONLY_FD442C74.zip"
DELTA = ROOT / "03_output/arc1_v339_ui_banner_geometry_TEST_ONLY_delta_from_v338_2FC2E472.zip"
ORIGINAL = ROOT / "00_original/arc.zip"
ANALYSIS = ROOT / "01_work/analysis/arc1_v339_ui_banner_geometry"
HASHES = {
    BASE: "29CEF6F5ADF4461C9263B39586222F7B88EEEE3DF0D6BEDFE5F0C5695509A777",
    FULL: "FD442C7492F7BE2FCFAED5B3BE377D67FE9794B6767C356AC275D407F2030C17",
    DELTA: "2FC2E47281593C796CA604722407D03095B2971616946587E6183F6653ED5307",
    ORIGINAL: "AE9F4366A1E7DA3805BB3BED3DDA9567E4CD4E669AF890E4E2A620D7861F11DD",
}

PSX = "PSX.EXE"
COMM = "COMM.IMG"
RAM_TO_FILE = 0x8011A800
EXPECTED_CHANGED = {PSX: 126, COMM: 25}

WIDTH_HOOK = 0x51C98
WIDTH_HELPER_FILE = 0x828C8
WIDTH_HELPER_RAM = 0x8019D0C8
WIDTH_HELPER_WORDS = (
    0x00001821, 0x90820000, 0x24840001, 0x1040000A,
    0x2C4800DD, 0x39080001, 0x00882021, 0x2448FF5F,
    0x11000003, 0x2463000E, 0x1000FFF6, 0x00000000,
    0x1000FFF4, 0x2463FFF8, 0x03E00008, 0x2462000F,
)
CAVE_END = 0x82938
PROTECTED = bytes.fromhex("3C CE 19 80 DA C2 19 80")
FORBIDDEN = (0x8F3D8, 0x428)

NAME_TABLES = (
    ("equipment", 0x804A4, 64),
    ("consumable", 0x80C9C, 32),
    ("skill", 0x811C0, 59),
)

WORD_TRANSITIONS = {
    0x51C68: (0x00402821, 0x2445FFFF),
    0x49888: (0x0C05ACC9, 0x0C066C8E),
    0x4A35C: (0x0C066C8E, 0x0C066C8E),
    0x51FB0: (0x3406000C, 0x3406000B),
    0x44F38: (0x3405001E, 0x3405001D),
    0x449C8: (0x26650016, 0x26650015),
}
QUANTITY_HELPER_FILE = 0x80A38
QUANTITY_HELPER = bytes.fromhex(
    "08 00 A2 94 00 00 00 00 01 00 42 24 C9 AC 05 08 08 00 A2 A4"
)

STRING_TRANSITIONS = {
    0x80696: (
        bytes.fromhex("0C DE B9 A1 8B 00"),
        bytes.fromhex("55 90 8B 00 00 00"),
    ),
    0x81DF2: (
        bytes.fromhex("09 58 A1 DD C9 A1 DD 31 DD 32 A1 DF 0B DE 07 A1 7A DD 9F 00"),
        bytes.fromhex("09 58 A1 DD C9 DD 31 DD 32 A1 DF 0B DE 07 7A DD 9F 00 00 00"),
    ),
    0x80950: (
        bytes.fromhex("E7 02 DD 10 DD 0A E7 05 DD AD DD 47 A1 DD 89 24 00"),
        bytes.fromhex("E7 02 DD 10 DD 0A E7 05 DE 54 A1 DD 89 24 00 00 00"),
    ),
}

OPEN_FILE = 0x82908
ITEM_CLOSE_FILE = 0x8290B
SKILL_CLOSE_FILE = 0x82919
POSSESSIVE_FILE = 0x82924
OPEN_RAM = OPEN_FILE + RAM_TO_FILE
ITEM_CLOSE_RAM = ITEM_CLOSE_FILE + RAM_TO_FILE
SKILL_CLOSE_RAM = SKILL_CLOSE_FILE + RAM_TO_FILE
POSSESSIVE_RAM = POSSESSIVE_FILE + RAM_TO_FILE
POINTERS = {
    0x82470: OPEN_RAM,
    0x82474: ITEM_CLOSE_RAM,
    0x82550: OPEN_RAM,
    0x82554: SKILL_CLOSE_RAM,
    0x82558: POSSESSIVE_RAM,
}
PAYLOADS = {
    OPEN_FILE: bytes.fromhex("DF 2D 00"),
    ITEM_CLOSE_FILE: bytes.fromhex("DF 09 36 A1 85 0E A1 6F 61 2D 07 01 21 00"),
    SKILL_CLOSE_FILE: bytes.fromhex("DF 09 36 A1 DD 93 DE 15 01 21 00"),
    POSSESSIVE_FILE: bytes.fromhex("DF 09 4D 00"),
}

ROW_BYTES = 896
PLANE_COUNT = 4
COLS16 = 15
CELL16 = 16
CLOSE_PLANE = 738
OPEN_PLANE = 774
ORIGINAL_CLOSE = (0x080,) * 10 + (0x780, 0x000)
ORIGINAL_OPEN = (0x03C,) + (0x020,) * 10 + (0x000,)
PADDED_CLOSE = (0, 0) + tuple(value << 2 for value in ORIGINAL_CLOSE) + (0, 0)
PADDED_OPEN = (0, 0) + tuple(value << 2 for value in ORIGINAL_OPEN) + (0, 0)


class VerifyError(RuntimeError):
    pass


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest().upper()


def read_zip(path: Path) -> tuple[list[str], dict[str, bytes]]:
    with ZipFile(path) as archive:
        names = [item.filename for item in archive.infolist() if not item.is_dir()]
        return names, {name: archive.read(name) for name in names}


def word(data: bytes, at: int) -> int:
    return struct.unpack_from("<I", data, at)[0]


def jump(address: int) -> int:
    return 0x08000000 | ((address >> 2) & 0x03FFFFFF)


def changed_offsets(before: bytes, after: bytes) -> set[int]:
    if len(before) != len(after):
        raise VerifyError("member length changed")
    return {i for i, (old, new) in enumerate(zip(before, after, strict=True)) if old != new}


def aligned_refs(data: bytes, address: int) -> list[int]:
    return [at for at in range(0, len(data) - 3, 4) if word(data, at) == address]


def c_string(data: bytes, start: int) -> bytes:
    return data[start:data.index(0, start) + 1]


def tokenize(data: bytes) -> list[bytes]:
    result: list[bytes] = []
    at = 0
    while at < len(data):
        value = data[at]
        if value == 0:
            break
        width = 1 if value < 0xDD else 2
        if at + width > len(data):
            raise VerifyError("truncated name token")
        result.append(data[at:at + width])
        at += width
    return result


def direct_callers(data: bytes, target: int) -> list[tuple[int, str]]:
    result: list[tuple[int, str]] = []
    for at in range(0x800, len(data) - 3, 4):
        instruction = word(data, at)
        if instruction >> 26 not in (2, 3):
            continue
        pc = at + RAM_TO_FILE
        decoded = ((pc + 4) & 0xF0000000) | ((instruction & 0x03FFFFFF) << 2)
        if decoded == target:
            result.append((pc, "jal" if instruction >> 26 == 3 else "j"))
    return result


def read_plane16(data: bytes, index: int) -> tuple[int, ...]:
    cell, plane = divmod(index, PLANE_COUNT)
    col, row = cell % COLS16, cell // COLS16
    bit = 1 << plane
    rows: list[int] = []
    for y in range(CELL16):
        value = 0
        base = (row * CELL16 + y) * ROW_BYTES + col * 8
        for x in range(CELL16):
            nibble = (data[base + x // 2] >> (0 if x % 2 == 0 else 4)) & 0xF
            if nibble & bit:
                value |= 1 << (15 - x)
        rows.append(value)
    return tuple(rows)


def read_plane12(data: bytes, index: int) -> tuple[int, ...]:
    cell, plane = divmod(index, 4)
    col, row = cell % 21, cell // 21
    bit = 1 << plane
    rows: list[int] = []
    for y in range(12):
        value = 0
        base = (row * 12 + y) * ROW_BYTES + col * 6
        for x in range(12):
            nibble = (data[base + x // 2] >> (0 if x % 2 == 0 else 4)) & 0xF
            if nibble & bit:
                value |= 1 << (11 - x)
        rows.append(value)
    return tuple(rows)


def verify_expected_writes(
    actual: dict[str, set[int]], before: dict[str, bytes], after: dict[str, bytes]
) -> None:
    rows = list(csv.DictReader((ANALYSIS / "expected_writes.csv").open(encoding="utf-8-sig", newline="")))
    declared: dict[str, set[int]] = {}
    for row in rows:
        name = row["member"]
        at = int(row["offset"], 16)
        if int(row["before"], 16) != before[name][at] or int(row["after"], 16) != after[name][at]:
            raise VerifyError(f"Expected-Write byte mismatch: {name}:0x{at:X}")
        declared.setdefault(name, set()).add(at)
    if declared != actual:
        raise VerifyError("Expected-Write CSV is not the complete archive diff")


def name_width_rows(exe: bytes) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for table, table_at, count in NAME_TABLES:
        for index in range(count):
            pointer = word(exe, table_at + index * 4)
            start = pointer - RAM_TO_FILE
            payload = c_string(exe, start)
            name_tokens = tokenize(payload)
            if any(token[0] >= 0xE1 for token in name_tokens):
                raise VerifyError(f"control token in name table: {table}[{index}]")
            old_width = len(name_tokens) * 12 + 15
            new_width = 15 + sum(6 if token == b"\xA1" else 14 for token in name_tokens)
            rows.append({
                "table": table,
                "index": index,
                "pointer": f"0x{pointer:08X}",
                "file": f"0x{start:X}",
                "tokens": len(name_tokens),
                "spaces": sum(token == b"\xA1" for token in name_tokens),
                "old_width": old_width,
                "new_width": new_width,
                "delta": new_width - old_width,
                "hex": payload[:-1].hex(" ").upper(),
            })
    return rows


def exact_rect_nontext_audit() -> dict[str, object]:
    states = Path.home() / "AppData/Local/DuckStation/savestates"
    rectangles = {
        "close738": (64, 80, 192, 208),
        "open774": (208, 224, 192, 208),
    }
    hits: dict[str, list[tuple[str, dict[str, object]]]] = {key: [] for key in rectangles}
    read = failed = 0
    for path in sorted(states.glob("*.sav")):
        try:
            blob = inflate(path)
            ram_base = locate_ram(blob)
            ram = blob[ram_base:ram_base + RAM_SIZE]
            _context, _parity, packets = trace_active_text_ot(ram)
        except BaseException:  # keep the historical full-state audit behavior
            failed += 1
            continue
        read += 1
        for packet in packets:
            if not is_font_tpage(packet.get("tpage")):
                continue
            try:
                u, v = int(packet["u"]), int(packet["v"])
                width, height = int(packet["width"]), int(packet["height"])
            except (KeyError, TypeError, ValueError):
                continue
            clut = packet.get("clut")
            looks_text = (
                packet.get("kind") in ("SPRT", "SPRT_8", "SPRT_16")
                and isinstance(clut, int) and FONT_CLUT_MIN <= clut <= FONT_CLUT_MAX
            )
            if looks_text:
                continue
            for key, (x0, x1, y0, y1) in rectangles.items():
                if u < x1 and u + width > x0 and v < y1 and v + height > y0:
                    hits[key].append((path.name, packet))
    if read < 629 or any(hits.values()):
        raise VerifyError(f"quote exact-rect nontext audit failed: read={read} hits={hits}")
    return {"states_read": read, "states_failed": failed, "hits": {key: 0 for key in hits}}


def main() -> None:
    for path, expected in HASHES.items():
        if not path.is_file() or sha256(path) != expected:
            raise VerifyError(f"archive hash mismatch: {path}")

    base_names, base = read_zip(BASE)
    full_names, full = read_zip(FULL)
    delta_names, delta = read_zip(DELTA)
    with ZipFile(ORIGINAL) as archive:
        original_comm = archive.read(COMM)
    if len(base_names) != 164 or full_names != base_names:
        raise VerifyError("full archive topology drift")
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
    verify_expected_writes(actual, base, full)

    old_exe, new_exe = base[PSX], full[PSX]
    helper = struct.pack("<16I", *WIDTH_HELPER_WORDS)
    if word(new_exe, WIDTH_HOOK) != jump(WIDTH_HELPER_RAM) or word(new_exe, WIDTH_HOOK + 4) != 0:
        raise VerifyError("width tail-jump mismatch")
    if new_exe[WIDTH_HELPER_FILE:WIDTH_HELPER_FILE + len(helper)] != helper:
        raise VerifyError("width helper words mismatch")
    if new_exe[CAVE_END:CAVE_END + len(PROTECTED)] != PROTECTED or old_exe[CAVE_END:CAVE_END + len(PROTECTED)] != PROTECTED:
        raise VerifyError("protected pointer words changed")
    if direct_callers(new_exe, 0x8016C498) != [
        (0x80164030, "jal"), (0x80164B04, "jal"), (0x8016C3BC, "jal")
    ]:
        raise VerifyError("shared width caller census drift")
    if direct_callers(new_exe, WIDTH_HELPER_RAM) != [(0x8016C498, "j")]:
        raise VerifyError("width helper external inbound flow mismatch")

    independent_rows = name_width_rows(new_exe)
    csv_rows = list(csv.DictReader((ANALYSIS / "name_width_census.csv").open(encoding="utf-8-sig", newline="")))
    if len(independent_rows) != 155 or len(csv_rows) != 155:
        raise VerifyError("name-width entry census drift")
    for actual_row, csv_row in zip(independent_rows, csv_rows, strict=True):
        normalized = {key: str(value) for key, value in actual_row.items()}
        if normalized != csv_row:
            raise VerifyError(f"name-width CSV mismatch: {actual_row['table']}[{actual_row['index']}]")
    deltas = [int(row["delta"]) for row in independent_rows]
    if (min(deltas), max(deltas)) != (-2, 10):
        raise VerifyError("name-width delta range drift")

    for at, (old, new) in WORD_TRANSITIONS.items():
        if word(old_exe, at) != old or word(new_exe, at) != new:
            raise VerifyError(f"word transition mismatch at 0x{at:X}")
    if old_exe[QUANTITY_HELPER_FILE:QUANTITY_HELPER_FILE + len(QUANTITY_HELPER)] != QUANTITY_HELPER:
        raise VerifyError("V338 quantity helper anchor drift")
    if new_exe[QUANTITY_HELPER_FILE:QUANTITY_HELPER_FILE + len(QUANTITY_HELPER)] != QUANTITY_HELPER:
        raise VerifyError("V339 quantity helper changed")
    # Algebraic screen deltas: base name=0/equip=0/cons=+1;
    # V339 name=-1/equip=-1+1=0/cons=-1+1=0.
    geometry = {
        "name_delta": -1,
        "equipment_quantity_delta": 0,
        "consumable_quantity_delta": -1,
        "consumable_quantity_relative_to_name": 1,
    }

    for at, (old, new) in STRING_TRANSITIONS.items():
        if old_exe[at:at + len(old)] != old or new_exe[at:at + len(new)] != new:
            raise VerifyError(f"string transition mismatch at 0x{at:X}")
    if new_exe[0x80950:0x80960].count(bytes.fromhex("E7 02")) != 1 or new_exe[0x80950:0x80960].count(bytes.fromhex("E7 05")) != 1:
        raise VerifyError("battle-help E7 button tokens changed")

    for at, address in POINTERS.items():
        if word(new_exe, at) != address:
            raise VerifyError(f"bracket pointer mismatch at 0x{at:X}")
    expected_refs = {
        OPEN_RAM: [0x82470, 0x82550],
        ITEM_CLOSE_RAM: [0x82474],
        SKILL_CLOSE_RAM: [0x82554],
        POSSESSIVE_RAM: [0x82558],
    }
    for address, refs in expected_refs.items():
        if aligned_refs(new_exe, address) != refs:
            raise VerifyError(f"bracket pointer ownership mismatch: 0x{address:08X}")
    for at, payload in PAYLOADS.items():
        if new_exe[at:at + len(payload)] != payload:
            raise VerifyError(f"bracket payload mismatch: 0x{at:X}")

    if read_plane12(original_comm, 89) != ORIGINAL_CLOSE or read_plane12(original_comm, 90) != ORIGINAL_OPEN:
        raise VerifyError("original 12px bracket source mismatch")
    changed_planes = [
        index for index in range(COLS16 * 32 * 4)
        if read_plane16(base[COMM], index) != read_plane16(full[COMM], index)
    ]
    if changed_planes != [CLOSE_PLANE, OPEN_PLANE]:
        raise VerifyError(f"unexpected changed COMM planes: {changed_planes}")
    if read_plane16(full[COMM], CLOSE_PLANE) != PADDED_CLOSE or read_plane16(full[COMM], OPEN_PLANE) != PADDED_OPEN:
        raise VerifyError("padded 16px bracket readback mismatch")
    for index in (CLOSE_PLANE, OPEN_PLANE):
        cell = index // 4
        for sibling in range(cell * 4, cell * 4 + 4):
            if sibling != index and read_plane16(base[COMM], sibling) != read_plane16(full[COMM], sibling):
                raise VerifyError(f"bracket sibling plane changed: {sibling}")

    start, size = FORBIDDEN
    if new_exe[start:start + size] != old_exe[start:start + size]:
        raise VerifyError("forbidden scene-loader/BSS cave changed")
    nontext = exact_rect_nontext_audit()

    report = {
        "result": "PASS",
        "archives": {path.name: expected for path, expected in HASHES.items()},
        "members": len(full_names),
        "changed_bytes": EXPECTED_CHANGED,
        "name_width_entries": len(independent_rows),
        "name_width_delta": {"min": min(deltas), "max": max(deltas)},
        "geometry": geometry,
        "quote_planes": [CLOSE_PLANE, OPEN_PLANE],
        "quote_nontext_audit": nontext,
        "runtime": "PENDING user cold boot",
    }
    (ANALYSIS / "independent_verification.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (ANALYSIS / "independent_verification.txt").write_text(
        "V339 independent static verification: PASS\n"
        "164 members; PSX.EXE+COMM.IMG only; Expected-Write exact\n"
        "width helper exact 64B; single external inbound J; 155/155 names independently recalculated\n"
        "name=-1; equipment quantity=unchanged; consumable quantity=-1 and remains name+1\n"
        "bottom help/acquisition/level-up=-1; E7 icons preserved; wording readback=PASS\n"
        "original 12px quote art -> planes 738/774 only; sibling planes=PASS\n"
        f"exact current-16px nontext audit={nontext['states_read']} states, 0 overlaps\n"
        "runtime=PENDING user cold boot\n",
        encoding="utf-8",
    )
    print("V339 independent verification: PASS")
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
