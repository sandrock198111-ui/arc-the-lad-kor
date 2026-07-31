#!/usr/bin/env python3
"""Independent static audit for the v0.41 E9/EA UI glyph probe."""

from __future__ import annotations

import csv
import hashlib
import struct
import sys
from pathlib import Path
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))
sys.path.insert(0, str(ROOT / "06_tools" / "python_packages"))

from capstone import Cs, CS_ARCH_MIPS, CS_MODE_LITTLE_ENDIAN, CS_MODE_MIPS32  # noqa: E402
from build_story_sf0b1_return_full import ROW_BYTES, get_pixel, render_glyph  # noqa: E402
from build_ui_full_v26 import GLYPHS_PER_ROW, PSX_LOAD_BASE, TABLES, pointer_target  # noqa: E402


BASE = (
    ROOT
    / "99_backup"
    / "baselines"
    / "ui_safe_v39_fallback_2026-07-18"
    / "ui_safe_v39_cumulative_patch_only.zip"
)
OUTPUT = ROOT / "03_output" / "ui_glyph_store_v41_e9ea_probe_patch_only.zip"
MANIFEST = ROOT / "05_docs" / "ui_glyph_store_v41_probe.csv"
GLYPH_MAP = ROOT / "05_docs" / "ui_glyph_store_v41_map.csv"
STORY_AUDIT = ROOT / "01_work" / "analysis" / "full_audit_v20" / "story_body_audit.csv"
REPORT = ROOT / "01_work" / "analysis" / "ui_glyph_store_v41" / "independent_audit.txt"

BASE_HASH = "0778FE435820409F190579D179F8B36FFFCEB02B5F2004FC1E3ACE58741D5DC3"
EXPECTED_COMM_HASH = "32E43ED674DF30D745F3DE889493A5917F937CB5013B745ED24B455ECE231733"
PSX_TARGET = "PSX.EXE"
FONT_TARGET = "COMM.IMG"

DECODER_HOOK = 0x8016B3D4
PRECLASS_HOOK = 0x8016BB48
MAINCLASS_HOOK = 0x8016BB74
PRE_STUB = 0x801A7460
MAIN_STUB = 0x801A748C
DECODER_STUB = 0x801A74B8
LOOKUP_TABLE = 0x801A7520
LOOKUP_COUNT = 278
CAVE_START = 0x801A7460
CAVE_USED_END = 0x801A774C
CAVE_LIMIT = 0x801A7860

ORIGINAL_HOOKS = {
    DECODER_HOOK: bytes.fromhex("DD 00 62 2C 05 00 40 10"),
    PRECLASS_HOOK: bytes.fromhex("E1 00 42 2C 07 00 40 14"),
    MAINCLASS_HOOK: bytes.fromhex("E1 00 42 2C 08 00 40 10"),
}

SAFE_CELLS = {
    14: range(16, 21),
    15: range(0, 21),
    16: range(0, 21),
    17: range(13, 21),
    18: range(13, 21),
    19: range(8, 21),
    20: range(8, 21),
    31: (20,),
    32: (20,),
    33: (20,),
    38: range(17, 21),
    39: range(0, 21),
    40: range(0, 21),
    41: range(0, 21),
}


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def file_offset(address: int) -> int:
    return address - PSX_LOAD_BASE


def j(address: int) -> int:
    return 0x08000000 | ((address >> 2) & 0x03FFFFFF)


def expected_virtual_codes() -> list[bytes]:
    values = [bytes((0xE9, second)) for second in range(1, 0xFF)]
    values.extend(bytes((0xEA, second)) for second in range(1, 0x19))
    return values


def safe_indices() -> set[int]:
    values: set[int] = set()
    for row, columns in SAFE_CELLS.items():
        for column in columns:
            base = row * GLYPHS_PER_ROW + column * 4
            values.update(range(base, base + 4))
    return values


def glyph_plane(font: bytes, physical_index: int) -> tuple[int, ...]:
    row, remainder = divmod(physical_index, GLYPHS_PER_ROW)
    column, plane = divmod(remainder, 4)
    bit = 1 << plane
    return tuple(
        1 if get_pixel(font, column * 12 + x, row * 12 + y) & bit else 0
        for y in range(12)
        for x in range(12)
    )


def changed_offsets(before: bytes, after: bytes) -> list[int]:
    if len(before) != len(after):
        raise SystemExit("FAIL: member length changed")
    return [index for index, pair in enumerate(zip(before, after)) if pair[0] != pair[1]]


def classify_prefix(value: int) -> str:
    if value in (0xE9, 0xEA):
        return "glyph"
    return "glyph" if value < 0xE1 else "command"


def parse_boundaries(payload: bytes) -> list[int]:
    boundaries: list[int] = []
    cursor = 0
    while cursor < len(payload):
        boundaries.append(cursor)
        first = payload[cursor]
        if first >= 0xDD and first not in range(0xE1, 0xE9):
            if cursor + 1 >= len(payload):
                raise SystemExit("FAIL: truncated two-byte glyph")
            cursor += 2
        else:
            cursor += 1
    return boundaries


def main() -> None:
    if digest(BASE.read_bytes()) != BASE_HASH:
        raise SystemExit("FAIL: frozen v0.39 base hash differs")

    with ZipFile(BASE) as archive:
        base_names = archive.namelist()
        before = {name: archive.read(name) for name in base_names}
    with ZipFile(OUTPUT) as archive:
        out_names = archive.namelist()
        after = {name: archive.read(name) for name in out_names}

    if base_names != out_names:
        raise SystemExit("FAIL: ZIP member order differs")
    changed_members = [name for name in base_names if before[name] != after[name]]
    if changed_members != [FONT_TARGET, PSX_TARGET]:
        raise SystemExit(f"FAIL: unexpected changed members {changed_members}")
    if digest(after[FONT_TARGET]) != EXPECTED_COMM_HASH:
        raise SystemExit("FAIL: sparse COMM.IMG hash differs from verified v0.40 storage")

    with GLYPH_MAP.open(encoding="utf-8-sig", newline="") as handle:
        map_rows = list(csv.DictReader(handle))
    if len(map_rows) != LOOKUP_COUNT:
        raise SystemExit(f"FAIL: glyph map count {len(map_rows)}")
    codes = [bytes.fromhex(row["virtual_code_hex"]) for row in map_rows]
    indices = [int(row["physical_index"]) for row in map_rows]
    if codes != expected_virtual_codes():
        raise SystemExit("FAIL: virtual E9/EA code sequence differs")
    if len(set(indices)) != LOOKUP_COUNT or any(index not in safe_indices() for index in indices):
        raise SystemExit("FAIL: physical lookup indices are duplicate or unsafe")

    base_font = before[FONT_TARGET]
    out_font = after[FONT_TARGET]
    for row, index in zip(map_rows, indices):
        expected = tuple(
            1 if render_glyph(row["char"]).getpixel((x, y)) else 0
            for y in range(12)
            for x in range(12)
        )
        if glyph_plane(out_font, index) != expected:
            raise SystemExit(f"FAIL: rendered glyph differs at physical index {index}")

    allowed_font_bits: dict[tuple[int, int], int] = {}
    for index in indices:
        row, remainder = divmod(index, GLYPHS_PER_ROW)
        column, plane = divmod(remainder, 4)
        bit = 1 << plane
        for y in range(12):
            for x in range(12):
                key = (column * 12 + x, row * 12 + y)
                allowed_font_bits[key] = allowed_font_bits.get(key, 0) | bit
    for offset in changed_offsets(base_font, out_font):
        y, byte_x = divmod(offset, ROW_BYTES)
        for half, shift in ((0, 0), (1, 4)):
            old = (base_font[offset] >> shift) & 0x0F
            new = (out_font[offset] >> shift) & 0x0F
            if old == new:
                continue
            x = byte_x * 2 + half
            if (old ^ new) & ~allowed_font_bits.get((x, y), 0):
                raise SystemExit(f"FAIL: COMM change outside mapped plane at ({x},{y})")

    base_exe = before[PSX_TARGET]
    out_exe = after[PSX_TARGET]
    for address, expected in ORIGINAL_HOOKS.items():
        offset = file_offset(address)
        if base_exe[offset : offset + 8] != expected:
            raise SystemExit(f"FAIL: base hook differs at 0x{address:08X}")
    for address, target in (
        (DECODER_HOOK, DECODER_STUB),
        (PRECLASS_HOOK, PRE_STUB),
        (MAINCLASS_HOOK, MAIN_STUB),
    ):
        expected = struct.pack("<II", j(target), 0)
        offset = file_offset(address)
        if out_exe[offset : offset + 8] != expected:
            raise SystemExit(f"FAIL: hook differs at 0x{address:08X}")

    table_offset = file_offset(LOOKUP_TABLE)
    table = list(struct.unpack_from(f"<{LOOKUP_COUNT}H", out_exe, table_offset))
    if table != indices:
        raise SystemExit("FAIL: runtime physical-index lookup table differs")
    for code, expected_index in zip(codes, indices):
        logical = code[1] - 1 if code[0] == 0xE9 else 254 + code[1] - 1
        if table[logical] != expected_index:
            raise SystemExit("FAIL: E9/EA lookup simulation differs")

    for value in range(256):
        expected = "glyph" if value < 0xE1 else "command"
        actual = classify_prefix(value)
        if value in (0xE9, 0xEA):
            expected = "glyph"
        if actual != expected:
            raise SystemExit(f"FAIL: classifier semantic mismatch for 0x{value:02X}")

    cave_start = file_offset(CAVE_START)
    cave_used_end = file_offset(CAVE_USED_END)
    cave_limit = file_offset(CAVE_LIMIT)
    if any(base_exe[cave_start:cave_limit]):
        raise SystemExit("FAIL: base cave was not empty")
    if not any(out_exe[cave_start:cave_used_end]):
        raise SystemExit("FAIL: output cave is empty")
    if any(out_exe[cave_used_end:cave_limit]):
        raise SystemExit("FAIL: output cave tail is not zero")

    md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN)
    for address, size in ((PRE_STUB, 44), (MAIN_STUB, 44), (DECODER_STUB, 104)):
        payload = out_exe[file_offset(address) : file_offset(address) + size]
        if len(list(md.disasm(payload, address))) != size // 4:
            raise SystemExit(f"FAIL: incomplete MIPS disassembly at 0x{address:08X}")

    with MANIFEST.open(encoding="utf-8-sig", newline="") as handle:
        records = list(csv.DictReader(handle))
    if len(records) != 503:
        raise SystemExit(f"FAIL: UI record count {len(records)}")
    changed_strings = 0
    allowed_psx: set[int] = set(range(cave_start, cave_limit))
    for address in ORIGINAL_HOOKS:
        allowed_psx.update(range(file_offset(address), file_offset(address) + 8))

    for row in records:
        table_key = row["table_key"]
        index = int(row["index"])
        pointer_table = TABLES[table_key][2]
        if (
            base_exe[pointer_table + index * 4 : pointer_table + index * 4 + 4]
            != out_exe[pointer_table + index * 4 : pointer_table + index * 4 + 4]
        ):
            raise SystemExit(f"FAIL: pointer changed for {table_key}[{index}]")
        target = pointer_target(out_exe, pointer_table, index)
        old_payload = bytes.fromhex(row["encoded_hex"])
        new_payload = bytes.fromhex(row["v41_encoded_hex"])
        if len(old_payload) != len(new_payload):
            raise SystemExit(f"FAIL: string length changed for {table_key}[{index}]")
        if out_exe[target : target + len(new_payload)] != new_payload:
            raise SystemExit(f"FAIL: payload readback differs for {table_key}[{index}]")
        allowed_psx.update(range(target, target + len(new_payload)))
        if old_payload != new_payload:
            changed_strings += 1
        boundaries = parse_boundaries(new_payload)
        for boundary in boundaries:
            first = new_payload[boundary]
            if first in (0xE9, 0xEA):
                code = new_payload[boundary : boundary + 2]
                if code not in codes:
                    raise SystemExit(f"FAIL: unmapped virtual code {code.hex().upper()}")
        if row["status"] == "preserved_v25_missing_glyph" and old_payload != new_payload:
            raise SystemExit("FAIL: preserved Japanese record changed")

    if changed_strings != 459:
        raise SystemExit(f"FAIL: changed UI string count {changed_strings}")
    for offset in changed_offsets(base_exe, out_exe):
        if offset not in allowed_psx:
            raise SystemExit(f"FAIL: PSX change outside declared ranges at 0x{offset:X}")

    protected_psx = ((0x80214, 0x80218), (0x820A8, 0x820BC), (0x823AC, 0x823C0))
    for start, end in protected_psx:
        if base_exe[start:end] != out_exe[start:end]:
            raise SystemExit(f"FAIL: v0.39 PSX canary regressed at 0x{start:X}")
    if base_font[128 * ROW_BYTES : 160 * ROW_BYTES] != out_font[128 * ROW_BYTES : 160 * ROW_BYTES]:
        raise SystemExit("FAIL: battle-cursor COMM neighborhood changed")

    with STORY_AUDIT.open(encoding="utf-8-sig", newline="") as handle:
        story_rows = list(csv.DictReader(handle))
    story_files: dict[str, bytes] = {}
    audited_story_bodies = 0
    for row in story_rows:
        name = row["file"]
        if name not in before:
            continue
        data = story_files.setdefault(name, before[name])
        start = int(row["offset"], 0)
        body = data[start : start + int(row["capacity"])]
        audited_story_bodies += 1
        cursor = 0
        while cursor < len(body):
            first = body[cursor]
            if first in (0xE9, 0xEA):
                raise SystemExit(
                    f"FAIL: pre-existing E9/EA at story boundary: {name} 0x{start + cursor:X}"
                )
            cursor += 2 if 0xDD <= first <= 0xE0 and cursor + 1 < len(body) else 1

    lines = [
        "UI glyph store v0.41 independent audit",
        f"output_zip_sha256={digest(OUTPUT.read_bytes())}",
        f"output_psx_sha256={digest(out_exe)}",
        f"output_comm_sha256={digest(out_font)}",
        f"changed_members={','.join(changed_members)}",
        f"mapped_glyphs={len(map_rows)}",
        f"changed_ui_strings={changed_strings}",
        "lookup_table_readback=278/278",
        "classifier_semantics=E1-E8_controls_E9-EA_glyphs",
        f"story_boundaries_without_e9_ea={audited_story_bodies}",
        "story_members_unchanged=true",
        "pointer_tables_unchanged=true",
        "string_lengths_unchanged=true",
        "v39_canaries_unchanged=true",
        "changes_outside_declared_ranges=false",
        "result=PASS",
        "runtime_status=UNVERIFIED_PROBE",
    ]
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
