#!/usr/bin/env python3
"""Build the v0.41 E9/EA sparse UI glyph-store runtime probe.

The physical glyph planes are the runtime-sampled sparse COMM.IMG planes from
v0.40.  Unlike v0.40, E1-E8 remain control bytes.  New E9/EA character codes
are routed around the dynamic control parser and mapped through a lookup table
to the verified sparse physical indices.
"""

from __future__ import annotations

import csv
import hashlib
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))
sys.path.insert(0, str(ROOT / "06_tools" / "python_packages"))

from capstone import Cs, CS_ARCH_MIPS, CS_MODE_LITTLE_ENDIAN, CS_MODE_MIPS32  # noqa: E402
import build_ui_glyph_store_v40 as v40  # noqa: E402
from build_ui_full_v26 import PSX_LOAD_BASE, TABLES, pointer_target  # noqa: E402
from build_ui_safe_v27 import load_mapping  # noqa: E402


BASE = (
    ROOT
    / "99_backup"
    / "baselines"
    / "ui_safe_v39_fallback_2026-07-18"
    / "ui_safe_v39_cumulative_patch_only.zip"
)
BASE_HASH = "0778FE435820409F190579D179F8B36FFFCEB02B5F2004FC1E3ACE58741D5DC3"
BASE_PSX_HASH = "D074E2D8D773528D7AB0BEF2F0AA55D43CF73DE6D30F552989F31E4377981FBF"
BASE_COMM_HASH = "CC06EE234F61416FE4C52829F54E078E33D83BD9DFD243B3D39C35C5667F0388"

OUTPUT = ROOT / "03_output" / "ui_glyph_store_v41_e9ea_probe_patch_only.zip"
SOURCE_MANIFEST = ROOT / "05_docs" / "ui_safe_v39.csv"
PHYSICAL_MAP = ROOT / "05_docs" / "ui_glyph_store_v40_map.csv"
MANIFEST = ROOT / "05_docs" / "ui_glyph_store_v41_probe.csv"
GLYPH_MAP = ROOT / "05_docs" / "ui_glyph_store_v41_map.csv"
ANALYSIS = ROOT / "01_work" / "analysis" / "ui_glyph_store_v41"
REPORT = ANALYSIS / "build_report.txt"
READBACK = ANALYSIS / "readback.csv"
DISASSEMBLY = ANALYSIS / "mips_disassembly.txt"

PSX_TARGET = "PSX.EXE"
FONT_TARGET = "COMM.IMG"

DECODER_HOOK = 0x8016B3D4
PRECLASS_HOOK = 0x8016BB48
MAINCLASS_HOOK = 0x8016BB74
DECODER_ONE_BYTE = 0x8016B3E0
DECODER_TWO_BYTE = 0x8016B3F0
DECODER_RETURN = 0x8016B410
PRECLASS_GLYPH = 0x8016BB6C
PRECLASS_COMMAND = 0x8016BB54
MAINCLASS_GLYPH = 0x8016BB80
MAINCLASS_COMMAND = 0x8016BB9C

CAVE_START = 0x801A7460
CAVE_LIMIT = 0x801A7860
CAVE_SIZE = CAVE_LIMIT - CAVE_START

EXPECTED_HOOKS = {
    DECODER_HOOK: bytes.fromhex("DD 00 62 2C 05 00 40 10"),
    PRECLASS_HOOK: bytes.fromhex("E1 00 42 2C 07 00 40 14"),
    MAINCLASS_HOOK: bytes.fromhex("E1 00 42 2C 08 00 40 10"),
}

# MIPS register numbers.
ZERO = 0
V0 = 2
V1 = 3
A1 = 5
A2 = 6
T0 = 8
T1 = 9
T2 = 10


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def file_offset(address: int) -> int:
    offset = address - PSX_LOAD_BASE
    if not 0 <= offset < 0x8E000:
        raise ValueError(f"address outside PSX.EXE: 0x{address:08X}")
    return offset


def j(address: int) -> int:
    return 0x08000000 | ((address >> 2) & 0x03FFFFFF)


def i_type(op: int, rs: int, rt: int, immediate: int) -> int:
    return (
        (op << 26)
        | (rs << 21)
        | (rt << 16)
        | (immediate & 0xFFFF)
    )


def r_type(rs: int, rt: int, rd: int, shift: int, function: int) -> int:
    return (
        (rs << 21)
        | (rt << 16)
        | (rd << 11)
        | (shift << 6)
        | function
    )


@dataclass
class BranchFixup:
    index: int
    op: int
    rs: int
    rt: int
    label: str


class Assembler:
    def __init__(self, address: int) -> None:
        self.address = address
        self.words: list[int] = []
        self.labels: dict[str, int] = {}
        self.fixups: list[BranchFixup] = []

    def emit(self, word: int) -> None:
        self.words.append(word & 0xFFFFFFFF)

    def label(self, name: str) -> None:
        if name in self.labels:
            raise ValueError(f"duplicate label {name}")
        self.labels[name] = len(self.words)

    def branch(self, op: int, rs: int, rt: int, label: str) -> None:
        self.fixups.append(BranchFixup(len(self.words), op, rs, rt, label))
        self.emit(0)

    def finish(self) -> bytes:
        words = list(self.words)
        for fixup in self.fixups:
            if fixup.label not in self.labels:
                raise ValueError(f"undefined label {fixup.label}")
            pc = self.address + fixup.index * 4
            target = self.address + self.labels[fixup.label] * 4
            delta = (target - (pc + 4)) // 4
            if not -0x8000 <= delta <= 0x7FFF:
                raise ValueError(f"branch out of range: {fixup.label}")
            words[fixup.index] = i_type(
                fixup.op, fixup.rs, fixup.rt, delta
            )
        return struct.pack(f"<{len(words)}I", *words)


def build_classifier_stub(address: int, glyph: int, command: int) -> bytes:
    asm = Assembler(address)
    asm.emit(i_type(0x09, V0, T0, -0xE9))       # addiu t0,v0,-E9
    asm.emit(i_type(0x0B, T0, T0, 2))           # sltiu t0,t0,2
    asm.branch(0x05, T0, ZERO, "glyph")         # bnez t0,glyph
    asm.emit(0)
    asm.emit(i_type(0x0B, V0, V0, 0xE1))        # original sltiu v0,v0,E1
    asm.branch(0x05, V0, ZERO, "glyph")         # bnez v0,glyph
    asm.emit(0)
    asm.emit(j(command))
    asm.emit(0)
    asm.label("glyph")
    asm.emit(j(glyph))
    asm.emit(0)
    return asm.finish()


def build_decoder_stub(address: int, table_address: int) -> bytes:
    asm = Assembler(address)
    asm.emit(i_type(0x09, V1, T0, -0xE9))        # addiu t0,v1,-E9
    asm.emit(i_type(0x0B, T0, T1, 2))            # sltiu t1,t0,2
    asm.branch(0x04, T1, ZERO, "normal")         # beqz t1,normal
    asm.emit(0)
    asm.emit(i_type(0x24, A1, T1, 1))            # lbu t1,1(a1)
    asm.emit(r_type(ZERO, T0, T2, 8, 0x00))      # sll t2,t0,8
    asm.emit(r_type(T2, T0, T2, 0, 0x23))        # subu t2,t2,t0
    asm.emit(r_type(T2, T0, T2, 0, 0x23))        # subu t2,t2,t0
    asm.emit(r_type(T2, T1, T2, 0, 0x21))        # addu t2,t2,t1
    asm.emit(i_type(0x09, T2, T2, -1))           # addiu t2,t2,-1
    asm.emit(r_type(ZERO, T2, T2, 1, 0x00))      # sll t2,t2,1
    asm.emit(i_type(0x0F, ZERO, T1, table_address >> 16))
    asm.emit(i_type(0x0D, T1, T1, table_address & 0xFFFF))
    asm.emit(r_type(T1, T2, T1, 0, 0x21))        # addu t1,t1,t2
    asm.emit(i_type(0x25, T1, V1, 0))            # lhu v1,0(t1)
    asm.emit(i_type(0x09, A1, V0, 2))            # addiu v0,a1,2
    asm.emit(i_type(0x2B, A2, V0, 0))            # sw v0,0(a2)
    asm.emit(j(DECODER_RETURN))
    asm.emit(0)
    asm.label("normal")
    asm.emit(i_type(0x0B, V1, V0, 0xDD))         # original sltiu v0,v1,DD
    asm.branch(0x04, V0, ZERO, "two_byte")       # beqz v0,two_byte
    asm.emit(0)
    asm.emit(j(DECODER_ONE_BYTE))
    asm.emit(0)
    asm.label("two_byte")
    asm.emit(j(DECODER_TWO_BYTE))
    asm.emit(0)
    return asm.finish()


def virtual_codes(count: int) -> list[bytes]:
    result = [bytes((0xE9, second)) for second in range(1, 0xFF)]
    result.extend(bytes((0xEA, second)) for second in range(1, 0xFF))
    if count > len(result):
        raise ValueError("E9/EA virtual code space exhausted")
    return result[:count]


def physical_rows() -> list[dict[str, str]]:
    with PHYSICAL_MAP.open(encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    if len(rows) != 278:
        raise SystemExit(f"v0.40 physical map count differs: {len(rows)}")
    indices = [int(row["physical_index"]) for row in rows]
    if len(set(indices)) != len(indices):
        raise SystemExit("v0.40 physical map contains duplicate indices")
    if any(index not in v40.safe_physical_indices() for index in indices):
        raise SystemExit("v0.40 physical map left verified sparse planes")
    return rows


def assemble_cave(physical_indices: list[int]) -> tuple[bytes, dict[str, int]]:
    pre_address = CAVE_START
    pre = build_classifier_stub(pre_address, PRECLASS_GLYPH, PRECLASS_COMMAND)
    main_address = pre_address + len(pre)
    main = build_classifier_stub(main_address, MAINCLASS_GLYPH, MAINCLASS_COMMAND)
    decoder_address = main_address + len(main)
    decoder_probe = build_decoder_stub(decoder_address, 0)
    table_address = (decoder_address + len(decoder_probe) + 3) & ~3
    decoder = build_decoder_stub(decoder_address, table_address)
    if len(decoder) != len(decoder_probe):
        raise SystemExit("decoder size changed after table placement")
    table = struct.pack(f"<{len(physical_indices)}H", *physical_indices)

    cave = bytearray(CAVE_SIZE)
    segments = (
        (pre_address, pre),
        (main_address, main),
        (decoder_address, decoder),
        (table_address, table),
    )
    for address, payload in segments:
        start = address - CAVE_START
        end = start + len(payload)
        if not 0 <= start <= end <= len(cave):
            raise SystemExit(f"cave segment overflow at 0x{address:08X}")
        if any(cave[start:end]):
            raise SystemExit(f"cave segment overlap at 0x{address:08X}")
        cave[start:end] = payload

    metadata = {
        "pre_stub": pre_address,
        "pre_size": len(pre),
        "main_stub": main_address,
        "main_size": len(main),
        "decoder_stub": decoder_address,
        "decoder_size": len(decoder),
        "lookup_table": table_address,
        "lookup_size": len(table),
        "used_end": table_address + len(table),
    }
    return bytes(cave), metadata


def patch_hook(executable: bytearray, address: int, target: int) -> None:
    offset = file_offset(address)
    expected = EXPECTED_HOOKS[address]
    if executable[offset : offset + len(expected)] != expected:
        raise SystemExit(f"hook source differs at 0x{address:08X}")
    executable[offset : offset + 8] = struct.pack("<II", j(target), 0)


def main() -> None:
    if digest(BASE.read_bytes()) != BASE_HASH:
        raise SystemExit("frozen v0.39 base ZIP hash differs")

    rows = v40.csv_rows(SOURCE_MANIFEST)
    expected_records = sum(count for count, _, _ in TABLES.values())
    if len(rows) != expected_records:
        raise SystemExit(f"v0.39 manifest count differs: {len(rows)}")

    translated = [row for row in rows if row["status"] != "preserved_v25_missing_glyph"]
    legacy = load_mapping()
    all_hangul = sorted(
        {char for row in translated for char in row["korean_target"] if v40.is_hangul(char)}
    )
    two_byte_hangul = [char for char in all_hangul if len(legacy[char]) == 2]
    legacy_one_byte = [char for char in all_hangul if len(legacy[char]) == 1]

    physical = physical_rows()
    physical_by_char = {row["char"]: row for row in physical}
    if set(two_byte_hangul) != set(physical_by_char):
        missing = sorted(set(two_byte_hangul) - set(physical_by_char))
        extra = sorted(set(physical_by_char) - set(two_byte_hangul))
        raise SystemExit(f"physical-map character mismatch: missing={missing} extra={extra}")

    ordered_chars = [row["char"] for row in physical]
    codes = virtual_codes(len(ordered_chars))
    virtual = dict(zip(ordered_chars, codes))
    physical_codes = {
        row["char"]: bytes.fromhex(row["code_hex"])
        for row in physical
    }
    physical_indices = [int(row["physical_index"]) for row in physical]

    with ZipFile(BASE) as archive:
        infos = archive.infolist()
        files = {info.filename: archive.read(info.filename) for info in infos}
    before_files = dict(files)
    if digest(files[PSX_TARGET]) != BASE_PSX_HASH:
        raise SystemExit("v0.39 PSX.EXE hash differs")
    if digest(files[FONT_TARGET]) != BASE_COMM_HASH:
        raise SystemExit("v0.39 COMM.IMG hash differs")

    base_executable = files[PSX_TARGET]
    executable = bytearray(base_executable)
    font = bytearray(files[FONT_TARGET])

    cave_offset = file_offset(CAVE_START)
    if any(executable[cave_offset : cave_offset + CAVE_SIZE]):
        raise SystemExit("v0.39 executable cave is not empty")

    used_cells = {
        (v40.glyph_position(code)[1], v40.glyph_position(code)[2])
        for code in physical_codes.values()
    }
    for row, column in sorted(used_cells):
        v40.assert_blank_cell(files[FONT_TARGET], row, column)
    for char, code in physical_codes.items():
        v40.write_glyph(font, code, char)

    manifest_by_key = {(row["table_key"], int(row["index"])): row for row in rows}
    output_records: list[dict[str, object]] = []
    changed_strings = 0
    seen_targets: dict[int, bytes] = {}
    for table_key, (count, _, pointer_table) in TABLES.items():
        for index in range(count):
            row = manifest_by_key[(table_key, index)]
            target = pointer_target(base_executable, pointer_table, index)
            old_payload = bytes.fromhex(row["encoded_hex"])
            if base_executable[target : target + len(old_payload)] != old_payload:
                raise SystemExit(f"v0.39 payload differs: {table_key}[{index}]")

            if row["status"] == "preserved_v25_missing_glyph":
                new_payload = old_payload
            elif row["status"] == "guide_exact_lv_fallback":
                suffix_text = row["korean_target"][-2:]
                suffix = b"".join(virtual[char] for char in suffix_text)
                if len(old_payload) < len(suffix):
                    raise SystemExit("LV fallback payload is too short")
                new_payload = old_payload[:-len(suffix)] + suffix
            else:
                new_payload = v40.encode_text(row["korean_target"], legacy, virtual)

            if len(new_payload) != len(old_payload):
                raise SystemExit(
                    f"in-place length changed: {table_key}[{index}] "
                    f"{len(old_payload)} -> {len(new_payload)}"
                )
            previous = seen_targets.get(target)
            if previous is not None and previous != new_payload:
                raise SystemExit(f"shared pointer conflict at 0x{target:X}")
            seen_targets[target] = new_payload
            if new_payload != old_payload:
                changed_strings += 1
            output_records.append(
                {
                    **row,
                    "v41_encoded_hex": new_payload.hex(" ").upper(),
                    "v41_string_offset": f"0x{target:X}",
                }
            )

    for target, payload in seen_targets.items():
        executable[target : target + len(payload)] = payload

    cave, layout = assemble_cave(physical_indices)
    executable[cave_offset : cave_offset + CAVE_SIZE] = cave
    patch_hook(executable, PRECLASS_HOOK, layout["pre_stub"])
    patch_hook(executable, MAINCLASS_HOOK, layout["main_stub"])
    patch_hook(executable, DECODER_HOOK, layout["decoder_stub"])

    for record in output_records:
        table_key = str(record["table_key"])
        index = int(record["index"])
        pointer_table = TABLES[table_key][2]
        target = pointer_target(executable, pointer_table, index)
        expected = bytes.fromhex(str(record["v41_encoded_hex"]))
        if executable[target : target + len(expected)] != expected:
            raise SystemExit(f"v0.41 readback failed: {table_key}[{index}]")

    changed_font_bytes, changed_font_nibbles = v40.verify_font_changes(
        files[FONT_TARGET], font, physical_codes
    )
    files[PSX_TARGET] = bytes(executable)
    files[FONT_TARGET] = bytes(font)

    changed_members = [name for name in files if files[name] != before_files[name]]
    if changed_members != [FONT_TARGET, PSX_TARGET]:
        raise SystemExit(f"unexpected changed ZIP members: {changed_members}")

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with ZipFile(OUTPUT, "w", ZIP_DEFLATED, compresslevel=9) as archive:
        for info in infos:
            archive.writestr(info, files[info.filename])
    with ZipFile(OUTPUT) as archive:
        for name, expected in files.items():
            if archive.read(name) != expected:
                raise SystemExit(f"output ZIP readback differs: {name}")

    ANALYSIS.mkdir(parents=True, exist_ok=True)
    fields = list(output_records[0])
    for path in (MANIFEST, READBACK):
        with path.open("w", encoding="utf-8-sig", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields)
            writer.writeheader()
            writer.writerows(output_records)

    map_rows: list[dict[str, object]] = []
    for char, virtual_code, source in zip(ordered_chars, codes, physical):
        map_rows.append(
            {
                "char": char,
                "virtual_code_hex": virtual_code.hex(" ").upper(),
                "physical_index": int(source["physical_index"]),
                "row": int(source["row"]),
                "column": int(source["column"]),
                "plane": int(source["plane"]),
                "source_x": int(source["source_x"]),
                "source_y": int(source["source_y"]),
            }
        )
    with GLYPH_MAP.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(map_rows[0]))
        writer.writeheader()
        writer.writerows(map_rows)

    md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN)
    disassembly_lines: list[str] = []
    for name in ("pre_stub", "main_stub", "decoder_stub"):
        address = layout[name]
        size = layout[name.replace("stub", "size")]
        payload = executable[file_offset(address) : file_offset(address) + size]
        instructions = list(md.disasm(payload, address))
        if len(instructions) != size // 4:
            raise SystemExit(f"incomplete MIPS disassembly for {name}")
        disassembly_lines.append(f"[{name}] 0x{address:08X} size={size}")
        disassembly_lines.extend(
            f"0x{item.address:08X}: {item.mnemonic} {item.op_str}"
            for item in instructions
        )
    DISASSEMBLY.write_text("\n".join(disassembly_lines) + "\n", encoding="utf-8")

    report = [
        "UI glyph store v0.41 E9/EA runtime probe",
        f"base_zip_sha256={BASE_HASH}",
        f"output_zip_sha256={digest(OUTPUT.read_bytes())}",
        f"output_psx_sha256={digest(files[PSX_TARGET])}",
        f"output_comm_sha256={digest(files[FONT_TARGET])}",
        "story_e2_members_unchanged=true",
        "dynamic_control_prefixes_e1_e8_preserved=true",
        "virtual_glyph_prefixes=E9,EA",
        f"allocated_hangul_glyphs={len(virtual)}",
        f"preserved_legacy_one_byte_hangul={''.join(legacy_one_byte)}",
        f"changed_ui_strings={changed_strings}",
        f"comm_changed_bytes={changed_font_bytes}",
        f"comm_changed_nibbles={changed_font_nibbles}",
        f"preclass_stub=0x{layout['pre_stub']:08X},size={layout['pre_size']}",
        f"mainclass_stub=0x{layout['main_stub']:08X},size={layout['main_size']}",
        f"decoder_stub=0x{layout['decoder_stub']:08X},size={layout['decoder_size']}",
        f"lookup_table=0x{layout['lookup_table']:08X},size={layout['lookup_size']}",
        f"cave_used_bytes={layout['used_end'] - CAVE_START}",
        f"cave_free_bytes={CAVE_LIMIT - layout['used_end']}",
        "pointer_tables_unchanged=true",
        "string_lengths_unchanged=true",
        "v39_lv_plane_unchanged=true",
        "v39_icon_regions_unchanged=true",
        "battle_cursor_region_unchanged=true",
        "hud_special_payloads_unchanged=true",
        f"changed_members={','.join(changed_members)}",
        "runtime_status=UNVERIFIED_PROBE",
    ]
    REPORT.write_text("\n".join(report) + "\n", encoding="utf-8")
    print("\n".join(report))


if __name__ == "__main__":
    main()
