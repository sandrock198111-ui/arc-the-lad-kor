#!/usr/bin/env python3
"""Build the complete PSX.EXE UI translation with an isolated UI glyph bank."""

from __future__ import annotations

import csv
import hashlib
import struct
import sys
from collections import OrderedDict
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))
sys.path.insert(0, str(ROOT / "06_tools" / "python_packages"))

from build_story_sf0b1_return_full import (  # noqa: E402
    FONT_TARGET,
    ROW_BYTES,
    get_pixel,
    render_glyph,
    set_pixel,
)
from ui_full_v26_data import TRANSLATIONS  # noqa: E402


BASE = ROOT / "03_output" / "ui_consumables_v25_cumulative_patch_only.zip"
BASE_HASH = "2808FD4A0CA191F01BB368AC3915DA27FD5CCA37B801308D3EEA5ACDBC3164C1"
OUTPUT = ROOT / "03_output" / "ui_full_v26_cumulative_patch_only.zip"
SOURCE_AUDIT = ROOT / "01_work" / "analysis" / "ui_tables_v24" / "psx_ui_tables.csv"
MANIFEST = ROOT / "05_docs" / "ui_full_v26.csv"
ANALYSIS = ROOT / "01_work" / "analysis" / "ui_full_v26"
READBACK = ANALYSIS / "readback.csv"
REPORT = ANALYSIS / "build_report.txt"

PSX_TARGET = "PSX.EXE"
PSX_LOAD_BASE = 0x8011A800
FILLER = 0x9C
GLYPHS_PER_ROW = 84
FONT_ROWS = 42
FONT_COLUMNS = 21
UI_FIRST_INDEX = 1240


TABLES = OrderedDict(
    (
        ("equipment_name", (64, (0x80224, 0x804A4), 0x804A4)),
        ("equipment_description", (64, (0x805A4, 0x80A94), 0x80A94)),
        ("consumable_name", (32, (0x80B94, 0x80C9C), 0x80C9C)),
        ("consumable_description", (32, (0x80D1C, 0x80F14), 0x80F14)),
        ("skill_name", (59, (0x80F94, 0x811C0), 0x811C0)),
        ("skill_description", (59, (0x812AC, 0x81708), 0x81708)),
        ("character_name", (108, (0x817F4, 0x81B4C), 0x81B4C)),
        ("region_name", (30, (0x81CFC, 0x81E38), 0x81E38)),
        ("location_name", (55, (0x81F04, 0x82170), 0x82170)),
    )
)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def csv_rows(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def ui_glyph_index(code: bytes) -> int:
    if len(code) != 2:
        raise ValueError(f"UI glyph must be two bytes: {code.hex()}")
    first, second = code
    if not 0xE1 <= first <= 0xE8 or second in (0x00, 0xFF):
        raise ValueError(f"UI glyph must use unique E1-E8/01-FE code: {code.hex()}")
    return (first - 0xDD) * 255 + second + 0xDB


def ui_codes() -> list[bytes]:
    result: list[bytes] = []
    for first in range(0xE1, 0xE9):
        for second in range(0x01, 0xFF):
            code = bytes((first, second))
            index = ui_glyph_index(code)
            if index < UI_FIRST_INDEX:
                continue
            row, remainder = divmod(index, GLYPHS_PER_ROW)
            column, _ = divmod(remainder, 4)
            if row < FONT_ROWS and column < FONT_COLUMNS:
                result.append(code)
    if len({ui_glyph_index(code) for code in result}) != len(result):
        raise SystemExit("UI glyph code list contains physical-index collisions")
    return result


def build_mapping() -> dict[str, bytes]:
    needed = sorted(
        {
            char
            for values in TRANSLATIONS.values()
            for text in values
            for char in text
            if char != " " and not (char.isascii() and char.isdigit())
        }
    )
    available = ui_codes()
    if len(needed) > len(available):
        raise SystemExit(f"UI glyph bank overflow: {len(needed)} > {len(available)}")
    return dict(zip(needed, available))


def encode(text: str, mapping: dict[str, bytes]) -> bytes:
    output = bytearray()
    for char in text:
        if char == " ":
            output.append(FILLER)
        elif char.isascii() and char.isdigit():
            output.append(0x11 + int(char))
        else:
            try:
                output.extend(mapping[char])
            except KeyError as exc:
                raise SystemExit(f"missing UI glyph for {char!r} in {text!r}") from exc
    return bytes(output)


def glyph_position(code: bytes) -> tuple[int, int, int, int]:
    index = ui_glyph_index(code)
    row, remainder = divmod(index, GLYPHS_PER_ROW)
    column, plane = divmod(remainder, 4)
    return index, row, column, plane


def write_ui_glyph(font: bytearray, code: bytes, char: str) -> None:
    _, row, column, plane = glyph_position(code)
    bit = 1 << plane
    glyph = render_glyph(char)
    for y in range(12):
        for x in range(12):
            px = column * 12 + x
            py = row * 12 + y
            old = get_pixel(font, px, py)
            new = old | bit if glyph.getpixel((x, y)) else old & ~bit
            if (new & ~bit) != (old & ~bit):
                raise SystemExit("UI font writer changed a neighboring bitplane")
            set_pixel(font, px, py, new)


def plane_bitmap(font: bytes | bytearray, code: bytes) -> tuple[int, ...]:
    _, row, column, plane = glyph_position(code)
    bit = 1 << plane
    return tuple(
        1 if get_pixel(font, column * 12 + x, row * 12 + y) & bit else 0
        for y in range(12)
        for x in range(12)
    )


def cursor_bytes(font: bytes | bytearray) -> bytes:
    return b"".join(font[y * ROW_BYTES : y * ROW_BYTES + 16] for y in range(128, 160))


def verify_font_changes(
    before: bytes, after: bytes, mapping: dict[str, bytes]
) -> tuple[int, int]:
    allowed: dict[tuple[int, int], int] = {}
    for code in mapping.values():
        _, row, column, plane = glyph_position(code)
        bit = 1 << plane
        for y in range(12):
            for x in range(12):
                key = (column * 12 + x, row * 12 + y)
                allowed[key] = allowed.get(key, 0) | bit

    changed_bytes = 0
    changed_nibbles = 0
    for offset, (old_byte, new_byte) in enumerate(zip(before, after)):
        if old_byte == new_byte:
            continue
        changed_bytes += 1
        y, byte_x = divmod(offset, ROW_BYTES)
        for half, shift in ((0, 0), (1, 4)):
            old = (old_byte >> shift) & 0x0F
            new = (new_byte >> shift) & 0x0F
            if old == new:
                continue
            changed_nibbles += 1
            x = byte_x * 2 + half
            if (old ^ new) & ~allowed.get((x, y), 0):
                raise SystemExit(f"COMM.IMG changed outside UI glyph planes at ({x},{y})")

    if cursor_bytes(before) != cursor_bytes(after):
        raise SystemExit("battle cursor rectangle changed")
    for char, code in mapping.items():
        expected = tuple(render_glyph(char).getpixel((x, y)) for y in range(12) for x in range(12))
        expected = tuple(1 if value else 0 for value in expected)
        if plane_bitmap(after, code) != expected:
            raise SystemExit(f"UI glyph readback failed for {char!r} at {code.hex().upper()}")
    return changed_bytes, changed_nibbles


def pointer_target(data: bytes | bytearray, table: int, index: int) -> int:
    return struct.unpack_from("<I", data, table + index * 4)[0] - PSX_LOAD_BASE


def raw_string(data: bytes | bytearray, offset: int) -> bytes:
    end = data.find(0, offset)
    if end < 0:
        raise SystemExit(f"unterminated string at 0x{offset:X}")
    return bytes(data[offset:end])


def allocate_pool(
    executable: bytearray, payloads: list[bytes]
) -> tuple[dict[bytes, int], list[int]]:
    segments = [block for _, block, _ in TABLES.values()]
    for start, end in segments:
        executable[start:end] = bytes(end - start)
    cursors = [start for start, _ in segments]
    locations: dict[bytes, int] = {}
    for payload in payloads:
        if payload in locations:
            continue
        required = len(payload) + 1
        for slot, ((_, end), cursor) in enumerate(zip(segments, cursors)):
            if cursor + required <= end:
                executable[cursor : cursor + len(payload)] = payload
                executable[cursor + len(payload)] = 0
                locations[payload] = cursor
                cursors[slot] += required
                break
        else:
            remaining = sum(end - cursor for (_, end), cursor in zip(segments, cursors))
            raise SystemExit(
                f"global UI string pool overflow for {len(payload)}-byte payload; "
                f"fragmented free={remaining}"
            )
    return locations, cursors


def verify_executable_changes(before: bytes, after: bytes) -> int:
    allowed = bytearray(len(after))
    for count, (start, end), pointer_table in TABLES.values():
        allowed[start:end] = b"\x01" * (end - start)
        allowed[pointer_table : pointer_table + count * 4] = b"\x01" * (count * 4)
    changed = 0
    for offset, (old, new) in enumerate(zip(before, after)):
        if old == new:
            continue
        changed += 1
        if not allowed[offset]:
            raise SystemExit(f"PSX.EXE changed outside declared UI ranges at 0x{offset:X}")
    return changed


def validate_inputs(audit_rows: list[dict[str, str]]) -> None:
    if set(TRANSLATIONS) != set(TABLES):
        raise SystemExit("translation table keys differ from the audited table keys")
    for key, (count, _, _) in TABLES.items():
        values = TRANSLATIONS[key]
        source = [row for row in audit_rows if row["table_key"] == key]
        if len(values) != count or len(source) != count:
            raise SystemExit(
                f"{key} count mismatch: translations={len(values)} audit={len(source)} expected={count}"
            )
        if [int(row["index"]) for row in source] != list(range(count)):
            raise SystemExit(f"{key} audit indices are not contiguous")
    if sum(len(values) for values in TRANSLATIONS.values()) != 503:
        raise SystemExit("full UI manifest must contain exactly 503 records")


def main() -> None:
    if digest(BASE.read_bytes()) != BASE_HASH:
        raise SystemExit("v0.25 cumulative base ZIP hash differs")

    audit_rows = csv_rows(SOURCE_AUDIT)
    validate_inputs(audit_rows)
    mapping = build_mapping()

    with ZipFile(BASE) as archive:
        infos = archive.infolist()
        files = {info.filename: archive.read(info.filename) for info in infos}
    before_files = dict(files)
    if PSX_TARGET not in files or FONT_TARGET not in files:
        raise SystemExit("cumulative base lacks PSX.EXE or COMM.IMG")

    executable = bytearray(files[PSX_TARGET])
    font = bytearray(files[FONT_TARGET])
    for char, code in mapping.items():
        write_ui_glyph(font, code, char)

    ordered: list[tuple[str, int, str, str, bytes]] = []
    payloads: list[bytes] = []
    for key, (count, _, _) in TABLES.items():
        source = [row for row in audit_rows if row["table_key"] == key]
        for index in range(count):
            korean = TRANSLATIONS[key][index]
            payload = encode(korean, mapping)
            ordered.append((key, index, source[index]["japanese"], korean, payload))
            payloads.append(payload)

    locations, cursors = allocate_pool(executable, payloads)
    readback_rows: list[dict[str, object]] = []
    manifest_rows: list[dict[str, object]] = []
    record_cursor = 0
    for key, (count, _, pointer_table) in TABLES.items():
        for index in range(count):
            table_key, row_index, japanese, korean, payload = ordered[record_cursor]
            if table_key != key or row_index != index:
                raise SystemExit("internal record order mismatch")
            target = locations[payload]
            struct.pack_into("<I", executable, pointer_table + index * 4, PSX_LOAD_BASE + target)
            readback_rows.append(
                {
                    "table_key": key,
                    "index": index,
                    "pointer_offset": f"0x{pointer_table + index * 4:X}",
                    "string_offset": f"0x{target:X}",
                    "encoded_bytes": len(payload),
                    "encoded_hex": payload.hex(" ").upper(),
                    "korean": korean,
                }
            )
            manifest_rows.append(
                {
                    "table_key": key,
                    "index": index,
                    "japanese": japanese,
                    "korean": korean,
                    "encoded_bytes": len(payload),
                    "source": "project_translation+guide_reference",
                }
            )
            record_cursor += 1

    allowed_segments = [block for _, block, _ in TABLES.values()]
    for row, (_, _, _, _, expected) in zip(readback_rows, ordered):
        key = str(row["table_key"])
        index = int(row["index"])
        _, _, pointer_table = TABLES[key]
        target = pointer_target(executable, pointer_table, index)
        if not any(start <= target < end for start, end in allowed_segments):
            raise SystemExit(f"{key}[{index}] pointer left the global UI pool")
        if raw_string(executable, target) != expected:
            raise SystemExit(f"{key}[{index}] readback differs")

    exe_changed = verify_executable_changes(before_files[PSX_TARGET], executable)
    font_changed, font_nibbles = verify_font_changes(before_files[FONT_TARGET], font, mapping)
    files[PSX_TARGET] = bytes(executable)
    files[FONT_TARGET] = bytes(font)
    changed_members = [name for name in files if files[name] != before_files[name]]
    if set(changed_members) != {PSX_TARGET, FONT_TARGET}:
        raise SystemExit(f"unexpected changed ZIP members: {changed_members}")

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with ZipFile(OUTPUT, "w", ZIP_DEFLATED, compresslevel=9) as archive:
        for info in infos:
            archive.writestr(info, files[info.filename])

    with ZipFile(OUTPUT) as archive:
        if archive.read(PSX_TARGET) != files[PSX_TARGET]:
            raise SystemExit("output PSX.EXE readback differs")
        if archive.read(FONT_TARGET) != files[FONT_TARGET]:
            raise SystemExit("output COMM.IMG readback differs")
        for name, before in before_files.items():
            if name not in {PSX_TARGET, FONT_TARGET} and archive.read(name) != before:
                raise SystemExit(f"output changed unrelated member: {name}")

    ANALYSIS.mkdir(parents=True, exist_ok=True)
    with MANIFEST.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(manifest_rows[0]))
        writer.writeheader()
        writer.writerows(manifest_rows)
    with READBACK.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(readback_rows[0]))
        writer.writeheader()
        writer.writerows(readback_rows)

    segments = [block for _, block, _ in TABLES.values()]
    free_bytes = sum(end - cursor for (_, end), cursor in zip(segments, cursors))
    report = [
        "UI full v0.26 cumulative patch",
        f"base_zip_sha256={BASE_HASH}",
        f"output_zip_sha256={digest(OUTPUT.read_bytes())}",
        "translated_records=503/503",
        f"ui_only_glyphs={len(mapping)}",
        f"ui_glyph_index_range={min(map(ui_glyph_index, mapping.values()))}-{max(map(ui_glyph_index, mapping.values()))}",
        f"deduplicated_strings={len(locations)}",
        f"global_pool_capacity={sum(end - start for start, end in segments)}",
        f"global_pool_free_bytes={free_bytes}",
        f"psx_exe_changed_bytes={exe_changed}",
        f"comm_img_changed_bytes={font_changed}",
        f"comm_img_changed_nibbles={font_nibbles}",
        "battle_cursor_preserved=true",
        "story_glyph_planes_preserved=true",
        "e2_code_caves_preserved=true",
        "unrelated_zip_members_preserved=true",
        f"changed_members={','.join(changed_members)}",
    ]
    REPORT.write_text("\n".join(report) + "\n", encoding="utf-8")
    print("\n".join(report))


if __name__ == "__main__":
    main()
