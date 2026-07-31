#!/usr/bin/env python3
"""Build v0.42 from the runtime-accepted v0.41 sparse glyph-store base.

This build restores the guide-based v0.26 UI wording without reintroducing its
continuous font-bank collision.  It keeps every accepted v0.41 E9/EA mapping,
adds only verified sparse physical planes, restores the battle cursor from
v0.37, and relocates E7 confirm/cancel icons outside the cursor texture.
"""

from __future__ import annotations

import csv
import hashlib
import struct
import sys
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))
sys.path.insert(0, str(ROOT / "06_tools" / "python_packages"))

from capstone import Cs, CS_ARCH_MIPS, CS_MODE_LITTLE_ENDIAN, CS_MODE_MIPS32  # noqa: E402
import build_ui_glyph_store_v40 as v40  # noqa: E402
import build_ui_glyph_store_v41 as v41  # noqa: E402
from build_story_sf0b1_return_full import get_pixel, render_glyph, set_pixel  # noqa: E402
from build_ui_full_v26 import PSX_LOAD_BASE, TABLES, pointer_target, raw_string  # noqa: E402
from build_ui_safe_v27 import load_mapping  # noqa: E402
from ui_full_v26_data import TRANSLATIONS  # noqa: E402


BASE = ROOT / "03_output" / "ui_glyph_store_v41_e9ea_probe_patch_only.zip"
BASE_HASH = "D5AC9441CB479F1B0B28B1732C97F52CCD284A8E73BE487AA16E41D9CC37BD78"
BASE_PSX_HASH = "C82EBFC4E2E9A1B3FCD8A3DF37D66BFCD6FE628C5257F0EF8BDDAAA7E3264B5E"
BASE_COMM_HASH = "32E43ED674DF30D745F3DE889493A5917F937CB5013B745ED24B455ECE231733"

V37 = ROOT / "03_output" / "ui_safe_v37_cumulative_patch_only.zip"
V37_HASH = "0583FEED2266C883B413260114F331D73FAC12AE1C9A17EB123D559D9EB29AA1"
V37_COMM_HASH = "FB6D4027023C6A75A1561D72507C52656472B4F31E1EB92B73965CA3B51543EA"

OUTPUT = ROOT / "03_output" / "ui_guide_terms_v42_v39_repairs_cumulative_patch_only.zip"
SOURCE_AUDIT = ROOT / "01_work" / "analysis" / "ui_tables_v24" / "psx_ui_tables.csv"
V41_MAP = ROOT / "05_docs" / "ui_glyph_store_v41_map.csv"
MANIFEST = ROOT / "05_docs" / "ui_full_v42.csv"
GLYPH_MAP = ROOT / "05_docs" / "ui_glyph_store_v42_map.csv"
REVIEW = ROOT / "05_docs" / "ui_items_equipment_skills_v42_review.csv"
SKILL_GUIDE_SOURCE = ROOT / "05_docs" / "ui_skill_guide_reference_v39.csv"
SKILL_GUIDE = ROOT / "05_docs" / "ui_skill_guide_reference_v42.csv"
ANALYSIS = ROOT / "01_work" / "analysis" / "ui_guide_repairs_v42"
READBACK = ANALYSIS / "readback.csv"
FONT_AUDIT = ANALYSIS / "font_audit.csv"
ICON_AUDIT = ANALYSIS / "icon_audit.csv"
HUD_AUDIT = ANALYSIS / "battle_hud_audit.csv"
DISASSEMBLY = ANALYSIS / "mips_disassembly.txt"
REPORT = ANALYSIS / "build_report.txt"

PSX_TARGET = "PSX.EXE"
FONT_TARGET = "COMM.IMG"
FILLER = 0x9C

# Keep the final 60 bytes of the native UI string pool for a loaded code stub
# and five fixed HUD strings.  All 503 table strings are packed below it.
RESERVE_START = 0x82134
RESERVE_END = 0x82170
ICON_STUB_OFFSET = 0x82134
ICON_STUB_ADDRESS = PSX_LOAD_BASE + ICON_STUB_OFFSET
HUD_SOURCES = (0x82154, 0x82158, 0x8215C, 0x82160, 0x82164)
HUD_POINTERS = (0x823AC, 0x823B0, 0x823B4, 0x823B8, 0x823BC)
V39_HUD_SOURCES = (0x820A8, 0x820AC, 0x820B0, 0x820B4, 0x820B8)
V39_HUD_PAYLOADS = (
    bytes.fromhex("6C 00 00 00"),
    bytes.fromhex("00 00 00 00"),
    bytes.fromhex("DD B2 00 00"),
    bytes.fromhex("01 DE 4F 00"),
    bytes.fromhex("DD 90 00 00"),
)

# E7 icon records are U,width pairs.  IDs 2 and 3 are confirm/cancel.
ICON_TABLE = 0x80210
ICON_U_OFFSETS = {2: ICON_TABLE + 4, 3: ICON_TABLE + 6}
EXPECTED_ICON_U = {2: 0x18, 3: 0x0C}
ICON_SOURCES = {2: (114, 354), 3: (162, 354)}
ICON_DESTINATIONS = {2: (180, 228), 3: (192, 228)}
ICON_PHYSICAL_INDICES = set(range(1656, 1664))
ICON_WIDTH = 12
ICON_HEIGHT = 12

# v0.38/v0.39 wrote E7 icons into the 32x32 battle-cursor texture.  Restore
# the affected three cells plus their border from the last clean v0.37 font.
CURSOR_X = 0
CURSOR_Y = 128
CURSOR_WIDTH = 36
CURSOR_HEIGHT = 32

E7_V_HOOK = 0x8016B6C8
E7_V_RETURN = 0x8016B6D0
EXPECTED_E7_V_HOOK = bytes.fromhex("82 00 02 34 29 00 02 A2")

# MIPS registers used by the compact E7 V-coordinate stub.
ZERO = 0
V0 = 2
V1 = 3
T0 = 8
S0 = 16


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def csv_rows(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    if not rows:
        raise SystemExit(f"refusing to write empty CSV: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    fields: list[str] = []
    for row in rows:
        for field in row:
            if field not in fields:
                fields.append(field)
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def translations() -> dict[str, list[str]]:
    result = {key: list(values) for key, values in TRANSLATIONS.items()}
    # These three were explicitly accepted by the user and must not regress to
    # the former "단계" wording.
    result["equipment_description"][8] = "던지기 레벨 +1"
    result["equipment_description"][20] = "점프 레벨 +1"
    result["equipment_description"][22] = "받기 레벨 +1"
    if set(result) != set(TABLES):
        raise SystemExit("translation table keys differ from audited UI tables")
    if sum(len(values) for values in result.values()) != 503:
        raise SystemExit("v0.42 must contain exactly 503 table records")
    for key, (count, _, _) in TABLES.items():
        if len(result[key]) != count:
            raise SystemExit(f"translation count differs for {key}")
    return result


def code_for_physical_index(index: int) -> bytes:
    """Return an index carrier for v40's plane helpers.

    Some verified sparse planes have a zero second byte and therefore were not
    directly addressable by the old E1-E8 text encoder.  The v0.41 lookup table
    returns physical indices directly, so those planes remain valid storage.
    """
    number = index - 0xDB
    if number < 0:
        raise ValueError(f"physical index below two-byte font range: {index}")
    return bytes((0xDD + number // 255, number % 255))


def virtual_and_physical_maps(
    texts: dict[str, list[str]], legacy: dict[str, bytes]
) -> tuple[list[str], dict[str, bytes], dict[str, bytes], list[dict[str, object]]]:
    old_rows = csv_rows(V41_MAP)
    if len(old_rows) != 278:
        raise SystemExit(f"v0.41 map count differs: {len(old_rows)}")

    old_chars = [row["char"] for row in old_rows]
    old_virtual = [bytes.fromhex(row["virtual_code_hex"]) for row in old_rows]
    old_indices = [int(row["physical_index"]) for row in old_rows]
    expected_codes = v41.virtual_codes(len(old_rows))
    if old_virtual != expected_codes:
        raise SystemExit("v0.41 virtual-code order differs")
    if len(set(old_chars)) != len(old_chars) or len(set(old_indices)) != len(old_indices):
        raise SystemExit("v0.41 glyph map contains duplicates")

    old_set = set(old_chars)
    text_chars = {
        char
        for values in texts.values()
        for text in values
        for char in text
    }
    new_hangul = sorted(
        char
        for char in text_chars
        if v40.is_hangul(char)
        and char not in old_set
        and (char not in legacy or len(legacy[char]) == 2)
    )
    new_chars = new_hangul + ["M", "P", "L", "V"]
    if len(new_hangul) != 127:
        raise SystemExit(f"guide-term Hangul count differs: {len(new_hangul)}")
    if old_set.intersection(new_chars):
        raise SystemExit("new glyph set overlaps v0.41 glyphs")

    ordered_chars = old_chars + new_chars
    virtual_codes = v41.virtual_codes(len(ordered_chars))
    virtual = dict(zip(ordered_chars, virtual_codes))

    physical_code_by_index = {
        index: code_for_physical_index(index)
        for index in v40.safe_physical_indices()
    }
    free_indices = sorted(
        v40.safe_physical_indices()
        - set(old_indices)
        - ICON_PHYSICAL_INDICES
    )
    if len(free_indices) < len(new_chars):
        raise SystemExit(
            f"verified sparse glyph planes exhausted: {len(free_indices)} < {len(new_chars)}"
        )
    new_indices = free_indices[: len(new_chars)]
    physical_indices = old_indices + new_indices
    physical_codes = {
        char: physical_code_by_index[index]
        for char, index in zip(ordered_chars, physical_indices)
    }

    rows: list[dict[str, object]] = []
    for position, (char, virtual_code, physical_index) in enumerate(
        zip(ordered_chars, virtual_codes, physical_indices)
    ):
        physical_code = physical_codes[char]
        _, row, column, plane = v40.glyph_position(physical_code)
        rows.append(
            {
                "char": char,
                "virtual_code_hex": virtual_code.hex(" ").upper(),
                "physical_code_hex": physical_code.hex(" ").upper(),
                "physical_index": physical_index,
                "row": row,
                "column": column,
                "plane": plane,
                "source_x": column * 12,
                "source_y": row * 12,
                "provenance": "v41_preserved" if position < len(old_rows) else "v42_sparse_extension",
            }
        )
    if len(rows) != 409:
        raise SystemExit(f"v0.42 lookup size differs: {len(rows)}")
    return ordered_chars, virtual, physical_codes, rows


def encode_text(text: str, legacy: dict[str, bytes], virtual: dict[str, bytes]) -> bytes:
    output = bytearray()
    for char in text:
        if char == " ":
            output.append(FILLER)
        elif char.isascii() and char.isdigit():
            output.append(0x11 + int(char))
        elif char == "%":
            output.append(0x06)
        elif char == "+":
            output.append(0x0C)
        elif char in virtual:
            output.extend(virtual[char])
        else:
            code = legacy.get(char)
            if code is None:
                raise SystemExit(f"missing code for {char!r} in {text!r}")
            if v40.is_hangul(char) and len(code) == 2:
                raise SystemExit(f"two-byte Hangul escaped sparse routing: {char!r}")
            output.extend(code)
    return bytes(output)


def pool_segments() -> list[tuple[int, int]]:
    segments = [block for _, block, _ in TABLES.values()]
    last_start, last_end = segments[-1]
    if last_end != RESERVE_END or not last_start < RESERVE_START < last_end:
        raise SystemExit("UI reserve no longer lies at the end of the location pool")
    return segments[:-1] + [(last_start, RESERVE_START)]


def allocate_pool(executable: bytearray, payloads: list[bytes]) -> tuple[dict[bytes, int], list[int]]:
    for _, (start, end), _ in TABLES.values():
        executable[start:end] = bytes(end - start)

    segments = pool_segments()
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
            free = sum(end - cursor for (_, end), cursor in zip(segments, cursors))
            raise SystemExit(
                f"UI string pool overflow for {len(payload)} bytes; fragmented free={free}"
            )
    return locations, cursors


def rectangle(data: bytes | bytearray, x: int, y: int, width: int, height: int) -> tuple[int, ...]:
    return tuple(
        get_pixel(data, x + dx, y + dy)
        for dy in range(height)
        for dx in range(width)
    )


def write_rectangle(
    data: bytearray, destination: tuple[int, int], pixels: tuple[int, ...], width: int, height: int
) -> None:
    for dy in range(height):
        for dx in range(width):
            set_pixel(data, destination[0] + dx, destination[1] + dy, pixels[dy * width + dx])


def build_icon_v_stub() -> bytes:
    asm = v41.Assembler(ICON_STUB_ADDRESS)
    asm.emit(v41.i_type(0x09, V1, T0, -4))       # addiu t0,v1,-4
    asm.emit(v41.i_type(0x0B, T0, T0, 3))        # sltiu t0,t0,3
    asm.branch(0x05, T0, ZERO, "store")          # IDs 2/3 use V=228
    asm.emit(v41.i_type(0x0D, ZERO, V0, 0xE4))   # delay slot
    asm.emit(v41.i_type(0x0D, ZERO, V0, 0x82))   # all other icons use V=130
    asm.label("store")
    asm.emit(v41.i_type(0x28, S0, V0, 0x29))     # sb v0,0x29(s0)
    asm.emit(v41.j(E7_V_RETURN))
    asm.emit(0)
    payload = asm.finish()
    if len(payload) != 32:
        raise SystemExit(f"E7 V stub size differs: {len(payload)}")
    return payload


def patch_font(
    base_font: bytes,
    v37_font: bytes,
    font: bytearray,
    old_count: int,
    ordered_chars: list[str],
    physical_codes: dict[str, bytes],
) -> list[dict[str, object]]:
    for char in ordered_chars[:old_count]:
        code = physical_codes[char]
        expected = tuple(
            1 if render_glyph(char).getpixel((x, y)) else 0
            for y in range(12) for x in range(12)
        )
        if v40.plane_bitmap(base_font, code) != expected:
            raise SystemExit(f"accepted v0.41 glyph differs for {char!r}")

    cursor = rectangle(v37_font, CURSOR_X, CURSOR_Y, CURSOR_WIDTH, CURSOR_HEIGHT)
    write_rectangle(font, (CURSOR_X, CURSOR_Y), cursor, CURSOR_WIDTH, CURSOR_HEIGHT)

    for physical_index in sorted(ICON_PHYSICAL_INDICES):
        code = code_for_physical_index(physical_index)
        if any(v40.plane_bitmap(base_font, code)):
            raise SystemExit(f"icon destination plane is occupied: {physical_index}")

    icon_rows: list[dict[str, object]] = []
    for icon_id in (2, 3):
        pixels = rectangle(font, *ICON_SOURCES[icon_id], ICON_WIDTH, ICON_HEIGHT)
        write_rectangle(font, ICON_DESTINATIONS[icon_id], pixels, ICON_WIDTH, ICON_HEIGHT)
        if rectangle(font, *ICON_DESTINATIONS[icon_id], ICON_WIDTH, ICON_HEIGHT) != pixels:
            raise SystemExit(f"icon {icon_id} readback differs")
        icon_rows.append(
            {
                "icon_id": f"E7_{icon_id:02d}",
                "source_x": ICON_SOURCES[icon_id][0],
                "source_y": ICON_SOURCES[icon_id][1],
                "destination_x": ICON_DESTINATIONS[icon_id][0],
                "destination_y": ICON_DESTINATIONS[icon_id][1],
                "width": ICON_WIDTH,
                "height": ICON_HEIGHT,
                "status": "relocated_outside_battle_cursor",
            }
        )

    for char in ordered_chars[old_count:]:
        code = physical_codes[char]
        if any(v40.plane_bitmap(font, code)):
            raise SystemExit(f"new sparse plane is not blank for {char!r}")
        v40.write_glyph(font, code, char)

    verify_font_changes(
        base_font, bytes(font), v37_font, ordered_chars, physical_codes, old_count
    )
    return icon_rows


def verify_font_changes(
    before: bytes,
    after: bytes,
    v37_font: bytes,
    ordered_chars: list[str],
    physical_codes: dict[str, bytes],
    old_count: int,
) -> tuple[int, int]:
    allowed: dict[tuple[int, int], int] = {}
    for char in ordered_chars[old_count:]:
        _, row, column, plane = v40.glyph_position(physical_codes[char])
        bit = 1 << plane
        for y in range(12):
            for x in range(12):
                key = (column * 12 + x, row * 12 + y)
                allowed[key] = allowed.get(key, 0) | bit
    for y in range(CURSOR_Y, CURSOR_Y + CURSOR_HEIGHT):
        for x in range(CURSOR_X, CURSOR_X + CURSOR_WIDTH):
            allowed[(x, y)] = 0x0F
    for x, y in ICON_DESTINATIONS.values():
        for dy in range(ICON_HEIGHT):
            for dx in range(ICON_WIDTH):
                allowed[(x + dx, y + dy)] = 0x0F

    changed_bytes = 0
    changed_nibbles = 0
    row_bytes = 0x380
    for offset, (old_byte, new_byte) in enumerate(zip(before, after)):
        if old_byte == new_byte:
            continue
        changed_bytes += 1
        y, byte_x = divmod(offset, row_bytes)
        for half, shift in ((0, 0), (1, 4)):
            old = (old_byte >> shift) & 0x0F
            new = (new_byte >> shift) & 0x0F
            if old == new:
                continue
            changed_nibbles += 1
            x = byte_x * 2 + half
            if (old ^ new) & ~allowed.get((x, y), 0):
                raise SystemExit(f"COMM.IMG changed outside v0.42 declarations at ({x},{y})")

    for char in ordered_chars:
        expected = tuple(
            1 if render_glyph(char).getpixel((x, y)) else 0
            for y in range(12) for x in range(12)
        )
        if v40.plane_bitmap(after, physical_codes[char]) != expected:
            raise SystemExit(f"v0.42 glyph readback failed for {char!r}")
    if rectangle(after, CURSOR_X, CURSOR_Y, CURSOR_WIDTH, CURSOR_HEIGHT) != rectangle(
        v37_font, CURSOR_X, CURSOR_Y, CURSOR_WIDTH, CURSOR_HEIGHT
    ):
        raise SystemExit("battle cursor rectangle was not restored to v0.37")
    for icon_id in (2, 3):
        if rectangle(after, *ICON_DESTINATIONS[icon_id], ICON_WIDTH, ICON_HEIGHT) != rectangle(
            after, *ICON_SOURCES[icon_id], ICON_WIDTH, ICON_HEIGHT
        ):
            raise SystemExit(f"relocated icon {icon_id} differs from verified source")
    return changed_bytes, changed_nibbles


def allowed_psx_changes(before: bytes, after: bytes) -> int:
    allowed = bytearray(len(after))
    for count, (start, end), pointer_table in TABLES.values():
        allowed[start:end] = b"\x01" * (end - start)
        allowed[pointer_table : pointer_table + count * 4] = b"\x01" * (count * 4)
    cave_offset = v41.file_offset(v41.CAVE_START)
    allowed[cave_offset : cave_offset + v41.CAVE_SIZE] = b"\x01" * v41.CAVE_SIZE
    hook_offset = v41.file_offset(E7_V_HOOK)
    allowed[hook_offset : hook_offset + 8] = b"\x01" * 8
    for offset in ICON_U_OFFSETS.values():
        allowed[offset] = 1
    for pointer in HUD_POINTERS:
        allowed[pointer : pointer + 4] = b"\x01" * 4

    changed = 0
    for offset, (old, new) in enumerate(zip(before, after)):
        if old == new:
            continue
        changed += 1
        if not allowed[offset]:
            raise SystemExit(f"PSX.EXE changed outside v0.42 declarations at 0x{offset:X}")
    return changed


def main() -> None:
    if digest(BASE.read_bytes()) != BASE_HASH:
        raise SystemExit("accepted v0.41 base ZIP hash differs")
    if digest(V37.read_bytes()) != V37_HASH:
        raise SystemExit("clean v0.37 reference ZIP hash differs")

    texts = translations()
    audit_rows = csv_rows(SOURCE_AUDIT)
    audit_by_key = {
        (row["table_key"], int(row["index"])): row for row in audit_rows
    }
    if len(audit_by_key) != 503:
        raise SystemExit(f"source UI audit count differs: {len(audit_by_key)}")

    legacy = load_mapping()
    ordered_chars, virtual, physical_codes, glyph_rows = virtual_and_physical_maps(texts, legacy)
    old_glyph_count = 278
    physical_indices = [int(row["physical_index"]) for row in glyph_rows]

    with ZipFile(BASE) as archive:
        infos = archive.infolist()
        files = {info.filename: archive.read(info.filename) for info in infos}
    with ZipFile(V37) as archive:
        v37_font = archive.read(FONT_TARGET)
    before_files = dict(files)
    if digest(files[PSX_TARGET]) != BASE_PSX_HASH:
        raise SystemExit("accepted v0.41 PSX.EXE hash differs")
    if digest(files[FONT_TARGET]) != BASE_COMM_HASH:
        raise SystemExit("accepted v0.41 COMM.IMG hash differs")
    if digest(v37_font) != V37_COMM_HASH:
        raise SystemExit("clean v0.37 COMM.IMG hash differs")

    base_executable = files[PSX_TARGET]
    executable = bytearray(base_executable)
    base_font = files[FONT_TARGET]
    font = bytearray(base_font)

    old_indices = physical_indices[:old_glyph_count]
    old_cave, old_layout = v41.assemble_cave(old_indices)
    cave_offset = v41.file_offset(v41.CAVE_START)
    if base_executable[cave_offset : cave_offset + v41.CAVE_SIZE] != old_cave:
        raise SystemExit("accepted v0.41 cave differs from documented layout")
    for hook, target in (
        (v41.PRECLASS_HOOK, old_layout["pre_stub"]),
        (v41.MAINCLASS_HOOK, old_layout["main_stub"]),
        (v41.DECODER_HOOK, old_layout["decoder_stub"]),
    ):
        expected = struct.pack("<II", v41.j(target), 0)
        offset = v41.file_offset(hook)
        if base_executable[offset : offset + 8] != expected:
            raise SystemExit(f"accepted v0.41 hook differs at 0x{hook:08X}")

    icon_rows = patch_font(
        base_font, v37_font, font, old_glyph_count, ordered_chars, physical_codes
    )

    ordered_records: list[tuple[str, int, str, str, bytes]] = []
    payloads: list[bytes] = []
    for key, (count, _, _) in TABLES.items():
        for index in range(count):
            source = audit_by_key[(key, index)]
            korean = texts[key][index]
            payload = encode_text(korean, legacy, virtual)
            ordered_records.append((key, index, source["japanese"], korean, payload))
            payloads.append(payload)

    # Capture inherited v0.39 HUD inputs before the table pools are cleared.
    for pointer, source, payload in zip(HUD_POINTERS, V39_HUD_SOURCES, V39_HUD_PAYLOADS):
        if struct.unpack_from("<I", base_executable, pointer)[0] != PSX_LOAD_BASE + source:
            raise SystemExit(f"inherited v0.39 HUD pointer differs at 0x{pointer:X}")
        if base_executable[source : source + len(payload)] != payload:
            raise SystemExit(f"inherited v0.39 HUD payload differs at 0x{source:X}")

    locations, cursors = allocate_pool(executable, payloads)
    manifest_rows: list[dict[str, object]] = []
    readback_rows: list[dict[str, object]] = []
    for key, index, japanese, korean, payload in ordered_records:
        pointer_table = TABLES[key][2]
        target = locations[payload]
        struct.pack_into("<I", executable, pointer_table + index * 4, PSX_LOAD_BASE + target)
        row = {
            "table_key": key,
            "index": index,
            "japanese": japanese,
            "korean": korean,
            "encoded_bytes": len(payload),
            "encoded_hex": payload.hex(" ").upper(),
            "pointer_offset": f"0x{pointer_table + index * 4:X}",
            "string_offset": f"0x{target:X}",
            "source": "project_translation+local_guide_reference",
        }
        manifest_rows.append(row)
        readback_rows.append(dict(row))

    for row in manifest_rows:
        key = str(row["table_key"])
        index = int(row["index"])
        target = pointer_target(executable, TABLES[key][2], index)
        expected = bytes.fromhex(str(row["encoded_hex"]))
        if not any(start <= target < end for start, end in pool_segments()):
            raise SystemExit(f"v0.42 pointer left declared pool: {key}[{index}]")
        if target >= RESERVE_START:
            raise SystemExit(f"v0.42 pointer entered reserve: {key}[{index}]")
        if raw_string(executable, target) != expected:
            raise SystemExit(f"v0.42 string readback failed: {key}[{index}]")

    expanded_cave, layout = v41.assemble_cave(physical_indices)
    if layout["used_end"] > v41.CAVE_LIMIT:
        raise SystemExit("expanded E9/EA lookup table overflowed verified cave")
    executable[cave_offset : cave_offset + v41.CAVE_SIZE] = expanded_cave

    if executable[v41.file_offset(E7_V_HOOK) : v41.file_offset(E7_V_HOOK) + 8] != EXPECTED_E7_V_HOOK:
        raise SystemExit("E7 V-coordinate hook source differs")
    icon_stub = build_icon_v_stub()
    executable[ICON_STUB_OFFSET : ICON_STUB_OFFSET + len(icon_stub)] = icon_stub
    struct.pack_into(
        "<II", executable, v41.file_offset(E7_V_HOOK), v41.j(ICON_STUB_ADDRESS), 0
    )

    for icon_id, destination in ICON_DESTINATIONS.items():
        offset = ICON_U_OFFSETS[icon_id]
        if base_executable[offset] != EXPECTED_ICON_U[icon_id]:
            raise SystemExit(f"inherited icon U differs for E7_{icon_id:02d}")
        if base_executable[offset + 1] != ICON_WIDTH:
            raise SystemExit(f"inherited icon width differs for E7_{icon_id:02d}")
        executable[offset] = destination[0]

    hud_payloads = (
        virtual["L"] + b"\x00\x00",
        virtual["V"] + b"\x00\x00",
        bytes.fromhex("DD B2 00 00"),
        bytes.fromhex("01 DE 4F 00"),
        bytes.fromhex("DD 90 00 00"),
    )
    hud_labels = ("L", "V", "original auxiliary", "M", "P")
    hud_rows: list[dict[str, object]] = []
    for pointer, source, payload, label in zip(HUD_POINTERS, HUD_SOURCES, hud_payloads, hud_labels):
        executable[source : source + len(payload)] = payload
        struct.pack_into("<I", executable, pointer, PSX_LOAD_BASE + source)
        if executable[source : source + len(payload)] != payload:
            raise SystemExit(f"HUD payload readback failed at 0x{source:X}")
        hud_rows.append(
            {
                "pointer_offset": f"0x{pointer:X}",
                "string_offset": f"0x{source:X}",
                "label": label,
                "payload_hex": payload.hex(" ").upper(),
                "status": "separate_sparse_glyph_labels",
            }
        )

    # The reserve must contain only the documented stub/HUD payloads and zeros.
    reserve_allowed = bytearray(RESERVE_END - RESERVE_START)
    reserve_allowed[: len(icon_stub)] = b"\x01" * len(icon_stub)
    for source, payload in zip(HUD_SOURCES, hud_payloads):
        start = source - RESERVE_START
        reserve_allowed[start : start + len(payload)] = b"\x01" * len(payload)
    for index, value in enumerate(executable[RESERVE_START:RESERVE_END]):
        if value and not reserve_allowed[index]:
            raise SystemExit(f"unexpected nonzero reserve byte at 0x{RESERVE_START + index:X}")

    changed_psx_bytes = allowed_psx_changes(base_executable, bytes(executable))
    changed_font_bytes, changed_font_nibbles = verify_font_changes(
        base_font, bytes(font), v37_font, ordered_chars, physical_codes, old_glyph_count
    )

    files[PSX_TARGET] = bytes(executable)
    files[FONT_TARGET] = bytes(font)
    changed_members = [name for name in files if files[name] != before_files[name]]
    if changed_members != [FONT_TARGET, PSX_TARGET]:
        raise SystemExit(f"unexpected changed ZIP members: {changed_members}")

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    temporary = OUTPUT.with_suffix(".tmp")
    with ZipFile(temporary, "w", ZIP_DEFLATED, compresslevel=9) as archive:
        for info in infos:
            archive.writestr(info, files[info.filename])
    temporary.replace(OUTPUT)
    with ZipFile(OUTPUT) as archive:
        for name, expected in files.items():
            if archive.read(name) != expected:
                raise SystemExit(f"output ZIP readback differs: {name}")

    ANALYSIS.mkdir(parents=True, exist_ok=True)
    write_csv(MANIFEST, manifest_rows)
    write_csv(READBACK, readback_rows)
    write_csv(GLYPH_MAP, glyph_rows)
    review_rows = [
        {
            "category": row["table_key"],
            "index": row["index"],
            "japanese": row["japanese"],
            "korean_display": row["korean"],
            "application_status": "guide_term_restored_v42",
            "encoded_bytes": row["encoded_bytes"],
            "encoded_hex": row["encoded_hex"],
            "pointer_offset": row["pointer_offset"],
            "string_offset": row["string_offset"],
        }
        for row in manifest_rows
        if str(row["table_key"]).startswith(("equipment_", "consumable_", "skill_"))
    ]
    write_csv(REVIEW, review_rows)
    write_csv(ICON_AUDIT, icon_rows)
    write_csv(HUD_AUDIT, hud_rows)

    skill_guide_rows = csv_rows(SKILL_GUIDE_SOURCE)
    for row in skill_guide_rows:
        record_type = row["record_type"]
        if record_type in ("skill_name", "skill_description"):
            row["korean"] = texts[record_type][int(row["index"])]
            row["basis"] = row["basis"] + "; v0.42 공략본 기준 명칭/효과 복원"
    write_csv(SKILL_GUIDE, skill_guide_rows)

    font_rows = [
        {
            "char": row["char"],
            "virtual_code_hex": row["virtual_code_hex"],
            "physical_index": row["physical_index"],
            "row": row["row"],
            "column": row["column"],
            "plane": row["plane"],
            "provenance": row["provenance"],
            "readback": "exact",
        }
        for row in glyph_rows
    ]
    write_csv(FONT_AUDIT, font_rows)

    md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN)
    disassembly_lines: list[str] = []
    disassembly_targets = [
        ("pre_stub", layout["pre_stub"], layout["pre_size"]),
        ("main_stub", layout["main_stub"], layout["main_size"]),
        ("decoder_stub", layout["decoder_stub"], layout["decoder_size"]),
        ("e7_v_stub", ICON_STUB_ADDRESS, len(icon_stub)),
    ]
    for name, address, size in disassembly_targets:
        payload = executable[address - PSX_LOAD_BASE : address - PSX_LOAD_BASE + size]
        instructions = list(md.disasm(payload, address))
        if len(instructions) != size // 4:
            raise SystemExit(f"incomplete MIPS disassembly for {name}")
        disassembly_lines.append(f"[{name}] 0x{address:08X} size={size}")
        disassembly_lines.extend(
            f"0x{item.address:08X}: {item.mnemonic} {item.op_str}" for item in instructions
        )
    DISASSEMBLY.write_text("\n".join(disassembly_lines) + "\n", encoding="utf-8")

    segment_free = [end - cursor for (_, end), cursor in zip(pool_segments(), cursors)]
    report = [
        "UI guide terms v0.42 with v0.39 inherited-defect repairs",
        f"base_zip_sha256={BASE_HASH}",
        f"output_zip_sha256={digest(OUTPUT.read_bytes())}",
        f"output_psx_sha256={digest(files[PSX_TARGET])}",
        f"output_comm_sha256={digest(files[FONT_TARGET])}",
        "base_runtime_status=USER_ACCEPTED_V41",
        "story_e2_members_unchanged=true",
        "dynamic_control_prefixes_e1_e8_preserved=true",
        "virtual_glyph_prefixes=E9,EA",
        f"lookup_entries={len(glyph_rows)}",
        f"preserved_v41_glyphs={old_glyph_count}",
        f"new_sparse_glyphs={len(glyph_rows) - old_glyph_count}",
        f"lookup_table=0x{layout['lookup_table']:08X}",
        f"lookup_size={layout['lookup_size']}",
        f"cave_free_bytes={v41.CAVE_LIMIT - layout['used_end']}",
        "translated_ui_records=503",
        f"unique_ui_payloads={len(locations)}",
        f"ui_pool_free_bytes={sum(segment_free)}",
        f"ui_pool_segment_free={','.join(str(value) for value in segment_free)}",
        "guide_level_overrides=equipment_description[8,20,22]",
        "system_level_wording_preserved=레벨 업!!|레벨이 올랐다",
        "battle_hud_lv=separate L and V sparse glyphs",
        "battle_cursor=v37 exact rectangle restored",
        "confirm_cancel_icons=relocated to U=180/192,V=228",
        f"e7_v_stub=0x{ICON_STUB_ADDRESS:08X},size={len(icon_stub)}",
        f"changed_psx_bytes={changed_psx_bytes}",
        f"changed_comm_bytes={changed_font_bytes}",
        f"changed_comm_nibbles={changed_font_nibbles}",
        f"changed_members={','.join(changed_members)}",
        "runtime_status=UNVERIFIED_CANDIDATE",
    ]
    REPORT.write_text("\n".join(report) + "\n", encoding="utf-8")
    print("\n".join(report))


if __name__ == "__main__":
    main()
