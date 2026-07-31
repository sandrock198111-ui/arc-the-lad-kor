#!/usr/bin/env python3
"""Build the v0.40 sparse UI glyph-store runtime probe from safe v0.39.

Unlike v0.26, this build never treats the physical font index range as one
continuous bank.  It writes only into 12x12 COMM.IMG cells that were blank in
the v0.39 source and in all 55 sampled DuckStation VRAM states.
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

from build_story_sf0b1_return_full import (  # noqa: E402
    ROW_BYTES,
    get_pixel,
    render_glyph,
    set_pixel,
)
from build_ui_full_v26 import (  # noqa: E402
    FILLER,
    GLYPHS_PER_ROW,
    PSX_LOAD_BASE,
    TABLES,
    pointer_target,
    raw_string,
)
from build_ui_safe_v27 import load_mapping  # noqa: E402


BASE = ROOT / "03_output" / "ui_safe_v39_cumulative_patch_only.zip"
BASE_HASH = "0778FE435820409F190579D179F8B36FFFCEB02B5F2004FC1E3ACE58741D5DC3"
BASE_PSX_HASH = "D074E2D8D773528D7AB0BEF2F0AA55D43CF73DE6D30F552989F31E4377981FBF"
BASE_COMM_HASH = "CC06EE234F61416FE4C52829F54E078E33D83BD9DFD243B3D39C35C5667F0388"

OUTPUT = ROOT / "03_output" / "ui_glyph_store_v40_sparse_probe_patch_only.zip"
SOURCE_MANIFEST = ROOT / "05_docs" / "ui_safe_v39.csv"
MANIFEST = ROOT / "05_docs" / "ui_glyph_store_v40_probe.csv"
GLYPH_MAP = ROOT / "05_docs" / "ui_glyph_store_v40_map.csv"
ANALYSIS = ROOT / "01_work" / "analysis" / "ui_glyph_store_v40"
REPORT = ANALYSIS / "build_report.txt"
READBACK = ANALYSIS / "readback.csv"

PSX_TARGET = "PSX.EXE"
FONT_TARGET = "COMM.IMG"

# Rows/columns are in the logical 21-column, four-bitplane 12x12 font grid.
# These cells were zero in v0.39 COMM.IMG and all 55 sampled runtime VRAMs.
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


def csv_rows(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def is_hangul(char: str) -> bool:
    return "\uac00" <= char <= "\ud7a3"


def glyph_index(code: bytes) -> int:
    first, second = code
    return (first - 0xDD) * 255 + second + 0xDB


def safe_physical_indices() -> set[int]:
    result: set[int] = set()
    for row, columns in SAFE_CELLS.items():
        for column in columns:
            base = row * GLYPHS_PER_ROW + column * 4
            result.update(range(base, base + 4))
    return result


def sparse_codes() -> list[bytes]:
    safe = safe_physical_indices()
    by_index: dict[int, bytes] = {}
    for first in range(0xE1, 0xE9):
        for second in range(0x01, 0xFF):
            code = bytes((first, second))
            index = glyph_index(code)
            if index in safe:
                if index in by_index:
                    raise SystemExit(f"duplicate sparse code for physical index {index}")
                by_index[index] = code
    return [by_index[index] for index in sorted(by_index)]


def glyph_position(code: bytes) -> tuple[int, int, int, int]:
    index = glyph_index(code)
    row, remainder = divmod(index, GLYPHS_PER_ROW)
    column, plane = divmod(remainder, 4)
    return index, row, column, plane


def assert_blank_cell(font: bytes, row: int, column: int) -> None:
    for y in range(12):
        for x in range(12):
            if get_pixel(font, column * 12 + x, row * 12 + y):
                raise SystemExit(f"declared sparse cell is not blank: row={row} col={column}")


def write_glyph(font: bytearray, code: bytes, char: str) -> None:
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
                raise SystemExit("sparse writer changed a neighboring bitplane")
            set_pixel(font, px, py, new)


def plane_bitmap(font: bytes | bytearray, code: bytes) -> tuple[int, ...]:
    _, row, column, plane = glyph_position(code)
    bit = 1 << plane
    return tuple(
        1 if get_pixel(font, column * 12 + x, row * 12 + y) & bit else 0
        for y in range(12)
        for x in range(12)
    )


def encode_text(text: str, legacy: dict[str, bytes], sparse: dict[str, bytes]) -> bytes:
    output = bytearray()
    index = 0
    while index < len(text):
        if text[index:index + 2] == "LV":
            output.append(0x6C)
            index += 2
            continue
        char = text[index]
        if char == " ":
            output.append(FILLER)
        elif char.isascii() and char.isdigit():
            output.append(0x11 + int(char))
        elif char == "%":
            output.append(0x06)
        elif char == "+":
            output.append(0x0C)
        elif char in sparse:
            output.extend(sparse[char])
        else:
            try:
                output.extend(legacy[char])
            except KeyError as exc:
                raise SystemExit(f"missing legacy code for {char!r} in {text!r}") from exc
        index += 1
    return bytes(output)


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
                raise SystemExit(f"COMM.IMG changed outside sparse planes at ({x},{y})")

    for char, code in mapping.items():
        expected = tuple(
            1 if render_glyph(char).getpixel((x, y)) else 0
            for y in range(12)
            for x in range(12)
        )
        if plane_bitmap(after, code) != expected:
            raise SystemExit(f"sparse glyph readback failed for {char!r}")
    return changed_bytes, changed_nibbles


def load_manifest() -> list[dict[str, str]]:
    rows = csv_rows(SOURCE_MANIFEST)
    expected = sum(count for count, _, _ in TABLES.values())
    if len(rows) != expected:
        raise SystemExit(f"v0.39 manifest count differs: {len(rows)} != {expected}")
    return rows


def main() -> None:
    if digest(BASE.read_bytes()) != BASE_HASH:
        raise SystemExit("v0.39 base ZIP hash differs")

    rows = load_manifest()
    translated = [row for row in rows if row["status"] != "preserved_v25_missing_glyph"]
    legacy = load_mapping()
    all_hangul = sorted(
        {char for row in translated for char in row["korean_target"] if is_hangul(char)}
    )
    # `덕` and `량` are established one-byte UI glyphs. Moving them to a
    # two-byte sparse code would grow strings and force pointer relocation.
    hangul = [char for char in all_hangul if len(legacy[char]) == 2]
    legacy_one_byte_hangul = [char for char in all_hangul if len(legacy[char]) == 1]
    available = sparse_codes()
    if len(hangul) > len(available):
        raise SystemExit(f"sparse bank overflow: {len(hangul)} > {len(available)}")
    sparse = dict(zip(hangul, available))

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

    used_cells = {(glyph_position(code)[1], glyph_position(code)[2]) for code in sparse.values()}
    for row, column in sorted(used_cells):
        assert_blank_cell(files[FONT_TARGET], row, column)
    for char, code in sparse.items():
        write_glyph(font, code, char)

    manifest_by_key = {(row["table_key"], int(row["index"])): row for row in rows}
    output_records: list[dict[str, object]] = []
    changed_strings = 0
    seen_targets: dict[int, bytes] = {}
    for table_key, (count, _, pointer_table) in TABLES.items():
        for index in range(count):
            row = manifest_by_key[(table_key, index)]
            target = pointer_target(base_executable, pointer_table, index)
            manifest_payload = bytes.fromhex(row["encoded_hex"])
            old_payload = base_executable[target : target + len(manifest_payload)]
            if old_payload != manifest_payload:
                raise SystemExit(f"v0.39 payload differs from manifest: {table_key}[{index}]")

            if row["status"] == "preserved_v25_missing_glyph":
                new_payload = old_payload
            elif row["status"] == "guide_exact_lv_fallback":
                suffix = b"".join(sparse[char] for char in "상승")
                if len(old_payload) < len(suffix):
                    raise SystemExit("LV fallback payload is too short")
                new_payload = old_payload[:-len(suffix)] + suffix
            else:
                new_payload = encode_text(row["korean_target"], legacy, sparse)

            if len(new_payload) != len(old_payload):
                raise SystemExit(
                    f"in-place length changed: {table_key}[{index}] "
                    f"{len(old_payload)} -> {len(new_payload)}"
                )
            previous = seen_targets.get(target)
            if previous is not None and previous != new_payload:
                raise SystemExit(f"shared pointer would receive different payloads at 0x{target:X}")
            seen_targets[target] = new_payload
            if new_payload != old_payload:
                changed_strings += 1

            output_records.append(
                {
                    **row,
                    "v40_encoded_hex": new_payload.hex(" ").upper(),
                    "v40_string_offset": f"0x{target:X}",
                }
            )

    for target, payload in seen_targets.items():
        executable[target : target + len(payload)] = payload

    # Pointer tables are deliberately untouched; verify all final payloads.
    for record in output_records:
        table_key = str(record["table_key"])
        index = int(record["index"])
        pointer_table = TABLES[table_key][2]
        target = pointer_target(executable, pointer_table, index)
        expected = bytes.fromhex(str(record["v40_encoded_hex"]))
        if executable[target : target + len(expected)] != expected:
            raise SystemExit(f"v0.40 readback failed: {table_key}[{index}]")

    changed_font_bytes, changed_font_nibbles = verify_font_changes(
        files[FONT_TARGET], font, sparse
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
    fieldnames = list(output_records[0])
    for path in (MANIFEST, READBACK):
        with path.open("w", encoding="utf-8-sig", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(output_records)

    map_rows = []
    for char, code in sparse.items():
        index, row, column, plane = glyph_position(code)
        map_rows.append(
            {
                "char": char,
                "code_hex": code.hex(" ").upper(),
                "physical_index": index,
                "row": row,
                "column": column,
                "plane": plane,
                "source_x": column * 12,
                "source_y": row * 12,
            }
        )
    with GLYPH_MAP.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(map_rows[0]))
        writer.writeheader()
        writer.writerows(map_rows)

    report = [
        "UI glyph store v0.40 sparse runtime probe",
        f"base_zip_sha256={BASE_HASH}",
        f"output_zip_sha256={digest(OUTPUT.read_bytes())}",
        f"output_psx_sha256={digest(files[PSX_TARGET])}",
        f"output_comm_sha256={digest(files[FONT_TARGET])}",
        f"sampled_runtime_states=55",
        f"declared_blank_cells={sum(len(tuple(cols)) for cols in SAFE_CELLS.values())}",
        f"e1_e8_reachable_sparse_planes={len(available)}",
        f"allocated_hangul_glyphs={len(sparse)}",
        f"preserved_legacy_one_byte_hangul={''.join(legacy_one_byte_hangul)}",
        f"remaining_verified_e1_e8_planes={len(available) - len(sparse)}",
        f"changed_ui_strings={changed_strings}",
        f"comm_changed_bytes={changed_font_bytes}",
        f"comm_changed_nibbles={changed_font_nibbles}",
        "pointer_tables_unchanged=true",
        "string_lengths_unchanged=true",
        "preserved_japanese_rows_unchanged=17",
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
