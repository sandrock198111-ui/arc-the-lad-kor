#!/usr/bin/env python3
"""Independently audit the v0.42 patch-only ZIP and its review manifests."""

from __future__ import annotations

import hashlib
import struct
import sys
from pathlib import Path
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))
sys.path.insert(0, str(ROOT / "06_tools" / "python_packages"))

import build_ui_glyph_store_v40 as v40  # noqa: E402
import build_ui_glyph_store_v41 as v41  # noqa: E402
import build_ui_guide_repairs_v42 as v42  # noqa: E402
from build_story_sf0b1_return_full import render_glyph  # noqa: E402
from build_ui_full_v26 import PSX_LOAD_BASE, TABLES, pointer_target, raw_string  # noqa: E402
from build_ui_safe_v27 import load_mapping  # noqa: E402


REPORT = v42.ANALYSIS / "independent_audit.txt"


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def main() -> None:
    if digest(v42.BASE.read_bytes()) != v42.BASE_HASH:
        raise SystemExit("v0.41 base ZIP hash differs during audit")
    if digest(v42.V37.read_bytes()) != v42.V37_HASH:
        raise SystemExit("v0.37 cursor reference ZIP hash differs during audit")
    if not v42.OUTPUT.exists():
        raise SystemExit("v0.42 output ZIP is missing")

    with ZipFile(v42.BASE) as archive:
        base_infos = archive.infolist()
        base_files = {info.filename: archive.read(info.filename) for info in base_infos}
    with ZipFile(v42.OUTPUT) as archive:
        output_infos = archive.infolist()
        output_files = {info.filename: archive.read(info.filename) for info in output_infos}
    with ZipFile(v42.V37) as archive:
        v37_font = archive.read(v42.FONT_TARGET)

    if [item.filename for item in output_infos] != [item.filename for item in base_infos]:
        raise SystemExit("output member order/list differs from v0.41")
    changed_members = [
        name for name in base_files if base_files[name] != output_files[name]
    ]
    if changed_members != [v42.FONT_TARGET, v42.PSX_TARGET]:
        raise SystemExit(f"unexpected changed members: {changed_members}")
    for name in base_files:
        if name not in changed_members and output_files[name] != base_files[name]:
            raise SystemExit(f"unrelated member changed: {name}")

    base_executable = base_files[v42.PSX_TARGET]
    executable = output_files[v42.PSX_TARGET]
    base_font = base_files[v42.FONT_TARGET]
    font = output_files[v42.FONT_TARGET]

    manifest = v42.csv_rows(v42.MANIFEST)
    if len(manifest) != 503:
        raise SystemExit(f"v0.42 manifest count differs: {len(manifest)}")
    translations = v42.translations()
    seen_records: set[tuple[str, int]] = set()
    unique_payloads: set[bytes] = set()
    for row in manifest:
        key = row["table_key"]
        index = int(row["index"])
        record = (key, index)
        if record in seen_records:
            raise SystemExit(f"duplicate manifest record: {record}")
        seen_records.add(record)
        if row["korean"] != translations[key][index]:
            raise SystemExit(f"manifest translation differs: {key}[{index}]")
        pointer_table = TABLES[key][2]
        if int(row["pointer_offset"], 0) != pointer_table + index * 4:
            raise SystemExit(f"manifest pointer offset differs: {key}[{index}]")
        target = pointer_target(executable, pointer_table, index)
        if int(row["string_offset"], 0) != target:
            raise SystemExit(f"manifest string offset differs: {key}[{index}]")
        if not any(start <= target < end for start, end in v42.pool_segments()):
            raise SystemExit(f"pointer outside declared pool: {key}[{index}]")
        if target >= v42.RESERVE_START:
            raise SystemExit(f"pointer entered code/HUD reserve: {key}[{index}]")
        payload = bytes.fromhex(row["encoded_hex"])
        unique_payloads.add(payload)
        if len(payload) != int(row["encoded_bytes"]):
            raise SystemExit(f"manifest byte count differs: {key}[{index}]")
        if raw_string(executable, target) != payload:
            raise SystemExit(f"string readback differs: {key}[{index}]")
    if len(seen_records) != sum(count for count, _, _ in TABLES.values()):
        raise SystemExit("manifest does not cover every UI table record")
    if len(unique_payloads) != 429:
        raise SystemExit(f"unique payload count differs: {len(unique_payloads)}")

    exact_level_terms = {
        ("equipment_description", 8): "던지기 레벨 +1",
        ("equipment_description", 20): "점프 레벨 +1",
        ("equipment_description", 22): "받기 레벨 +1",
    }
    manifest_by_key = {
        (row["table_key"], int(row["index"])): row for row in manifest
    }
    for key, text in exact_level_terms.items():
        if manifest_by_key[key]["korean"] != text:
            raise SystemExit(f"accepted level wording regressed: {key}")

    glyph_rows = v42.csv_rows(v42.GLYPH_MAP)
    old_rows = v42.csv_rows(v42.V41_MAP)
    if len(glyph_rows) != 409 or len(old_rows) != 278:
        raise SystemExit("glyph-map record count differs")
    for old, new in zip(old_rows, glyph_rows):
        for field in ("char", "virtual_code_hex", "physical_index", "row", "column", "plane"):
            if old[field] != new[field]:
                raise SystemExit(f"accepted v0.41 map regressed for {old['char']!r}: {field}")

    chars = [row["char"] for row in glyph_rows]
    virtual_codes = [bytes.fromhex(row["virtual_code_hex"]) for row in glyph_rows]
    physical_indices = [int(row["physical_index"]) for row in glyph_rows]
    if len(set(chars)) != len(chars):
        raise SystemExit("v0.42 glyph map contains duplicate characters")
    if virtual_codes != v41.virtual_codes(len(glyph_rows)):
        raise SystemExit("v0.42 virtual code sequence differs")
    if len(set(physical_indices)) != len(physical_indices):
        raise SystemExit("v0.42 physical map contains duplicates")
    if any(index not in v40.safe_physical_indices() for index in physical_indices):
        raise SystemExit("v0.42 physical map left verified sparse planes")
    if set(physical_indices).intersection(v42.ICON_PHYSICAL_INDICES):
        raise SystemExit("v0.42 glyph planes overlap relocated icons")

    physical_codes = {
        row["char"]: v42.code_for_physical_index(int(row["physical_index"]))
        for row in glyph_rows
    }
    for char in chars:
        expected = tuple(
            1 if render_glyph(char).getpixel((x, y)) else 0
            for y in range(12) for x in range(12)
        )
        if v40.plane_bitmap(font, physical_codes[char]) != expected:
            raise SystemExit(f"glyph pixel readback differs for {char!r}")

    cave, layout = v41.assemble_cave(physical_indices)
    cave_offset = v41.file_offset(v41.CAVE_START)
    if executable[cave_offset : cave_offset + v41.CAVE_SIZE] != cave:
        raise SystemExit("expanded E9/EA cave readback differs")
    if layout["used_end"] != 0x801A7852 or v41.CAVE_LIMIT - layout["used_end"] != 14:
        raise SystemExit("expanded lookup-table boundary differs")
    for hook, target in (
        (v41.PRECLASS_HOOK, layout["pre_stub"]),
        (v41.MAINCLASS_HOOK, layout["main_stub"]),
        (v41.DECODER_HOOK, layout["decoder_stub"]),
    ):
        offset = v41.file_offset(hook)
        if executable[offset : offset + 8] != struct.pack("<II", v41.j(target), 0):
            raise SystemExit(f"E9/EA hook readback differs at 0x{hook:08X}")

    icon_stub = v42.build_icon_v_stub()
    if executable[v42.ICON_STUB_OFFSET : v42.ICON_STUB_OFFSET + len(icon_stub)] != icon_stub:
        raise SystemExit("E7 V-coordinate stub readback differs")
    e7_hook_offset = v41.file_offset(v42.E7_V_HOOK)
    if executable[e7_hook_offset : e7_hook_offset + 8] != struct.pack(
        "<II", v41.j(v42.ICON_STUB_ADDRESS), 0
    ):
        raise SystemExit("E7 V-coordinate hook readback differs")

    if v42.rectangle(
        font, v42.CURSOR_X, v42.CURSOR_Y, v42.CURSOR_WIDTH, v42.CURSOR_HEIGHT
    ) != v42.rectangle(
        v37_font, v42.CURSOR_X, v42.CURSOR_Y, v42.CURSOR_WIDTH, v42.CURSOR_HEIGHT
    ):
        raise SystemExit("battle cursor is not byte/pixel-equivalent to v0.37")
    for icon_id in (2, 3):
        if executable[v42.ICON_U_OFFSETS[icon_id]] != v42.ICON_DESTINATIONS[icon_id][0]:
            raise SystemExit(f"E7_{icon_id:02d} U-coordinate differs")
        if executable[v42.ICON_U_OFFSETS[icon_id] + 1] != v42.ICON_WIDTH:
            raise SystemExit(f"E7_{icon_id:02d} width differs")
        if v42.rectangle(
            font, *v42.ICON_DESTINATIONS[icon_id], v42.ICON_WIDTH, v42.ICON_HEIGHT
        ) != v42.rectangle(
            font, *v42.ICON_SOURCES[icon_id], v42.ICON_WIDTH, v42.ICON_HEIGHT
        ):
            raise SystemExit(f"E7_{icon_id:02d} relocated pixels differ")

    legacy = load_mapping()
    _, virtual, _, _ = v42.virtual_and_physical_maps(translations, legacy)
    hud_payloads = (
        virtual["L"] + b"\x00\x00",
        virtual["V"] + b"\x00\x00",
        bytes.fromhex("DD B2 00 00"),
        bytes.fromhex("01 DE 4F 00"),
        bytes.fromhex("DD 90 00 00"),
    )
    for pointer, source, payload in zip(v42.HUD_POINTERS, v42.HUD_SOURCES, hud_payloads):
        if struct.unpack_from("<I", executable, pointer)[0] != PSX_LOAD_BASE + source:
            raise SystemExit(f"HUD pointer readback differs at 0x{pointer:X}")
        if executable[source : source + len(payload)] != payload:
            raise SystemExit(f"HUD payload readback differs at 0x{source:X}")

    changed_psx = v42.allowed_psx_changes(base_executable, executable)
    changed_font, changed_nibbles = v42.verify_font_changes(
        base_font, font, v37_font, chars, physical_codes, 278
    )

    review = v42.csv_rows(v42.REVIEW)
    if len(review) != 310:
        raise SystemExit(f"equipment/item/skill review count differs: {len(review)}")
    if any(row["application_status"] != "guide_term_restored_v42" for row in review):
        raise SystemExit("review CSV contains a non-v0.42 status")
    skill_guide = v42.csv_rows(v42.SKILL_GUIDE)
    if not skill_guide:
        raise SystemExit("v0.42 skill guide reference is empty")

    lines = [
        "UI guide terms v0.42 independent audit: PASS",
        f"output_zip_sha256={digest(v42.OUTPUT.read_bytes())}",
        f"output_psx_sha256={digest(executable)}",
        f"output_comm_sha256={digest(font)}",
        f"changed_members={','.join(changed_members)}",
        "unrelated_members_byte_identical=true",
        "story_e2_members_byte_identical=true",
        "ui_pointer_readbacks=503/503",
        "ui_string_readbacks=503/503",
        f"unique_ui_payloads={len(unique_payloads)}",
        "glyph_readbacks=409/409",
        "v41_glyph_assignments_preserved=278/278",
        "new_sparse_glyphs=131",
        "battle_cursor_v37_exact=true",
        "confirm_cancel_icons_exact=true",
        "battle_hud_separate_lv_exact=true",
        "accepted_level_wording_exact=true",
        f"changed_psx_bytes={changed_psx}",
        f"changed_comm_bytes={changed_font}",
        f"changed_comm_nibbles={changed_nibbles}",
    ]
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
