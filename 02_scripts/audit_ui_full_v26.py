#!/usr/bin/env python3
"""Independently audit the cumulative v0.26 UI patch."""

from __future__ import annotations

import csv
import hashlib
import sys
from pathlib import Path
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))
sys.path.insert(0, str(ROOT / "06_tools" / "python_packages"))

from build_story_sf0b1_return_full import get_pixel  # noqa: E402
from build_ui_full_v26 import (  # noqa: E402
    BASE,
    FONT_TARGET,
    GLYPHS_PER_ROW,
    MANIFEST,
    OUTPUT,
    PSX_TARGET,
    READBACK,
    TABLES,
    build_mapping,
    digest,
    encode,
    pointer_target,
    raw_string,
    ui_glyph_index,
    verify_executable_changes,
    verify_font_changes,
)
from ui_full_v26_data import TRANSLATIONS  # noqa: E402


REPORT = ROOT / "01_work" / "analysis" / "ui_full_v26" / "collision_audit.txt"


def rows(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def plane(font: bytes, index: int) -> tuple[int, ...]:
    row, remainder = divmod(index, GLYPHS_PER_ROW)
    column, bitplane = divmod(remainder, 4)
    bit = 1 << bitplane
    return tuple(
        1 if get_pixel(font, column * 12 + x, row * 12 + y) & bit else 0
        for y in range(12)
        for x in range(12)
    )


def main() -> None:
    mapping = build_mapping()
    codes = list(mapping.values())
    indices = [ui_glyph_index(code) for code in codes]
    if len(codes) != len(set(codes)) or len(indices) != len(set(indices)):
        raise SystemExit("UI character/code/physical-index mapping is not one-to-one")
    if any(0x00 in code or 0xFF in code for code in codes):
        raise SystemExit("UI mapping contains forbidden 00/FF second-byte codes")
    if min(indices) <= 1239:
        raise SystemExit("UI glyph bank overlaps the DD-E0 story glyph bank")

    manifest = rows(MANIFEST)
    readback = rows(READBACK)
    if len(manifest) != 503 or len(readback) != 503:
        raise SystemExit("manifest/readback row count differs from 503")

    with ZipFile(BASE) as archive:
        base_names = archive.namelist()
        base_files = {name: archive.read(name) for name in base_names}
    with ZipFile(OUTPUT) as archive:
        output_names = archive.namelist()
        output_files = {name: archive.read(name) for name in output_names}
    if base_names != output_names:
        raise SystemExit("ZIP member order or set differs from the cumulative base")
    for name in base_names:
        if name not in {PSX_TARGET, FONT_TARGET} and base_files[name] != output_files[name]:
            raise SystemExit(f"unrelated ZIP member differs: {name}")

    executable = output_files[PSX_TARGET]
    record = 0
    for key, (count, _, pointer_table) in TABLES.items():
        for index in range(count):
            text = TRANSLATIONS[key][index]
            expected = encode(text, mapping)
            target = pointer_target(executable, pointer_table, index)
            actual = raw_string(executable, target)
            if actual != expected:
                raise SystemExit(f"pointer readback mismatch: {key}[{index}]")
            row = readback[record]
            if row["table_key"] != key or int(row["index"]) != index:
                raise SystemExit(f"readback manifest order mismatch at row {record}")
            if row["encoded_hex"] != expected.hex(" ").upper():
                raise SystemExit(f"encoded audit mismatch: {key}[{index}]")
            record += 1

    exe_changed = verify_executable_changes(base_files[PSX_TARGET], executable)
    font_changed, font_nibbles = verify_font_changes(
        base_files[FONT_TARGET], output_files[FONT_TARGET], mapping
    )
    for index in range(1240):
        if plane(base_files[FONT_TARGET], index) != plane(output_files[FONT_TARGET], index):
            raise SystemExit(f"legacy/story glyph plane changed at physical index {index}")

    lines = [
        "UI full v0.26 independent collision audit",
        f"output_zip_sha256={digest(OUTPUT.read_bytes())}",
        f"zip_members={len(output_names)}",
        "pointer_readback=503/503",
        "manifest_readback=503/503",
        f"ui_code_count={len(codes)}",
        f"ui_physical_index_range={min(indices)}-{max(indices)}",
        "ui_code_00_ff_free=true",
        "ui_physical_indices_unique=true",
        "story_glyph_planes_0_1239_preserved=true",
        "battle_cursor_preserved=true",
        f"psx_exe_changed_bytes={exe_changed}",
        f"comm_img_changed_bytes={font_changed}",
        f"comm_img_changed_nibbles={font_nibbles}",
        "unrelated_zip_members_preserved=true",
    ]
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
