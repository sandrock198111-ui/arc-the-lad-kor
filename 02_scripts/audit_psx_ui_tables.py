#!/usr/bin/env python3
"""Extract the confirmed PSX.EXE UI pointer tables for review.

This tool is read-only with respect to game files. It accepts either a PSX.EXE
or a cumulative patch ZIP containing PSX.EXE and writes a UTF-8 CSV plus a
short Markdown summary.
"""

from __future__ import annotations

import argparse
import csv
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[1]
VENDORED_PACKAGES = ROOT / "06_tools" / "python_packages"
if str(VENDORED_PACKAGES) not in sys.path:
    sys.path.insert(0, str(VENDORED_PACKAGES))
if str(ROOT / "02_scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "02_scripts"))

from extract_story_corpus import build_glyph_map  # noqa: E402


PSX_LOAD_BASE = 0x8011A800


@dataclass(frozen=True)
class TableSpec:
    key: str
    label: str
    pointer_offset: int
    count: int


TABLES = (
    TableSpec("equipment_name", "장비 이름", 0x804A4, 64),
    TableSpec("equipment_description", "장비 설명", 0x80A94, 64),
    TableSpec("consumable_name", "소비 아이템 이름", 0x80C9C, 32),
    TableSpec("consumable_description", "소비 아이템 설명", 0x80F14, 32),
    TableSpec("skill_name", "기술 이름", 0x811C0, 59),
    TableSpec("skill_description", "기술 설명", 0x81708, 59),
    TableSpec("character_name", "인물·몬스터 이름", 0x81B4C, 108),
    TableSpec("region_name", "지역 이름", 0x81E38, 30),
    TableSpec("location_name", "장소 이름", 0x82170, 55),
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path, help="PSX.EXE or patch-only ZIP")
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=ROOT / "01_work" / "analysis" / "ui_tables_v24",
    )
    return parser.parse_args()


def read_executable(source: Path) -> bytes:
    if source.suffix.lower() != ".zip":
        return source.read_bytes()
    with ZipFile(source) as archive:
        names = [name for name in archive.namelist() if Path(name).name.upper() == "PSX.EXE"]
        if len(names) != 1:
            raise ValueError(f"expected one PSX.EXE in {source}, found {len(names)}")
        return archive.read(names[0])


def decode_string(
    data: bytes,
    offset: int,
    glyph_map: dict[int, str],
    nearest: dict[int, tuple[str, int]],
) -> tuple[str, int]:
    output: list[str] = []
    cursor = offset
    while cursor < len(data):
        first = data[cursor]
        if first == 0:
            return "".join(output), cursor - offset
        if 0x01 <= first < 0xDD:
            index = first - 1
            cursor += 1
        elif 0xDD <= first <= 0xE0 and cursor + 1 < len(data):
            index = (first - 0xDD) * 255 + data[cursor + 1] + 0xDB
            cursor += 2
        else:
            output.append(f"<CTRL:{first:02X}>")
            cursor += 1
            continue
        if index in glyph_map:
            output.append(glyph_map[index])
        else:
            near_char, distance = nearest[index]
            output.append(f"<N:{near_char}:{distance}>")
    raise ValueError(f"unterminated string at 0x{offset:X}")


def extract_rows(data: bytes) -> list[dict[str, str | int]]:
    glyph_map, _ambiguity, nearest, _glyph_rows = build_glyph_map()
    rows: list[dict[str, str | int]] = []
    for spec in TABLES:
        targets = [
            struct.unpack_from("<I", data, spec.pointer_offset + index * 4)[0]
            - PSX_LOAD_BASE
            for index in range(spec.count)
        ]
        unique_targets = sorted(set(targets))
        next_target = {
            target: unique_targets[position + 1]
            if position + 1 < len(unique_targets)
            else spec.pointer_offset
            for position, target in enumerate(unique_targets)
        }
        for index, string_offset in enumerate(targets):
            if not 0 <= string_offset < len(data):
                raise ValueError(
                    f"{spec.key}[{index}] target 0x{string_offset:X} is outside PSX.EXE"
                )
            text, encoded_length = decode_string(data, string_offset, glyph_map, nearest)
            slot_size = next_target[string_offset] - string_offset
            rows.append(
                {
                    "table_key": spec.key,
                    "table_label": spec.label,
                    "index": index,
                    "pointer_offset": f"0x{spec.pointer_offset + index * 4:X}",
                    "string_offset": f"0x{string_offset:X}",
                    "encoded_length": encoded_length,
                    "slot_size": slot_size,
                    "free_bytes_in_slot": slot_size - encoded_length - 1,
                    "japanese": text,
                }
            )
    return rows


def write_outputs(rows: list[dict[str, str | int]], out_dir: Path, source: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    csv_path = out_dir / "psx_ui_tables.csv"
    with csv_path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)

    lines = [
        "# PSX.EXE UI Table Audit",
        "",
        f"- Source: `{source}`",
        f"- Extracted rows: {len(rows)}",
        "- Operation: read-only extraction",
        "",
        "| Table | Rows | First string offset | Last string offset |",
        "|---|---:|---:|---:|",
    ]
    for spec in TABLES:
        selected = [row for row in rows if row["table_key"] == spec.key]
        lines.append(
            f"| {spec.label} | {len(selected)} | {selected[0]['string_offset']} | "
            f"{selected[-1]['string_offset']} |"
        )
    lines.extend(
        [
            "",
            "## Notes",
            "",
            "- Offsets are PSX.EXE file offsets, not runtime RAM addresses.",
            "- `slot_size` includes the terminating zero and any existing padding.",
            "- Ambiguous font matches are preserved as `<N:...>` markers for manual review.",
            "- No game binary is modified by this audit.",
        ]
    )
    (out_dir / "README.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    args = parse_args()
    data = read_executable(args.source)
    rows = extract_rows(data)
    write_outputs(rows, args.out_dir, args.source)
    print(f"extracted {len(rows)} rows to {args.out_dir}")


if __name__ == "__main__":
    main()
