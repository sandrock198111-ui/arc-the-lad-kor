#!/usr/bin/env python3
"""Build the first PSX.EXE item-table probe on top of story v0.23."""

from __future__ import annotations

import csv
import hashlib
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile


ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "03_output" / "story_choice_row_alignment_v23_cumulative_patch_only.zip"
BASE_HASH = "E0A6C6EF167CFDDDA375FCE2B336A2CEAE478499DDDEB371668E2B99672C3C89"
CHARMAP = ROOT / "05_docs" / "korean_charmap_extended.csv"
MANIFEST = ROOT / "05_docs" / "ui_item_probe_v24.csv"
OUTPUT = ROOT / "03_output" / "ui_item_herb_probe_v24_cumulative_patch_only.zip"
REPORT = ROOT / "01_work" / "analysis" / "ui_tables_v24" / "item_probe_build_report.txt"

FILLER = 0x9C

TARGETS = {
    ("consumable_name", 7): {
        "offset": 0x80BCC,
        "size": 8,
        "expected": bytes.fromhex("DD 58 DD 65 00 00 00 00"),
    },
    ("consumable_description", 7): {
        "offset": 0x80D88,
        "size": 20,
        "expected": bytes.fromhex(
            "DD FA DD 90 2A 13 11 D7 65 34 5C 9E DD 2C 1E 27 2B 00 00 00"
        ),
    },
}


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def load_mapping() -> dict[str, bytes]:
    with CHARMAP.open(encoding="utf-8-sig", newline="") as handle:
        return {
            row["char"]: bytes.fromhex(row["code_hex"])
            for row in csv.DictReader(handle)
            if row["char"]
        }


def load_manifest() -> list[dict[str, str]]:
    with MANIFEST.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


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
                raise SystemExit(f"missing glyph mapping for {char!r}") from exc
    return bytes(output)


def main() -> None:
    if digest(BASE.read_bytes()) != BASE_HASH:
        raise SystemExit("story v0.23 base ZIP hash differs")

    mapping = load_mapping()
    manifest = load_manifest()
    if {(row["table"], int(row["index"])) for row in manifest} != set(TARGETS):
        raise SystemExit("unexpected v0.24 manifest scope")

    with ZipFile(BASE) as archive:
        infos = {info.filename: info for info in archive.infolist()}
        files = {name: archive.read(name) for name in infos}
    before_files = dict(files)
    executable = bytearray(files["PSX.EXE"])
    allowed = bytearray(len(executable))
    report = [
        "UI item probe v0.24",
        f"Base ZIP SHA256: {BASE_HASH}",
        "Scope: PSX.EXE consumable item index 7 only",
    ]

    for row in manifest:
        key = (row["table"], int(row["index"]))
        target = TARGETS[key]
        offset = target["offset"]
        size = target["size"]
        current = bytes(executable[offset : offset + size])
        if current != target["expected"]:
            raise SystemExit(f"source mismatch at PSX.EXE 0x{offset:X}")
        encoded = encode(row["korean"], mapping)
        if len(encoded) + 1 > size:
            raise SystemExit(
                f"text does not fit at 0x{offset:X}: {len(encoded) + 1}/{size} bytes"
            )
        replacement = encoded + bytes(size - len(encoded))
        executable[offset : offset + size] = replacement
        allowed[offset : offset + size] = b"\x01" * size
        report.append(
            f"{key[0]}[{key[1]}] 0x{offset:X} {row['japanese']} -> {row['korean']} "
            f"({len(encoded) + 1}/{size} bytes including terminator)"
        )

    files["PSX.EXE"] = bytes(executable)
    outside = [
        index
        for index, (old, new) in enumerate(zip(before_files["PSX.EXE"], files["PSX.EXE"]))
        if old != new and not allowed[index]
    ]
    if outside:
        raise SystemExit(f"PSX.EXE changed outside declared ranges at 0x{outside[0]:X}")
    changed_members = [name for name in files if files[name] != before_files[name]]
    if changed_members != ["PSX.EXE"]:
        raise SystemExit(f"unexpected changed ZIP members: {changed_members}")

    with ZipFile(OUTPUT, "w", ZIP_DEFLATED, compresslevel=9) as archive:
        for name in sorted(files):
            archive.writestr(infos[name], files[name])

    report.extend(
        [
            f"Changed members: {', '.join(changed_members)}",
            f"Changed PSX.EXE bytes: {sum(a != b for a, b in zip(before_files['PSX.EXE'], files['PSX.EXE']))}",
            f"Output ZIP SHA256: {digest(OUTPUT.read_bytes())}",
        ]
    )
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text("\n".join(report) + "\n", encoding="utf-8")
    print("\n".join(report))


if __name__ == "__main__":
    main()
