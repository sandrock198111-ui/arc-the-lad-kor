#!/usr/bin/env python3
"""Repack all consumable item names and descriptions inside PSX.EXE."""

from __future__ import annotations

import csv
import hashlib
import struct
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile


ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "03_output" / "ui_item_herb_probe_v24_cumulative_patch_only.zip"
BASE_HASH = "E5755DB4B0C911D406F1D03F752C5241A4681176D7C8FBBC759AA9CE08E0B3E8"
CHARMAP = ROOT / "05_docs" / "korean_charmap_extended.csv"
MANIFEST = ROOT / "05_docs" / "ui_consumables_v25.csv"
OUTPUT = ROOT / "03_output" / "ui_consumables_v25_cumulative_patch_only.zip"
REPORT = ROOT / "01_work" / "analysis" / "ui_tables_v25" / "build_report.txt"
AUDIT = ROOT / "01_work" / "analysis" / "ui_tables_v25" / "readback.csv"

PSX_LOAD_BASE = 0x8011A800
FILLER = 0x9C
COUNT = 32

NAME_BLOCK = (0x80B94, 0x80C9C)
NAME_POINTERS = 0x80C9C
DESCRIPTION_BLOCK = (0x80D1C, 0x80F14)
DESCRIPTION_POINTERS = 0x80F14


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def align4(value: int) -> int:
    return (value + 3) & ~3


def rows(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def load_mapping() -> dict[str, bytes]:
    return {
        row["char"]: bytes.fromhex(row["code_hex"])
        for row in rows(CHARMAP)
        if row["char"]
    }


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
                raise SystemExit(f"missing glyph mapping for {char!r} in {text!r}") from exc
    return bytes(output)


def pointer_target(data: bytes | bytearray, table: int, index: int) -> int:
    return struct.unpack_from("<I", data, table + index * 4)[0] - PSX_LOAD_BASE


def raw_string(data: bytes | bytearray, offset: int) -> bytes:
    end = data.find(0, offset)
    if end < 0:
        raise SystemExit(f"unterminated string at 0x{offset:X}")
    return bytes(data[offset:end])


def repack(
    executable: bytearray,
    block: tuple[int, int],
    pointer_table: int,
    payloads: list[bytes],
) -> tuple[list[int], int]:
    start, end = block
    executable[start:end] = bytes(end - start)
    offsets: list[int] = []
    cursor = start
    for index, payload in enumerate(payloads):
        cursor = align4(cursor)
        required = len(payload) + 1
        if cursor + required > end:
            raise SystemExit(
                f"block overflow at index {index}: 0x{cursor:X}+{required} > 0x{end:X}"
            )
        executable[cursor : cursor + len(payload)] = payload
        executable[cursor + len(payload)] = 0
        offsets.append(cursor)
        struct.pack_into("<I", executable, pointer_table + index * 4, PSX_LOAD_BASE + cursor)
        cursor += required
    return offsets, end - align4(cursor)


def verify_table(
    executable: bytes,
    block: tuple[int, int],
    pointer_table: int,
    payloads: list[bytes],
) -> None:
    start, end = block
    targets = [pointer_target(executable, pointer_table, index) for index in range(COUNT)]
    if targets != sorted(targets) or len(set(targets)) != COUNT:
        raise SystemExit(f"pointer order or uniqueness failure at 0x{pointer_table:X}")
    for index, (target, expected) in enumerate(zip(targets, payloads)):
        if not start <= target < end:
            raise SystemExit(f"pointer {index} outside block: 0x{target:X}")
        if raw_string(executable, target) != expected:
            raise SystemExit(f"string readback differs at index {index}")
        if executable[target + len(expected)] != 0:
            raise SystemExit(f"missing terminator at index {index}")


def main() -> None:
    if digest(BASE.read_bytes()) != BASE_HASH:
        raise SystemExit("accepted item v0.24 base ZIP hash differs")

    manifest = rows(MANIFEST)
    indices = [int(row["index"]) for row in manifest]
    if indices != list(range(29)):
        raise SystemExit(f"manifest must contain exact indices 0-28, got {indices}")
    mapping = load_mapping()

    with ZipFile(BASE) as archive:
        infos = {info.filename: info for info in archive.infolist()}
        files = {name: archive.read(name) for name in infos}
    before_files = dict(files)
    executable = bytearray(files["PSX.EXE"])

    original_name_payloads = [
        raw_string(executable, pointer_target(executable, NAME_POINTERS, index))
        for index in range(COUNT)
    ]
    original_description_payloads = [
        raw_string(executable, pointer_target(executable, DESCRIPTION_POINTERS, index))
        for index in range(COUNT)
    ]
    name_payloads = [encode(row["korean_name"], mapping) for row in manifest]
    description_payloads = [encode(row["korean_description"], mapping) for row in manifest]
    name_payloads.extend(original_name_payloads[29:])
    description_payloads.extend(original_description_payloads[29:])

    name_offsets, name_free = repack(executable, NAME_BLOCK, NAME_POINTERS, name_payloads)
    description_offsets, description_free = repack(
        executable,
        DESCRIPTION_BLOCK,
        DESCRIPTION_POINTERS,
        description_payloads,
    )
    verify_table(bytes(executable), NAME_BLOCK, NAME_POINTERS, name_payloads)
    verify_table(
        bytes(executable),
        DESCRIPTION_BLOCK,
        DESCRIPTION_POINTERS,
        description_payloads,
    )

    audit_rows = []
    for index in range(COUNT):
        translated = index < len(manifest)
        audit_rows.append(
            {
                "index": index,
                "status": "translated" if translated else "reserved_original",
                "korean_name": manifest[index]["korean_name"] if translated else "",
                "name_offset": f"0x{name_offsets[index]:X}",
                "name_bytes": len(name_payloads[index]),
                "name_hex": name_payloads[index].hex(" ").upper(),
                "korean_description": (
                    manifest[index]["korean_description"] if translated else ""
                ),
                "description_offset": f"0x{description_offsets[index]:X}",
                "description_bytes": len(description_payloads[index]),
                "description_hex": description_payloads[index].hex(" ").upper(),
            }
        )

    allowed = bytearray(len(executable))
    for start, end in (
        NAME_BLOCK,
        (NAME_POINTERS, NAME_POINTERS + COUNT * 4),
        DESCRIPTION_BLOCK,
        (DESCRIPTION_POINTERS, DESCRIPTION_POINTERS + COUNT * 4),
    ):
        allowed[start:end] = b"\x01" * (end - start)
    outside = [
        index
        for index, (old, new) in enumerate(zip(before_files["PSX.EXE"], executable))
        if old != new and not allowed[index]
    ]
    if outside:
        raise SystemExit(f"PSX.EXE changed outside declared ranges at 0x{outside[0]:X}")

    files["PSX.EXE"] = bytes(executable)
    changed_members = [name for name in files if files[name] != before_files[name]]
    if changed_members != ["PSX.EXE"]:
        raise SystemExit(f"unexpected changed ZIP members: {changed_members}")
    for name in files:
        if name != "PSX.EXE" and files[name] != before_files[name]:
            raise SystemExit(f"non-executable member changed: {name}")

    with ZipFile(OUTPUT, "w", ZIP_DEFLATED, compresslevel=9) as archive:
        for name in sorted(files):
            archive.writestr(infos[name], files[name])

    report = [
        "UI consumables v0.25",
        f"Base ZIP SHA256: {BASE_HASH}",
        "Translated records: 29/29 active consumables",
        "Reserved records preserved: 3/3",
        f"Name block: 0x{NAME_BLOCK[0]:X}-0x{NAME_BLOCK[1] - 1:X}, free aligned bytes: {name_free}",
        f"Description block: 0x{DESCRIPTION_BLOCK[0]:X}-0x{DESCRIPTION_BLOCK[1] - 1:X}, free aligned bytes: {description_free}",
        f"Name targets: 0x{name_offsets[0]:X}-0x{name_offsets[-1]:X}",
        f"Description targets: 0x{description_offsets[0]:X}-0x{description_offsets[-1]:X}",
        f"Changed members: {', '.join(changed_members)}",
        f"Changed PSX.EXE bytes: {sum(a != b for a, b in zip(before_files['PSX.EXE'], files['PSX.EXE']))}",
        f"Output ZIP SHA256: {digest(OUTPUT.read_bytes())}",
    ]
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text("\n".join(report) + "\n", encoding="utf-8")
    with AUDIT.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(audit_rows[0]))
        writer.writeheader()
        writer.writerows(audit_rows)
    print("\n".join(report))


if __name__ == "__main__":
    main()
