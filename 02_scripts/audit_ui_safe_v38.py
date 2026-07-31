#!/usr/bin/env python3
"""Independent static audit for ui_safe_v38_cumulative_patch_only.zip."""

from __future__ import annotations

import csv
import hashlib
import re
import struct
from pathlib import Path
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "03_output" / "ui_safe_v37_cumulative_patch_only.zip"
OUTPUT = ROOT / "03_output" / "ui_safe_v38_cumulative_patch_only.zip"
EXPECTED_HASH = "D66E6F4F780E3096B604C7699E3E7EB00392EE7C0C4FA457AEDE3F61EEFD45D9"
ROW_BYTES = 0x380
PSX_LOAD_BASE = 0x8011A800

ICON_SOURCES = {2: (114, 354), 3: (162, 354)}
ICON_DESTINATIONS = {2: (0, 130), 3: (12, 130)}
LV_BITMAP = (
    "............",
    "............",
    ".#....#...#.",
    ".#....#...#.",
    ".#....#...#.",
    ".#....#...#.",
    ".#.....#.#..",
    ".#.....#.#..",
    ".####...#...",
    "............",
    "............",
    "............",
)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def pixel(data: bytes, x: int, y: int) -> int:
    value = data[y * ROW_BYTES + x // 2]
    return value & 0x0F if x % 2 == 0 else value >> 4


def rectangle(data: bytes, x: int, y: int) -> tuple[int, ...]:
    return tuple(pixel(data, x + dx, y + dy) for dy in range(12) for dx in range(12))


def code_for(row: int, column: int, plane: int) -> bytes:
    number = row * 84 + column * 4 + plane - 0xDB
    return bytes((0xDD + number // 255, number % 255))


def active_sequences(files: dict[str, bytes]) -> list[bytes]:
    normalized = {name.replace("\\", "/"): data for name, data in files.items()}
    sequences: list[bytes] = []
    corpus = ROOT / "01_work" / "analysis" / "story_corpus" / "story_corpus.csv"
    with corpus.open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            data = normalized.get(row["file"])
            if data is None:
                continue
            start = int(row["payload_start"], 0)
            capacity = int(row["capacity"])
            body = data[start:start + capacity]
            sequences.append(body)
            for index in range(len(body) - 1):
                if body[index] != 0xE2:
                    continue
                slot_id = body[index + 1]
                if 0x81 <= slot_id <= 0xA8:
                    slot = slot_id - 0x81
                elif 0xAA <= slot_id <= 0xD0:
                    slot = slot_id - 0x82
                else:
                    continue
                start = 0x45000 + slot * 0x80
                sequences.append(data[start:start + 0x80])

    for path in sorted((ROOT / "05_docs").glob("*v38*.csv")):
        with path.open(encoding="utf-8-sig", newline="") as handle:
            for row in csv.DictReader(handle):
                encoded = row.get("encoded_hex") or row.get("encoded_bytes_hex") or ""
                compact = "".join(encoded.split())
                if compact and len(compact) % 2 == 0 and re.fullmatch(r"[0-9A-Fa-f]+", compact):
                    sequences.append(bytes.fromhex(compact))
    return sequences


def main() -> None:
    if digest(OUTPUT.read_bytes()) != EXPECTED_HASH:
        raise SystemExit("v0.38 ZIP hash differs")
    with ZipFile(BASE) as archive:
        before = {name: archive.read(name) for name in archive.namelist()}
    with ZipFile(OUTPUT) as archive:
        after = {name: archive.read(name) for name in archive.namelist()}
    if set(before) != set(after):
        raise SystemExit("member list differs")
    changed = [name for name in sorted(before) if before[name] != after[name]]
    if changed != ["COMM.IMG", "PSX.EXE"]:
        raise SystemExit(f"changed member set differs: {changed}")

    exe = after["PSX.EXE"]
    font = after["COMM.IMG"]
    if exe[0x80214] != 0 or exe[0x80215] != 12:
        raise SystemExit("E7 02 table differs")
    if exe[0x80216] != 12 or exe[0x80217] != 12:
        raise SystemExit("E7 03 table differs")
    target = struct.unpack_from("<I", exe, 0x8235C)[0] - PSX_LOAD_BASE
    expected_help = bytes.fromhex(
        "E7 02 DF 86 E0 EB 9C E7 03 E0 D5 E0 9C E0 C0 E0 AC"
    )
    if target != 0x82094 or exe[target:target + len(expected_help) + 1] != expected_help + b"\0":
        raise SystemExit("button-help readback differs")

    for icon_id in (2, 3):
        if rectangle(font, *ICON_DESTINATIONS[icon_id]) != rectangle(font, *ICON_SOURCES[icon_id]):
            raise SystemExit(f"icon {icon_id} destination differs from verified duplicate")

    assigned: set[bytes] = set()
    for name in ("korean_charmap.csv", "korean_charmap_extended.csv"):
        with (ROOT / "05_docs" / name).open(encoding="utf-8-sig", newline="") as handle:
            assigned.update(
                bytes.fromhex(row["code_hex"])
                for row in csv.DictReader(handle)
                if row["code_hex"]
            )
    destination_codes = [
        code_for(row, column, plane)
        for column in (0, 1)
        for row in (10, 11)
        for plane in range(4)
    ]
    if assigned.intersection(destination_codes):
        raise SystemExit("icon destination is assigned in Korean charmap")
    sequences = active_sequences(after)
    uses = sum(sequence.count(code) for sequence in sequences for code in destination_codes)
    if uses:
        raise SystemExit(f"icon destination codes occur in active payloads: {uses}")

    index = 0x6C - 1
    row, remainder = divmod(index, 84)
    column, plane = divmod(remainder, 4)
    bit = 1 << plane
    for y, line in enumerate(LV_BITMAP):
        for x, value in enumerate(line):
            px = column * 12 + x
            py = row * 12 + y
            expected = value == "#"
            if bool(pixel(font, px, py) & bit) != expected:
                raise SystemExit(f"LV bitmap differs at ({x},{y})")
            if (pixel(font, px, py) & ~bit) != (pixel(before["COMM.IMG"], px, py) & ~bit):
                raise SystemExit(f"LV neighboring plane differs at ({x},{y})")

    if struct.unpack_from("<I", exe, 0x463D8)[0] != 0x24750028:
        raise SystemExit("v37 confirmation-box width regressed")
    if struct.unpack_from("<I", exe, 0x46428)[0] != 0x26440014:
        raise SystemExit("v37 confirmation prompt position regressed")

    print("v0.38 independent audit: PASS")
    print(f"zip_sha256={EXPECTED_HASH}")
    print(f"active_payloads_scanned={len(sequences)}")
    print("destination_glyph_code_uses=0")
    print("changed_members=COMM.IMG,PSX.EXE")
    print("button_controls=E7_02,E7_03")
    print("lv_bitmap=v35_thin_pointed_23px")
    print("v37_confirmation_geometry=preserved")


if __name__ == "__main__":
    main()
