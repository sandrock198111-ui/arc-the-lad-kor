#!/usr/bin/env python3
"""Build v0.29 with reviewed help text and an isolated LV label repair."""

from __future__ import annotations

import csv
import sys
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))

import build_ui_safe_v28 as base  # noqa: E402
from build_story_sf0b1_return_full import (  # noqa: E402
    ROW_BYTES,
    get_pixel,
    glyph_index,
    set_pixel,
)
from ui_safe_v29_overrides import OVERRIDES  # noqa: E402


OUTPUT = ROOT / "03_output" / "ui_safe_v29_cumulative_patch_only.zip"
MANIFEST = ROOT / "05_docs" / "ui_safe_v29.csv"
SKILL_REFERENCE = ROOT / "05_docs" / "ui_skill_guide_reference_v29.csv"
ANALYSIS = ROOT / "01_work" / "analysis" / "ui_safe_v29"
REPORT = ANALYSIS / "build_report.txt"
READBACK = ANALYSIS / "readback.csv"
LOW_CODE_AUDIT = ANALYSIS / "low_6c_story_audit.csv"
PREVIEW = ANALYSIS / "lv_label_before_after.pbm"
STORY_AUDIT = ROOT / "01_work" / "analysis" / "full_audit_v20" / "story_body_audit.csv"

SINGLE_BYTE = {"%": 0x07, "+": 0x0C}
LABEL_CODE = b"\x6C"
LABEL_BIT = 1 << 3


def missing_chars(text: str, mapping: dict[str, bytes]) -> str:
    return "".join(
        sorted(
            {
                char
                for char in text
                if char != " "
                and not (char.isascii() and char.isdigit())
                and char not in SINGLE_BYTE
                and (char not in mapping or 0x00 in mapping[char])
            }
        )
    )


def encode(text: str, mapping: dict[str, bytes]) -> bytes:
    output = bytearray()
    for char in text:
        if char == " ":
            output.append(0x9C)
        elif char.isascii() and char.isdigit():
            output.append(0x11 + int(char))
        elif char in SINGLE_BYTE:
            output.append(SINGLE_BYTE[char])
        else:
            output.extend(mapping[char])
    return bytes(output)


def label_bitmap() -> set[tuple[int, int]]:
    rows = (
        "............",
        ".##...##..##",
        ".##...##..##",
        ".##...##..##",
        ".##...##..##",
        ".##....####.",
        ".##....####.",
        ".##.....##..",
        ".#####..##..",
        ".#####......",
        "............",
        "............",
    )
    return {(x, y) for y, row in enumerate(rows) for x, value in enumerate(row) if value == "#"}


def plane_pixels(font: bytes | bytearray) -> set[tuple[int, int]]:
    index = glyph_index(LABEL_CODE)
    row, remainder = divmod(index, 84)
    column, plane = divmod(remainder, 4)
    bit = 1 << plane
    pixels: set[tuple[int, int]] = set()
    for y in range(12):
        for x in range(12):
            if get_pixel(font, column * 12 + x, row * 12 + y) & bit:
                pixels.add((x, y))
    return pixels


def patch_label(font: bytearray) -> tuple[int, int]:
    before = bytes(font)
    index = glyph_index(LABEL_CODE)
    row, remainder = divmod(index, 84)
    column, plane = divmod(remainder, 4)
    bit = 1 << plane
    glyph = label_bitmap()
    for y in range(12):
        for x in range(12):
            px = column * 12 + x
            py = row * 12 + y
            old = get_pixel(font, px, py)
            new = old | bit if (x, y) in glyph else old & ~bit
            if (new & ~bit) != (old & ~bit):
                raise SystemExit("LV writer changed a neighboring font plane")
            set_pixel(font, px, py, new)

    changed_bytes = 0
    changed_nibbles = 0
    for offset, (old_byte, new_byte) in enumerate(zip(before, font)):
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
            inside = column * 12 <= x < column * 12 + 12 and row * 12 <= y < row * 12 + 12
            if not inside or (old ^ new) & ~bit:
                raise SystemExit(f"COMM.IMG changed outside LV plane at ({x},{y})")
    if plane_pixels(font) != glyph:
        raise SystemExit("LV glyph plane readback failed")
    return changed_bytes, changed_nibbles


def write_preview(before: bytes, after: bytes) -> None:
    PREVIEW.parent.mkdir(parents=True, exist_ok=True)
    left = plane_pixels(before)
    right = plane_pixels(after)
    rows = ["P1", "25 12"]
    for y in range(12):
        values = ["1" if (x, y) in left else "0" for x in range(12)]
        values.append("0")
        values.extend("1" if (x, y) in right else "0" for x in range(12))
        rows.append(" ".join(values))
    PREVIEW.write_text("\n".join(rows) + "\n", encoding="ascii")


def audit_low_code(files: dict[str, bytes]) -> tuple[int, int]:
    rows: list[dict[str, str]] = []
    with STORY_AUDIT.open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            if row["in_patch_zip"] != "1" or row["file"] not in files:
                continue
            offset = int(row["offset"], 16)
            body = files[row["file"]][offset : offset + int(row["capacity"])]
            if LABEL_CODE[0] not in body:
                continue
            classification = (
                "e2_redirect_tail"
                if row["status"] == "e2_valid" and body.startswith(b"\xE2")
                else "original_or_binary_body"
            )
            rows.append(
                {
                    "file": row["file"],
                    "offset": row["offset"],
                    "status": row["status"],
                    "classification": classification,
                    "body_hex": body.hex(" ").upper(),
                }
            )
    with LOW_CODE_AUDIT.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    redirects = sum(row["classification"] == "e2_redirect_tail" for row in rows)
    originals = len(rows) - redirects
    return redirects, originals


def rewrite_report(comm_bytes: int, comm_nibbles: int, redirects: int, originals: int) -> None:
    lines = REPORT.read_text(encoding="utf-8").splitlines()
    replacements = {
        "UI safe v0.28 cumulative guide-reviewed batch": "UI safe v0.29 cumulative help-and-label repair",
        "comm_img_byte_identical_to_v25=true": "comm_img_byte_identical_to_v25=false",
        "changed_members=PSX.EXE": "changed_members=PSX.EXE,COMM.IMG",
    }
    lines = [replacements.get(line, line) for line in lines]
    lines = [
        f"output_zip_sha256={base.digest(OUTPUT.read_bytes())}" if line.startswith("output_zip_sha256=") else line
        for line in lines
    ]
    lines.extend(
        [
            f"comm_img_changed_bytes={comm_bytes}",
            f"comm_img_changed_nibbles={comm_nibbles}",
            "skill_level_label=LV",
            "skill_level_label_code=0x6C",
            "skill_level_label_scope=single_physical_bitplane",
            f"low_6c_e2_redirect_tail_hits={redirects}",
            f"low_6c_original_or_binary_hits={originals}",
        ]
    )
    REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    base.OUTPUT = OUTPUT
    base.MANIFEST = MANIFEST
    base.SKILL_REFERENCE = SKILL_REFERENCE
    base.ANALYSIS = ANALYSIS
    base.REPORT = REPORT
    base.READBACK = READBACK
    base.OVERRIDES = OVERRIDES
    base.missing_chars = missing_chars
    base.encode = encode
    base.main()

    with ZipFile(OUTPUT) as archive:
        infos = archive.infolist()
        files = {info.filename: archive.read(info.filename) for info in infos}
    font_before = files[base.FONT_TARGET]
    font = bytearray(font_before)
    comm_bytes, comm_nibbles = patch_label(font)
    files[base.FONT_TARGET] = bytes(font)
    write_preview(font_before, files[base.FONT_TARGET])
    redirects, originals = audit_low_code(files)

    temporary = OUTPUT.with_suffix(".tmp.zip")
    with ZipFile(temporary, "w", ZIP_DEFLATED, compresslevel=9) as archive:
        for info in infos:
            archive.writestr(info, files[info.filename])
    temporary.replace(OUTPUT)

    with ZipFile(OUTPUT) as archive:
        for name, expected in files.items():
            if archive.read(name) != expected:
                raise SystemExit(f"v0.29 output readback differs: {name}")
    rewrite_report(comm_bytes, comm_nibbles, redirects, originals)
    print(REPORT.read_text(encoding="utf-8"), end="")


if __name__ == "__main__":
    main()
