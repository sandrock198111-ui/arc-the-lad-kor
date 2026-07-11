from __future__ import annotations

import argparse
import csv
import hashlib
import shutil
import zipfile
from dataclasses import dataclass
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BASE_ZIP = ROOT / "99_backup" / "story_test_18_s1011_nine_blocks_fix_block8_success.zip"
DEFAULT_MANIFEST = ROOT / "05_docs" / "story_patch_manifest.csv"
DEFAULT_CHARMAP = ROOT / "05_docs" / "korean_charmap.csv"
DEFAULT_ANALYSIS = ROOT / "01_work" / "analysis" / "dialog_block_candidates.csv"
DEFAULT_OUTPUT = ROOT / "03_output" / "story_manifest_build_patch_only.zip"
DEFAULT_WORK = ROOT / "01_work" / "story_manifest_build"
FILLER = 0x9C
LINEBREAK = bytes((0xE6, 0x01))
FONT_PATH = Path(r"C:\Windows\Fonts\gulim.ttc")
FONT_SIZE = 12
THRESHOLD = 192
ROW_BYTES = 0x380


@dataclass(frozen=True)
class BlockInfo:
    file: str
    payload_start: int
    double_zero: int
    payload_capacity: int
    control_after: bytes
    confidence: str


@dataclass(frozen=True)
class PatchRow:
    file: str
    payload_start: int
    text: str
    notes: str


def parse_int(value: str) -> int:
    return int(value.strip(), 0)


def digest_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def load_charmap(path: Path) -> tuple[dict[str, int], dict[str, str]]:
    table: dict[str, int] = {}
    notes: dict[str, str] = {}
    with path.open(newline="", encoding="utf-8-sig") as f:
        for row in csv.DictReader(f):
            char = row["char"]
            if not char:
                continue
            table[char] = parse_int("0x" + row["code_hex"].strip())
            notes[char] = row.get("slot_note", "")
    return table, notes


def load_analysis(path: Path) -> dict[tuple[str, int], BlockInfo]:
    blocks: dict[tuple[str, int], BlockInfo] = {}
    with path.open(newline="", encoding="utf-8-sig") as f:
        for row in csv.DictReader(f):
            file = row["file"].strip()
            payload_start = parse_int(row["payload_start"])
            double_zero = parse_int(row["double_zero"])
            control_after = bytes.fromhex(row["control_after_hex"])
            blocks[(file, payload_start)] = BlockInfo(
                file=file,
                payload_start=payload_start,
                double_zero=double_zero,
                payload_capacity=int(row["payload_capacity"]),
                control_after=control_after,
                confidence=row["confidence"],
            )
    return blocks


def load_manifest(path: Path) -> list[PatchRow]:
    rows: list[PatchRow] = []
    with path.open(newline="", encoding="utf-8-sig") as f:
        for row in csv.DictReader(f):
            if row.get("enabled", "1").strip() in {"", "0", "false", "False", "no", "NO"}:
                continue
            rows.append(
                PatchRow(
                    file=row["file"].strip(),
                    payload_start=parse_int(row["payload_start"]),
                    text=row["text"],
                    notes=row.get("notes", ""),
                )
            )
    return rows


def add_auto_placeholder_rows(rows: list[PatchRow], blocks: dict[tuple[str, int], BlockInfo], files: list[str]) -> list[PatchRow]:
    existing = {(row.file, row.payload_start) for row in rows}
    added: list[PatchRow] = []
    for file in files:
        file = file.strip().replace("\\", "/")
        if not file:
            continue
        file_blocks = sorted(
            [block for block in blocks.values() if block.file == file],
            key=lambda block: block.payload_start,
        )
        if not file_blocks:
            raise SystemExit(f"No analyzed dialogue blocks found for auto-placeholder file: {file}")
        for index, block in enumerate(file_blocks, 1):
            key = (block.file, block.payload_start)
            if key in existing:
                continue
            # High-slot-only placeholders. Keep them intentionally short so auto scenes
            # do not race past long text. This is for progression, not final translation.
            if block.payload_capacity >= 16:
                text = "아크|마을로 가라"
            elif block.payload_capacity >= 10:
                text = "아크|가라"
            elif block.payload_capacity >= 6:
                text = "아크"
            else:
                text = "예"
            added.append(PatchRow(block.file, block.payload_start, text, f"auto placeholder #{index}"))
            existing.add(key)
    return rows + added


def encode_text(text: str, charmap: dict[str, int]) -> bytes:
    out = bytearray()
    for line_no, line in enumerate(text.split("|")):
        if line_no:
            out.extend(LINEBREAK)
        for char in line:
            try:
                out.append(charmap[char])
            except KeyError as exc:
                raise SystemExit(f"Unmapped glyph '{char}' in text: {text}") from exc
    return bytes(out)


def read_patch_source(base_zip: zipfile.ZipFile, file: str) -> bytes:
    try:
        return base_zip.read(file)
    except KeyError:
        source = ROOT / "01_work" / file
        if not source.exists():
            raise SystemExit(f"{file} is not in base zip and does not exist under 01_work")
        return source.read_bytes()


def validate_no_overlaps(rows: list[PatchRow], blocks: dict[tuple[str, int], BlockInfo]) -> None:
    by_file: dict[str, list[tuple[int, int, PatchRow]]] = {}
    for row in rows:
        block = blocks.get((row.file, row.payload_start))
        if block is None:
            raise SystemExit(f"Manifest target not found in analysis: {row.file} payload_start=0x{row.payload_start:X}")
        by_file.setdefault(row.file, []).append((row.payload_start, block.double_zero, row))
    for file, ranges in by_file.items():
        ranges.sort()
        for (_, prev_end, prev), (next_start, _, nxt) in zip(ranges, ranges[1:]):
            if next_start < prev_end:
                raise SystemExit(
                    f"Overlapping manifest patches in {file}: "
                    f"0x{prev.payload_start:X}-0x{prev_end:X} overlaps 0x{nxt.payload_start:X}"
                )


def apply_patch_row(data: bytearray, row: PatchRow, block: BlockInfo, payload: bytes) -> None:
    if data[block.double_zero:block.double_zero + 2] != b"\x00\x00":
        raise SystemExit(f"{row.file} 0x{row.payload_start:X}: first 00 00 boundary missing at 0x{block.double_zero:X}")
    original_control_after = bytes(data[block.double_zero:block.double_zero + len(block.control_after)])
    if original_control_after != block.control_after:
        raise SystemExit(
            f"{row.file} 0x{row.payload_start:X}: control bytes after 00 00 differ from analysis; "
            "rerun analyze_dialog_blocks.py or check the base"
        )
    if len(payload) > block.payload_capacity:
        raise SystemExit(
            f"{row.file} 0x{row.payload_start:X}: encoded text too long "
            f"{len(payload)} > capacity {block.payload_capacity}; shorten text or add font/encoding strategy"
        )

    data[row.payload_start:block.double_zero] = bytes([FILLER]) * block.payload_capacity
    data[row.payload_start:row.payload_start + len(payload)] = payload

    if data[block.double_zero:block.double_zero + 2] != b"\x00\x00":
        raise SystemExit(f"{row.file} 0x{row.payload_start:X}: patch corrupted 00 00 boundary")
    if bytes(data[block.double_zero:block.double_zero + len(block.control_after)]) != block.control_after:
        raise SystemExit(f"{row.file} 0x{row.payload_start:X}: patch corrupted control bytes after boundary")


def render_glyph(char: str) -> Image.Image:
    font = ImageFont.truetype(str(FONT_PATH), size=FONT_SIZE)
    canvas = Image.new("L", (24, 24), 0)
    draw = ImageDraw.Draw(canvas)
    bbox = draw.textbbox((0, 0), char, font=font)
    width = bbox[2] - bbox[0]
    height = bbox[3] - bbox[1]
    x = (24 - width) // 2 - bbox[0]
    y = (24 - height) // 2 - bbox[1]
    draw.text((x, y), char, fill=255, font=font)
    glyph = canvas.crop((6, 6, 18, 18))
    return glyph.point(lambda value: 255 if value >= THRESHOLD else 0, mode="1")


def set_pixel(data: bytearray, x: int, y: int, value: int) -> None:
    offset = y * ROW_BYTES + x // 2
    if x % 2 == 0:
        data[offset] = (data[offset] & 0xF0) | (value & 0x0F)
    else:
        data[offset] = (data[offset] & 0x0F) | ((value & 0x0F) << 4)


def write_cell(font: bytearray, cell: int, glyph: Image.Image) -> None:
    x0 = (cell % 21) * 12
    y0 = (cell // 21) * 12
    for y in range(12):
        for x in range(12):
            set_pixel(font, x0 + x, y0 + y, 15 if glyph.getpixel((x, y)) else 0)


def used_chars(rows: list[PatchRow]) -> set[str]:
    chars: set[str] = set()
    for row in rows:
        for char in row.text.replace("|", ""):
            if char != " ":
                chars.add(char)
    return chars


def apply_low_slot_font_updates(font: bytearray, rows: list[PatchRow], charmap: dict[str, int], notes: dict[str, str]) -> list[str]:
    rendered: list[str] = []
    for char in sorted(used_chars(rows)):
        code = charmap.get(char)
        if code is None:
            continue
        if "low-slot" not in notes.get(char, ""):
            continue
        # Verified low-slot relation from story_test_23:
        #   code 0x08 -> cell 1, 0x0C -> cell 2, ...
        cell = code // 4 - 1
        if cell < 1:
            raise SystemExit(f"Refusing to render suspicious low-slot cell {cell} for {char}=0x{code:02X}")
        write_cell(font, cell, render_glyph(char))
        rendered.append(f"{char}=0x{code:02X}/cell{cell}")
    return rendered


def build(args: argparse.Namespace) -> None:
    charmap, charmap_notes = load_charmap(args.charmap)
    blocks = load_analysis(args.analysis)
    rows = load_manifest(args.manifest)
    if args.auto_placeholder_files:
        rows = add_auto_placeholder_rows(rows, blocks, args.auto_placeholder_files.split(","))
    validate_no_overlaps(rows, blocks)

    if args.work.exists():
        shutil.rmtree(args.work)
    args.work.mkdir(parents=True, exist_ok=True)
    args.output.parent.mkdir(parents=True, exist_ok=True)

    modified: dict[str, bytearray] = {}
    report_lines: list[str] = []

    with zipfile.ZipFile(args.base_zip) as base_zip:
        font_updates = []
        if args.render_low_glyphs:
            font = bytearray(read_patch_source(base_zip, "COMM.IMG"))
            font_updates = apply_low_slot_font_updates(font, rows, charmap, charmap_notes)
            if font_updates:
                modified["COMM.IMG"] = font

        for row in rows:
            block = blocks[(row.file, row.payload_start)]
            if row.file not in modified:
                modified[row.file] = bytearray(read_patch_source(base_zip, row.file))
            payload = encode_text(row.text, charmap)
            apply_patch_row(modified[row.file], row, block, payload)
            report_lines.append(
                f"{row.file} 0x{row.payload_start:X}-0x{block.double_zero:X} "
                f"{len(payload)}/{block.payload_capacity} bytes {block.confidence} :: {row.text}"
            )

        for file, data in modified.items():
            out_path = args.work / file
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_bytes(data)

        report = "\n".join([
            "Story manifest build report",
            f"base={args.base_zip}",
            f"manifest={args.manifest}",
            f"patches={len(rows)}",
            f"font_low_slot_updates={len(font_updates)}",
            "",
            *[f"font {item}" for item in font_updates],
            "",
            *report_lines,
            "",
            *[f"{file} sha256={digest_bytes(bytes(data))}" for file, data in sorted(modified.items())],
            "",
        ])
        (args.work / "BUILD_REPORT.txt").write_text(report, encoding="utf-8")

        if args.output.exists():
            args.output.unlink()
        with zipfile.ZipFile(args.output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as out_zip:
            copied = set()
            for info in base_zip.infolist():
                # Reports are build metadata, never game replacement payloads.
                if info.filename == "BUILD_REPORT.txt":
                    continue
                if info.filename in modified:
                    out_zip.writestr(info.filename, bytes(modified[info.filename]))
                    copied.add(info.filename)
                else:
                    out_zip.writestr(info, base_zip.read(info.filename))
            for file, data in sorted(modified.items()):
                if file not in copied:
                    out_zip.writestr(file, bytes(data))

    print(f"wrote {args.output}")
    print(f"sha256={digest_bytes(args.output.read_bytes())}")
    print(f"work={args.work}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Safe manifest-based story DAT patch builder.")
    parser.add_argument("--base-zip", type=Path, default=DEFAULT_BASE_ZIP)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--charmap", type=Path, default=DEFAULT_CHARMAP)
    parser.add_argument("--analysis", type=Path, default=DEFAULT_ANALYSIS)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--work", type=Path, default=DEFAULT_WORK)
    parser.add_argument("--no-render-low-glyphs", dest="render_low_glyphs", action="store_false")
    parser.add_argument("--auto-placeholder-files", default="", help="Comma-separated DAT paths whose analyzed dialogue blocks should be filled with high-slot placeholder text.")
    parser.set_defaults(render_low_glyphs=True)
    args = parser.parse_args()
    build(args)


if __name__ == "__main__":
    main()
