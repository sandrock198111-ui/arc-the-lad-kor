from __future__ import annotations

import csv
import hashlib
import zipfile
from collections import Counter
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "03_output" / "story_s2051_throne_full_patch_only.zip"
SOURCE = ROOT / "01_work" / "F" / "SF0B1.DAT"
MANIFEST = ROOT / "05_docs" / "story_sf0b1_return_translation.csv"
BASE_CHARMAP = ROOT / "05_docs" / "korean_charmap.csv"
EXTENDED_CHARMAP = ROOT / "05_docs" / "korean_charmap_extended.csv"
OUTPUT = ROOT / "03_output" / "story_sf0b1_return_cursor_fixed_full_patch_only.zip"
TARGET = "F/SF0B1.DAT"
FONT_TARGET = "COMM.IMG"
FONT_PATH = Path(r"C:\Windows\Fonts\gulim.ttc")
ROW_BYTES = 0x380
FILLER = 0x9C
LINEBREAK = b"\xE6\x01"
PAGEBREAK = b"\xE4\x1F"
CURSOR_RESERVED_CELLS = {
    (row, column)
    for row in (11, 12, 13)
    for column in (0, 1, 2)
}


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def load_rows() -> list[dict[str, str]]:
    with MANIFEST.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def load_charmap() -> dict[str, bytes]:
    result: dict[str, bytes] = {}
    for path in (BASE_CHARMAP, EXTENDED_CHARMAP):
        with path.open(encoding="utf-8-sig", newline="") as handle:
            for row in csv.DictReader(handle):
                code = bytes.fromhex(row["code_hex"])
                if len(code) not in (1, 2):
                    raise SystemExit(f"invalid code for {row['char']}: {row['code_hex']}")
                # The extended table deliberately overrides legacy mappings
                # whose glyphs have not been verified against the real decoder.
                result[row["char"]] = code
    return result


def glyph_index(code: bytes) -> int:
    if len(code) == 1:
        if code[0] >= 0xDD:
            raise ValueError("one-byte glyph code must be below 0xDD")
        return code[0] - 1
    first, second = code
    if not 0xDD <= first <= 0xE0:
        raise ValueError("two-byte glyph prefix must be DD-E0")
    return (first - 0xDD) * 255 + second + 0xDB


def render_glyph(char: str) -> Image.Image:
    font = ImageFont.truetype(str(FONT_PATH), size=12)
    canvas = Image.new("L", (24, 24), 0)
    draw = ImageDraw.Draw(canvas)
    bbox = draw.textbbox((0, 0), char, font=font)
    x = (24 - (bbox[2] - bbox[0])) // 2 - bbox[0]
    y = (24 - (bbox[3] - bbox[1])) // 2 - bbox[1]
    draw.text((x, y), char, fill=255, font=font)
    return canvas.crop((6, 6, 18, 18)).point(
        lambda value: 255 if value >= 192 else 0, mode="1"
    )


def get_pixel(data: bytearray, x: int, y: int) -> int:
    value = data[y * ROW_BYTES + x // 2]
    return value & 0x0F if x % 2 == 0 else value >> 4


def set_pixel(data: bytearray, x: int, y: int, value: int) -> None:
    offset = y * ROW_BYTES + x // 2
    if x % 2 == 0:
        data[offset] = (data[offset] & 0xF0) | (value & 0x0F)
    else:
        data[offset] = (data[offset] & 0x0F) | ((value & 0x0F) << 4)


def write_glyph_plane(font: bytearray, code: bytes, char: str) -> None:
    index = glyph_index(code)
    row, remainder = divmod(index, 84)
    column, plane = divmod(remainder, 4)
    if row >= 42 or column >= 21:
        raise SystemExit(f"glyph position out of range for {char}: {code.hex()}")
    bit = 1 << plane
    glyph = render_glyph(char)
    for y in range(12):
        for x in range(12):
            old = get_pixel(font, column * 12 + x, row * 12 + y)
            if glyph.getpixel((x, y)):
                new = old | bit
            else:
                new = old & ~bit
            if (new & ~bit) != (old & ~bit):
                raise SystemExit("font writer changed a neighboring bitplane")
            set_pixel(font, column * 12 + x, row * 12 + y, new)


def encode_text(text: str, charmap: dict[str, bytes]) -> bytes:
    output = bytearray()
    for char in text:
        if char == "|":
            output.extend(LINEBREAK)
        elif char == "^":
            output.extend(PAGEBREAK)
        elif char == " ":
            output.append(FILLER)
        else:
            try:
                output.extend(charmap[char])
            except KeyError as exc:
                raise SystemExit(f"unmapped character: {char}") from exc
    return bytes(output)


def verify_extended_codes_unused() -> None:
    baseline_dirs = (
        "1", "21", "22", "23", "31", "32", "4", "5", "6", "7", "8", "9",
        "B", "C1", "C2", "D", "E1", "E2", "E3", "E4", "E5", "F",
    )
    counts: Counter[bytes] = Counter()
    for directory in baseline_dirs:
        for path in (ROOT / "01_work" / directory).glob("*.DAT"):
            data = path.read_bytes()[0x45000:]
            for offset in range(len(data) - 1):
                if data[offset] == 0xE0:
                    counts[data[offset : offset + 2]] += 1
    with EXTENDED_CHARMAP.open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            code = bytes.fromhex(row["code_hex"])
            if counts[code]:
                raise SystemExit(
                    f"extended code {code.hex()} for {row['char']} occurs in baseline story data"
                )
            index = glyph_index(code)
            glyph_row, remainder = divmod(index, 84)
            column, _ = divmod(remainder, 4)
            if (glyph_row, column) in CURSOR_RESERVED_CELLS:
                raise SystemExit(
                    f"extended code {code.hex()} for {row['char']} overlaps battle cursor"
                )


def main() -> None:
    rows = load_rows()
    charmap = load_charmap()
    verify_extended_codes_unused()

    with zipfile.ZipFile(BASE) as archive:
        files = {
            info.filename: archive.read(info.filename)
            for info in archive.infolist()
            if info.filename != "BUILD_REPORT.txt"
        }
    if len(files) != 29 or FONT_TARGET not in files:
        raise SystemExit("unexpected cumulative base")

    original = SOURCE.read_bytes()
    data = bytearray(original)
    font = bytearray(files[FONT_TARGET])
    original_font = bytes(font)

    with EXTENDED_CHARMAP.open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            write_glyph_plane(font, bytes.fromhex(row["code_hex"]), row["char"])

    report: list[str] = []
    for row in rows:
        offset = int(row["offset"], 0)
        expected = bytes.fromhex(row["expected_hex"])
        end = offset + len(expected)
        if original[offset:end] != expected:
            raise SystemExit(f"{TARGET} 0x{offset:X}: source bytes differ")
        if original[end : end + 2] != b"\x00\x00":
            raise SystemExit(f"{TARGET} 0x{offset:X}: missing 00 00 boundary")
        payload = encode_text(row["text"], charmap)
        if len(payload) > len(expected):
            raise SystemExit(
                f"{TARGET} 0x{offset:X}: translation too long "
                f"{len(payload)} > {len(expected)} :: {row['text']}"
            )
        data[offset:end] = bytes([FILLER]) * len(expected)
        data[offset : offset + len(payload)] = payload
        if data[end : end + 2] != b"\x00\x00":
            raise SystemExit(f"{TARGET} 0x{offset:X}: boundary changed")
        report.append(f"0x{offset:X} {len(payload)}/{len(expected)} {row['text']}")

    files[FONT_TARGET] = bytes(font)
    files[TARGET] = bytes(data)
    if original_font == files[FONT_TARGET]:
        raise SystemExit("font was not changed")

    if OUTPUT.exists():
        OUTPUT.unlink()
    with zipfile.ZipFile(OUTPUT, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name in sorted(files):
            archive.writestr(name, files[name])

    with zipfile.ZipFile(OUTPUT) as archive:
        names = archive.namelist()
        if len(names) != 30 or len(names) != len(set(names)):
            raise SystemExit("output must contain 30 unique game files")
        if archive.read(TARGET) != data or archive.read(FONT_TARGET) != font:
            raise SystemExit("output payload verification failed")
        with zipfile.ZipFile(BASE) as base:
            for name in base.namelist():
                if name not in (TARGET, FONT_TARGET, "BUILD_REPORT.txt"):
                    if archive.read(name) != base.read(name):
                        raise SystemExit(f"unrelated cumulative file changed: {name}")

    print("\n".join(report))
    print(f"font_changed_bytes={sum(a != b for a, b in zip(original_font, font))}")
    print(f"wrote {OUTPUT}")
    print(f"sha256={digest(OUTPUT.read_bytes())}")


if __name__ == "__main__":
    main()
