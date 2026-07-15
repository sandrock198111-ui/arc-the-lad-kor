from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "03_output/story_intro_e2_skip_v11_cumulative_patch_only.zip"
BASE_HASH = "84490A7196300C903A8B1E21A408556A10D79E0406534B921557B6D75D6A88AB"
OUTPUT = ROOT / "03_output/story_punctuation_v12_cumulative_patch_only.zip"
REPORT = ROOT / "01_work/analysis/story_punctuation_v12_report.txt"

FONT_TARGET = "COMM.IMG"
ROW_BYTES = 0x380
PUNCTUATION = {
    ",": bytes.fromhex("DFE2"),
    ".": bytes.fromhex("E060"),
}
Y_SHIFT = 4


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def glyph_index(code: bytes) -> int:
    if len(code) == 1:
        return code[0] - 1
    first, second = code
    return (first - 0xDD) * 255 + second + 0xDB


def get_pixel(data: bytes | bytearray, x: int, y: int) -> int:
    value = data[y * ROW_BYTES + x // 2]
    return value & 0x0F if x % 2 == 0 else value >> 4


def set_pixel(data: bytearray, x: int, y: int, value: int) -> None:
    offset = y * ROW_BYTES + x // 2
    if x % 2 == 0:
        data[offset] = (data[offset] & 0xF0) | (value & 0x0F)
    else:
        data[offset] = (data[offset] & 0x0F) | ((value & 0x0F) << 4)


def shift_plane(font: bytearray, code: bytes) -> tuple[int, int]:
    index = glyph_index(code)
    row, remainder = divmod(index, 84)
    column, plane = divmod(remainder, 4)
    bit = 1 << plane
    pixels = [
        [bool(get_pixel(font, column * 12 + x, row * 12 + y) & bit) for x in range(12)]
        for y in range(12)
    ]
    before = sum(sum(line) for line in pixels)
    shifted = [[False] * 12 for _ in range(12)]
    for y in range(12 - Y_SHIFT):
        for x in range(12):
            shifted[y + Y_SHIFT][x] = pixels[y][x]
    after = sum(sum(line) for line in shifted)
    if before != after or before == 0:
        raise SystemExit(f"punctuation pixels clipped or empty: {code.hex()}")
    for y in range(12):
        for x in range(12):
            old = get_pixel(font, column * 12 + x, row * 12 + y)
            new = old | bit if shifted[y][x] else old & ~bit
            if (new & ~bit) != (old & ~bit):
                raise SystemExit("punctuation shift changed a neighboring plane")
            set_pixel(font, column * 12 + x, row * 12 + y, new)
    return before, after


def cursor(data: bytes | bytearray) -> bytes:
    return b"".join(data[y * ROW_BYTES:y * ROW_BYTES + 16] for y in range(128, 160))


def main() -> None:
    if digest(BASE.read_bytes()) != BASE_HASH:
        raise SystemExit("v0.11 base hash differs")
    with zipfile.ZipFile(BASE) as archive:
        infos = {item.filename: item for item in archive.infolist()}
        files = {name: archive.read(name) for name in infos}
    if len(files) != 39:
        raise SystemExit("unexpected cumulative entry count")

    original = files[FONT_TARGET]
    font = bytearray(original)
    results = {char: shift_plane(font, code) for char, code in PUNCTUATION.items()}
    if cursor(font) != cursor(original):
        raise SystemExit("battle cursor texture regression")
    files[FONT_TARGET] = bytes(font)

    with zipfile.ZipFile(OUTPUT, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name in sorted(files):
            archive.writestr(infos[name], files[name])

    report = (
        "base=v0.11\n"
        "comma_code=DFE2\n"
        "period_code=E060\n"
        f"vertical_shift={Y_SHIFT}\n"
        f"comma_pixels={results[','][1]}\n"
        f"period_pixels={results['.'][1]}\n"
        "neighbor_planes_preserved=true\n"
        "battle_cursor_preserved=true\n"
        f"sha256={digest(OUTPUT.read_bytes())}\n"
    )
    REPORT.write_text(report, encoding="utf-8")
    print(report, end="")
    print(OUTPUT)


if __name__ == "__main__":
    main()
