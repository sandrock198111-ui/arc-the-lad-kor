from __future__ import annotations

import csv
import hashlib
import struct
import zipfile
from pathlib import Path

from build_story_sf0b1_return_full import (
    FONT_TARGET,
    ROW_BYTES,
    get_pixel,
    glyph_index,
    set_pixel,
)


ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "03_output/story_intro_e2_expanded_v06_cumulative_patch_only.zip"
BASE_HASH = "D849F637D7F1C0E5B6E170BBE3CB6ACB47E48FC045C9E0A702B60CAF26991FF5"
OUTPUT = ROOT / "03_output/story_intro_dialogue_width11_v08_cumulative_patch_only.zip"
REPORT = ROOT / "01_work/analysis/story_intro_dialogue_width11_v08_report.txt"
CHARMAPS = (
    ROOT / "05_docs/korean_charmap.csv",
    ROOT / "05_docs/korean_charmap_extended.csv",
)

PSX_TARGET = "PSX.EXE"
LOAD_ADDRESS = 0x8011B000
DIALOGUE_RESET_ADDRESS = 0x8016C4D8
DIALOGUE_RESET_CALLS = (
    0x80163CD0,
    0x801640EC,
    0x80164BC8,
    0x8016C374,
)
DIALOGUE_WIDTH_STORE = 0x8016C4E4
WIDTH_11 = 0x3402000B             # ori v0,zero,000B
STORE_DIALOGUE_WIDTH = 0xA0221DC1 # sb  v0,1DC1(at) = state 0x801F1DB4 + 0x0D


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def file_offset(address: int) -> int:
    return address - LOAD_ADDRESS + 0x800


def jal(address: int) -> int:
    return 0x0C000000 | ((address >> 2) & 0x03FFFFFF)


def mapped_codes() -> list[bytes]:
    output: list[bytes] = []
    for path in CHARMAPS:
        with path.open(encoding="utf-8-sig", newline="") as handle:
            for row in csv.DictReader(handle):
                code = bytes.fromhex(row["code_hex"])
                if row["char"] != " " and code not in output:
                    output.append(code)
    return output


def narrow_plane(font: bytearray, code: bytes) -> bool:
    index = glyph_index(code)
    row, remainder = divmod(index, 84)
    column, plane = divmod(remainder, 4)
    bit = 1 << plane
    pixels = [
        [bool(get_pixel(font, column * 12 + x, row * 12 + y) & bit) for x in range(12)]
        for y in range(12)
    ]
    occupied = [x for x in range(12) if any(pixels[y][x] for y in range(12))]
    if not occupied:
        return False
    left, right = min(occupied), max(occupied)
    width = right - left + 1
    narrowed = [[False] * 12 for _ in range(12)]
    if width <= 11:
        target_left = (11 - width) // 2
        for y in range(12):
            for x in range(width):
                narrowed[y][target_left + x] = pixels[y][left + x]
    else:
        for y in range(12):
            for x in range(11):
                source_x = left + round(x * (width - 1) / 10)
                narrowed[y][x] = pixels[y][source_x]

    changed = narrowed != pixels
    if not changed:
        return False
    for y in range(12):
        for x in range(12):
            old = get_pixel(font, column * 12 + x, row * 12 + y)
            new = old | bit if narrowed[y][x] else old & ~bit
            if (new & ~bit) != (old & ~bit):
                raise SystemExit("narrowing changed a neighboring font plane")
            set_pixel(font, column * 12 + x, row * 12 + y, new)
    return True


def cursor(data: bytes) -> bytes:
    return b"".join(data[y * ROW_BYTES:y * ROW_BYTES + 16] for y in range(128, 160))


def main() -> None:
    if digest(BASE.read_bytes()) != BASE_HASH:
        raise SystemExit("v0.6 base hash differs")
    with zipfile.ZipFile(BASE) as archive:
        infos = {item.filename: item for item in archive.infolist()}
        files = {name: archive.read(name) for name in infos}
    if len(files) != 39:
        raise SystemExit("unexpected cumulative entry count")

    psx = bytearray(files[PSX_TARGET])
    for address in DIALOGUE_RESET_CALLS:
        offset = file_offset(address)
        if struct.unpack_from("<I", psx, offset)[0] != jal(DIALOGUE_RESET_ADDRESS):
            raise SystemExit(f"dialogue reset call differs at 0x{address:08X}")
        if struct.unpack_from("<I", psx, offset + 4)[0] != 0:
            raise SystemExit(f"dialogue reset delay slot differs at 0x{address + 4:08X}")
        struct.pack_into("<I", psx, offset + 4, WIDTH_11)
    store_offset = file_offset(DIALOGUE_WIDTH_STORE)
    if struct.unpack_from("<I", psx, store_offset)[0] != 0:
        raise SystemExit("dialogue reset return delay slot differs")
    struct.pack_into("<I", psx, store_offset, STORE_DIALOGUE_WIDTH)
    files[PSX_TARGET] = bytes(psx)

    original_font = files[FONT_TARGET]
    font = bytearray(original_font)
    changed_glyphs = sum(narrow_plane(font, code) for code in mapped_codes())
    if cursor(font) != cursor(original_font):
        raise SystemExit("battle cursor texture regression")
    files[FONT_TARGET] = bytes(font)

    with zipfile.ZipFile(OUTPUT, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name in sorted(files):
            archive.writestr(infos[name], files[name])
    report = (
        "dialogue_glyph_width=11\n"
        "dialogue_space_width=11\n"
        f"narrowed_mapped_glyphs={changed_glyphs}\n"
        "method=dialogue_state_reset_delay_slots\n"
        "patched_reset_calls=0x80163CD0,0x801640EC,0x80164BC8,0x8016C374\n"
        f"sha256={digest(OUTPUT.read_bytes())}\n"
    )
    REPORT.write_text(report, encoding="utf-8")
    print(report, end="")
    print(OUTPUT)


if __name__ == "__main__":
    main()
