from __future__ import annotations

import csv
import hashlib
import struct
import zipfile
from pathlib import Path

from build_story_sf0b1_return_full import (
    BASE_CHARMAP, CURSOR_RESERVED_CELLS, FILLER, FONT_TARGET,
    glyph_index, write_glyph_plane,
)

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "03_output/story_intro_stable_v01_cumulative_patch_only.zip"
MANIFEST = ROOT / "05_docs/story_intro_s1071_s1011_stable_translation.csv"
EXTENDED = ROOT / "05_docs/korean_charmap_extended.csv"
CORPUS = ROOT / "01_work/analysis/story_corpus/story_corpus.csv"
PSX_SOURCE = ROOT / "01_work/PSX.EXE"
OUTPUT = ROOT / "03_output/story_intro_longtext_e2ff_proof_patch_only.zip"
PSX_TARGET = "PSX.EXE"
PSX_HASH = "947EBF893F2D46207EC7E32CA514E4EA670E0BED34EF2144B5F7FB0FDD15BC67"
LOAD_ADDRESS = 0x8011B000
HOOK_ADDRESS = 0x8015EA44
CAVE_ADDRESS = 0x801A86F0
TEXT_ADDRESS = CAVE_ADDRESS + 0x30
RESUME_ADDRESS = 0x8015EA4C
LONG_FILE = "1/S1011.DAT"
LONG_OFFSET = 0x479FC
LONG_CAPACITY = 36
LONG_TEXT = "그리고 신의 피를 잇는|일족의 딸이라는 이유로|왕자와 결혼해야 해..."
LINEBREAK = b"\xE6\x01"


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def file_offset(address: int) -> int:
    return address - LOAD_ADDRESS + 0x800


def jump(address: int) -> int:
    return 0x08000000 | ((address >> 2) & 0x03FFFFFF)


def cursor_code(code: bytes) -> bool:
    row, rem = divmod(glyph_index(code), 84)
    column, _ = divmod(rem, 4)
    return (row, column) in CURSOR_RESERVED_CELLS


def encode(text: str, mapping: dict[str, bytes]) -> bytes:
    output = bytearray()
    for char in text:
        output.extend(LINEBREAK if char == "|" else bytes((FILLER,)) if char == " " else mapping[char])
    return bytes(output)


def main() -> None:
    manifest = load_csv(MANIFEST)
    extended_rows = load_csv(EXTENDED)
    extended_chars = {row["char"] for row in extended_rows}
    all_text = "".join(row["text"] for row in manifest) + LONG_TEXT
    missing_hangul = sorted({char for char in all_text if "가" <= char <= "힣" and char not in extended_chars})

    mapping: dict[str, bytes] = {}
    for path in (BASE_CHARMAP, EXTENDED):
        for row in load_csv(path):
            mapping[row["char"]] = bytes.fromhex(row["code_hex"])
    occupied = set(mapping.values())
    parsed: set[bytes] = set()
    for row in load_csv(CORPUS):
        body = bytes.fromhex(row["original_hex"])
        pos = 0
        while pos < len(body):
            if 0xDD <= body[pos] <= 0xE0 and pos + 1 < len(body):
                parsed.add(body[pos:pos + 2])
                pos += 2
            else:
                pos += 1
    if b"\xE2\xFF" in b"".join(bytes.fromhex(row["original_hex"]) for row in load_csv(CORPUS)):
        raise SystemExit("E2 FF already occurs in parsed story data")
    candidates = [bytes((first, second)) for first in range(0xE0, 0xDC, -1) for second in range(0xFF, -1, -1)
                  if bytes((first, second)) not in occupied and bytes((first, second)) not in parsed
                  and not cursor_code(bytes((first, second)))]
    if len(candidates) < len(missing_hangul):
        raise SystemExit("not enough verified Hangul codes")
    added = []
    for char, code in zip(missing_hangul, candidates):
        mapping[char] = code
        added.append({"char": char, "code_hex": code.hex().upper(), "slot_note": "E2 FF long-text proof; replaces legacy Hangul"})

    with zipfile.ZipFile(BASE) as archive:
        files = {item.filename: archive.read(item.filename) for item in archive.infolist()}
    if len(files) != 38 or PSX_TARGET in files:
        raise SystemExit("unexpected proof base")

    targets = {name: bytearray(files[name]) for name in {row["file"] for row in manifest}}
    report = []
    for row in manifest:
        name, offset, capacity = row["file"], int(row["offset"], 0), int(row["capacity"])
        end = offset + capacity
        if files[name][end:end + 2] != b"\x00\x00":
            raise SystemExit(f"missing boundary: {name} 0x{offset:X}")
        if name == LONG_FILE and offset == LONG_OFFSET:
            payload = b"\xE2\xFF"
            shown = LONG_TEXT
        else:
            payload = encode(row["text"], mapping)
            shown = row["text"]
        if len(payload) > capacity:
            raise SystemExit(f"too long: {name} 0x{offset:X}")
        targets[name][offset:end] = bytes((FILLER,)) * capacity
        targets[name][offset:offset + len(payload)] = payload
        report.append(f"{name} 0x{offset:X} inline={len(payload)}/{capacity} {shown}")

    base_font = files[FONT_TARGET]
    font = bytearray(base_font)
    for row in extended_rows + added:
        write_glyph_plane(font, bytes.fromhex(row["code_hex"]), row["char"])
    cursor = lambda data: b"".join(data[y * 0x380:y * 0x380 + 16] for y in range(128, 160))
    if cursor(font) != cursor(base_font):
        raise SystemExit("battle cursor regression")
    files[FONT_TARGET] = bytes(font)
    files.update({name: bytes(data) for name, data in targets.items()})

    psx = bytearray(PSX_SOURCE.read_bytes())
    if digest(psx) != PSX_HASH:
        raise SystemExit("PSX.EXE source hash differs")
    hook_offset = file_offset(HOOK_ADDRESS)
    expected_hook = bytes.fromhex("1A80033C4CC36324")
    if psx[hook_offset:hook_offset + 8] != expected_hook:
        raise SystemExit("E2 lookup prologue differs")
    cave_offset = file_offset(CAVE_ADDRESS)
    if any(psx[cave_offset:]):
        raise SystemExit("selected end cave is not empty")

    # E2 FF returns a pointer to our proof string; every other E2 index resumes the original lookup.
    wrapper = struct.pack(
        "<12I",
        0x308400FF,             # andi a0,a0,00FF
        0x340800FE,             # ori t0,zero,00FE (E2 argument is decremented)
        0x10880005,             # beq a0,t0,custom
        0x00000000,             # nop
        0x3C03801A,             # lui v1,801A
        0x2463C34C,             # addiu v1,v1,C34C
        jump(RESUME_ADDRESS),
        0x00000000,
        0x3C02801A,             # custom: lui v0,801A
        0x34428720,             # ori v0,v0,8720
        0x03E00008,             # jr ra
        0x00000000,
    )
    long_payload = encode(LONG_TEXT, mapping) + b"\x00"
    if len(wrapper) != 0x30 or len(long_payload) > len(psx) - file_offset(TEXT_ADDRESS):
        raise SystemExit("proof code or text does not fit cave")
    psx[hook_offset:hook_offset + 8] = struct.pack("<II", jump(CAVE_ADDRESS), 0)
    psx[cave_offset:cave_offset + len(wrapper)] = wrapper
    text_offset = file_offset(TEXT_ADDRESS)
    psx[text_offset:text_offset + len(long_payload)] = long_payload
    if struct.unpack_from("<I", psx, hook_offset)[0] != jump(CAVE_ADDRESS):
        raise SystemExit("hook verification failed")
    if psx[text_offset:text_offset + len(long_payload)] != long_payload:
        raise SystemExit("external text verification failed")
    files[PSX_TARGET] = bytes(psx)

    with zipfile.ZipFile(OUTPUT, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name in sorted(files):
            archive.writestr(name, files[name])
    with zipfile.ZipFile(OUTPUT) as archive:
        if len(archive.namelist()) != 39 or len(set(archive.namelist())) != 39:
            raise SystemExit("proof ZIP must contain 39 unique files")
        if archive.read(PSX_TARGET) != psx or archive.read(LONG_FILE) != targets[LONG_FILE]:
            raise SystemExit("proof ZIP payload differs")
    if added:
        with EXTENDED.open("a", encoding="utf-8", newline="") as handle:
            csv.DictWriter(handle, fieldnames=["char", "code_hex", "slot_note"]).writerows(added)
    report_path = ROOT / "01_work/analysis/story_intro_e2ff_longtext_proof_report.txt"
    report_path.write_text(
        "\n".join(report)
        + f"\nexternal_text_bytes={len(long_payload) - 1}\nnew_glyphs={len(added)}\n"
        + f"psx_sha256={digest(psx)}\nzip_sha256={digest(OUTPUT.read_bytes())}\n",
        encoding="utf-8",
    )
    print(f"entries={len(manifest)} external_text_bytes={len(long_payload) - 1} new_glyphs={len(added)} files={len(files)}")
    print(OUTPUT)
    print(digest(OUTPUT.read_bytes()))


if __name__ == "__main__":
    main()
