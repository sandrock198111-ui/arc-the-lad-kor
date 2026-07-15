from __future__ import annotations

import csv
import hashlib
import sys
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "06_tools/python_packages"))

from build_story_sf0b1_return_full import (  # noqa: E402
    FONT_TARGET,
    glyph_index,
    write_glyph_plane,
)

BASE = ROOT / "03_output/story_punctuation_v12_cumulative_patch_only.zip"
BASE_HASH = "4CE0465201FE204A542413271C2FDC1C52E7F7DC793224F9D533B855A2D4CDFB"
MANIFEST = ROOT / "05_docs/story_s1072_e2_translation.csv"
BASE_CHARMAP = ROOT / "05_docs/korean_charmap.csv"
EXTENDED_CHARMAP = ROOT / "05_docs/korean_charmap_extended.csv"
CORPUS = ROOT / "01_work/analysis/story_corpus/story_corpus.csv"
OUTPUT = ROOT / "03_output/story_s1072_e2_v13_cumulative_patch_only.zip"
REPORT = ROOT / "01_work/analysis/story_s1072_e2_v13_report.txt"

TARGET = "1/S1072.DAT"
SLOT_BASE = 0x45000
SLOT_SIZE = 0x80
SLOT_COUNT = 16
CUSTOM_DISK_FIRST = 0x81
FILLER = 0x9C


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def rows(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def encode(text: str, mapping: dict[str, bytes]) -> bytes:
    payload = bytearray()
    for char in text:
        payload.extend(bytes((FILLER,)) if char == " " else mapping[char])
    return bytes(payload)


def cursor_code(code: bytes) -> bool:
    index = glyph_index(code)
    row, remainder = divmod(index, 84)
    column, _ = divmod(remainder, 4)
    left, top = column * 12, row * 12
    return left <= 31 and left + 11 >= 0 and top <= 159 and top + 11 >= 128


def cursor(data: bytes | bytearray) -> bytes:
    return b"".join(data[y * 0x380:y * 0x380 + 16] for y in range(128, 160))


def main() -> None:
    if digest(BASE.read_bytes()) != BASE_HASH:
        raise SystemExit("v0.12 base hash differs")

    manifest = rows(MANIFEST)
    if len(manifest) != 10 or {item["file"] for item in manifest} != {TARGET}:
        raise SystemExit("unexpected S1072 manifest")

    mapping: dict[str, bytes] = {}
    extended = rows(EXTENDED_CHARMAP)
    for path in (BASE_CHARMAP, EXTENDED_CHARMAP):
        for item in rows(path):
            mapping[item["char"]] = bytes.fromhex(item["code_hex"])
    missing = sorted({char for item in manifest for char in item["text"] if char != " " and char not in mapping})
    occupied = set(mapping.values())
    parsed_codes: set[bytes] = set()
    for item in rows(CORPUS):
        body = bytes.fromhex(item["original_hex"])
        position = 0
        while position < len(body):
            if 0xDD <= body[position] <= 0xE0 and position + 1 < len(body):
                parsed_codes.add(body[position:position + 2])
                position += 2
            else:
                position += 1
    candidates = [
        bytes((first, second))
        for first in range(0xE0, 0xDC, -1)
        for second in range(0xFF, -1, -1)
        if bytes((first, second)) not in occupied
        and bytes((first, second)) not in parsed_codes
        and not cursor_code(bytes((first, second)))
    ]
    if len(candidates) < len(missing):
        raise SystemExit(f"not enough safe glyph codes: {len(missing)} > {len(candidates)}")
    additions = []
    for char, code in zip(missing, candidates):
        mapping[char] = code
        additions.append({
            "char": char,
            "code_hex": code.hex().upper(),
            "slot_note": "S1072 E2 v0.13",
        })

    with zipfile.ZipFile(BASE) as archive:
        infos = {item.filename: item for item in archive.infolist()}
        files = {name: archive.read(name) for name in infos}
    if len(files) != 39 or TARGET not in files:
        raise SystemExit("unexpected cumulative file set")

    base_font = files[FONT_TARGET]
    font = bytearray(base_font)
    batch_glyphs = [item for item in extended if item["slot_note"] == "S1072 E2 v0.13"] + additions
    for item in batch_glyphs:
        write_glyph_plane(font, bytes.fromhex(item["code_hex"]), item["char"])
    if cursor(font) != cursor(base_font):
        raise SystemExit("battle cursor texture regression")
    files[FONT_TARGET] = bytes(font)

    story = bytearray(files[TARGET])
    used_slots: set[int] = set()
    report_lines = []
    for item in manifest:
        offset = int(item["offset"], 0)
        capacity = int(item["capacity"])
        slot = int(item["slot"])
        if not 0 <= slot < SLOT_COUNT or slot in used_slots:
            raise SystemExit(f"invalid or duplicate slot {slot}")
        used_slots.add(slot)
        if story[offset + capacity:offset + capacity + 2] != b"\x00\x00":
            raise SystemExit(f"missing boundary at 0x{offset:X}")

        slot_offset = SLOT_BASE + slot * SLOT_SIZE
        if any(story[slot_offset:slot_offset + SLOT_SIZE]):
            raise SystemExit(f"slot {slot} is not empty")
        payload = encode(item["text"], mapping)
        if len(payload) + 1 > SLOT_SIZE - 1:
            raise SystemExit(f"slot overflow {slot}: {len(payload) + 1}/{SLOT_SIZE - 1}")

        story[slot_offset:slot_offset + len(payload)] = payload
        story[slot_offset + len(payload):slot_offset + SLOT_SIZE - 1] = b"\x00" * (SLOT_SIZE - 1 - len(payload))
        story[slot_offset + SLOT_SIZE - 1] = capacity - 2
        story[offset:offset + 2] = bytes((0xE2, CUSTOM_DISK_FIRST + slot))
        report_lines.append(
            f"{TARGET} 0x{offset:X} slot={slot} command=E2 {CUSTOM_DISK_FIRST + slot:02X} "
            f"skip={capacity - 2} bytes={len(payload)}/{SLOT_SIZE - 1} text={item['text']}"
        )

    files[TARGET] = bytes(story)
    with zipfile.ZipFile(OUTPUT, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name in sorted(files):
            archive.writestr(infos[name], files[name])

    with zipfile.ZipFile(BASE) as before, zipfile.ZipFile(OUTPUT) as after:
        if len(after.namelist()) != 39 or len(set(after.namelist())) != 39:
            raise SystemExit("output must contain 39 unique files")
        changed = [name for name in before.namelist() if before.read(name) != after.read(name)]
        if set(changed) != {TARGET, FONT_TARGET}:
            raise SystemExit(f"unexpected changed files: {changed}")

    if additions:
        with EXTENDED_CHARMAP.open("a", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=["char", "code_hex", "slot_note"])
            writer.writerows(additions)

    report = "\n".join(report_lines) + "\n"
    report += f"e2_slots=10\nbatch_glyphs={len(batch_glyphs)}\nbattle_cursor_preserved=true\nother_files_preserved=true\n"
    report += f"sha256={digest(OUTPUT.read_bytes())}\n"
    REPORT.write_text(report, encoding="utf-8")
    print(report, end="")
    print(OUTPUT)


if __name__ == "__main__":
    main()
