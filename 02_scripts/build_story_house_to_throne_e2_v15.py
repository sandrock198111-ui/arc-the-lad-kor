from __future__ import annotations

import csv
import hashlib
import sys
import zipfile
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "06_tools/python_packages"))
sys.path.insert(0, str(ROOT / "02_scripts"))

from build_story_sf0b1_return_full import (  # noqa: E402
    FONT_TARGET,
    glyph_index,
    write_glyph_plane,
)

BASE = ROOT / "03_output/story_e2_bank79_v14_cumulative_patch_only.zip"
BASE_HASH = "992885C8BF7EC05CAAE38E91A42E866AAF166179548CBD400086F6548FBFE779"
MANIFEST = ROOT / "05_docs/story_house_to_throne_e2_translation.csv"
EXTENDED = ROOT / "05_docs/korean_charmap_extended.csv"
CORPUS = ROOT / "01_work/analysis/story_corpus/story_corpus.csv"
OUTPUT = ROOT / "03_output/story_house_to_throne_e2_v15_cumulative_patch_only.zip"
REPORT = ROOT / "01_work/analysis/story_house_to_throne_e2_v15_report.txt"

SLOT_BASE = 0x45000
SLOT_SIZE = 0x80
SLOT_COUNT = 79
FILLER = 0x9C
BATCH_NOTE = "house-to-throne E2 v0.15"
GLYPH_INDEX_MIGRATIONS = {
    "1/S1011.DAT": (0x4531E,),
    "21/S2021.DAT": (0x4537D,),
    "31/S3022.DAT": (0x485DA,),
}
OLD_COLLIDING_CODE = bytes.fromhex("DFFF")
NEW_DISTINCT_CODE = bytes.fromhex("DEF7")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def rows(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def cursor_code(code: bytes) -> bool:
    index = glyph_index(code)
    row, remainder = divmod(index, 84)
    column, _ = divmod(remainder, 4)
    left, top = column * 12, row * 12
    return left <= 31 and left + 11 >= 0 and top <= 159 and top + 11 >= 128


def cursor(data: bytes | bytearray) -> bytes:
    return b"".join(data[y * 0x380:y * 0x380 + 16] for y in range(128, 160))


def disk_id(slot: int) -> int:
    if not 0 <= slot < SLOT_COUNT:
        raise ValueError(slot)
    return slot + 0x81 if slot < 40 else slot + 0x82


def encode(text: str, mapping: dict[str, bytes]) -> bytes:
    payload = bytearray()
    for char in text:
        payload.extend(bytes((FILLER,)) if char == " " else mapping[char])
    return bytes(payload)


def main() -> None:
    if digest(BASE.read_bytes()) != BASE_HASH:
        raise SystemExit("v0.14 base hash differs")
    manifest = rows(MANIFEST)
    counts = Counter(item["file"] for item in manifest)
    if len(manifest) != 185 or len(counts) != 14:
        raise SystemExit(f"unexpected manifest: rows={len(manifest)} files={len(counts)}")

    with zipfile.ZipFile(BASE) as archive:
        infos = {item.filename: item for item in archive.infolist()}
        files = {name: archive.read(name) for name in infos}
    if len(files) != 39 or set(counts) - files.keys():
        raise SystemExit("unexpected cumulative file set")
    for name, offsets in GLYPH_INDEX_MIGRATIONS.items():
        data = bytearray(files[name])
        for offset in offsets:
            if data[offset:offset + 2] != OLD_COLLIDING_CODE:
                raise SystemExit(f"glyph migration source differs: {name} 0x{offset:X}")
            data[offset:offset + 2] = NEW_DISTINCT_CODE
        files[name] = bytes(data)

    extended = rows(EXTENDED)
    mapping = {item["char"]: bytes.fromhex(item["code_hex"]) for item in extended}
    occupied = set(mapping.values())
    occupied_indices = {glyph_index(code) for code in occupied}
    replaced = {(item["file"], item["offset"]) for item in manifest}
    parsed_codes: set[bytes] = set()
    for item in rows(CORPUS):
        if item["file"] not in files or (item["file"], item["payload_start"]) in replaced:
            continue
        offset = int(item["payload_start"], 0)
        capacity = int(item["capacity"])
        body = files[item["file"]][offset:offset + capacity]
        position = 0
        while position < len(body):
            if 0xDD <= body[position] <= 0xE0 and position + 1 < len(body):
                parsed_codes.add(body[position:position + 2])
                position += 2
            else:
                position += 1

    needed = {char for item in manifest for char in item["text"] if char != " "}
    missing = sorted(needed - mapping.keys())
    candidates = []
    candidate_indices: set[int] = set()
    for first in range(0xE0, 0xDC, -1):
        for second in range(0xFF, -1, -1):
            code = bytes((first, second))
            index = glyph_index(code)
            if (
                code not in occupied
                and code not in parsed_codes
                and index not in occupied_indices
                and index not in candidate_indices
                and not cursor_code(code)
            ):
                candidates.append(code)
                candidate_indices.add(index)
    if len(candidates) < len(missing):
        raise SystemExit(f"not enough safe glyph codes: {len(missing)} > {len(candidates)}")
    additions = []
    for char, code in zip(missing, candidates):
        mapping[char] = code
        additions.append({"char": char, "code_hex": code.hex().upper(), "slot_note": BATCH_NOTE})

    base_font = files[FONT_TARGET]
    font = bytearray(base_font)
    batch_rows = [item for item in extended if item["slot_note"] == BATCH_NOTE] + additions
    batch_chars = needed | {"앗", "았"}
    for char in sorted(batch_chars):
        write_glyph_plane(font, mapping[char], char)
    if cursor(font) != cursor(base_font):
        raise SystemExit("battle cursor texture regression")
    files[FONT_TARGET] = bytes(font)

    targets = {name: bytearray(files[name]) for name in counts}
    free_slots = {
        name: [
            slot for slot in range(SLOT_COUNT)
            if not any(data[SLOT_BASE + slot * SLOT_SIZE:SLOT_BASE + (slot + 1) * SLOT_SIZE])
        ]
        for name, data in targets.items()
    }
    for name, count in counts.items():
        if len(free_slots[name]) < count:
            raise SystemExit(f"not enough empty slots in {name}: {len(free_slots[name])} < {count}")

    used_slots = {name: [] for name in counts}
    report_lines = []
    overflow = []
    for item in manifest:
        name = item["file"]
        data = targets[name]
        offset = int(item["offset"], 0)
        capacity = int(item["capacity"])
        if data[offset + capacity:offset + capacity + 2] != b"\x00\x00":
            raise SystemExit(f"missing dialogue boundary: {name} 0x{offset:X}")
        payload = encode(item["text"], mapping)
        if len(payload) > SLOT_SIZE - 1:
            overflow.append(f"{name} 0x{offset:X} {len(payload)}/{SLOT_SIZE - 1} {item['text']}")
            continue

        slot = free_slots[name].pop(0)
        used_slots[name].append(slot)
        slot_offset = SLOT_BASE + slot * SLOT_SIZE
        data[slot_offset:slot_offset + SLOT_SIZE] = b"\x00" * SLOT_SIZE
        data[slot_offset:slot_offset + len(payload)] = payload
        data[slot_offset + SLOT_SIZE - 1] = capacity - 2
        data[offset:offset + 2] = bytes((0xE2, disk_id(slot)))
        report_lines.append(
            f"{name} 0x{offset:X} slot={slot} command=E2 {disk_id(slot):02X} "
            f"skip={capacity - 2} bytes={len(payload)}/{SLOT_SIZE - 1} text={item['text']}"
        )
    if overflow:
        raise SystemExit("E2 overflow:\n" + "\n".join(overflow))

    files.update({name: bytes(data) for name, data in targets.items()})
    with zipfile.ZipFile(OUTPUT, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name in sorted(files):
            archive.writestr(infos[name], files[name])

    with zipfile.ZipFile(BASE) as before, zipfile.ZipFile(OUTPUT) as after:
        if len(after.namelist()) != 39 or len(set(after.namelist())) != 39:
            raise SystemExit("output must contain 39 unique files")
        changed = {name for name in before.namelist() if before.read(name) != after.read(name)}
        expected = set(counts) | set(GLYPH_INDEX_MIGRATIONS) | {FONT_TARGET}
        if changed != expected:
            raise SystemExit(f"unexpected changed files: {sorted(changed ^ expected)}")

    if additions:
        with EXTENDED.open("a", encoding="utf-8", newline="") as handle:
            csv.DictWriter(handle, fieldnames=["char", "code_hex", "slot_note"]).writerows(additions)

    report = "\n".join(report_lines) + "\n"
    report += f"dialogues={len(manifest)}\nfiles={len(counts)}\n"
    report += f"batch_glyphs={len(batch_chars)}\nnew_glyphs={len(batch_rows)}\n"
    report += "glyph_index_collisions_fixed=DEFF/DF00,DFFF/E000\n"
    report += "battle_cursor_preserved=true\nother_files_preserved=true\n"
    report += f"sha256={digest(OUTPUT.read_bytes())}\n"
    REPORT.write_text(report, encoding="utf-8")
    print(f"dialogues={len(manifest)} files={len(counts)} additions={len(additions)}")
    print(f"sha256={digest(OUTPUT.read_bytes())}")
    print(OUTPUT)


if __name__ == "__main__":
    main()
