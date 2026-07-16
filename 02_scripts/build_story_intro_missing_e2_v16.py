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

BASE = ROOT / "03_output/story_house_to_throne_e2_v15_cumulative_patch_only.zip"
BASE_HASH = "196AB88F3AAF7956D5194723498D791267662D405075880121276E4ABDAAAD68"
MANIFEST = ROOT / "05_docs/story_intro_missing_e2_translation.csv"
EXTENDED = ROOT / "05_docs/korean_charmap_extended.csv"
CORPUS = ROOT / "01_work/analysis/story_corpus/story_corpus.csv"
ORIGINAL_S1023 = ROOT / "01_work/1/S1023.DAT"
OUTPUT = ROOT / "03_output/story_intro_complete_e2_v16_cumulative_patch_only.zip"
REPORT = ROOT / "01_work/analysis/story_intro_complete_e2_v16_report.txt"

SLOT_BASE = 0x45000
SLOT_SIZE = 0x80
SLOT_COUNT = 79
FILLER = 0x9C
CHOICE = b"\xE5\x03"
LINEBREAK = b"\xE6\x01"
BATCH_NOTE = "intro missing E2 v0.16"

# The sets identify which translated segments retain the original choice marker
# and line-break positions. This keeps selection behavior out of the E2 path.
CHOICE_LAYOUTS = {
    0x47952: ({2, 3}, {0, 1, 2}),
    0x47AB0: ({0, 1, 2, 3}, {0, 1}),
    0x47B30: ({0, 1, 2}, {1}),
}


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


def encode_choice(offset: int, text: str, mapping: dict[str, bytes]) -> bytes:
    marker_before, linebreak_after = CHOICE_LAYOUTS[offset]
    parts = text.split("|")
    if max(marker_before | linebreak_after) >= len(parts):
        raise SystemExit(f"choice layout exceeds segment count: 0x{offset:X}")
    payload = bytearray()
    for index, part in enumerate(parts):
        if index in marker_before:
            payload.extend(CHOICE)
        payload.extend(encode(part, mapping))
        if index in linebreak_after:
            payload.extend(LINEBREAK)
    return bytes(payload)


def main() -> None:
    if digest(BASE.read_bytes()) != BASE_HASH:
        raise SystemExit("v0.15 base hash differs")
    manifest = rows(MANIFEST)
    counts = Counter(item["file"] for item in manifest)
    modes = Counter(item["mode"] for item in manifest)
    if len(manifest) != 103 or counts != {
        "1/S1013.DAT": 9,
        "1/S1021.DAT": 50,
        "1/S1022.DAT": 12,
        "1/S1023.DAT": 32,
    } or modes != {"e2": 100, "choice": 3}:
        raise SystemExit(f"unexpected manifest: rows={len(manifest)} files={counts} modes={modes}")

    corpus = rows(CORPUS)
    corpus_keys = {
        (item["file"], item["payload_start"])
        for item in corpus
        if item["file"] in counts and item["confidence"] == "high"
    }
    manifest_keys = {(item["file"], item["offset"]) for item in manifest}
    if corpus_keys != manifest_keys:
        raise SystemExit(f"manifest/corpus mismatch: {sorted(corpus_keys ^ manifest_keys)}")

    with zipfile.ZipFile(BASE) as archive:
        infos = {item.filename: item for item in archive.infolist()}
        files = {name: archive.read(name) for name in infos}
    if len(files) != 39 or set(counts) - files.keys():
        raise SystemExit("unexpected cumulative file set")

    extended = rows(EXTENDED)
    mapping = {item["char"]: bytes.fromhex(item["code_hex"]) for item in extended}
    occupied = set(mapping.values())
    occupied_indices = {glyph_index(code) for code in occupied}
    replaced = {(item["file"], item["offset"]) for item in manifest}
    parsed_codes: set[bytes] = set()
    for item in corpus:
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

    needed = {
        char
        for item in manifest
        for char in item["text"]
        if char not in {" ", "|"}
    }
    missing = sorted(needed - mapping.keys())
    candidates: list[bytes] = []
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
    batch_glyphs = [item for item in extended if item["slot_note"] == BATCH_NOTE] + additions

    base_font = files[FONT_TARGET]
    font = bytearray(base_font)
    for char in sorted(needed):
        write_glyph_plane(font, mapping[char], char)
    if cursor(font) != cursor(base_font):
        raise SystemExit("battle cursor texture regression")
    files[FONT_TARGET] = bytes(font)

    targets = {name: bytearray(files[name]) for name in counts}
    e2_counts = Counter(item["file"] for item in manifest if item["mode"] == "e2")
    free_slots = {
        name: [
            slot
            for slot in range(SLOT_COUNT)
            if not any(data[SLOT_BASE + slot * SLOT_SIZE:SLOT_BASE + (slot + 1) * SLOT_SIZE])
        ]
        for name, data in targets.items()
    }
    for name, count in e2_counts.items():
        if len(free_slots[name]) < count:
            raise SystemExit(f"not enough empty slots in {name}: {len(free_slots[name])} < {count}")

    original_s1023 = ORIGINAL_S1023.read_bytes()
    report_lines = []
    used_slots: dict[str, list[int]] = {name: [] for name in counts}
    for item in manifest:
        name = item["file"]
        data = targets[name]
        offset = int(item["offset"], 0)
        capacity = int(item["capacity"])
        if data[offset + capacity:offset + capacity + 2] != b"\x00\x00":
            raise SystemExit(f"missing dialogue boundary: {name} 0x{offset:X}")

        if item["mode"] == "choice":
            original = original_s1023[offset:offset + capacity]
            markers = len(CHOICE_LAYOUTS[offset][0])
            breaks = len(CHOICE_LAYOUTS[offset][1])
            if original.count(CHOICE) != markers or original.count(LINEBREAK) != breaks:
                raise SystemExit(f"original choice controls differ: 0x{offset:X}")
            payload = encode_choice(offset, item["text"], mapping)
            if len(payload) > capacity:
                raise SystemExit(f"choice overflow: 0x{offset:X} {len(payload)}/{capacity}")
            data[offset:offset + capacity] = payload + bytes((FILLER,)) * (capacity - len(payload))
            if data[offset:offset + capacity].count(CHOICE) != markers:
                raise SystemExit(f"choice marker regression: 0x{offset:X}")
            report_lines.append(
                f"{name} 0x{offset:X} mode=choice markers={markers} "
                f"bytes={len(payload)}/{capacity} text={item['text']}"
            )
            continue

        payload = encode(item["text"], mapping)
        if len(payload) > SLOT_SIZE - 1:
            raise SystemExit(f"E2 overflow: {name} 0x{offset:X} {len(payload)}/{SLOT_SIZE - 1}")
        slot = free_slots[name].pop(0)
        used_slots[name].append(slot)
        slot_offset = SLOT_BASE + slot * SLOT_SIZE
        data[slot_offset:slot_offset + SLOT_SIZE] = b"\x00" * SLOT_SIZE
        data[slot_offset:slot_offset + len(payload)] = payload
        data[slot_offset + SLOT_SIZE - 1] = capacity - 2
        data[offset:offset + 2] = bytes((0xE2, disk_id(slot)))
        report_lines.append(
            f"{name} 0x{offset:X} mode=e2 slot={slot} command=E2 {disk_id(slot):02X} "
            f"skip={capacity - 2} bytes={len(payload)}/{SLOT_SIZE - 1} text={item['text']}"
        )

    files.update({name: bytes(data) for name, data in targets.items()})
    with zipfile.ZipFile(OUTPUT, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name in sorted(files):
            archive.writestr(infos[name], files[name])

    with zipfile.ZipFile(BASE) as before, zipfile.ZipFile(OUTPUT) as after:
        if len(after.namelist()) != 39 or len(set(after.namelist())) != 39:
            raise SystemExit("output must contain 39 unique files")
        changed = {name for name in before.namelist() if before.read(name) != after.read(name)}
        expected = set(counts) | {FONT_TARGET}
        if changed != expected:
            raise SystemExit(f"unexpected changed files: {sorted(changed ^ expected)}")

    low_map = {}
    with (ROOT / "05_docs/korean_charmap.csv").open(encoding="utf-8-sig", newline="") as handle:
        low_map = {item["char"]: bytes.fromhex(item["code_hex"]) for item in csv.DictReader(handle)}

    def low_encode(text: str) -> bytes:
        out = bytearray()
        for line_number, line in enumerate(text.split("|")):
            if line_number:
                out.extend(LINEBREAK)
            for char in line:
                out.extend(bytes((FILLER,)) if char == " " else low_map[char])
        return bytes(out)

    forbidden = [
        low_encode("아크|마을로 가라"),
        low_encode("아크|마을로 돌아가라"),
        low_encode("아크|가라"),
    ]
    for name in counts:
        body = files[name][0x47800:0x50000]
        if any(pattern in body for pattern in forbidden):
            raise SystemExit(f"old structural probe remains in {name}")

    if additions:
        with EXTENDED.open("a", encoding="utf-8", newline="") as handle:
            csv.DictWriter(handle, fieldnames=["char", "code_hex", "slot_note"]).writerows(additions)

    report = "\n".join(report_lines) + "\n"
    report += f"dialogues={len(manifest)}\ne2={modes['e2']}\nchoices={modes['choice']}\n"
    report += f"files={len(counts)}\nnew_glyphs={len(batch_glyphs)}\n"
    report += "old_structural_probes=0\nchoice_markers_preserved=true\n"
    report += "battle_cursor_preserved=true\nother_files_preserved=true\n"
    report += f"sha256={digest(OUTPUT.read_bytes())}\n"
    REPORT.write_text(report, encoding="utf-8")
    print(f"dialogues={len(manifest)} e2={modes['e2']} choices={modes['choice']}")
    print(f"new_glyphs={len(batch_glyphs)}")
    print(f"sha256={digest(OUTPUT.read_bytes())}")
    print(OUTPUT)


if __name__ == "__main__":
    main()
