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


BASE = ROOT / "03_output/story_intro_complete_e2_v16_cumulative_patch_only.zip"
BASE_HASH = "61D58B4640BC03C581AEF9785EA95B87BA183568835FB2D4F62A695F3A23F762"
MANIFEST = ROOT / "05_docs/story_verified_returns_e2_translation.csv"
EXTENDED = ROOT / "05_docs/korean_charmap_extended.csv"
CORPUS = ROOT / "01_work/analysis/story_corpus/story_corpus.csv"
OUTPUT = ROOT / "03_output/story_verified_returns_e2_v17_cumulative_patch_only.zip"
REPORT = ROOT / "01_work/analysis/story_verified_returns_e2_v17_report.txt"

SLOT_BASE = 0x45000
SLOT_SIZE = 0x80
SLOT_COUNT = 79
FILLER = 0x9C
BATCH_NOTE = "verified short and return scenes v0.17"
RESTORE_FILES = {"1/S1051.DAT", "D/SD031.DAT"}
PRESERVE_FILES = {"22/S2053.DAT", "F/SF0B1.DAT"}
SHORT_RESTORE = ("23/S2061.DAT", 0x485DC)
STANDARD_FILES = {"F/SF0D1.DAT", "F/SF091.DAT", "23/S2081.DAT", "23/S2082.DAT"}

EXPECTED_COUNTS = {
    "1/S1031.DAT": 1,
    "D/SD011.DAT": 3,
    "23/S2061.DAT": 1,
    "F/SF0D1.DAT": 3,
    "F/SF091.DAT": 11,
    "23/S2081.DAT": 7,
    "23/S2082.DAT": 9,
}
EXCEPTION_KEYS = {
    ("1/S1031.DAT", "0x4787A"),
    ("D/SD011.DAT", "0x47B60"),
    ("D/SD011.DAT", "0x47D58"),
    ("D/SD011.DAT", "0x47D78"),
    ("23/S2061.DAT", "0x485DC"),
}


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def read_rows(path: Path) -> list[dict[str, str]]:
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


def structural_blocks(data: bytes) -> list[tuple[int, int]]:
    blocks: list[tuple[int, int]] = []
    for marker in range(0x45000, len(data) - 4):
        if data[marker:marker + 2] not in (b"\x17\x00", b"\x19\x00"):
            continue
        header = marker - 6
        if data[header:header + 2] != b"\x29\x00" or data[header + 4:header + 6] != b"\x7F\x00":
            continue
        start = marker + 2
        if data[start:start + 2] in (b"\x00\x00", b"\x01\x00", b"\x03\x00", b"\x04\x00"):
            start += 2
        end = data.find(b"\x00\x00", start, min(len(data), start + 0x100))
        if end > start:
            blocks.append((start, end))
    return blocks


def active_auto_probes(files: dict[str, bytes]) -> list[str]:
    found: list[str] = []
    patterns = (b"\x98\xA0\xE6\x01\x90\x8C", b"\x98\xA0\x3C", b"\x98\xA0", b"\x90")
    for name, current in files.items():
        if not name.upper().endswith(".DAT"):
            continue
        original_path = ROOT / "01_work" / name
        if not original_path.exists():
            continue
        original = original_path.read_bytes()
        for start, end in structural_blocks(original):
            if current[start:start + 1] == b"\xE2" or current[start:end] == original[start:end]:
                continue
            for pattern in patterns:
                if current[start:start + len(pattern)] == pattern:
                    found.append(f"{name}:0x{start:X}:{pattern.hex().upper()}")
                    break
    return found


def main() -> None:
    if digest(BASE.read_bytes()) != BASE_HASH:
        raise SystemExit("v0.16 base hash differs")

    manifest = read_rows(MANIFEST)
    counts = Counter(item["file"] for item in manifest)
    scenes = Counter(item["scene"] for item in manifest)
    if len(manifest) != 35 or counts != EXPECTED_COUNTS:
        raise SystemExit(f"unexpected manifest: rows={len(manifest)} files={counts}")
    if scenes != {
        "house_return": 4,
        "reed_short": 1,
        "reed_aftermath": 3,
        "cave_event": 11,
        "post_battle_cutscene": 16,
    }:
        raise SystemExit(f"unexpected scene counts: {scenes}")

    corpus = read_rows(CORPUS)
    standard_keys = {
        (item["file"], item["payload_start"])
        for item in corpus
        if item["file"] in STANDARD_FILES and item["confidence"] == "high"
    }
    manifest_keys = {(item["file"], item["offset"]) for item in manifest}
    if standard_keys != manifest_keys - EXCEPTION_KEYS:
        raise SystemExit(f"manifest/corpus mismatch: {sorted(standard_keys ^ (manifest_keys - EXCEPTION_KEYS))}")

    with zipfile.ZipFile(BASE) as archive:
        infos = {item.filename: item for item in archive.infolist()}
        files = {name: archive.read(name) for name in infos}
    required = set(counts) | RESTORE_FILES | PRESERVE_FILES
    if len(files) != 39 or required - files.keys():
        raise SystemExit("unexpected cumulative file set")

    preserved = {name: files[name] for name in PRESERVE_FILES}
    for name in RESTORE_FILES:
        files[name] = (ROOT / "01_work" / name).read_bytes()

    extended = read_rows(EXTENDED)
    mapping = {item["char"]: bytes.fromhex(item["code_hex"]) for item in extended}
    occupied = set(mapping.values())
    occupied_indices = {glyph_index(code) for code in occupied}
    replaced = manifest_keys
    parsed_codes: set[bytes] = set()
    for item in corpus:
        key = (item["file"], item["payload_start"])
        if key in replaced:
            continue
        source = ROOT / "01_work" / item["file"]
        if not source.exists():
            continue
        data = source.read_bytes()
        offset = int(item["payload_start"], 0)
        capacity = int(item["capacity"])
        body = data[offset:offset + capacity]
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
        if (item["file"], int(item["offset"], 0)) != SHORT_RESTORE
        for char in item["text"]
        if char != " "
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
    free_slots = {
        name: [
            slot
            for slot in range(SLOT_COUNT)
            if not any(data[SLOT_BASE + slot * SLOT_SIZE:SLOT_BASE + (slot + 1) * SLOT_SIZE])
        ]
        for name, data in targets.items()
    }
    needed_slots = Counter(item["file"] for item in manifest if (item["file"], int(item["offset"], 0)) != SHORT_RESTORE)
    for name, count in needed_slots.items():
        if len(free_slots[name]) < count:
            raise SystemExit(f"not enough empty slots in {name}: {len(free_slots[name])} < {count}")

    report_lines: list[str] = []
    used_slots: dict[str, list[int]] = {name: [] for name in counts}
    for item in manifest:
        name = item["file"]
        data = targets[name]
        original = (ROOT / "01_work" / name).read_bytes()
        offset = int(item["offset"], 0)
        capacity = int(item["capacity"])
        if original[offset + capacity:offset + capacity + 2] != b"\x00\x00":
            raise SystemExit(f"original dialogue boundary differs: {name} 0x{offset:X}")
        if data[offset + capacity:offset + capacity + 2] != b"\x00\x00":
            raise SystemExit(f"current dialogue boundary differs: {name} 0x{offset:X}")

        if (name, offset) == SHORT_RESTORE:
            if capacity != 1 or original[offset:offset + 1] != b"\x02":
                raise SystemExit("S2061 one-byte exclamation source differs")
            data[offset] = original[offset]
            report_lines.append(f"{name} 0x{offset:X} mode=restore bytes=02 text=!")
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
            f"{name} 0x{offset:X} scene={item['scene']} mode=e2 slot={slot} "
            f"command=E2 {disk_id(slot):02X} skip={capacity - 2} "
            f"bytes={len(payload)}/{SLOT_SIZE - 1} text={item['text']}"
        )

    files.update({name: bytes(data) for name, data in targets.items()})
    for name, before in preserved.items():
        if files[name] != before:
            raise SystemExit(f"verified return scene rolled back: {name}")

    probes = active_auto_probes(files)
    if probes:
        raise SystemExit("active structural probes remain:\n" + "\n".join(probes))

    with zipfile.ZipFile(OUTPUT, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name in sorted(files):
            archive.writestr(infos[name], files[name])

    with zipfile.ZipFile(BASE) as before, zipfile.ZipFile(OUTPUT) as after:
        names = after.namelist()
        if len(names) != 39 or len(set(names)) != 39:
            raise SystemExit("output must contain 39 unique files")
        changed = {name for name in before.namelist() if before.read(name) != after.read(name)}
        expected = set(counts) | RESTORE_FILES | {FONT_TARGET}
        if changed != expected:
            raise SystemExit(f"unexpected changed files: {sorted(changed ^ expected)}")
        for name in PRESERVE_FILES:
            if before.read(name) != after.read(name):
                raise SystemExit(f"preserved scene changed in output: {name}")

    if additions:
        with EXTENDED.open("a", encoding="utf-8", newline="") as handle:
            csv.DictWriter(handle, fieldnames=["char", "code_hex", "slot_note"]).writerows(additions)

    report = "\n".join(report_lines) + "\n"
    report += f"dialogues={len(manifest)}\ne2={len(manifest) - 1}\nshort_restore=1\n"
    report += f"new_glyphs={len(batch_glyphs)}\nrestored_files={','.join(sorted(RESTORE_FILES))}\n"
    report += "active_structural_probes=0\npost_cave_sf0b1_preserved=true\n"
    report += "pre_cave_s2053_preserved=true\nbattle_cursor_preserved=true\n"
    report += "other_files_preserved=true\n"
    report += f"sha256={digest(OUTPUT.read_bytes())}\n"
    REPORT.write_text(report, encoding="utf-8")
    print(f"dialogues={len(manifest)} e2={len(manifest) - 1} short_restore=1")
    print(f"new_glyphs={len(batch_glyphs)}")
    print(f"sha256={digest(OUTPUT.read_bytes())}")
    print(OUTPUT)


if __name__ == "__main__":
    main()
