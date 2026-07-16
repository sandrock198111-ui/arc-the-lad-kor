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

from build_story_legacy_tone_e2_v18 import (  # noqa: E402
    FILLER,
    FONT_TARGET,
    SLOT_BASE,
    SLOT_COUNT,
    SLOT_SIZE,
    cursor,
    cursor_code,
    digest,
    disk_id,
    encode,
    glyph_index,
    rows,
    write_glyph_plane,
)


BASE = ROOT / "03_output/story_legacy_tone_e2_v18_cumulative_patch_only.zip"
BASE_HASH = "3263B9269EA7582E7F4C165D46B7EFB63FD112808250686BAAFCD8DBF1C06588"
MANIFEST = ROOT / "05_docs/story_minister_s3022_s3031_e2_v19_translation.csv"
EXTENDED = ROOT / "05_docs/korean_charmap_extended.csv"
CORPUS = ROOT / "01_work/analysis/story_corpus/story_corpus.csv"
OUTPUT = ROOT / "03_output/story_minister_s3022_s3031_e2_v19_cumulative_patch_only.zip"
REPORT = ROOT / "01_work/analysis/story_minister_s3022_s3031_e2_v19_report.txt"
BATCH_NOTE = "minister labels and S2012 S3022 S3031 E2 v0.19"
REBUILD_FILES = {"31/S3022.DAT", "31/S3031.DAT"}
S3022_CHOICE = (0x48822, 33)


def slot_from_disk_id(value: int) -> int:
    if 0x81 <= value <= 0xA8:
        return value - 0x81
    if 0xAA <= value <= 0xD0:
        return value - 0x82
    raise ValueError(f"not a custom E2 disk ID: 0x{value:02X}")


def main() -> None:
    if digest(BASE.read_bytes()) != BASE_HASH:
        raise SystemExit("v0.18 base hash differs")

    manifest = rows(MANIFEST)
    counts = Counter(item["file"] for item in manifest)
    modes = Counter(item["mode"] for item in manifest)
    if len(manifest) != 82 or counts != {
        "22/S2051.DAT": 9,
        "22/S2052.DAT": 7,
        "22/S2053.DAT": 2,
        "21/S2012.DAT": 2,
        "31/S3022.DAT": 35,
        "31/S3031.DAT": 27,
    } or modes != {"replace_e2": 18, "new_e2": 2, "rebuild_e2": 62}:
        raise SystemExit(f"unexpected manifest: rows={len(manifest)} files={counts} modes={modes}")

    corpus = rows(CORPUS)
    corpus_by_key = {(item["file"], item["payload_start"]): item for item in corpus}
    for item in manifest:
        key = (item["file"], item["offset"])
        source = corpus_by_key.get(key)
        if source is None or source["confidence"] != "high":
            raise SystemExit(f"manifest row is not high-confidence corpus: {key}")
        if int(source["capacity"]) != int(item["capacity"]):
            raise SystemExit(f"capacity mismatch: {key}")

    with zipfile.ZipFile(BASE) as archive:
        infos = {item.filename: item for item in archive.infolist()}
        files = {name: archive.read(name) for name in infos}
    if len(files) != 40:
        raise SystemExit("unexpected v0.18 file count")
    for name in counts:
        if name not in files:
            files[name] = (ROOT / "01_work" / name).read_bytes()

    extended = rows(EXTENDED)
    mapping = {item["char"]: bytes.fromhex(item["code_hex"]) for item in extended}
    occupied = set(mapping.values())
    occupied_indices = {glyph_index(code) for code in occupied}
    replaced = {(item["file"], item["offset"]) for item in manifest}
    parsed_codes: set[bytes] = set()
    for item in corpus:
        if (item["file"], item["payload_start"]) in replaced:
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

    needed = {char for item in manifest for char in item["text"] if char != " "}
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
    for name in REBUILD_FILES:
        targets[name] = bytearray((ROOT / "01_work" / name).read_bytes())

    # S3022 contains an interactive choice. Keep its already verified command
    # layout while rebuilding every ordinary dialogue from clean original data.
    choice_offset, choice_capacity = S3022_CHOICE
    targets["31/S3022.DAT"][choice_offset:choice_offset + choice_capacity] = (
        files["31/S3022.DAT"][choice_offset:choice_offset + choice_capacity]
    )

    new_counts = Counter(
        item["file"] for item in manifest if item["mode"] in {"new_e2", "rebuild_e2"}
    )
    free_slots = {
        name: [
            slot
            for slot in range(SLOT_COUNT)
            if not any(data[SLOT_BASE + slot * SLOT_SIZE:SLOT_BASE + (slot + 1) * SLOT_SIZE])
        ]
        for name, data in targets.items()
    }
    for name, count in new_counts.items():
        if len(free_slots[name]) < count:
            raise SystemExit(f"not enough empty slots in {name}: {len(free_slots[name])} < {count}")

    report_lines: list[str] = []
    for item in manifest:
        name = item["file"]
        data = targets[name]
        original = (ROOT / "01_work" / name).read_bytes()
        offset = int(item["offset"], 0)
        capacity = int(item["capacity"])
        payload = encode(item["text"], mapping)
        if len(payload) > SLOT_SIZE - 1:
            raise SystemExit(f"E2 overflow: {name} 0x{offset:X} {len(payload)}/{SLOT_SIZE - 1}")
        if original[offset + capacity:offset + capacity + 2] != b"\x00\x00":
            raise SystemExit(f"original boundary differs: {name} 0x{offset:X}")
        if item["mode"] != "rebuild_e2" and data[offset + capacity:offset + capacity + 2] != b"\x00\x00":
            raise SystemExit(f"current boundary differs: {name} 0x{offset:X}")

        if item["mode"] == "replace_e2":
            if data[offset] != 0xE2:
                raise SystemExit(f"existing E2 command missing: {name} 0x{offset:X}")
            command = bytes(data[offset:offset + 2])
            slot = slot_from_disk_id(data[offset + 1])
            slot_offset = SLOT_BASE + slot * SLOT_SIZE
            metadata = data[slot_offset + SLOT_SIZE - 1]
            if metadata != capacity - 2:
                raise SystemExit(f"existing skip metadata differs: {name} 0x{offset:X}")
        elif item["mode"] == "new_e2":
            if data[offset:offset + capacity] != original[offset:offset + capacity]:
                raise SystemExit(f"new target was already modified: {name} 0x{offset:X}")
            slot = free_slots[name].pop(0)
            slot_offset = SLOT_BASE + slot * SLOT_SIZE
            metadata = capacity - 2
            command = bytes((0xE2, disk_id(slot)))
            data[offset:offset + 2] = command
        else:
            if item["mode"] != "rebuild_e2" or name not in REBUILD_FILES:
                raise SystemExit(f"unexpected mode: {item['mode']}")
            if data[offset:offset + capacity] != original[offset:offset + capacity]:
                raise SystemExit(f"rebuild target is not clean original: {name} 0x{offset:X}")
            slot = free_slots[name].pop(0)
            slot_offset = SLOT_BASE + slot * SLOT_SIZE
            metadata = capacity - 2
            command = bytes((0xE2, disk_id(slot)))
            data[offset:offset + 2] = command

        data[slot_offset:slot_offset + SLOT_SIZE] = b"\x00" * SLOT_SIZE
        data[slot_offset:slot_offset + len(payload)] = payload
        data[slot_offset + SLOT_SIZE - 1] = metadata
        report_lines.append(
            f"{name} 0x{offset:X} mode={item['mode']} slot={slot} command={command.hex(' ').upper()} "
            f"skip={metadata} bytes={len(payload)}/{SLOT_SIZE - 1} text={item['text']}"
        )

    files.update({name: bytes(data) for name, data in targets.items()})
    with zipfile.ZipFile(OUTPUT, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name in sorted(files):
            if name in infos:
                archive.writestr(infos[name], files[name])
            else:
                info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = 0o600 << 16
                archive.writestr(info, files[name])

    with zipfile.ZipFile(BASE) as before, zipfile.ZipFile(OUTPUT) as after:
        if len(after.namelist()) != 41 or len(set(after.namelist())) != 41:
            raise SystemExit("output must contain 41 unique files")
        common_changed = {
            name for name in before.namelist() if before.read(name) != after.read(name)
        }
        expected = set(counts) - {"21/S2012.DAT"}
        if files[FONT_TARGET] != before.read(FONT_TARGET):
            expected.add(FONT_TARGET)
        if common_changed != expected:
            raise SystemExit(f"unexpected common changes: {sorted(common_changed ^ expected)}")
        if "21/S2012.DAT" not in after.namelist():
            raise SystemExit("S2012 missing from output")

        rebuilt_rows = {
            name: [item for item in manifest if item["file"] == name]
            for name in REBUILD_FILES
        }
        for name, items in rebuilt_rows.items():
            original = (ROOT / "01_work" / name).read_bytes()
            result = after.read(name)
            allowed = bytearray(len(result))
            allowed[SLOT_BASE:SLOT_BASE + SLOT_COUNT * SLOT_SIZE] = b"\x01" * (
                SLOT_COUNT * SLOT_SIZE
            )
            for item in items:
                offset = int(item["offset"], 0)
                allowed[offset:offset + 2] = b"\x01\x01"
            if name == "31/S3022.DAT":
                choice_offset, choice_capacity = S3022_CHOICE
                allowed[choice_offset:choice_offset + choice_capacity] = b"\x01" * choice_capacity
                if (
                    result[choice_offset:choice_offset + choice_capacity]
                    != before.read(name)[choice_offset:choice_offset + choice_capacity]
                ):
                    raise SystemExit("S3022 choice bytes changed")
            outside = [
                index
                for index, (old, new) in enumerate(zip(original, result))
                if old != new and not allowed[index]
            ]
            if outside:
                raise SystemExit(
                    f"{name} changed outside E2/slot/choice ranges: "
                    f"0x{outside[0]:X} ({len(outside)} bytes)"
                )

    if additions:
        with EXTENDED.open("a", encoding="utf-8", newline="") as handle:
            csv.DictWriter(handle, fieldnames=["char", "code_hex", "slot_note"]).writerows(additions)

    report = "\n".join(report_lines) + "\n"
    report += f"dialogues={len(manifest)}\nreplace_e2={modes['replace_e2']}\nnew_e2={modes['new_e2']}\n"
    report += f"rebuild_e2={modes['rebuild_e2']}\n"
    report += f"new_glyphs={len(batch_glyphs)}\n"
    report += "minister_speaker_labels_preserved=true\ns2012_complete=true\n"
    report += "s3022_choice_preserved=true\ns3022_s3031_legacy_inline_removed=true\n"
    report += "battle_cursor_preserved=true\nother_files_preserved=true\n"
    report += f"sha256={digest(OUTPUT.read_bytes())}\n"
    REPORT.write_text(report, encoding="utf-8")
    print(
        f"dialogues={len(manifest)} replace={modes['replace_e2']} "
        f"new={modes['new_e2']} rebuild={modes['rebuild_e2']}"
    )
    print(f"new_glyphs={len(batch_glyphs)}")
    print(f"sha256={digest(OUTPUT.read_bytes())}")
    print(OUTPUT)


if __name__ == "__main__":
    main()
