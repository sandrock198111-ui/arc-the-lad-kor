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
    FONT_TARGET,
    SLOT_BASE,
    SLOT_COUNT,
    SLOT_SIZE,
    cursor,
    cursor_code,
    disk_id,
    glyph_index,
    write_glyph_plane,
)
from build_story_all_choices_v21 import encode, original_dynamic_e2  # noqa: E402


BASE = ROOT / "03_output/story_all_choices_v21_cumulative_patch_only.zip"
BASE_HASH = "A050991D8D4400081689A6F72F730E2221AE328DF74D7D971B9CC5EAFA1D4C4E"
CHOICES = ROOT / "05_docs/story_all_choices_v21_translation.csv"
DIALOGUES = ROOT / "05_docs/story_v22_dialogue_translation.csv"
OVERRIDES = ROOT / "05_docs/story_v22_fixed_choice_overrides.csv"
CHARMAP = ROOT / "05_docs/korean_charmap_extended.csv"
CORPUS = ROOT / "01_work/analysis/story_corpus/story_corpus.csv"
OUTPUT = ROOT / "03_output/story_dialogue_choice_structure_v22_cumulative_patch_only.zip"
REPORT = ROOT / "01_work/analysis/story_dialogue_choice_structure_v22_report.txt"
AUDIT = ROOT / "01_work/analysis/story_dialogue_choice_structure_v22_audit.csv"

FILLER = 0x9C
BATCH_NOTE = "dialogue and choice structure v0.22"
NO_EXTERNAL_BANK = {"6/S6054.DAT", "C2/SC0B6.DAT"}


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def rows(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def marker_positions(body: bytes) -> list[int]:
    return [position for position, _ in control_positions(body, 0xE5)]


def control_positions(body: bytes, command: int) -> list[tuple[int, int]]:
    found: list[tuple[int, int]] = []
    index = 0
    while index + 1 < len(body):
        if 0xDD <= body[index] <= 0xE0:
            index += 2
            continue
        if body[index] == command:
            found.append((index, body[index + 1]))
            index += 2
            continue
        index += 1
    return found


def slot_from_disk_id(value: int) -> int:
    if 0x81 <= value <= 0xA8:
        return value - 0x81
    if 0xAA <= value <= 0xD0:
        return value - 0x82
    raise ValueError(f"not a custom E2 disk ID: 0x{value:02X}")


def main() -> None:
    if digest(BASE.read_bytes()) != BASE_HASH:
        raise SystemExit("v0.21 base hash differs")

    choice_rows = rows(CHOICES)
    dialogue_rows = rows(DIALOGUES)
    override_rows = rows(OVERRIDES)
    if len(choice_rows) != 265 or len(dialogue_rows) != 2 or len(override_rows) != 15:
        raise SystemExit("unexpected v0.22 manifest scope")

    corpus = rows(CORPUS)
    high_choices = {
        (item["file"], item["payload_start"]): item
        for item in corpus
        if item["confidence"] == "high" and "<CTRL:E5>" in item["decoded_jp"]
    }
    medium_e5 = [
        item
        for item in corpus
        if item["confidence"] == "medium" and "<CTRL:E5>" in item["decoded_jp"]
    ]
    if len(high_choices) != 265 or len(medium_e5) != 93:
        raise SystemExit("whole E5 corpus count differs")

    with zipfile.ZipFile(BASE) as archive:
        infos = {info.filename: info for info in archive.infolist()}
        files = {name: archive.read(name) for name in infos}
    base_files = dict(files)

    target_names = {item["file"] for item in dialogue_rows}
    target_names.update(item["file"] for item in choice_rows)
    for name in target_names:
        if name not in files:
            files[name] = (ROOT / "01_work" / name).read_bytes()

    extended = rows(CHARMAP)
    mapping = {item["char"]: bytes.fromhex(item["code_hex"]) for item in extended}
    override_map = {
        (item["file"], item["offset"], int(item["option_index"])): item["text"]
        for item in override_rows
    }
    needed = {
        char
        for item in dialogue_rows
        for char in item["text"]
        if char != " " and not (char.isascii() and char.isdigit())
    }
    needed.update(
        char
        for text in override_map.values()
        for char in text
        if char != " " and not (char.isascii() and char.isdigit())
    )
    missing = sorted(needed - mapping.keys())
    occupied = set(mapping.values())
    occupied_indices = {glyph_index(code) for code in occupied}
    parsed_codes: set[bytes] = set()
    for item in corpus:
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

    additions: list[dict[str, str]] = []
    for char, code in zip(missing, candidates):
        mapping[char] = code
        additions.append({"char": char, "code_hex": code.hex().upper(), "slot_note": BATCH_NOTE})

    font_before = files[FONT_TARGET]
    font = bytearray(font_before)
    for item in additions:
        write_glyph_plane(font, bytes.fromhex(item["code_hex"]), item["char"])
    if cursor(font) != cursor(font_before):
        raise SystemExit("battle cursor texture regression")
    files[FONT_TARGET] = bytes(font)

    free_slots: dict[str, list[int]] = {}
    for name in target_names:
        data = files[name]
        if len(data) < SLOT_BASE + SLOT_COUNT * SLOT_SIZE:
            continue
        free_slots[name] = [
            slot
            for slot in range(SLOT_COUNT)
            if not any(data[SLOT_BASE + slot * SLOT_SIZE:SLOT_BASE + (slot + 1) * SLOT_SIZE])
        ]

    allocations: list[dict[str, object]] = []

    def allocate(name: str, data: bytearray, text: str, skip: int, kind: str, key: str) -> bytes:
        payload = encode(text, mapping)
        if len(payload) > SLOT_SIZE - 2:
            raise SystemExit(f"E2 text overflow: {name} {key} {len(payload)}/{SLOT_SIZE - 2}")
        if name in NO_EXTERNAL_BANK or not free_slots.get(name):
            raise SystemExit(f"no verified E2 slot: {name} {key}")
        slot = free_slots[name].pop(0)
        slot_offset = SLOT_BASE + slot * SLOT_SIZE
        data[slot_offset:slot_offset + SLOT_SIZE] = b"\x00" * SLOT_SIZE
        data[slot_offset:slot_offset + len(payload)] = payload
        data[slot_offset + SLOT_SIZE - 1] = skip
        command = bytes((0xE2, disk_id(slot)))
        allocations.append(
            {
                "file": name,
                "key": key,
                "kind": kind,
                "slot": slot,
                "command": command.hex(" ").upper(),
                "skip": skip,
                "bytes": len(payload),
                "text": text,
            }
        )
        return command

    # Restore original E5/E6 geometry for every v0.21 body whose marker offsets moved.
    repaired_choices = 0
    external_prompts = 0
    external_options = 0
    inline_options = 0
    audit_rows: list[dict[str, object]] = []
    for item in choice_rows:
        name = item["file"]
        offset = int(item["offset"], 0)
        capacity = int(item["capacity"])
        original_file = (ROOT / "01_work" / name).read_bytes()
        original = original_file[offset:offset + capacity]
        current = files[name][offset:offset + capacity]
        original_markers = marker_positions(original)
        current_markers = marker_positions(current)
        should_repair = item["mode"] != "preserve_current" and (
            original_markers != current_markers
            or control_positions(original, 0xE6) != control_positions(current, 0xE6)
        )
        if not should_repair:
            audit_rows.append(
                {
                    "file": name,
                    "offset": item["offset"],
                    "action": "preserved",
                    "original_markers": "|".join(map(str, original_markers)),
                    "result_markers": "|".join(map(str, current_markers)),
                    "original_e6": "|".join(str(pos) for pos, _ in control_positions(original, 0xE6)),
                    "result_e6": "|".join(str(pos) for pos, _ in control_positions(current, 0xE6)),
                }
            )
            continue

        parts = item["text"].split("|")
        prompt, options = parts[0], parts[1:]
        if len(options) != len(original_markers):
            raise SystemExit(f"choice option count differs: {name} 0x{offset:X}")
        data = bytearray(files[name])
        body = bytearray(original)

        if prompt:
            if int(item["dynamic_e2"]):
                first_marker = original_markers[0]
                prompt_region = original[:first_marker]
                linebreak = prompt_region.find(b"\xE6\x01")
                available = linebreak if linebreak >= 0 else len(prompt_region)
                payload = original_dynamic_e2(prompt_region) + encode(prompt, mapping)
                if len(payload) > available:
                    raise SystemExit(
                        f"dynamic prompt overflow: {name} 0x{offset:X} "
                        f"{len(payload)}/{available}"
                    )
                body[0:available] = payload + bytes((FILLER,)) * (available - len(payload))
            else:
                first_marker = original_markers[0]
                if first_marker < 2:
                    raise SystemExit(f"prompt has no inline command space: {name} 0x{offset:X}")
                command = allocate(
                    name,
                    data,
                    prompt,
                    first_marker - 2,
                    "prompt",
                    f"0x{offset:X}",
                )
                body[0:2] = command
                external_prompts += 1

        for option_index, (marker, text) in enumerate(zip(original_markers, options), start=1):
            text = override_map.get((name, item["offset"], option_index), text)
            segment_end = (
                original_markers[option_index]
                if option_index < len(original_markers)
                else len(original)
            )
            segment_start = marker + 2
            segment = original[segment_start:segment_end]
            linebreak = segment.find(b"\xE6\x01")
            available = linebreak if linebreak >= 0 else len(segment)
            payload = encode(text, mapping)
            if len(payload) <= available:
                body[segment_start:segment_start + available] = payload + bytes((FILLER,)) * (
                    available - len(payload)
                )
                inline_options += 1
            else:
                if available < 2:
                    raise SystemExit(
                        f"option has no E2 command space: {name} 0x{offset:X} option={option_index}"
                    )
                command = allocate(
                    name,
                    data,
                    text,
                    available - 2,
                    "option",
                    f"0x{offset:X}:{option_index}",
                )
                body[segment_start:segment_start + 2] = command
                external_options += 1

        data[offset:offset + capacity] = body
        if control_positions(body, 0xE5) != control_positions(original, 0xE5):
            raise SystemExit(f"E5 geometry regression: {name} 0x{offset:X}")
        if control_positions(body, 0xE6) != control_positions(original, 0xE6):
            raise SystemExit(f"E6 geometry regression: {name} 0x{offset:X}")
        files[name] = bytes(data)
        repaired_choices += 1
        audit_rows.append(
            {
                "file": name,
                "offset": item["offset"],
                "action": "geometry_repaired",
                "original_markers": "|".join(map(str, original_markers)),
                "result_markers": "|".join(map(str, marker_positions(body))),
                "original_e6": "|".join(str(pos) for pos, _ in control_positions(original, 0xE6)),
                "result_e6": "|".join(str(pos) for pos, _ in control_positions(body, 0xE6)),
            }
        )

    # Patch the two ordinary dialogues identified from live RAM and slot 1.
    for item in dialogue_rows:
        name = item["file"]
        offset = int(item["offset"], 0)
        capacity = int(item["capacity"])
        original = (ROOT / "01_work" / name).read_bytes()
        data = bytearray(files[name])
        if original[offset + capacity:offset + capacity + 2] != b"\x00\x00":
            raise SystemExit(f"ordinary dialogue boundary differs: {name} 0x{offset:X}")
        current_body = bytes(data[offset:offset + capacity])
        original_body = original[offset:offset + capacity]
        if current_body != original_body and (name, offset) != ("31/S3011.DAT", 0x47FEE):
            raise SystemExit(f"ordinary dialogue target was already modified: {name} 0x{offset:X}")
        if (name, offset) == ("31/S3011.DAT", 0x47FEE) and current_body == original_body:
            raise SystemExit("S3011 expected the verified v0.21 inline Korean body")
        command = allocate(name, data, item["text"], capacity - 2, "dialogue", f"0x{offset:X}")
        data[offset:offset + 2] = command
        files[name] = bytes(data)

    # Whole-choice verification includes all 265 real bodies and records the 93 medium false positives.
    marker_mismatches = 0
    e6_mismatches = 0
    e6_mismatch_keys: list[str] = []
    accepted_legacy_marker_layouts = 0
    accepted_legacy_e6_layouts = 0
    for item in choice_rows:
        name = item["file"]
        offset = int(item["offset"], 0)
        capacity = int(item["capacity"])
        original = (ROOT / "01_work" / name).read_bytes()[offset:offset + capacity]
        result = files[name][offset:offset + capacity]
        marker_differs = control_positions(result, 0xE5) != control_positions(original, 0xE5)
        e6_differs = control_positions(result, 0xE6) != control_positions(original, 0xE6)
        if item["mode"] == "preserve_current":
            accepted_legacy_marker_layouts += int(marker_differs)
            accepted_legacy_e6_layouts += int(e6_differs)
        else:
            marker_mismatches += int(marker_differs)
            e6_mismatches += int(e6_differs)
            if e6_differs:
                e6_mismatch_keys.append(
                    f"{name}:{item['offset']} "
                    f"orig={control_positions(original, 0xE6)} "
                    f"result={control_positions(result, 0xE6)}"
                )
    if marker_mismatches or e6_mismatches:
        raise SystemExit(
            f"whole-choice geometry differs: E5={marker_mismatches} E6={e6_mismatches} "
            f"keys={e6_mismatch_keys}"
        )

    sorted_names = sorted(files)
    with zipfile.ZipFile(OUTPUT, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name in sorted_names:
            if name in infos:
                archive.writestr(infos[name], files[name])
            else:
                info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = 0o600 << 16
                archive.writestr(info, files[name])

    with zipfile.ZipFile(OUTPUT) as archive:
        if archive.namelist() != sorted_names or len(sorted_names) != len(set(sorted_names)):
            raise SystemExit("output ZIP names/order differ")
        for name in sorted_names:
            if archive.read(name) != files[name]:
                raise SystemExit(f"ZIP readback differs: {name}")

    if additions:
        with CHARMAP.open("a", encoding="utf-8", newline="") as handle:
            csv.DictWriter(handle, fieldnames=["char", "code_hex", "slot_note"]).writerows(additions)

    AUDIT.parent.mkdir(parents=True, exist_ok=True)
    with AUDIT.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "file", "offset", "action", "original_markers", "result_markers",
                "original_e6", "result_e6",
            ],
        )
        writer.writeheader()
        writer.writerows(audit_rows)

    changed_names = sorted(name for name in files if files[name] != base_files.get(name))
    report = [
        "Story dialogue and choice structure v0.22",
        f"base_sha256={BASE_HASH}",
        "e5_candidates_total=358",
        "real_high_confidence_choices=265",
        "medium_binary_false_positives=93",
        f"choice_geometry_repaired={repaired_choices}",
        f"choice_geometry_preserved={265 - repaired_choices}",
        f"external_prompts={external_prompts}",
        f"external_options={external_options}",
        f"inline_options={inline_options}",
        "ordinary_dialogues_added=2",
        f"external_allocations={len(allocations)}",
        f"new_glyphs={len(additions)}",
        "original_e5_positions_preserved_for_v22_rewrites=true",
        "original_e6_positions_preserved_for_v22_rewrites=true",
        f"accepted_legacy_marker_layouts={accepted_legacy_marker_layouts}",
        f"accepted_legacy_e6_layouts={accepted_legacy_e6_layouts}",
        "battle_cursor_preserved=true",
        f"changed_files={','.join(changed_names)}",
        f"zip_entries={len(sorted_names)}",
        f"sha256={digest(OUTPUT.read_bytes())}",
        "",
        "Allocations:",
    ]
    report.extend(
        f"{item['file']} {item['key']} {item['kind']} slot={item['slot']} "
        f"command={item['command']} skip={item['skip']} bytes={item['bytes']} text={item['text']}"
        for item in allocations
    )
    REPORT.write_text("\n".join(report) + "\n", encoding="utf-8")
    print(f"choices_repaired={repaired_choices} allocations={len(allocations)}")
    print(f"new_glyphs={len(additions)} zip_entries={len(sorted_names)}")
    print(f"sha256={digest(OUTPUT.read_bytes())}")
    print(OUTPUT)


if __name__ == "__main__":
    main()
