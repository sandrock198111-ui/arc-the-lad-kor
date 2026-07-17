#!/usr/bin/env python3
"""Build v0.31 with system-screen text and battle-choice repairs."""

from __future__ import annotations

import csv
import hashlib
import struct
import sys
from collections import defaultdict
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))

import build_ui_safe_v30 as base  # noqa: E402
from build_story_all_choices_v21 import encode as story_encode  # noqa: E402
from build_story_dialogue_choice_structure_v22 import (  # noqa: E402
    control_positions,
    slot_from_disk_id,
)
from build_story_legacy_tone_e2_v18 import (  # noqa: E402
    SLOT_BASE,
    SLOT_COUNT,
    SLOT_SIZE,
    disk_id,
)
from build_ui_full_v26 import PSX_LOAD_BASE, TABLES  # noqa: E402
from build_ui_safe_v27 import load_mapping  # noqa: E402
from ui_safe_v31_overrides import OVERRIDES  # noqa: E402


OUTPUT = ROOT / "03_output" / "ui_safe_v31_cumulative_patch_only.zip"
MANIFEST = ROOT / "05_docs" / "ui_safe_v31.csv"
SKILL_REFERENCE = ROOT / "05_docs" / "ui_skill_guide_reference_v31.csv"
SYSTEM_MANIFEST = ROOT / "05_docs" / "ui_system_v31.csv"
BATTLE_MANIFEST = ROOT / "05_docs" / "ui_battle_choice_v31.csv"
CHOICES = ROOT / "05_docs" / "story_all_choices_v21_translation.csv"
ANALYSIS = ROOT / "01_work" / "analysis" / "ui_safe_v31"
REPORT = ANALYSIS / "build_report.txt"
READBACK = ANALYSIS / "readback.csv"
LOW_CODE_AUDIT = ANALYSIS / "low_6c_story_audit.csv"
PREVIEW = ANALYSIS / "lv_label_before_after.pbm"
TUTORIAL_AUDIT = ANALYSIS / "tutorial_e2_audit.csv"
SYSTEM_AUDIT = ANALYSIS / "system_text_audit.csv"
BATTLE_AUDIT = ANALYSIS / "battle_choice_audit.csv"


# Every source pointer below was confirmed against the untouched Japanese PSX.EXE.
SYSTEM_TEXTS = (
    (0x780E8, 0x7809C, "처음부터"),
    (0x780EC, 0x780A4, "저장 데이터가 없습니다"),
    (0x780F0, 0x780B0, "메모리 카드에 남은 공간이 없습니다"),
    (0x780F4, 0x780C0, "그대로 계속하기"),
    (0x780F8, 0x780CC, "데이터가 손상되었습니다"),
    (0x781B8, 0x78100, "불러올 데이터를 선택하세요"),
    (0x781BC, 0x78110, "메모리 카드 없이 계속하시겠습니까?"),
    (0x781C0, 0x7812C, "메모리 카드를 넣고 확인 버튼을 누르세요"),
    (0x781C4, 0x7814C, "어느 카드를 사용하시겠습니까?"),
    (0x781C8, 0x7815C, "메모리 카드를 초기화하시겠습니까?"),
    (0x781CC, 0x78174, "메모리 카드가 가득합니다. 계속하시겠습니까?"),
    (0x781D0, 0x78194, "쓰지 않는 데이터를 지우거나 다른 카드를 넣으세요"),
    (0x78220, 0x781D4, "메모리 카드를 확인하고 있습니다"),
    (0x78224, 0x781E8, "메모리 카드를 초기화하고 있습니다"),
    (0x78228, 0x78200, "데이터를 저장하고 있습니다"),
    (0x7822C, 0x78210, "데이터를 불러오고 있습니다"),
    (0x8235C, 0x822AC, "확인: 결정, 뒤로: 돌아가기"),
    (0x82AC0, 0x82A88, "예  아니요"),
    (0x82AC4, 0x82A90, "저장하시겠습니까?"),
    (0x82AC8, 0x82AA0, "전투 전 장비를 정비하시겠습니까?"),
    (0x82ACC, 0x82AB0, "진행하시겠습니까?"),
)

# The first five ranges are superseded Japanese pools. The last range is the
# verified zero suffix left by the v0.31 UI table allocator.
SYSTEM_POOLS = (
    (0x7809C, 0x780DC),
    (0x78100, 0x781B8),
    (0x781D4, 0x78220),
    (0x822AC, 0x822C4),
    (0x82A88, 0x82AC0),
    (0x81F6B, 0x82170),
)

BATTLE_PROMPT = "전투를 시작할까?"
BATTLE_ACCEPT = "싸운다"
BATTLE_DECLINE = "돌아간다"
BATTLE_FILES = (
    "C1/SC011.DAT",
    "C1/SC021.DAT",
    "C1/SC031.DAT",
    "C1/SC041.DAT",
    "C1/SC051.DAT",
    "C1/SC061.DAT",
    "C1/SC081.DAT",
    "C1/SC091.DAT",
    "C2/SC0A1.DAT",
)


def rows(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def write_csv(path: Path, values: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(values[0]))
        writer.writeheader()
        writer.writerows(values)


def raw_string(data: bytes | bytearray, offset: int) -> bytes:
    end = data.find(0, offset)
    if end < 0:
        raise SystemExit(f"unterminated system string at 0x{offset:X}")
    return bytes(data[offset:end])


def patch_system_text(executable: bytearray) -> list[dict[str, object]]:
    mapping = load_mapping()
    original = (ROOT / "01_work" / "PSX.EXE").read_bytes()
    before = bytes(executable)

    for pointer_offset, source_offset, _text in SYSTEM_TEXTS:
        expected = PSX_LOAD_BASE + source_offset
        actual = struct.unpack_from("<I", executable, pointer_offset)[0]
        if actual != expected:
            raise SystemExit(
                f"system source pointer differs at 0x{pointer_offset:X}: "
                f"0x{actual:X} != 0x{expected:X}"
            )
    for start, end in SYSTEM_POOLS[:-1]:
        if executable[start:end] != original[start:end]:
            raise SystemExit(f"system source pool differs: 0x{start:X}-0x{end:X}")
    tail_start, tail_end = SYSTEM_POOLS[-1]
    if any(executable[tail_start:tail_end]):
        raise SystemExit("verified UI zero suffix is no longer empty")

    payloads = {
        text: base.encode(text, mapping)
        for _pointer, _source, text in SYSTEM_TEXTS
    }
    for text, payload in payloads.items():
        if base.missing_chars(text, mapping) or b"\x00" in payload:
            raise SystemExit(f"unsafe system text payload: {text!r}")

    for start, end in SYSTEM_POOLS:
        executable[start:end] = b"\x00" * (end - start)
    cursors = [start for start, _end in SYSTEM_POOLS]
    locations: dict[str, int] = {}
    for text in sorted(payloads, key=lambda value: len(payloads[value]), reverse=True):
        payload = payloads[text]
        required = len(payload) + 1
        candidates = [
            (end - cursor, index)
            for index, ((_, end), cursor) in enumerate(zip(SYSTEM_POOLS, cursors))
            if cursor + required <= end
        ]
        if not candidates:
            remaining = sum(end - cursor for (_, end), cursor in zip(SYSTEM_POOLS, cursors))
            raise SystemExit(f"system string pool overflow: {text!r}; remaining={remaining}")
        _remaining, pool_index = min(candidates)
        location = cursors[pool_index]
        executable[location:location + len(payload)] = payload
        executable[location + len(payload)] = 0
        cursors[pool_index] += required
        locations[text] = location

    audit: list[dict[str, object]] = []
    for pointer_offset, source_offset, text in SYSTEM_TEXTS:
        location = locations[text]
        struct.pack_into("<I", executable, pointer_offset, PSX_LOAD_BASE + location)
        payload = payloads[text]
        if raw_string(executable, location) != payload:
            raise SystemExit(f"system text readback differs: {text!r}")
        audit.append(
            {
                "pointer_offset": f"0x{pointer_offset:X}",
                "source_offset": f"0x{source_offset:X}",
                "new_offset": f"0x{location:X}",
                "encoded_bytes": len(payload),
                "korean": text,
            }
        )

    allowed = bytearray(len(executable))
    for start, end in SYSTEM_POOLS:
        allowed[start:end] = b"\x01" * (end - start)
    for pointer_offset, _source_offset, _text in SYSTEM_TEXTS:
        allowed[pointer_offset:pointer_offset + 4] = b"\x01" * 4
    for offset, (old, new) in enumerate(zip(before, executable)):
        if old != new and not allowed[offset]:
            raise SystemExit(f"system patch changed undeclared PSX byte at 0x{offset:X}")
    return audit


def battle_rows() -> list[dict[str, str]]:
    selected = [
        row
        for row in rows(CHOICES)
        if row["file"] in BATTLE_FILES and "やつっりやめる" in row["source"]
    ]
    if len(selected) != 63:
        raise SystemExit(f"unexpected battle-choice scope: {len(selected)}/63")
    return selected


def write_slot(
    data: bytearray,
    slot: int,
    text: str,
    skip: int,
    mapping: dict[str, bytes],
) -> int:
    payload = story_encode(text, mapping)
    if len(payload) > SLOT_SIZE - 1 or b"\x00" in payload:
        raise SystemExit(f"battle E2 payload overflow: {text!r}")
    offset = SLOT_BASE + slot * SLOT_SIZE
    data[offset:offset + SLOT_SIZE] = b"\x00" * SLOT_SIZE
    data[offset:offset + len(payload)] = payload
    data[offset + SLOT_SIZE - 1] = skip
    return len(payload)


def patch_battle_choices(files: dict[str, bytes]) -> list[dict[str, object]]:
    mapping = load_mapping()
    targets = battle_rows()
    grouped: dict[str, list[dict[str, str]]] = defaultdict(list)
    for item in targets:
        grouped[item["file"]].append(item)

    audit: list[dict[str, object]] = []
    for name in BATTLE_FILES:
        before = files[name]
        data = bytearray(before)
        free = [
            slot
            for slot in range(SLOT_COUNT)
            if not any(data[SLOT_BASE + slot * SLOT_SIZE:SLOT_BASE + (slot + 1) * SLOT_SIZE])
        ]
        if len(free) < 2:
            raise SystemExit(f"not enough shared battle option slots: {name}")
        accept_slot = free.pop(0)
        decline_slot = free.pop(0)
        accept_bytes = write_slot(data, accept_slot, BATTLE_ACCEPT, 0, mapping)
        decline_bytes = write_slot(data, decline_slot, BATTLE_DECLINE, 5, mapping)
        allowed: list[tuple[int, int]] = [
            (SLOT_BASE + accept_slot * SLOT_SIZE, SLOT_BASE + (accept_slot + 1) * SLOT_SIZE),
            (SLOT_BASE + decline_slot * SLOT_SIZE, SLOT_BASE + (decline_slot + 1) * SLOT_SIZE),
        ]

        prompt_slots: set[int] = set()
        for item in grouped[name]:
            offset = int(item["offset"], 0)
            capacity = int(item["capacity"])
            original = (ROOT / "01_work" / name).read_bytes()[offset:offset + capacity]
            body = bytearray(data[offset:offset + capacity])
            e5 = [position for position, _arg in control_positions(original, 0xE5)]
            e6 = [position for position, _arg in control_positions(original, 0xE6)]
            if len(e5) != 2:
                raise SystemExit(f"battle choice E5 geometry differs: {name} {item['offset']}")
            prompt_end = max(position for position in e6 if position < e5[0])
            accept_start = e5[0] + 2
            accept_end = min(position for position in e6 if position > accept_start)
            decline_start = e5[1] + 2
            if accept_end - accept_start != 2 or capacity - decline_start != 7:
                raise SystemExit(f"battle option spans differ: {name} {item['offset']}")
            if body[0] == 0xE2:
                prompt_slot = slot_from_disk_id(body[1])
            else:
                if not free:
                    raise SystemExit(f"no free battle prompt slot: {name} {item['offset']}")
                prompt_slot = free.pop(0)
                body[0:2] = bytes((0xE2, disk_id(prompt_slot)))
                allowed.append((offset, offset + 2))
            if prompt_slot in prompt_slots:
                raise SystemExit(f"shared battle prompt slot: {name} slot={prompt_slot}")
            prompt_slots.add(prompt_slot)
            prompt_bytes = write_slot(data, prompt_slot, BATTLE_PROMPT, prompt_end - 2, mapping)
            allowed.append(
                (SLOT_BASE + prompt_slot * SLOT_SIZE, SLOT_BASE + (prompt_slot + 1) * SLOT_SIZE)
            )

            body[accept_start:accept_start + 2] = bytes((0xE2, disk_id(accept_slot)))
            body[decline_start:decline_start + 2] = bytes((0xE2, disk_id(decline_slot)))
            data[offset:offset + capacity] = body
            allowed.extend(
                (
                    (offset + accept_start, offset + accept_start + 2),
                    (offset + decline_start, offset + decline_start + 2),
                )
            )
            if control_positions(body, 0xE5) != control_positions(original, 0xE5):
                raise SystemExit(f"battle E5 moved: {name} {item['offset']}")
            if control_positions(body, 0xE6) != control_positions(original, 0xE6):
                raise SystemExit(f"battle E6 moved: {name} {item['offset']}")
            audit.append(
                {
                    "file": name,
                    "offset": item["offset"],
                    "capacity": capacity,
                    "prompt_slot": prompt_slot,
                    "accept_slot": accept_slot,
                    "decline_slot": decline_slot,
                    "prompt_bytes": prompt_bytes,
                    "accept_bytes": accept_bytes,
                    "decline_bytes": decline_bytes,
                    "prompt": BATTLE_PROMPT,
                    "accept": BATTLE_ACCEPT,
                    "decline": BATTLE_DECLINE,
                }
            )

        for index, (old, new) in enumerate(zip(before, data)):
            if old == new:
                continue
            if not any(start <= index < end for start, end in allowed):
                raise SystemExit(f"battle patch changed undeclared byte: {name} 0x{index:X}")
        files[name] = bytes(data)
    return audit


def rewrite_report(system_count: int, battle_count: int, changed: list[str]) -> None:
    lines = REPORT.read_text(encoding="utf-8").splitlines()
    rewritten: list[str] = []
    for line in lines:
        if line.startswith("UI safe v0.30"):
            rewritten.append("UI safe v0.31 cumulative system-screen and battle-choice repair")
        elif line.startswith("output_zip_sha256="):
            rewritten.append(
                f"output_zip_sha256={hashlib.sha256(OUTPUT.read_bytes()).hexdigest().upper()}"
            )
        elif line == "balanced_skill_help_rows=12":
            rewritten.append("single_line_skill_help_rows=12")
        else:
            rewritten.append(line)
    rewritten.extend(
        [
            f"v31_system_texts={system_count}",
            f"v31_battle_choice_bodies={battle_count}",
            "v31_battle_choice_prompt=전투를 시작할까?",
            "v31_battle_choice_options=싸운다|돌아간다",
            f"v31_delta_members={','.join(changed)}",
            "memory_card_existing_slot_labels_migrated=false",
        ]
    )
    REPORT.write_text("\n".join(rewritten) + "\n", encoding="utf-8")


def main() -> None:
    base.OUTPUT = OUTPUT
    base.MANIFEST = MANIFEST
    base.SKILL_REFERENCE = SKILL_REFERENCE
    base.ANALYSIS = ANALYSIS
    base.REPORT = REPORT
    base.READBACK = READBACK
    base.LOW_CODE_AUDIT = LOW_CODE_AUDIT
    base.PREVIEW = PREVIEW
    base.TUTORIAL_AUDIT = TUTORIAL_AUDIT
    base.OVERRIDES = OVERRIDES
    base.main()

    with ZipFile(OUTPUT) as archive:
        infos = archive.infolist()
        files = {info.filename: archive.read(info.filename) for info in infos}
    before_files = dict(files)

    executable = bytearray(files["PSX.EXE"])
    system_audit = patch_system_text(executable)
    files["PSX.EXE"] = bytes(executable)
    battle_audit = patch_battle_choices(files)

    temporary = OUTPUT.with_suffix(".tmp.zip")
    with ZipFile(temporary, "w", ZIP_DEFLATED, compresslevel=9) as archive:
        for info in infos:
            archive.writestr(info, files[info.filename])
    temporary.replace(OUTPUT)
    with ZipFile(OUTPUT) as archive:
        if any(archive.read(name) != payload for name, payload in files.items()):
            raise SystemExit("v0.31 ZIP readback differs")

    changed = [name for name in files if files[name] != before_files[name]]
    expected = ["PSX.EXE", *BATTLE_FILES]
    if changed != [name for name in files if name in expected]:
        raise SystemExit(f"unexpected v0.31 delta members: {changed}")

    write_csv(SYSTEM_MANIFEST, system_audit)
    write_csv(SYSTEM_AUDIT, system_audit)
    write_csv(BATTLE_MANIFEST, battle_audit)
    write_csv(BATTLE_AUDIT, battle_audit)
    rewrite_report(len(system_audit), len(battle_audit), changed)
    print(REPORT.read_text(encoding="utf-8"), end="")


if __name__ == "__main__":
    main()
