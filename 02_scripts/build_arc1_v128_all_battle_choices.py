#!/usr/bin/env python3
"""Build v128: apply the runtime-accepted battle confirmation repair to all 63 entries.

Base: v127 slot 1-7 repair.
Scope: eight additional battle DATs. C1/SC051.DAT is verified but left byte-identical,
because the user already runtime-tested its v127 repair.

The script restores each choice body's original E5/E6 geometry from arc.zip, then
replaces only the prompt and two option spans with E2 references. It writes:
  전투를 시작하시겠습니까?
  시작한다
  돌아간다
No file changes size.
"""
from __future__ import annotations
import csv
import hashlib
import zipfile
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BASE = ROOT / "arc1_v127_slots_1_to_7_fixes_patch_only.zip"
ORIGINAL = ROOT / "arc.zip"
OUTPUT = ROOT / "arc1_v128_all_battle_choices_patch_only.zip"

BASE_SHA256 = "1299675CD36485D17AE9348A735CFABB1C163EE5EDF814661AC4845EE9E848BA"
OUTPUT_SHA256 = "E41FDD3A7FEB4B8874E1D05D9C9B77E74928F3CA527C71288F5516CD63CBA200"

BATTLE_FILES = ('C1/SC011.DAT', 'C1/SC021.DAT', 'C1/SC031.DAT', 'C1/SC041.DAT', 'C1/SC051.DAT', 'C1/SC061.DAT', 'C1/SC081.DAT', 'C1/SC091.DAT', 'C2/SC0A1.DAT')
OFFSETS = {'C1/SC011.DAT': [290278, 290376, 290474, 290574, 290676, 290776, 290868], 'C1/SC021.DAT': [290278, 290376, 290474, 290574, 290676, 290776, 290868], 'C1/SC031.DAT': [290278, 290376, 290474, 290574, 290676, 290776, 290868], 'C1/SC041.DAT': [290278, 290376, 290474, 290574, 290676, 290776, 290868], 'C1/SC051.DAT': [290278, 290376, 290474, 290574, 290676, 290776, 290868], 'C1/SC061.DAT': [290278, 290376, 290474, 290574, 290676, 290776, 290868], 'C1/SC081.DAT': [290278, 290376, 290474, 290572, 290672, 290772, 290864], 'C1/SC091.DAT': [290278, 290372, 290466, 290564, 290658, 290752, 290844], 'C2/SC0A1.DAT': [290278, 290376, 290468, 290560, 290662, 290762, 290854]}

SLOT_BASE = 0x45000
SLOT_SIZE = 0x80
SLOT_COUNT = 79

PROMPT = bytes.fromhex("e0cce0efe0ab9ce061e092e0c4e061e0a8e05fe035df59e047")
ACCEPT = bytes.fromhex("e061e092e084e0c1")
DECLINE = bytes.fromhex("e0d5e09ce0f7e0c1")

def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()

def disk_id(slot: int) -> int:
    return slot + 0x81 if slot < 40 else slot + 0x82

def slot_from_disk_id(value: int) -> int:
    return value - 0x81 if value <= 0xA8 else value - 0x82

def clone(info: zipfile.ZipInfo) -> zipfile.ZipInfo:
    out = zipfile.ZipInfo(info.filename, info.date_time)
    for attr in ("compress_type", "comment", "extra", "create_system",
                 "create_version", "extract_version", "flag_bits", "volume",
                 "internal_attr", "external_attr"):
        setattr(out, attr, getattr(info, attr))
    return out

def main() -> None:
    if sha256(BASE.read_bytes()) != BASE_SHA256:
        raise SystemExit("v127 base SHA256 differs")

    with zipfile.ZipFile(BASE) as archive:
        infos = archive.infolist()
        before = {i.filename: archive.read(i.filename) for i in infos}
    with zipfile.ZipFile(ORIGINAL) as archive:
        original = {name: archive.read(name) for name in BATTLE_FILES}

    members = dict(before)
    allowed: dict[str, list[tuple[int, int]]] = defaultdict(list)

    for name in BATTLE_FILES:
        data = bytearray(before[name])
        source = original[name]

        if name == "C1/SC051.DAT":
            # v127's runtime-tested instance must remain exact.
            continue

        free = [
            slot for slot in range(SLOT_COUNT)
            if not any(data[SLOT_BASE + slot * SLOT_SIZE:
                            SLOT_BASE + (slot + 1) * SLOT_SIZE])
        ]
        if len(free) < 9:
            raise SystemExit(f"{name}: only {len(free)} empty E2 slots")

        accept_slot = free.pop(0)
        decline_slot = free.pop(0)
        prompt_slots = [free.pop(0) for _ in range(7)]

        def write_slot(slot: int, payload: bytes, skip: int) -> None:
            start = SLOT_BASE + slot * SLOT_SIZE
            data[start:start + SLOT_SIZE] = bytes(SLOT_SIZE)
            data[start:start + len(payload)] = payload
            data[start + SLOT_SIZE - 1] = skip
            allowed[name].append((start, start + SLOT_SIZE))

        write_slot(accept_slot, ACCEPT, 0)
        write_slot(decline_slot, DECLINE, 5)

        for offset, prompt_slot in zip(OFFSETS[name], prompt_slots):
            end = source.find(b"\x00\x00", offset, offset + 128)
            if end < 0:
                raise SystemExit(f"{name} 0x{offset:X}: no body terminator")
            capacity = end - offset
            body = bytearray(source[offset:end])
            e5 = [i for i, value in enumerate(body) if value == 0xE5]
            e6 = [i for i, value in enumerate(body) if value == 0xE6]
            if len(e5) != 2:
                raise SystemExit(f"{name} 0x{offset:X}: E5 geometry differs")

            prompt_end = max(i for i in e6 if i < e5[0])
            accept_start = e5[0] + 2
            accept_end = min(i for i in e6 if i > accept_start)
            decline_start = e5[1] + 2
            if accept_end - accept_start != 2 or capacity - decline_start != 7:
                raise SystemExit(f"{name} 0x{offset:X}: option geometry differs")

            write_slot(prompt_slot, PROMPT, prompt_end - 2)
            body[0:2] = bytes((0xE2, disk_id(prompt_slot)))
            body[accept_start:accept_start + 2] = bytes((0xE2, disk_id(accept_slot)))
            body[decline_start:decline_start + 2] = bytes((0xE2, disk_id(decline_slot)))
            data[offset:offset + capacity] = body
            allowed[name].append((offset, offset + capacity))

        members[name] = bytes(data)

    # Global verification: all 63 entries, including the untouched tested SC051 entries.
    checked = 0
    for name in BATTLE_FILES:
        data = members[name]
        source = original[name]
        for offset in OFFSETS[name]:
            end = source.find(b"\x00\x00", offset, offset + 128)
            capacity = end - offset
            old = source[offset:end]
            new = data[offset:offset + capacity]
            old_e5 = [i for i, value in enumerate(old) if value == 0xE5]
            old_e6 = [i for i, value in enumerate(old) if value == 0xE6]
            new_e5 = [i for i, value in enumerate(new) if value == 0xE5]
            new_e6 = [i for i, value in enumerate(new) if value == 0xE6]
            if new_e5 != old_e5 or new_e6 != old_e6:
                raise SystemExit(f"{name} 0x{offset:X}: E5/E6 moved")
            if new[0] != 0xE2:
                raise SystemExit(f"{name} 0x{offset:X}: prompt is not E2")

            prompt_slot = slot_from_disk_id(new[1])
            accept_start = old_e5[0] + 2
            decline_start = old_e5[1] + 2
            if new[accept_start] != 0xE2 or new[decline_start] != 0xE2:
                raise SystemExit(f"{name} 0x{offset:X}: option is not E2")
            accept_slot = slot_from_disk_id(new[accept_start + 1])
            decline_slot = slot_from_disk_id(new[decline_start + 1])

            prompt_block = data[SLOT_BASE + prompt_slot * SLOT_SIZE:
                                SLOT_BASE + (prompt_slot + 1) * SLOT_SIZE]
            accept_block = data[SLOT_BASE + accept_slot * SLOT_SIZE:
                                SLOT_BASE + (accept_slot + 1) * SLOT_SIZE]
            decline_block = data[SLOT_BASE + decline_slot * SLOT_SIZE:
                                 SLOT_BASE + (decline_slot + 1) * SLOT_SIZE]
            if not prompt_block.startswith(PROMPT):
                raise SystemExit(f"{name} 0x{offset:X}: prompt payload differs")
            if not accept_block.startswith(ACCEPT) or accept_block[-1] != 0:
                raise SystemExit(f"{name} 0x{offset:X}: accept payload differs")
            if not decline_block.startswith(DECLINE) or decline_block[-1] != 5:
                raise SystemExit(f"{name} 0x{offset:X}: decline payload differs")
            checked += 1
    if checked != 63:
        raise SystemExit(f"checked {checked}/63 choices")

    # Isolation: only the eight new DATs, and only declared body/slot ranges.
    expected = set(BATTLE_FILES) - {"C1/SC051.DAT"}
    changed = {name for name in before if before[name] != members[name]}
    if changed != expected:
        raise SystemExit(f"changed member set differs: {sorted(changed)}")
    if members["C1/SC051.DAT"] != before["C1/SC051.DAT"]:
        raise SystemExit("runtime-tested SC051 changed")

    for name in expected:
        mask = bytearray(len(before[name]))
        for start, end in allowed[name]:
            mask[start:end] = b"\x01" * (end - start)
        for i, (old, new) in enumerate(zip(before[name], members[name])):
            if old != new and not mask[i]:
                raise SystemExit(f"{name} undeclared byte change at 0x{i:X}")
        if len(before[name]) != len(members[name]):
            raise SystemExit(f"{name} size changed")

    if OUTPUT.exists():
        OUTPUT.unlink()
    with zipfile.ZipFile(OUTPUT, "w") as archive:
        for info in infos:
            archive.writestr(clone(info), members[info.filename])

    with zipfile.ZipFile(OUTPUT) as archive:
        readback = {i.filename: archive.read(i.filename) for i in archive.infolist()}
    if readback != members:
        raise SystemExit("ZIP readback differs")
    if sha256(OUTPUT.read_bytes()) != OUTPUT_SHA256:
        raise SystemExit("output SHA256 differs")
    print(OUTPUT.name)
    print(OUTPUT_SHA256)
    print("63/63 battle choices verified")

if __name__ == "__main__":
    main()
