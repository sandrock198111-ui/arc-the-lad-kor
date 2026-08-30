#!/usr/bin/env python3
"""Independent static verifier for V350 dialogue-only slot edits."""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[1]
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

BASE = ROOT / "03_output/arc1_v349_floor_resident_helper_reuse_TEST_ONLY_EC5724F9.zip"
BASE_SHA256 = "EC5724F91C6251C76D349AAB135BC411010CE7E4BBBDBCF0D4EFFEFE1488D481"
S5024 = "5/S5024.DAT"
S5052 = "5/S5052.DAT"
SLOT_BASE = 0x45000
SLOT_SIZE = 0x80
SLOT_META = 0x7F

# member, body offset, slot, metadata, exact final payload
EXPECTED = (
    (S5024, 0x478E8, 0, 19, bytes.fromhex(
        "DD F9 A1 DD 07 2E 49 D1 A1 03 DD 12 DD 53 A1 1B 03 A1 94 A1 73 DD BC 09 0F"
    )),
    (S5052, 0x47A90, 6, 19, bytes.fromhex(
        "03 49 0D A1 5A 92 0E A1 DD A2 DD 2D 7C 0F A1 1C DE CA 01 0F"
    )),
    (S5052, 0x47ADA, 0, 25, bytes.fromhex(
        "1C DE CA 01 1C 06 A1 2B A1 40 04 0F A1 19 04 38 A1 60 6D 26 A1 1E DD 55 04 "
        "A1 78 0D A1 32 49 0F A1 1B 03 49 A1 DD 10 DE B9 07 3B 0F"
    )),
    (S5052, 0x47B28, 4, 27, bytes.fromhex(
        "2C DD 86 09 DD 02 A1 34 DD 22 26 A1 DD E3 DD 6B 38 A1 DD B9 8F A1 34 06 A1 41 A1 09 07 01 0F"
    )),
)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def disk_id(slot: int) -> int:
    return slot + (0x81 if slot < 40 else 0x82)


def start(slot: int) -> int:
    return SLOT_BASE + slot * SLOT_SIZE


def slot_payload(data: bytes, slot: int) -> bytes:
    raw = data[start(slot):start(slot) + SLOT_META]
    end = raw.find(b"\0")
    if end < 0:
        raise AssertionError(f"unterminated slot {slot}")
    return raw[:end]


def main() -> None:
    if sha(BASE.read_bytes()) != BASE_SHA256:
        raise AssertionError("V349 base hash mismatch")
    candidates = sorted((ROOT / "03_output").glob("arc1_v350_dialogue_wording_fixes_TEST_ONLY_*.zip"))
    candidates = [p for p in candidates if "delta_from" not in p.name]
    if len(candidates) != 1:
        raise AssertionError(f"expected exactly one V350 full ZIP, found {[p.name for p in candidates]}")
    final_path = candidates[0]
    with ZipFile(BASE) as archive:
        base_names = [x.filename for x in archive.infolist() if not x.is_dir()]
        base = {name: archive.read(name) for name in base_names}
    with ZipFile(final_path) as archive:
        final_names = [x.filename for x in archive.infolist() if not x.is_dir()]
        final = {name: archive.read(name) for name in final_names}
    if final_names != base_names or len(final_names) != 164:
        raise AssertionError("archive member topology changed")
    changed = [name for name in base_names if base[name] != final[name]]
    if changed != [S5024, S5052]:
        raise AssertionError(f"changed member set mismatch: {changed}")
    if any(len(base[name]) != len(final[name]) for name in base_names):
        raise AssertionError("member size changed")
    if final["PSX.EXE"] != base["PSX.EXE"] or final["COMM.IMG"] != base["COMM.IMG"]:
        raise AssertionError("PSX.EXE/COMM.IMG changed")

    allowed = {S5024: set(), S5052: set()}
    for member, body_offset, slot, metadata, payload in EXPECTED:
        old = base[member]
        new = final[member]
        token = bytes((0xE2, disk_id(slot)))
        if old[body_offset:body_offset + 2] != token or new[body_offset:body_offset + 2] != token:
            raise AssertionError(f"E2 caller changed: {member}:0x{body_offset:X}")
        if new[start(slot) + SLOT_META] != metadata or old[start(slot) + SLOT_META] != metadata:
            raise AssertionError(f"slot metadata changed: {member} slot {slot}")
        if slot_payload(new, slot) != payload:
            raise AssertionError(f"payload mismatch: {member} slot {slot}")
        allowed[member].update(range(start(slot), start(slot) + SLOT_META))

    for member in changed:
        diff = {i for i, (before, after) in enumerate(zip(base[member], final[member], strict=True)) if before != after}
        if not diff or not diff <= allowed[member]:
            raise AssertionError(f"write escaped slot payload envelope: {member}")
        for _member, _body, slot, metadata, _payload in EXPECTED:
            if _member == member and start(slot) + SLOT_META in diff:
                raise AssertionError(f"metadata byte changed: {member} slot {slot}")

    print(f"V350={final_path.name} sha256={sha(final_path.read_bytes())}")
    print("changed members: 5/S5024.DAT, 5/S5052.DAT only")
    print("4/4 final E2 slot payloads exact; callers and +0x7F metadata preserved")
    print("PSX.EXE/COMM.IMG/all other members byte exact V349")
    print("RESULT: PASS (static only; runtime not established)")


if __name__ == "__main__":
    main()
