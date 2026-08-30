#!/usr/bin/env python3
"""Independent verifier for V351's ten 0x0F -> 0x21 full-stop repairs."""

from __future__ import annotations

import csv
import hashlib
import sys
from pathlib import Path
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[1]
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

BASE = ROOT / "03_output/arc1_v350_dialogue_wording_fixes_TEST_ONLY_2B760572.zip"
BASE_SHA256 = "2B76057250E02F29D6EAA55A8882B04A420F3C232715409938DAF2070AD4041E"
ATLAS = ROOT / "01_work/analysis/arc1_v319_pilgi16_integration/atlas_mapping.csv"
ATLAS_SHA256 = "9553E7643621CC80C23355067611EAE7650FEF7CB547DC9115B62157DB0C3122"
SLOT_BASE, SLOT_SIZE, SLOT_META = 0x45000, 0x80, 0x7F
BAD, FULL_STOP = 0x0F, 0x21
PSX, COMM = "PSX.EXE", "COMM.IMG"

EXPECTED = (
    ("5/S5011.DAT", 4, 13, 0x4810A, (0x45212,)),
    ("5/S5021.DAT", 20, 22, 0x47B70, (0x45A1B,)),
    ("5/S5021.DAT", 22, 43, 0x47B0E, (0x45B1A,)),
    ("5/S5024.DAT", 0, 19, 0x478E8, (0x45018,)),
    ("5/S5052.DAT", 0, 25, 0x47ADA, (0x4500B, 0x4501F, 0x4502B)),
    ("5/S5052.DAT", 4, 27, 0x47B28, (0x4521E,)),
    ("5/S5052.DAT", 6, 19, 0x47A90, (0x4530D, 0x45313)),
)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def disk_id(slot: int) -> int:
    return slot + (0x81 if slot < 40 else 0x82)


def start(slot: int) -> int:
    return SLOT_BASE + slot * SLOT_SIZE


def main() -> None:
    if sha(BASE.read_bytes()) != BASE_SHA256:
        raise AssertionError("V350 base hash mismatch")
    if sha(ATLAS.read_bytes()) != ATLAS_SHA256:
        raise AssertionError("atlas mapping hash mismatch")
    with ATLAS.open(encoding="utf-8-sig", newline="") as handle:
        atlas = {int(row["index"]): row for row in csv.DictReader(handle)}
    if atlas[14].get("unicode") != "U+C758":
        raise AssertionError(f"bad-glyph atlas premise changed: {atlas[14]}")
    if atlas[32].get("unicode") != "U+002E" or atlas[32].get("char") != ".":
        raise AssertionError(f"full-stop atlas premise changed: {atlas[32]}")

    candidates = sorted((ROOT / "03_output").glob("arc1_v351_period_code_repair_TEST_ONLY_*.zip"))
    candidates = [p for p in candidates if "delta_from" not in p.name]
    if len(candidates) != 1:
        raise AssertionError(f"expected exactly one V351 full ZIP, found {[p.name for p in candidates]}")
    final_path = candidates[0]
    with ZipFile(BASE) as archive:
        base_names = [x.filename for x in archive.infolist() if not x.is_dir()]
        base = {name: archive.read(name) for name in base_names}
    with ZipFile(final_path) as archive:
        final_names = [x.filename for x in archive.infolist() if not x.is_dir()]
        final = {name: archive.read(name) for name in final_names}
    if final_names != base_names or len(final_names) != 164:
        raise AssertionError("archive member topology changed")
    expected_members = ["5/S5011.DAT", "5/S5021.DAT", "5/S5024.DAT", "5/S5052.DAT"]
    changed = [name for name in base_names if base[name] != final[name]]
    if changed != expected_members:
        raise AssertionError(f"changed member set mismatch: {changed}")
    if any(len(base[name]) != len(final[name]) for name in base_names):
        raise AssertionError("member size changed")
    if final[PSX] != base[PSX] or final[COMM] != base[COMM]:
        raise AssertionError("PSX.EXE/COMM.IMG changed")

    expected_offsets = {name: set() for name in expected_members}
    total = 0
    for member, slot, metadata, caller, offsets in EXPECTED:
        old, new = base[member], final[member]
        token = bytes((0xE2, disk_id(slot)))
        if old[caller:caller + 2] != token or new[caller:caller + 2] != token:
            raise AssertionError(f"E2 caller changed: {member}:0x{caller:X}")
        if old[start(slot) + SLOT_META] != metadata or new[start(slot) + SLOT_META] != metadata:
            raise AssertionError(f"slot metadata changed: {member} slot {slot}")
        for offset in offsets:
            if not start(slot) <= offset < start(slot) + SLOT_META:
                raise AssertionError(f"offset outside payload: {member}:0x{offset:X}")
            if old[offset] != BAD or new[offset] != FULL_STOP:
                raise AssertionError(
                    f"expected 0F->21 not found: {member}:0x{offset:X} {old[offset]:02X}->{new[offset]:02X}"
                )
            expected_offsets[member].add(offset)
            total += 1
    if total != 10:
        raise AssertionError(f"expected ten fixes, got {total}")

    for member in changed:
        diff = {i for i, (a, b) in enumerate(zip(base[member], final[member], strict=True)) if a != b}
        if diff != expected_offsets[member]:
            raise AssertionError(f"Expected-Write mismatch: {member}")
    if sum(len(expected_offsets[n]) for n in expected_members) != 10:
        raise AssertionError("expected-write cardinality drift")

    print(f"V351={final_path.name} sha256={sha(final_path.read_bytes())}")
    print("atlas premise: 0x0F -> physical14 U+C758; 0x21 -> physical32 '.' (U+002E)")
    print("10/10 pinned recent full stops changed exactly 0F->21")
    print("changed members: 5/S5011.DAT, 5/S5021.DAT, 5/S5024.DAT, 5/S5052.DAT only")
    print("E2 callers/completion metadata/member sizes and PSX.EXE/COMM.IMG preserved")
    print("RESULT: PASS (static only; runtime not established)")


if __name__ == "__main__":
    main()
