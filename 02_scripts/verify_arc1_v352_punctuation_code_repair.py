#!/usr/bin/env python3
"""Independent static verifier for V352 punctuation-code repair."""

from __future__ import annotations

import csv
import hashlib
from pathlib import Path
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "03_output/arc1_v351_period_code_repair_TEST_ONLY_76DFD702.zip"
BASE_SHA256 = "76DFD702BBDD9D11A9CEE2B6B9DF795F90B2F4D6744DB474209E92F4825CA50D"
ASSIGNMENTS = ROOT / "01_work/analysis/arc1_v320_hanme_static_recovery/character_assignments.csv"
ASSIGNMENTS_SHA256 = "933BDAC4BC4C39D33DB134D2FF836902B5053B93725C96E19DED714CB7DE98A4"

REPAIRS = (
    ("5/S5011.DAT", 0x4510B, 0x0D, 0xB3),
    ("5/S5011.DAT", 0x45113, 0x02, 0xA9),
    ("5/S5011.DAT", 0x45121, 0x02, 0xA9),
    ("5/S5052.DAT", 0x45302, 0x0D, 0xB3),
)
EXPECTED_PUNCTUATION = {
    ",": ("B3", "178", "U+002C"),
    ".": ("21", "32", "U+002E"),
    "!": ("A9", "168", "U+0021"),
    "?": ("D1", "208", "U+003F"),
}


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def archive(path: Path) -> tuple[list[str], dict[str, bytes]]:
    with ZipFile(path) as z:
        names = [i.filename for i in z.infolist() if not i.is_dir()]
        return names, {n: z.read(n) for n in names}


def main() -> None:
    if sha(BASE.read_bytes()) != BASE_SHA256:
        raise AssertionError("V351 base hash drift")
    if sha(ASSIGNMENTS.read_bytes()) != ASSIGNMENTS_SHA256:
        raise AssertionError("assignment hash drift")
    with ASSIGNMENTS.open(encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    for char, (code, physical, unicode_value) in EXPECTED_PUNCTUATION.items():
        ok = any(
            row.get("char") == char
            and row.get("code_hex", "").replace(" ", "").upper() == code
            and row.get("physical_index") == physical
            and row.get("unicode") == unicode_value
            for row in rows
        )
        if not ok:
            raise AssertionError(f"punctuation mapping drift: {char!r}")

    candidates = sorted((ROOT / "03_output").glob("arc1_v352_punctuation_code_repair_TEST_ONLY_*.zip"))
    candidates = [p for p in candidates if "delta" not in p.name]
    if len(candidates) != 1:
        raise AssertionError(f"expected one V352 full archive, found {[p.name for p in candidates]}")
    out = candidates[0]
    old_names, old = archive(BASE)
    new_names, new = archive(out)
    if old_names != new_names or len(new_names) != 164:
        raise AssertionError("archive topology changed")

    expected: dict[str, set[int]] = {"5/S5011.DAT": set(), "5/S5052.DAT": set()}
    for member, offset, before, after in REPAIRS:
        if old[member][offset] != before or new[member][offset] != after:
            raise AssertionError(
                f"expected punctuation repair missing: {member}:0x{offset:X} "
                f"{old[member][offset]:02X}->{new[member][offset]:02X}"
            )
        expected[member].add(offset)

    changed = [name for name in old_names if old[name] != new[name]]
    if changed != ["5/S5011.DAT", "5/S5052.DAT"]:
        raise AssertionError(f"changed-member drift: {changed}")
    for member in changed:
        diff = {i for i, (a, b) in enumerate(zip(old[member], new[member], strict=True)) if a != b}
        if diff != expected[member]:
            raise AssertionError(f"Expected-Write mismatch: {member}")
    if sum(len(v) for v in expected.values()) != 4:
        raise AssertionError("repair cardinality drift")

    if new["5/S5011.DAT"][0x4815A:0x4815C] != bytes.fromhex("E2 83"):
        raise AssertionError("S5011 E2 caller changed")
    if new["5/S5011.DAT"][0x4517F] != 35:
        raise AssertionError("S5011 completion changed")
    if new["5/S5052.DAT"][0x47A90:0x47A92] != bytes.fromhex("E2 87"):
        raise AssertionError("S5052 E2 caller changed")
    if new["5/S5052.DAT"][0x4537F] != 19:
        raise AssertionError("S5052 completion changed")
    if new["PSX.EXE"] != old["PSX.EXE"] or new["COMM.IMG"] != old["COMM.IMG"]:
        raise AssertionError("PSX.EXE/COMM.IMG changed")
    for name in old_names:
        if len(old[name]) != len(new[name]):
            raise AssertionError(f"member size changed: {name}")

    print(f"V352={out.name} sha256={sha(out.read_bytes())}")
    print("punctuation map PASS: ,=B3 .=21 !=A9 ?=D1")
    print("4/4 pinned recent punctuation bytes repaired exactly")
    print("changed members: 5/S5011.DAT, 5/S5052.DAT only")
    print("E2 callers/completion metadata/member sizes and PSX.EXE/COMM.IMG preserved")
    print("RESULT: PASS (static only; runtime not established)")


if __name__ == "__main__":
    main()
