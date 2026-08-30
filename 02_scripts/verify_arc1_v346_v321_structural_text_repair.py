#!/usr/bin/env python3
"""Independent static verifier for V346.

This intentionally does not import the V346 builder.  All offsets, archive
comparisons, V321 census classification, pointer arithmetic and text payloads
are recomputed from the built archives.
"""

from __future__ import annotations

import csv
import hashlib
import json
import struct
import sys
from pathlib import Path
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[1]
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

BASE = ROOT / "03_output/arc1_v345_story_timing_cursor_recovery_TEST_ONLY_AB9A8E99.zip"
BASE_SHA = "AB9A8E99707D4E11EF0878E65451AA0DAD441328C6EDE9277E6142A9164BC54D"
BUILD = ROOT / "03_output/arc1_v346_v321_structural_text_repair_TEST_ONLY_30A40DD7.zip"
BUILD_SHA = "30A40DD7560CAEC5F9C464BC0166EDC00FADAB9F95823748B44AF260334890B8"
DELTA = ROOT / "03_output/arc1_v346_v321_structural_text_repair_TEST_ONLY_delta_from_v345_DDC32CAB.zip"
DELTA_SHA = "DDC32CABE4903B01A61C67F559AF9CB564ED88FF66F2F0999E588DAA3CC90B11"
V320C = ROOT / "03_output/arc1_v320c_hanme_official_beol_TEST_ONLY_81D215E1.zip"
V321 = ROOT / "03_output/arc1_v321_text_identity_repair_TEST_ONLY_1B04A832.zip"
ANALYSIS = ROOT / "01_work/analysis/arc1_v346_v321_structural_text_repair"
EXPECTED_WRITES = ANALYSIS / "expected_writes.csv"

PSX = "PSX.EXE"
DAT = "4/S4031.DAT"
COMM = "COMM.IMG"
RAM_TO_FILE = 0x8011A800

REAL_MON = {0x82382, 0x82407}
NUMERIC = {0x7B760, 0x7B784, 0x7EB54}
DISPATCH_BYTE = 0x7C005
STRUCT = {0x7F94E + index * 0x3A for index in range(30)}
RESTORE = NUMERIC | {DISPATCH_BYTE} | STRUCT
LATER_POINTERS = {0x804F1 + index * 4 for index in range(20)} | {0x829B0}
STORY_WRITES = {0x47F9F, 0x48519, 0x48527}


class VerificationError(RuntimeError):
    pass


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest().upper()


def members(path: Path) -> tuple[list[str], dict[str, bytes]]:
    with ZipFile(path) as archive:
        names = [item.filename for item in archive.infolist() if not item.is_dir()]
        return names, {name: archive.read(name) for name in names}


def word(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def changes(before: bytes, after: bytes) -> set[int]:
    if len(before) != len(after):
        raise VerificationError("member size changed")
    return {index for index, (left, right) in enumerate(zip(before, after, strict=True)) if left != right}


def main() -> None:
    expected_hashes = ((BASE, BASE_SHA), (BUILD, BUILD_SHA), (DELTA, DELTA_SHA))
    for path, expected in expected_hashes:
        if not path.is_file() or sha(path) != expected:
            raise VerificationError(f"archive hash mismatch: {path.name}")

    base_names, base = members(BASE)
    build_names, build = members(BUILD)
    _v320_names, v320 = members(V320C)
    _v321_names, v321 = members(V321)
    delta_names, delta = members(DELTA)
    if len(base_names) != 164 or base_names != build_names:
        raise VerificationError("164-member topology/order drift")
    changed_members = [name for name in base_names if base[name] != build[name]]
    if changed_members != [DAT, PSX] or delta_names != changed_members:
        raise VerificationError(f"changed/delta member drift: {changed_members} / {delta_names}")
    if any(delta[name] != build[name] for name in delta_names):
        raise VerificationError("delta payload differs from full build")
    if any(len(base[name]) != len(build[name]) for name in base_names):
        raise VerificationError("one or more member sizes changed")
    if build[COMM] != base[COMM]:
        raise VerificationError("COMM.IMG changed")

    actual = {name: changes(base[name], build[name]) for name in changed_members}
    if actual[DAT] != STORY_WRITES:
        raise VerificationError(f"DAT write set drift: {sorted(actual[DAT])}")
    with EXPECTED_WRITES.open(encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    csv_sets: dict[str, set[int]] = {}
    for row in rows:
        csv_sets.setdefault(row["member"], set()).add(int(row["offset"], 16))
        offset = int(row["offset"], 16)
        if base[row["member"]][offset] != int(row["before"], 16):
            raise VerificationError(f"Expected-Write before mismatch: {row}")
        if build[row["member"]][offset] != int(row["after"], 16):
            raise VerificationError(f"Expected-Write after mismatch: {row}")
    if csv_sets != actual:
        raise VerificationError("Expected-Write rows do not equal actual diff")

    old_exe = v320[PSX]
    v321_exe = v321[PSX]
    base_exe = base[PSX]
    exe = build[PSX]
    v321_diffs = changes(old_exe, v321_exe)
    classified = RESTORE | REAL_MON | LATER_POINTERS
    if len(v321_diffs) != 57 or v321_diffs != classified:
        raise VerificationError("independent V321 57-byte classification failed")
    if any((old_exe[offset], v321_exe[offset]) != (0xAB, 0x64) for offset in v321_diffs):
        raise VerificationError("V321 diff contains a non AB->64 change")
    if not (len(RESTORE), len(REAL_MON), len(LATER_POINTERS)) == (34, 2, 21):
        raise VerificationError("57-byte category counts drift")
    if any((base_exe[offset], exe[offset]) != (0x64, 0xAB) for offset in RESTORE):
        raise VerificationError("non-text structural restoration mismatch")
    if any(exe[offset] != 0x64 for offset in REAL_MON):
        raise VerificationError("real 몬 token was not preserved")
    if any(exe[offset] != base_exe[offset] for offset in LATER_POINTERS):
        raise VerificationError("later-rebuilt pointer byte regressed")

    table = 0x7B9E8
    index = 391
    entry = table + index * 4
    if entry != 0x7C004:
        raise VerificationError("dispatcher table arithmetic failed")
    if word(base_exe, entry) != 0x8014643C or word(exe, entry) != 0x8014AB3C:
        raise VerificationError("dispatcher freeze pointer mismatch")
    target = word(exe, entry) - RAM_TO_FILE
    if target != 0x3033C or exe[target:target + 32] != old_exe[target:target + 32]:
        raise VerificationError("restored dispatcher target body mismatch")
    if target == 0x2BC3C:  # file offset of the broken dispatcher's own lw
        raise VerificationError("dispatcher remains self-referential")

    numeric_windows = {
        0x7B760: [136, 145, 153, 162, 171, 180, 189, 199, 210],
        0x7B784: [345, 363, 383, 404, 427, 451, 478, 508, 541],
        0x7EB54: [93, 94, 65535, 65535, 171, 172, 173, 174, 175],
    }
    for offset, expected in numeric_windows.items():
        start = (offset & ~1) - 8
        got = [struct.unpack_from("<H", exe, at)[0] for at in range(start, start + 18, 2)]
        if got != expected:
            raise VerificationError(f"numeric-table restoration failed at 0x{offset:X}: {got}")
    if any(struct.unpack_from("<H", exe, offset)[0] != 171 for offset in STRUCT):
        raise VerificationError("stride-0x3A struct fields are not all 171")
    if sorted(STRUCT)[1] - sorted(STRUCT)[0] != 0x3A or sorted(STRUCT)[-1] != 0x7FFE0:
        raise VerificationError("stride-0x3A field census drift")

    dat = build[DAT]
    story_a = bytes.fromhex(
        "DD BA 4E D5 A1 7E A1 1A DD 31 0E A1 33 DD 70 03 A1 DD D9 A1 "
        "1C 37 0F A1 24 DD 72 26 A1 83 3D DD A7 A1 94 DD 69 0E A1 A1 00"
    )
    story_b = bytes.fromhex(
        "DD 0D 09 A9 A1 1C 37 0F A1 24 DD 72 0D A1 DD 56 28 21 A1 00"
    )
    if dat[0x47F7A:0x47F7A + len(story_a)] != story_a:
        raise VerificationError("안쪽에 story body/control mismatch")
    if dat[0x48516:0x48516 + len(story_b)] != story_b:
        raise VerificationError("좋아!/찾자. story body/control mismatch")

    if exe[0x82924:0x82928] != bytes.fromhex("DF 09 A1 00"):
        raise VerificationError("level-up suffix bytes mismatch")
    if word(exe, 0x82558) != RAM_TO_FILE + 0x82924:
        raise VerificationError("level-up suffix pointer mismatch")

    mirumana = {
        0x80944: bytes.fromhex("DD 2F 70 45 1E 00"),
        0x80982: bytes.fromhex("DD 2F 70 45 1E A1 DD 10 DD F2 00"),
        0x81A1F: bytes.fromhex("DD 2F 70 45 1E A1 7C DD 58 6C 00"),
    }
    for offset, payload in mirumana.items():
        if exe[offset:offset + len(payload)] != payload:
            raise VerificationError(f"미르마나 payload mismatch at 0x{offset:X}")
    pointer_targets = {
        0x81EEC: 0x80944,
        0x81E58: 0x80982,
        0x8219C: 0x80982,
        0x821A0: 0x81A1F,
    }
    for at, target_file in pointer_targets.items():
        if word(exe, at) != RAM_TO_FILE + target_file:
            raise VerificationError(f"미르마나 pointer mismatch at 0x{at:X}")
    # The HQ payload grows one byte to the left and still terminates at 0x81A29.
    if exe[0x81A29] != 0 or exe[0x81A2A:0x81A34] != base_exe[0x81A2A:0x81A34]:
        raise VerificationError("미르마나 군본부 boundary damaged the next string")

    report = {
        "verdict": "PASS",
        "archive": {
            "members": len(build_names),
            "changed": changed_members,
            "changed_bytes": {name: len(actual[name]) for name in changed_members},
            "full_sha256": BUILD_SHA,
            "delta_sha256": DELTA_SHA,
        },
        "v321_census": {
            "total": len(v321_diffs),
            "restored_nontext": len(RESTORE),
            "preserved_real_mon": len(REAL_MON),
            "preserved_later_pointers": len(LATER_POINTERS),
        },
        "freeze": {
            "index": index,
            "entry_file": f"0x{entry:X}",
            "before": f"0x{word(base_exe, entry):08X}",
            "after": f"0x{word(exe, entry):08X}",
            "target_file": f"0x{target:X}",
        },
        "texts": "PASS",
        "COMM_IMG": "byte exact",
        "runtime": "PENDING user cold boot",
    }
    ANALYSIS.mkdir(parents=True, exist_ok=True)
    (ANALYSIS / "independent_verification.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    lines = [
        "V346 independent verification PASS",
        f"archives={BUILD_SHA} delta={DELTA_SHA}",
        f"members=164 changed={','.join(changed_members)} bytes={DAT}:{len(actual[DAT])},{PSX}:{len(actual[PSX])}",
        "V321=57 total / 34 nontext restored / 2 real 몬 preserved / 21 later pointers preserved",
        "freeze=dispatcher[391] 0x8014643C -> 0x8014AB3C; target body matches V320C",
        "numeric tables and 30 stride-0x3A fields restored",
        "texts=안쪽에; 좋아! ... 찾자.; 레벨 상승; 미르마나 three strings PASS",
        "COMM.IMG and all undeclared bytes byte exact",
        "runtime=PENDING user cold boot; TEST_ONLY",
    ]
    (ANALYSIS / "independent_verification.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
