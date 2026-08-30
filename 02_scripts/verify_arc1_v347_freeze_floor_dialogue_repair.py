#!/usr/bin/env python3
"""Independent static verifier for V347.

This verifier deliberately does not import the V347 builder.  Archive hashes,
member diffs, original code-pointer identity, floor formatter inputs, E2 slot
ownership/completion and preservation ranges are recomputed from the files.
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

BASE = ROOT / "03_output/arc1_v346_v321_structural_text_repair_TEST_ONLY_30A40DD7.zip"
BASE_SHA = "30A40DD7560CAEC5F9C464BC0166EDC00FADAB9F95823748B44AF260334890B8"
BUILD = ROOT / "03_output/arc1_v347_freeze_floor_dialogue_repair_TEST_ONLY_028303F6.zip"
BUILD_SHA = "028303F62EFA7D1362DAA6AA57B2224B39A8692CD2D8CA0073980DA1DAF73302"
DELTA = ROOT / "03_output/arc1_v347_freeze_floor_dialogue_repair_TEST_ONLY_delta_from_v346_13E496A0.zip"
DELTA_SHA = "13E496A0ED28B0FA41113F8C5DC5EBDBF7402872F805AF2C792F3658F71A99CE"
PRISTINE = ROOT / "00_original/arc.zip"
PRISTINE_SHA = "AE9F4366A1E7DA3805BB3BED3DDA9567E4CD4E669AF890E4E2A620D7861F11DD"

ANALYSIS = ROOT / "01_work/analysis/arc1_v347_freeze_floor_dialogue_repair"
EXPECTED_WRITES = ANALYSIS / "expected_writes.csv"

PSX = "PSX.EXE"
COMM = "COMM.IMG"
S5011 = "5/S5011.DAT"
S5021 = "5/S5021.DAT"
CHANGED_MEMBERS = [S5011, S5021, PSX]

MEMBER_SHA = {
    PSX: "826BD14337B287A656364FA4AB004535B85F276376072CA6FA6351AC3A64A337",
    S5011: "56C982F78305D61E81C4AA8A32194A492586EA7CA1AA3072798289C7D54EF12C",
    S5021: "28F75F211C4AEDC797966D960C7033FB32F50928BC00282EB5861C5B86EB0057",
    COMM: "A6681F1355007725328372CC6143EF21EEE43A9FDE91FD3DC2EF3461C6805405",
}

RAM_TO_FILE = 0x8011A800
CODE_START = 0x8011B000
CODE_END = 0x80192800
POINTERS = {
    0x7EF3C: (0x80168DE1, 0x80162CE0),
    0x8D788: (0x801204E0, 0x8012E2E0),
}
PSX_DIFFS = {
    0x7EF3C, 0x7EF3D,
    0x809F4, 0x809F5, 0x809F6,
    0x8215C, 0x8215D,
    0x8D789,
}
FORMATTER_AT = 0x4EF4C
FORMATTER_SIZE = 0x50
FORMATTER_SHA = "ADDFAE0E7FDC55887733E00A0A4430E25B737EF3D2D7540BF3B0D2E8B99AE49C"

SLOT_BASE = 0x45000
SLOT_SIZE = 0x80
SLOT_META = 0x7F
SLOT_SPECS = (
    (S5011, 2, 35, 0x4815A, bytes.fromhex(
        "56 34 06 A1 5F DD A0 A1 56 34 49 0D A1 03 A1 28 DD B5 09 02 "
        "A1 53 A1 37 A1 DD B1 1C A1 DD 4E DD 51 02"
    )),
    (S5011, 4, 13, 0x4810A, bytes.fromhex(
        "1E 33 A1 03 A1 6B D5 A1 DE 66 1C 34 07 3B A1 1B 03 04 0F"
    )),
    (S5021, 20, 22, 0x47B70, bytes.fromhex(
        "7E 0C A1 14 DD 44 41 A1 DE 66 1C 34 06 04 A1 0A 4E 20 A1 DD 5C "
        "A1 41 A1 09 07 49 0F"
    )),
    (S5021, 21, 18, 0x47D3E, bytes.fromhex(
        "03 66 6C 02 0C A1 32 DD 12 A1 03 49 24 DE 3E A1 32 04 D1"
    )),
    (S5021, 22, 43, 0x47B0E, bytes.fromhex(
        "1E 06 A1 8A DD 09 0E 25 A1 60 6D 0D A1 DD 56 09 A1 DD 7B 06 A1 "
        "55 DD 54 0C 04 0F"
    )),
)
CALLS = {
    0x47B0E: (bytes.fromhex("1E 06"), bytes.fromhex("E2 97"), 22, 45),
    0x47B70: (bytes.fromhex("7E A1"), bytes.fromhex("E2 95"), 20, 24),
}
REPEAT_SLOT = 8
REPEAT_HASH = "70629AEE0B2816C285C9685C5873477C3DFCBFEED6C67AF607BFED06C374C793"
REPEAT_REF = 0x4791C
CURSOR_RANGES = (
    (0x2060, 4),
    (0x3E14, 8),
    (0x75590, 0x34),
    (0x8F0D0, 36),
)


class VerificationError(RuntimeError):
    pass


def sha_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def sha_file(path: Path) -> str:
    return sha_bytes(path.read_bytes())


def archive(path: Path) -> tuple[list[str], dict[str, bytes]]:
    with ZipFile(path) as handle:
        names = [item.filename for item in handle.infolist() if not item.is_dir()]
        return names, {name: handle.read(name) for name in names}


def word(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def changes(before: bytes, after: bytes) -> set[int]:
    if len(before) != len(after):
        raise VerificationError("member size changed")
    return {
        index for index, (left, right) in enumerate(zip(before, after, strict=True))
        if left != right
    }


def body(data: bytes, offset: int) -> bytes:
    end = data.find(b"\0", offset)
    if end < 0:
        raise VerificationError(f"unterminated body at 0x{offset:X}")
    return data[offset:end]


def disk_id(slot: int) -> int:
    return slot + (0x81 if slot < 40 else 0x82)


def slot_block(data: bytes, slot: int) -> bytes:
    start = SLOT_BASE + slot * SLOT_SIZE
    return data[start:start + SLOT_SIZE]


def slot_references(data: bytes, slot: int) -> list[int]:
    needle = bytes((0xE2, disk_id(slot)))
    result: list[int] = []
    cursor = SLOT_BASE + 64 * SLOT_SIZE
    while True:
        cursor = data.find(needle, cursor)
        if cursor < 0:
            return result
        result.append(cursor)
        cursor += 2


def pointer_census(
    pristine: dict[str, bytes], candidate: dict[str, bytes]
) -> tuple[int, list[tuple[str, int, int, int]]]:
    names = [PSX] + [
        name for name in pristine
        if name.upper().endswith(".DAT") and name in candidate
    ]
    total = 0
    bad: list[tuple[str, int, int, int]] = []
    for name in names:
        original = pristine[name]
        current = candidate[name]
        for offset in range(0, min(len(original), len(current)) - 3, 4):
            old_word = word(original, offset)
            if CODE_START <= old_word < CODE_END:
                total += 1
                new_word = word(current, offset)
                if new_word != old_word:
                    bad.append((name, offset, old_word, new_word))
    return total, bad


def main() -> None:
    for path, expected in (
        (BASE, BASE_SHA), (BUILD, BUILD_SHA), (DELTA, DELTA_SHA),
        (PRISTINE, PRISTINE_SHA),
    ):
        if not path.is_file() or sha_file(path) != expected:
            raise VerificationError(f"archive hash mismatch: {path.name}")

    base_names, base = archive(BASE)
    build_names, build = archive(BUILD)
    delta_names, delta = archive(DELTA)
    _pristine_names, pristine = archive(PRISTINE)
    if len(base_names) != 164 or base_names != build_names:
        raise VerificationError("164-member topology/order drift")
    changed_members = [name for name in base_names if base[name] != build[name]]
    if changed_members != CHANGED_MEMBERS or delta_names != CHANGED_MEMBERS:
        raise VerificationError(f"changed/delta member drift: {changed_members} / {delta_names}")
    if any(delta[name] != build[name] for name in delta_names):
        raise VerificationError("delta payload differs from full build")
    if any(len(base[name]) != len(build[name]) for name in base_names):
        raise VerificationError("one or more member sizes changed")
    for name, expected in MEMBER_SHA.items():
        if sha_bytes(build[name]) != expected:
            raise VerificationError(f"built member hash mismatch: {name}")
    if build[COMM] != base[COMM]:
        raise VerificationError("COMM.IMG changed")

    actual = {name: changes(base[name], build[name]) for name in changed_members}
    if {name: len(offsets) for name, offsets in actual.items()} != {
        S5011: 58, S5021: 118, PSX: 8,
    }:
        raise VerificationError("changed-byte census drift")
    if actual[PSX] != PSX_DIFFS:
        raise VerificationError(f"PSX exact diff-set drift: {sorted(actual[PSX])}")

    with EXPECTED_WRITES.open(encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    csv_sets: dict[str, set[int]] = {}
    for row in rows:
        name = row["member"]
        offset = int(row["offset"], 16)
        csv_sets.setdefault(name, set()).add(offset)
        if base[name][offset] != int(row["before"], 16):
            raise VerificationError(f"Expected-Write before mismatch: {row}")
        if build[name][offset] != int(row["after"], 16):
            raise VerificationError(f"Expected-Write after mismatch: {row}")
    if csv_sets != actual:
        raise VerificationError("Expected-Write rows do not equal actual diff")

    total_base, bad_base = pointer_census(pristine, base)
    total_build, bad_build = pointer_census(pristine, build)
    expected_bad = [
        (PSX, offset, original, broken)
        for offset, (broken, original) in sorted(POINTERS.items())
    ]
    if total_base != 5311 or total_build != 5311 or bad_base != expected_bad or bad_build:
        raise VerificationError(
            f"code-pointer identity failed: {total_base}/{bad_base} -> {total_build}/{bad_build}"
        )
    for offset, (_broken, original) in POINTERS.items():
        if word(build[PSX], offset) != original or word(pristine[PSX], offset) != original:
            raise VerificationError(f"pointer word restore mismatch at 0x{offset:X}")
        target = original - RAM_TO_FILE
        if build[PSX][target:target + 64] != pristine[PSX][target:target + 64]:
            raise VerificationError(f"target body mismatch at 0x{original:08X}")

    exe = build[PSX]
    if sha_bytes(exe[FORMATTER_AT:FORMATTER_AT + FORMATTER_SIZE]) != FORMATTER_SHA:
        raise VerificationError("floor formatter changed")
    if word(exe, 0x823B0) != RAM_TO_FILE + 0x809F4:
        raise VerificationError("floor prefix pointer changed")
    if word(exe, 0x823B4) != RAM_TO_FILE + 0x8215C:
        raise VerificationError("floor suffix pointer changed")
    if exe[0x809F4:0x809F8] != bytes.fromhex("04 19 A1 00"):
        raise VerificationError("지하 prefix payload mismatch")
    if exe[0x8215C:0x8215F] != bytes.fromhex("DE 50 00"):
        raise VerificationError("층 suffix payload mismatch")

    for member, slot, meta, reference, payload in SLOT_SPECS:
        block = slot_block(build[member], slot)
        if block[:len(payload)] != payload or block[len(payload)] != 0:
            raise VerificationError(f"slot payload mismatch: {member} {slot}")
        if any(block[len(payload) + 1:SLOT_META]):
            raise VerificationError(f"slot zero-fill mismatch: {member} {slot}")
        if block[SLOT_META] != meta:
            raise VerificationError(f"slot completion mismatch: {member} {slot}")
        if slot_references(build[member], slot) != [reference]:
            raise VerificationError(f"slot ownership mismatch: {member} {slot}")

    for offset, (before, after, slot, body_len) in CALLS.items():
        old_body = body(base[S5021], offset)
        new_body = body(build[S5021], offset)
        if len(old_body) != body_len or len(new_body) != body_len:
            raise VerificationError(f"body length changed at 0x{offset:X}")
        if old_body[:2] != before or new_body[:2] != after:
            raise VerificationError(f"E2 call bytes mismatch at 0x{offset:X}")
        if new_body[2:] != old_body[2:]:
            raise VerificationError(f"shared body tail changed at 0x{offset:X}")
        if 2 + slot_block(build[S5021], slot)[SLOT_META] != body_len:
            raise VerificationError(f"completion target mismatch at 0x{offset:X}")

    if sha_bytes(slot_block(build[S5021], REPEAT_SLOT)) != REPEAT_HASH:
        raise VerificationError("source-authentic repetition changed")
    if slot_references(build[S5021], REPEAT_SLOT) != [REPEAT_REF]:
        raise VerificationError("repetition reference changed")
    for offset, size in CURSOR_RANGES:
        if build[PSX][offset:offset + size] != base[PSX][offset:offset + size]:
            raise VerificationError(f"choice/range cursor range changed at 0x{offset:X}")

    report = {
        "verdict": "PASS",
        "archive": {
            "members": len(build_names),
            "changed_members": changed_members,
            "changed_bytes": {name: len(actual[name]) for name in changed_members},
            "full_sha256": BUILD_SHA,
            "delta_sha256": DELTA_SHA,
        },
        "code_pointer_census": {
            "total": total_build,
            "v346_mismatches": len(bad_base),
            "v347_mismatches": len(bad_build),
        },
        "floor": "지하 n층 formatter inputs PASS",
        "dialogue_slots": "5/5 payload, metadata, ownership and shared tails PASS",
        "repetition": "preserved",
        "COMM_IMG": "byte exact",
        "choice_cursor": "byte exact/deferred",
        "runtime": "PENDING user cold boot",
    }
    ANALYSIS.mkdir(parents=True, exist_ok=True)
    (ANALYSIS / "independent_verification.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    lines = [
        "V347 independent verification PASS",
        f"archives={BUILD_SHA} delta={DELTA_SHA}",
        "members=164 changed=5/S5011.DAT,5/S5021.DAT,PSX.EXE bytes=58/118/8",
        "code pointers=5311 candidates; V346 mismatches 2; V347 mismatches 0",
        "floor=formatter code/pointers unchanged; inputs emit 지하 n층",
        "dialogue=5/5 slots, completion metadata, E2 ownership and shared tails PASS",
        "repetition=source-authentic duplicate preserved",
        "COMM.IMG and choice/range cursor ranges byte exact",
        "runtime=PENDING user cold boot; TEST_ONLY",
    ]
    (ANALYSIS / "independent_verification.txt").write_text(
        "\n".join(lines) + "\n", encoding="utf-8"
    )
    print("\n".join(lines))


if __name__ == "__main__":
    main()
