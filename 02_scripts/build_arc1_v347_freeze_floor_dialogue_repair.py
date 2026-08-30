#!/usr/bin/env python3
"""Build V347: restore two code pointers, Korean floor labels, and five lines.

The V346 runtime states prove that two original aligned code pointers were
mistaken for text targets by older global repointers.  One is the immediate
cause of the skill-use self-overwrite freeze; the other is a latent indirect
call to an odd address.  Both are restored from the immutable Japanese disc.

The dungeon-floor formatter is left untouched.  Its existing
``prefix + decimal number + suffix`` inputs become ``지하 `` and ``층``.

Five approved dialogue revisions are stored in their existing E2 slots.  Two
S5021 call sites whose E2 opcodes had been flattened back to inline text are
restored without changing their shared tails or completion metadata.
"""

from __future__ import annotations

import csv
import hashlib
import json
import struct
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

import build_arc1_v345_story_timing_cursor_recovery as v345  # noqa: E402


BASE = ROOT / "03_output/arc1_v346_v321_structural_text_repair_TEST_ONLY_30A40DD7.zip"
BASE_SHA256 = "30A40DD7560CAEC5F9C464BC0166EDC00FADAB9F95823748B44AF260334890B8"
PRISTINE = ROOT / "00_original/arc.zip"
PRISTINE_SHA256 = "AE9F4366A1E7DA3805BB3BED3DDA9567E4CD4E669AF890E4E2A620D7861F11DD"

OUTPUT_STEM = "arc1_v347_freeze_floor_dialogue_repair_TEST_ONLY"
DELTA_STEM = OUTPUT_STEM + "_delta_from_v346"
ANALYSIS = ROOT / "01_work/analysis/arc1_v347_freeze_floor_dialogue_repair"

PSX = "PSX.EXE"
COMM = "COMM.IMG"
S5011 = "5/S5011.DAT"
S5021 = "5/S5021.DAT"

BASE_MEMBER_SHA256 = {
    PSX: "11D8B8B737FA34BED7C05F5005AF32398AB8C838E7537A7D274DF19B65E50F1A",
    S5011: "463652B98020711E00A92A0DC463636BA57BA7A350B097BFF14444733204B5FF",
    S5021: "E6DFD6521245A94364EF31374B88F386CFF841AEFE0B2D4042D26191A7A861F2",
    COMM: "A6681F1355007725328372CC6143EF21EEE43A9FDE91FD3DC2EF3461C6805405",
}
PRISTINE_MEMBER_SHA256 = {
    PSX: "947EBF893F2D46207EC7E32CA514E4EA670E0BED34EF2144B5F7FB0FDD15BC67",
    S5011: "F717437B78685D400FDC3BF471DB81A63029CC981377C872B285E52FA7DEE217",
    S5021: "57FE9A886E704D496C280CE6E241A9355BEAA39F830DE913D054AEE1E9CC4281",
}

RAM_TO_FILE = 0x8011A800
CODE_START = 0x8011B000
CODE_END = 0x80192800

# Original function-pointer words proven by the V346 runtime freeze and the
# immutable Japanese PSX.EXE.
CODE_POINTER_RESTORES = {
    0x7EF3C: (0x80168DE1, 0x80162CE0, "restore_latent_indirect_dispatch_id2"),
    0x8D788: (0x801204E0, 0x8012E2E0, "restore_skill_use_action_callback"),
}
TARGET_BODY_WINDOWS = {
    0x80162CE0: 64,
    0x8012E2E0: 64,
}

# Existing formatter at 0x8016974C concatenates [0x8019CBB0], a formatted
# decimal number, and [0x8019CBB4], then dynamically centres the result.
FLOOR_FORMATTER_FILE = 0x4EF4C
FLOOR_FORMATTER_SIZE = 0x50
FLOOR_FORMATTER_SHA256 = "ADDFAE0E7FDC55887733E00A0A4430E25B737EF3D2D7540BF3B0D2E8B99AE49C"
FLOOR_PREFIX_POINTER = 0x823B0
FLOOR_SUFFIX_POINTER = 0x823B4
FLOOR_PREFIX_FILE = 0x809F4
FLOOR_SUFFIX_FILE = 0x8215C
FLOOR_PREFIX_POINTER_VALUE = RAM_TO_FILE + FLOOR_PREFIX_FILE
FLOOR_SUFFIX_POINTER_VALUE = RAM_TO_FILE + FLOOR_SUFFIX_FILE
FLOOR_PREFIX_BEFORE = bytes.fromhex("00 00 00 00")
FLOOR_PREFIX_AFTER = bytes.fromhex("04 19 A1 00")  # "지하 " + NUL
FLOOR_SUFFIX_BEFORE = bytes.fromhex("DD B2 00")     # 階 + NUL
FLOOR_SUFFIX_AFTER = bytes.fromhex("DE 50 00")      # 층 + NUL

# Existing fixed E2 slots.  +0x7F is completion/skip metadata and must never be
# cleared.  The pinned encodings prevent an assignment-table change from
# silently altering the release.
SLOT_EDITS = (
    {
        "member": S5011,
        "slot": 2,
        "meta": 35,
        "before_sha256": "DBCA2D42996197DEFE99F9F883098803BB703FECB99A4FED9B758BCE9F6034C2",
        "text": "장사는 무슨 장사야, 이 자식아! 한 대 맞고 싶냐!",
        "encoded": bytes.fromhex(
            "56 34 06 A1 5F DD A0 A1 56 34 49 0D A1 03 A1 28 DD B5 09 02 "
            "A1 53 A1 37 A1 DD B1 1C A1 DD 4E DD 51 02"
        ),
        "reference": 0x4815A,
        "purpose": "naturalize_merchant_retort",
    },
    {
        "member": S5011,
        "slot": 4,
        "meta": 13,
        "before_sha256": "C329264DBA6674FF6AC82B3AFA26EA55B389C5525EC4E191B19679E18C43B28C",
        "text": "나도 이 일로 먹고사니까 말이지.",
        "encoded": bytes.fromhex(
            "1E 33 A1 03 A1 6B D5 A1 DE 66 1C 34 07 3B A1 1B 03 04 0F"
        ),
        "reference": 0x4810A,
        "purpose": "naturalize_merchant_livelihood",
    },
    {
        "member": S5021,
        "slot": 20,
        "meta": 22,
        "before_sha256": "B5BB25FDB03FD2711B4D66E491BB4EA786ED49F22D7EAEEF7EAAD206F984935C",
        "text": "네가 어떻게 먹고사는지 들으러 온 게 아니야.",
        "encoded": bytes.fromhex(
            "7E 0C A1 14 DD 44 41 A1 DE 66 1C 34 06 04 A1 0A 4E 20 A1 DD 5C "
            "A1 41 A1 09 07 49 0F"
        ),
        "reference": 0x47B70,
        "purpose": "naturalize_not_here_for_livelihood_story",
    },
    {
        "member": S5021,
        "slot": 21,
        "meta": 18,
        "before_sha256": "3B73352FE638FDB6A90514F5534F9E945F812A98B43A2240F7521AD9F3D64733",
        "text": "이제부터가 거래 이야기란 거지?",
        "encoded": bytes.fromhex(
            "03 66 6C 02 0C A1 32 DD 12 A1 03 49 24 DE 3E A1 32 04 D1"
        ),
        "reference": 0x47D3E,
        "purpose": "business_to_transaction_context",
    },
    {
        "member": S5021,
        "slot": 22,
        "meta": 43,
        "before_sha256": "3D9B6A7527E9EDADEFA47AE735AFE027B50A893E22A878D3293D57F8947ABE37",
        "text": "나는 유적에서 보물을 찾아 파는 모험가지.",
        "encoded": bytes.fromhex(
            "1E 06 A1 8A DD 09 0E 25 A1 60 6D 0D A1 DD 56 09 A1 DD 7B 06 A1 "
            "55 DD 54 0C 04 0F"
        ),
        "reference": 0x47B0E,
        "purpose": "naturalize_ruin_treasure_adventurer",
    },
)

# V320/V197 bulk insertion intended these two bodies to call slots 20 and 22.
# Their current completion values equal body_length - 2 exactly, so restoring
# only the E2 opcode/id preserves every shared-tail byte and resume target.
S5021_CALL_RESTORES = {
    0x47B0E: (bytes.fromhex("1E 06"), bytes.fromhex("E2 97"), 22, 45),
    0x47B70: (bytes.fromhex("7E A1"), bytes.fromhex("E2 95"), 20, 24),
}

REPETITION_SLOT = 8
REPETITION_SLOT_SHA256 = "70629AEE0B2816C285C9685C5873477C3DFCBFEED6C67AF607BFED06C374C793"
REPETITION_REFERENCE = 0x4791C


class BuildError(RuntimeError):
    pass


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def word(data: bytes | bytearray, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def put_word(data: bytearray, offset: int, value: int) -> None:
    struct.pack_into("<I", data, offset, value)


def archive(path: Path, expected_hash: str) -> tuple[list[str], dict[str, bytes]]:
    if not path.is_file() or sha(path.read_bytes()) != expected_hash:
        raise BuildError(f"archive hash drift: {path.name}")
    return v345.read_archive(path)


def code_pointer_mismatches(
    pristine: dict[str, bytes], candidate: dict[str, bytes]
) -> tuple[int, list[tuple[str, int, int, int]]]:
    names = [PSX] + [
        name for name in pristine
        if name.upper().endswith(".DAT") and name in candidate
    ]
    total = 0
    mismatches: list[tuple[str, int, int, int]] = []
    for name in names:
        old = pristine[name]
        new = candidate[name]
        for offset in range(0, min(len(old), len(new)) - 3, 4):
            original = word(old, offset)
            if CODE_START <= original < CODE_END:
                total += 1
                current = word(new, offset)
                if current != original:
                    mismatches.append((name, offset, original, current))
    return total, mismatches


def assert_slot(
    data: bytes, slot: int, expected_hash: str, expected_meta: int,
    expected_refs: list[int]
) -> None:
    block = v345.slot_block(data, slot)
    if sha(block) != expected_hash:
        raise BuildError(f"slot {slot} hash drift")
    if block[v345.SLOT_META] != expected_meta:
        raise BuildError(f"slot {slot} completion metadata drift")
    if v345.slot_references(data, slot) != expected_refs:
        raise BuildError(f"slot {slot} reference topology drift")


def assert_base(
    names: list[str], base: dict[str, bytes], pristine: dict[str, bytes]
) -> None:
    if len(names) != 164 or len(base) != 164:
        raise BuildError("V346 archive topology drift")
    for name, expected in BASE_MEMBER_SHA256.items():
        if sha(base[name]) != expected:
            raise BuildError(f"V346 member hash drift: {name}")
    for name, expected in PRISTINE_MEMBER_SHA256.items():
        if sha(pristine[name]) != expected:
            raise BuildError(f"pristine member hash drift: {name}")

    exe = base[PSX]
    original_exe = pristine[PSX]
    for offset, (before, original, _purpose) in CODE_POINTER_RESTORES.items():
        if word(exe, offset) != before or word(original_exe, offset) != original:
            raise BuildError(f"code pointer premise drift at 0x{offset:X}")
        target_file = original - RAM_TO_FILE
        size = TARGET_BODY_WINDOWS[original]
        if exe[target_file:target_file + size] != original_exe[target_file:target_file + size]:
            raise BuildError(f"original target body drift at 0x{original:08X}")

    total, mismatches = code_pointer_mismatches(pristine, base)
    expected_mismatches = [
        (PSX, offset, original, before)
        for offset, (before, original, _purpose) in sorted(CODE_POINTER_RESTORES.items())
    ]
    if total != 5311 or mismatches != expected_mismatches:
        raise BuildError(f"aligned code-pointer census drift: {total}, {mismatches}")

    if sha(exe[FLOOR_FORMATTER_FILE:FLOOR_FORMATTER_FILE + FLOOR_FORMATTER_SIZE]) != FLOOR_FORMATTER_SHA256:
        raise BuildError("dungeon-floor formatter drift")
    if word(exe, FLOOR_PREFIX_POINTER) != FLOOR_PREFIX_POINTER_VALUE:
        raise BuildError("floor prefix pointer drift")
    if word(exe, FLOOR_SUFFIX_POINTER) != FLOOR_SUFFIX_POINTER_VALUE:
        raise BuildError("floor suffix pointer drift")
    if exe[FLOOR_PREFIX_FILE:FLOOR_PREFIX_FILE + 4] != FLOOR_PREFIX_BEFORE:
        raise BuildError("floor prefix pool premise drift")
    if exe[FLOOR_SUFFIX_FILE:FLOOR_SUFFIX_FILE + 3] != FLOOR_SUFFIX_BEFORE:
        raise BuildError("floor suffix pool premise drift")

    for edit in SLOT_EDITS:
        expected_refs = [] if edit["member"] == S5021 and edit["slot"] in (20, 22) else [edit["reference"]]
        assert_slot(
            base[edit["member"]], edit["slot"], edit["before_sha256"],
            edit["meta"], expected_refs,
        )
    s5021 = base[S5021]
    for offset, (before, _after, slot, body_len) in S5021_CALL_RESTORES.items():
        payload = v345.body(s5021, offset)
        if len(payload) != body_len or payload[:2] != before:
            raise BuildError(f"S5021 call/body premise drift at 0x{offset:X}")
        if 2 + v345.slot_block(s5021, slot)[v345.SLOT_META] != body_len:
            raise BuildError(f"S5021 completion arithmetic drift at 0x{offset:X}")
    assert_slot(
        s5021, REPETITION_SLOT, REPETITION_SLOT_SHA256, 19,
        [REPETITION_REFERENCE],
    )


def rewrite_slot(data: bytearray, edit: dict[str, object]) -> None:
    slot = int(edit["slot"])
    code = bytes(edit["encoded"])
    if len(code) >= v345.SLOT_META:
        raise BuildError(f"slot {slot} payload overflow")
    start = v345.SLOT_BASE + slot * v345.SLOT_SIZE
    block = bytearray(v345.SLOT_SIZE)
    block[:len(code)] = code
    block[len(code)] = 0
    block[v345.SLOT_META] = int(edit["meta"])
    data[start:start + v345.SLOT_SIZE] = block


def build_once(
    names: list[str], base: dict[str, bytes], pristine: dict[str, bytes]
) -> dict[str, bytes]:
    assert_base(names, base, pristine)
    table = v345.character_codes()
    for edit in SLOT_EDITS:
        if v345.encode(str(edit["text"]), table) != edit["encoded"]:
            raise BuildError(f"pinned encoding drift: {edit['text']}")
    if v345.encode("지하 ", table) + b"\0" != FLOOR_PREFIX_AFTER:
        raise BuildError("floor prefix encoding drift")
    if v345.encode("층", table) + b"\0" != FLOOR_SUFFIX_AFTER:
        raise BuildError("floor suffix encoding drift")

    final = dict(base)

    exe = bytearray(base[PSX])
    for offset, (before, original, _purpose) in CODE_POINTER_RESTORES.items():
        if word(exe, offset) != before:
            raise BuildError(f"pointer changed before write at 0x{offset:X}")
        put_word(exe, offset, original)
    exe[FLOOR_PREFIX_FILE:FLOOR_PREFIX_FILE + 4] = FLOOR_PREFIX_AFTER
    exe[FLOOR_SUFFIX_FILE:FLOOR_SUFFIX_FILE + 3] = FLOOR_SUFFIX_AFTER
    final[PSX] = bytes(exe)

    s5011 = bytearray(base[S5011])
    for edit in SLOT_EDITS:
        if edit["member"] == S5011:
            rewrite_slot(s5011, edit)
    final[S5011] = bytes(s5011)

    s5021 = bytearray(base[S5021])
    for edit in SLOT_EDITS:
        if edit["member"] == S5021:
            rewrite_slot(s5021, edit)
    for offset, (before, after, _slot, _body_len) in S5021_CALL_RESTORES.items():
        if s5021[offset:offset + 2] != before:
            raise BuildError(f"call-site changed before write at 0x{offset:X}")
        s5021[offset:offset + 2] = after
    final[S5021] = bytes(s5021)

    # Post-build ownership, control-flow and preservation guards.
    total, mismatches = code_pointer_mismatches(pristine, final)
    if total != 5311 or mismatches:
        raise BuildError(f"code-pointer identity invariant failed: {total}, {mismatches}")
    if final[COMM] != base[COMM]:
        raise BuildError("COMM.IMG changed")
    if final[PSX][FLOOR_FORMATTER_FILE:FLOOR_FORMATTER_FILE + FLOOR_FORMATTER_SIZE] != base[PSX][
        FLOOR_FORMATTER_FILE:FLOOR_FORMATTER_FILE + FLOOR_FORMATTER_SIZE
    ]:
        raise BuildError("floor formatter code changed")
    if word(final[PSX], FLOOR_PREFIX_POINTER) != FLOOR_PREFIX_POINTER_VALUE:
        raise BuildError("floor prefix pointer changed")
    if word(final[PSX], FLOOR_SUFFIX_POINTER) != FLOOR_SUFFIX_POINTER_VALUE:
        raise BuildError("floor suffix pointer changed")

    for edit in SLOT_EDITS:
        member = str(edit["member"])
        block = v345.slot_block(final[member], int(edit["slot"]))
        code = bytes(edit["encoded"])
        if block[:len(code)] != code or block[len(code)] != 0:
            raise BuildError(f"slot payload readback failed: {member} {edit['slot']}")
        if any(block[len(code) + 1:v345.SLOT_META]):
            raise BuildError(f"slot zero-fill failed: {member} {edit['slot']}")
        if block[v345.SLOT_META] != edit["meta"]:
            raise BuildError(f"slot metadata changed: {member} {edit['slot']}")
        if v345.slot_references(final[member], int(edit["slot"])) != [edit["reference"]]:
            raise BuildError(f"slot reference restore failed: {member} {edit['slot']}")

    if sha(v345.slot_block(final[S5021], REPETITION_SLOT)) != REPETITION_SLOT_SHA256:
        raise BuildError("source-authentic repeated line changed")
    if v345.slot_references(final[S5021], REPETITION_SLOT) != [REPETITION_REFERENCE]:
        raise BuildError("repeated-line reference changed")
    for offset, (_before, after, slot, body_len) in S5021_CALL_RESTORES.items():
        payload = v345.body(final[S5021], offset)
        if len(payload) != body_len or payload[:2] != after:
            raise BuildError(f"E2 call restore readback failed at 0x{offset:X}")
        if 2 + v345.slot_block(final[S5021], slot)[v345.SLOT_META] != body_len:
            raise BuildError(f"E2 resume target changed at 0x{offset:X}")
    return final


def allowed_offsets() -> dict[str, set[int]]:
    result: dict[str, set[int]] = {PSX: set(), S5011: set(), S5021: set()}
    for offset in CODE_POINTER_RESTORES:
        result[PSX].update(range(offset, offset + 4))
    result[PSX].update(range(FLOOR_PREFIX_FILE, FLOOR_PREFIX_FILE + 4))
    result[PSX].update(range(FLOOR_SUFFIX_FILE, FLOOR_SUFFIX_FILE + 3))
    for edit in SLOT_EDITS:
        start = v345.SLOT_BASE + int(edit["slot"]) * v345.SLOT_SIZE
        result[str(edit["member"])].update(range(start, start + v345.SLOT_META))
    for offset in S5021_CALL_RESTORES:
        result[S5021].update(range(offset, offset + 2))
    return result


def purpose(member: str, offset: int) -> str:
    if member == PSX:
        for start, (_before, _after, label) in CODE_POINTER_RESTORES.items():
            if start <= offset < start + 4:
                return label
        if FLOOR_PREFIX_FILE <= offset < FLOOR_PREFIX_FILE + 4:
            return "floor_prefix_지하_space"
        if FLOOR_SUFFIX_FILE <= offset < FLOOR_SUFFIX_FILE + 3:
            return "floor_suffix_층"
    for edit in SLOT_EDITS:
        start = v345.SLOT_BASE + int(edit["slot"]) * v345.SLOT_SIZE
        if member == edit["member"] and start <= offset < start + v345.SLOT_META:
            return str(edit["purpose"])
    if member == S5021:
        for start, (_before, _after, slot, _body_len) in S5021_CALL_RESTORES.items():
            if start <= offset < start + 2:
                return f"restore_E2_slot_{slot}_call"
    raise BuildError(f"unclassified write {member}:0x{offset:X}")


def main() -> None:
    names, base = archive(BASE, BASE_SHA256)
    pristine_names, pristine = archive(PRISTINE, PRISTINE_SHA256)
    if not set(names) <= set(pristine_names):
        raise BuildError("one or more V346 members are absent from pristine archive")

    final = build_once(names, base, pristine)
    rebuilt = build_once(names, base, pristine)
    if final != rebuilt:
        raise BuildError("in-memory deterministic rebuild mismatch")
    if any(len(final[name]) != len(base[name]) for name in names):
        raise BuildError("member size changed")

    changed_members = [name for name in names if final[name] != base[name]]
    expected_members = [name for name in names if name in (S5011, S5021, PSX)]
    if changed_members != expected_members:
        raise BuildError(f"changed member order/set drift: {changed_members}")
    actual = {
        name: v345.changed_offsets(base[name], final[name])
        for name in changed_members
    }
    allowed = allowed_offsets()
    for name in changed_members:
        if not actual[name] or not actual[name] <= allowed[name]:
            raise BuildError(f"Expected-Write envelope violation: {name}")
    for start, (_before, after, _purpose) in CODE_POINTER_RESTORES.items():
        if word(final[PSX], start) != after:
            raise BuildError(f"pointer restore did not survive at 0x{start:X}")

    ANALYSIS.mkdir(parents=True, exist_ok=True)
    output_temp = ROOT / "03_output" / f"{OUTPUT_STEM}.zip"
    delta_temp = ROOT / "03_output" / f"{DELTA_STEM}.zip"
    for path in (output_temp, delta_temp):
        if path.exists():
            path.unlink()
    v345.write_archive(output_temp, names, final)
    v345.write_archive(delta_temp, changed_members, final)
    output_hash = sha(output_temp.read_bytes())
    delta_hash = sha(delta_temp.read_bytes())
    output = output_temp.with_name(f"{OUTPUT_STEM}_{output_hash[:8]}.zip")
    delta = delta_temp.with_name(f"{DELTA_STEM}_{delta_hash[:8]}.zip")
    for source, target in ((output_temp, output), (delta_temp, delta)):
        if target.exists():
            if sha(target.read_bytes()) != sha(source.read_bytes()):
                raise BuildError(f"existing output differs: {target.name}")
            source.unlink()
        else:
            source.replace(target)

    expected_rows: list[dict[str, str]] = []
    for name in changed_members:
        for offset in sorted(actual[name]):
            expected_rows.append({
                "member": name,
                "offset": f"0x{offset:X}",
                "before": f"{base[name][offset]:02X}",
                "after": f"{final[name][offset]:02X}",
                "purpose": purpose(name, offset),
            })
    with (ANALYSIS / "expected_writes.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(expected_rows[0]))
        writer.writeheader()
        writer.writerows(expected_rows)

    pointer_rows = [
        {
            "member": PSX,
            "file_offset": f"0x{offset:X}",
            "v346": f"0x{before:08X}",
            "pristine_v347": f"0x{after:08X}",
            "purpose": label,
        }
        for offset, (before, after, label) in sorted(CODE_POINTER_RESTORES.items())
    ]
    with (ANALYSIS / "code_pointer_restores.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(pointer_rows[0]))
        writer.writeheader()
        writer.writerows(pointer_rows)

    story_rows = [
        {
            "member": edit["member"],
            "slot": edit["slot"],
            "reference": f"0x{int(edit['reference']):X}",
            "completion": edit["meta"],
            "encoded_bytes": len(bytes(edit["encoded"])),
            "text": edit["text"],
        }
        for edit in SLOT_EDITS
    ]
    with (ANALYSIS / "story_revisions.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(story_rows[0]))
        writer.writeheader()
        writer.writerows(story_rows)

    manifest = {
        "version": "V347",
        "status": "STATIC_PASS_RUNTIME_PENDING",
        "base": {"file": BASE.name, "sha256": BASE_SHA256},
        "output": {"file": output.name, "sha256": output_hash},
        "delta": {"file": delta.name, "sha256": delta_hash},
        "changed_members_vs_v346": changed_members,
        "changed_bytes": {name: len(actual[name]) for name in changed_members},
        "code_pointer_census": {
            "original_aligned_code_pointers": 5311,
            "v346_mismatches": len(CODE_POINTER_RESTORES),
            "v347_mismatches": 0,
        },
        "floor": {
            "formatter": "prefix + decimal + suffix, unchanged",
            "prefix": "지하 ",
            "suffix": "층",
            "dynamic_centering": True,
        },
        "dialogue": [edit["text"] for edit in SLOT_EDITS],
        "preserved": {
            "choice_cursor": "byte exact; deferred pending second-selection state",
            "repeated_line": "기다렸지, 기다렸지. 무엇부터 이야기할까?",
            "COMM_IMG": "byte exact",
            "all_member_sizes": "byte exact",
        },
        "runtime": "PENDING user cold boot; TEST_ONLY",
    }
    (ANALYSIS / "build_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )

    report = [
        "V347 freeze + floor + dialogue repair",
        f"base={BASE.name} sha256={BASE_SHA256}",
        f"output={output.name} sha256={output_hash}",
        f"delta={delta.name} sha256={delta_hash}",
        f"changed_members={','.join(changed_members)}",
        f"changed_bytes={json.dumps({name: len(actual[name]) for name in changed_members}, ensure_ascii=False)}",
        "code pointers=5311 original aligned candidates / V346 mismatches 2 / V347 mismatches 0",
        "freeze=0x8D788 0x801204E0 -> 0x8012E2E0",
        "latent=0x7EF3C 0x80168DE1 -> 0x80162CE0",
        "floor=existing formatter now emits 지하 n층 and centres dynamically",
        "dialogue=5 approved revisions in slots 2,4,20,21,22",
        "repetition=source-authentic 기다렸지, 기다렸지 preserved",
        "choice cursor=unchanged/deferred; COMM.IMG=byte exact",
        "runtime=PENDING user cold boot; TEST_ONLY",
    ]
    (ANALYSIS / "build_report.txt").write_text("\n".join(report) + "\n", encoding="utf-8")
    (ANALYSIS / "runtime_checklist.txt").write_text(
        "V347 cold-boot checklist\n"
        "1. 슬롯 10 전투 상태에서 기술을 선택해 프리징 없이 범위 선택과 행동이 진행되는지 확인.\n"
        "2. 아이템 사용과 다른 기술도 각각 1회 실행해 간접 호출 회귀가 없는지 확인.\n"
        "3. 유적 각 층 진입 표시가 지하 1층/2층/... 형식이며 중앙 정렬되는지 확인.\n"
        "4. S5011/S5021의 수정된 다섯 문장을 확인.\n"
        "5. '기다렸지, 기다렸지.' 반복이 그대로인지 확인.\n"
        "6. 선택지 커서 위치와 V346 UI/대사/아이콘이 바뀌지 않았는지 확인.\n",
        encoding="utf-8",
    )
    print("\n".join(report))


if __name__ == "__main__":
    main()
