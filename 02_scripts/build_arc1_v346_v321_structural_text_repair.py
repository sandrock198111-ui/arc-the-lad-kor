#!/usr/bin/env python3
"""Build V346: undo V321's non-text AB->64 damage and repair four texts.

V321 reassigned the old one-byte 0xAB glyph from ``몬`` to ``괄``.  Its
``text_regions`` census accidentally included executable/data structures, so
57 PSX.EXE bytes were rewritten from AB to 64.  Later pointer-table rebuilds
superseded 21 of those writes and two remaining bytes are genuine ``몬`` text.
The other 34 bytes are structural data and are restored here from V320C.

This build is deliberately based on runtime-observed V345.  It does not touch
COMM.IMG or any cursor/render timing code.
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


BASE = ROOT / "03_output/arc1_v345_story_timing_cursor_recovery_TEST_ONLY_AB9A8E99.zip"
BASE_SHA256 = "AB9A8E99707D4E11EF0878E65451AA0DAD441328C6EDE9277E6142A9164BC54D"
BASE_PSX_SHA256 = "C4572A888018DC24325E30E6250B60513058C24D74DBF0E1CA95EA2DA1E82AD3"
BASE_S4031_SHA256 = "8A21D64DCF8955727D5FC96DFE661FB59A9C73568C3E66BC789E880725D2564A"

V320C = ROOT / "03_output/arc1_v320c_hanme_official_beol_TEST_ONLY_81D215E1.zip"
V320C_SHA256 = "81D215E1B1138E26707353D8982AE3139AE4F3900F6E832FEC83BB66A43AEA8D"
V321 = ROOT / "03_output/arc1_v321_text_identity_repair_TEST_ONLY_1B04A832.zip"
V321_SHA256 = "1B04A832B33BF061A1AAC8BEE1186B53D6FE977ACA5295C6B5A019CD0759DDFF"

OUTPUT_STEM = "arc1_v346_v321_structural_text_repair_TEST_ONLY"
DELTA_STEM = OUTPUT_STEM + "_delta_from_v345"
ANALYSIS = ROOT / "01_work/analysis/arc1_v346_v321_structural_text_repair"

PSX = "PSX.EXE"
S4031 = "4/S4031.DAT"
RAM_TO_FILE = 0x8011A800

# Two bytes that really are the one-byte code for 몬.  These must remain 0x64.
REAL_MON_OFFSETS = (0x82382, 0x82407)

# V321's false-positive text writes that remain live in V345.
NUMERIC_TABLE_OFFSETS = (0x7B760, 0x7B784, 0x7EB54)
DISPATCH_POINTER_BYTE = 0x7C005
STRUCT_FIELD_OFFSETS = tuple(0x7F94E + index * 0x3A for index in range(30))
RESTORE_OFFSETS = (
    *NUMERIC_TABLE_OFFSETS,
    DISPATCH_POINTER_BYTE,
    *STRUCT_FIELD_OFFSETS,
)

# The other 21 V321 writes were pointer bytes superseded by later UI rebuilds.
LATER_REBUILT_POINTER_OFFSETS = (
    *(0x804F1 + index * 4 for index in range(20)),
    0x829B0,
)

DISPATCH_TABLE_FILE = 0x7B9E8
DISPATCH_INDEX = 391
DISPATCH_ENTRY_FILE = DISPATCH_TABLE_FILE + DISPATCH_INDEX * 4
BAD_DISPATCH_TARGET = 0x8014643C
GOOD_DISPATCH_TARGET = 0x8014AB3C
GOOD_DISPATCH_TARGET_FILE = GOOD_DISPATCH_TARGET - RAM_TO_FILE

# Same-size story fixes observed in the user's V345 states.
STORY_BYTE_EDITS = {
    0x47F9F: (0x0D, 0x0E, "안쪽을_to_안쪽에"),
    0x48519: (0x02, 0xA9, "좋아터_to_좋아!"),
    0x48527: (0x0F, 0x21, "찾자의_to_찾자."),
}

STORY_A_AT = 0x47F7A
STORY_A_BEFORE = bytes.fromhex(
    "DD BA 4E D5 A1 7E A1 1A DD 31 0E A1 33 DD 70 03 A1 DD D9 A1 "
    "1C 37 0F A1 24 DD 72 26 A1 83 3D DD A7 A1 94 DD 69 0D"
)
STORY_A_AFTER = STORY_A_BEFORE[:-1] + bytes((0x0E,))
STORY_B_AT = 0x48516
STORY_B_BEFORE = bytes.fromhex(
    "DD 0D 09 02 A1 1C 37 0F A1 24 DD 72 0D A1 DD 56 28 0F"
)
STORY_B_AFTER = bytes.fromhex(
    "DD 0D 09 A9 A1 1C 37 0F A1 24 DD 72 0D A1 DD 56 28 21"
)

# Skill-level-up suffix: ｢skill｣느레벨 상승 -> ｢skill｣ 레벨 상승.
LEVEL_SUFFIX_FILE = 0x82924
LEVEL_SUFFIX_BYTE = 0x82926
LEVEL_SUFFIX_POINTER = 0x82558
LEVEL_SUFFIX_BEFORE = bytes.fromhex("DF 09 4D 00")
LEVEL_SUFFIX_AFTER = bytes.fromhex("DF 09 A1 00")

# Restore the V124/V145 terminology decision in proven-live V325/V326 pools.
MIRUMANA_STANDALONE_FILE = 0x80944
MIRUMANA_AIRPORT_FILE = 0x80982
MIRUMANA_HQ_FILE = 0x81A1F
MIRUMANA_STANDALONE = bytes.fromhex("DD 2F 70 45 1E 00")
MIRUMANA_AIRPORT = bytes.fromhex("DD 2F 70 45 1E A1 DD 10 DD F2 00")
MIRUMANA_HQ = bytes.fromhex("DD 2F 70 45 1E A1 7C DD 58 6C 00")
MIRUMANA_POINTERS = {
    0x81EEC: MIRUMANA_STANDALONE_FILE,
    0x81E58: MIRUMANA_AIRPORT_FILE,
    0x8219C: MIRUMANA_AIRPORT_FILE,
    0x821A0: MIRUMANA_HQ_FILE,
}
OLD_MILMANA_STANDALONE_FILE = 0x80818
OLD_MILMANA_AIRPORT_FILE = 0x81A2A
OLD_MILMANA_HQ_FILE = 0x81A20
OLD_MILMANA_STANDALONE = bytes.fromhex("DE 33 45 1E 00")
OLD_MILMANA_AIRPORT = bytes.fromhex("DE 33 45 1E A1 DD 10 DD F2 00")
OLD_MILMANA_HQ = bytes.fromhex("DE 33 45 1E A1 7C DD 58 6C 00")


class BuildError(RuntimeError):
    pass


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def word(data: bytes | bytearray, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def put_word(data: bytearray, offset: int, value: int) -> None:
    struct.pack_into("<I", data, offset, value)


def pointer(file_offset: int) -> int:
    return RAM_TO_FILE + file_offset


def archive(path: Path, expected_hash: str) -> tuple[list[str], dict[str, bytes]]:
    if not path.is_file() or sha(path.read_bytes()) != expected_hash:
        raise BuildError(f"archive hash drift: {path.name}")
    return v345.read_archive(path)


def assert_v321_census(v320c: bytes, v321: bytes, base: bytes) -> None:
    diffs = [index for index, pair in enumerate(zip(v320c, v321, strict=True)) if pair[0] != pair[1]]
    if len(diffs) != 57 or any((v320c[index], v321[index]) != (0xAB, 0x64) for index in diffs):
        raise BuildError("V320C->V321 57-byte AB->64 census drift")
    expected = set(RESTORE_OFFSETS) | set(REAL_MON_OFFSETS) | set(LATER_REBUILT_POINTER_OFFSETS)
    if set(diffs) != expected or len(expected) != 57:
        raise BuildError("V321 57-byte classification is no longer complete")
    if any(base[index] != 0x64 for index in (*RESTORE_OFFSETS, *REAL_MON_OFFSETS)):
        raise BuildError("V345 retained V321 bytes drift")
    if any(v320c[index] != 0xAB for index in RESTORE_OFFSETS):
        raise BuildError("V320C structural source drift")
    if base[0x8237C:0x8238D] != bytes.fromhex(
        "C9 8F DE 74 4D 9C 64 6F 8D 9C 5E E1 9C 9C E1 90 69"
    ):
        raise BuildError("real 몬스터 UI text drift")
    if base[0x82403:0x82410] != bytes.fromhex(
        "78 E0 C3 95 64 DF 41 9C E1 C1 6F E0 ED"
    ):
        raise BuildError("real 다이아몬드 UI text drift")


def assert_base(base: dict[str, bytes], v320c: bytes, v321: bytes) -> None:
    if len(base) != 164:
        raise BuildError("V345 archive topology drift")
    if sha(base[PSX]) != BASE_PSX_SHA256 or sha(base[S4031]) != BASE_S4031_SHA256:
        raise BuildError("V345 base member hash drift")
    exe = base[PSX]
    dat = base[S4031]
    assert_v321_census(v320c, v321, exe)

    if DISPATCH_ENTRY_FILE != 0x7C004:
        raise BuildError("dispatcher index arithmetic drift")
    if word(exe, DISPATCH_ENTRY_FILE) != BAD_DISPATCH_TARGET:
        raise BuildError("V345 freeze dispatcher premise drift")
    if word(v320c, DISPATCH_ENTRY_FILE) != GOOD_DISPATCH_TARGET:
        raise BuildError("V320C dispatcher source drift")
    if exe[GOOD_DISPATCH_TARGET_FILE:GOOD_DISPATCH_TARGET_FILE + 32] != v320c[
        GOOD_DISPATCH_TARGET_FILE:GOOD_DISPATCH_TARGET_FILE + 32
    ]:
        raise BuildError("good dispatcher handler body drift")

    for offset in NUMERIC_TABLE_OFFSETS:
        if exe[offset] != 0x64 or v320c[offset] != 0xAB:
            raise BuildError(f"numeric table premise drift at 0x{offset:X}")
    if any(struct.unpack_from("<H", exe, offset)[0] != 0x64 for offset in STRUCT_FIELD_OFFSETS):
        raise BuildError("V345 stride-0x3A structure field drift")
    if any(struct.unpack_from("<H", v320c, offset)[0] != 0xAB for offset in STRUCT_FIELD_OFFSETS):
        raise BuildError("V320C stride-0x3A source field drift")

    if dat[STORY_A_AT:STORY_A_AT + len(STORY_A_BEFORE)] != STORY_A_BEFORE:
        raise BuildError("안쪽을 source body drift")
    if dat[STORY_B_AT:STORY_B_AT + len(STORY_B_BEFORE)] != STORY_B_BEFORE:
        raise BuildError("좋아터/찾자의 source body drift")
    if dat[STORY_A_AT + len(STORY_A_BEFORE):STORY_A_AT + len(STORY_A_BEFORE) + 3] != b"\xA1\xA1\x00":
        raise BuildError("first story terminator/padding drift")
    if dat[STORY_B_AT + len(STORY_B_BEFORE):STORY_B_AT + len(STORY_B_BEFORE) + 2] != b"\xA1\x00":
        raise BuildError("second story terminator/padding drift")

    if exe[LEVEL_SUFFIX_FILE:LEVEL_SUFFIX_FILE + 4] != LEVEL_SUFFIX_BEFORE:
        raise BuildError("느레벨 suffix premise drift")
    if word(exe, LEVEL_SUFFIX_POINTER) != pointer(LEVEL_SUFFIX_FILE):
        raise BuildError("skill-level suffix pointer drift")

    if exe[MIRUMANA_STANDALONE_FILE:MIRUMANA_STANDALONE_FILE + 12] != bytes(12):
        raise BuildError("standalone live pool is no longer empty")
    if exe[MIRUMANA_AIRPORT_FILE:MIRUMANA_AIRPORT_FILE + 14] != bytes(14):
        raise BuildError("airport live pool is no longer empty")
    if exe[MIRUMANA_HQ_FILE:MIRUMANA_HQ_FILE + len(MIRUMANA_HQ)] != b"\x00" + OLD_MILMANA_HQ:
        raise BuildError("HQ one-byte growth premise drift")
    if exe[OLD_MILMANA_STANDALONE_FILE:OLD_MILMANA_STANDALONE_FILE + len(OLD_MILMANA_STANDALONE)] != OLD_MILMANA_STANDALONE:
        raise BuildError("old standalone 밀마나 text drift")
    if exe[OLD_MILMANA_AIRPORT_FILE:OLD_MILMANA_AIRPORT_FILE + len(OLD_MILMANA_AIRPORT)] != OLD_MILMANA_AIRPORT:
        raise BuildError("old airport 밀마나 text drift")
    old_targets = {
        0x81EEC: OLD_MILMANA_STANDALONE_FILE,
        0x81E58: OLD_MILMANA_AIRPORT_FILE,
        0x8219C: OLD_MILMANA_AIRPORT_FILE,
        0x821A0: OLD_MILMANA_HQ_FILE,
    }
    for at, target in old_targets.items():
        if word(exe, at) != pointer(target):
            raise BuildError(f"old 밀마나 pointer drift at 0x{at:X}")


def build_once(base: dict[str, bytes], v320c: bytes, v321: bytes) -> dict[str, bytes]:
    assert_base(base, v320c, v321)
    final = dict(base)

    dat = bytearray(base[S4031])
    for offset, (before, after, _purpose) in STORY_BYTE_EDITS.items():
        if dat[offset] != before:
            raise BuildError(f"story byte drift at 0x{offset:X}")
        dat[offset] = after
    if dat[STORY_A_AT:STORY_A_AT + len(STORY_A_AFTER)] != STORY_A_AFTER:
        raise BuildError("안쪽에 readback failed")
    if dat[STORY_B_AT:STORY_B_AT + len(STORY_B_AFTER)] != STORY_B_AFTER:
        raise BuildError("좋아!/찾자. readback failed")
    final[S4031] = bytes(dat)

    exe = bytearray(base[PSX])
    for offset in RESTORE_OFFSETS:
        if exe[offset] != 0x64:
            raise BuildError(f"structural restore premise drift at 0x{offset:X}")
        exe[offset] = 0xAB

    if exe[LEVEL_SUFFIX_FILE:LEVEL_SUFFIX_FILE + 4] != LEVEL_SUFFIX_BEFORE:
        raise BuildError("level suffix changed during structural restore")
    exe[LEVEL_SUFFIX_BYTE] = 0xA1

    exe[MIRUMANA_STANDALONE_FILE:MIRUMANA_STANDALONE_FILE + len(MIRUMANA_STANDALONE)] = MIRUMANA_STANDALONE
    exe[MIRUMANA_AIRPORT_FILE:MIRUMANA_AIRPORT_FILE + len(MIRUMANA_AIRPORT)] = MIRUMANA_AIRPORT
    exe[MIRUMANA_HQ_FILE:MIRUMANA_HQ_FILE + len(MIRUMANA_HQ)] = MIRUMANA_HQ
    for at, target in MIRUMANA_POINTERS.items():
        put_word(exe, at, pointer(target))
    final[PSX] = bytes(exe)

    # Post-build structural and ownership guards.
    if word(exe, DISPATCH_ENTRY_FILE) != GOOD_DISPATCH_TARGET:
        raise BuildError("dispatcher pointer restore failed")
    if exe[GOOD_DISPATCH_TARGET_FILE:GOOD_DISPATCH_TARGET_FILE + 32] != v320c[
        GOOD_DISPATCH_TARGET_FILE:GOOD_DISPATCH_TARGET_FILE + 32
    ]:
        raise BuildError("dispatcher handler body changed")
    if any(exe[offset] != 0xAB for offset in RESTORE_OFFSETS):
        raise BuildError("one or more structural bytes were not restored")
    if any(exe[offset] != 0x64 for offset in REAL_MON_OFFSETS):
        raise BuildError("real 몬 text was damaged")
    if exe[LEVEL_SUFFIX_FILE:LEVEL_SUFFIX_FILE + 4] != LEVEL_SUFFIX_AFTER:
        raise BuildError("level suffix readback failed")
    for at, target in MIRUMANA_POINTERS.items():
        if word(exe, at) != pointer(target):
            raise BuildError(f"미르마나 pointer readback failed at 0x{at:X}")
    if exe[MIRUMANA_STANDALONE_FILE:MIRUMANA_STANDALONE_FILE + len(MIRUMANA_STANDALONE)] != MIRUMANA_STANDALONE:
        raise BuildError("미르마나 standalone readback failed")
    if exe[MIRUMANA_AIRPORT_FILE:MIRUMANA_AIRPORT_FILE + len(MIRUMANA_AIRPORT)] != MIRUMANA_AIRPORT:
        raise BuildError("미르마나 공항 readback failed")
    if exe[MIRUMANA_HQ_FILE:MIRUMANA_HQ_FILE + len(MIRUMANA_HQ)] != MIRUMANA_HQ:
        raise BuildError("미르마나 군본부 readback failed")
    if final[v345.COMM] != base[v345.COMM]:
        raise BuildError("COMM.IMG changed")
    return final


def allowed_offsets() -> dict[str, set[int]]:
    psx = set(RESTORE_OFFSETS)
    psx.add(LEVEL_SUFFIX_BYTE)
    psx.update(range(MIRUMANA_STANDALONE_FILE, MIRUMANA_STANDALONE_FILE + len(MIRUMANA_STANDALONE)))
    psx.update(range(MIRUMANA_AIRPORT_FILE, MIRUMANA_AIRPORT_FILE + len(MIRUMANA_AIRPORT)))
    psx.update(range(MIRUMANA_HQ_FILE, MIRUMANA_HQ_FILE + len(MIRUMANA_HQ)))
    for at in MIRUMANA_POINTERS:
        psx.update(range(at, at + 4))
    return {PSX: psx, S4031: set(STORY_BYTE_EDITS)}


def purpose(member: str, offset: int) -> str:
    if member == S4031:
        return STORY_BYTE_EDITS[offset][2]
    if offset in RESTORE_OFFSETS:
        if offset == DISPATCH_POINTER_BYTE:
            return "restore_skill_use_dispatch_pointer_byte"
        if offset in NUMERIC_TABLE_OFFSETS:
            return "restore_v321_misclassified_numeric_table"
        return "restore_v321_misclassified_stride_3A_struct_field"
    if offset == LEVEL_SUFFIX_BYTE:
        return "느레벨_to_space_레벨"
    if MIRUMANA_STANDALONE_FILE <= offset < MIRUMANA_STANDALONE_FILE + len(MIRUMANA_STANDALONE):
        return "write_live_pool_미르마나"
    if MIRUMANA_AIRPORT_FILE <= offset < MIRUMANA_AIRPORT_FILE + len(MIRUMANA_AIRPORT):
        return "write_live_pool_미르마나_공항"
    if MIRUMANA_HQ_FILE <= offset < MIRUMANA_HQ_FILE + len(MIRUMANA_HQ):
        return "grow_in_place_미르마나_군본부"
    for at in MIRUMANA_POINTERS:
        if at <= offset < at + 4:
            return "repoint_미르마나_UI"
    raise BuildError(f"unclassified write {member}:0x{offset:X}")


def main() -> None:
    names, base = archive(BASE, BASE_SHA256)
    _v320_names, v320_members = archive(V320C, V320C_SHA256)
    _v321_names, v321_members = archive(V321, V321_SHA256)
    final = build_once(base, v320_members[PSX], v321_members[PSX])
    rebuilt = build_once(base, v320_members[PSX], v321_members[PSX])
    if final != rebuilt:
        raise BuildError("in-memory deterministic rebuild mismatch")
    if any(len(final[name]) != len(base[name]) for name in names):
        raise BuildError("member size changed")

    changed_members = [name for name in names if final[name] != base[name]]
    if changed_members != [S4031, PSX]:
        raise BuildError(f"changed member order/set drift: {changed_members}")
    actual = {name: v345.changed_offsets(base[name], final[name]) for name in changed_members}
    allowed = allowed_offsets()
    for name in changed_members:
        if not actual[name] or not actual[name] <= allowed[name]:
            raise BuildError(f"Expected-Write envelope violation: {name}")
    if actual[S4031] != set(STORY_BYTE_EDITS):
        raise BuildError("story actual-write set drift")
    if not set(RESTORE_OFFSETS) <= actual[PSX]:
        raise BuildError("one or more structural restores produced no write")

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

    restore_rows = [
        {
            "offset": f"0x{offset:X}",
            "category": (
                "dispatcher_pointer" if offset == DISPATCH_POINTER_BYTE else
                "numeric_table" if offset in NUMERIC_TABLE_OFFSETS else
                "stride_0x3A_struct_field"
            ),
            "v320c": f"{v320_members[PSX][offset]:02X}",
            "v321": f"{v321_members[PSX][offset]:02X}",
            "v345": f"{base[PSX][offset]:02X}",
            "v346": f"{final[PSX][offset]:02X}",
        }
        for offset in RESTORE_OFFSETS
    ]
    with (ANALYSIS / "v321_false_text_restores.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(restore_rows[0]))
        writer.writeheader()
        writer.writerows(restore_rows)

    manifest = {
        "version": "V346",
        "status": "STATIC_PASS_RUNTIME_PENDING",
        "base": {"file": BASE.name, "sha256": BASE_SHA256, "runtime": "PASS_EXCEPT_SKILL_USE_FREEZE"},
        "output": {"file": output.name, "sha256": output_hash},
        "delta": {"file": delta.name, "sha256": delta_hash},
        "changed_members_vs_v345": changed_members,
        "changed_bytes": {name: len(actual[name]) for name in changed_members},
        "v321_census": {
            "total_AB_to_64": 57,
            "restore_nontext": len(RESTORE_OFFSETS),
            "preserve_real_mon_text": len(REAL_MON_OFFSETS),
            "later_rebuilt_pointers": len(LATER_REBUILT_POINTER_OFFSETS),
        },
        "freeze": {
            "dispatcher_index": DISPATCH_INDEX,
            "entry_file": f"0x{DISPATCH_ENTRY_FILE:X}",
            "before": f"0x{BAD_DISPATCH_TARGET:08X}",
            "after": f"0x{GOOD_DISPATCH_TARGET:08X}",
        },
        "texts": [
            "앞으로 네 여행에 도움이 될 고대의 기록은 토우빌 안쪽에",
            "좋아! 고대의 기록을 찾자.",
            "｢기술명｣ 레벨 상승",
            "미르마나 / 미르마나 공항 / 미르마나 군본부",
        ],
        "regression_guards": {
            "COMM_IMG": "byte exact",
            "real_mon_tokens": [f"0x{offset:X}" for offset in REAL_MON_OFFSETS],
            "cursor_timing": "V345 byte exact outside declared writes",
            "all_member_sizes": "byte exact",
        },
        "runtime": "PENDING user cold boot; TEST_ONLY",
    }
    (ANALYSIS / "build_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    report = [
        "V346 V321 structural + text repair",
        f"base={BASE.name} sha256={BASE_SHA256}",
        f"output={output.name} sha256={output_hash}",
        f"delta={delta.name} sha256={delta_hash}",
        f"PSX.EXE sha256={sha(final[PSX])}",
        f"changed_members={','.join(changed_members)}",
        f"changed_bytes={json.dumps({name: len(actual[name]) for name in changed_members}, ensure_ascii=False)}",
        "V321 census=57 total: 34 nontext restored, 2 real 몬 preserved, 21 later pointers preserved",
        "freeze=dispatcher[391] 0x8014643C -> 0x8014AB3C",
        "story=안쪽에; 좋아! 고대의 기록을 찾자.",
        "UI=느레벨 -> 레벨; 밀마나 -> 미르마나 three live strings",
        "COMM.IMG and all cursor/timing ranges unchanged",
        "runtime=PENDING user cold boot; TEST_ONLY",
    ]
    (ANALYSIS / "build_report.txt").write_text("\n".join(report) + "\n", encoding="utf-8")
    (ANALYSIS / "runtime_checklist.txt").write_text(
        "V346 cold-boot checklist\n"
        "1. 슬롯 5 위치에서 기술을 선택·사용해 프리징 없이 범위 커서와 행동이 진행되는지 확인.\n"
        "2. 고대의 기록 대사가 '토우빌 안쪽에', '좋아! ... 찾자.'로 표시되는지 확인.\n"
        "3. 슬로우 에너미·큐어 레벨업 배너가 '｣ 레벨 상승'으로 표시되는지 확인.\n"
        "4. 월드맵과 지역 UI의 미르마나/미르마나 공항/미르마나 군본부를 확인.\n"
        "5. 몬스터 도감과 다이아몬드 더스트의 '몬'이 정상인지 확인.\n"
        "6. V345의 아이템·기술 범위 커서 및 대화 타이밍이 그대로인지 확인.\n",
        encoding="utf-8",
    )
    print("\n".join(report))


if __name__ == "__main__":
    main()
