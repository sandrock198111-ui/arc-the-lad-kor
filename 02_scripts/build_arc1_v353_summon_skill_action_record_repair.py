#!/usr/bin/env python3
"""Build V353: restore the summon-healing action record corrupted in V207.

V207 searched PSX.EXE for a long zero run and used one beginning at RAM
0x801932E5 as relocated string storage.  That address is not free: it is the
second byte of a live 32-bit action ID at RAM 0x801932E4.  The write changed the
record's action word from 0x00000026 to 0xA352E026.  Runtime code copies its low
half (0xE026), sign-extends it, and indexes the action table with a negative
value, so the healing callback, animation, and MP spend never start.

This build restores only the three overwritten high bytes.  The stale bytes
after the 12-byte record are deliberately preserved because no live pointer to
them remains and clearing them is outside the proven repair envelope.
"""

from __future__ import annotations

import csv
import hashlib
import json
import struct
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo


ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "03_output/arc1_v352_punctuation_code_repair_TEST_ONLY_D4E8D2E2.zip"
BASE_SHA256 = "D4E8D2E24238123065DE0D3AF1F3FF4F7E82CCB9CB17ACEC5241AB3C2E6DDE3D"
ORIGINAL = ROOT / "00_original/arc.zip"
ORIGINAL_SHA256 = "AE9F4366A1E7DA3805BB3BED3DDA9567E4CD4E669AF890E4E2A620D7861F11DD"
V206 = ROOT / "03_output/arc1_v206_restore_zeroed_script_data.zip"
V206_SHA256 = "974AAC70D3DBFC3414AE81D71871AF010CF1DFF745CF0F836387C0DFBFA6CD5D"
V207 = ROOT / "03_output/arc1_v207_move_stub_strings.zip"
V207_SHA256 = "9C06092ED16307FECDE1F38E62B32933782AD22D5E1C199D4D0855F82595162E"

OUTPUT_STEM = "arc1_v353_summon_skill_action_record_repair_TEST_ONLY"
DELTA_STEM = OUTPUT_STEM + "_delta_from_v352"
ANALYSIS = ROOT / "01_work/analysis/arc1_v353_summon_skill_action_record_repair"

PSX = "PSX.EXE"
COMM = "COMM.IMG"
BASE_MEMBER_SHA256 = {
    PSX: "0D540C1E71C4546708B7C6C1D7328D58E31137ED4453EBCEB5B7F645A4764E1F",
    COMM: "A6681F1355007725328372CC6143EF21EEE43A9FDE91FD3DC2EF3461C6805405",
}

RAM_TO_FILE = 0x8011A800
RECORD_RAM = 0x801932DC
RECORD_FILE = RECORD_RAM - RAM_TO_FILE
ACTION_WORD_FILE = RECORD_FILE + 8
BEFORE_RECORD = bytes.fromhex("58 38 12 80 6C 3B 12 80 26 E0 52 A3")
AFTER_RECORD = bytes.fromhex("58 38 12 80 6C 3B 12 80 26 00 00 00")
REPAIRS = (
    (ACTION_WORD_FILE + 1, 0xE0, 0x00),
    (ACTION_WORD_FILE + 2, 0x52, 0x00),
    (ACTION_WORD_FILE + 3, 0xA3, 0x00),
)
RECORD_REFERENCES = (0x78B48, 0x78B58)
LIVE_POINTER_FILE = 0x82A6C
LIVE_POINTER_VALUE = 0x8019AF14
STALE_STRING_POINTERS = tuple(range(0x801932E5, 0x801932EB))

STATE_EVIDENCE = (
    ("V352_before_skill", "HASH-A58FDAA95812DA43_5.sav", "219EFF851AA23790FEA26F231F6CA7856139480C9D5E6EE812AC26F94887415B", "before summon skill"),
    ("V352_range_cursor", "HASH-A58FDAA95812DA43_6.sav", "0FF04FB0D1602212688610D7E48A2F9C0CD4E6584E1D5805F6A46725439F0612", "range cursor; global command 0xE026"),
    ("V352_after_confirm", "HASH-A58FDAA95812DA43_7.sav", "A79468F39ACBBB606832F3E0E43BEDB3D9F3FDADD904C06EA4D17C9B6260BD95", "confirm returned to movement without callback"),
    ("V352_afterward", "HASH-A58FDAA95812DA43_8.sav", "B5BB28F9C03EEB13A13D60689AE1A0E309C04ED70F693204776EDCA909F59DCE", "no animation, healing, or MP spend"),
    ("original_success", "SCPS-91302_1.sav", "59249BE32E809BB4A0128D1449A2BB793B2159ED9135484FE61D3869AB1A72AF", "original action 0x26 and callback active"),
)


class BuildError(RuntimeError):
    pass


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def read_archive(path: Path) -> tuple[list[str], dict[str, bytes]]:
    with ZipFile(path) as archive:
        names = [i.filename for i in archive.infolist() if not i.is_dir()]
        return names, {name: archive.read(name) for name in names}


def read_member(path: Path, member: str) -> bytes:
    with ZipFile(path) as archive:
        return archive.read(member)


def write_archive(path: Path, names: list[str], members: dict[str, bytes]) -> None:
    with ZipFile(path, "w", compression=ZIP_DEFLATED, compresslevel=9) as archive:
        for name in names:
            info = ZipInfo(name, date_time=(2026, 8, 31, 0, 0, 0))
            info.compress_type = ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, members[name], compress_type=ZIP_DEFLATED, compresslevel=9)


def assert_archive_hash(path: Path, expected: str, label: str) -> None:
    if not path.is_file() or sha(path.read_bytes()) != expected:
        raise BuildError(f"{label} archive hash drift")


def pointer_hits(members: dict[str, bytes]) -> list[tuple[str, int, int]]:
    hits: list[tuple[str, int, int]] = []
    for member, data in members.items():
        for pointer in STALE_STRING_POINTERS:
            needle = struct.pack("<I", pointer)
            start = 0
            while True:
                offset = data.find(needle, start)
                if offset < 0:
                    break
                hits.append((member, offset, pointer))
                start = offset + 1
    return hits


def provenance_guard() -> None:
    assert_archive_hash(ORIGINAL, ORIGINAL_SHA256, "original")
    assert_archive_hash(V206, V206_SHA256, "V206")
    assert_archive_hash(V207, V207_SHA256, "V207")
    original = read_member(ORIGINAL, PSX)
    v206 = read_member(V206, PSX)
    v207 = read_member(V207, PSX)
    if original[RECORD_FILE:RECORD_FILE + 12] != AFTER_RECORD:
        raise BuildError("original action record drift")
    if v206[RECORD_FILE:RECORD_FILE + 12] != AFTER_RECORD:
        raise BuildError("V206 action record drift")
    if v207[RECORD_FILE:RECORD_FILE + 12] != bytes.fromhex(
        "58 38 12 80 6C 3B 12 80 26 E0 0A A3"
    ):
        raise BuildError("V207 corruption provenance drift")


def assert_base(names: list[str], base: dict[str, bytes]) -> None:
    if len(names) != 164 or len(base) != 164:
        raise BuildError("V352 archive topology drift")
    for member, expected in BASE_MEMBER_SHA256.items():
        if sha(base[member]) != expected:
            raise BuildError(f"V352 member hash drift: {member}")
    exe = base[PSX]
    if exe[RECORD_FILE:RECORD_FILE + 12] != BEFORE_RECORD:
        raise BuildError("V352 corrupted action-record premise drift")
    for offset, before, _after in REPAIRS:
        if exe[offset] != before:
            raise BuildError(f"V352 repair premise drift at PSX.EXE:0x{offset:X}")
    for offset in RECORD_REFERENCES:
        if struct.unpack_from("<I", exe, offset)[0] != RECORD_RAM:
            raise BuildError(f"action-record reference drift at PSX.EXE:0x{offset:X}")
    if struct.unpack_from("<I", exe, LIVE_POINTER_FILE)[0] != LIVE_POINTER_VALUE:
        raise BuildError("current live string pointer drift")
    hits = pointer_hits(base)
    if hits:
        raise BuildError(f"stale string range still has live archive pointers: {hits[:5]}")
    before_word = struct.unpack_from("<I", exe, ACTION_WORD_FILE)[0]
    before_signed = struct.unpack_from("<h", exe, ACTION_WORD_FILE)[0]
    if before_word != 0xA352E026 or before_signed >= 0:
        raise BuildError("corrupted action semantic premise drift")


def build_once(names: list[str], base: dict[str, bytes]) -> dict[str, bytes]:
    assert_base(names, base)
    final = dict(base)
    exe = bytearray(base[PSX])
    for offset, before, after in REPAIRS:
        if exe[offset] != before:
            raise BuildError(f"write guard failed at PSX.EXE:0x{offset:X}")
        exe[offset] = after
    final[PSX] = bytes(exe)

    if final[PSX][RECORD_FILE:RECORD_FILE + 12] != AFTER_RECORD:
        raise BuildError("action record did not restore exactly")
    if struct.unpack_from("<I", final[PSX], ACTION_WORD_FILE)[0] != 0x00000026:
        raise BuildError("restored action ID is not 0x26")
    if struct.unpack_from("<h", final[PSX], ACTION_WORD_FILE)[0] != 0x26:
        raise BuildError("restored signed action ID is not positive 0x26")

    changed = [name for name in names if final[name] != base[name]]
    if changed != [PSX]:
        raise BuildError(f"changed-member drift: {changed}")
    actual = {
        i for i, (old, new) in enumerate(zip(base[PSX], final[PSX], strict=True))
        if old != new
    }
    expected = {offset for offset, _before, _after in REPAIRS}
    if actual != expected:
        raise BuildError(f"Expected-Write mismatch: {sorted(actual ^ expected)}")
    for name in names:
        if len(final[name]) != len(base[name]):
            raise BuildError(f"member size changed: {name}")
    if final[COMM] != base[COMM]:
        raise BuildError("COMM.IMG changed")
    if pointer_hits(final):
        raise BuildError("repair introduced a stale-range pointer")
    return final


def main() -> None:
    assert_archive_hash(BASE, BASE_SHA256, "V352 base")
    provenance_guard()
    names, base = read_archive(BASE)
    final = build_once(names, base)
    second = build_once(names, base)
    if final != second:
        raise BuildError("in-memory deterministic rebuild mismatch")

    ANALYSIS.mkdir(parents=True, exist_ok=True)
    changed = [name for name in names if final[name] != base[name]]
    out_temp = ROOT / "03_output" / f"{OUTPUT_STEM}.zip"
    delta_temp = ROOT / "03_output" / f"{DELTA_STEM}.zip"
    for path in (out_temp, delta_temp):
        if path.exists():
            path.unlink()
    write_archive(out_temp, names, final)
    write_archive(delta_temp, changed, final)
    out_hash = sha(out_temp.read_bytes())
    delta_hash = sha(delta_temp.read_bytes())
    output = out_temp.with_name(f"{OUTPUT_STEM}_{out_hash[:8]}.zip")
    delta = delta_temp.with_name(f"{DELTA_STEM}_{delta_hash[:8]}.zip")
    for source, target in ((out_temp, output), (delta_temp, delta)):
        if target.exists():
            if sha(target.read_bytes()) != sha(source.read_bytes()):
                raise BuildError(f"existing output differs: {target.name}")
            source.unlink()
        else:
            source.replace(target)

    expected_rows = [
        {
            "member": PSX,
            "offset": f"0x{offset:X}",
            "before": f"{before:02X}",
            "after": f"{after:02X}",
            "reason": "restore high byte of live 32-bit summon action ID 0x00000026",
        }
        for offset, before, after in REPAIRS
    ]
    with (ANALYSIS / "expected_writes.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=tuple(expected_rows[0]))
        writer.writeheader()
        writer.writerows(expected_rows)

    audit_rows = (
        ("original", ORIGINAL.name, ORIGINAL_SHA256, AFTER_RECORD.hex(" ").upper(), "0x00000026", "38"),
        ("V206", V206.name, V206_SHA256, AFTER_RECORD.hex(" ").upper(), "0x00000026", "38"),
        ("V207", V207.name, V207_SHA256, "58 38 12 80 6C 3B 12 80 26 E0 0A A3", "0xA30AE026", str(struct.unpack("<h", bytes.fromhex("26 E0"))[0])),
        ("V352", BASE.name, BASE_SHA256, BEFORE_RECORD.hex(" ").upper(), "0xA352E026", str(struct.unpack("<h", bytes.fromhex("26 E0"))[0])),
        ("V353", output.name, out_hash, AFTER_RECORD.hex(" ").upper(), "0x00000026", "38"),
    )
    with (ANALYSIS / "action_record_audit.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(("version", "archive", "archive_sha256", "record_hex", "action_word", "signed_low16"))
        writer.writerows(audit_rows)
    with (ANALYSIS / "runtime_state_evidence.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(("state", "file", "sha256", "observation"))
        writer.writerows(STATE_EVIDENCE)

    manifest = {
        "version": "V353",
        "status": "STATIC_PASS_RUNTIME_PENDING",
        "base": {"file": BASE.name, "sha256": BASE_SHA256},
        "output": {"file": output.name, "sha256": out_hash},
        "delta": {"file": delta.name, "sha256": delta_hash},
        "changed_members_vs_v352": changed,
        "changed_bytes": 3,
        "expected_writes": expected_rows,
        "action_record": {
            "ram": f"0x{RECORD_RAM:08X}",
            "file": f"0x{RECORD_FILE:X}",
            "before": BEFORE_RECORD.hex(" ").upper(),
            "after": AFTER_RECORD.hex(" ").upper(),
            "before_action_word": "0xA352E026",
            "after_action_word": "0x00000026",
        },
        "root_cause": "V207 zero-run string relocation began at byte 1 of a live 32-bit action ID",
        "preserved": "COMM.IMG, every DAT, all other PSX.EXE bytes, archive topology/order and member sizes byte exact V352",
        "runtime": "PENDING user cold boot; RAM-only intervention already reproduced callback and MP 56->44",
    }
    (ANALYSIS / "build_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    report = [
        "V353 summon-skill action-record repair",
        f"base={BASE.name} sha256={BASE_SHA256}",
        f"output={output.name} sha256={out_hash}",
        f"delta={delta.name} sha256={delta_hash}",
        "changed_members=PSX.EXE only",
        "changed_bytes=3 exact: PSX.EXE 0x78AE5..0x78AE7 E0 52 A3 -> 00 00 00",
        "action_record=RAM 0x801932DC / file 0x78ADC; action 0xA352E026 -> 0x00000026",
        "provenance=original/V206 action 0x26; V207 first corruption; V352 inherited corruption",
        "stale_pointer_scan=0 pointers to 0x801932E5..0x801932EA across all 164 members",
        "COMM.IMG/all DAT/all other PSX.EXE bytes=byte exact V352",
        "runtime=PENDING user cold boot; TEST_ONLY",
    ]
    (ANALYSIS / "build_report.txt").write_text("\n".join(report) + "\n", encoding="utf-8")
    (ANALYSIS / "runtime_checklist.txt").write_text(
        "V353 콜드부팅 체크리스트\n"
        "1. V353.cue를 완전 콜드부팅한다. V352 세이브스테이트를 V353에 직접 로드하지 않는다.\n"
        "2. 케라크의 회복 스킬을 선택하고 범위 커서에서 확정한다.\n"
        "3. 소환수가 제자리에서 정상 회복 동작/연출을 수행하는지 확인한다.\n"
        "4. MP가 스킬 비용만큼 감소하는지 확인한다. 진단 재현값은 56 -> 44였다.\n"
        "5. 대상 HP가 가득 차 있어도 원본처럼 스킬 동작과 MP 소비가 실행되는지 확인한다.\n"
        "6. 스킬 후 자유 이동으로 즉시 복귀하거나 소환수가 다른 유닛 위로 날아가지 않는지 확인한다.\n",
        encoding="utf-8",
    )
    print("\n".join(report))


if __name__ == "__main__":
    main()
