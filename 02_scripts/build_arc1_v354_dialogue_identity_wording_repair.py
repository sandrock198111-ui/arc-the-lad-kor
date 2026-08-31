#!/usr/bin/env python3
"""Build V354: repair five misencoded 재 glyphs and two reviewed lines.

The build is based on the runtime-approved V353 archive.  It changes only
four DAT members.  Five exact DD B4 tokens that mean 개 are replaced with
the atlas-proven direct token DE 52 for 재; two already-live E2 slots in
5/S5041.DAT receive the user-approved Korean wording.  PSX.EXE, COMM.IMG,
E2 callers, slot metadata, member sizes, and every other member are pinned.
"""

from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo


ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "03_output/arc1_v353_summon_skill_action_record_repair_TEST_ONLY_83AB9F25.zip"
BASE_SHA256 = "83AB9F2580478826D4B37F9B8147A6594646E3995C9B8211645C59AC7458AE91"
OUTPUT_STEM = "arc1_v354_dialogue_identity_wording_repair_TEST_ONLY"
DELTA_STEM = OUTPUT_STEM + "_delta_from_v353"
ANALYSIS = ROOT / "01_work/analysis/arc1_v354_dialogue_identity_wording_repair"

PSX = "PSX.EXE"
COMM = "COMM.IMG"
S4031 = "4/S4031.DAT"
S5041 = "5/S5041.DAT"
S8051 = "8/S8051.DAT"
SE05A = "E5/SE05A.DAT"
SLOT_BASE = 0x45000
SLOT_SIZE = 0x80
SLOT_META = 0x7F

BASE_MEMBER_SHA256 = {
    PSX: "7866E637A8CA5E641C6DA3518A5475BB736F0B4505F009917DC998FBBC06B7FD",
    COMM: "A6681F1355007725328372CC6143EF21EEE43A9FDE91FD3DC2EF3461C6805405",
    S4031: "F2683F09A09601003A4ABA0DE1B2EFDA88C7F833803B24D21BB1DCAD1FF08CAB",
    S5041: "57BE469D14FE3CD04A512AD8645B24070081B0E2EEDE973D91A83DF078E30E4B",
    S8051: "7366C74EEE59B7F19DA2165A583FA6ADE560880178C49544366432693868A066",
    SE05A: "4C0181AD7BF6E4AB3D87B19D4D6C34A3B9399C1A12429A74608ED0F08EEB9E75",
}

BAD_JAE = bytes.fromhex("DD B4")       # physical 399 = 개
GOOD_JAE = bytes.fromhex("DE 52")      # physical 556 = 재
IDENTITY_REPAIRS = (
    (S4031, 0x45916, "존개 -> 존재"),
    (S5041, 0x45214, "존개 -> 존재"),
    (S8051, 0x4548C, "개미있는 -> 재미있는"),
    (SE05A, 0x48BFA, "개미있었다 -> 재미있었다"),
    (SE05A, 0x4903A, "개미있다 -> 재미있다"),
)

# member, E2 body offset, slot, +0x7F metadata, old payload, new payload,
# old text, approved new text
DIALOGUE_FIXES = (
    (
        S5041, 0x47BEA, 8, 22,
        bytes.fromhex(
            "DD C4 0F A1 31 51 DD 02 A1 35 DD 1B 0A DD 01 A1 5F DD A8 "
            "0D A1 2B A1 DD 88 06 04 0E 21"
        ),
        bytes.fromhex(
            "DD C4 0F A1 31 51 DD 02 A1 35 DD 1B 0A 03 A1 5F DD A0 A1 "
            "DE 1C 0D A1 2B A1 DD 88 06 04 A1 1B 03 49 21"
        ),
        "빛의 정령: 인간들이 무엇을 해 왔는지에.",
        "빛의 정령: 인간들이 무슨 짓을 해 왔는지 말이야.",
    ),
    (
        S5041, 0x47E0C, 3, 35,
        bytes.fromhex(
            "15 DD 16 A1 6C 19 0F A1 DD 10 0D A1 28 24 A1 18 4E DD 04 "
            "A1 38 0A A1 50 A1 1F 01 06 A1 6A 0F A1 8B A1 09 DD DF 0C 21"
        ),
        bytes.fromhex(
            "15 DD 16 A1 3E 19 0F A1 DD 10 DD 09 0D A1 DE 13 DD A4 0D "
            "A1 50 A1 1F 06 A1 6A 0F A1 8B A1 09 DD DF 0C A9"
        ),
        "그건 부하의 공을 자기 것으로 만들 수 있다는 왕의 상 아닌가.",
        "그건 신하의 공적을 빼앗을 수 있는 왕의 상 아닌가!",
    ),
)

ACTION_RECORD_FILE = 0x78ADC
V353_ACTION_RECORD = bytes.fromhex("58 38 12 80 6C 3B 12 80 26 00 00 00")
EXPECTED_CHANGED_MEMBERS = [S4031, S5041, S8051, SE05A]


class BuildError(RuntimeError):
    pass


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def read_archive(path: Path) -> tuple[list[str], dict[str, bytes]]:
    with ZipFile(path) as archive:
        names = [item.filename for item in archive.infolist() if not item.is_dir()]
        return names, {name: archive.read(name) for name in names}


def write_archive(path: Path, names: list[str], members: dict[str, bytes]) -> None:
    with ZipFile(path, "w", compression=ZIP_DEFLATED, compresslevel=9) as archive:
        for name in names:
            info = ZipInfo(name, date_time=(2026, 8, 31, 0, 0, 0))
            info.compress_type = ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, members[name], compress_type=ZIP_DEFLATED, compresslevel=9)


def slot_start(slot: int) -> int:
    return SLOT_BASE + slot * SLOT_SIZE


def disk_id(slot: int) -> int:
    return slot + (0x81 if slot < 40 else 0x82)


def read_slot(data: bytes | bytearray, slot: int) -> bytes:
    raw = bytes(data[slot_start(slot):slot_start(slot) + SLOT_META])
    end = raw.find(b"\0")
    if end < 0:
        raise BuildError(f"unterminated slot {slot}")
    return raw[:end]


def find_all(data: bytes, needle: bytes) -> list[int]:
    hits: list[int] = []
    start = 0
    while True:
        start = data.find(needle, start)
        if start < 0:
            return hits
        hits.append(start)
        start += 1


def archive_hits(members: dict[str, bytes], needle: bytes) -> list[tuple[str, int]]:
    return [
        (name, offset)
        for name, data in members.items()
        for offset in find_all(data, needle)
    ]


def slot_refs(data: bytes, slot: int) -> list[int]:
    return [x for x in find_all(data[SLOT_BASE + 64 * SLOT_SIZE:], bytes((0xE2, disk_id(slot))))]


def assert_base(names: list[str], base: dict[str, bytes]) -> None:
    if len(names) != 164 or len(base) != 164:
        raise BuildError("V353 archive topology drift")
    for member, expected in BASE_MEMBER_SHA256.items():
        if sha(base[member]) != expected:
            raise BuildError(f"V353 member hash drift: {member}")
    if base[PSX][ACTION_RECORD_FILE:ACTION_RECORD_FILE + 12] != V353_ACTION_RECORD:
        raise BuildError("V353 summon action repair drift")

    for member, offset, _reason in IDENTITY_REPAIRS:
        if base[member][offset:offset + 2] != BAD_JAE:
            raise BuildError(f"identity premise drift: {member}:0x{offset:X}")

    expected_bad_exists = [(S4031, 0x45914), (S5041, 0x45212)]
    expected_bad_fun = [(S8051, 0x4548C), (SE05A, 0x48BFA), (SE05A, 0x4903A)]
    if archive_hits(base, bytes.fromhex("DE EB DD B4")) != expected_bad_exists:
        raise BuildError("존개 census drift")
    if archive_hits(base, bytes.fromhex("DD B4 DD 2F")) != expected_bad_fun:
        raise BuildError("개미 census drift")
    if len(archive_hits(base, bytes.fromhex("DE 52 31 DD 06"))) != 5:
        raise BuildError("V338 재정비 census drift")
    if archive_hits(base, bytes.fromhex("DD B4 31 DD 06")):
        raise BuildError("개정비 regression already present")

    for member, body, slot, metadata, old, _new, _old_text, _new_text in DIALOGUE_FIXES:
        data = base[member]
        if data[body:body + 2] != bytes((0xE2, disk_id(slot))):
            raise BuildError(f"E2 caller drift: {member}:0x{body:X}")
        if read_slot(data, slot) != old:
            raise BuildError(f"old dialogue payload drift: {member} slot {slot}")
        if data[slot_start(slot) + SLOT_META] != metadata:
            raise BuildError(f"slot metadata drift: {member} slot {slot}")
        token = bytes((0xE2, disk_id(slot)))
        refs = find_all(data[SLOT_BASE + 64 * SLOT_SIZE:], token)
        absolute = [SLOT_BASE + 64 * SLOT_SIZE + x for x in refs]
        if absolute != [body]:
            raise BuildError(f"slot ownership drift: {member} slot {slot}: {absolute}")


def build_once(names: list[str], base: dict[str, bytes]) -> dict[str, bytes]:
    assert_base(names, base)
    final = dict(base)
    mutable = {name: bytearray(base[name]) for name in EXPECTED_CHANGED_MEMBERS}

    for member, offset, _reason in IDENTITY_REPAIRS:
        if mutable[member][offset:offset + 2] != BAD_JAE:
            raise BuildError(f"identity write guard failed: {member}:0x{offset:X}")
        mutable[member][offset:offset + 2] = GOOD_JAE

    for member, body, slot, metadata, old, new, _old_text, _new_text in DIALOGUE_FIXES:
        if not new or b"\0" in new or len(new) >= SLOT_META:
            raise BuildError(f"invalid dialogue payload: {member} slot {slot}")
        data = mutable[member]
        if read_slot(data, slot) != old:
            raise BuildError(f"dialogue write guard failed: {member} slot {slot}")
        start = slot_start(slot)
        data[start:start + SLOT_META] = new + bytes(SLOT_META - len(new))
        if data[start + SLOT_META] != metadata:
            raise BuildError(f"slot metadata changed: {member} slot {slot}")
        if data[body:body + 2] != bytes((0xE2, disk_id(slot))):
            raise BuildError(f"E2 caller changed: {member}:0x{body:X}")

    for member in EXPECTED_CHANGED_MEMBERS:
        final[member] = bytes(mutable[member])

    changed = [name for name in names if final[name] != base[name]]
    if changed != EXPECTED_CHANGED_MEMBERS:
        raise BuildError(f"changed-member drift: {changed}")
    for name in names:
        if len(final[name]) != len(base[name]):
            raise BuildError(f"member size changed: {name}")
    if final[PSX] != base[PSX] or final[COMM] != base[COMM]:
        raise BuildError("PSX.EXE or COMM.IMG changed")
    if final[PSX][ACTION_RECORD_FILE:ACTION_RECORD_FILE + 12] != V353_ACTION_RECORD:
        raise BuildError("summon action record changed")

    if archive_hits(final, bytes.fromhex("DE EB DD B4")):
        raise BuildError("존개 remains")
    if archive_hits(final, bytes.fromhex("DD B4 DD 2F")):
        raise BuildError("개미 remains")
    if len(archive_hits(final, bytes.fromhex("DE EB DE 52"))) != 2:
        raise BuildError("존재 count mismatch")
    if len(archive_hits(final, bytes.fromhex("DE 52 DD 2F"))) != 3:
        raise BuildError("재미 count mismatch")
    if len(archive_hits(final, bytes.fromhex("DE 52 31 DD 06"))) != 5:
        raise BuildError("재정비 regression")
    return final


def changed_rows(names: list[str], base: dict[str, bytes], final: dict[str, bytes]) -> list[dict[str, str]]:
    reasons: dict[tuple[str, int], str] = {}
    for member, offset, reason in IDENTITY_REPAIRS:
        reasons[(member, offset)] = reason
        reasons[(member, offset + 1)] = reason
    for member, _body, slot, _metadata, _old, _new, _old_text, new_text in DIALOGUE_FIXES:
        start = slot_start(slot)
        for offset in range(start, start + SLOT_META):
            reasons.setdefault((member, offset), f"approved E2 slot wording: {new_text}")

    rows: list[dict[str, str]] = []
    for name in names:
        for offset, (before, after) in enumerate(zip(base[name], final[name], strict=True)):
            if before != after:
                rows.append({
                    "member": name,
                    "offset": f"0x{offset:X}",
                    "before": f"{before:02X}",
                    "after": f"{after:02X}",
                    "reason": reasons[(name, offset)],
                })
    return rows


def main() -> None:
    if not BASE.is_file() or sha(BASE.read_bytes()) != BASE_SHA256:
        raise BuildError("V353 base archive hash drift")
    names, base = read_archive(BASE)
    final = build_once(names, base)
    if final != build_once(names, base):
        raise BuildError("in-memory deterministic rebuild mismatch")
    rows = changed_rows(names, base, final)
    if not rows:
        raise BuildError("empty Expected-Write set")

    ANALYSIS.mkdir(parents=True, exist_ok=True)
    output_temp = ROOT / "03_output" / f"{OUTPUT_STEM}.zip"
    delta_temp = ROOT / "03_output" / f"{DELTA_STEM}.zip"
    for path in (output_temp, delta_temp):
        if path.exists():
            path.unlink()
    write_archive(output_temp, names, final)
    write_archive(delta_temp, EXPECTED_CHANGED_MEMBERS, final)
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

    with (ANALYSIS / "expected_writes.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=("member", "offset", "before", "after", "reason"))
        writer.writeheader()
        writer.writerows(rows)
    with (ANALYSIS / "dialogue_fixes.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(("member", "body_offset", "slot", "metadata", "old_text", "new_text", "new_hex"))
        for member, body, slot, metadata, _old, new, old_text, new_text in DIALOGUE_FIXES:
            writer.writerow((member, f"0x{body:X}", slot, metadata, old_text, new_text, new.hex(" ").upper()))

    counts = {name: sum(1 for row in rows if row["member"] == name) for name in EXPECTED_CHANGED_MEMBERS}
    manifest = {
        "version": "V354",
        "status": "STATIC_PASS_RUNTIME_PENDING",
        "base": {"file": BASE.name, "sha256": BASE_SHA256, "runtime": "V353 user-confirmed summon skill fix"},
        "output": {"file": output.name, "sha256": output_hash},
        "delta": {"file": delta.name, "sha256": delta_hash},
        "changed_members_vs_v353": EXPECTED_CHANGED_MEMBERS,
        "changed_bytes": counts,
        "identity_repairs": 5,
        "dialogue_repairs": 2,
        "preserved": "PSX.EXE, COMM.IMG, V353 action record, E2 callers, slot +0x7F metadata, sizes/order, all other members",
        "runtime": "PENDING user cold boot and scene review; TEST_ONLY",
    }
    (ANALYSIS / "build_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    report = [
        "V354 dialogue identity and wording repair",
        f"base={BASE.name} sha256={BASE_SHA256}",
        f"output={output.name} sha256={output_hash}",
        f"delta={delta.name} sha256={delta_hash}",
        f"changed_members={','.join(EXPECTED_CHANGED_MEMBERS)}",
        f"changed_bytes={counts} total={len(rows)}",
        "identity=5 exact DD B4(개/399) -> DE 52(재/556) repairs only",
        "wording=5/S5041.DAT slots 8 and 3 only; E2 callers/metadata preserved",
        "census=존개 0, 존재 2, 개미 0, 재미 3, 재정비 5",
        "PSX.EXE/COMM.IMG/V353 summon action record/all other members=byte exact V353",
        "runtime=PENDING user cold boot/scene review; TEST_ONLY",
    ]
    (ANALYSIS / "build_report.txt").write_text("\n".join(report) + "\n", encoding="utf-8")
    (ANALYSIS / "runtime_checklist.txt").write_text(
        "V354 콜드부팅 체크리스트\n"
        "1. V354.cue로 완전 콜드부팅하고 V353 세이브를 불러온다.\n"
        "2. 빛의 정령 장면에서 '존재', '무슨 짓을 해 왔는지 말이야.'를 확인한다.\n"
        "3. 같은 장면에서 '신하의 공적을 빼앗을 수 있는 왕의 상 아닌가!'를 확인한다.\n"
        "4. 다른 장면의 '재미있는/재미있었다/재미있다' 세 곳을 확인한다.\n"
        "5. 소환수 회복 스킬이 V353처럼 발동하고 MP가 소모되는지 회귀 확인한다.\n"
        "6. PSX/UI/폰트/대화 진행에 새 멈춤이나 깨짐이 없는지 확인한다.\n",
        encoding="utf-8",
    )
    print("\n".join(report))


if __name__ == "__main__":
    main()
