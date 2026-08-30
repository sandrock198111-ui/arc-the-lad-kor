#!/usr/bin/env python3
"""Build V351: repair ten proven bad full-stop codes inherited by V350.

V350 runtime screenshots proved that raw 0x0F renders the current 16px atlas
glyph at physical index 14 ("��"), not a full stop.  The current full stop is
physical index 32, direct raw 0x21.  This build changes only the ten 0x0F bytes
that recent V347/V350 builders introduced specifically for Korean full stops.

No global 0x0F replacement is allowed: older content still contains many 0x0F
tokens with mixed historical provenance.  Every write below is pinned by member,
slot, byte offset, caller and completion metadata.
"""

from __future__ import annotations

import csv
import hashlib
import json
import sys
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo


ROOT = Path(__file__).resolve().parents[1]
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

BASE = ROOT / "03_output/arc1_v350_dialogue_wording_fixes_TEST_ONLY_2B760572.zip"
BASE_SHA256 = "2B76057250E02F29D6EAA55A8882B04A420F3C232715409938DAF2070AD4041E"
OUTPUT_STEM = "arc1_v351_period_code_repair_TEST_ONLY"
DELTA_STEM = OUTPUT_STEM + "_delta_from_v350"
ANALYSIS = ROOT / "01_work/analysis/arc1_v351_period_code_repair"
ATLAS = ROOT / "01_work/analysis/arc1_v319_pilgi16_integration/atlas_mapping.csv"
ATLAS_SHA256 = "9553E7643621CC80C23355067611EAE7650FEF7CB547DC9115B62157DB0C3122"

PSX = "PSX.EXE"
COMM = "COMM.IMG"
SLOT_BASE = 0x45000
SLOT_SIZE = 0x80
SLOT_META = 0x7F
BAD = 0x0F
FULL_STOP = 0x21

BASE_MEMBER_SHA256 = {
    "5/S5011.DAT": "56C982F78305D61E81C4AA8A32194A492586EA7CA1AA3072798289C7D54EF12C",
    "5/S5021.DAT": "28F75F211C4AEDC797966D960C7033FB32F50928BC00282EB5861C5B86EB0057",
    "5/S5024.DAT": "C3CE199C8A6801BF81E336FE90F7F83DE1DE147F6EF400BB690B836647A091A1",
    "5/S5052.DAT": "8DE3FC4A8E48226BB81B597914D9E60163F6A735174447A4EA4A29D0456569BF",
    PSX: "0D540C1E71C4546708B7C6C1D7328D58E31137ED4453EBCEB5B7F645A4764E1F",
    COMM: "A6681F1355007725328372CC6143EF21EEE43A9FDE91FD3DC2EF3461C6805405",
}

# member, slot, completion, E2 caller, exact file offsets that are Korean '.'
SLOT_FIXES = (
    ("5/S5011.DAT", 4, 13, 0x4810A, (0x45212,)),
    ("5/S5021.DAT", 20, 22, 0x47B70, (0x45A1B,)),
    ("5/S5021.DAT", 22, 43, 0x47B0E, (0x45B1A,)),
    ("5/S5024.DAT", 0, 19, 0x478E8, (0x45018,)),
    ("5/S5052.DAT", 0, 25, 0x47ADA, (0x4500B, 0x4501F, 0x4502B)),
    ("5/S5052.DAT", 4, 27, 0x47B28, (0x4521E,)),
    ("5/S5052.DAT", 6, 19, 0x47A90, (0x4530D, 0x45313)),
)


class BuildError(RuntimeError):
    pass


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def disk_id(slot: int) -> int:
    return slot + (0x81 if slot < 40 else 0x82)


def slot_start(slot: int) -> int:
    return SLOT_BASE + slot * SLOT_SIZE


def write_archive(path: Path, names: list[str], members: dict[str, bytes]) -> None:
    with ZipFile(path, "w", compression=ZIP_DEFLATED, compresslevel=9) as archive:
        for name in names:
            info = ZipInfo(name, date_time=(2026, 8, 30, 0, 0, 0))
            info.compress_type = ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, members[name], compress_type=ZIP_DEFLATED, compresslevel=9)


def read_archive(path: Path) -> tuple[list[str], dict[str, bytes]]:
    with ZipFile(path) as archive:
        names = [item.filename for item in archive.infolist() if not item.is_dir()]
        return names, {name: archive.read(name) for name in names}


def atlas_guard() -> None:
    if sha(ATLAS.read_bytes()) != ATLAS_SHA256:
        raise BuildError("atlas mapping hash drift")
    with ATLAS.open(encoding="utf-8-sig", newline="") as handle:
        rows = {int(row["index"]): row for row in csv.DictReader(handle)}
    if rows[14].get("unicode") != "U+C758":
        raise BuildError("physical 14 is no longer the bad 0x0F glyph")
    if rows[32].get("unicode") != "U+002E" or rows[32].get("char") != ".":
        raise BuildError("physical 32 is no longer the full stop glyph")


def assert_base(names: list[str], base: dict[str, bytes]) -> None:
    if len(names) != 164 or len(base) != 164:
        raise BuildError("V350 archive topology drift")
    for member, expected in BASE_MEMBER_SHA256.items():
        if sha(base[member]) != expected:
            raise BuildError(f"V350 member hash drift: {member}")
    total = 0
    for member, slot, metadata, caller, offsets in SLOT_FIXES:
        data = base[member]
        start = slot_start(slot)
        if data[start + SLOT_META] != metadata:
            raise BuildError(f"slot metadata drift: {member} slot {slot}")
        if data[caller:caller + 2] != bytes((0xE2, disk_id(slot))):
            raise BuildError(f"E2 caller drift: {member}:0x{caller:X}")
        for offset in offsets:
            if not start <= offset < start + SLOT_META:
                raise BuildError(f"offset escaped slot payload: {member}:0x{offset:X}")
            if data[offset] != BAD:
                raise BuildError(f"expected bad 0x0F missing: {member}:0x{offset:X}")
            total += 1
    if total != 10:
        raise BuildError(f"expected ten punctuation fixes, got {total}")


def build_once(names: list[str], base: dict[str, bytes]) -> tuple[dict[str, bytes], list[dict[str, object]]]:
    assert_base(names, base)
    final = dict(base)
    mutable = {member: bytearray(base[member]) for member in BASE_MEMBER_SHA256 if member not in (PSX, COMM)}
    rows: list[dict[str, object]] = []
    for member, slot, metadata, caller, offsets in SLOT_FIXES:
        data = mutable[member]
        for offset in offsets:
            data[offset] = FULL_STOP
            rows.append({
                "member": member,
                "slot": slot,
                "caller": f"0x{caller:X}",
                "offset": f"0x{offset:X}",
                "before": "0F",
                "after": "21",
                "meaning": "Korean full stop '.'",
            })
        if data[slot_start(slot) + SLOT_META] != metadata:
            raise BuildError(f"slot metadata changed: {member} slot {slot}")
        if data[caller:caller + 2] != bytes((0xE2, disk_id(slot))):
            raise BuildError(f"E2 caller changed: {member}:0x{caller:X}")
    for member, data in mutable.items():
        final[member] = bytes(data)

    expected_members = ["5/S5011.DAT", "5/S5021.DAT", "5/S5024.DAT", "5/S5052.DAT"]
    changed_members = [name for name in names if final[name] != base[name]]
    if changed_members != expected_members:
        raise BuildError(f"changed-member drift: {changed_members}")
    expected_offsets: dict[str, set[int]] = {name: set() for name in expected_members}
    for member, _slot, _metadata, _caller, offsets in SLOT_FIXES:
        expected_offsets[member].update(offsets)
    total = 0
    for member in changed_members:
        if len(final[member]) != len(base[member]):
            raise BuildError(f"member size changed: {member}")
        actual = {i for i, (a, b) in enumerate(zip(base[member], final[member], strict=True)) if a != b}
        if actual != expected_offsets[member]:
            raise BuildError(f"Expected-Write mismatch: {member}: {sorted(actual ^ expected_offsets[member])[:8]}")
        for offset in actual:
            if base[member][offset] != BAD or final[member][offset] != FULL_STOP:
                raise BuildError(f"non 0F->21 edit: {member}:0x{offset:X}")
        total += len(actual)
    if total != 10:
        raise BuildError(f"changed byte count drift: {total}")
    for name in names:
        if name not in expected_members and final[name] != base[name]:
            raise BuildError(f"unexpected member changed: {name}")
    if final[PSX] != base[PSX] or final[COMM] != base[COMM]:
        raise BuildError("PSX.EXE or COMM.IMG changed")
    return final, rows


def main() -> None:
    if not BASE.is_file() or sha(BASE.read_bytes()) != BASE_SHA256:
        raise BuildError("V350 base archive hash drift")
    atlas_guard()
    names, base = read_archive(BASE)
    final, rows = build_once(names, base)
    second, rows2 = build_once(names, base)
    if final != second or rows != rows2:
        raise BuildError("in-memory deterministic rebuild mismatch")

    changed_members = [name for name in names if final[name] != base[name]]
    ANALYSIS.mkdir(parents=True, exist_ok=True)
    output_temp = ROOT / "03_output" / f"{OUTPUT_STEM}.zip"
    delta_temp = ROOT / "03_output" / f"{DELTA_STEM}.zip"
    for path in (output_temp, delta_temp):
        if path.exists():
            path.unlink()
    write_archive(output_temp, names, final)
    write_archive(delta_temp, changed_members, final)
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

    with (ANALYSIS / "period_repairs.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=tuple(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    manifest = {
        "version": "V351",
        "status": "STATIC_PASS_RUNTIME_PENDING",
        "cause": "V350/V347 recent Korean full stops encoded as 0x0F, which current atlas renders as '��'",
        "base": {"file": BASE.name, "sha256": BASE_SHA256, "runtime": "FAIL punctuation glyph"},
        "output": {"file": output.name, "sha256": output_hash},
        "delta": {"file": delta.name, "sha256": delta_hash},
        "changed_members_vs_v350": changed_members,
        "changed_bytes": 10,
        "exact_edit": "ten pinned bytes only: 0x0F -> 0x21",
        "preserved": "PSX.EXE, COMM.IMG, all E2 callers/completion metadata, member sizes, all other members",
        "runtime": "PENDING user cold boot/dialogue review; inherits V349 dungeon runtime gate",
    }
    (ANALYSIS / "build_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    report = [
        "V351 period-code repair",
        f"base={BASE.name} sha256={BASE_SHA256}",
        f"output={output.name} sha256={output_hash}",
        f"delta={delta.name} sha256={delta_hash}",
        f"changed_members={','.join(changed_members)}",
        "changed_bytes=10 exact 0F->21",
        "atlas guard: raw 0F=physical14 U+C758; raw 21=physical32='.' (U+002E)",
        "PSX.EXE/COMM.IMG/E2 callers/completion metadata/all other members=byte exact V350",
        "runtime=PENDING user cold boot/dialogue review; TEST_ONLY",
    ]
    (ANALYSIS / "build_report.txt").write_text("\n".join(report) + "\n", encoding="utf-8")
    (ANALYSIS / "runtime_checklist.txt").write_text(
        "V351 cold-boot checklist\n"
        "1. V351.cue를 완전 콜드부팅하고 V351_1.mcd를 불러온다.\n"
        "2. V350에서 깨졌던 네 자연화 대사의 모든 마침표가 정상 '.'인지 확인한다.\n"
        "3. V347에서 추가된 상인 대사 3곳의 문장 끝 마침표도 정상인지 확인한다.\n"
        "4. V349에서 미확정인 던전 진입 및 지하 1/2/3층 숫자 표기를 확인한다.\n",
        encoding="utf-8",
    )
    print("\n".join(report))


if __name__ == "__main__":
    main()
