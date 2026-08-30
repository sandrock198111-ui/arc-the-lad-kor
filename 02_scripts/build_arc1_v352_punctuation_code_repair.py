#!/usr/bin/env python3
"""Build V352: repair the remaining recent punctuation-code regressions.

V351 proved that the current 16px atlas must be treated as the source of truth
for punctuation.  The historical V345 helper hard-coded legacy one-byte values
for comma/full stop/exclamation and can therefore select Hangul glyphs in the
current atlas.  V351 repaired the ten recent full stops.  This build repairs the
four remaining recent punctuation bytes whose provenance is known exactly:

* V347 merchant line: comma 0x0D -> 0xB3 and two exclamation marks 0x02 -> 0xA9
* V350/V351 "이야," line: comma 0x0D -> 0xB3

No global byte replacement is performed.  All other bytes remain V351-exact.
"""

from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo


ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "03_output/arc1_v351_period_code_repair_TEST_ONLY_76DFD702.zip"
BASE_SHA256 = "76DFD702BBDD9D11A9CEE2B6B9DF795F90B2F4D6744DB474209E92F4825CA50D"
OUTPUT_STEM = "arc1_v352_punctuation_code_repair_TEST_ONLY"
DELTA_STEM = OUTPUT_STEM + "_delta_from_v351"
ANALYSIS = ROOT / "01_work/analysis/arc1_v352_punctuation_code_repair"

ASSIGNMENTS = ROOT / "01_work/analysis/arc1_v320_hanme_static_recovery/character_assignments.csv"
ASSIGNMENTS_SHA256 = "933BDAC4BC4C39D33DB134D2FF836902B5053B93725C96E19DED714CB7DE98A4"

PSX = "PSX.EXE"
COMM = "COMM.IMG"
S5011 = "5/S5011.DAT"
S5052 = "5/S5052.DAT"

BASE_MEMBER_SHA256 = {
    S5011: "F7F19693622C44C0B5FAFFB5787F0B5E5791A72DB4E30513AFDE3FBA942888AA",
    S5052: "08BD9EF0FD611EE0888A57DE68601C3DA32DFE722DDAD1483E4DBA8A0098E51D",
    PSX: "0D540C1E71C4546708B7C6C1D7328D58E31137ED4453EBCEB5B7F645A4764E1F",
    COMM: "A6681F1355007725328372CC6143EF21EEE43A9FDE91FD3DC2EF3461C6805405",
}

# member, absolute file offset, before, after, intended punctuation, provenance
REPAIRS = (
    (S5011, 0x4510B, 0x0D, 0xB3, ",", "V347 merchant: 장사야,"),
    (S5011, 0x45113, 0x02, 0xA9, "!", "V347 merchant: 이 자식아!"),
    (S5011, 0x45121, 0x02, 0xA9, "!", "V347 merchant: 싶냐!"),
    (S5052, 0x45302, 0x0D, 0xB3, ",", "V350/V351: 이야,"),
)

PUNCTUATION = {
    ",": ("B3", "178", "U+002C"),
    ".": ("21", "32", "U+002E"),
    "!": ("A9", "168", "U+0021"),
    "?": ("D1", "208", "U+003F"),
}


class BuildError(RuntimeError):
    pass


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def read_archive(path: Path) -> tuple[list[str], dict[str, bytes]]:
    with ZipFile(path) as archive:
        names = [i.filename for i in archive.infolist() if not i.is_dir()]
        return names, {name: archive.read(name) for name in names}


def write_archive(path: Path, names: list[str], members: dict[str, bytes]) -> None:
    with ZipFile(path, "w", compression=ZIP_DEFLATED, compresslevel=9) as archive:
        for name in names:
            info = ZipInfo(name, date_time=(2026, 8, 30, 0, 0, 0))
            info.compress_type = ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, members[name], compress_type=ZIP_DEFLATED, compresslevel=9)


def punctuation_guard() -> None:
    if sha(ASSIGNMENTS.read_bytes()) != ASSIGNMENTS_SHA256:
        raise BuildError("character assignments hash drift")
    with ASSIGNMENTS.open(encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    for char, (code, physical, unicode_value) in PUNCTUATION.items():
        matches = [
            row for row in rows
            if row.get("char") == char
            and row.get("code_hex", "").replace(" ", "").upper() == code
            and row.get("physical_index") == physical
            and row.get("unicode") == unicode_value
        ]
        if not matches:
            raise BuildError(f"current punctuation mapping drift: {char!r}")


def assert_base(names: list[str], base: dict[str, bytes]) -> None:
    if len(names) != 164 or len(base) != 164:
        raise BuildError("V351 archive topology drift")
    for member, expected in BASE_MEMBER_SHA256.items():
        if sha(base[member]) != expected:
            raise BuildError(f"V351 member hash drift: {member}")
    for member, offset, before, _after, _char, _why in REPAIRS:
        if base[member][offset] != before:
            raise BuildError(
                f"punctuation premise drift: {member}:0x{offset:X} "
                f"{base[member][offset]:02X} != {before:02X}"
            )
    # The two edited E2 slots and their completion bytes must already be intact.
    if base[S5011][0x4815A:0x4815C] != bytes.fromhex("E2 83"):
        raise BuildError("S5011 slot2 caller drift")
    if base[S5011][0x4517F] != 35:
        raise BuildError("S5011 slot2 completion drift")
    if base[S5052][0x47A90:0x47A92] != bytes.fromhex("E2 87"):
        raise BuildError("S5052 slot6 caller drift")
    if base[S5052][0x4537F] != 19:
        raise BuildError("S5052 slot6 completion drift")


def build_once(names: list[str], base: dict[str, bytes]) -> dict[str, bytes]:
    assert_base(names, base)
    final = dict(base)
    mutable = {S5011: bytearray(base[S5011]), S5052: bytearray(base[S5052])}
    for member, offset, before, after, _char, _why in REPAIRS:
        data = mutable[member]
        if data[offset] != before:
            raise BuildError(f"write guard failed: {member}:0x{offset:X}")
        data[offset] = after
    for member, data in mutable.items():
        final[member] = bytes(data)

    expected_offsets: dict[str, set[int]] = {S5011: set(), S5052: set()}
    for member, offset, before, after, _char, _why in REPAIRS:
        expected_offsets[member].add(offset)
        if final[member][offset] != after or base[member][offset] != before:
            raise BuildError(f"repair readback failed: {member}:0x{offset:X}")

    changed = [name for name in names if final[name] != base[name]]
    if changed != [S5011, S5052]:
        raise BuildError(f"changed-member drift: {changed}")
    for member in changed:
        actual = {
            i for i, (a, b) in enumerate(zip(base[member], final[member], strict=True)) if a != b
        }
        if actual != expected_offsets[member]:
            raise BuildError(f"Expected-Write mismatch: {member}")
    for name in names:
        if len(final[name]) != len(base[name]):
            raise BuildError(f"member size changed: {name}")
    if final[PSX] != base[PSX] or final[COMM] != base[COMM]:
        raise BuildError("PSX.EXE or COMM.IMG changed")
    return final


def main() -> None:
    if not BASE.is_file() or sha(BASE.read_bytes()) != BASE_SHA256:
        raise BuildError("V351 base archive hash drift")
    punctuation_guard()
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

    rows = [
        {
            "member": member,
            "offset": f"0x{offset:X}",
            "before": f"{before:02X}",
            "after": f"{after:02X}",
            "char": char,
            "provenance": why,
        }
        for member, offset, before, after, char, why in REPAIRS
    ]
    with (ANALYSIS / "punctuation_repairs.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=tuple(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    with (ANALYSIS / "punctuation_map.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(("char", "code_hex", "physical_index", "unicode"))
        for char, (code, physical, unicode_value) in PUNCTUATION.items():
            writer.writerow((char, code, physical, unicode_value))

    manifest = {
        "version": "V352",
        "status": "STATIC_PASS_RUNTIME_PENDING",
        "base": {"file": BASE.name, "sha256": BASE_SHA256},
        "output": {"file": output.name, "sha256": out_hash},
        "delta": {"file": delta.name, "sha256": delta_hash},
        "changed_members_vs_v351": changed,
        "changed_bytes": 4,
        "repairs": rows,
        "preserved": "PSX.EXE, COMM.IMG, E2 callers/completion metadata, member sizes, all other bytes byte exact V351",
        "runtime": "PENDING user cold boot/dialogue review; inherits V349 dungeon runtime gate",
    }
    (ANALYSIS / "build_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    report = [
        "V352 punctuation-code repair",
        f"base={BASE.name} sha256={BASE_SHA256}",
        f"output={output.name} sha256={out_hash}",
        f"delta={delta.name} sha256={delta_hash}",
        "changed_members=5/S5011.DAT,5/S5052.DAT",
        "changed_bytes=4 exact: comma 0D->B3 x2, exclamation 02->A9 x2",
        "current punctuation guard: ,=B3 .=21 !=A9 ?=D1",
        "PSX.EXE/COMM.IMG/E2 callers/completion metadata/all other bytes=byte exact V351",
        "runtime=PENDING user cold boot/dialogue review; TEST_ONLY",
    ]
    (ANALYSIS / "build_report.txt").write_text("\n".join(report) + "\n", encoding="utf-8")
    (ANALYSIS / "runtime_checklist.txt").write_text(
        "V352 cold-boot checklist\n"
        "1. V352.cue를 완전 콜드부팅한다.\n"
        "2. '이야, 덕분에 살았군. 고맙다.'에서 쉼표와 마침표를 확인한다.\n"
        "3. V347 상인 대사 '장사야, 이 자식아! ... 싶냐!'의 쉼표/느낌표를 확인한다.\n"
        "4. 나머지 V350 자연화 대사와 V349 던전 진입/층수도 회귀 확인한다.\n",
        encoding="utf-8",
    )
    print("\n".join(report))


if __name__ == "__main__":
    main()
