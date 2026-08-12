#!/usr/bin/env python3
"""Build v188 by removing v187's code-delay-slot string allocation.

v187 wrote text at PSX.EXE 0x828CC, but that word is the delay slot of the
jump at runtime 0x8019D0C8.  v188 restores the exact v186 NOP and stores the
two system strings only in bounded string slots orphaned by earlier pointer
repairs:

* 0x8248B: old item-acquisition suffix, orphaned when v185 moved 0x82474.
* 0x8243A: old skill-learn suffix, orphaned after this build moves 0x82554.

The v187 SD011 and S1023 data repairs are retained byte-for-byte.
"""
from __future__ import annotations

import hashlib
import struct
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo


ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "03_output"
ANALYSIS = ROOT / "01_work/analysis/arc1_v188_safe_string_slot_repair"

BASE = ROOT / "03_output/arc1_v187_control_skill_choice_repair_292BF4BE.zip"
BASE_SHA256 = "292BF4BE4283A121A9435D58781F89FB7E6847262A4660F3C8E7424CF4B1ABE8"
CONTROL = ROOT / "03_output/arc1_v186_runtime_text_choice_fixes_0D144525.zip"
CONTROL_SHA256 = "0D144525001BA1FE6284DE7D823D6C68FEC26AC733B51D69E9AFB9A679B67BB5"
OUT_STEM = "arc1_v188_safe_string_slot_repair"

PSX = "PSX.EXE"
RAM_TO_FILE = 0x8011A800

SKILL_CLOSE_PTR = 0x82554
FUSION_PTR = 0x829B8
BAD_DELAY_SLOT = (0x828CC, 0x828DC)

# Both slots are exact C-string extents ending immediately before the next
# declared object.  v187 has no pointer to either slot before the new writes.
ORPHAN_ITEM_SLOT = (0x8248B, 0x82498)   # 13 bytes, v185 orphan
ORPHAN_SKILL_SLOT = (0x8243A, 0x82444)  # 10 bytes, v188 orphan

EXPECTED_ITEM_ORPHAN = bytes.fromhex(
    "65 9C C3 46 9C C8 91 61 45 78 E0 60 00"
)
EXPECTED_SKILL_ORPHAN = bytes.fromhex(
    "65 9C DF BD DE D6 78 E0 60 00"
)
FUSION = bytes.fromhex("DE D9 E0 73")  # 합체


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def clone(info: ZipInfo) -> ZipInfo:
    result = ZipInfo(info.filename, info.date_time)
    for attr in (
        "compress_type", "comment", "extra", "create_system", "create_version",
        "extract_version", "flag_bits", "volume", "internal_attr", "external_attr",
    ):
        setattr(result, attr, getattr(info, attr))
    return result


def pointer_target(exe: bytes, at: int) -> int:
    return struct.unpack_from("<I", exe, at)[0] - RAM_TO_FILE


def pointer_refs(exe: bytes, target: int) -> list[int]:
    needle = struct.pack("<I", RAM_TO_FILE + target)
    refs: list[int] = []
    start = 0
    while True:
        at = exe.find(needle, start)
        if at < 0:
            return refs
        refs.append(at)
        start = at + 1


def put_bounded(exe: bytearray, extent: tuple[int, int], payload: bytes) -> None:
    start, end = extent
    if len(payload) + 1 > end - start or 0 in payload:
        raise SystemExit(f"payload does not fit bounded slot 0x{start:X}..0x{end:X}")
    exe[start:end] = payload + bytes(end - start - len(payload))


def main() -> None:
    if digest(BASE.read_bytes()) != BASE_SHA256:
        raise SystemExit("v187 base archive hash differs")
    if digest(CONTROL.read_bytes()) != CONTROL_SHA256:
        raise SystemExit("v186 control archive hash differs")

    with ZipFile(BASE) as archive:
        infos = archive.infolist()
        members = {info.filename: archive.read(info.filename) for info in infos}
    with ZipFile(CONTROL) as archive:
        control_members = {name: archive.read(name) for name in archive.namelist()}

    before = dict(members)
    exe = bytearray(members[PSX])
    control_exe = control_members[PSX]

    # Prove the diagnosed v187 corruption and the exact control instruction.
    bad_start, bad_end = BAD_DELAY_SLOT
    if bytes(exe[bad_start:bad_end]) != bytes.fromhex(
        "5A 65 9C DF BD DE D6 78 E0 60 00 DE D9 E0 73 00"
    ):
        raise SystemExit("v187 unsafe allocation guard differs")
    if control_exe[bad_start:bad_end] != bytes(16):
        raise SystemExit("v186 control delay slot/tail is not all zero")
    jump_word = struct.unpack_from("<I", exe, 0x828C8)[0]
    if jump_word != 0x0805AD78:
        raise SystemExit(f"jump before delay slot differs: 0x{jump_word:08X}")

    # The slots must still be bounded original strings and currently orphaned.
    item_start, item_end = ORPHAN_ITEM_SLOT
    skill_start, skill_end = ORPHAN_SKILL_SLOT
    if bytes(exe[item_start:item_end]) != EXPECTED_ITEM_ORPHAN:
        raise SystemExit("orphaned item suffix slot differs")
    if bytes(exe[skill_start:skill_end]) != EXPECTED_SKILL_ORPHAN:
        raise SystemExit("orphaned skill suffix slot differs")
    if pointer_refs(exe, item_start) or pointer_refs(exe, skill_start):
        raise SystemExit("a supposedly orphaned string slot still has a pointer")
    if exe[item_start - 1] != 0 or exe[skill_start - 1] != 0:
        raise SystemExit("orphaned string start is not on a C-string boundary")

    # Keep the existing translated suffix and add only the missing close bracket.
    skill_close = bytes((0x5A,)) + EXPECTED_SKILL_ORPHAN[:-1]
    put_bounded(exe, ORPHAN_ITEM_SLOT, skill_close)
    struct.pack_into("<I", exe, SKILL_CLOSE_PTR, RAM_TO_FILE + item_start)

    # Reuse the now-orphaned old skill slot for the four-byte 합체 label.
    put_bounded(exe, ORPHAN_SKILL_SLOT, FUSION)
    struct.pack_into("<I", exe, FUSION_PTR, RAM_TO_FILE + skill_start)

    # Restore the delay slot and its zero tail exactly from runtime-working v186.
    exe[bad_start:bad_end] = control_exe[bad_start:bad_end]

    final_exe = bytes(exe)
    if struct.unpack_from("<I", final_exe, bad_start)[0] != 0:
        raise SystemExit("0x8019D0CC is not restored to NOP")
    if pointer_target(final_exe, SKILL_CLOSE_PTR) != item_start:
        raise SystemExit("skill closer pointer readback differs")
    if pointer_target(final_exe, FUSION_PTR) != skill_start:
        raise SystemExit("fusion pointer readback differs")
    if final_exe[item_start:item_start + len(skill_close) + 1] != skill_close + b"\0":
        raise SystemExit("skill closer string readback differs")
    if final_exe[skill_start:skill_start + len(FUSION) + 1] != FUSION + b"\0":
        raise SystemExit("fusion string readback differs")
    if pointer_refs(final_exe, item_start) != [SKILL_CLOSE_PTR]:
        raise SystemExit("skill closer slot ownership differs")
    if pointer_refs(final_exe, skill_start) != [FUSION_PTR]:
        raise SystemExit("fusion slot ownership differs")

    # Preserve every v187 non-EXE repair exactly.
    members[PSX] = final_exe
    for name in members:
        if name != PSX and members[name] != before[name]:
            raise SystemExit(f"non-EXE member changed inside v188: {name}")
    if members["D/SD011.DAT"] != before["D/SD011.DAT"]:
        raise SystemExit("v187 SD011 repair was not retained")
    if members["1/S1023.DAT"] != before["1/S1023.DAT"]:
        raise SystemExit("v187 S1023 repair was not retained")

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    ANALYSIS.mkdir(parents=True, exist_ok=True)
    temporary = OUT_DIR / f"{OUT_STEM}_building.zip"
    if temporary.exists():
        raise SystemExit(f"refusing to overwrite {temporary}")
    with ZipFile(temporary, "w", ZIP_DEFLATED) as archive:
        for info in infos:
            archive.writestr(clone(info), members[info.filename])
    with ZipFile(temporary) as archive:
        if archive.namelist() != [info.filename for info in infos]:
            raise SystemExit("archive member order changed")
        for name in archive.namelist():
            if archive.read(name) != members[name]:
                raise SystemExit(f"archive readback differs: {name}")

    output_hash = digest(temporary.read_bytes())
    output = OUT_DIR / f"{OUT_STEM}_{output_hash[:8]}.zip"
    if output.exists():
        raise SystemExit(f"refusing to overwrite {output}")
    temporary.replace(output)

    changed_from_v187 = [name for name in members if members[name] != before[name]]
    changed_from_v186 = [
        name for name in members if members[name] != control_members.get(name)
    ]
    report = [
        "v188 safe string-slot repair",
        f"base={BASE.name}",
        f"base_sha256={BASE_SHA256}",
        f"output={output.name}",
        f"output_sha256={output_hash}",
        "",
        "root_cause=v187 text occupied jump delay slot at 0x8019D0CC",
        "delay_slot=0x8019D0CC NOP restored byte-identical to v186",
        f"skill_closer_slot=0x{item_start:X}..0x{item_end - 1:X}",
        f"fusion_slot=0x{skill_start:X}..0x{skill_end - 1:X}",
        "unsafe_pool=0x828CC..0x828DB restored to zero",
        "decoder 0x801FF30C / 568 bytes",
        "frame routine 0x801FF634 / 636 bytes",
        f"changed_from_v187={','.join(changed_from_v187)}",
        f"changed_from_v186={','.join(changed_from_v186)}",
        "v187_SD011_and_S1023=byte-identical",
        "cold_boot=NOT RUN (user test required)",
        "rollback=v186",
    ]
    (ANALYSIS / "build_report.txt").write_text(
        "\n".join(report) + "\n", encoding="utf-8"
    )
    print("\n".join(report))


if __name__ == "__main__":
    main()
