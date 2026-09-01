#!/usr/bin/env python3
"""Build V355: a one-line, byte-identical E2 Bank-B runtime probe.

This intentionally does *not* consume the user's pending dialogue CSV edits.  It
starts from the hash-pinned V354 archive and changes only:

* the existing 192-byte E2 handler region in PSX.EXE; and
* 1/S1011.DAT, where the already-rendered first line's complete 128-byte slot is
  copied byte-for-byte to the scene-owned Bank-B area and its E2 id is changed
  from 0x8F to 0xD1.

The visible Korean text and completion metadata therefore remain identical.  A
runtime pass proves that a non-zero Bank-B payload is loaded and that lookup and
deferred completion both work in the current V354 lineage.  COMM.IMG is never
changed, so additional VRAM use is exactly zero bytes.
"""

from __future__ import annotations

import csv
import hashlib
import json
import struct
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo


ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "03_output/arc1_v354_dialogue_identity_wording_repair_TEST_ONLY_2AA6C42A.zip"
BASE_SHA256 = "2AA6C42AC1F62B5D1C7121F27B77807610C9E05D423C548429CB38653DF9C194"
OUTPUT_STEM = "arc1_v355_bankb_runtime_probe_TEST_ONLY"
DELTA_STEM = OUTPUT_STEM + "_delta_from_v354"
ANALYSIS = ROOT / "01_work/analysis/arc1_v355_bankb_runtime_probe"
OUT = ROOT / "03_output"

PSX = "PSX.EXE"
COMM = "COMM.IMG"
PROBE_DAT = "1/S1011.DAT"
BASE_PSX_SHA256 = "7866E637A8CA5E641C6DA3518A5475BB736F0B4505F009917DC998FBBC06B7FD"
BASE_DAT_SHA256 = "954CFDE3B7A55D97D2A33F600A7501402BBAC0AD09BAA5FD27B40C8F4C9DFB8A"

LOAD_ADDRESS = 0x8011B000
LOOKUP_HANDLER = 0x8018FCD0
COMPLETION_HANDLER = 0x8018FD28
HANDLER_SIZE = 0xC0
ORIGINAL_LOOKUP = 0x8015EA44
COMPLETION_TARGET = 0x8016BE44
CURSOR_GATE = 0x8018FD90
BASE_HANDLER_SHA256 = "ACF5643E561053D0EC8491686BE4AFB6661C2E539DE2A034A796DDABD4A938C8"
CANDIDATE_HANDLER_SHA256 = "BD8FEE05BE81BACBE0207A94D4414B516052A728E8F53996CEBA1F76FADB8DFB"
CURSOR_GATE_PREFIX = bytes.fromhex("1F 80 08 3C 58 E0 09 8D 24 E0 0A 95 1F 80 0B 3C")

PROBE_BODY = 0x478AA
PROBE_OLD_ID = 0x8F
PROBE_NEW_ID = 0xD1
STANDARD_SLOT = 14
STANDARD_SLOT_OFFSET = 0x45000 + STANDARD_SLOT * 0x80
BANK_B_OFFSET = 0x4200
SLOT_SIZE = 0x80
BANK_B_SLOTS = 28
STANDARD_SLOT_SHA256 = "B9BCB916B04B1CD3A2679B907251A1B6DB4C7ECE4659736E06FD5B6FC4814A7A"
ZERO_BANK_SHA256 = "6CF1B57D59E7111BC218DFB01DDA93AC0F776715599A1C69F89035BD20C16A10"


class BuildError(RuntimeError):
    pass


def sha(data: bytes | Path) -> str:
    raw = data.read_bytes() if isinstance(data, Path) else data
    return hashlib.sha256(raw).hexdigest().upper()


def file_offset(address: int) -> int:
    return address - LOAD_ADDRESS + 0x800


def jump(address: int) -> int:
    return 0x08000000 | ((address >> 2) & 0x03FFFFFF)


def branch(op: int, rs: int, rt: int, pc: int, target: int) -> int:
    displacement = (target - (pc + 4)) // 4
    if not -0x8000 <= displacement <= 0x7FFF or pc + 4 + displacement * 4 != target:
        raise BuildError("branch target is not encodable")
    return (op << 26) | (rs << 21) | (rt << 16) | (displacement & 0xFFFF)


def build_handler() -> bytes:
    """Return the complete 0x8018FCD0..0x8018FD8F E2 handler image."""
    lookup_common = LOOKUP_HANDLER + 12 * 4
    lookup_original = LOOKUP_HANDLER + 19 * 4
    lookup = [
        0x308800FF,  # andi  t0,a0,0xff
        0x250AFF80,  # addiu t2,t0,-0x80
        0x2D49006C,  # sltiu t1,t2,0x6c: reject below 0x80 and >=0xec together
        branch(0x04, 9, 0, LOOKUP_HANDLER + 3 * 4, lookup_original),
        0x250BFF58,  # delay: addiu t3,t0,-0xa8
        branch(0x04, 11, 0, LOOKUP_HANDLER + 5 * 4, lookup_original),
        0x2D0900A8,  # delay: sltiu t1,t0,0xa8
        branch(0x05, 9, 0, LOOKUP_HANDLER + 7 * 4, lookup_common),
        0x2D0900D0,  # delay: sltiu t1,t0,0xd0
        branch(0x05, 9, 0, LOOKUP_HANDLER + 9 * 4, lookup_common),
        0x254AFFFF,  # delay: Bank A high and Bank B both cross reserved A9
        0x254AF795,  # Bank B adjustment: logical slots -2076..-2049
        0x000A11C0,  # sll   v0,t2,7
        0x3C098011,  # lui   t1,0x8011
        0x25294000,  # addiu t1,t1,0x4000
        0x03E00008,  # jr    ra
        0x00491021,  # delay: addu v0,v0,t1
        0x00000000,
        0x00000000,
        jump(ORIGINAL_LOOKUP),
        0x00000000,
    ]

    completion_common = COMPLETION_HANDLER + 16 * 4
    completion_done = COMPLETION_HANDLER + 24 * 4
    completion = [
        0x8E080014,  # lw    t0,0x14(s0)
        0x34020001,  # load-delay filler and preserved success return value
        0x9109FFFF,  # lbu   t1,-1(t0): original disk E2 id
        0x3C0B8011,  # load-delay filler; standard-bank high half
        0x252AFF7F,  # addiu t2,t1,-0x81
        0x2D4C0028,  # sltiu t4,t2,40
        branch(0x05, 12, 0, COMPLETION_HANDLER + 6 * 4, completion_common),
        0x00000000,
        0x252AFF56,  # addiu t2,t1,-0xaa
        0x2D4C0027,  # sltiu t4,t2,39
        branch(0x05, 12, 0, COMPLETION_HANDLER + 10 * 4, completion_common),
        0x254A0028,  # delay: high Bank-A logical slot += 40
        0x252AFF2F,  # addiu t2,t1,-0xd1
        0x2D4C001C,  # sltiu t4,t2,28
        branch(0x04, 12, 0, COMPLETION_HANDLER + 14 * 4, completion_done),
        0x252AF713,  # delay: disk D1..EC -> logical -2076..-2049
        0x000A51C0,  # sll   t2,t2,7
        0x256B4000,  # addiu t3,t3,0x4000
        0x014B5021,  # addu  t2,t2,t3
        0x914B007F,  # lbu   t3,0x7f(t2)
        0x00000000,  # R3000 load-delay filler
        0x010B4021,  # addu  t0,t0,t3
        0xAE080014,  # sw    t0,0x14(s0)
        0x00000000,
        jump(COMPLETION_TARGET),
        0x3C08801F,  # preserve V354's return delay-slot register semantics
    ]
    if len(lookup) != 21 or len(completion) != 26:
        raise BuildError("handler word-count drift")
    blob = struct.pack("<21I", *lookup) + b"\0" * 4 + struct.pack("<26I", *completion)
    if len(blob) != HANDLER_SIZE or sha(blob) != CANDIDATE_HANDLER_SHA256:
        raise BuildError("candidate handler drift")
    return blob


def clone_info(source: ZipInfo) -> ZipInfo:
    clone = ZipInfo(source.filename, source.date_time)
    for attribute in (
        "compress_type", "comment", "extra", "create_system", "create_version",
        "extract_version", "flag_bits", "volume", "internal_attr", "external_attr",
    ):
        setattr(clone, attribute, getattr(source, attribute))
    return clone


def write_archive(path: Path, infos: list[ZipInfo], members: dict[str, bytes], names: list[str]) -> None:
    by_name = {item.filename: item for item in infos}
    with ZipFile(path, "w", compression=ZIP_DEFLATED, compresslevel=9) as archive:
        for name in names:
            archive.writestr(
                clone_info(by_name[name]), members[name],
                compress_type=ZIP_DEFLATED, compresslevel=9,
            )


def finalize_archive(temp: Path, stem: str) -> tuple[Path, str]:
    digest = sha(temp)
    output = temp.with_name(f"{stem}_{digest[:8]}.zip")
    if output.exists():
        if sha(output) != digest:
            raise BuildError(f"refusing to replace a different archive: {output}")
        temp.unlink()
    else:
        temp.replace(output)
    return output, digest


def differences(before: bytes, after: bytes) -> list[tuple[int, int, int]]:
    if len(before) != len(after):
        raise BuildError("member-size drift")
    return [(offset, old, new) for offset, (old, new) in enumerate(zip(before, after)) if old != new]


def main() -> None:
    if sha(BASE) != BASE_SHA256:
        raise BuildError("V354 archive hash drift")
    with ZipFile(BASE) as archive:
        infos = [item for item in archive.infolist() if not item.is_dir()]
        names = [item.filename for item in infos]
        base = {name: archive.read(name) for name in names}
    if len(names) != 164 or len(set(names)) != 164:
        raise BuildError("V354 archive topology drift")
    if sha(base[PSX]) != BASE_PSX_SHA256 or sha(base[PROBE_DAT]) != BASE_DAT_SHA256:
        raise BuildError("V354 member hash drift")

    handler_offset = file_offset(LOOKUP_HANDLER)
    current_handler = base[PSX][handler_offset:handler_offset + HANDLER_SIZE]
    if sha(current_handler) != BASE_HANDLER_SHA256:
        raise BuildError("V354 E2 handler drift")
    gate_offset = file_offset(CURSOR_GATE)
    if base[PSX][gate_offset:gate_offset + len(CURSOR_GATE_PREFIX)] != CURSOR_GATE_PREFIX:
        raise BuildError("range-cursor gate drift")

    dat = base[PROBE_DAT]
    bank = dat[BANK_B_OFFSET:BANK_B_OFFSET + BANK_B_SLOTS * SLOT_SIZE]
    source_slot = dat[STANDARD_SLOT_OFFSET:STANDARD_SLOT_OFFSET + SLOT_SIZE]
    if len(dat) != 305152 or sha(bank) != ZERO_BANK_SHA256 or any(bank):
        raise BuildError("Bank-B zero premise drift")
    if sha(source_slot) != STANDARD_SLOT_SHA256:
        raise BuildError("probe source slot drift")
    if dat[PROBE_BODY:PROBE_BODY + 2] != bytes((0xE2, PROBE_OLD_ID)):
        raise BuildError("probe E2 caller drift")

    output = dict(base)
    exe_out = bytearray(base[PSX])
    dat_out = bytearray(dat)
    exe_out[handler_offset:handler_offset + HANDLER_SIZE] = build_handler()
    dat_out[BANK_B_OFFSET:BANK_B_OFFSET + SLOT_SIZE] = source_slot
    dat_out[PROBE_BODY + 1] = PROBE_NEW_ID
    output[PSX] = bytes(exe_out)
    output[PROBE_DAT] = bytes(dat_out)

    changed_members = [name for name in names if output[name] != base[name]]
    if len(changed_members) != 2 or set(changed_members) != {PSX, PROBE_DAT}:
        raise BuildError(f"unexpected changed members: {changed_members}")
    if output[COMM] != base[COMM]:
        raise BuildError("COMM.IMG changed; VRAM budget must remain zero")

    ANALYSIS.mkdir(parents=True, exist_ok=True)
    OUT.mkdir(parents=True, exist_ok=True)
    full_temp = OUT / f"{OUTPUT_STEM}_TEMP.zip"
    delta_temp = OUT / f"{DELTA_STEM}_TEMP.zip"
    write_archive(full_temp, infos, output, names)
    write_archive(delta_temp, infos, output, changed_members)
    full_path, full_sha = finalize_archive(full_temp, OUTPUT_STEM)
    delta_path, delta_sha = finalize_archive(delta_temp, DELTA_STEM)

    diff_rows: list[dict[str, str]] = []
    reasons = {
        PSX: "E2 Bank-B lookup/completion handler",
        PROBE_DAT: "copy existing slot 14 to Bank-B D1 and redirect one caller",
    }
    for member in changed_members:
        for offset, old, new in differences(base[member], output[member]):
            diff_rows.append({
                "member": member,
                "file_offset": f"0x{offset:X}",
                "before": f"{old:02X}",
                "after": f"{new:02X}",
                "reason": reasons[member],
            })
    with (ANALYSIS / "expected_writes.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(diff_rows[0]))
        writer.writeheader()
        writer.writerows(diff_rows)

    manifest = {
        "version": "V355",
        "status": "STATIC CANDIDATE / RUNTIME PENDING / TEST_ONLY",
        "base": str(BASE.relative_to(ROOT)).replace("\\", "/"),
        "base_sha256": BASE_SHA256,
        "full_zip": str(full_path.relative_to(ROOT)).replace("\\", "/"),
        "full_sha256": full_sha,
        "delta_zip": str(delta_path.relative_to(ROOT)).replace("\\", "/"),
        "delta_sha256": delta_sha,
        "changed_members": changed_members,
        "member_sha256": {name: sha(output[name]) for name in changed_members},
        "actual_changed_bytes": {
            name: len(differences(base[name], output[name])) for name in changed_members
        },
        "additional_vram_bytes": 0,
        "handler": {
            "ram_range": "0x8018FCD0..0x8018FD8F",
            "file_range": f"0x{handler_offset:X}..0x{handler_offset + HANDLER_SIZE - 1:X}",
            "size": HANDLER_SIZE,
            "sha256": CANDIDATE_HANDLER_SHA256,
            "bank_b_ids": "D1..EC",
            "bank_b_ram": "0x800D3200..0x800D3FFF",
            "cursor_gate_first_address": "0x8018FD90 (unchanged)",
        },
        "probe": {
            "member": PROBE_DAT,
            "body_offset": f"0x{PROBE_BODY:X}",
            "old_e2": "E2 8F",
            "new_e2": "E2 D1",
            "source_slot": STANDARD_SLOT,
            "source_offset": f"0x{STANDARD_SLOT_OFFSET:X}",
            "bank_b_offset": f"0x{BANK_B_OFFSET:X}",
            "payload_and_metadata_byte_exact": True,
            "expected_visible_text": "3천 년이나 계속 타오르는 정령의 산, 시온의 불꽃.",
        },
    }
    (ANALYSIS / "build_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (ANALYSIS / "build_report.txt").write_text(
        "\n".join([
            "Arc the Lad 1 V355 E2 Bank-B runtime probe",
            "status: STATIC CANDIDATE / RUNTIME PENDING / TEST_ONLY",
            f"base: {BASE.name}",
            f"full: {full_path.name}",
            f"full sha256: {full_sha}",
            f"delta: {delta_path.name}",
            f"delta sha256: {delta_sha}",
            f"changed members: {', '.join(changed_members)}",
            f"actual changed bytes: PSX.EXE={manifest['actual_changed_bytes'][PSX]}, "
            f"{PROBE_DAT}={manifest['actual_changed_bytes'][PROBE_DAT]}",
            "additional VRAM: 0 bytes (COMM.IMG byte-identical)",
            "probe: 1/S1011.DAT 0x478AA E2 8F -> E2 D1; slot 14 copied byte-exact",
            "runtime acceptance: first new-game dialogue is visually identical and the next dialogue proceeds",
            "",
        ]), encoding="utf-8"
    )
    (ANALYSIS / "runtime_checklist.txt").write_text(
        "\n".join([
            "V355 TEST_ONLY runtime checklist",
            "1. Cold boot V355; do not resume a V354 RAM snapshot directly.",
            "2. Start a new game and reach the first 1/S1011 dialogue.",
            "3. Confirm the line is exactly:",
            "   3천 년이나 계속 타오르는 정령의 산, 시온의 불꽃.",
            "4. Advance and confirm the next dialogue appears normally.",
            "5. Save a state while the probe line is visible and another after advancing.",
            "6. Until both checks pass, keep V355 TEST_ONLY and do not promote it.",
            "",
        ]), encoding="utf-8"
    )
    print(f"V355 build complete: {full_path.name}")
    print(f"full sha256:  {full_sha}")
    print(f"delta sha256: {delta_sha}")
    print(f"changed bytes: {manifest['actual_changed_bytes']}")


if __name__ == "__main__":
    main()
