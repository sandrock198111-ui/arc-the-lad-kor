#!/usr/bin/env python3
"""Build V334: move V333 UI payloads out of a live MIPS delay slot.

V333 placed the first local UI string at file 0x809E0 / RAM 0x8019B1E0.
That word is not free: it is the delay slot of the jump at 0x8019B1DC.
The resulting word 0xF4DFE7DF raises a Reserved Instruction exception during
the first common-glyph build.  V334 restores the delay slot to NOP and packs
the same four strings into the proven-zero bytes beginning at 0x809E4.

Only PSX.EXE changes.  COMM.IMG, every DAT member, V333's synthetic glyphs,
UV routing, E5 placeholder and all V332 alignment work remain byte-identical.
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
sys.path.insert(0, str(ROOT / "02_scripts"))
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

import build_arc1_v324_static_ui_cursor_recovery as v324  # noqa: E402


BASE = ROOT / "03_output/arc1_v333_dynamic_ui_glyph_recovery_TEST_ONLY_55D826DC.zip"
BASE_SHA256 = "55D826DC02FE5A7DE5167EBB81623184409FA4F8FC395B2EB04369A17DC2D450"
BASE_PSX_SHA256 = "6E7E9E3A0521C502E4672F95C55F73B77C31D9DA3EA3C66A6B8F36FF961A8567"
BASE_COMM_SHA256 = "095885C3EA58F1A886BEE20033EE8313FE07476088AC27FD726F53AE44D8331B"

OUTPUT_STEM = "arc1_v334_delay_slot_payload_relocation_TEST_ONLY"
DELTA_STEM = OUTPUT_STEM + "_delta_from_v333"
ANALYSIS = ROOT / "01_work/analysis/arc1_v334_delay_slot_payload_relocation"

PSX = "PSX.EXE"
COMM = "COMM.IMG"
RAM_TO_FILE = 0x8011A800

JUMP_FILE = 0x809DC
DELAY_FILE = 0x809E0
JUMP_WORD = 0x0805AD49  # j 0x8016B524
BAD_DELAY_WORD = 0xF4DFE7DF
NOP = 0

POOL_START = 0x809E0
POOL_END = 0x809F9
BASE_POOL = bytes.fromhex(
    "DF E7 DF F4 00 00 00 00 "
    "DF E7 DF F5 00 00 00 00 "
    "DF F6 00 00 DF F4 00 00 00"
)

# V333 payload bytes are retained exactly; only their addresses change.
HUD_L = bytes.fromhex("DF E7 DF F4 00")
HUD_M = bytes.fromhex("DF E7 DF F5 00")
HUD_P = bytes.fromhex("DF F6 00")
LOAD_L = bytes.fromhex("DF F4 00")

HUD_L_FILE = 0x809E4
HUD_M_FILE = 0x809E9
HUD_P_FILE = 0x809EE
LOAD_L_FILE = 0x809F1
EMPTY_FILE = 0x809F4

LOAD_L_POINTER_FILE = 0x780FC
HUD_POINTERS_FILE = 0x823AC
HUD_AUX_POINTER = 0x8019C95C

V333_LOAD_L_POINTER = 0x8019B1F4
V333_HUD_POINTERS = (
    0x8019B1E0,
    0x8019B1F8,
    HUD_AUX_POINTER,
    0x8019B1E8,
    0x8019B1F0,
)

# V333 routes that this repair must not redesign.
UV_COUNT_FILE = 0x80918
UV_COUNT_WORD = 0x2D090011
E5_PLACEHOLDER_FILE = 0x51604
E5_PLACEHOLDER_WORD = 0x340403C0


class BuildError(RuntimeError):
    pass


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def changed_offsets(before: bytes, after: bytes) -> set[int]:
    if len(before) != len(after):
        raise BuildError("member size changed")
    return {
        offset
        for offset, (old, new) in enumerate(zip(before, after, strict=True))
        if old != new
    }


def pointer_hits(exe: bytes, start_ram: int, end_ram: int) -> list[tuple[int, int]]:
    hits: list[tuple[int, int]] = []
    for offset in range(0, len(exe) - 3):
        value = struct.unpack_from("<I", exe, offset)[0]
        if start_ram <= value < end_ram:
            hits.append((offset, value))
    return hits


def control_targets(exe: bytes, start_ram: int, end_ram: int) -> list[tuple[int, int]]:
    hits: list[tuple[int, int]] = []
    for offset in range(0x800, len(exe) - 3, 4):
        word = struct.unpack_from("<I", exe, offset)[0]
        address = RAM_TO_FILE + offset
        opcode = word >> 26
        target: int | None = None
        if opcode in (2, 3):
            target = ((address + 4) & 0xF0000000) | ((word & 0x03FFFFFF) << 2)
        elif opcode in (1, 4, 5, 6, 7):
            immediate = word & 0xFFFF
            if immediate & 0x8000:
                immediate -= 0x10000
            target = address + 4 + (immediate << 2)
        if target is not None and start_ram <= target < end_ram:
            hits.append((address, target))
    return hits


def assert_base(members: dict[str, bytes]) -> None:
    exe = members[PSX]
    if len(members) != 164:
        raise BuildError(f"V333 member count drift: {len(members)}")
    if sha256_bytes(exe) != BASE_PSX_SHA256:
        raise BuildError("V333 PSX.EXE hash drift")
    if sha256_bytes(members[COMM]) != BASE_COMM_SHA256:
        raise BuildError("V333 COMM.IMG hash drift")
    if struct.unpack_from("<I", exe, JUMP_FILE)[0] != JUMP_WORD:
        raise BuildError("common-remap return jump drift")
    if struct.unpack_from("<I", exe, DELAY_FILE)[0] != BAD_DELAY_WORD:
        raise BuildError("V333 failing delay-slot word drift")
    if exe[POOL_START:POOL_END] != BASE_POOL:
        raise BuildError("V333 local payload pool drift")
    if struct.unpack_from("<I", exe, LOAD_L_POINTER_FILE)[0] != V333_LOAD_L_POINTER:
        raise BuildError("V333 load-L pointer drift")
    if struct.unpack_from("<5I", exe, HUD_POINTERS_FILE) != V333_HUD_POINTERS:
        raise BuildError("V333 HUD pointer table drift")
    if struct.unpack_from("<I", exe, UV_COUNT_FILE)[0] != UV_COUNT_WORD:
        raise BuildError("V333 UV route drift")
    if struct.unpack_from("<I", exe, E5_PLACEHOLDER_FILE)[0] != E5_PLACEHOLDER_WORD:
        raise BuildError("V333 E5 placeholder drift")


def build_once(before: dict[str, bytes]) -> tuple[dict[str, bytes], dict[str, object]]:
    assert_base(before)
    exe = bytearray(before[PSX])

    # Clear the complete old local pool first.  This restores the live delay
    # slot and guarantees that no stale terminator or token remains.
    exe[POOL_START:POOL_END] = b"\0" * (POOL_END - POOL_START)
    for offset, payload in (
        (HUD_L_FILE, HUD_L),
        (HUD_M_FILE, HUD_M),
        (HUD_P_FILE, HUD_P),
        (LOAD_L_FILE, LOAD_L),
    ):
        exe[offset : offset + len(payload)] = payload
    exe[EMPTY_FILE] = 0

    load_l_pointer = RAM_TO_FILE + LOAD_L_FILE
    hud_pointers = (
        RAM_TO_FILE + HUD_L_FILE,
        RAM_TO_FILE + EMPTY_FILE,
        HUD_AUX_POINTER,
        RAM_TO_FILE + HUD_M_FILE,
        RAM_TO_FILE + HUD_P_FILE,
    )
    struct.pack_into("<I", exe, LOAD_L_POINTER_FILE, load_l_pointer)
    struct.pack_into("<5I", exe, HUD_POINTERS_FILE, *hud_pointers)

    if struct.unpack_from("<I", exe, DELAY_FILE)[0] != NOP:
        raise BuildError("delay slot was not restored to NOP")
    for offset, payload in (
        (HUD_L_FILE, HUD_L),
        (HUD_M_FILE, HUD_M),
        (HUD_P_FILE, HUD_P),
        (LOAD_L_FILE, LOAD_L),
    ):
        if exe[offset : offset + len(payload)] != payload:
            raise BuildError(f"payload readback failed at 0x{offset:X}")
    if struct.unpack_from("<I", exe, LOAD_L_POINTER_FILE)[0] != load_l_pointer:
        raise BuildError("load-L pointer readback failed")
    if struct.unpack_from("<5I", exe, HUD_POINTERS_FILE) != hud_pointers:
        raise BuildError("HUD pointer readback failed")

    pool_ram_start = RAM_TO_FILE + HUD_L_FILE
    pool_ram_end = RAM_TO_FILE + POOL_END
    allowed_pointer_offsets = {
        LOAD_L_POINTER_FILE,
        HUD_POINTERS_FILE,
        HUD_POINTERS_FILE + 4,
        HUD_POINTERS_FILE + 12,
        HUD_POINTERS_FILE + 16,
    }
    actual_hits = pointer_hits(bytes(exe), pool_ram_start, pool_ram_end)
    if {offset for offset, _value in actual_hits} != allowed_pointer_offsets:
        raise BuildError(f"relocated-pool pointer ownership drift: {actual_hits}")
    if control_targets(bytes(exe), pool_ram_start, pool_ram_end):
        raise BuildError("control transfer enters relocated data pool")

    final = dict(before)
    final[PSX] = bytes(exe)
    metadata = {
        "failure": {
            "branch_pc": "0x8019B1DC",
            "bad_delay_pc": "0x8019B1E0",
            "bad_word": "0xF4DFE7DF",
            "cause": "0xD0000428: ExcCode 10 Reserved Instruction, BD=1",
        },
        "layout": {
            "delay_nop": "0x8019B1E0",
            "hud_l": f"0x{RAM_TO_FILE + HUD_L_FILE:08X}",
            "hud_m": f"0x{RAM_TO_FILE + HUD_M_FILE:08X}",
            "hud_p": f"0x{RAM_TO_FILE + HUD_P_FILE:08X}",
            "load_l": f"0x{RAM_TO_FILE + LOAD_L_FILE:08X}",
            "empty": f"0x{RAM_TO_FILE + EMPTY_FILE:08X}",
        },
        "pointer_hits": [
            {"file_offset": f"0x{offset:X}", "value": f"0x{value:08X}"}
            for offset, value in actual_hits
        ],
    }
    return final, metadata


def main() -> None:
    if not BASE.is_file() or v324.sha256_file(BASE) != BASE_SHA256:
        raise BuildError(f"V333 base hash mismatch: {BASE}")
    infos, before = v324.read_archive(BASE)

    final, metadata = build_once(before)
    rebuilt, rebuilt_metadata = build_once(before)
    if final != rebuilt or metadata != rebuilt_metadata:
        raise BuildError("in-memory deterministic rebuild mismatch")

    changed_members = [name for name in before if before[name] != final[name]]
    if changed_members != [PSX]:
        raise BuildError(f"changed member set drift: {changed_members}")
    if any(len(before[name]) != len(final[name]) for name in before):
        raise BuildError("member size changed")

    actual = changed_offsets(before[PSX], final[PSX])
    envelope = set(range(POOL_START, POOL_END))
    envelope |= set(range(LOAD_L_POINTER_FILE, LOAD_L_POINTER_FILE + 4))
    envelope |= set(range(HUD_POINTERS_FILE, HUD_POINTERS_FILE + 20))
    if not actual <= envelope:
        raise BuildError(f"Expected-Write escape: {sorted(actual - envelope)[:8]}")

    output_path, output_hash = v324.write_archive(OUTPUT_STEM, infos, final, None)
    delta_path, delta_hash = v324.write_archive(DELTA_STEM, infos, final, {PSX})
    with ZipFile(output_path) as archive:
        names = [item.filename for item in archive.infolist() if not item.is_dir()]
        expected_names = [item.filename for item in infos if not item.is_dir()]
        if names != expected_names or any(archive.read(name) != final[name] for name in final):
            raise BuildError("full ZIP round-trip/topology mismatch")
    with ZipFile(delta_path) as archive:
        if archive.namelist() != [PSX] or archive.read(PSX) != final[PSX]:
            raise BuildError("delta ZIP round-trip mismatch")

    ANALYSIS.mkdir(parents=True, exist_ok=True)
    with (ANALYSIS / "expected_writes.csv").open(
        "w", encoding="utf-8-sig", newline=""
    ) as handle:
        writer = csv.writer(handle)
        writer.writerow(("member", "offset", "before", "after", "purpose"))
        for offset in sorted(actual):
            if DELAY_FILE <= offset < DELAY_FILE + 4:
                purpose = "restore_live_jump_delay_slot_to_nop"
            elif POOL_START <= offset < POOL_END:
                purpose = "relocate_local_UI_payload"
            elif offset < LOAD_L_POINTER_FILE + 4:
                purpose = "load_L_pointer"
            else:
                purpose = "battle_HUD_pointer"
            writer.writerow(
                (
                    PSX,
                    f"0x{offset:X}",
                    f"{before[PSX][offset]:02X}",
                    f"{final[PSX][offset]:02X}",
                    purpose,
                )
            )

    manifest = {
        "build": "V334 TEST_ONLY V333 delay-slot payload relocation",
        "base": {"path": str(BASE), "sha256": BASE_SHA256},
        "output": {"path": str(output_path), "sha256": output_hash},
        "delta": {"path": str(delta_path), "sha256": delta_hash},
        "changed_members": changed_members,
        "changed_bytes": {PSX: len(actual)},
        **metadata,
        "preserved": (
            "V333 COMM.IMG and synthetic glyphs, all DAT, UV count, E5 blank, "
            "V332 skill/config alignment and every non-PSX member"
        ),
        "runtime": "PENDING user cold boot",
        "release_status": "DIAGNOSTIC; DO NOT DISTRIBUTE",
    }
    (ANALYSIS / "build_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    report = [
        "V334 TEST ONLY - V333 delay-slot payload relocation",
        f"base={BASE.name}",
        f"output={output_path.name}",
        f"sha256={output_hash}",
        f"delta={delta_path.name}",
        f"delta_sha256={delta_hash}",
        "changed_members=PSX.EXE only",
        f"changed_bytes={len(actual)}",
        "failure=V333 wrote 0xF4DFE7DF into live jump delay slot 0x8019B1E0",
        "repair=restore NOP and move identical local UI payloads to 0x8019B1E4 onward",
        "COMM.IMG/all DAT/V333 UI routes=unchanged",
        "runtime=PENDING; TEST_ONLY",
    ]
    (ANALYSIS / "build_report.txt").write_text("\n".join(report) + "\n", encoding="utf-8")
    print("\n".join(report))


if __name__ == "__main__":
    main()
