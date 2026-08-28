#!/usr/bin/env python3
"""Build V329: restore the stock one-byte decoder before V328's D==6 gate.

V326 redirected the resident one-byte decoder trampoline to a raw-code helper.
That helper cannot see the text state's width and therefore remaps ordinary
Korean one-byte codes in dialogue and 16px UI before V328 can reject them.

V328 already performs the required compact remap at the common glyph builder,
where state +0x0D is live.  V329 changes only the resident trampoline word back
to its stock destination, 0x8016B3E0.  Compact D==6 objects are still remapped
by V328 after stock decoding; D==14/16 text once again follows the stock path.
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


BASE = ROOT / "03_output/arc1_v328_compact_common_remap_TEST_ONLY_A71FCF2E.zip"
BASE_SHA256 = "A71FCF2E2F6C60EBFA554E6D4951FAE25CF7B3DC03CC27C9801EE4993CFC0324"
BASE_PSX_SHA256 = "6C2968C4A1DCB888D355840D91319CAB65F0A1208F010C7655A64D97C43F22FF"
OUTPUT_STEM = "arc1_v329_restore_stock_direct_decoder_TEST_ONLY"
DELTA_STEM = OUTPUT_STEM + "_delta_from_v328"
ANALYSIS = ROOT / "01_work/analysis/arc1_v329_restore_stock_direct_decoder"

PSX = "PSX.EXE"
RAM_TO_FILE = 0x8011A800

# This resident trampoline is a separately placed copy of the one-byte path.
DIRECT_TRAMPOLINE_FILE = 0x8EF44
DIRECT_TRAMPOLINE_RAM = RAM_TO_FILE + DIRECT_TRAMPOLINE_FILE
DIRECT_HELPER_RAM = 0x8019B0B0
STOCK_DIRECT_RAM = 0x8016B3E0
OLD_WORD = 0x08066C2C  # j 0x8019B0B0 (V326 raw-code helper)
NEW_WORD = 0x0805ACF8  # j 0x8016B3E0 (stock one-byte decoder)
DELAY_WORD = 0x00000000

# Stock one-byte decoder: v1 = raw - 1; advance source pointer; return.
STOCK_DECODER_FILE = STOCK_DIRECT_RAM - RAM_TO_FILE
STOCK_DECODER_PREFIX = (
    0x2463FFFF,  # addiu v1,v1,-1
    0x24A20001,  # addiu v0,a1,1
    0x0805AD04,  # j 0x8016B410
    0xACC20000,  # delay: sw v0,0(a2)
)

# Inherited mechanisms required after stock decoding.
COMMON_HOOK_FILE = 0x8016B51C - RAM_TO_FILE
COMMON_HOOK_WORD = 0x08066C64  # j 0x8019B190
COMMON_HOOK_DELAY = 0x84C20004
UV_HOOK_FILE = 0x8016B5A8 - RAM_TO_FILE
UV_HOOK_WORDS = (0x08066C44, 0x90C3000D)
UV_T1_RESTORE_FILE = 0x80940
UV_T1_RESTORE_WORD = 0x340900A0

SYNTH_BASE = 960
COMPACT_WIDTH = 6


class BuildError(RuntimeError):
    pass


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def sign16(value: int) -> int:
    return value - 0x10000 if value & 0x8000 else value


def jump_target(pc: int, word: int) -> int | None:
    op = word >> 26
    if op in (1, 4, 5, 6, 7):
        return (pc + 4 + sign16(word & 0xFFFF) * 4) & 0xFFFFFFFF
    if op in (2, 3):
        return ((pc + 4) & 0xF0000000) | ((word & 0x03FFFFFF) << 2)
    return None


def inbound(exe: bytes, target: int) -> list[tuple[int, int]]:
    hits: list[tuple[int, int]] = []
    for offset in range(0, len(exe) - 3, 4):
        word = struct.unpack_from("<I", exe, offset)[0]
        pc = RAM_TO_FILE + offset
        if jump_target(pc, word) == target:
            hits.append((pc, word))
    return hits


def remap_after_stock_decode(width: int, physical: int) -> int:
    if width != COMPACT_WIDTH:
        return physical
    if physical == 0:
        return SYNTH_BASE
    if 15 <= physical <= 25:
        return SYNTH_BASE + 1 + physical - 15
    if physical == 127:
        return SYNTH_BASE + 12
    return physical


def build_once(before: dict[str, bytes]) -> dict[str, bytes]:
    members = dict(before)
    exe = bytearray(before[PSX])
    if struct.unpack_from("<II", exe, DIRECT_TRAMPOLINE_FILE) != (OLD_WORD, DELAY_WORD):
        raise BuildError("V328 raw-decoder trampoline premise drift")
    if struct.unpack_from("<4I", exe, STOCK_DECODER_FILE) != STOCK_DECODER_PREFIX:
        raise BuildError("stock one-byte decoder prefix drift")
    if struct.unpack_from("<II", exe, COMMON_HOOK_FILE) != (COMMON_HOOK_WORD, COMMON_HOOK_DELAY):
        raise BuildError("V328 common-builder gate drift")
    if struct.unpack_from("<II", exe, UV_HOOK_FILE) != UV_HOOK_WORDS:
        raise BuildError("V326 synthetic UV routing drift")
    if struct.unpack_from("<I", exe, UV_T1_RESTORE_FILE)[0] != UV_T1_RESTORE_WORD:
        raise BuildError("V327 t1 restore drift")
    expected_old_inbound = [(DIRECT_TRAMPOLINE_RAM, OLD_WORD)]
    if inbound(bytes(exe), DIRECT_HELPER_RAM) != expected_old_inbound:
        raise BuildError("raw helper has an unexpected inbound path")

    struct.pack_into("<I", exe, DIRECT_TRAMPOLINE_FILE, NEW_WORD)
    if inbound(bytes(exe), DIRECT_HELPER_RAM):
        raise BuildError("raw helper remains reachable after restoration")
    members[PSX] = bytes(exe)
    return members


def main() -> None:
    if not BASE.is_file() or v324.sha256_file(BASE) != BASE_SHA256:
        raise BuildError(f"V328 base hash mismatch: {BASE}")
    infos, before = v324.read_archive(BASE)
    if len(before) != 164 or sha256_bytes(before[PSX]) != BASE_PSX_SHA256:
        raise BuildError("V328 archive/PSX premise drift")

    final = build_once(before)
    if final != build_once(before):
        raise BuildError("in-memory deterministic rebuild mismatch")
    changed_members = [name for name in before if before[name] != final[name]]
    if changed_members != [PSX]:
        raise BuildError(f"changed member set drift: {changed_members}")
    if any(len(before[name]) != len(final[name]) for name in before):
        raise BuildError("member size changed")

    actual = {
        offset for offset, (old, new) in enumerate(zip(before[PSX], final[PSX], strict=True))
        if old != new
    }
    expected = {
        DIRECT_TRAMPOLINE_FILE + index
        for index, (old, new) in enumerate(zip(struct.pack("<I", OLD_WORD), struct.pack("<I", NEW_WORD)))
        if old != new
    }
    if actual != expected:
        raise BuildError(f"Expected-Write mismatch: {sorted(actual)}")

    # Pipeline truth table: stock raw-byte decode first, then V328's D gate.
    for width in (6, 14, 16):
        for raw in range(1, 0xDD):
            physical = raw - 1
            mapped = remap_after_stock_decode(width, physical)
            if width != 6 and mapped != physical:
                raise BuildError(f"non-compact raw regression D={width} raw=0x{raw:02X}")
            eligible = physical == 0 or 15 <= physical <= 25 or physical == 127
            if width == 6 and (mapped != physical) != eligible:
                raise BuildError(f"compact raw truth mismatch raw=0x{raw:02X}")

    output_path, output_hash = v324.write_archive(OUTPUT_STEM, infos, final, None)
    delta_path, delta_hash = v324.write_archive(DELTA_STEM, infos, final, {PSX})
    with ZipFile(output_path) as archive:
        names = [item.filename for item in archive.infolist() if not item.is_dir()]
        expected_names = [item.filename for item in infos if not item.is_dir()]
        if names != expected_names or any(archive.read(name) != final[name] for name in final):
            raise BuildError("full ZIP round-trip/topology mismatch")
    with ZipFile(delta_path) as archive:
        if archive.namelist() != [PSX] or archive.read(PSX) != final[PSX]:
            raise BuildError("delta ZIP mismatch")

    ANALYSIS.mkdir(parents=True, exist_ok=True)
    with (ANALYSIS / "expected_writes.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(("member", "offset", "before", "after", "purpose"))
        for offset in sorted(actual):
            writer.writerow((
                PSX, f"0x{offset:X}", f"{before[PSX][offset]:02X}",
                f"{final[PSX][offset]:02X}", "restore_stock_one_byte_decoder_trampoline",
            ))
    with (ANALYSIS / "pipeline_truth.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(("width", "raw_byte", "stock_physical", "final_physical", "class"))
        for width in (6, 14, 16):
            for raw in (0x01, *range(0x10, 0x1B), 0x80):
                physical = raw - 1
                writer.writerow((
                    width, f"0x{raw:02X}", physical,
                    remap_after_stock_decode(width, physical),
                    "compact" if width == 6 else "hangul_identity",
                ))

    manifest = {
        "build": "V329 TEST_ONLY restore stock direct decoder",
        "base": {"path": str(BASE), "sha256": BASE_SHA256},
        "output": {"path": str(output_path), "sha256": output_hash},
        "delta": {"path": str(delta_path), "sha256": delta_hash},
        "changed_members": [PSX],
        "changed_bytes": {PSX: len(actual)},
        "patch": {
            "file_offset": f"0x{DIRECT_TRAMPOLINE_FILE:X}",
            "runtime_source": f"0x{DIRECT_TRAMPOLINE_RAM:08X}",
            "old_destination": f"0x{DIRECT_HELPER_RAM:08X}",
            "new_destination": f"0x{STOCK_DIRECT_RAM:08X}",
        },
        "scope": "restore stock raw decode; retain V328 D==6 physical-index remap",
        "preserved": "V328 common gate, UV strip, t1 restore, COMM.IMG, DAT and all non-PSX members",
        "known_remaining": "E5 choice-prefix physical-0 packets require a separate handler/data investigation",
        "runtime": "PENDING user cold boot and dialogue/load/item/battle traversal",
        "release_status": "DIAGNOSTIC; DO NOT DISTRIBUTE",
    }
    (ANALYSIS / "build_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    report = [
        "V329 TEST ONLY - restore stock direct decoder",
        f"base={BASE.name}",
        f"output={output_path.name}",
        f"sha256={output_hash}",
        f"delta={delta_path.name}",
        f"delta_sha256={delta_hash}",
        "changed_members=PSX.EXE only",
        f"changed_bytes={len(actual)} in one jump word at file 0x{DIRECT_TRAMPOLINE_FILE:X}",
        "patch=j raw-helper -> j stock 0x8016B3E0; delay nop preserved",
        "D6 compact path=stock decode then V328 960..972 remap",
        "D14/D16 one-byte Hangul=stock physical indices, no synthetic remap",
        "runtime=PENDING; TEST_ONLY",
    ]
    (ANALYSIS / "build_report.txt").write_text("\n".join(report) + "\n", encoding="utf-8")
    print("\n".join(report))


if __name__ == "__main__":
    main()
