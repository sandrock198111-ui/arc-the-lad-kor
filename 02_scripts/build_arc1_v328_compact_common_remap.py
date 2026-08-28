#!/usr/bin/env python3
"""Build V328: remap legacy compact physical indices in the common glyph builder.

V326's raw-byte decoder catches only one parser path.  V327 runtime states show
that load/save level and time, item quantities, and battle HUD counters reach
the common builder already decoded as stock physical indices 0, 15..25 and
127.  On the 16px Hangul atlas those indices no longer mean blank, slash,
digits and the compact auxiliary glyph.

V328 hooks the common builder at 0x8016B51C.  Only text states whose width
field is exactly six pixels are eligible.  The stock compact indices are then
translated to V326's synthetic strip 960..972; every other state and glyph is
passed through byte-for-byte.  The leaf function's RA and all live registers
except the intentional a0 glyph value are preserved.
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
import build_ui_glyph_store_v41 as v41  # noqa: E402


BASE = ROOT / "03_output/arc1_v327_compact_ui_t1_restore_TEST_ONLY_B93E1001.zip"
BASE_SHA256 = "B93E100124AA69050DE6F181DB507E43042E20AF52EBEFC0857147D042B117EE"
BASE_PSX_SHA256 = "35508934198E7CC35659F8F56D59B58C3B199D7FE5B5B9B971EFD3E5B29365BA"
OUTPUT_STEM = "arc1_v328_compact_common_remap_TEST_ONLY"
DELTA_STEM = OUTPUT_STEM + "_delta_from_v327"
ANALYSIS = ROOT / "01_work/analysis/arc1_v328_compact_common_remap"

PSX = "PSX.EXE"
RAM_TO_FILE = 0x8011A800

HOOK_RAM = 0x8016B51C
HOOK_FILE = HOOK_RAM - RAM_TO_FILE
HOOK_DELAY_RAM = 0x8016B520
RETURN_RAM = 0x8016B524
EXPECTED_HOOK_WORD = 0x84C5000A       # lh a1,0x0a(a2)
EXPECTED_DELAY_WORD = 0x84C20004      # lh v0,4(a2)

# V326/V327 left this verified UI pool tail entirely zero.
HELPER_FILE = 0x80990
HELPER_RAM = RAM_TO_FILE + HELPER_FILE
HELPER_LIMIT = 0x80A94

SYNTH_BASE = 960
SYNTH_COUNT = 13
COMPACT_WIDTH = 6


class BuildError(RuntimeError):
    pass


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def sign16(value: int) -> int:
    return value - 0x10000 if value & 0x8000 else value


def branch_hits(exe: bytes, targets: set[int]) -> dict[int, list[tuple[int, int]]]:
    hits = {target: [] for target in targets}
    for offset in range(0, len(exe) - 3, 4):
        word = struct.unpack_from("<I", exe, offset)[0]
        pc = RAM_TO_FILE + offset
        op = word >> 26
        target: int | None = None
        if op in (1, 4, 5, 6, 7):
            target = (pc + 4 + sign16(word & 0xFFFF) * 4) & 0xFFFFFFFF
        elif op in (2, 3):
            target = ((pc + 4) & 0xF0000000) | ((word & 0x03FFFFFF) << 2)
        if target in hits:
            hits[target].append((pc, word))
    return hits


def remap_compact(width: int, glyph: int) -> int:
    """Independent truth table mirrored by the helper machine code."""
    if width != COMPACT_WIDTH:
        return glyph
    if glyph == 0:
        return SYNTH_BASE
    if 15 <= glyph <= 25:
        return SYNTH_BASE + 1 + glyph - 15
    if glyph == 127:
        return SYNTH_BASE + 12
    return glyph


def build_helper(address: int) -> bytes:
    asm = v41.Assembler(address)
    asm.emit(v41.i_type(0x24, v41.A2, v41.T0, 0x0D))        # lbu t0,0x0d(a2)
    asm.emit(v41.i_type(0x0D, v41.ZERO, v41.T1, 6))         # load-delay filler
    asm.branch(0x05, v41.T0, v41.T1, "done")               # bne t0,t1,done
    asm.emit(0)
    asm.branch(0x04, 4, v41.ZERO, "blank")                  # beq a0,zero,blank
    asm.emit(v41.i_type(0x09, 4, v41.T0, -15))              # delay: addiu t0,a0,-15
    asm.emit(v41.i_type(0x0B, v41.T0, v41.T1, 11))          # sltiu t1,t0,11
    asm.branch(0x05, v41.T1, v41.ZERO, "digit")             # bnez t1,digit
    asm.emit(v41.i_type(0x0D, v41.ZERO, v41.T1, 127))       # delay: ori t1,zero,127
    asm.branch(0x05, 4, v41.T1, "done")                     # bne a0,t1,done
    asm.emit(0)
    asm.emit(v41.i_type(0x0D, v41.ZERO, 4, SYNTH_BASE + 12))
    asm.branch(0x04, v41.ZERO, v41.ZERO, "done")
    asm.emit(0)
    asm.label("blank")
    asm.emit(v41.i_type(0x0D, v41.ZERO, 4, SYNTH_BASE))
    asm.branch(0x04, v41.ZERO, v41.ZERO, "done")
    asm.emit(0)
    asm.label("digit")
    asm.emit(v41.i_type(0x09, v41.T0, 4, SYNTH_BASE + 1))
    asm.label("done")
    asm.emit(v41.i_type(0x21, v41.A2, v41.A1, 0x0A))        # lh a1,0x0a(a2)
    asm.emit(v41.j(RETURN_RAM))
    asm.emit(0)                                              # settle lh before stock slt
    helper = asm.finish()
    if len(helper) != 84:
        raise BuildError(f"helper size drift: {len(helper)}")
    return helper


def build_once(before: dict[str, bytes]) -> tuple[dict[str, bytes], bytes]:
    members = dict(before)
    exe = bytearray(before[PSX])
    if struct.unpack_from("<I", exe, HOOK_FILE)[0] != EXPECTED_HOOK_WORD:
        raise BuildError("common-builder hook premise drift")
    if struct.unpack_from("<I", exe, HOOK_FILE + 4)[0] != EXPECTED_DELAY_WORD:
        raise BuildError("common-builder hook delay premise drift")
    helper = build_helper(HELPER_RAM)
    if HELPER_FILE + len(helper) > HELPER_LIMIT:
        raise BuildError("helper exceeds verified free UI pool")
    if any(exe[HELPER_FILE:HELPER_LIMIT]):
        raise BuildError("verified free UI pool is no longer zero")
    for offset in range(0, len(exe) - 3):
        value = struct.unpack_from("<I", exe, offset)[0]
        if HELPER_RAM <= value < HELPER_RAM + len(helper):
            raise BuildError(f"pre-existing pointer into helper cave at file 0x{offset:X}")

    helper_targets = set(range(HELPER_RAM, HELPER_RAM + len(helper), 4))
    incoming = branch_hits(bytes(exe), {HOOK_RAM, HOOK_DELAY_RAM, RETURN_RAM} | helper_targets)
    if incoming[HOOK_RAM] or incoming[HOOK_DELAY_RAM] or incoming[RETURN_RAM] or incoming[HELPER_RAM]:
        raise BuildError(f"unexpected pre-patch branch target: {incoming}")
    if any(incoming[target] for target in helper_targets):
        raise BuildError("pre-existing control-flow target enters helper cave")

    struct.pack_into("<I", exe, HOOK_FILE, v41.j(HELPER_RAM))
    exe[HELPER_FILE:HELPER_FILE + len(helper)] = helper
    members[PSX] = bytes(exe)
    return members, helper


def main() -> None:
    if not BASE.is_file() or v324.sha256_file(BASE) != BASE_SHA256:
        raise BuildError(f"V327 base hash mismatch: {BASE}")
    infos, before = v324.read_archive(BASE)
    if len(before) != 164 or sha256_bytes(before[PSX]) != BASE_PSX_SHA256:
        raise BuildError("V327 archive/PSX premise drift")

    final, helper = build_once(before)
    second, helper2 = build_once(before)
    if final != second or helper != helper2:
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
    allowed = set(range(HOOK_FILE, HOOK_FILE + 4)) | set(range(HELPER_FILE, HELPER_FILE + len(helper)))
    if not actual or not actual <= allowed or actual & set(range(HOOK_FILE + 4, HELPER_FILE)):
        raise BuildError("Expected-Write range mismatch")
    exe = final[PSX]
    helper_targets = set(range(HELPER_RAM, HELPER_RAM + len(helper), 4))
    post = branch_hits(exe, {HOOK_RAM, HOOK_DELAY_RAM, RETURN_RAM} | helper_targets)
    if post[HOOK_RAM] or post[HOOK_DELAY_RAM]:
        raise BuildError("hook middle became an inbound target")
    if post[HELPER_RAM] != [(HOOK_RAM, v41.j(HELPER_RAM))]:
        raise BuildError(f"helper inbound mismatch: {post[HELPER_RAM]}")
    external_middle = {
        target: [(source, word) for source, word in post[target] if not HELPER_RAM <= source < HELPER_RAM + len(helper)]
        for target in helper_targets - {HELPER_RAM}
    }
    if any(external_middle.values()):
        raise BuildError(f"external control flow enters helper middle: {external_middle}")
    return_source = HELPER_RAM + len(helper) - 8
    if post[RETURN_RAM] != [(return_source, v41.j(RETURN_RAM))]:
        raise BuildError(f"helper return target mismatch: {post[RETURN_RAM]}")

    for width in (6, 14, 16):
        for glyph in (0, 1, 14, 15, 16, 20, 25, 26, 126, 127, 128, 959, 960, 972, 1238):
            mapped = remap_compact(width, glyph)
            if width != 6:
                expected = glyph
            elif glyph == 0:
                expected = 960
            elif 15 <= glyph <= 25:
                expected = 961 + glyph - 15
            elif glyph == 127:
                expected = 972
            else:
                expected = glyph
            if mapped != expected:
                raise BuildError(f"truth-table failure width={width} glyph={glyph}")

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
        writer.writerow(("member", "offset", "before", "after", "region"))
        for offset in sorted(actual):
            region = "common_builder_hook" if offset < HOOK_FILE + 4 else "compact_common_helper"
            writer.writerow((PSX, f"0x{offset:X}", f"{before[PSX][offset]:02X}", f"{final[PSX][offset]:02X}", region))
    with (ANALYSIS / "remap_truth.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(("width", "input_physical", "output_physical", "meaning"))
        for width in (6, 14, 16):
            for glyph, meaning in ((0, "blank"), (15, "slash"), *[(x, f"digit_{x-16}") for x in range(16, 26)], (127, "aux")):
                writer.writerow((width, glyph, remap_compact(width, glyph), meaning))

    manifest = {
        "build": "V328 TEST_ONLY common-builder compact remap",
        "base": {"path": str(BASE), "sha256": BASE_SHA256},
        "output": {"path": str(output_path), "sha256": output_hash},
        "delta": {"path": str(delta_path), "sha256": delta_hash},
        "changed_members": [PSX],
        "changed_bytes": {PSX: len(actual)},
        "hook": {"ram": f"0x{HOOK_RAM:08X}", "delay_preserved": f"0x{HOOK_DELAY_RAM:08X}"},
        "helper": {"ram": f"0x{HELPER_RAM:08X}", "file": f"0x{HELPER_FILE:X}", "size": len(helper)},
        "scope": "state width D==6 only; 0->960, 15..25->961..971, 127->972",
        "preserved": "V327 COMM.IMG/DAT/UI strings/E7 icons/UV helper/t1 restore and every non-PSX member",
        "known_remaining": "E5 03 choice control emits two D14 physical-0 placeholder packets ('다') per option; intentionally out of V328 scope",
        "known_blocker": "V326 raw-code helper runs before this gate and globally remaps D14/D16 Hangul; fixed by V329",
        "runtime": "Superseded before approval",
        "release_status": "FAILED DIAGNOSTIC; DO NOT USE OR DISTRIBUTE",
    }
    (ANALYSIS / "build_manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    lines = [
        "V328 TEST ONLY - common-builder compact remap",
        f"base={BASE.name}",
        f"output={output_path.name}",
        f"sha256={output_hash}",
        f"delta={delta_path.name}",
        f"delta_sha256={delta_hash}",
        "changed_members=PSX.EXE only",
        f"changed_bytes={len(actual)}; hook=0x{HOOK_RAM:08X}; helper=0x{HELPER_RAM:08X}/{len(helper)}B",
        "scope=D==6 only: stock compact physical 0,15..25,127 -> synthetic 960..972",
        "expected=load level/time, item quantities, HP/MP/status digits use preserved compact strip",
        "D14/D16 Hangul and choice indentation=unchanged",
        "KNOWN BLOCKER=earlier raw-code helper bypasses width gate; DO NOT USE (fixed by V329)",
    ]
    (ANALYSIS / "build_report.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
