#!/usr/bin/env python3
"""Build V330: move only the battle skill-name glyph packets four pixels left.

V329 runtime state 4 proves that the six-token skill name ``번 그라운드``
starts at packet X=198 and its final 16-pixel sprite starts at X=260.  The
window is still sized with the old 12-pixel metric, so the final sprite touches
the right border after the 14-pixel Hangul advance.

The skill-name table has a dedicated caller at 0x80162080.  V330 redirects
only that JAL to a wrapper in V329's now-unreachable raw-decoder helper area.
The wrapper calls the original window/text routine unchanged, then invokes the
stock packet-offset helper 0x8016B440 with dx=-4, dy=0 for text object
0x801F1DB4.  The window, skill description, items, equipment, status UI and
dialogue therefore retain their V329 coordinates.
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


BASE = ROOT / "03_output/arc1_v329_restore_stock_direct_decoder_TEST_ONLY_25C7DECF.zip"
BASE_SHA256 = "25C7DECF7D69B356DCBA2B2CB098D0667EB7CF081CB8A87B4AB64583ABBF8C90"
BASE_PSX_SHA256 = "00AD3D5E3EC4664BCEAB563351B9952B0735FC8745787C06E9A722B8CB9BB547"
OUTPUT_STEM = "arc1_v330_skill_name_x_minus4_TEST_ONLY"
DELTA_STEM = OUTPUT_STEM + "_delta_from_v329"
ANALYSIS = ROOT / "01_work/analysis/arc1_v330_skill_name_x_minus4"

PSX = "PSX.EXE"
RAM_TO_FILE = 0x8011A800

SKILL_CALL_RAM = 0x80162080
SKILL_CALL_FILE = SKILL_CALL_RAM - RAM_TO_FILE
ORIGINAL_TEXT_ROUTINE = 0x8016C38C
PACKET_OFFSET_ROUTINE = 0x8016B440
SKILL_STATE = 0x801F1DB4
SHIFT_X = -4

# This was V326's raw decoder helper.  V329 proves that no branch, jump or
# pointer reaches the 92-byte region after the stock decoder restoration.
WRAPPER_RAM = 0x8019B0B0
WRAPPER_FILE = WRAPPER_RAM - RAM_TO_FILE
WRAPPER_REGION_SIZE = 92
V329_DEAD_REGION_SHA256 = "F0D9AA59AACFFD1C9EEB58949B7E8E6FF50F29921BBB419B33E103B7BAE00C11"

ORIGINAL_CALL_WORD = 0x0C05B0E3  # jal 0x8016C38C
WRAPPER_CALL_WORD = 0x0C066C2C   # jal 0x8019B0B0
CALL_DELAY_WORD = 0xAFA20010     # sw v0,0x10(sp): selected skill string

# The surrounding table load fixes this caller to the 59-entry skill-name
# table at RAM 0x8019B9C0 / file 0x811C0.
SKILL_CALL_CONTEXT_RAM = 0x80162060
SKILL_CALL_CONTEXT_FILE = SKILL_CALL_CONTEXT_RAM - RAM_TO_FILE
SKILL_CALL_CONTEXT = (
    0x02202021,  # move a0,s1
    0x00521021,  # addu v0,v0,s2
    0x00028880,  # sll s1,v0,2
    0x3C01801A,  # lui at,0x801A
    0x2421B9C0,  # addiu at,at,-0x4640 -> 0x8019B9C0 skill names
    0x00310821,  # addu at,at,s1
    0x8C220000,  # lw v0,0(at)
    0x34070018,  # ori a3,zero,0x18
    ORIGINAL_CALL_WORD,
    CALL_DELAY_WORD,
)


def jal(target: int) -> int:
    return 0x0C000000 | ((target >> 2) & 0x03FFFFFF)


WRAPPER_WORDS = (
    0x27BDFFE8,                   # addiu sp,sp,-0x18
    0xAFBF0014,                   # sw ra,0x14(sp)
    0x8FA20028,                   # lw v0,0x28(sp): caller sp+0x10
    0x00000000,                   # load delay
    0xAFA20010,                   # sw v0,0x10(sp): fifth arg for C38C
    jal(ORIGINAL_TEXT_ROUTINE),   # original skill window/text routine
    0x00000000,                   # JAL delay
    0x2404FFFC,                   # addiu a0,zero,-4
    0x00002821,                   # move a1,zero
    0x3C06801F,                   # lui a2,0x801F
    0x24C61DB4,                   # addiu a2,a2,0x1DB4
    jal(PACKET_OFFSET_ROUTINE),   # shift only rendered skill-name packets
    0x00000000,                   # JAL delay
    0x8FBF0014,                   # lw ra,0x14(sp)
    0x00000000,                   # load delay
    0x03E00008,                   # jr ra
    0x27BD0018,                   # restore sp in return delay
)
WRAPPER_BLOB = struct.pack(f"<{len(WRAPPER_WORDS)}I", *WRAPPER_WORDS).ljust(
    WRAPPER_REGION_SIZE, b"\x00"
)


class BuildError(RuntimeError):
    pass


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def sign16(value: int) -> int:
    return value - 0x10000 if value & 0x8000 else value


def control_target(pc: int, word: int) -> int | None:
    op = word >> 26
    if op in (1, 4, 5, 6, 7):
        return (pc + 4 + sign16(word & 0xFFFF) * 4) & 0xFFFFFFFF
    if op in (2, 3):
        return ((pc + 4) & 0xF0000000) | ((word & 0x03FFFFFF) << 2)
    return None


def external_inbound(exe: bytes, start: int, size: int) -> list[tuple[int, int, int]]:
    hits: list[tuple[int, int, int]] = []
    end = start + size
    for offset in range(0, len(exe) - 3, 4):
        pc = RAM_TO_FILE + offset
        word = struct.unpack_from("<I", exe, offset)[0]
        target = control_target(pc, word)
        if target is not None and start <= target < end and not start <= pc < end:
            hits.append((pc, word, target))
    return hits


def pointer_hits(exe: bytes, start: int, size: int) -> list[tuple[int, int]]:
    result = []
    end = start + size
    for offset in range(0, len(exe) - 3):
        value = struct.unpack_from("<I", exe, offset)[0]
        if start <= value < end:
            result.append((offset, value))
    return result


def build_once(before: dict[str, bytes]) -> dict[str, bytes]:
    members = dict(before)
    exe = bytearray(before[PSX])
    if struct.unpack_from("<10I", exe, SKILL_CALL_CONTEXT_FILE) != SKILL_CALL_CONTEXT:
        raise BuildError("skill-name caller/table context drift")
    old_region = bytes(exe[WRAPPER_FILE : WRAPPER_FILE + WRAPPER_REGION_SIZE])
    if sha256_bytes(old_region) != V329_DEAD_REGION_SHA256:
        raise BuildError("V329 dead raw-helper region drift")
    if external_inbound(bytes(exe), WRAPPER_RAM, WRAPPER_REGION_SIZE):
        raise BuildError("V329 dead region unexpectedly has control-flow inbound")
    if pointer_hits(bytes(exe), WRAPPER_RAM, WRAPPER_REGION_SIZE):
        raise BuildError("V329 dead region unexpectedly has a pointer inbound")
    if external_inbound(bytes(exe), SKILL_CALL_RAM, 4):
        raise BuildError("skill call word is an external branch/jump target")

    struct.pack_into("<I", exe, SKILL_CALL_FILE, WRAPPER_CALL_WORD)
    exe[WRAPPER_FILE : WRAPPER_FILE + WRAPPER_REGION_SIZE] = WRAPPER_BLOB

    inbound = external_inbound(bytes(exe), WRAPPER_RAM, WRAPPER_REGION_SIZE)
    if inbound != [(SKILL_CALL_RAM, WRAPPER_CALL_WORD, WRAPPER_RAM)]:
        raise BuildError(f"V330 wrapper inbound drift: {inbound}")
    members[PSX] = bytes(exe)
    return members


def main() -> None:
    if not BASE.is_file() or v324.sha256_file(BASE) != BASE_SHA256:
        raise BuildError(f"V329 base hash mismatch: {BASE}")
    infos, before = v324.read_archive(BASE)
    if len(before) != 164 or sha256_bytes(before[PSX]) != BASE_PSX_SHA256:
        raise BuildError("V329 archive/PSX premise drift")

    final = build_once(before)
    if final != build_once(before):
        raise BuildError("in-memory deterministic rebuild mismatch")
    changed_members = [name for name in before if before[name] != final[name]]
    if changed_members != [PSX]:
        raise BuildError(f"changed member set drift: {changed_members}")
    if any(len(before[name]) != len(final[name]) for name in before):
        raise BuildError("member size changed")

    actual = {
        offset
        for offset, (old, new) in enumerate(zip(before[PSX], final[PSX], strict=True))
        if old != new
    }
    candidate = {SKILL_CALL_FILE, SKILL_CALL_FILE + 1, SKILL_CALL_FILE + 2, SKILL_CALL_FILE + 3}
    candidate.update(range(WRAPPER_FILE, WRAPPER_FILE + WRAPPER_REGION_SIZE))
    expected = {offset for offset in candidate if before[PSX][offset] != final[PSX][offset]}
    if actual != expected:
        raise BuildError("Expected-Write envelope mismatch")

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
            purpose = "skill_call_to_shift_wrapper" if SKILL_CALL_FILE <= offset < SKILL_CALL_FILE + 4 else "skill_shift_wrapper"
            writer.writerow((PSX, f"0x{offset:X}", f"{before[PSX][offset]:02X}", f"{final[PSX][offset]:02X}", purpose))

    manifest = {
        "build": "V330 TEST_ONLY skill-name x minus 4",
        "base": {"path": str(BASE), "sha256": BASE_SHA256},
        "output": {"path": str(output_path), "sha256": output_hash},
        "delta": {"path": str(delta_path), "sha256": delta_hash},
        "changed_members": [PSX],
        "changed_bytes": {PSX: len(actual)},
        "patch": {
            "skill_call_file": f"0x{SKILL_CALL_FILE:X}",
            "skill_call_ram": f"0x{SKILL_CALL_RAM:08X}",
            "wrapper_file": f"0x{WRAPPER_FILE:X}",
            "wrapper_ram": f"0x{WRAPPER_RAM:08X}",
            "dx": SHIFT_X,
            "state": f"0x{SKILL_STATE:08X}",
        },
        "scope": "shift only rendered skill-name object packets; keep window and all other text objects unchanged",
        "runtime_evidence": "V329 states 4/5 skill names start at X 198/71; predicted V330 starts 194/67",
        "known_remaining": "E5 choice-prefix physical-0 packets and inherited V329 MEDIUM items remain separate",
        "runtime": "PENDING user cold boot and skill/item/status/dialogue comparison",
        "release_status": "DIAGNOSTIC; DO NOT DISTRIBUTE",
    }
    (ANALYSIS / "build_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    report = [
        "V330 TEST ONLY - skill-name X minus 4",
        f"base={BASE.name}",
        f"output={output_path.name}",
        f"sha256={output_hash}",
        f"delta={delta_path.name}",
        f"delta_sha256={delta_hash}",
        "changed_members=PSX.EXE only",
        f"changed_bytes={len(actual)} within skill call + dead-helper wrapper envelope",
        f"skill_call=0x{SKILL_CALL_RAM:08X} -> wrapper 0x{WRAPPER_RAM:08X}",
        "effect=call original renderer, then shift object 0x801F1DB4 packets dx=-4",
        "window/items/equipment/status/dialogue=unchanged by construction",
        "runtime=PENDING; TEST_ONLY",
    ]
    (ANALYSIS / "build_report.txt").write_text("\n".join(report) + "\n", encoding="utf-8")
    print("\n".join(report))


if __name__ == "__main__":
    main()
