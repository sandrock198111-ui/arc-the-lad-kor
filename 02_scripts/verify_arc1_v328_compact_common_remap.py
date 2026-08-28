#!/usr/bin/env python3
"""Independent static and runtime-evidence verification for V328."""

from __future__ import annotations

import csv
import hashlib
import json
import struct
import sys
from collections import Counter
from pathlib import Path
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[1]
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

BASE = ROOT / "03_output/arc1_v327_compact_ui_t1_restore_TEST_ONLY_B93E1001.zip"
FINAL = ROOT / "03_output/arc1_v328_compact_common_remap_TEST_ONLY_A71FCF2E.zip"
DELTA = ROOT / "03_output/arc1_v328_compact_common_remap_TEST_ONLY_delta_from_v327_04BCF32C.zip"
RUNTIME_PACKETS = ROOT / "01_work/analysis/arc1_v327_runtime_states_8/packets.csv"
ANALYSIS = ROOT / "01_work/analysis/arc1_v328_compact_common_remap"

BASE_SHA256 = "B93E100124AA69050DE6F181DB507E43042E20AF52EBEFC0857147D042B117EE"
FINAL_SHA256 = "A71FCF2E2F6C60EBFA554E6D4951FAE25CF7B3DC03CC27C9801EE4993CFC0324"
DELTA_SHA256 = "04BCF32CA5DEEF71683A08C4112FAEE705E217D9AFEA271C1F847046E25FD80C"

PSX = "PSX.EXE"
RAM_TO_FILE = 0x8011A800
HOOK_RAM = 0x8016B51C
HOOK_FILE = HOOK_RAM - RAM_TO_FILE
HOOK_DELAY_RAM = 0x8016B520
RETURN_RAM = 0x8016B524
HELPER_FILE = 0x80990
HELPER_RAM = RAM_TO_FILE + HELPER_FILE
HELPER_WORDS = (
    0x90C8000D, 0x34090006, 0x1509000F, 0x00000000,
    0x10800009, 0x2488FFF1, 0x2D09000B, 0x15200009,
    0x3409007F, 0x14890008, 0x00000000, 0x340403CC,
    0x10000005, 0x00000000, 0x340403C0, 0x10000002,
    0x00000000, 0x250403C1, 0x84C5000A, 0x0805AD49,
    0x00000000,
)
HOOK_WORD = 0x08066C64
HOOK_DELAY_WORD = 0x84C20004
OLD_HOOK_WORD = 0x84C5000A

# V327 fixes that V328 must not disturb.
UV_T1_RESTORE_FILE = 0x80940
UV_T1_RESTORE_WORD = 0x340900A0
UV_HOOK_FILE = 0x8016B5A8 - RAM_TO_FILE
UV_HOOK_WORD = 0x08066C44
UV_HOOK_DELAY = 0x90C3000D


class VerifyError(RuntimeError):
    pass


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def read_zip(path: Path) -> tuple[list[str], dict[str, bytes]]:
    with ZipFile(path) as archive:
        names = [item.filename for item in archive.infolist() if not item.is_dir()]
        return names, {name: archive.read(name) for name in names}


def sign16(value: int) -> int:
    return value - 0x10000 if value & 0x8000 else value


def jump(address: int) -> int:
    return 0x08000000 | ((address >> 2) & 0x03FFFFFF)


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


def read_half(memory: dict[int, int], address: int) -> int:
    value = memory.get(address, 0) | (memory.get(address + 1, 0) << 8)
    return value | 0xFFFF0000 if value & 0x8000 else value


def run_helper(width: int, glyph: int) -> dict[int, int]:
    """MIPS-I subset interpreter with an explicit one-instruction load delay."""
    regs = {index: (0x10000000 + index * 0x10101) & 0xFFFFFFFF for index in range(32)}
    regs[0] = 0
    state = 0x3000
    regs[4] = glyph & 0xFFFFFFFF
    regs[5] = 0xA1A1A1A1
    regs[6] = state
    regs[2] = 0x02020202
    regs[31] = 0x80123456
    memory = {state + 0x0D: width, state + 0x0A: 7, state + 0x0B: 0}
    pc = HELPER_RAM
    pending_target: int | None = None
    pending_load: tuple[int, int] | None = None
    for _step in range(128):
        if pc == RETURN_RAM:
            return regs
        if not HELPER_RAM <= pc < HELPER_RAM + len(HELPER_WORDS) * 4 or (pc - HELPER_RAM) & 3:
            raise VerifyError(f"helper PC escaped: 0x{pc:08X}")
        word = HELPER_WORDS[(pc - HELPER_RAM) // 4]
        op = word >> 26
        rs, rt = (word >> 21) & 31, (word >> 16) & 31
        imm = word & 0xFFFF
        new_target: int | None = None
        new_load: tuple[int, int] | None = None
        if word == 0:
            pass
        elif op == 0x09:  # addiu
            regs[rt] = (regs[rs] + sign16(imm)) & 0xFFFFFFFF
        elif op == 0x0B:  # sltiu
            regs[rt] = int((regs[rs] & 0xFFFFFFFF) < (sign16(imm) & 0xFFFFFFFF))
        elif op == 0x0D:  # ori
            regs[rt] = (regs[rs] | imm) & 0xFFFFFFFF
        elif op == 0x04:  # beq
            if regs[rs] == regs[rt]:
                new_target = (pc + 4 + sign16(imm) * 4) & 0xFFFFFFFF
        elif op == 0x05:  # bne
            if regs[rs] != regs[rt]:
                new_target = (pc + 4 + sign16(imm) * 4) & 0xFFFFFFFF
        elif op == 0x21:  # lh, delayed
            new_load = (rt, read_half(memory, (regs[rs] + sign16(imm)) & 0xFFFFFFFF))
        elif op == 0x24:  # lbu, delayed
            address = (regs[rs] + sign16(imm)) & 0xFFFFFFFF
            new_load = (rt, memory.get(address, 0))
        elif op == 0x02:  # j
            new_target = ((pc + 4) & 0xF0000000) | ((word & 0x03FFFFFF) << 2)
        else:
            raise VerifyError(f"unsupported helper word 0x{word:08X}")

        # A load issued by the previous instruction becomes visible only after
        # this instruction has consumed its source registers.
        if pending_load is not None:
            regs[pending_load[0]] = pending_load[1] & 0xFFFFFFFF
        pending_load = new_load
        regs[0] = 0
        if pending_target is not None:
            pc = pending_target
            pending_target = None
        else:
            pc = (pc + 4) & 0xFFFFFFFF
            if new_target is not None:
                pending_target = new_target
    raise VerifyError("helper interpreter step limit")


def expected_mapping(width: int, glyph: int) -> int:
    if width != 6:
        return glyph
    if glyph == 0:
        return 960
    if 15 <= glyph <= 25:
        return 961 + glyph - 15
    if glyph == 127:
        return 972
    return glyph


def runtime_census() -> tuple[Counter[tuple[str, int]], int]:
    census: Counter[tuple[str, int]] = Counter()
    with RUNTIME_PACKETS.open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            if int(row["w"]) != 6:
                continue
            plane, u, v = int(row["plane"]), int(row["u"]), int(row["v"])
            if u == 244:  # V326 strip U=240, then stock half-width correction +4
                physical = 960 + ((v - 176) // 16) * 4 + plane
                mode = "synthetic"
            else:
                physical = (v // 16) * 60 + ((u - 4) // 16) * 4 + plane
                mode = "legacy"
            census[(mode, physical)] += 1
    eligible = sum(
        count for (mode, physical), count in census.items()
        if mode == "legacy" and (physical == 0 or 15 <= physical <= 25 or physical == 127)
    )
    return census, eligible


def main() -> None:
    if sha256(BASE.read_bytes()) != BASE_SHA256:
        raise VerifyError("V327 base ZIP hash mismatch")
    if sha256(FINAL.read_bytes()) != FINAL_SHA256:
        raise VerifyError("V328 full ZIP hash mismatch")
    if sha256(DELTA.read_bytes()) != DELTA_SHA256:
        raise VerifyError("V328 delta ZIP hash mismatch")

    base_names, base = read_zip(BASE)
    final_names, final = read_zip(FINAL)
    if base_names != final_names or len(final_names) != 164:
        raise VerifyError("archive topology mismatch")
    changed_members = [name for name in base_names if base[name] != final[name]]
    if changed_members != [PSX]:
        raise VerifyError(f"changed member set mismatch: {changed_members}")
    with ZipFile(DELTA) as archive:
        if archive.namelist() != [PSX] or archive.read(PSX) != final[PSX]:
            raise VerifyError("delta archive mismatch")

    exe0, exe1 = base[PSX], final[PSX]
    if struct.unpack_from("<I", exe0, HOOK_FILE)[0] != OLD_HOOK_WORD:
        raise VerifyError("V327 hook premise drift")
    if struct.unpack_from("<I", exe1, HOOK_FILE)[0] != HOOK_WORD:
        raise VerifyError("V328 hook word mismatch")
    if struct.unpack_from("<I", exe1, HOOK_FILE + 4)[0] != HOOK_DELAY_WORD:
        raise VerifyError("hook delay no longer preserves lh v0,4(a2)")
    if struct.unpack_from(f"<{len(HELPER_WORDS)}I", exe1, HELPER_FILE) != HELPER_WORDS:
        raise VerifyError("helper machine words mismatch")

    expected = bytearray(exe0)
    struct.pack_into("<I", expected, HOOK_FILE, HOOK_WORD)
    struct.pack_into(f"<{len(HELPER_WORDS)}I", expected, HELPER_FILE, *HELPER_WORDS)
    if bytes(expected) != exe1:
        bad = [i for i, (a, b) in enumerate(zip(expected, exe1, strict=True)) if a != b]
        raise VerifyError(f"full PSX Expected-Write mismatch: {bad[:16]}")
    psx_diff = {i for i, (a, b) in enumerate(zip(exe0, exe1, strict=True)) if a != b}
    if len(psx_diff) != 55:
        raise VerifyError(f"changed-byte census drift: {len(psx_diff)}")

    helper_targets = set(range(HELPER_RAM, HELPER_RAM + len(HELPER_WORDS) * 4, 4))
    base_hits = branch_hits(exe0, helper_targets)
    if any(base_hits[target] for target in helper_targets):
        raise VerifyError("V327 already had a control-flow target in the helper cave")
    pointer_hits = []
    for offset in range(0, len(exe0) - 3):
        value = struct.unpack_from("<I", exe0, offset)[0]
        if HELPER_RAM <= value < HELPER_RAM + len(HELPER_WORDS) * 4:
            pointer_hits.append((offset, value))
    if pointer_hits:
        raise VerifyError(f"V327 pointer enters helper cave: {pointer_hits[:8]}")

    hits = branch_hits(exe1, {HOOK_RAM, HOOK_DELAY_RAM, RETURN_RAM} | helper_targets)
    if hits[HOOK_RAM] or hits[HOOK_DELAY_RAM]:
        raise VerifyError("hook or delay slot has an external inbound branch")
    if hits[HELPER_RAM] != [(HOOK_RAM, HOOK_WORD)]:
        raise VerifyError(f"helper inbound mismatch: {hits[HELPER_RAM]}")
    external_middle = {
        target: [(source, word) for source, word in hits[target] if not HELPER_RAM <= source < HELPER_RAM + len(HELPER_WORDS) * 4]
        for target in helper_targets - {HELPER_RAM}
    }
    if any(external_middle.values()):
        raise VerifyError(f"external control flow enters helper middle: {external_middle}")
    if hits[RETURN_RAM] != [(HELPER_RAM + 76, jump(RETURN_RAM))]:
        raise VerifyError(f"return inbound mismatch: {hits[RETURN_RAM]}")
    if any(word >> 26 == 3 for word in HELPER_WORDS):
        raise VerifyError("helper contains jal and would clobber RA")

    # The two inherited V327/V326 mechanisms required by the new mapping are
    # explicitly checked even though the anchored whole-file overlay already
    # proves all other bytes are inherited.
    if struct.unpack_from("<I", exe1, UV_T1_RESTORE_FILE)[0] != UV_T1_RESTORE_WORD:
        raise VerifyError("V327 live-t1 restore regressed")
    if struct.unpack_from("<II", exe1, UV_HOOK_FILE) != (UV_HOOK_WORD, UV_HOOK_DELAY):
        raise VerifyError("V326 synthetic UV routing hook regressed")

    truth: dict[str, dict[str, int]] = {}
    for width in (6, 14, 16):
        for glyph in range(0, 1239):
            regs = run_helper(width, glyph)
            mapped = expected_mapping(width, glyph)
            if regs[4] != mapped:
                raise VerifyError(f"mapping mismatch D={width} glyph={glyph}: {regs[4]}")
            if regs[5] != 7:
                raise VerifyError("overwritten ordinal load was not recreated")
            if regs[2] != 0x02020202 or regs[6] != 0x3000 or regs[31] != 0x80123456:
                raise VerifyError(f"live register/RA corruption D={width} glyph={glyph}")
        for glyph in (0, 15, 16, 25, 127):
            mapped = expected_mapping(width, glyph)
            truth[f"D{width}:{glyph}"] = {
                "mapped": mapped,
                "u_after_halfwidth": 244 if 960 <= mapped < 973 else -1,
                "v": 176 + ((mapped - 960) >> 2) * 16 if 960 <= mapped < 973 else -1,
            }

    census, eligible = runtime_census()
    expected_census = Counter({
        ("legacy", 0): 15, ("legacy", 15): 3, ("legacy", 16): 7,
        ("legacy", 17): 4, ("legacy", 18): 7, ("legacy", 19): 1,
        ("legacy", 20): 5, ("legacy", 23): 4, ("legacy", 24): 4,
        ("legacy", 25): 1, ("legacy", 127): 1, ("synthetic", 960): 1,
    })
    if census != expected_census or eligible != 52:
        raise VerifyError(f"V327 runtime compact census drift: {census}/{eligible}")

    verification = {
        "result": "PASS",
        "hashes": {"base": BASE_SHA256, "final": FINAL_SHA256, "delta": DELTA_SHA256},
        "archive": {"members": len(final_names), "changed_members": changed_members},
        "psx_expected_write": {"changed_bytes": len(psx_diff), "exact_overlay_match": True},
        "hook": {"ram": f"0x{HOOK_RAM:08X}", "delay_word": f"0x{HOOK_DELAY_WORD:08X}"},
        "helper": {"ram": f"0x{HELPER_RAM:08X}", "size": len(HELPER_WORDS) * 4, "jal_count": 0},
        "truth_table": truth,
        "exhaustive_interpreter": "D=6/14/16 x physical 0..1238 PASS; RA/v0/a2 preserved; a1 ordinal restored",
        "V327_runtime_evidence": {
            "six_pixel_packets": sum(census.values()),
            "legacy_packets_fixed_by_V328": eligible,
            "already_synthetic_packets": census[("synthetic", 960)],
        },
        "inheritance": "V327 anchored; COMM.IMG and all 163 non-PSX members byte exact",
        "runtime": "PENDING V328 user cold boot",
    }
    ANALYSIS.mkdir(parents=True, exist_ok=True)
    (ANALYSIS / "independent_verification.json").write_text(
        json.dumps(verification, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    lines = [
        "V328 independent verification: PASS",
        f"full_sha256={FINAL_SHA256}",
        f"delta_sha256={DELTA_SHA256}",
        "archive=164 members; changed=PSX.EXE only; exact overlay match",
        "Expected-Write=55 changed bytes within one hook word and 84-byte zero cave",
        "control flow=one inbound J, one return J, no JAL/RA clobber, hook delay preserved",
        "interpreter=D6/D14/D16 x physical0..1238 PASS; v0/a2/RA preserved; ordinal restored",
        "scope=D6 maps 0,15..25,127 to 960..972; D14/D16 are identity",
        "V327 runtime evidence=53 W6 packets: 52 legacy targets fixed, 1 already synthetic",
        "V326 UV routing and V327 t1 restore=preserved",
        "runtime=PENDING V328 cold boot; TEST_ONLY",
    ]
    (ANALYSIS / "independent_verification.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
