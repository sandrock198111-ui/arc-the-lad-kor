#!/usr/bin/env python3
"""Independent verification for V329's stock-decoder restoration."""

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

REFERENCE = ROOT / "03_output/arc1_v325_ui_reencode_TEST_ONLY_7828AA04.zip"
BASE = ROOT / "03_output/arc1_v328_compact_common_remap_TEST_ONLY_A71FCF2E.zip"
FINAL = ROOT / "03_output/arc1_v329_restore_stock_direct_decoder_TEST_ONLY_25C7DECF.zip"
DELTA = ROOT / "03_output/arc1_v329_restore_stock_direct_decoder_TEST_ONLY_delta_from_v328_6585D27B.zip"
RUNTIME_PACKETS = ROOT / "01_work/analysis/arc1_v327_runtime_states_8/packets.csv"
ANALYSIS = ROOT / "01_work/analysis/arc1_v329_restore_stock_direct_decoder"

REFERENCE_SHA256 = "7828AA04F6A0684981332924C30B4139ABFCA5065138FA899C4D429E87C74CD1"
BASE_SHA256 = "A71FCF2E2F6C60EBFA554E6D4951FAE25CF7B3DC03CC27C9801EE4993CFC0324"
FINAL_SHA256 = "25C7DECF7D69B356DCBA2B2CB098D0667EB7CF081CB8A87B4AB64583ABBF8C90"
DELTA_SHA256 = "6585D27B3DA45A9CFDA53E2F590C60AF7DA7DCE658D70D7CB47D0AE5DD95E9E6"
FINAL_PSX_SHA256 = "00AD3D5E3EC4664BCEAB563351B9952B0735FC8745787C06E9A722B8CB9BB547"

PSX = "PSX.EXE"
RAM_TO_FILE = 0x8011A800
TRAMPOLINE_FILE = 0x8EF44
TRAMPOLINE_RAM = RAM_TO_FILE + TRAMPOLINE_FILE
RAW_HELPER_RAM = 0x8019B0B0
RAW_HELPER_SIZE = 92
STOCK_RAM = 0x8016B3E0
OLD_WORD = 0x08066C2C
NEW_WORD = 0x0805ACF8
STOCK_PREFIX = (0x2463FFFF, 0x24A20001, 0x0805AD04, 0xACC20000)

COMMON_HELPER_FILE = 0x80990
COMMON_HELPER_RAM = 0x8019B190
COMMON_RETURN_RAM = 0x8016B524
COMMON_HELPER_WORDS = (
    0x90C8000D, 0x34090006, 0x1509000F, 0x00000000,
    0x10800009, 0x2488FFF1, 0x2D09000B, 0x15200009,
    0x3409007F, 0x14890008, 0x00000000, 0x340403CC,
    0x10000005, 0x00000000, 0x340403C0, 0x10000002,
    0x00000000, 0x250403C1, 0x84C5000A, 0x0805AD49,
    0x00000000,
)
COMMON_HOOK_FILE = 0x8016B51C - RAM_TO_FILE
COMMON_HOOK_WORDS = (0x08066C64, 0x84C20004)
UV_HOOK_FILE = 0x8016B5A8 - RAM_TO_FILE
UV_HOOK_WORDS = (0x08066C44, 0x90C3000D)
T1_RESTORE_FILE = 0x80940
T1_RESTORE_WORD = 0x340900A0


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


def target_of(pc: int, word: int) -> int | None:
    op = word >> 26
    if op in (1, 4, 5, 6, 7):
        return (pc + 4 + sign16(word & 0xFFFF) * 4) & 0xFFFFFFFF
    if op in (2, 3):
        return ((pc + 4) & 0xF0000000) | ((word & 0x03FFFFFF) << 2)
    return None


def inbound(exe: bytes, target: int) -> list[tuple[int, int]]:
    result = []
    for offset in range(0, len(exe) - 3, 4):
        word = struct.unpack_from("<I", exe, offset)[0]
        pc = RAM_TO_FILE + offset
        if target_of(pc, word) == target:
            result.append((pc, word))
    return result


def read_half(memory: dict[int, int], address: int) -> int:
    value = memory.get(address, 0) | (memory.get(address + 1, 0) << 8)
    return value | 0xFFFF0000 if value & 0x8000 else value


def run_common(width: int, physical: int) -> dict[int, int]:
    """Execute the actual V328 helper with one-instruction MIPS-I load delays."""
    regs = {index: (0x40000000 + index * 0x10101) & 0xFFFFFFFF for index in range(32)}
    regs[0] = 0
    state = 0x5000
    regs[4], regs[5], regs[6] = physical, 0xA5A5A5A5, state
    regs[2], regs[31] = 0x02020202, 0x80123456
    memory = {state + 0x0D: width, state + 0x0A: 9, state + 0x0B: 0}
    pc = COMMON_HELPER_RAM
    pending_target: int | None = None
    pending_load: tuple[int, int] | None = None
    for _ in range(128):
        if pc == COMMON_RETURN_RAM:
            return regs
        if not COMMON_HELPER_RAM <= pc < COMMON_HELPER_RAM + len(COMMON_HELPER_WORDS) * 4:
            raise VerifyError(f"common helper escaped to 0x{pc:08X}")
        word = COMMON_HELPER_WORDS[(pc - COMMON_HELPER_RAM) // 4]
        op = word >> 26
        rs, rt, imm = (word >> 21) & 31, (word >> 16) & 31, word & 0xFFFF
        new_target: int | None = None
        new_load: tuple[int, int] | None = None
        if word == 0:
            pass
        elif op == 0x09:
            regs[rt] = (regs[rs] + sign16(imm)) & 0xFFFFFFFF
        elif op == 0x0B:
            regs[rt] = int((regs[rs] & 0xFFFFFFFF) < (sign16(imm) & 0xFFFFFFFF))
        elif op == 0x0D:
            regs[rt] = (regs[rs] | imm) & 0xFFFFFFFF
        elif op == 0x04:
            if regs[rs] == regs[rt]:
                new_target = (pc + 4 + sign16(imm) * 4) & 0xFFFFFFFF
        elif op == 0x05:
            if regs[rs] != regs[rt]:
                new_target = (pc + 4 + sign16(imm) * 4) & 0xFFFFFFFF
        elif op == 0x21:
            new_load = (rt, read_half(memory, (regs[rs] + sign16(imm)) & 0xFFFFFFFF))
        elif op == 0x24:
            new_load = (rt, memory.get((regs[rs] + sign16(imm)) & 0xFFFFFFFF, 0))
        elif op == 0x02:
            new_target = ((pc + 4) & 0xF0000000) | ((word & 0x03FFFFFF) << 2)
        else:
            raise VerifyError(f"unsupported common-helper word 0x{word:08X}")
        if pending_load is not None:
            regs[pending_load[0]] = pending_load[1] & 0xFFFFFFFF
        pending_load = new_load
        regs[0] = 0
        if pending_target is not None:
            pc, pending_target = pending_target, None
        else:
            pc = (pc + 4) & 0xFFFFFFFF
            if new_target is not None:
                pending_target = new_target
    raise VerifyError("common-helper interpreter step limit")


def expected(width: int, physical: int) -> int:
    if width != 6:
        return physical
    if physical == 0:
        return 960
    if 15 <= physical <= 25:
        return 961 + physical - 15
    if physical == 127:
        return 972
    return physical


def runtime_census() -> Counter[tuple[str, int]]:
    census: Counter[tuple[str, int]] = Counter()
    with RUNTIME_PACKETS.open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            if int(row["w"]) != 6:
                continue
            plane, u, v = int(row["plane"]), int(row["u"]), int(row["v"])
            if u == 244:
                physical = 960 + ((v - 176) // 16) * 4 + plane
                census[("synthetic", physical)] += 1
            else:
                physical = (v // 16) * 60 + ((u - 4) // 16) * 4 + plane
                census[("legacy", physical)] += 1
    return census


def main() -> None:
    for path, digest in (
        (REFERENCE, REFERENCE_SHA256), (BASE, BASE_SHA256),
        (FINAL, FINAL_SHA256), (DELTA, DELTA_SHA256),
    ):
        if sha256(path.read_bytes()) != digest:
            raise VerifyError(f"hash mismatch: {path.name}")

    _, reference = read_zip(REFERENCE)
    base_names, base = read_zip(BASE)
    final_names, final = read_zip(FINAL)
    if base_names != final_names or len(final_names) != 164:
        raise VerifyError("archive topology mismatch")
    if [name for name in base_names if base[name] != final[name]] != [PSX]:
        raise VerifyError("changed member set is not PSX.EXE only")
    with ZipFile(DELTA) as archive:
        if archive.namelist() != [PSX] or archive.read(PSX) != final[PSX]:
            raise VerifyError("delta archive mismatch")

    exe0, exe1 = base[PSX], final[PSX]
    if sha256(exe1) != FINAL_PSX_SHA256:
        raise VerifyError("V329 PSX.EXE hash mismatch")
    if struct.unpack_from("<II", exe0, TRAMPOLINE_FILE) != (OLD_WORD, 0):
        raise VerifyError("V328 raw-helper trampoline premise drift")
    if struct.unpack_from("<II", exe1, TRAMPOLINE_FILE) != (NEW_WORD, 0):
        raise VerifyError("V329 stock trampoline mismatch")
    if struct.unpack_from("<II", reference[PSX], TRAMPOLINE_FILE) != (NEW_WORD, 0):
        raise VerifyError("V329 trampoline does not match the pre-V326 stock reference")

    exact = bytearray(exe0)
    struct.pack_into("<I", exact, TRAMPOLINE_FILE, NEW_WORD)
    if bytes(exact) != exe1:
        raise VerifyError("V329 is not the exact one-word overlay over V328")
    diff = {i for i, (a, b) in enumerate(zip(exe0, exe1, strict=True)) if a != b}
    if diff != {TRAMPOLINE_FILE, TRAMPOLINE_FILE + 1, TRAMPOLINE_FILE + 2}:
        raise VerifyError(f"changed-byte census drift: {sorted(diff)}")

    if struct.unpack_from("<4I", exe1, STOCK_RAM - RAM_TO_FILE) != STOCK_PREFIX:
        raise VerifyError("stock raw-1 decoder prefix mismatch")
    if struct.unpack_from("<II", exe1, COMMON_HOOK_FILE) != COMMON_HOOK_WORDS:
        raise VerifyError("V328 common hook regressed")
    if struct.unpack_from(f"<{len(COMMON_HELPER_WORDS)}I", exe1, COMMON_HELPER_FILE) != COMMON_HELPER_WORDS:
        raise VerifyError("V328 common helper regressed")
    if struct.unpack_from("<II", exe1, UV_HOOK_FILE) != UV_HOOK_WORDS:
        raise VerifyError("V326 UV strip route regressed")
    if struct.unpack_from("<I", exe1, T1_RESTORE_FILE)[0] != T1_RESTORE_WORD:
        raise VerifyError("V327 t1 restore regressed")

    if inbound(exe0, RAW_HELPER_RAM) != [(TRAMPOLINE_RAM, OLD_WORD)]:
        raise VerifyError("V328 raw helper inbound premise mismatch")
    if inbound(exe1, RAW_HELPER_RAM):
        raise VerifyError("V329 raw helper remains reachable by direct control flow")
    pointer_hits = []
    for offset in range(0, len(exe1) - 3):
        value = struct.unpack_from("<I", exe1, offset)[0]
        if RAW_HELPER_RAM <= value < RAW_HELPER_RAM + RAW_HELPER_SIZE:
            pointer_hits.append((offset, value))
    if pointer_hits:
        raise VerifyError(f"V329 has a pointer into the unreachable raw helper: {pointer_hits[:8]}")
    if (TRAMPOLINE_RAM, NEW_WORD) not in inbound(exe1, STOCK_RAM):
        raise VerifyError("restored trampoline does not enter stock decoder")

    for width in (6, 14, 16):
        for physical in range(1239):
            regs = run_common(width, physical)
            if regs[4] != expected(width, physical):
                raise VerifyError(f"common mapping mismatch D={width} physical={physical}")
            if regs[5] != 9 or regs[2] != 0x02020202 or regs[6] != 0x5000 or regs[31] != 0x80123456:
                raise VerifyError(f"common helper live-register failure D={width} physical={physical}")
        for raw in range(1, 0xDD):
            stock_physical = raw - 1
            mapped = run_common(width, stock_physical)[4]
            if width in (14, 16) and mapped != stock_physical:
                raise VerifyError(f"one-byte Hangul remap survived D={width} raw=0x{raw:02X}")

    census = runtime_census()
    expected_census = Counter({
        ("legacy", 0): 15, ("legacy", 15): 3, ("legacy", 16): 7,
        ("legacy", 17): 4, ("legacy", 18): 7, ("legacy", 19): 1,
        ("legacy", 20): 5, ("legacy", 23): 4, ("legacy", 24): 4,
        ("legacy", 25): 1, ("legacy", 127): 1, ("synthetic", 960): 1,
    })
    if census != expected_census:
        raise VerifyError(f"V327 compact runtime census drift: {census}")

    verification = {
        "result": "PASS",
        "hashes": {"base": BASE_SHA256, "final": FINAL_SHA256, "delta": DELTA_SHA256},
        "archive": {"members": len(final_names), "changed_members": [PSX]},
        "expected_write": {"changed_bytes": len(diff), "one_word_exact_overlay": True},
        "decoder": {
            "trampoline": f"0x{TRAMPOLINE_RAM:08X}",
            "stock_destination": f"0x{STOCK_RAM:08X}",
            "raw_helper_external_inbound_after": 0,
            "pointer_hits_into_raw_helper": 0,
        },
        "pipeline": "stock raw-1 decode then D6-only common remap; D14/D16 raw 01..DC identity",
        "exhaustive": "D6/D14/D16 x physical0..1238 and raw01..DC PASS with MIPS-I load delays",
        "runtime_evidence": "V327 53 W6 packets: 52 eligible legacy indices plus one already synthetic",
        "runtime": "PENDING V329 user cold boot",
    }
    ANALYSIS.mkdir(parents=True, exist_ok=True)
    (ANALYSIS / "independent_verification.json").write_text(
        json.dumps(verification, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    lines = [
        "V329 independent verification: PASS",
        f"full_sha256={FINAL_SHA256}",
        f"delta_sha256={DELTA_SHA256}",
        "archive=164 members; changed=PSX.EXE only; exact one-word overlay",
        "Expected-Write=3 changed bytes at file 0x8EF44; delay nop preserved",
        "decoder=V325 stock j 0x8016B3E0 restored; raw helper has no branch/pointer entry",
        "pipeline=stock raw-1 decode then D6-only common remap",
        "interpreter=D6/D14/D16 x physical0..1238 and raw01..DC PASS",
        "D14/D16 Hangul=no synthetic 960..972 remap",
        "V328 common gate, UV strip and V327 t1 restore=byte exact",
        "runtime=PENDING V329 cold boot; TEST_ONLY",
    ]
    (ANALYSIS / "independent_verification.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
