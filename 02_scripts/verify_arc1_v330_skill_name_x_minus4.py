#!/usr/bin/env python3
"""Independent static verification for V330's skill-name-only X shift."""

from __future__ import annotations

import csv
import hashlib
import json
import struct
import sys
from pathlib import Path
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[1]
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

BASE = ROOT / "03_output/arc1_v329_restore_stock_direct_decoder_TEST_ONLY_25C7DECF.zip"
FINAL = ROOT / "03_output/arc1_v330_skill_name_x_minus4_TEST_ONLY_38FE2472.zip"
DELTA = ROOT / "03_output/arc1_v330_skill_name_x_minus4_TEST_ONLY_delta_from_v329_FB827FE3.zip"
RUNTIME_PACKETS = ROOT / "01_work/analysis/arc1_v329_skill_states_5/packets.csv"
ANALYSIS = ROOT / "01_work/analysis/arc1_v330_skill_name_x_minus4"

BASE_SHA256 = "25C7DECF7D69B356DCBA2B2CB098D0667EB7CF081CB8A87B4AB64583ABBF8C90"
FINAL_SHA256 = "38FE24725CA82B721A544C4F6A6B787A4028ADA00F4312A2717F746BAF809DF0"
DELTA_SHA256 = "FB827FE3E9B21711D2030E6DF7BBBECF96A1E3D28E0860A4095D4C8690DAD504"
FINAL_PSX_SHA256 = "D1F4E1A90527289416BC2D7ED4D2206AC3A6ADF8FAB59A96FC4E8FB8BD31C04E"

PSX = "PSX.EXE"
RAM_TO_FILE = 0x8011A800
SKILL_CALL_RAM = 0x80162080
SKILL_CALL_FILE = SKILL_CALL_RAM - RAM_TO_FILE
ORIGINAL_ROUTINE = 0x8016C38C
SHIFT_ROUTINE = 0x8016B440
SKILL_STATE = 0x801F1DB4
WRAPPER_RAM = 0x8019B0B0
WRAPPER_FILE = WRAPPER_RAM - RAM_TO_FILE
WRAPPER_SIZE = 92
OLD_CALL = 0x0C05B0E3
NEW_CALL = 0x0C066C2C

CONTEXT_FILE = 0x80162060 - RAM_TO_FILE
BASE_CONTEXT = (
    0x02202021, 0x00521021, 0x00028880, 0x3C01801A, 0x2421B9C0,
    0x00310821, 0x8C220000, 0x34070018, OLD_CALL, 0xAFA20010,
)
FINAL_CONTEXT = BASE_CONTEXT[:8] + (NEW_CALL, BASE_CONTEXT[9])

WRAPPER_WORDS = (
    0x27BDFFE8, 0xAFBF0014, 0x8FA20028, 0x00000000,
    0xAFA20010, 0x0C05B0E3, 0x00000000, 0x2404FFFC,
    0x00002821, 0x3C06801F, 0x24C61DB4, 0x0C05AD10,
    0x00000000, 0x8FBF0014, 0x00000000, 0x03E00008,
    0x27BD0018,
)
WRAPPER_BLOB = struct.pack(f"<{len(WRAPPER_WORDS)}I", *WRAPPER_WORDS).ljust(
    WRAPPER_SIZE, b"\x00"
)

SHIFT_ROUTINE_WORDS = (
    0x84C2000A, 0x27BDFFF8, 0x18400015, 0x00004021,
    0x00003821, 0x8CC30000, 0x00000000, 0x00E31821,
    0x9462002C, 0x00000000, 0x00441021, 0xA462002C,
    0x8CC30000, 0x00000000, 0x00E31821, 0x9462002E,
    0x00000000, 0x00451021, 0xA462002E, 0x84C2000A,
    0x25080001, 0x0102102A, 0x1440FFEE, 0x24E70034,
    0x03E00008, 0x27BD0008,
)


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


def external_inbound(exe: bytes, start: int, size: int) -> list[tuple[int, int, int]]:
    result = []
    for offset in range(0, len(exe) - 3, 4):
        pc = RAM_TO_FILE + offset
        word = struct.unpack_from("<I", exe, offset)[0]
        target = target_of(pc, word)
        if target is not None and start <= target < start + size and not start <= pc < start + size:
            result.append((pc, word, target))
    return result


def pointer_hits(exe: bytes, start: int, size: int) -> list[tuple[int, int]]:
    hits = []
    for offset in range(0, len(exe) - 3):
        value = struct.unpack_from("<I", exe, offset)[0]
        if start <= value < start + size:
            hits.append((offset, value))
    return hits


def jal_calls(exe: bytes, target: int) -> list[int]:
    calls = []
    for offset in range(0, len(exe) - 3, 4):
        word = struct.unpack_from("<I", exe, offset)[0]
        pc = RAM_TO_FILE + offset
        if word >> 26 == 3 and target_of(pc, word) == target:
            calls.append(pc)
    return calls


def execute_wrapper(words: tuple[int, ...]) -> dict[str, object]:
    """Run the wrapper words with stubs for the two proven stock callees."""
    regs = [0] * 32
    original_sp = 0x10000000
    original_ra = 0x81234568
    string_pointer = 0x8019B9F0
    regs[4:8] = [164, 56, 3, 24]
    original_args = tuple(regs[4:8])
    regs[29], regs[31] = original_sp, original_ra
    memory = {original_sp + 0x10: string_pointer}
    pc = WRAPPER_RAM
    pending_target: int | None = None
    pending_load: tuple[int, int] | None = None
    original_capture: tuple[object, ...] | None = None
    shift_capture: tuple[int, int, int] | None = None

    for _ in range(96):
        if pc == original_ra:
            return {
                "sp": regs[29], "ra": regs[31],
                "original_capture": original_capture,
                "shift_capture": shift_capture,
            }
        if pc == ORIGINAL_ROUTINE:
            original_capture = (
                *tuple(regs[4:8]), memory.get(regs[29] + 0x10),
            )
            return_pc = regs[31]
            for index in (2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 24, 25):
                regs[index] = 0xA0000000 | index
            regs[31] = return_pc
            pc = return_pc
            continue
        if pc == SHIFT_ROUTINE:
            shift_capture = (sign16(regs[4] & 0xFFFF), regs[5], regs[6])
            pc = regs[31]
            continue
        if not WRAPPER_RAM <= pc < WRAPPER_RAM + len(words) * 4:
            raise VerifyError(f"wrapper escaped to 0x{pc:08X}")
        word = words[(pc - WRAPPER_RAM) // 4]
        op = word >> 26
        rs, rt, rd = (word >> 21) & 31, (word >> 16) & 31, (word >> 11) & 31
        imm = word & 0xFFFF
        new_target: int | None = None
        new_load: tuple[int, int] | None = None
        if word == 0:
            pass
        elif op == 0x09:  # addiu
            regs[rt] = (regs[rs] + sign16(imm)) & 0xFFFFFFFF
        elif op == 0x0F:  # lui
            regs[rt] = imm << 16
        elif op == 0x2B:  # sw
            memory[(regs[rs] + sign16(imm)) & 0xFFFFFFFF] = regs[rt]
        elif op == 0x23:  # lw
            new_load = (rt, memory.get((regs[rs] + sign16(imm)) & 0xFFFFFFFF, 0))
        elif op == 0 and (word & 0x3F) == 0x21:  # addu/move
            regs[rd] = (regs[rs] + regs[rt]) & 0xFFFFFFFF
        elif op == 0x03:  # jal
            regs[31] = (pc + 8) & 0xFFFFFFFF
            new_target = target_of(pc, word)
        elif op == 0 and (word & 0x3F) == 0x08:  # jr
            new_target = regs[rs]
        else:
            raise VerifyError(f"unsupported wrapper word 0x{word:08X}")
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
    raise VerifyError("wrapper interpreter step limit")


def runtime_predictions() -> list[dict[str, object]]:
    with RUNTIME_PACKETS.open(encoding="utf-8-sig", newline="") as handle:
        rows = [
            row for row in csv.DictReader(handle)
            if row["header"] == "0x801F1DB4" and row["state"] in ("4", "5")
        ]
    result = []
    expected = {4: (198, 260, 6), 5: (71, 147, 7)}
    for state, (first_x, last_x, count) in expected.items():
        packets = sorted(
            (row for row in rows if int(row["state"]) == state),
            key=lambda row: int(row["ordinal"]),
        )
        xs = [int(row["x"]) for row in packets]
        if len(xs) != count or xs[0] != first_x or xs[-1] != last_x:
            raise VerifyError(f"V329 runtime skill coordinate drift state{state}: {xs}")
        for row in packets:
            result.append({
                "state": state,
                "ordinal": int(row["ordinal"]),
                "char": row["char"],
                "v329_x": int(row["x"]),
                "v330_predicted_x": int(row["x"]) - 4,
                "y_unchanged": int(row["y"]),
            })
    return result


def main() -> None:
    for path, digest in ((BASE, BASE_SHA256), (FINAL, FINAL_SHA256), (DELTA, DELTA_SHA256)):
        if sha256(path.read_bytes()) != digest:
            raise VerifyError(f"hash mismatch: {path.name}")
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
        raise VerifyError("V330 PSX.EXE hash mismatch")
    if struct.unpack_from("<10I", exe0, CONTEXT_FILE) != BASE_CONTEXT:
        raise VerifyError("V329 skill call/table context drift")
    if struct.unpack_from("<10I", exe1, CONTEXT_FILE) != FINAL_CONTEXT:
        raise VerifyError("V330 skill call/table context mismatch")
    if exe1[WRAPPER_FILE : WRAPPER_FILE + WRAPPER_SIZE] != WRAPPER_BLOB:
        raise VerifyError("V330 wrapper byte mismatch")
    if struct.unpack_from(f"<{len(SHIFT_ROUTINE_WORDS)}I", exe1, SHIFT_ROUTINE - RAM_TO_FILE) != SHIFT_ROUTINE_WORDS:
        raise VerifyError("stock packet-offset routine drift")

    exact = bytearray(exe0)
    struct.pack_into("<I", exact, SKILL_CALL_FILE, NEW_CALL)
    exact[WRAPPER_FILE : WRAPPER_FILE + WRAPPER_SIZE] = WRAPPER_BLOB
    if bytes(exact) != exe1:
        raise VerifyError("V330 is not the exact declared overlay")
    diff = {i for i, (a, b) in enumerate(zip(exe0, exe1, strict=True)) if a != b}
    if len(diff) != 70 or not diff <= ({SKILL_CALL_FILE + i for i in range(4)} | set(range(WRAPPER_FILE, WRAPPER_FILE + WRAPPER_SIZE))):
        raise VerifyError(f"Expected-Write mismatch: {len(diff)} bytes")

    if external_inbound(exe0, WRAPPER_RAM, WRAPPER_SIZE):
        raise VerifyError("V329 dead-region premise has external inbound")
    if external_inbound(exe1, WRAPPER_RAM, WRAPPER_SIZE) != [(SKILL_CALL_RAM, NEW_CALL, WRAPPER_RAM)]:
        raise VerifyError("V330 wrapper does not have exactly one skill-only inbound")
    if pointer_hits(exe1, WRAPPER_RAM, WRAPPER_SIZE):
        raise VerifyError("pointer into V330 wrapper region")
    if jal_calls(exe0, ORIGINAL_ROUTINE) != [0x8016200C, 0x80162080, 0x80163CA8]:
        raise VerifyError("V329 C38C call census drift")
    if jal_calls(exe1, ORIGINAL_ROUTINE) != [0x8016200C, 0x80163CA8, 0x8019B0C4]:
        raise VerifyError("non-skill C38C callers or wrapper call changed")

    execution = execute_wrapper(WRAPPER_WORDS)
    if execution["sp"] != 0x10000000 or execution["ra"] != 0x81234568:
        raise VerifyError(f"wrapper SP/RA contract failed: {execution}")
    if execution["original_capture"] != (164, 56, 3, 24, 0x8019B9F0):
        raise VerifyError(f"original call arguments changed: {execution}")
    if execution["shift_capture"] != (-4, 0, SKILL_STATE):
        raise VerifyError(f"skill shift call mismatch: {execution}")

    predictions = runtime_predictions()
    ANALYSIS.mkdir(parents=True, exist_ok=True)
    with (ANALYSIS / "runtime_coordinate_prediction.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(predictions[0]))
        writer.writeheader()
        writer.writerows(predictions)

    verification = {
        "result": "PASS",
        "hashes": {"base": BASE_SHA256, "final": FINAL_SHA256, "delta": DELTA_SHA256},
        "archive": {"members": len(final_names), "changed_members": [PSX]},
        "expected_write": {"changed_bytes": len(diff), "declared_envelope_only": True},
        "skill_caller": "only 0x80162080 redirected; skill table base 0x8019B9C0 retained",
        "wrapper": "original renderer arguments preserved; then dx=-4,dy=0 on state 0x801F1DB4; SP/RA/load-delay PASS",
        "other_callers": "character and equipment C38C calls at 0x8016200C/0x80163CA8 unchanged; direct item/equipment C400 calls unchanged",
        "runtime_prediction": "V329 state4 198..260 -> 194..256; state5 71..147 -> 67..143",
        "runtime": "PENDING V330 user cold boot",
    }
    (ANALYSIS / "independent_verification.json").write_text(
        json.dumps(verification, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    lines = [
        "V330 independent verification: PASS",
        f"full_sha256={FINAL_SHA256}",
        f"delta_sha256={DELTA_SHA256}",
        "archive=164 members; changed=PSX.EXE only; exact declared overlay",
        f"Expected-Write={len(diff)} changed bytes within call+dead-region envelope",
        "routing=only skill-name caller 0x80162080 enters wrapper",
        "wrapper=original C38C args/string preserved; then B440(dx=-4,dy=0,state=0x801F1DB4)",
        "SP/RA/R3000 load-delay=PASS; other C38C callers unchanged",
        "runtime prediction=state4 X 198..260 -> 194..256; state5 71..147 -> 67..143",
        "runtime=PENDING V330 cold boot; TEST_ONLY",
    ]
    (ANALYSIS / "independent_verification.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
