#!/usr/bin/env python3
"""Independent static verification for V332 skill/configuration alignment."""

from __future__ import annotations

import csv
import hashlib
import json
import struct
import sys
from pathlib import Path
from zipfile import ZipFile

from capstone import Cs, CS_ARCH_MIPS, CS_MODE_LITTLE_ENDIAN, CS_MODE_MIPS32


ROOT = Path(__file__).resolve().parents[1]
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

BASE = ROOT / "03_output/arc1_v331_skill_config_alignment_TEST_ONLY_4D5F9D16.zip"
FINAL = ROOT / "03_output/arc1_v332_skill_config_bar_alignment_TEST_ONLY_D2951A33.zip"
DELTA = ROOT / "03_output/arc1_v332_skill_config_bar_alignment_TEST_ONLY_delta_from_v331_72E259EF.zip"
RUNTIME_OBJECTS = ROOT / "01_work/analysis/arc1_v329_skill_states_5/objects.csv"
ANALYSIS = ROOT / "01_work/analysis/arc1_v332_skill_config_bar_alignment"

BASE_SHA256 = "4D5F9D165B54F8EE740DE313D8524E999DFEC2763BB0E3018F767C499A2E1DD5"
FINAL_SHA256 = "D2951A33C598C04BDDDCDC07678ADADCC18471CE98FE32B904527073445BB5AF"
DELTA_SHA256 = "72E259EF0F521E917CB014F4DA70DA4CD9BBC0B7D8EBEB5332D5F1A0297921B5"
FINAL_PSX_SHA256 = "394CF9F98A4A4E95B3DD953EA8C72ADADE26B1A404382B8342794213F8178751"

PSX = "PSX.EXE"
RAM_TO_FILE = 0x8011A800

BAR_LEFT_RAM, BAR_RIGHT_RAM = 0x801608F4, 0x801608F8
BAR_LEFT_FILE, BAR_RIGHT_FILE = BAR_LEFT_RAM - RAM_TO_FILE, BAR_RIGHT_RAM - RAM_TO_FILE
BAR_LEFT_OLD, BAR_RIGHT_OLD = 0x26650082, 0x266500BE
BAR_LEFT_NEW, BAR_RIGHT_NEW = 0x2665007E, 0x266500BA
BAR_CALL_RAM = 0x801608FC
BAR_STORE_RAM = 0x8016D620
BAR_STORE_FILE = BAR_STORE_RAM - RAM_TO_FILE
BAR_STORE_WORDS = (
    0x000410C0, 0x00441023, 0x000210C0, 0x3C01801B,
    0x2421DF0C, 0x00220821, 0xA4250000, 0x3C01801B,
    0x2421DF0E, 0x00220821, 0xA4260000, 0x03E00008,
    0x00000000,
)

CONFIG_BASE_FILE = 0x80160854 - RAM_TO_FILE
CONFIG_FIRST_FILE = 0x8016089C - RAM_TO_FILE
CONFIG_SECOND_FILE = 0x801608BC - RAM_TO_FILE
BAR_WIDTH_FILE = 0x801607A8 - RAM_TO_FILE
BAR_HEIGHT_FILE = 0x801607B0 - RAM_TO_FILE
CONFIG_PAYLOAD_FILE = 0x8019C2A4 - RAM_TO_FILE
CONFIG_PAYLOAD = bytes.fromhex("34 DD 1A 94 DD CF 00 00 00")

SKILL_CALL_RAM = 0x80162080
SKILL_CALL_FILE = SKILL_CALL_RAM - RAM_TO_FILE
SKILL_CALL_WORDS = (0x0C066C2C, 0xAFA20010)
SKILL_WRAPPER_RAM = 0x8019B0B0
SKILL_WRAPPER_FILE = SKILL_WRAPPER_RAM - RAM_TO_FILE
SKILL_WRAPPER_SIZE = 92
SKILL_WRAPPER_SHA256 = "C6F127C8C0F5602F2582207B3E4643C6CA5457530CF0CD866BAC84EFAF4C60ED"
SKILL_TABLE_FILE = 0x8019B9C0 - RAM_TO_FILE
SKILL_GROUND_RAM = 0x8019ADEA
SKILL_SLOW_RAM = 0x8019C1EE
SKILL_GROUND_BYTES = bytes.fromhex("9B A1 15 8F 86 17 00")
SKILL_SLOW_BYTES = bytes.fromhex("DD FC D5 3D A1 0E 89 DD 2F 00")


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


def control_target(pc: int, word: int) -> int | None:
    op = word >> 26
    if op in (1, 4, 5, 6, 7):
        return (pc + 4 + sign16(word & 0xFFFF) * 4) & 0xFFFFFFFF
    if op in (2, 3):
        return ((pc + 4) & 0xF0000000) | ((word & 0x03FFFFFF) << 2)
    return None


def inbound_to(exe: bytes, targets: set[int]) -> list[tuple[int, int, int]]:
    result: list[tuple[int, int, int]] = []
    for offset in range(0, len(exe) - 3, 4):
        pc = RAM_TO_FILE + offset
        word = struct.unpack_from("<I", exe, offset)[0]
        target = control_target(pc, word)
        if target in targets:
            result.append((pc, word, target))
    return result


def instruction_lines(exe: bytes, start: int, end: int) -> list[str]:
    md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN)
    blob = exe[start - RAM_TO_FILE : end - RAM_TO_FILE]
    insns = list(md.disasm(blob, start))
    if sum(insn.size for insn in insns) != len(blob):
        raise VerifyError(f"incomplete MIPS disassembly at 0x{start:08X}")
    return [
        f"0x{insn.address:08X}: {insn.bytes.hex().upper()}  {insn.mnemonic} {insn.op_str}"
        for insn in insns
    ]


def verify_skill_runtime_evidence(exe: bytes) -> list[dict[str, object]]:
    table = struct.unpack_from("<5I", exe, SKILL_TABLE_FILE)
    if table[1] != SKILL_GROUND_RAM or table[4] != SKILL_SLOW_RAM:
        raise VerifyError("dedicated skill-name table entries drift")
    ground_file = SKILL_GROUND_RAM - RAM_TO_FILE
    slow_file = SKILL_SLOW_RAM - RAM_TO_FILE
    if exe[ground_file : ground_file + len(SKILL_GROUND_BYTES)] != SKILL_GROUND_BYTES:
        raise VerifyError("번 그라운드 source bytes drift")
    if exe[slow_file : slow_file + len(SKILL_SLOW_BYTES)] != SKILL_SLOW_BYTES:
        raise VerifyError("슬로우 에너미 source bytes drift")

    with RUNTIME_OBJECTS.open(encoding="utf-8-sig", newline="") as handle:
        rows = [
            row for row in csv.DictReader(handle)
            if row["header"] == "0x801F1DB4" and row["state"] in ("4", "5")
        ]
    if len(rows) != 2:
        raise VerifyError(f"V329 skill runtime object census drift: {len(rows)}")
    by_state = {row["state"]: row for row in rows}
    expected = {
        "4": ("번 그라운드", "0x8019ADF0", 198, 194),
        "5": ("슬로우 에너미", "0x8019C1F7", 71, 67),
    }
    result: list[dict[str, object]] = []
    for state, (text, end_pointer, old_x, new_x) in expected.items():
        row = by_state[state]
        if row["text"] != text or row["source_pointer"] != end_pointer:
            raise VerifyError(f"state {state} skill pointer/text evidence drift")
        first_x = min(
            int(packet["x"])
            for packet in csv.DictReader(
                (ROOT / "01_work/analysis/arc1_v329_skill_states_5/packets.csv").open(
                    encoding="utf-8-sig", newline=""
                )
            )
            if packet["state"] == state and packet["header"] == "0x801F1DB4"
        )
        if first_x != old_x:
            raise VerifyError(f"state {state} skill X evidence drift: {first_x}")
        result.append(
            {
                "screen": f"skill_state_{state}",
                "text": text,
                "v329_x": old_x,
                "v332_x": new_x,
                "bar_x": "",
                "text_inset": "",
            }
        )
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
        raise VerifyError("V332 PSX.EXE hash mismatch")
    if struct.unpack_from("<2I", exe0, BAR_LEFT_FILE) != (BAR_LEFT_OLD, BAR_RIGHT_OLD):
        raise VerifyError("V331 selection-bar X words drift")
    if struct.unpack_from("<2I", exe1, BAR_LEFT_FILE) != (BAR_LEFT_NEW, BAR_RIGHT_NEW):
        raise VerifyError("V332 selection-bar X words mismatch")

    exact = bytearray(exe0)
    struct.pack_into("<I", exact, BAR_LEFT_FILE, BAR_LEFT_NEW)
    struct.pack_into("<I", exact, BAR_RIGHT_FILE, BAR_RIGHT_NEW)
    if bytes(exact) != exe1:
        raise VerifyError("V332 is not the exact two-word overlay")
    diff = {i for i, (a, b) in enumerate(zip(exe0, exe1, strict=True)) if a != b}
    if diff != {BAR_LEFT_FILE, BAR_RIGHT_FILE}:
        raise VerifyError(f"Expected-Write mismatch: {sorted(diff)}")

    # V331 text alignment, owned payload and dedicated skill route are immutable.
    if struct.unpack_from("<I", exe1, CONFIG_BASE_FILE)[0] != 0x34130022:
        raise VerifyError("configuration base is not s3=34")
    if struct.unpack_from("<I", exe1, CONFIG_FIRST_FILE)[0] != 0x26640080:
        raise VerifyError("first configuration text column is not X=162")
    if struct.unpack_from("<I", exe1, CONFIG_SECOND_FILE)[0] != 0x266400BC:
        raise VerifyError("second configuration text column is not X=222")
    if struct.unpack_from("<I", exe1, BAR_WIDTH_FILE)[0] != 0x34050033:
        raise VerifyError("selection bar width is not 51")
    if struct.unpack_from("<I", exe1, BAR_HEIGHT_FILE)[0] != 0x3406000E:
        raise VerifyError("selection bar height is not 14")
    if exe1[CONFIG_PAYLOAD_FILE : CONFIG_PAYLOAD_FILE + 9] != CONFIG_PAYLOAD:
        raise VerifyError("V331 사용안함 payload was not preserved")
    if struct.unpack_from("<2I", exe1, SKILL_CALL_FILE) != SKILL_CALL_WORDS:
        raise VerifyError("dedicated skill wrapper call changed")
    wrapper = exe1[SKILL_WRAPPER_FILE : SKILL_WRAPPER_FILE + SKILL_WRAPPER_SIZE]
    if sha256(wrapper) != SKILL_WRAPPER_SHA256:
        raise VerifyError("dedicated skill wrapper changed")

    if struct.unpack_from(f"<{len(BAR_STORE_WORDS)}I", exe1, BAR_STORE_FILE) != BAR_STORE_WORDS:
        raise VerifyError("0x8016D620 a1/a2 store semantics drift")
    expected_inbound = [
        (0x801608E8, 0x14400003, 0x801608F8),
        (0x801608F0, 0x0805823F, 0x801608FC),
    ]
    if inbound_to(exe1, {BAR_LEFT_RAM, BAR_RIGHT_RAM, BAR_CALL_RAM}) != expected_inbound:
        raise VerifyError("selection-bar branch/jump topology drift")

    disassembly = instruction_lines(exe1, 0x801608E4, 0x80160904)
    if not any("addiu $a1, $s3, 0x7e" in line for line in disassembly):
        raise VerifyError("Capstone did not confirm first bar X=160 instruction")
    if not any("addiu $a1, $s3, 0xba" in line for line in disassembly):
        raise VerifyError("Capstone did not confirm second bar X=220 instruction")
    if not any("jal 0x8016d620" in line for line in disassembly):
        raise VerifyError("Capstone did not confirm bar-coordinate consumer")

    predictions = verify_skill_runtime_evidence(exe1)
    predictions.extend(
        [
            {
                "screen": "configuration_first_column",
                "text": "사용안함 포함",
                "v329_x": 166,
                "v332_x": 162,
                "bar_x": 160,
                "text_inset": 2,
            },
            {
                "screen": "configuration_second_column",
                "text": "두 번째 선택열",
                "v329_x": 226,
                "v332_x": 222,
                "bar_x": 220,
                "text_inset": 2,
            },
        ]
    )

    ANALYSIS.mkdir(parents=True, exist_ok=True)
    with (ANALYSIS / "runtime_coordinate_prediction.csv").open(
        "w", encoding="utf-8-sig", newline=""
    ) as handle:
        writer = csv.DictWriter(handle, fieldnames=list(predictions[0]))
        writer.writeheader()
        writer.writerows(predictions)
    (ANALYSIS / "mips_disassembly.txt").write_text(
        "V332 configuration selection-bar dispatch\n" + "\n".join(disassembly) + "\n",
        encoding="utf-8",
    )

    verification = {
        "result": "PASS",
        "hashes": {
            "base": BASE_SHA256,
            "final": FINAL_SHA256,
            "delta": DELTA_SHA256,
            "psx": FINAL_PSX_SHA256,
        },
        "archive": {"members": 164, "changed_members": [PSX]},
        "expected_write": {"changed_bytes": 2, "exact_offsets": ["0x460F4", "0x460F8"]},
        "skill": "V331 dedicated 0x80162080 wrapper preserved; table/pointers prove both target names",
        "configuration": "text 162/222 and 사용안함 preserved; bars 164/224 -> 160/220; inset 2px",
        "control_flow": "0x801608F4 remains jump delay slot; 0x801608F8 remains branch target",
        "runtime": "PENDING V332 user cold boot",
    }
    (ANALYSIS / "independent_verification.json").write_text(
        json.dumps(verification, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    lines = [
        "V332 independent verification: PASS",
        f"full_sha256={FINAL_SHA256}",
        f"delta_sha256={DELTA_SHA256}",
        f"psx_sha256={FINAL_PSX_SHA256}",
        "archive=164 members; changed=PSX.EXE only; all DAT/COMM byte-identical",
        "Expected-Write=2 bytes at file 0x460F4/0x460F8 only",
        "skill=V331 dedicated two-screen dx=-4 route preserved byte-exact",
        "configuration=text X=162/222; bar X=160/220; 2px inset preserved; 사용안함 preserved",
        "R3000=jump delay slot and branch target preserved; a1 X store at 0x8016D638 confirmed",
        "runtime=PENDING V332 cold boot; TEST_ONLY",
    ]
    (ANALYSIS / "independent_verification.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    checklist = [
        "V332 cold-boot runtime checklist",
        "",
        "- Boot 03_output/V332.cue from a cold emulator start (do not load an older-build savestate).",
        "- Confirm both skill-name screens: 번 그라운드 and 슬로우 에너미 begin 4px left of V329.",
        "- Open configuration and confirm both choice columns and their blue selection bars moved together 4px left.",
        "- Confirm 사용안함 has no spaces and no overlap with the second choice column.",
        "- Move the cursor through all four configuration rows; selected/unselected bar positions must stay aligned.",
        "- Check representative item/equipment/status/dialogue screens for unchanged coordinates and glyphs.",
        "- Save new DUCCU states/screenshots from V332 for runtime attribution.",
        "",
        "Static result: PASS. Runtime result: PENDING user cold boot.",
    ]
    (ANALYSIS / "runtime_checklist.txt").write_text("\n".join(checklist) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
