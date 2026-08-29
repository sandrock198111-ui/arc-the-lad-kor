#!/usr/bin/env python3
"""Independent static verification for V336 (known invalid build).

This verifier does not import the V336 builder.  It reopens the archives,
recomputes every byte envelope, decodes the repaired text, simulates the
bounded physical-index remap for all catalogued text tokens, and reads the
4bpp COMM planes independently.  It also decodes the common-gate branch
target; V336 is expected to fail because its out-of-range BEQ wrapped to
0x801AB524.  V337 repairs this defect.
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

import build_arc1_v320_hanme_static_recovery as v320  # noqa: E402


BASE = ROOT / "03_output/arc1_v335_dialogue_text_y_minus4_TEST_ONLY_CF4FB2E5.zip"
OUTPUT = ROOT / "03_output/arc1_v336_ui_text_native_damage_repair_TEST_ONLY_28C9A039.zip"
DELTA = ROOT / "03_output/arc1_v336_ui_text_native_damage_repair_TEST_ONLY_delta_from_v335_FAF7E785.zip"
ORIGINAL = ROOT / "00_original/arc.zip"
ASSIGNMENTS = ROOT / "01_work/analysis/arc1_v320_hanme_static_recovery/character_assignments.csv"
CELL_AUDIT = ROOT / "01_work/analysis/font_cell_audit_full/cell_consumers.csv"
ANALYSIS = ROOT / "01_work/analysis/arc1_v336_ui_text_native_damage_repair"

BASE_SHA256 = "CF4FB2E518ADD6CE6B528C44D2AD4696DCD9DAF2940FE0A105F60B50C76C70D0"
OUTPUT_SHA256 = "28C9A03986B549DD62B4B1517815327DDC52E776770221630557B360F0B0C0F4"
DELTA_SHA256 = "FAF7E7854AEABB7CB04E96B32DFF1226194F0F883ABF324653C3618F39604B7D"
ORIGINAL_SHA256 = "AE9F4366A1E7DA3805BB3BED3DDA9567E4CD4E669AF890E4E2A620D7861F11DD"
OUTPUT_PSX_SHA256 = "3A6991E99492979552007C6705E8E635E279BBABE6E3F11F719767ED295A11DC"
OUTPUT_COMM_SHA256 = "BDDDF442BC43926CF77A1356F9D0986B199A7A2F32745A3D47D5C1B6B654B9C3"

PSX, COMM = "PSX.EXE", "COMM.IMG"
ROW_BYTES = 896
SLOT_BASE, SLOT_SIZE, SLOT_META = 0x45000, 0x80, 0x7F
SOURCE = tuple(range(804, 820))
DEST = tuple(range(161, 177))
DISPLACED = (168, 169, 170)
BACKUP = (741, 742, 743)
E5_BLANK = 746
CANONICAL_BLANK = 116

EXPECTED_CHANGED = {
    PSX,
    COMM,
    "1/S1023.DAT",
    "21/S2042.DAT",
    "4/S4011.DAT",
    "4/S4021.DAT",
}
EXPECTED_COUNTS = {
    PSX: 155,
    COMM: 792,
    "1/S1023.DAT": 22,
    "21/S2042.DAT": 2,
    "4/S4011.DAT": 18,
    "4/S4021.DAT": 31,
}

EQUIPMENT_CAVE = (0x808F4, 0x80910)
MAIN_CAVE = (0x809F8, 0x80A94)
EQUIPMENT_HEX = (
    "E0FFBD273000A28F1C00BFAFE3B0050C1000A2AF856C060800000000"
)
MAIN_HEX = (
    "E0FFBD273000A28F3400A38F1C00BFAF1000A2AF00B1050C1400A3AF"
    "FCFF04241F80063CB41DC62410AD050C212800001C00BF8F2000BD2708"
    "00E003000000000800A2940000000002004224C9AC05080800A2A45FFF"
    "88241000092D0800201100000000F9FF09250300292D0200201174000434"
    "DE02042549AD050800000000DCFC88241000092DA8402011000000007DFD"
    "842449AD050800000000"
)


class VerifyError(RuntimeError):
    pass


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def file_sha256(path: Path) -> str:
    return sha256(path.read_bytes())


def read_zip(path: Path) -> tuple[list[str], dict[str, bytes]]:
    with ZipFile(path) as archive:
        names = [item.filename for item in archive.infolist() if not item.is_dir()]
        return names, {name: archive.read(name) for name in names}


def changed_offsets(before: bytes, after: bytes) -> set[int]:
    if len(before) != len(after):
        raise VerifyError("member size changed")
    return {i for i, (a, b) in enumerate(zip(before, after, strict=True)) if a != b}


def read_plane(comm: bytes, index: int) -> tuple[int, ...]:
    cell, plane = divmod(index, 4)
    col, row = cell % 15, cell // 15
    rows: list[int] = []
    for y in range(16):
        value = 0
        start = (row * 16 + y) * ROW_BYTES + col * 8
        for x in range(16):
            byte = comm[start + x // 2]
            nibble = (byte >> (0 if x % 2 == 0 else 4)) & 0xF
            if nibble & (1 << plane):
                value |= 1 << (15 - x)
        rows.append(value)
    return tuple(rows)


def runtime_target(index: int) -> int:
    if 161 <= index < 177:
        if 168 <= index <= 170:
            return 741 + index - 168
        return CANONICAL_BLANK
    if 804 <= index < 820:
        return index - 643
    return index


def direct_index(token: bytes) -> int | None:
    if len(token) == 1:
        return token[0] - 1 if 1 <= token[0] <= 0xDC else None
    if len(token) != 2:
        return None
    lead, trail = token
    if lead in (0xE9, 0xEA) or lead < 0xDD or not 1 <= trail <= 0xFE:
        return None
    return (lead - 0xDD) * 255 + trail + 0xDB


def glyph_target(exe: bytes, token: bytes) -> int | None:
    if len(token) == 2 and token[0] in (0xE9, 0xEA) and 1 <= token[1] <= 0xFE:
        slot = (token[0] - 0xE9) * 254 + token[1] - 1
        return v320.lookup_get(exe, slot) if slot < v320.LOOKUP_SLOTS else None
    return direct_index(token)


def code_map() -> dict[bytes, str]:
    result: dict[bytes, str] = {}
    with ASSIGNMENTS.open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            token = bytes.fromhex(row["code_hex"])
            old = result.setdefault(token, row["char"])
            if old != row["char"]:
                raise VerifyError(f"assignment collision for {token.hex()}")
    return result


def decode(payload: bytes, mapping: dict[bytes, str]) -> str:
    result: list[str] = []
    at = 0
    while at < len(payload):
        width = 1 if payload[at] < 0xDD else 2
        token = payload[at : at + width]
        if token not in mapping:
            raise VerifyError(f"unknown token {token.hex()} at +0x{at:X}")
        result.append(mapping[token])
        at += width
    return "".join(result)


def slot(data: bytes, number: int) -> tuple[bytes, int]:
    start = SLOT_BASE + number * SLOT_SIZE
    payload = data[start : start + SLOT_META]
    end = payload.find(0)
    if end < 0:
        raise VerifyError(f"slot {number} has no terminator")
    return payload[:end], data[start + SLOT_META]


def nontext_safe(indices: tuple[int, ...]) -> None:
    audit: dict[tuple[int, int], int] = {}
    with CELL_AUDIT.open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            audit[(int(row["row"]), int(row["col"]))] = int(row["nontext_reads"])
    for index in indices:
        cell = index // 4
        x0, y0 = (cell % 15) * 16, (cell // 15) * 16
        covered = {(y // 12, x // 12) for y in range(y0, y0 + 16) for x in range(x0, x0 + 16)}
        if any(audit.get(key, -1) != 0 for key in covered):
            raise VerifyError(f"physical {index} is not nontext-safe")


def main() -> None:
    for path, expected in (
        (BASE, BASE_SHA256),
        (OUTPUT, OUTPUT_SHA256),
        (DELTA, DELTA_SHA256),
        (ORIGINAL, ORIGINAL_SHA256),
    ):
        if file_sha256(path) != expected:
            raise VerifyError(f"archive hash mismatch: {path.name}")

    base_names, base = read_zip(BASE)
    out_names, out = read_zip(OUTPUT)
    delta_names, delta = read_zip(DELTA)
    if len(base_names) != 164 or out_names != base_names:
        raise VerifyError("164-member topology changed")
    changed = {name for name in base_names if base[name] != out[name]}
    if changed != EXPECTED_CHANGED or set(delta_names) != EXPECTED_CHANGED:
        raise VerifyError(f"changed-member set mismatch: {sorted(changed)}")
    if any(delta[name] != out[name] for name in delta_names):
        raise VerifyError("delta payload differs from full output")
    counts = {name: len(changed_offsets(base[name], out[name])) for name in changed}
    if counts != EXPECTED_COUNTS:
        raise VerifyError(f"changed-byte counts mismatch: {counts}")
    if sha256(out[PSX]) != OUTPUT_PSX_SHA256 or sha256(out[COMM]) != OUTPUT_COMM_SHA256:
        raise VerifyError("output member hash mismatch")

    exe = out[PSX]
    if exe[slice(*EQUIPMENT_CAVE)] != bytes.fromhex(EQUIPMENT_HEX):
        raise VerifyError("equipment wrapper bytes differ")
    if exe[slice(*MAIN_CAVE)] != bytes.fromhex(MAIN_HEX):
        raise VerifyError("main helper bytes differ")
    expected_words = {
        0x494A8: 0x0C066C3D,
        0x4A32C: 0x0C066C7E,
        0x4A35C: 0x0C066C8E,
        0x809DC: 0x08066C93,
        0x51604: 0x340402EA,
        0x51DBC: 0x00028100,
        0x51DC0: 0x00021840,
        0x51DC8: 0x02038023,
    }
    for offset, expected in expected_words.items():
        actual = struct.unpack_from("<I", exe, offset)[0]
        if actual != expected:
            raise VerifyError(f"word mismatch at 0x{offset:X}: 0x{actual:08X}")

    mapping = code_map()
    choice = out["1/S1023.DAT"]
    expected_choice = {0: ("어머니: 아버지 편지 볼래?", 5), 2: ("다음", 5), 3: ("읽는다", 1)}
    for number, (text, metadata) in expected_choice.items():
        payload, meta = slot(choice, number)
        if decode(payload, mapping) != text or meta != metadata:
            raise VerifyError(f"choice slot {number} readback mismatch")
    body = choice[0x47952 : 0x47952 + 56]
    if body.count(bytes.fromhex("E5 03")) != 2 or body.count(bytes.fromhex("E6 01")) != 3:
        raise VerifyError("choice E5/E6 topology changed")

    l_payload, l_meta = slot(out["21/S2042.DAT"], 1)
    if l_meta != 45 or l_payload.count(bytes.fromhex("DD D8")) != 1 or bytes.fromhex("EA 9E") in l_payload:
        raise VerifyError("L/R help repair mismatch")
    soldier_payload, soldier_meta = slot(out["4/S4021.DAT"], 4)
    if soldier_meta != 29 or decode(soldier_payload, mapping)[:4] != "병사 2":
        raise VerifyError("병사 2 repair mismatch")
    warehouse = out["4/S4011.DAT"][0x485A2 : 0x485A2 + 21]
    if warehouse[10:12] != bytes.fromhex("E6 01"):
        raise VerifyError("warehouse line break changed")
    if decode(warehouse[:10], mapping).rstrip() != "잠깐, 뭔가":
        raise VerifyError("warehouse first line mismatch")
    if decode(warehouse[12:], mapping).rstrip() != "이상해.":
        raise VerifyError("warehouse second line mismatch")

    nontext_safe(DEST + BACKUP + (E5_BLANK,))
    base_comm, final_comm = base[COMM], out[COMM]
    with ZipFile(ORIGINAL) as archive:
        original_comm = archive.read(COMM)
    for source, destination in zip(SOURCE, DEST, strict=True):
        if read_plane(base_comm, source) != read_plane(final_comm, destination):
            raise VerifyError(f"source relocation mismatch {source}->{destination}")
    for source, destination in zip(DISPLACED, BACKUP, strict=True):
        if read_plane(base_comm, source) != read_plane(final_comm, destination):
            raise VerifyError(f"displaced backup mismatch {source}->{destination}")
    if any(read_plane(final_comm, E5_BLANK)) or any(read_plane(final_comm, CANONICAL_BLANK)):
        raise VerifyError("blank plane is not blank")
    for y in range(208, 224):
        start = y * ROW_BYTES + 48
        if final_comm[start : start + 32] != original_comm[start : start + 32]:
            raise VerifyError(f"native damage cell row {y} differs from original")
    for y in range(208, 220):
        start = y * ROW_BYTES
        if final_comm[start : start + 78] != original_comm[start : start + 78]:
            raise VerifyError(f"13-cell damage bank row {y} differs")

    compared = affected = 0
    for name, start, end in v320.text_regions(base):
        data = base[name]
        at = start
        while at < end:
            if v320.is_control(data, at):
                at += 2
                continue
            width = v320.token_width(data[at])
            token = data[at : at + width]
            target = glyph_target(base[PSX], token)
            if target is not None and target < 960:
                remapped = runtime_target(target)
                if read_plane(base_comm, target) != read_plane(final_comm, remapped):
                    raise VerifyError(f"runtime bitmap mismatch {name}:0x{at:X} {target}->{remapped}")
                compared += 1
                affected += target in SOURCE or 161 <= target < 177
            at += width
    if compared != 130963 or affected <= 47:
        raise VerifyError(f"text census drift: compared={compared} affected={affected}")

    branch_file = 0x80A80
    branch_ram = 0x8019B280
    branch_word = struct.unpack_from("<I", exe, branch_file)[0]
    immediate = branch_word & 0xFFFF
    if immediate & 0x8000:
        immediate -= 0x10000
    actual_branch_target = (branch_ram + 4 + immediate * 4) & 0xFFFFFFFF
    branch_failure = actual_branch_target != 0x8016B524

    report = {
        "verdict": "FAIL_STATIC_BRANCH_WRAP" if branch_failure else "PASS_STATIC_RUNTIME_PENDING",
        "output_sha256": OUTPUT_SHA256,
        "changed_members": sorted(changed),
        "changed_bytes": counts,
        "text_bitmap_comparisons": compared,
        "remapped_or_preserved_occurrences": affected,
        "native_damage_cells": 13,
        "damage_text_relocation": [f"{a}->{b}" for a, b in zip(SOURCE, DEST, strict=True)],
        "displaced_backup": [f"{a}->{b}" for a, b in zip(DISPLACED, BACKUP, strict=True)],
        "common_gate_branch": {
            "word": f"0x{branch_word:08X}",
            "actual_target": f"0x{actual_branch_target:08X}",
            "required_target": "0x8016B524",
        },
        "runtime": "DO NOT RUN; superseded by V337" if branch_failure else "PENDING user cold boot",
    }
    ANALYSIS.mkdir(parents=True, exist_ok=True)
    (ANALYSIS / "independent_verification.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (ANALYSIS / "independent_verification.txt").write_text(
        "\n".join(
            [
                "V336 independent verification: FAIL (out-of-range branch wrapped)",
                f"archive={OUTPUT_SHA256}",
                f"changed_members={','.join(sorted(changed))}",
                f"changed_bytes={counts}",
                f"text_bitmap_comparisons={compared}",
                f"remapped_or_preserved_occurrences={affected}",
                "choice/L/병사 2/warehouse/location/item/quantity=PASS",
                "native_damage=13/13 original cells; text relocation and backups=PASS",
                f"common_gate_branch=0x{branch_word:08X} -> 0x{actual_branch_target:08X} (required 0x8016B524)",
                "runtime=DO NOT RUN; superseded by V337",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    if branch_failure:
        raise VerifyError(
            "V336 INVALID: common-gate BEQ wraps to "
            f"0x{actual_branch_target:08X}; use V337"
        )
    print("V336 independent verification: PASS")


if __name__ == "__main__":
    main()
