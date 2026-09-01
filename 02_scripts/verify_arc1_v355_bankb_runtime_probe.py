#!/usr/bin/env python3
"""Independently verify the V355 E2 Bank-B runtime probe."""

from __future__ import annotations

import csv
import hashlib
import json
import struct
from pathlib import Path
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "03_output/arc1_v354_dialogue_identity_wording_repair_TEST_ONLY_2AA6C42A.zip"
BASE_SHA256 = "2AA6C42AC1F62B5D1C7121F27B77807610C9E05D423C548429CB38653DF9C194"
ANALYSIS = ROOT / "01_work/analysis/arc1_v355_bankb_runtime_probe"
MANIFEST = ANALYSIS / "build_manifest.json"
ORIGINAL_CSV = ROOT / "05_docs/script_original_full.csv"

PSX = "PSX.EXE"
COMM = "COMM.IMG"
DAT = "1/S1011.DAT"
LOAD = 0x8011B000
LOOKUP = 0x8018FCD0
COMPLETION = 0x8018FD28
HANDLER_END = 0x8018FD90
CURSOR_GATE = 0x8018FD90
ORIGINAL_LOOKUP = 0x8015EA44
COMPLETION_TARGET = 0x8016BE44
HANDLER_SHA256 = "BD8FEE05BE81BACBE0207A94D4414B516052A728E8F53996CEBA1F76FADB8DFB"
BODY = 0x478AA
SOURCE_SLOT = 0x45700
BANK_B = 0x4200
SLOT_SIZE = 0x80


class VerifyError(RuntimeError):
    pass


def sha(data: bytes | Path) -> str:
    raw = data.read_bytes() if isinstance(data, Path) else data
    return hashlib.sha256(raw).hexdigest().upper()


def fo(address: int) -> int:
    return address - LOAD + 0x800


def sx16(value: int) -> int:
    return value - 0x10000 if value & 0x8000 else value


def tokens(data: bytes):
    offset = 0
    while offset < len(data):
        width = 1 if data[offset] < 0xDD else 2
        yield data[offset:offset + width]
        offset += width


def owned_slot(disk_id: int) -> int | None:
    if 0x81 <= disk_id <= 0xA8:
        return disk_id - 0x81
    if 0xAA <= disk_id <= 0xD0:
        return disk_id - 0x82
    if 0xD1 <= disk_id <= 0xEC:
        return disk_id - 0xD1 - 2076
    return None


def run(words: list[int], base: int, disk_id: int, completion: bool = False) -> tuple[list[int], dict[int, int], int]:
    """Execute the emitted subset with R3000 one-instruction load delay."""
    registers = [0] * 32
    registers[4] = ((disk_id if completion else disk_id - 1) & 0xFF)
    registers[16] = 0x90000000
    registers[31] = 0xDEADBEEF
    pointer = 0x81234567
    memory = {0x90000014: pointer}
    byte_memory = {(pointer - 1) & 0xFFFFFFFF: disk_id & 0xFF}
    pc = base
    pending_load: tuple[int, int] | None = None
    deferred: int | None = None
    for _step in range(100):
        index = (pc - base) // 4
        if not 0 <= index < len(words):
            return registers, memory, pc
        word = words[index]
        op = word >> 26
        rs, rt = (word >> 21) & 31, (word >> 16) & 31
        rd, shift, function = (word >> 11) & 31, (word >> 6) & 31, word & 63
        immediate = word & 0xFFFF
        old_load, pending_load = pending_load, None
        next_pc = (pc + 4) & 0xFFFFFFFF
        new_branch: int | None = None

        def write(register: int, value: int) -> None:
            if register:
                registers[register] = value & 0xFFFFFFFF

        if op == 0:
            if word == 0:
                pass
            elif function == 0:
                write(rd, registers[rt] << shift)
            elif function == 0x21:
                write(rd, registers[rs] + registers[rt])
            elif function == 8:
                new_branch = registers[rs]
            else:
                raise VerifyError(f"unsupported R instruction {word:08X}")
        elif op == 0x0C:
            write(rt, registers[rs] & immediate)
        elif op == 0x0D:
            write(rt, registers[rs] | immediate)
        elif op == 0x09:
            write(rt, registers[rs] + sx16(immediate))
        elif op == 0x0B:
            write(rt, int((registers[rs] & 0xFFFFFFFF) < immediate))
        elif op in (4, 5):
            condition = registers[rs] == registers[rt]
            if (op == 4 and condition) or (op == 5 and not condition):
                new_branch = (pc + 4 + (sx16(immediate) << 2)) & 0xFFFFFFFF
        elif op == 0x0F:
            write(rt, immediate << 16)
        elif op == 0x23:
            address = (registers[rs] + sx16(immediate)) & 0xFFFFFFFF
            pending_load = (rt, memory.get(address, 0))
        elif op == 0x24:
            address = (registers[rs] + sx16(immediate)) & 0xFFFFFFFF
            value = byte_memory.get(address, 37 if (address & 0x7F) == 0x7F else 0)
            pending_load = (rt, value)
        elif op == 0x2B:
            address = (registers[rs] + sx16(immediate)) & 0xFFFFFFFF
            memory[address] = registers[rt]
        elif op == 2:
            new_branch = ((pc + 4) & 0xF0000000) | ((word & 0x03FFFFFF) << 2)
        else:
            raise VerifyError(f"unsupported instruction {word:08X}")

        if old_load is not None:
            write(*old_load)
        if deferred is not None:
            if new_branch is not None:
                raise VerifyError("control instruction in a delay slot")
            next_pc, deferred = deferred, None
        elif new_branch is not None:
            deferred = new_branch
        pc = next_pc
    raise VerifyError("handler simulation did not terminate")


def register_access(word: int) -> tuple[set[int], set[int], bool]:
    op = word >> 26
    rs, rt, rd, function = (word >> 21) & 31, (word >> 16) & 31, (word >> 11) & 31, word & 63
    reads: set[int] = set()
    writes: set[int] = set()
    load = False
    if op == 0:
        if word == 0:
            pass
        elif function in (0, 2, 3):
            reads.add(rt); writes.add(rd)
        elif function in (8, 9):
            reads.add(rs)
        else:
            reads.update((rs, rt)); writes.add(rd)
    elif op in (4, 5):
        reads.update((rs, rt))
    elif op in (6, 7):
        reads.add(rs)
    elif op in (0x20, 0x21, 0x23, 0x24, 0x25):
        reads.add(rs); writes.add(rt); load = True
    elif op in (0x28, 0x29, 0x2B):
        reads.update((rs, rt))
    elif op not in (2, 3, 0x0F):
        reads.add(rs); writes.add(rt)
    return reads - {0}, writes - {0}, load


def direct_edges(exe: bytes) -> list[tuple[int, int, int]]:
    edges: list[tuple[int, int, int]] = []
    for offset in range(0x800, len(exe) - 3, 4):
        pc = LOAD + offset - 0x800
        word = struct.unpack_from("<I", exe, offset)[0]
        op = word >> 26
        target = None
        if op in (2, 3):
            target = ((pc + 4) & 0xF0000000) | ((word & 0x03FFFFFF) << 2)
        elif op in (1, 4, 5, 6, 7):
            target = (pc + 4 + (sx16(word & 0xFFFF) << 2)) & 0xFFFFFFFF
        if target is not None:
            edges.append((pc, target, op))
    return edges


def active_bank_b_refs(members: dict[str, bytes]) -> list[tuple[str, int, int]]:
    """Parser-aware scan of current dialogue bodies; raw binary coincidences do not count."""
    references: list[tuple[str, int, int]] = []
    with ORIGINAL_CSV.open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        offset_key = "byte offset" if "byte offset" in (reader.fieldnames or []) else "offset"
        for row in reader:
            name = row["source file"]
            if name not in members:
                continue
            offset = int(row[offset_key], 0)
            raw = bytes.fromhex(row["raw bytes as hex"].replace(" ", ""))
            body = members[name][offset:offset + len(raw)]
            stream = [body[:2]] if len(body) >= 2 and body[0] == 0xE2 else tokens(body)
            for token in stream:
                if len(token) == 1 and token[0] == 0:
                    break
                if len(token) == 2 and token[0] == 0xE2 and 0xD1 <= token[1] <= 0xEC:
                    references.append((name, offset, token[1]))
    return references


def main() -> None:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    full = ROOT / manifest["full_zip"]
    delta = ROOT / manifest["delta_zip"]
    if sha(BASE) != BASE_SHA256 or sha(full) != manifest["full_sha256"] or sha(delta) != manifest["delta_sha256"]:
        raise VerifyError("archive hash mismatch")
    if full.stem.rsplit("_", 1)[-1] != manifest["full_sha256"][:8]:
        raise VerifyError("full archive hash suffix mismatch")

    with ZipFile(BASE) as archive:
        base_names = [item.filename for item in archive.infolist() if not item.is_dir()]
        base = {name: archive.read(name) for name in base_names}
    with ZipFile(full) as archive:
        out_names = [item.filename for item in archive.infolist() if not item.is_dir()]
        out = {name: archive.read(name) for name in out_names}
    with ZipFile(delta) as archive:
        delta_names = [item.filename for item in archive.infolist() if not item.is_dir()]
        delta_members = {name: archive.read(name) for name in delta_names}
    if len(base_names) != 164 or out_names != base_names:
        raise VerifyError("full archive topology mismatch")
    changed = [name for name in base_names if base[name] != out[name]]
    if len(changed) != 2 or set(changed) != {PSX, DAT} or delta_names != changed:
        raise VerifyError(f"changed-member isolation mismatch: {changed}/{delta_names}")
    if any(delta_members[name] != out[name] for name in changed):
        raise VerifyError("delta member mismatch")
    if out[COMM] != base[COMM]:
        raise VerifyError("COMM.IMG changed; additional VRAM must be zero")

    handler = out[PSX][fo(LOOKUP):fo(HANDLER_END)]
    if len(handler) != 0xC0 or sha(handler) != HANDLER_SHA256:
        raise VerifyError("handler image mismatch")
    if out[PSX][:fo(LOOKUP)] != base[PSX][:fo(LOOKUP)] or out[PSX][fo(HANDLER_END):] != base[PSX][fo(HANDLER_END):]:
        raise VerifyError("PSX.EXE changed outside E2 handler")
    if out[PSX][fo(CURSOR_GATE):fo(CURSOR_GATE) + 64] != base[PSX][fo(CURSOR_GATE):fo(CURSOR_GATE) + 64]:
        raise VerifyError("range-cursor gate changed")

    lookup_words = list(struct.unpack("<21I", handler[:84]))
    completion_words = list(struct.unpack("<26I", handler[88:]))
    for disk_id in range(256):
        slot = owned_slot(disk_id)
        registers, _memory, target = run(lookup_words, LOOKUP, disk_id)
        expected_address = None if slot is None else (0x80114000 + slot * 0x80) & 0xFFFFFFFF
        if slot is None:
            if target != ORIGINAL_LOOKUP:
                raise VerifyError(f"lookup fallback mismatch for {disk_id:02X}")
        elif registers[2] != expected_address or target != 0xDEADBEEF:
            raise VerifyError(f"lookup address mismatch for {disk_id:02X}")
        registers, memory, target = run(completion_words, COMPLETION, disk_id, completion=True)
        expected_pointer = 0x81234567 + (37 if slot is not None else 0)
        if memory[0x90000014] != expected_pointer or registers[2] != 1 or target != COMPLETION_TARGET:
            raise VerifyError(f"completion mismatch for {disk_id:02X}")

    combined_words = lookup_words + [0] + completion_words
    for index, word in enumerate(combined_words[:-1]):
        _reads, writes, is_load = register_access(word)
        next_reads, _next_writes, _next_load = register_access(combined_words[index + 1])
        if is_load and writes & next_reads:
            raise VerifyError(f"R3000 load-delay hazard at handler word {index}")

    edges = direct_edges(out[PSX])
    external_handler = sorted(
        (source, target) for source, target, _op in edges
        if LOOKUP <= target < HANDLER_END and not (LOOKUP <= source < HANDLER_END)
    )
    if external_handler != [(0x8016BC84, LOOKUP), (0x8016BDC0, COMPLETION)]:
        raise VerifyError(f"unexpected external handler edges: {external_handler}")
    external_cursor = sorted(
        (source, target) for source, target, _op in edges
        if target == CURSOR_GATE and not (LOOKUP <= source < HANDLER_END)
    )
    if external_cursor != [(0x8011C860, CURSOR_GATE)]:
        raise VerifyError(f"range-cursor inbound mismatch: {external_cursor}")

    base_dat, out_dat = base[DAT], out[DAT]
    if base_dat[BANK_B:BANK_B + 28 * SLOT_SIZE] != bytes(28 * SLOT_SIZE):
        raise VerifyError("V354 Bank-B premise was not zero")
    if out_dat[BANK_B:BANK_B + SLOT_SIZE] != base_dat[SOURCE_SLOT:SOURCE_SLOT + SLOT_SIZE]:
        raise VerifyError("Bank-B probe slot is not a byte-exact copy")
    if out_dat[BANK_B + SLOT_SIZE:BANK_B + 28 * SLOT_SIZE] != bytes(27 * SLOT_SIZE):
        raise VerifyError("unused Bank-B slots changed")
    if out_dat[SOURCE_SLOT:SOURCE_SLOT + SLOT_SIZE] != base_dat[SOURCE_SLOT:SOURCE_SLOT + SLOT_SIZE]:
        raise VerifyError("standard source slot changed")
    if base_dat[BODY:BODY + 2] != bytes((0xE2, 0x8F)) or out_dat[BODY:BODY + 2] != bytes((0xE2, 0xD1)):
        raise VerifyError("probe caller mismatch")
    allowed_dat = set(range(BANK_B, BANK_B + SLOT_SIZE)) | {BODY + 1}
    actual_dat = {offset for offset, pair in enumerate(zip(base_dat, out_dat)) if pair[0] != pair[1]}
    if not actual_dat <= allowed_dat or BODY + 1 not in actual_dat:
        raise VerifyError("probe DAT changed outside its envelope")

    base_conflicts = active_bank_b_refs(base)
    out_refs = active_bank_b_refs(out)
    if base_conflicts:
        raise VerifyError(f"V354 already had live D1..EC E2 ids: {base_conflicts[:5]}")
    if out_refs != [(DAT, BODY, 0xD1)]:
        raise VerifyError(f"V355 Bank-B reference census mismatch: {out_refs}")

    expected_rows = list(csv.DictReader((ANALYSIS / "expected_writes.csv").open(encoding="utf-8-sig", newline="")))
    actual_rows = []
    for member in changed:
        for offset, (old, new) in enumerate(zip(base[member], out[member])):
            if old != new:
                actual_rows.append((member, f"0x{offset:X}", f"{old:02X}", f"{new:02X}"))
    recorded_rows = [(row["member"], row["file_offset"], row["before"], row["after"]) for row in expected_rows]
    if recorded_rows != actual_rows:
        raise VerifyError("expected-write ledger mismatch")

    result = {
        "status": "PASS",
        "runtime": "PENDING",
        "full_sha256": sha(full),
        "changed_members": changed,
        "actual_changed_bytes": {
            member: sum(a != b for a, b in zip(base[member], out[member])) for member in changed
        },
        "lookup_truth_table": "256/256",
        "completion_truth_table": "256/256",
        "load_delay_hazards": 0,
        "base_live_bank_b_conflicts": 0,
        "v355_live_bank_b_refs": 1,
        "additional_vram_bytes": 0,
        "runtime_acceptance": "cold boot, first dialogue identical, following dialogue proceeds",
    }
    (ANALYSIS / "independent_verification.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
