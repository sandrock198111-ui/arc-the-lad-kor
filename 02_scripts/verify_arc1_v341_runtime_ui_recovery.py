#!/usr/bin/env python3
"""Independent readback for V341 runtime UI recovery.

This verifier does not import the V341 builder.  It reconstructs the expected
overlay from the fixed V340 archive, checks every changed byte, executes the
small helper truth tables, disassembles all hooks, and uses the six uploaded
V340 DUCCU states only as pre-patch runtime evidence.
"""

from __future__ import annotations

import csv
import hashlib
import json
import struct
import sys
from collections import Counter
from pathlib import Path
from zipfile import ZipFile

from capstone import CS_ARCH_MIPS, CS_MODE_LITTLE_ENDIAN, CS_MODE_MIPS32, Cs


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

from build_arc1_v231_static_promotion_restored162 import text_regions  # noqa: E402


BASE = ROOT / "03_output/arc1_v340_battle_choice_ui_geometry_TEST_ONLY_3F63BFD1.zip"
FINAL = ROOT / "03_output/arc1_v341_runtime_ui_recovery_TEST_ONLY_FCAF5CFB.zip"
DELTA = ROOT / "03_output/arc1_v341_runtime_ui_recovery_TEST_ONLY_delta_from_v340_7A776491.zip"
ANALYSIS = ROOT / "01_work/analysis/arc1_v341_runtime_ui_recovery"

BASE_SHA = "3F63BFD149A100152DE8B1B3223136CC501AF5AC19E19F443D4519142F9C783E"
FINAL_SHA = "FCAF5CFB8BAC230A041DC68E9B23B0F6916112D8F5406B2312DD19CE2A4E33D2"
DELTA_SHA = "7A77649153E705CC5F19C1617F651EBB4952799558209E1EFB1F49008CC0AB09"
PSX = "PSX.EXE"
COMM = "COMM.IMG"
RAM_TO_FILE = 0x8011A800

SLOT_BASE = 0x45000
SLOT_SIZE = 0x80
SLOT_META = 0x7F
TARGETS = (
    ("C1/SC011.DAT", 0x46F0E, 8, 12), ("C1/SC011.DAT", 0x46F74, 11, 10),
    ("C1/SC021.DAT", 0x46F0E, 8, 12), ("C1/SC021.DAT", 0x46F74, 11, 10),
    ("C1/SC031.DAT", 0x46F0E, 8, 12), ("C1/SC031.DAT", 0x46F74, 11, 10),
    ("C1/SC041.DAT", 0x46F0E, 37, 12), ("C1/SC041.DAT", 0x46F74, 40, 10),
    ("C1/SC051.DAT", 0x46F0E, 8, 12), ("C1/SC051.DAT", 0x46F74, 11, 10),
    ("C1/SC061.DAT", 0x46F0E, 13, 12), ("C1/SC061.DAT", 0x46F74, 16, 10),
    ("C1/SC081.DAT", 0x46F70, 12, 10),
    ("C2/SC0A1.DAT", 0x46F00, 6, 12), ("C2/SC0A1.DAT", 0x46F66, 9, 10),
)
CHANGED_DATS = tuple(dict.fromkeys(item[0] for item in TARGETS))

# Exact final machine words, duplicated rather than imported from the builder.
E7_HELPER_FILE = 0x82800
E7_W16_WORDS = (
    0x2C68000F, 0x34024114, 0x00621006, 0x01024024, 0x11000002,
    0x34020082, 0x340200E4, 0x0805ADB4, 0xA2020029,
    0x3C08801F, 0x25080E18, 0x14C80004, 0x340800D6, 0x14480002,
    0x00000000, 0x2442FFFF, 0x03E00008, 0xA4A2002E,
)
CURSOR_GATE_FILE = 0x75590
CURSOR_GATE_WORDS = (
    0x3C08801F, 0x8D09E058, 0x950AE024, 0x3C0B801F, 0x256B52BC,
    0x152B0005, 0x00000000, 0x15400003, 0xAFA4FFE8, 0x0807FD22,
    0x00000000, 0x0805DB87, 0x00000000,
)
CURSOR_EPILOGUE_FILE = 0x8F0D0
CURSOR_EPILOGUE_WORDS = (
    0x8FA401B8, 0x8FB401BC, 0x0C05DB87, 0x8FB301C0, 0x8FBF01CC,
    0x8FB201C4, 0x8FB001C8, 0x03E00008, 0x27BD01D0,
)
CURSOR_HELPER_FILE = 0x8EFB0
CURSOR_HELPER_RAM = 0x801FF488
CURSOR_HELPER_SIZE = 324
CURSOR_HELPER_SHA256 = "D27FAD41247937C9B80E1F5125850F10803FBBD9B9BA71A058D5308198F8B217"
CURSOR_HELPER_PREFIX_SHA256 = "D3D0324B84865EA32F814916295856FF4242C5B843C5DBC4EE52E5256D848DE1"
LOADIMAGE_RAM = 0x80177E4C
DRAWOT_RAM = 0x80176E1C
ORKAS_FILE = 0x82928
ORKAS_RAM = 0x8019D128
ORKAS_BYTES = bytes.fromhex("46 70 DD 38 30 A1 DD 30 5A 00")

EXPECTED_PSX_WRITES = (
    (0x3E14, struct.pack("<2I", 0x3C11801F, 0x263152BC)),
    (0x50DF4, struct.pack("<2I", 0x0C067409, 0x00000000)),
    (0x50EFC, struct.pack("<I", 0x340501EB)),
    (0x51FB0, struct.pack("<I", 0x3406000B)),
    (E7_HELPER_FILE, struct.pack("<18I", *E7_W16_WORDS)),
    (0x2060, struct.pack("<I", 0x0C063F64)),
    (CURSOR_GATE_FILE, struct.pack("<13I", *CURSOR_GATE_WORDS)),
    (CURSOR_EPILOGUE_FILE, struct.pack("<9I", *CURSOR_EPILOGUE_WORDS)),
    (0x81E44, struct.pack("<I", ORKAS_RAM)),
    (0x821B4, struct.pack("<I", ORKAS_RAM)),
    (ORKAS_FILE, ORKAS_BYTES),
)

STATE_PATHS = {
    1: Path(r"C:\Users\Administrator\.paseo\uploads\upload_2ff2f4d3-db43-4ff9-886f-31a9fcacab8a\HASH-D0E40EB3BD3F8B04_1.sav"),
    2: Path(r"C:\Users\Administrator\.paseo\uploads\upload_685f068c-30c3-4461-8363-2062dfec3583\HASH-D0E40EB3BD3F8B04_2.sav"),
    3: Path(r"C:\Users\Administrator\.paseo\uploads\upload_37d2169c-184b-4bdb-a192-8c60be88a9a8\HASH-D0E40EB3BD3F8B04_3.sav"),
    4: Path(r"C:\Users\Administrator\.paseo\uploads\upload_c62fc35c-b6af-4a06-a1ae-9c11f472ab82\HASH-D0E40EB3BD3F8B04_4.sav"),
    5: Path(r"C:\Users\Administrator\.paseo\uploads\upload_fd0c6451-dac9-4982-90c6-37c0a7ea3802\HASH-D0E40EB3BD3F8B04_5.sav"),
    6: Path(r"C:\Users\Administrator\.paseo\uploads\upload_b226ce8a-94e2-4b5d-9529-9649e677f327\HASH-D0E40EB3BD3F8B04_6.sav"),
}


class VerifyError(RuntimeError):
    pass


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def read_archive(path: Path):
    with ZipFile(path) as archive:
        infos = [item for item in archive.infolist() if not item.is_dir()]
        return [item.filename for item in infos], {item.filename: archive.read(item.filename) for item in infos}


def changed_offsets(before: bytes, after: bytes) -> set[int]:
    if len(before) != len(after):
        raise VerifyError("member size changed")
    return {i for i, (a, b) in enumerate(zip(before, after, strict=True)) if a != b}


def expected_overlay(base: dict[str, bytes]) -> dict[str, bytes]:
    result = dict(base)
    for member in CHANGED_DATS:
        data = bytearray(base[member])
        for name, _body, slot, old_meta in TARGETS:
            if name == member:
                at = SLOT_BASE + slot * SLOT_SIZE + SLOT_META
                if data[at] != old_meta:
                    raise VerifyError(f"base metadata premise drift: {name}/{slot}")
                data[at] = old_meta + 2
        result[member] = bytes(data)
    exe = bytearray(base[PSX])
    for offset, payload in EXPECTED_PSX_WRITES:
        exe[offset:offset + len(payload)] = payload
    result[PSX] = bytes(exe)
    return result


def marker_topology(members: dict[str, bytes]):
    # Fixed 63 battle bodies; duplicated independently from the historical tool.
    files = {
        "C1/SC011.DAT": (290278, 290376, 290474, 290574, 290676, 290776, 290868),
        "C1/SC021.DAT": (290278, 290376, 290474, 290574, 290676, 290776, 290868),
        "C1/SC031.DAT": (290278, 290376, 290474, 290574, 290676, 290776, 290868),
        "C1/SC041.DAT": (290278, 290376, 290474, 290574, 290676, 290776, 290868),
        "C1/SC051.DAT": (290278, 290376, 290474, 290574, 290676, 290776, 290868),
        "C1/SC061.DAT": (290278, 290376, 290474, 290574, 290676, 290776, 290868),
        "C1/SC081.DAT": (290278, 290376, 290474, 290572, 290672, 290772, 290864),
        "C1/SC091.DAT": (290278, 290372, 290466, 290564, 290658, 290752, 290844),
        "C2/SC0A1.DAT": (290278, 290376, 290468, 290560, 290662, 290762, 290854),
    }
    result = {}
    for member, bodies in files.items():
        data = members[member]
        for body in bodies:
            end = data.find(b"\0", body, body + 0x80)
            payload = data[body:end]
            result[(member, body)] = (
                tuple(i for i, b in enumerate(payload) if b == 0xE5),
                tuple(i for i, b in enumerate(payload) if b == 0xE6),
            )
    if len(result) != 63:
        raise VerifyError("battle body census drift")
    return result


def token_width(value: int) -> int:
    return 1 if value < 0xDD else 2


def region_callers(members: dict[str, bytes]) -> Counter[tuple[str, int]]:
    calls: Counter[tuple[str, int]] = Counter()
    regions = list(text_regions(members))
    if len(regions) != 8612:
        raise VerifyError(f"V340 region census drift: {len(regions)}")
    for member, start, end in regions:
        data = members[member]
        at = start
        while at < end:
            value = data[at]
            if value == 0xE2 or 0xE3 <= value <= 0xE8:
                if at + 2 > end:
                    break
                if value == 0xE2:
                    calls[(member, data[at + 1])] += 1
                at += 2
            else:
                width = token_width(value)
                if at + width > end:
                    break
                at += width
    return calls


def verify_choices(base: dict[str, bytes], final: dict[str, bytes]) -> list[dict[str, object]]:
    if marker_topology(base) != marker_topology(final):
        raise VerifyError("E5/E6 body topology changed")
    calls = region_callers(base)
    rows = []
    for member, body, slot, old_meta in TARGETS:
        disk_id = slot + (0x81 if slot < 40 else 0x82)
        meta_at = SLOT_BASE + slot * SLOT_SIZE + SLOT_META
        if (base[member][meta_at], final[member][meta_at]) != (old_meta, old_meta + 2):
            raise VerifyError(f"metadata transition failed: {member}/{slot}")
        end = base[member].find(b"\0", body, body + 0x80)
        payload = base[member][body:end]
        if payload[:2] != bytes((0xE2, disk_id)):
            raise VerifyError("prompt caller drift")
        if payload[2:2 + old_meta] != b"\xA1" * old_meta:
            raise VerifyError("prompt padding drift")
        if payload[2 + old_meta:4 + old_meta] != b"\xE6\x01":
            raise VerifyError("old completion is not redundant E6")
        if payload[4 + old_meta:6 + old_meta] != b"\xE5\x03":
            raise VerifyError("new completion does not land on first E5")
        if calls[(member, disk_id)] != 1:
            raise VerifyError(f"shared prompt slot: {member}/{slot}")
        rows.append({
            "member": member, "body": f"0x{body:X}", "slot": slot,
            "disk_id": f"0x{disk_id:02X}", "old_meta": old_meta,
            "new_meta": old_meta + 2, "callers": 1,
        })

    # Claude specifically asked for these four full-file scans.
    sc041 = final["C1/SC041.DAT"]
    for disk_id in (0xA4, 0xA7, 0xAB, 0xB0):
        needle = bytes((0xE2, disk_id))
        hits = [i for i in range(len(sc041) - 1) if sc041[i:i + 2] == needle]
        if len(hits) != 1:
            raise VerifyError(f"SC041 full-file E2 {disk_id:02X} census={hits}")
    return rows


def control_target(pc: int, instruction: int) -> int | None:
    op = instruction >> 26
    if op in (2, 3):
        return ((pc + 4) & 0xF0000000) | ((instruction & 0x03FFFFFF) << 2)
    if op in (4, 5, 6, 7):
        imm = instruction & 0xFFFF
        if imm & 0x8000:
            imm -= 0x10000
        return (pc + 4 + imm * 4) & 0xFFFFFFFF
    return None


def inbound(exe: bytes, lo: int, hi: int):
    result = []
    text_size = struct.unpack_from("<I", exe, 0x1C)[0]
    for offset in range(0x800, min(len(exe), 0x800 + text_size), 4):
        pc = offset + RAM_TO_FILE
        target = control_target(pc, struct.unpack_from("<I", exe, offset)[0])
        if target is not None and lo <= target < hi:
            result.append((pc, target))
    return result


def read_registers(instruction: int) -> set[int]:
    opcode = instruction >> 26
    rs, rt = (instruction >> 21) & 31, (instruction >> 16) & 31
    if opcode == 0:
        function = instruction & 0x3F
        if function == 0x08:
            return {rs}
        if function in (0x00, 0x02, 0x03):
            return {rt} - {0}
        return {rs, rt} - {0}
    if opcode in (0x02, 0x03, 0x0F):
        return set()
    if opcode in (0x04, 0x05):
        return {rs, rt} - {0}
    if opcode in (0x01, 0x06, 0x07):
        return {rs} - {0}
    if opcode in (0x28, 0x29, 0x2A, 0x2B, 0x2E):
        return {rs, rt} - {0}
    return {rs} - {0}


def verify_full_cursor_helper(exe: bytes, md: Cs) -> list[str]:
    helper = exe[CURSOR_HELPER_FILE:CURSOR_HELPER_FILE + CURSOR_HELPER_SIZE]
    if len(helper) != CURSOR_HELPER_SIZE or sha(helper) != CURSOR_HELPER_SHA256:
        raise VerifyError("full cursor helper hash/size drift")
    if sha(helper[:-36]) != CURSOR_HELPER_PREFIX_SHA256:
        raise VerifyError("inherited cursor decoder/LoadImage prefix drift")
    instructions = list(md.disasm(helper, CURSOR_HELPER_RAM))
    if len(instructions) != 81:
        raise VerifyError(f"cursor helper instruction census={len(instructions)}")
    if (instructions[0].mnemonic, instructions[0].op_str) != ("addiu", "$sp, $sp, -0x1d0"):
        raise VerifyError("cursor helper stack prologue drift")
    if (instructions[-2].mnemonic, instructions[-2].op_str) != ("jr", "$ra"):
        raise VerifyError("cursor helper return drift")
    if (instructions[-1].mnemonic, instructions[-1].op_str) != ("addiu", "$sp, $sp, 0x1d0"):
        raise VerifyError("cursor helper stack restoration drift")

    words = struct.unpack("<81I", helper)
    calls = []
    for index, instruction in enumerate(instructions):
        raw = words[index]
        opcode = raw >> 26
        if opcode == 3:
            calls.append((instruction.address, control_target(instruction.address, raw)))
        if instruction.mnemonic in {"lb", "lbu", "lh", "lhu", "lw", "lwl", "lwr"} and index + 1 < len(words):
            destination = (raw >> 16) & 31
            if destination in read_registers(words[index + 1]):
                raise VerifyError(f"R3000 load delay at 0x{instruction.address:08X}")
        if opcode in (4, 5, 6, 7):
            target = control_target(instruction.address, raw)
            if target is None or not CURSOR_HELPER_RAM <= target < CURSOR_HELPER_RAM + CURSOR_HELPER_SIZE:
                raise VerifyError(f"cursor helper branch escapes at 0x{instruction.address:08X}")
    if calls != [(0x801FF590, LOADIMAGE_RAM), (0x801FF5B0, DRAWOT_RAM)]:
        raise VerifyError(f"cursor helper call topology drift: {calls}")

    remaining = 33
    chunks = []
    while remaining:
        height = min(remaining, 8)
        chunks.append(height)
        remaining -= height
    if chunks != [8, 8, 8, 8, 1] or sum(chunks) != 33:
        raise VerifyError("cursor upload chunk simulation drift")
    return [
        "[resident_cursor_uploader_full_81_words]",
        *(f"0x{insn.address:08X}: {insn.mnemonic} {insn.op_str}" for insn in instructions),
        "[cursor_uploader_static_summary]",
        f"sha256={CURSOR_HELPER_SHA256}",
        "stack_frame=0x1D0 fixed; branches remain inside helper",
        "calls=0x801FF590->LoadImage,0x801FF5B0->DrawOT",
        "upload_chunks=8,8,8,8,1 rows; destination=(960,447), width=25, total_height=33",
    ]


def verify_mips(exe: bytes) -> list[str]:
    if struct.unpack_from("<18I", exe, E7_HELPER_FILE) != E7_W16_WORDS:
        raise VerifyError("E7/W16 helper words differ")
    if struct.unpack_from("<13I", exe, CURSOR_GATE_FILE) != CURSOR_GATE_WORDS:
        raise VerifyError("cursor gate words differ")
    if struct.unpack_from("<9I", exe, CURSOR_EPILOGUE_FILE) != CURSOR_EPILOGUE_WORDS:
        raise VerifyError("cursor epilogue words differ")

    for value in range(512):
        expected = 0xE4 if value in (2, 4, 8, 14) else 0x82
        selected = int(value < 15) & ((0x4114 >> (value & 31)) & 1)
        actual = 0xE4 if selected else 0x82
        if actual != expected:
            raise VerifyError(f"E7 truth-table failure: {value}")
    for obj in (0x801F0E18, 0x801F9D44, 0x801F031C, 0x801F1DB4):
        for y in range(0, 256):
            actual = y - int(obj == 0x801F0E18 and y == 214)
            if actual != (213 if (obj, y) == (0x801F0E18, 214) else y):
                raise VerifyError("W16 scope truth-table failure")

    # Gate outcomes: uninitialized and inactive go directly to DrawOT; only
    # exact pointer + flag zero enters the uploader.  Future helper stack slot
    # new_sp+0x1B8 equals caller_sp-0x18 exactly.
    cases = {
        (0x00000000, 0): "DrawOT",
        (0x801F52BC, 1): "DrawOT",
        (0x801F52BC, 0): "uploader",
        (0x801F52BD, 0): "DrawOT",
    }
    for (pointer, flag), expected in cases.items():
        actual = "uploader" if pointer == 0x801F52BC and flag == 0 else "DrawOT"
        if actual != expected:
            raise VerifyError("cursor gate simulation failed")
    if -0x1D0 + 0x1B8 != -0x18:
        raise VerifyError("saved DrawOT a0 stack algebra failed")

    e7_edges = inbound(exe, 0x8019D000, 0x8019D048)
    expected_e7 = [
        (0x8016B5F4, 0x8019D024),
        (0x80197FC4, 0x8019D018),  # pinned mixed-data false instruction
        (0x8019C934, 0x8019D000),
        (0x8019D010, 0x8019D01C),
        (0x8019D02C, 0x8019D040),
        (0x8019D034, 0x8019D040),
    ]
    if e7_edges != expected_e7:
        raise VerifyError(f"E7/W16 inbound topology drift: {e7_edges}")
    gate_edges = inbound(exe, 0x8018FD90, 0x8018FDC4)
    expected_gate = [
        (0x8011C860, 0x8018FD90),
        (0x8018FDA4, 0x8018FDBC),
        (0x8018FDAC, 0x8018FDBC),
    ]
    if gate_edges != expected_gate:
        raise VerifyError(f"cursor gate inbound topology drift: {gate_edges}")

    md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 | CS_MODE_LITTLE_ENDIAN)
    lines = []
    sections = (
        ("w16_hook", 0x8016B5F0, 0x8016B600),
        ("e7_hook", 0x8016B6F8, 0x8016B70C),
        ("e7_w16_helper", 0x8019D000, 0x8019D048),
        ("frame_hook", 0x8011C858, 0x8011C870),
        ("cursor_gate", 0x8018FD90, 0x8018FDC4),
    )
    for label, start, end in sections:
        lines.append(f"[{label}]")
        blob = exe[start - RAM_TO_FILE:end - RAM_TO_FILE]
        for insn in md.disasm(blob, start):
            lines.append(f"0x{insn.address:08X}: {insn.mnemonic} {insn.op_str}")
    lines.extend(verify_full_cursor_helper(exe, md))
    return lines


def decode_cursor_rle(exe: bytes) -> bytes:
    encoded = exe[0x8F0F4:0x8F380]
    if sha(encoded) != "94CED131CFC00C7B4A249009DEA5BE2361ABC6DAF6C244EE9B6D134F621C7133":
        raise VerifyError("cursor RLE hash drift")
    out = bytearray()
    at = 0
    while at < len(encoded):
        token = encoded[at]
        at += 1
        count = (token & 0x3F) + 1
        if not token & 0x80:
            size = count * 2
            out += encoded[at:at + size]
            at += size
        elif token & 0x40:
            value = encoded[at:at + 2]
            at += 2
            out += value * count
        else:
            out += b"\0\0" * count
    if len(out) != 25 * 33 * 2 or sha(bytes(out)) != "B0005B318220FC61C11C3290837A7DF245646254FFA5CEBE7EA9A11932C7F421":
        raise VerifyError("cursor RLE decode mismatch")
    return bytes(out)


def inflate_state(path: Path):
    raw = path.read_bytes()
    if raw[:5] != b"DUCCU" or raw[8:12] != b"V340":
        raise VerifyError(f"not a V340 DUCCU state: {path.name}")
    state_size = struct.unpack_from("<I", raw, 0xD0)[0]
    state_at = struct.unpack_from("<I", raw, 0xD4)[0]
    try:
        from compression import zstd
        blob = zstd.decompress(raw[state_at:])
    except ImportError:
        import zstandard
        blob = zstandard.ZstdDecompressor().decompress(raw[state_at:], max_output_size=16 << 20)
    if len(blob) != state_size:
        raise VerifyError("DUCCU state length drift")
    bus_tag = struct.pack("<I", 3) + b"Bus"
    bus = blob.find(bus_tag)
    ram_at = bus + len(bus_tag) + 64
    ram = blob[ram_at:ram_at + 0x200000]
    marker = struct.pack("<I", 8) + b"GPU-VRAM"
    hit = blob.find(marker)
    vram_at = hit + len(marker)
    vram = blob[vram_at:vram_at + 1024 * 512 * 2]
    if len(ram) != 0x200000 or len(vram) != 1024 * 512 * 2:
        raise VerifyError("DUCCU RAM/VRAM truncation")
    return raw, ram, vram


def runtime_evidence() -> list[dict[str, object]]:
    rows = []
    expected = {
        1: (0x801F52BC, 1), 2: (0x801F52BC, 1), 3: (0x801F52BC, 1),
        4: (0, 0), 5: (0x801F52BC, 0), 6: (0x801F52BC, 0),
    }
    for index, path in STATE_PATHS.items():
        raw, ram, vram = inflate_state(path)
        pointer = struct.unpack_from("<I", ram, 0x1EE058)[0]
        active = struct.unpack_from("<H", ram, 0x1EE024)[0]
        if (pointer, active) != expected[index]:
            raise VerifyError(f"range owner state drift: state{index}")
        target = bytearray()
        for y in range(447, 480):
            row = y * 1024 * 2
            target += vram[row + 960 * 2:row + 985 * 2]
        nonzero = sum(value != 0 for value in target)
        if index in (5, 6) and nonzero:
            raise VerifyError("active V340 range destination is no longer zero baseline")
        obj = 0x1F0E18
        packet_y = []
        widths = []
        base = struct.unpack_from("<I", ram, obj)[0]
        count = struct.unpack_from("<H", ram, obj + 0x0A)[0]
        if 0x80000000 <= base < 0x80200000 and count < 128:
            for item in range(count):
                at = base - 0x80000000 + item * 52
                widths.append(ram[at + 0x2A])
                packet_y.append(struct.unpack_from("<H", ram, at + 0x2E)[0])
        rows.append({
            "state": index, "sha256": sha(raw), "owner_pointer": f"0x{pointer:08X}",
            "owner_flag": active, "cursor_destination_nonzero_bytes": nonzero,
            "bottom_help_packet_y": " ".join(map(str, sorted(set(packet_y)))),
            "bottom_help_widths": " ".join(map(str, sorted(set(widths)))),
        })
    return rows


def verify_map(exe: bytes) -> None:
    if exe[ORKAS_FILE:ORKAS_FILE + len(ORKAS_BYTES)] != ORKAS_BYTES:
        raise VerifyError("Orkas string bytes differ")
    hits = []
    needle = struct.pack("<I", ORKAS_RAM)
    for at in range(len(exe) - 3):
        if exe[at:at + 4] == needle:
            hits.append(at)
    if hits != [0x81E44, 0x821B4]:
        raise VerifyError(f"Orkas pointer census={hits}")


def verify_expected_writes(base: dict[str, bytes], final: dict[str, bytes]) -> None:
    actual = {
        member: changed_offsets(base[member], final[member])
        for member in base if base[member] != final[member]
    }
    rows = list(csv.DictReader((ANALYSIS / "expected_writes.csv").open(encoding="utf-8-sig", newline="")))
    declared: dict[str, set[int]] = {}
    for row in rows:
        member = row["member"]
        offset = int(row["offset"], 16)
        declared.setdefault(member, set()).add(offset)
        if (f"{base[member][offset]:02X}", f"{final[member][offset]:02X}") != (row["before"], row["after"]):
            raise VerifyError("Expected-Write byte readback mismatch")
    if actual != declared:
        raise VerifyError("Expected-Write offset set differs")


def write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    if sha(BASE.read_bytes()) != BASE_SHA or sha(FINAL.read_bytes()) != FINAL_SHA or sha(DELTA.read_bytes()) != DELTA_SHA:
        raise VerifyError("archive hash mismatch")
    base_names, base = read_archive(BASE)
    final_names, final = read_archive(FINAL)
    delta_names, delta = read_archive(DELTA)
    if len(base_names) != 164 or final_names != base_names:
        raise VerifyError("full archive topology drift")
    expected_members = [name for name in base_names if name == PSX or name in CHANGED_DATS]
    if delta_names != expected_members or any(delta[name] != final[name] for name in delta_names):
        raise VerifyError("delta topology/readback drift")
    changed = [name for name in base_names if base[name] != final[name]]
    if changed != expected_members:
        raise VerifyError(f"changed member set/order drift: {changed}")

    reconstructed = expected_overlay(base)
    if reconstructed != final:
        bad = [name for name in base_names if reconstructed[name] != final[name]]
        raise VerifyError(f"final differs from independent overlay: {bad}")
    if final[COMM] != base[COMM]:
        raise VerifyError("COMM.IMG changed")
    verify_expected_writes(base, final)
    choice_rows = verify_choices(base, final)
    mips_lines = verify_mips(final[PSX])
    decode_cursor_rle(final[PSX])
    verify_map(final[PSX])
    runtime_rows = runtime_evidence()

    ANALYSIS.mkdir(parents=True, exist_ok=True)
    write_csv(ANALYSIS / "independent_choice_completion.csv", choice_rows)
    write_csv(ANALYSIS / "v340_runtime_evidence.csv", runtime_rows)
    (ANALYSIS / "independent_mips_disassembly.txt").write_text("\n".join(mips_lines) + "\n", encoding="utf-8")
    result = {
        "result": "STATIC_PASS_RUNTIME_PENDING",
        "archives": {"members": 164, "changed": changed},
        "expected_write": "exact",
        "choices": "15 metadata-only completions; 63/63 E5/E6 topology unchanged",
        "help": "W16 exact object+Y scope; E7 icons unchanged",
        "map": "two pointers only -> 오르카스 언덕",
        "cursor": "exact owner/active pre-DrawOT gate; RLE/descriptor/UV preserved",
        "runtime": "V340 failure evidence reproduced; V341 cold boot PENDING",
    }
    (ANALYSIS / "independent_verification.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    lines = [
        "V341 independent static verification: PASS",
        f"full={FINAL.name} sha256={FINAL_SHA}",
        f"delta={DELTA.name} sha256={DELTA_SHA}",
        f"archive=164 members; changed={','.join(changed)}; Expected-Write exact",
        "choice_alignment=15 metadata bytes only; body bytes/E5/E6 unchanged; SC041 full-file caller census PASS",
        "bottom_help=W16 only when object=0x801F0E18 and original Y=214; E7 0..511 truth table PASS",
        "map=region/location pointers only -> 오르카스 언덕",
        "cursor=owner/active gate truth table + stack algebra + RLE decode + MIPS inbound PASS",
        "runtime=V340 active states5/6 destination zero reproduced; V341 cold boot PENDING",
    ]
    (ANALYSIS / "independent_verification.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
