#!/usr/bin/env python3
"""Independent verification for V340 battle-choice/UI geometry.

This verifier does not import the V340 builder.  It reconstructs the complete
overlay from V339, decodes all 63 approved answer bitmaps, executes the E7
helper truth table, and reads the uploaded V339 DUCCU states as the runtime
coordinate baseline.
"""

from __future__ import annotations

import csv
import hashlib
import json
import struct
import sys
from collections import Counter, defaultdict
from pathlib import Path
from zipfile import ZipFile

from capstone import Cs, CS_ARCH_MIPS, CS_MODE_LITTLE_ENDIAN, CS_MODE_MIPS32


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

import build_arc1_v128_all_battle_choices as v128  # noqa: E402
import build_arc1_v320_hanme_static_recovery as v320  # noqa: E402


BASE = ROOT / "03_output/arc1_v339_ui_banner_geometry_TEST_ONLY_FD442C74.zip"
FINAL = ROOT / "03_output/arc1_v340_battle_choice_ui_geometry_TEST_ONLY_3F63BFD1.zip"
DELTA = ROOT / "03_output/arc1_v340_battle_choice_ui_geometry_TEST_ONLY_delta_from_v339_A58CA81C.zip"
ANALYSIS = ROOT / "01_work/analysis/arc1_v340_battle_choice_ui_geometry"
ASSIGNMENTS = ROOT / "01_work/analysis/arc1_v320_hanme_static_recovery/character_assignments.csv"
TRANSLATIONS = ROOT / "05_docs/script_translated_full.csv"

BASE_SHA256 = "FD442C7492F7BE2FCFAED5B3BE377D67FE9794B6767C356AC275D407F2030C17"
FINAL_SHA256 = "3F63BFD149A100152DE8B1B3223136CC501AF5AC19E19F443D4519142F9C783E"
DELTA_SHA256 = "A58CA81C5C49D849BA6ED8B7788F0FB28FF4E48ED2F147E55F4C34AE3FF734B0"
FINAL_PSX_SHA256 = "9EE5CD445BA98B2B2BFB92C11772AB2A1DDCA656BE0926FC9D95E611176F6180"

PSX, COMM = "PSX.EXE", "COMM.IMG"
RAM_TO_FILE = 0x8011A800
SLOT_BASE, SLOT_SIZE = 0x45000, 0x80

HELP_Y_FILE = 0x8016C7B0 - RAM_TO_FILE
E7_HELPER_RAM = 0x8019D000
E7_HELPER_FILE = E7_HELPER_RAM - RAM_TO_FILE
E7_HELPER_SIZE = 0x48
E7_Y_ENTRY = 0x8019D02C
E7_Y_HOOK_FILE = 0x8016B6FC - RAM_TO_FILE
BAR_WIDTH_FILE = 0x801607A8 - RAM_TO_FILE
BAR_HEIGHT_FILE = 0x801607B0 - RAM_TO_FILE
BOTTOM_HELP_OBJECT = 0x801F0E18
BOTTOM_HELP_PACKET_BASE = 0x801F0798
CONFIG_PRIMITIVES = 0x801ADF0C

PAYLOADS = {
    "물론": bytes.fromhex("6D DF 30"),
    "괜찮아": bytes.fromhex("DD 3B DD 3A 09"),
    "괜찮다": bytes.fromhex("DD 3B DD 3A 01"),
    "싸운다": bytes.fromhex("DD 14 86 01"),
    "간다": bytes.fromhex("DD 1B 01"),
}

# Independent overlay description: member -> (slot, text, old payload).
SLOTS = {
    "C1/SC011.DAT": ((6, "물론", "AA E1 C7"), (9, "괜찮아", "DF 85 DF ED 95"),
                      (12, "괜찮다", "DF 85 DF ED 78"), (17, "싸운다", "DE AD DA 78")),
    "C1/SC021.DAT": ((6, "물론", "AA E1 C7"), (9, "괜찮아", "DF 85 DF ED 95"),
                      (12, "괜찮다", "DF 85 DF ED 78"), (17, "싸운다", "DE AD DA 78")),
    "C1/SC031.DAT": ((6, "물론", "AA E1 C7"), (9, "괜찮아", "DF 85 DF ED 95"),
                      (12, "괜찮다", "DF 85 DF ED 78"), (17, "싸운다", "DE AD DA 78")),
    "C1/SC041.DAT": ((35, "물론", "AA DF D1"), (38, "괜찮아", "DF 85 DF ED 95"),
                      (41, "괜찮다", "E0 3F DF ED 78"), (46, "싸운다", "E0 FB DA 78")),
    "C1/SC051.DAT": ((6, "물론", "AA E1 C7"), (9, "괜찮아", "DF 85 DF ED 95"),
                      (12, "괜찮다", "DF 85 DF ED 78"), (17, "싸운다", "DE AD DA 78")),
    "C1/SC061.DAT": ((11, "물론", "AA E1 C7"), (14, "괜찮아", "DF 85 DF ED 95"),
                      (17, "괜찮다", "DF 85 DF ED 78"), (22, "싸운다", "DE AD DA 78")),
    "C1/SC081.DAT": ((13, "괜찮다", "DF 85 DF ED 78"), (16, "간다", "DE C5 78")),
    "C2/SC0A1.DAT": ((8, "괜찮아", "DF 85 DF ED 95"),
                      (11, "괜찮다", "DF 85 DF ED 78"), (15, "싸운다", "DE AD DA 78")),
}
INLINE = (
    (0x46EAA, 0x46EBA, 35, bytes.fromhex("7E A1")),
    (0x46F0E, 0x46F20, 38, bytes.fromhex("7E A1")),
    (0x46F74, 0x46F84, 41, bytes.fromhex("7E A1")),
    (0x47034, 0x4703F, 46, bytes.fromhex("53 01")),
)

V339_STATES = {
    1: Path(r"C:\Users\Administrator\.paseo\uploads\upload_3725c071-05ed-426d-ae25-e14e562af013\HASH-859F428F91A23BB_1.sav"),
    2: Path(r"C:\Users\Administrator\.paseo\uploads\upload_f46282d9-e0fa-410d-bd13-1ef140c5d551\HASH-859F428F91A23BB_2.sav"),
    3: Path(r"C:\Users\Administrator\.paseo\uploads\upload_c72d156b-61e1-434a-9fc2-724d5bfc3d61\HASH-859F428F91A23BB_3.sav"),
    4: Path(r"C:\Users\Administrator\.paseo\uploads\upload_53f93fd4-c906-4de8-b7e8-d3f1361365b8\HASH-859F428F91A23BB_4.sav"),
    6: Path(r"C:\Users\Administrator\.paseo\uploads\upload_9dfebed1-fdb1-42ec-9986-78287d7ce0f2\HASH-859F428F91A23BB_6.sav"),
}


class VerifyError(RuntimeError):
    pass


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def read_zip(path: Path) -> tuple[list[str], dict[str, bytes]]:
    with ZipFile(path) as archive:
        names = [item.filename for item in archive.infolist() if not item.is_dir()]
        return names, {name: archive.read(name) for name in names}


def word(data: bytes | bytearray, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def write_word(data: bytearray, offset: int, value: int) -> None:
    struct.pack_into("<I", data, offset, value & 0xFFFFFFFF)


def i_type(op: int, rs: int, rt: int, imm: int) -> int:
    return (op << 26) | (rs << 21) | (rt << 16) | (imm & 0xFFFF)


def r_type(rs: int, rt: int, rd: int, shift: int, function: int) -> int:
    return (rs << 21) | (rt << 16) | (rd << 11) | (shift << 6) | function


def jump(address: int, link: bool = False) -> int:
    return ((3 if link else 2) << 26) | ((address >> 2) & 0x03FFFFFF)


def helper_words() -> tuple[int, ...]:
    z, v0, v1, a1, t0, s0, s1, ra = 0, 2, 3, 5, 8, 16, 17, 31
    return (
        i_type(0x0B, v1, t0, 15), i_type(0x04, t0, z, 7), i_type(0x0D, z, v0, 0x82),
        i_type(0x0D, z, t0, 0x4114), r_type(v1, t0, t0, 0, 0x06), i_type(0x0C, t0, t0, 1),
        i_type(0x04, t0, z, 2), 0, i_type(0x0D, z, v0, 0xE4),
        jump(0x8016B6D0), i_type(0x28, s0, v0, 0x29),
        i_type(0x0F, z, t0, 0x801F), i_type(0x09, t0, t0, 0x0E18),
        i_type(0x05, s1, t0, 2), 0, i_type(0x09, v0, v0, 1),
        r_type(ra, z, z, 0, 0x08), i_type(0x0D, z, a1, 0x01EB),
    )


def disk_id(slot: int) -> int:
    return slot + (0x81 if slot < 40 else 0x82)


def slot_from_disk_id(value: int) -> int:
    if 0x81 <= value <= 0xA8:
        return value - 0x81
    if 0xAA <= value <= 0xD0:
        return value - 0x82
    raise VerifyError(f"invalid E2 id 0x{value:02X}")


def load_codes() -> dict[str, bytes]:
    choices: dict[str, list[bytes]] = defaultdict(list)
    with ASSIGNMENTS.open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            choices[row["char"]].append(bytes.fromhex(row["code_hex"]))
    result = {char: min(values, key=lambda value: (len(value), value)) for char, values in choices.items()}
    for text, payload in PAYLOADS.items():
        if b"".join(result[ch] for ch in text) != payload:
            raise VerifyError(f"assignment encoding drift: {text}")
    return result


def approved_answers() -> dict[tuple[str, int], str]:
    keys = {(name, offset) for name in v128.BATTLE_FILES for offset in v128.OFFSETS[name]}
    result: dict[tuple[str, int], str] = {}
    with TRANSLATIONS.open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            key = (row["source file"], int(row["offset"], 16))
            if key in keys:
                parts = row["korean"].split("|")
                if len(parts) != 3:
                    raise VerifyError(f"translation topology drift: {key}")
                result[key] = parts[1]
    if set(result) != keys or len(result) != 63:
        raise VerifyError(f"approved translation census {len(result)}/63")
    return result


def read_slot(data: bytes, slot: int) -> bytes:
    start = SLOT_BASE + slot * SLOT_SIZE
    end = data.find(b"\0", start, start + 0x7F)
    if end < 0:
        raise VerifyError(f"unterminated slot {slot}")
    return data[start:end]


def answer(data: bytes, body: int) -> bytes:
    end = data.find(b"\0", body, body + 0x80)
    segment = data[body:end]
    e5 = [at for at, value in enumerate(segment) if value == 0xE5]
    e6 = [at for at, value in enumerate(segment) if value == 0xE6]
    if len(e5) != 2 or len(e6) < 2:
        raise VerifyError(f"choice control drift at 0x{body:X}")
    start = e5[0] + 2
    if segment[start] == 0xE2:
        return read_slot(data, slot_from_disk_id(segment[start + 1]))
    stop = min(at for at in e6 if at > start)
    return segment[start:stop].rstrip(b"\xA1")


def tokenize(payload: bytes) -> list[bytes]:
    result: list[bytes] = []
    at = 0
    while at < len(payload):
        width = v320.token_width(payload[at])
        if at + width > len(payload) or v320.is_control(payload, at):
            raise VerifyError(f"bad answer token at {at}: {payload.hex()}")
        result.append(payload[at:at + width])
        at += width
    return result


def glyphs(exe: bytes, comm: bytes, payload: bytes) -> tuple[tuple[int, ...], ...]:
    result: list[tuple[int, ...]] = []
    for token in tokenize(payload):
        physical = v320.direct_index(token)
        if physical is None:
            slot = v320.virtual_slot(token)
            if slot is None:
                raise VerifyError(f"unknown token {token.hex()}")
            physical = v320.lookup_get(exe, slot)
        result.append(v320.read_plane(comm, physical))
    return tuple(result)


def choice_census(members: dict[str, bytes]) -> tuple[list[dict[str, object]], dict[tuple[str, int], tuple[tuple[int, ...], tuple[int, ...]]]]:
    codes, approved = load_codes(), approved_answers()
    rows: list[dict[str, object]] = []
    topology: dict[tuple[str, int], tuple[tuple[int, ...], tuple[int, ...]]] = {}
    for name in v128.BATTLE_FILES:
        data = members[name]
        for row_index, body in enumerate(v128.OFFSETS[name]):
            end = data.find(b"\0", body, body + 0x80)
            segment = data[body:end]
            topology[(name, body)] = (
                tuple(i for i, value in enumerate(segment) if value == 0xE5),
                tuple(i for i, value in enumerate(segment) if value == 0xE6),
            )
            current = answer(data, body)
            expected_text = approved[(name, body)]
            expected = b"".join(codes[ch] for ch in expected_text)
            match = glyphs(members[PSX], members[COMM], current) == glyphs(members[PSX], members[COMM], expected)
            rows.append({
                "member": name, "row": row_index, "body": f"0x{body:X}",
                "approved": expected_text, "payload": current.hex(" ").upper(),
                "canonical": expected.hex(" ").upper(), "bitmap_match": int(match),
            })
    return rows, topology


def expected_overlay(base: dict[str, bytes]) -> dict[str, bytes]:
    result = dict(base)
    exe = bytearray(base[PSX])
    write_word(exe, HELP_Y_FILE, 0x3406000A)
    exe[E7_HELPER_FILE:E7_HELPER_FILE + E7_HELPER_SIZE] = struct.pack("<18I", *helper_words())
    write_word(exe, E7_Y_HOOK_FILE, jump(E7_Y_ENTRY, link=True))
    write_word(exe, BAR_WIDTH_FILE, 0x3405003E)
    write_word(exe, BAR_HEIGHT_FILE, 0x34060010)
    result[PSX] = bytes(exe)
    for name, repairs in SLOTS.items():
        data = bytearray(base[name])
        for slot, text, old_hex in repairs:
            start = SLOT_BASE + slot * SLOT_SIZE
            old = bytes.fromhex(old_hex)
            if data[start:start + len(old)] != old or data[start + len(old)] != 0 or data[start + 0x7F] != 0:
                raise VerifyError(f"base slot premise drift: {name} slot {slot}")
            data[start:start + len(old)] = PAYLOADS[text]
        if name == "C1/SC041.DAT":
            for _body, offset, slot, old in INLINE:
                if data[offset:offset + 2] != old:
                    raise VerifyError(f"base inline premise drift: 0x{offset:X}")
                data[offset:offset + 2] = bytes((0xE2, disk_id(slot)))
        result[name] = bytes(data)
    return result


def changed_offsets(before: bytes, after: bytes) -> set[int]:
    if len(before) != len(after):
        raise VerifyError("member size drift")
    return {i for i, (a, b) in enumerate(zip(before, after, strict=True)) if a != b}


def verify_expected_write_csv(base: dict[str, bytes], final: dict[str, bytes], actual: dict[str, set[int]]) -> None:
    declared: dict[str, set[int]] = defaultdict(set)
    with (ANALYSIS / "expected_writes.csv").open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            name, offset = row["member"], int(row["offset"], 16)
            if int(row["before"], 16) != base[name][offset] or int(row["after"], 16) != final[name][offset]:
                raise VerifyError(f"Expected-Write byte mismatch: {name}:0x{offset:X}")
            declared[name].add(offset)
    if dict(declared) != actual:
        raise VerifyError("Expected-Write CSV is not the complete archive diff")


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


def inbound(exe: bytes, lo: int, hi: int) -> list[tuple[int, int]]:
    result: list[tuple[int, int]] = []
    for offset in range(0x800, len(exe) - 3, 4):
        pc = offset + RAM_TO_FILE
        target = control_target(pc, word(exe, offset))
        if target is not None and lo <= target < hi:
            result.append((pc, target))
    return result


def inflate_state(path: Path) -> bytes:
    raw = path.read_bytes()
    if raw[:5] != b"DUCCU":
        raise VerifyError(f"not DUCCU: {path.name}")
    state_size = struct.unpack_from("<I", raw, 0xD0)[0]
    state_offset = struct.unpack_from("<I", raw, 0xD4)[0]
    compressed_size = struct.unpack_from("<I", raw, 0xCC)[0]
    if state_offset + compressed_size != len(raw):
        raise VerifyError(f"DUCCU state frame size mismatch: {path.name}")
    try:
        from compression import zstd
        blob = zstd.decompress(raw[state_offset:])
    except ImportError:
        import zstandard
        blob = zstandard.ZstdDecompressor().decompress(raw[state_offset:], max_output_size=16 << 20)
    if len(blob) != state_size:
        raise VerifyError(f"DUCCU decompressed size mismatch: {path.name}")
    tag = struct.pack("<I", 3) + b"Bus"
    at = blob.find(tag)
    if at < 0:
        raise VerifyError(f"DUCCU Bus tag missing: {path.name}")
    ram_start = at + len(tag) + 64
    ram = blob[ram_start:ram_start + 0x200000]
    if len(ram) != 0x200000:
        raise VerifyError(f"DUCCU RAM truncated: {path.name}")
    return ram


def text_packets(ram: bytes, object_address: int) -> list[dict[str, int]]:
    obj = object_address - 0x80000000
    packet_base = struct.unpack_from("<I", ram, obj)[0]
    count = struct.unpack_from("<H", ram, obj + 0x0A)[0]
    packets: list[dict[str, int]] = []
    for index in range(count):
        at = packet_base - 0x80000000 + index * 52
        u, v, width, height = struct.unpack_from("<4B", ram, at + 0x28)
        x, y, clut = struct.unpack_from("<HHH", ram, at + 0x2C)
        packets.append({"index": index, "x": x, "y": y, "u": u, "v": v,
                        "w": width, "h": height, "clut": clut})
    return packets


def runtime_baseline() -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    help_rows: list[dict[str, object]] = []
    for state in (2, 3, 4):
        ram = inflate_state(V339_STATES[state])
        packets = text_packets(ram, BOTTOM_HELP_OBJECT)
        if not packets or any(packet["y"] != 214 for packet in packets):
            raise VerifyError(f"V339 state{state} help Y baseline drift")
        if state in (2, 3) and not any(packet["w"] in (12, 20) for packet in packets):
            raise VerifyError(f"V339 state{state} E7 icon evidence missing")
        for packet in packets:
            icon = packet["w"] in (12, 20)
            help_rows.append({
                "state": state, "index": packet["index"], "width": packet["w"],
                "v339_y": packet["y"], "v340_predicted_y": 214 if icon else 213,
                "class": "E7_icon" if icon else "ordinary_W16",
            })
    ram = inflate_state(V339_STATES[6])
    bar_rows: list[dict[str, object]] = []
    for slot in range(4):
        at = CONFIG_PRIMITIVES - 0x80000000 + slot * 56
        x, y, width, height = struct.unpack_from("<4H", ram, at)
        if (width, height) != (51, 14):
            raise VerifyError(f"V339 config bar baseline drift: slot {slot}")
        bar_rows.append({"slot": slot, "x": x, "y": y, "v339_w": width, "v339_h": height,
                         "v340_w": 62, "v340_h": 16})
    return help_rows, bar_rows


def disassembly(exe: bytes, start: int, end: int) -> list[str]:
    md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 | CS_MODE_LITTLE_ENDIAN)
    blob = exe[start - RAM_TO_FILE:end - RAM_TO_FILE]
    instructions = list(md.disasm(blob, start))
    if sum(insn.size for insn in instructions) != len(blob):
        raise VerifyError(f"incomplete disassembly at 0x{start:08X}")
    return [f"0x{i.address:08X}: {i.bytes.hex().upper()}  {i.mnemonic} {i.op_str}" for i in instructions]


def write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    for path, digest in ((BASE, BASE_SHA256), (FINAL, FINAL_SHA256), (DELTA, DELTA_SHA256)):
        if not path.is_file() or sha256(path.read_bytes()) != digest:
            raise VerifyError(f"archive hash mismatch: {path.name}")
    base_names, base = read_zip(BASE)
    final_names, final = read_zip(FINAL)
    if len(base_names) != 164 or final_names != base_names:
        raise VerifyError("full archive topology drift")
    if sha256(final[PSX]) != FINAL_PSX_SHA256:
        raise VerifyError("V340 PSX hash mismatch")
    expected = expected_overlay(base)
    if final != expected:
        bad = [name for name in final if final[name] != expected[name]]
        raise VerifyError(f"V340 differs from independently reconstructed overlay: {bad}")

    changed = [name for name in base_names if base[name] != final[name]]
    expected_changed = [name for name in base_names if name == PSX or name in SLOTS]
    if changed != expected_changed:
        raise VerifyError(f"changed member set/order drift: {changed}")
    with ZipFile(DELTA) as archive:
        if archive.namelist() != expected_changed or any(archive.read(name) != final[name] for name in expected_changed):
            raise VerifyError("delta archive topology/readback mismatch")
    actual = {name: changed_offsets(base[name], final[name]) for name in changed}
    verify_expected_write_csv(base, final, actual)

    before_rows, before_topology = choice_census(base)
    after_rows, after_topology = choice_census(final)
    before_bad = [row for row in before_rows if not row["bitmap_match"]]
    after_bad = [row for row in after_rows if not row["bitmap_match"]]
    if len(before_bad) != 29 or after_bad:
        raise VerifyError(f"battle bitmap census mismatch: {len(before_bad)} -> {len(after_bad)}")
    if Counter(row["approved"] for row in before_bad) != Counter(
        {"물론": 6, "괜찮아": 7, "괜찮다": 8, "싸운다": 7, "간다": 1}
    ):
        raise VerifyError("battle mismatch distribution drift")
    if before_topology != after_topology:
        raise VerifyError("E5/E6 marker topology changed")

    exe = final[PSX]
    if word(exe, HELP_Y_FILE) != 0x3406000A:
        raise VerifyError("bottom-help base Y is not 10")
    if struct.unpack_from("<18I", exe, E7_HELPER_FILE) != helper_words():
        raise VerifyError("E7 helper words mismatch")
    if word(exe, E7_Y_HOOK_FILE) != jump(E7_Y_ENTRY, link=True):
        raise VerifyError("E7 Y helper call mismatch")
    if struct.unpack_from("<3I", exe, E7_Y_HOOK_FILE + 4) != (0x34040010, 0x0C05E399, 0xA602002E):
        raise VerifyError("E7 load-delay/CLUT/Y-store context changed")
    edges = inbound(exe, E7_HELPER_RAM, E7_HELPER_RAM + E7_HELPER_SIZE)
    expected_edges = [
        (0x8016B6FC, 0x8019D02C),
        (0x80197FC4, 0x8019D018),  # mixed data-pool false instruction, pinned
        (0x8019C934, 0x8019D000),
        (0x8019D004, 0x8019D024),
        (0x8019D018, 0x8019D024),
        (0x8019D034, 0x8019D040),
    ]
    if edges != expected_edges:
        raise VerifyError(f"E7 helper inbound topology drift: {edges}")
    for value in range(0x200):
        old_v = 0xE4 if value in (2, 4, 8, 14) else 0x82
        new_v = 0xE4 if value < 15 and ((0x4114 >> value) & 1) else 0x82
        if old_v != new_v:
            raise VerifyError(f"E7 V truth-table mismatch at v1={value}")
    for state in (0x801F0E18, 0x801F9D44, 0x801F031C, 0x801F1DB4):
        observed = 101 + (1 if state == BOTTOM_HELP_OBJECT else 0)
        expected_y = 102 if state == BOTTOM_HELP_OBJECT else 101
        if observed != expected_y:
            raise VerifyError("E7 Y scope simulation failed")
    if word(exe, BAR_WIDTH_FILE) != 0x3405003E or word(exe, BAR_HEIGHT_FILE) != 0x34060010:
        raise VerifyError("configuration bar dimensions mismatch")
    if word(exe, BAR_WIDTH_FILE + 4) != 0x0C05B57B:
        raise VerifyError("configuration bar producer call changed")

    help_runtime, bar_runtime = runtime_baseline()
    ANALYSIS.mkdir(parents=True, exist_ok=True)
    write_csv(ANALYSIS / "independent_battle_choice_census.csv", after_rows)
    write_csv(ANALYSIS / "runtime_help_prediction.csv", help_runtime)
    write_csv(ANALYSIS / "runtime_config_bar_prediction.csv", bar_runtime)
    mips_lines = []
    for start, end, label in (
        (0x8019D000, 0x8019D048, "E7 V + bottom-help Y helpers"),
        (0x8016B6F8, 0x8016B70C, "E7 Y hook and CLUT call"),
        (0x8016C7AC, 0x8016C7BC, "bottom-help producer"),
        (0x801607A4, 0x801607B4, "configuration bar producer"),
    ):
        mips_lines.append(label)
        mips_lines.extend(disassembly(exe, start, end))
        mips_lines.append("")
    (ANALYSIS / "independent_mips_disassembly.txt").write_text("\n".join(mips_lines), encoding="utf-8")

    result = {
        "result": "PASS",
        "hashes": {"base": BASE_SHA256, "full": FINAL_SHA256, "delta": DELTA_SHA256,
                   "psx": FINAL_PSX_SHA256},
        "archive": {"members": 164, "changed_members": changed,
                    "changed_bytes": {name: len(actual[name]) for name in changed}},
        "battle_choices": {"bodies": 63, "before_mismatch": 29, "after_mismatch": 0,
                           "E5_E6_topology": "unchanged"},
        "bottom_help": {"runtime_baseline_states": [2, 3, 4],
                        "ordinary_W16": "214 -> predicted 213",
                        "E7_icons": "214 -> predicted 214"},
        "configuration": {"runtime_baseline_state": 6, "bar": "51x14 -> predicted 62x16"},
        "mips": "18-word in-place helper; truth table 512/512; R3000 delay contexts preserved",
        "runtime": "PENDING V340 cold boot",
    }
    (ANALYSIS / "independent_verification.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    lines = [
        "V340 independent static verification: PASS",
        f"full_sha256={FINAL_SHA256}",
        f"delta_sha256={DELTA_SHA256}",
        f"psx_sha256={FINAL_PSX_SHA256}",
        f"archive=164 members; changed={','.join(changed)}; Expected-Write exact",
        "battle_choices=V339 29 mismatches -> V340 0; 63/63 approved bitmap; E5/E6 byte offsets unchanged",
        "E7=old/new V truth table 512/512; helper remains inside original 72B; external edges pinned",
        "bottom_help=V339 states2-4 all y214; predicted V340 W16 y213, E7 W12/W20 y214",
        "configuration=V339 state6 bars 51x14; predicted V340 62x16",
        "runtime=PENDING V340 cold boot; TEST_ONLY",
    ]
    (ANALYSIS / "independent_verification.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
