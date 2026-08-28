#!/usr/bin/env python3
"""Independent static verification for V333 dynamic UI glyph recovery.

The builder is deliberately not imported.  This verifier reconstructs the
two-member overlay, 16px strip planes, local pointer routes and packet
coordinates from raw archive bytes.
"""

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

BASE = ROOT / "03_output/arc1_v332_skill_config_bar_alignment_TEST_ONLY_D2951A33.zip"
FINAL = ROOT / "03_output/arc1_v333_dynamic_ui_glyph_recovery_TEST_ONLY_55D826DC.zip"
DELTA = ROOT / "03_output/arc1_v333_dynamic_ui_glyph_recovery_TEST_ONLY_delta_from_v332_69AC3C90.zip"
ORIGINAL = ROOT / "00_original/arc.zip"
ANALYSIS = ROOT / "01_work/analysis/arc1_v333_dynamic_ui_glyph_recovery"

BASE_SHA256 = "D2951A33C598C04BDDDCDC07678ADADCC18471CE98FE32B904527073445BB5AF"
FINAL_SHA256 = "55D826DC02FE5A7DE5167EBB81623184409FA4F8FC395B2EB04369A17DC2D450"
DELTA_SHA256 = "69AC3C90278CA30E93E7CC67B43FEAFE0CBA063D04EA6B8A4D6795AA04AA9E86"
ORIGINAL_SHA256 = "AE9F4366A1E7DA3805BB3BED3DDA9567E4CD4E669AF890E4E2A620D7861F11DD"

PSX = "PSX.EXE"
COMM = "COMM.IMG"
RAM_TO_FILE = 0x8011A800
ROW_BYTES = 896

SYNTH_BASE = 960
STRIP_X = 240
STRIP_Y = 176
STRIP_CELL = 16
SOURCE_CELL = 12
OLD_SYNTH_COUNT = 13
NEW_SYNTH_COUNT = 17
NEW_GLYPHS = (
    (13, "L", 825),
    (14, "M", 553),
    (15, "P", 363),
    (16, ":", 36),
)

UV_FILE = 0x80910
UV_WORDS = (
    0xA0A20029,
    0x2488FC40,
    0x2D090011,
    0x11200007,
    0x00000000,
    0x340900F0,
    0xA0A90028,
    0x00084082,
    0x00084100,
    0x250800B0,
    0xA0A80029,
    0x0805AD6C,
    0x340900A0,
)
LOOKUP_FILE = 0x801A7520 - RAM_TO_FILE
LOOKUP_SLOTS = 0x19D
LOOKUP_BYTES = (LOOKUP_SLOTS * 11 + 7) // 8 + 2

E5_FILE = 0x51604
E5_WORDS = (0x340403C0, 0x0C05AD46, 0x02002821)

LOAD_SLOT_FILES = (0x78090, 0x78094, 0x78098)
LOAD_SLOT_PAYLOADS = (b"\xDF\xEA\0\0", b"\xDF\xEB\0\0", b"\xDF\xEC\0\0")
LOAD_L_POINTER = 0x780FC
LOAD_COLON_FILE = 0x78240

HUD_POINTER_FILES = (0x823AC, 0x823B0, 0x823B4, 0x823B8, 0x823BC)
HUD_AUX_POINTER = 0x8019C95C
HUD_L_FILE = 0x809E0
HUD_M_FILE = 0x809E8
HUD_P_FILE = 0x809F0
LOAD_L_FILE = 0x809F4
EMPTY_FILE = 0x809F8

EXPECTED_PAYLOADS = {
    HUD_L_FILE: b"\xDF\xE7\xDF\xF4\0",
    HUD_M_FILE: b"\xDF\xE7\xDF\xF5\0",
    HUD_P_FILE: b"\xDF\xF6\0",
    LOAD_L_FILE: b"\xDF\xF4\0",
    EMPTY_FILE: b"\0",
}


class VerifyError(RuntimeError):
    pass


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def read_zip(path: Path) -> tuple[list[str], dict[str, bytes]]:
    with ZipFile(path) as archive:
        names = [item.filename for item in archive.infolist() if not item.is_dir()]
        return names, {name: archive.read(name) for name in names}


def changed(before: bytes, after: bytes) -> set[int]:
    if len(before) != len(after):
        raise VerifyError("member size changed")
    return {
        offset
        for offset, (old, new) in enumerate(zip(before, after, strict=True))
        if old != new
    }


def encode_index(index: int) -> bytes:
    if 0 <= index < 0xDC:
        return bytes((index + 1,))
    lead_delta, trail = divmod(index - 0xDB, 255)
    if not 0 <= lead_delta <= 3 or not 1 <= trail <= 0xFE:
        raise VerifyError(f"cannot encode physical index {index}")
    return bytes((0xDD + lead_delta, trail))


def direct_index(token: bytes) -> int:
    if len(token) == 1 and 1 <= token[0] <= 0xDC:
        return token[0] - 1
    if len(token) == 2 and 0xDD <= token[0] <= 0xE0 and 1 <= token[1] <= 0xFE:
        return (token[0] - 0xDD) * 255 + token[1] + 0xDB
    raise VerifyError(f"not a direct glyph token: {token.hex().upper()}")


def split_tokens(payload: bytes) -> list[bytes]:
    result: list[bytes] = []
    at = 0
    while at < len(payload) and payload[at]:
        width = 1 if payload[at] < 0xDD else 2
        if at + width > len(payload):
            raise VerifyError("truncated token payload")
        result.append(payload[at : at + width])
        at += width
    return result


def raw_string(data: bytes, offset: int) -> bytes:
    end = data.find(b"\0", offset, min(offset + 64, len(data)))
    if end < 0:
        raise VerifyError(f"unterminated payload at 0x{offset:X}")
    return data[offset:end]


def nibble(data: bytes | bytearray, x: int, y: int) -> int:
    value = data[y * ROW_BYTES + x // 2]
    return (value >> (0 if x % 2 == 0 else 4)) & 0xF


def set_plane(data: bytearray, x: int, y: int, plane: int, enabled: bool) -> None:
    at = y * ROW_BYTES + x // 2
    shift = 0 if x % 2 == 0 else 4
    value = (data[at] >> shift) & 0xF
    bit = 1 << plane
    value = value | bit if enabled else value & (~bit & 0xF)
    if shift:
        data[at] = (data[at] & 0x0F) | (value << 4)
    else:
        data[at] = (data[at] & 0xF0) | value


def read_original_plane(data: bytes, physical: int) -> tuple[int, ...]:
    cell, plane = divmod(physical, 4)
    row, col = divmod(cell, 21)
    bit = 1 << plane
    result: list[int] = []
    for y in range(SOURCE_CELL):
        value = 0
        for x in range(SOURCE_CELL):
            px = col * SOURCE_CELL + x
            if nibble(data, px, row * SOURCE_CELL + y) & bit:
                value |= 1 << (SOURCE_CELL - 1 - x)
        result.append(value)
    return tuple(result)


def read_strip_plane(data: bytes | bytearray, slot: int) -> tuple[int, ...]:
    plane = slot & 3
    y0 = STRIP_Y + (slot >> 2) * STRIP_CELL
    bit = 1 << plane
    result: list[int] = []
    for y in range(STRIP_CELL):
        value = 0
        for x in range(STRIP_CELL):
            if nibble(data, STRIP_X + x, y0 + y) & bit:
                value |= 1 << (STRIP_CELL - 1 - x)
        result.append(value)
    return tuple(result)


def padded_source(rows: tuple[int, ...]) -> tuple[int, ...]:
    return tuple(value << 4 for value in rows) + (0, 0, 0, 0)


def expected_comm(base: bytes, original: bytes) -> bytes:
    output = bytearray(base)
    for slot, _label, source in NEW_GLYPHS:
        if any(read_strip_plane(base, slot)):
            raise VerifyError(f"V332 target strip plane {slot} is not blank")
        plane = slot & 3
        y0 = STRIP_Y + (slot >> 2) * STRIP_CELL
        rows = read_original_plane(original, source)
        for y in range(STRIP_CELL):
            for x in range(STRIP_CELL):
                enabled = y < SOURCE_CELL and x < SOURCE_CELL and bool(
                    rows[y] & (1 << (SOURCE_CELL - 1 - x))
                )
                set_plane(output, STRIP_X + x, y0 + y, plane, enabled)
    return bytes(output)


def expected_exe(base: bytes) -> bytes:
    output = bytearray(base)
    struct.pack_into("<I", output, UV_FILE + 8, 0x2D090011)
    struct.pack_into("<I", output, E5_FILE, E5_WORDS[0])
    for offset, payload in zip(LOAD_SLOT_FILES, LOAD_SLOT_PAYLOADS, strict=True):
        output[offset : offset + 4] = payload
    for offset, payload in EXPECTED_PAYLOADS.items():
        output[offset : offset + len(payload)] = payload
    struct.pack_into("<I", output, LOAD_L_POINTER, RAM_TO_FILE + LOAD_L_FILE)
    output[LOAD_COLON_FILE : LOAD_COLON_FILE + 4] = b"\xDF\xF7\0\0"
    pointers = (
        RAM_TO_FILE + HUD_L_FILE,
        RAM_TO_FILE + EMPTY_FILE,
        HUD_AUX_POINTER,
        RAM_TO_FILE + HUD_M_FILE,
        RAM_TO_FILE + HUD_P_FILE,
    )
    struct.pack_into("<5I", output, HUD_POINTER_FILES[0], *pointers)
    return bytes(output)


def instruction_lines(exe: bytes, start: int, end: int) -> list[str]:
    md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN)
    blob = exe[start - RAM_TO_FILE : end - RAM_TO_FILE]
    insns = list(md.disasm(blob, start))
    if sum(item.size for item in insns) != len(blob):
        raise VerifyError(f"incomplete disassembly at 0x{start:08X}")
    return [
        f"0x{item.address:08X}: {item.bytes.hex().upper()}  {item.mnemonic} {item.op_str}".rstrip()
        for item in insns
    ]


def texture(index: int, state_d: int) -> tuple[int, int, int, int]:
    if not SYNTH_BASE <= index < SYNTH_BASE + NEW_SYNTH_COUNT:
        raise VerifyError(f"index outside V333 strip: {index}")
    slot = index - SYNTH_BASE
    u = STRIP_X + (4 if state_d == 6 else 0)
    v = STRIP_Y + (slot >> 2) * STRIP_CELL
    return u, v, slot & 3, 6 if state_d == 6 else 16


def pointer_hits(exe: bytes, start: int, end: int) -> list[tuple[int, int]]:
    hits: list[tuple[int, int]] = []
    for offset in range(0, len(exe) - 3, 4):
        value = struct.unpack_from("<I", exe, offset)[0]
        target = value - RAM_TO_FILE
        if start <= target < end:
            hits.append((offset, target))
    return hits


def main() -> None:
    for path, digest in (
        (BASE, BASE_SHA256),
        (FINAL, FINAL_SHA256),
        (DELTA, DELTA_SHA256),
        (ORIGINAL, ORIGINAL_SHA256),
    ):
        if sha256(path.read_bytes()) != digest:
            raise VerifyError(f"hash mismatch: {path.name}")

    base_names, base = read_zip(BASE)
    final_names, final = read_zip(FINAL)
    if base_names != final_names or len(final_names) != 164:
        raise VerifyError("full archive topology mismatch")
    changed_members = [name for name in base_names if base[name] != final[name]]
    if set(changed_members) != {PSX, COMM} or len(changed_members) != 2:
        raise VerifyError(f"changed member set mismatch: {changed_members}")
    if any(len(base[name]) != len(final[name]) for name in base_names):
        raise VerifyError("member size drift")
    if any(base[name] != final[name] for name in base_names if name not in {PSX, COMM}):
        raise VerifyError("non-PSX/COMM member changed")
    with ZipFile(DELTA) as archive:
        if set(archive.namelist()) != {PSX, COMM}:
            raise VerifyError("delta member set mismatch")
        if any(archive.read(name) != final[name] for name in (PSX, COMM)):
            raise VerifyError("delta payload mismatch")

    with ZipFile(ORIGINAL) as archive:
        original_comm = archive.read(COMM)

    exe0, exe1 = base[PSX], final[PSX]
    comm0, comm1 = base[COMM], final[COMM]
    if expected_exe(exe0) != exe1:
        raise VerifyError("independent PSX overlay reconstruction mismatch")
    if expected_comm(comm0, original_comm) != comm1:
        raise VerifyError("independent COMM plane reconstruction mismatch")

    psx_diff = changed(exe0, exe1)
    comm_diff = changed(comm0, comm1)
    if len(psx_diff) != 35 or len(comm_diff) != 44:
        raise VerifyError(f"changed-byte census mismatch: {len(psx_diff)}/{len(comm_diff)}")

    # Compare the builder's Expected-Write ledger against a fresh whole-file diff.
    with (ANALYSIS / "expected_writes.csv").open(encoding="utf-8-sig", newline="") as handle:
        ledger = {
            (row["member"], int(row["offset"], 16), row["before"], row["after"])
            for row in csv.DictReader(handle)
        }
    actual = {
        (member, offset, f"{before[offset]:02X}", f"{after[offset]:02X}")
        for member, before, after, offsets in (
            (PSX, exe0, exe1, psx_diff),
            (COMM, comm0, comm1, comm_diff),
        )
        for offset in offsets
    }
    if ledger != actual:
        raise VerifyError(f"Expected-Write ledger mismatch: symmetric={len(ledger ^ actual)}")

    if struct.unpack_from(f"<{len(UV_WORDS)}I", exe1, UV_FILE) != UV_WORDS:
        raise VerifyError("UV helper word array mismatch")
    if struct.unpack_from("<3I", exe1, E5_FILE) != E5_WORDS:
        raise VerifyError("E5 placeholder/JAL/delay words mismatch")
    if exe0[LOOKUP_FILE : LOOKUP_FILE + LOOKUP_BYTES] != exe1[LOOKUP_FILE : LOOKUP_FILE + LOOKUP_BYTES]:
        raise VerifyError("global E9/EA lookup changed")

    # V332's skill/configuration alignment remains byte exact.
    if struct.unpack_from("<2I", exe1, 0x460F4) != (0x2665007E, 0x266500BA):
        raise VerifyError("V332 configuration-bar alignment drift")
    if struct.unpack_from("<2I", exe1, 0x47880) != (0x0C066C2C, 0xAFA20010):
        raise VerifyError("V331 skill-name wrapper call drift")

    for slot in range(OLD_SYNTH_COUNT):
        if read_strip_plane(comm0, slot) != read_strip_plane(comm1, slot):
            raise VerifyError(f"inherited compact strip slot changed: {slot}")
    new_slots = {slot for slot, _label, _source in NEW_GLYPHS}
    for slot, label, source in NEW_GLYPHS:
        if STRIP_X + STRIP_CELL > 256 or STRIP_Y + (slot >> 2) * 16 + 16 > 256:
            raise VerifyError(f"UV page overflow for {label}")
        expected = padded_source(read_original_plane(original_comm, source))
        if read_strip_plane(comm1, slot) != expected:
            raise VerifyError(f"new strip plane mismatch: {slot}/{label}")
        if label in {"L", ":"}:
            source_rows = read_original_plane(original_comm, source)
            for bits in source_rows:
                for x in (*range(0, 4), *range(10, 12)):
                    if bits & (1 << (SOURCE_CELL - 1 - x)):
                        raise VerifyError(f"6px crop would cut {label} at source x={x}")
        for neighbor in range(4):
            other = (slot & ~3) | neighbor
            if other in new_slots:
                continue
            if read_strip_plane(comm0, other) != read_strip_plane(comm1, other):
                raise VerifyError(f"neighbor strip plane changed: {slot}/{neighbor}")

    expected_hits = sorted(
        [
            (LOAD_L_POINTER, LOAD_L_FILE),
            (HUD_POINTER_FILES[0], HUD_L_FILE),
            (HUD_POINTER_FILES[1], EMPTY_FILE),
            (HUD_POINTER_FILES[3], HUD_M_FILE),
            (HUD_POINTER_FILES[4], HUD_P_FILE),
        ]
    )
    if pointer_hits(exe1, HUD_L_FILE, EMPTY_FILE + 1) != expected_hits:
        raise VerifyError("local payload-pool pointer ownership mismatch")

    # Local routes, decoded without consulting the global E9/EA table.
    if [direct_index(payload[:2]) for payload in LOAD_SLOT_PAYLOADS] != [963, 964, 965]:
        raise VerifyError("load slot-number route mismatch")
    load_l_target = struct.unpack_from("<I", exe1, LOAD_L_POINTER)[0] - RAM_TO_FILE
    if load_l_target != LOAD_L_FILE or direct_index(raw_string(exe1, load_l_target)) != 973:
        raise VerifyError("load L local route mismatch")
    if direct_index(raw_string(exe1, LOAD_COLON_FILE)) != 976:
        raise VerifyError("load colon local route mismatch")
    if struct.unpack_from("<5I", exe1, HUD_POINTER_FILES[0]) != (
        RAM_TO_FILE + HUD_L_FILE,
        RAM_TO_FILE + EMPTY_FILE,
        HUD_AUX_POINTER,
        RAM_TO_FILE + HUD_M_FILE,
        RAM_TO_FILE + HUD_P_FILE,
    ):
        raise VerifyError("HUD pointer array mismatch")
    hud_indices = {}
    for label, pointer_file in (("L", HUD_POINTER_FILES[0]), ("M", HUD_POINTER_FILES[3]), ("P", HUD_POINTER_FILES[4])):
        target = struct.unpack_from("<I", exe1, pointer_file)[0] - RAM_TO_FILE
        hud_indices[label] = [direct_index(token) for token in split_tokens(raw_string(exe1, target))]
    if hud_indices != {"L": [960, 973], "M": [960, 974], "P": [975]}:
        raise VerifyError(f"HUD local token routes mismatch: {hud_indices}")
    if any(read_strip_plane(comm1, 0)):
        raise VerifyError("synthetic placeholder slot 960 is not blank")

    route_rows: list[dict[str, object]] = []
    semantics = {960: "blank", 963: "1", 964: "2", 965: "3", 973: "L", 974: "M", 975: "P", 976: ":"}
    routes = (
        ("load", "slot_number_1", 6, [963]),
        ("load", "slot_number_2", 6, [964]),
        ("load", "slot_number_3", 6, [965]),
        ("load", "level_label", 6, [973]),
        ("load", "time_colon", 6, [976]),
        ("choice", "E5_03_indent", 14, [960, 960]),
        ("battle", "level_label", 6, [960, 973]),
        ("battle", "magic_label", 14, [960, 974]),
        ("battle", "power_label", 14, [975]),
    )
    for screen, producer, state_d, indices in routes:
        coords = [texture(index, state_d) for index in indices]
        route_rows.append(
            {
                "screen": screen,
                "producer": producer,
                "state_d": state_d,
                "indices": " ".join(map(str, indices)),
                "semantics": "".join(semantics[index] for index in indices),
                "u": " ".join(str(item[0]) for item in coords),
                "v": " ".join(str(item[1]) for item in coords),
                "plane": " ".join(str(item[2]) for item in coords),
                "packet_w": " ".join(str(item[3]) for item in coords),
                "advance_total": len(indices) * state_d,
            }
        )
    if route_rows[5]["advance_total"] != 28:
        raise VerifyError("E5 indentation width was not preserved at 28 pixels")

    disassembly = ["[E5 direct placeholder route]"]
    disassembly += instruction_lines(exe1, 0x8016BDFC, 0x8016BE18)
    disassembly += ["", "[synthetic UV helper]"]
    disassembly += instruction_lines(exe1, RAM_TO_FILE + UV_FILE, RAM_TO_FILE + UV_FILE + len(UV_WORDS) * 4)
    if not any("ori $a0, $zero, 0x3c0" in line for line in disassembly):
        raise VerifyError("Capstone did not confirm E5 synthetic blank")
    if not any("sltiu $t1, $t0, 0x11" in line for line in disassembly):
        raise VerifyError("Capstone did not confirm 17-slot UV limit")
    if not any("ori $t1, $zero, 0xa0" in line for line in disassembly):
        raise VerifyError("UV helper does not restore live t1=160")

    ANALYSIS.mkdir(parents=True, exist_ok=True)
    (ANALYSIS / "mips_disassembly.txt").write_text("\n".join(disassembly) + "\n", encoding="utf-8")
    with (ANALYSIS / "route_truth.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(route_rows[0]))
        writer.writeheader()
        writer.writerows(route_rows)

    verification = {
        "verdict": "STATIC PASS; RUNTIME PENDING",
        "hashes": {
            "full_zip": FINAL_SHA256,
            "delta_zip": DELTA_SHA256,
            "PSX.EXE": sha256(exe1),
            "COMM.IMG": sha256(comm1),
        },
        "archive": {"members": len(final_names), "changed_members": changed_members},
        "changed_bytes": {PSX: len(psx_diff), COMM: len(comm_diff)},
        "checks": {
            "independent_PSX_rebuild": "PASS",
            "independent_COMM_plane_rebuild": "PASS",
            "expected_write_exact": "PASS",
            "global_lookup_unchanged": "PASS",
            "all_DAT_unchanged": "PASS",
            "V332_skill_config_alignment_unchanged": "PASS",
            "old_compact_strip_0_to_12_unchanged": "PASS",
            "new_strip_13_to_16_and_neighbors": "PASS",
            "E5_two_blank_packets_28px": "PASS",
            "UV_t1_restore_and_page_bounds": "PASS",
        },
        "runtime": "PENDING user cold boot",
    }
    (ANALYSIS / "independent_verification.json").write_text(
        json.dumps(verification, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    report = [
        "V333 independent verification",
        "verdict=STATIC PASS; RUNTIME PENDING",
        f"full_sha256={FINAL_SHA256}",
        f"delta_sha256={DELTA_SHA256}",
        f"changed_members={','.join(changed_members)}",
        f"changed_bytes=PSX.EXE {len(psx_diff)} / COMM.IMG {len(comm_diff)}",
        "load=1/2/3 + L + colon local synthetic routes PASS",
        "choice=E5 two blank packets / 28px indentation PASS",
        "battle=L/M/P local routes; compact digit path retained PASS",
        "global E9/EA lookup, all DAT, V332 skill/config alignment unchanged PASS",
    ]
    (ANALYSIS / "independent_verification.txt").write_text("\n".join(report) + "\n", encoding="utf-8")
    (ANALYSIS / "runtime_checklist.txt").write_text(
        "V333 cold-boot checklist\n"
        "1. Load screen: slots 1/2/3, L plus compact level, and H:MM playtime are readable.\n"
        "2. Choice screen: no visible '다다'; the original 28px indentation remains.\n"
        "3. Battle HUD: L, M, P and compact counters are readable; HP orb/icon remains.\n"
        "4. Item/status compact digits remain intentionally six pixels wide.\n"
        "5. V332 skill/config alignment and ordinary dialogue remain unchanged.\n",
        encoding="utf-8",
    )
    print("\n".join(report))


if __name__ == "__main__":
    main()
