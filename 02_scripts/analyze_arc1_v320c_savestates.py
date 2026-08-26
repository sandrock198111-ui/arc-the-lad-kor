#!/usr/bin/env python3
"""Read-only forensic audit for the six user-supplied V320C save states.

The analyzer proves the chain from the compressed DuckStation container through
loaded PS1 RAM and sprite packets to the physical 16px COMM.IMG plane.  It never
modifies a game archive or a save state; only CSV/JSON/PNG reports are written.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import struct
from collections import defaultdict
from pathlib import Path
from zipfile import ZipFile

from compression import zstd
from PIL import Image, ImageDraw


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BUILD = (
    ROOT
    / "03_output/arc1_v320c_hanme_official_beol_TEST_ONLY_81D215E1.zip"
)
DEFAULT_OUTPUT = ROOT / "01_work/analysis/arc1_v320c_runtime_states_6"
DEFAULT_STATES = (
    Path(r"C:\Users\Administrator\.paseo\uploads\upload_0d1278d9-dd4a-4d20-bf32-a17d9a3a498c\HASH-DA1F130F993926AA_1.sav"),
    Path(r"C:\Users\Administrator\.paseo\uploads\upload_83998f36-99f5-41ef-a74a-c62d34e0238e\HASH-DA1F130F993926AA_2.sav"),
    Path(r"C:\Users\Administrator\.paseo\uploads\upload_6c7e0c92-fd8b-4f7e-aba8-8a0283fdcfb9\HASH-DA1F130F993926AA_3.sav"),
    Path(r"C:\Users\Administrator\.paseo\uploads\upload_8f535fe4-485d-4905-98a6-daab84ce4799\HASH-DA1F130F993926AA_4.sav"),
    Path(r"C:\Users\Administrator\.paseo\uploads\upload_d1c2bfb2-1a65-4fa9-80b6-1fc22f608202\HASH-DA1F130F993926AA_5.sav"),
    Path(r"C:\Users\Administrator\.paseo\uploads\upload_0fc10fd8-227a-4167-899f-abd974b466ab\HASH-DA1F130F993926AA_6.sav"),
)

BUILD_SHA256 = "81D215E1B1138E26707353D8982AE3139AE4F3900F6E832FEC83BB66A43AEA8D"
PSX_SHA256 = "3D477AF6E97860485D89ADA92932FA90FA05B0834B583072E7A0946D2912D291"

ATLAS_MAPPING = ROOT / "01_work/analysis/arc1_v319_pilgi16_integration/atlas_mapping.csv"
ASSIGNMENTS = ROOT / "01_work/analysis/arc1_v320_hanme_static_recovery/character_assignments.csv"
SOURCE_RANGES = ROOT / "05_docs/script_original_full.csv"
TRANSLATIONS = ROOT / "05_docs/script_translated_full.csv"
DIALOGUE_SITES = ROOT / "05_docs/dialogue_sites_full.csv"
VERIFIED_E2_RETURNS = ROOT / "01_work/analysis/story_verified_returns_e2_v17_report.txt"

ZSTD_MAGIC = b"\x28\xB5\x2F\xFD"
RAM_SIZE = 2 * 1024 * 1024
VRAM_SIZE = 1024 * 512 * 2
VRAM_ROW_BYTES = 1024 * 2
GPU_VRAM_MARKER = struct.pack("<I", len("GPU-VRAM")) + b"GPU-VRAM"
COMM_ROW_BYTES = 896
COMM_VRAM_X_BYTES = 320 * 2

TEXT_HEADER = 0x801F9D44
TEXT_POINTER = 0x801F9D58
EXPECTED_PACKET_BASE = 0x801BE9BC
TEXT_HEADER2 = 0x801F9D88
EXPECTED_PACKET_BASE2 = 0x801BF6BC
FIXED_TEXT_OBJECTS = (
    (TEXT_HEADER, EXPECTED_PACKET_BASE),
    (TEXT_HEADER2, EXPECTED_PACKET_BASE2),
)
PACKET_STRIDE = 52

RAM_TO_FILE = 0x8011A800
EXE_LOAD_ADDRESS = 0x8011B000
EXE_TEXT_FILE_OFFSET = 0x800
EXE_TEXT_SIZE = 0x8F000
LOOKUP_RAM = 0x801A7520
LOOKUP_SLOTS = 0x19D
SLOT_BASE = 0x45000
SLOT_SIZE = 0x80

CELL = 16
COLS = 15
PLANES = 4

CODE_SIGNATURES = {
    0x8016B150: 0xAE200008,
    0x8016B154: 0xA2200010,
    0x8016B15C: 0xAE20000C,
    0x8016B160: 0x3402000E,
    0x8016B168: 0x34020010,
    0x8016B16C: 0xA222000E,
    0x8016B174: 0xA222000F,
    0x8016B394: 0x3404000E,
    0x8016B398: 0x34050010,
    0x8016B39C: 0x34060002,
    0x8016B3A4: 0x00003821,
    0x8016B530: 0x3402003C,
    0x8016B5CC: 0x90C3000D,
    0x8016B5D0: 0x90C1000F,
    0x8016B5D4: 0x90C2000E,
    0x8016B5D8: 0x00611821,
    0x8016B5DC: 0xA0A3002A,
    0x8016B5E0: 0xA0A2002B,
    0x8016BEF4: 0x25080008,
    0x8016BEFC: 0x25290008,
}


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest().upper()


def u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def s16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<h", data, offset)[0]


def u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def ram_offset(address: int) -> int:
    return address & 0x1FFFFF


def section_end(blob: bytes, name: str) -> int:
    tag = struct.pack("<I", len(name)) + name.encode("ascii")
    hits = []
    cursor = 0
    while True:
        at = blob.find(tag, cursor)
        if at < 0:
            break
        hits.append(at)
        cursor = at + 1
    if len(hits) != 1:
        raise ValueError(f"expected one {name!r} section, found {len(hits)}")
    return hits[0] + len(tag)


def locate_vram(blob: bytes) -> int:
    gpu = section_end(blob, "GPU")
    hits = []
    cursor = gpu
    search_end = min(len(blob), gpu + (1 << 16))
    while True:
        at = blob.find(GPU_VRAM_MARKER, cursor, search_end)
        if at < 0:
            break
        base = at + len(GPU_VRAM_MARKER)
        if base + VRAM_SIZE <= len(blob):
            hits.append(base)
        cursor = at + 1
    if len(hits) != 1:
        raise ValueError(f"expected one complete GPU-VRAM array, found {len(hits)}")
    return hits[0]


def find_zstd_offsets(raw: bytes) -> list[int]:
    offsets = []
    cursor = raw.find(ZSTD_MAGIC)
    while cursor >= 0:
        offsets.append(cursor)
        cursor = raw.find(ZSTD_MAGIC, cursor + 1)
    return offsets


def media_paths(blob: bytes) -> list[str]:
    pattern = re.compile(rb"[ -~]{4,300}\.(?:cue|bin)", re.IGNORECASE)
    return sorted({match.group().decode("ascii", "replace") for match in pattern.finditer(blob)})


def parse_state(path: Path) -> dict[str, object]:
    raw = path.read_bytes()
    if raw[:5] != b"DUCCU":
        raise ValueError(f"{path.name}: expected DUCCU")
    offsets = find_zstd_offsets(raw)
    if len(offsets) != 2:
        raise ValueError(f"{path.name}: expected exactly two zstd frames, got {offsets}")
    thumb_offset = u32(raw, 0xC4)
    compressed_size = u32(raw, 0xCC)
    state_size = u32(raw, 0xD0)
    state_offset = u32(raw, 0xD4)
    if offsets != [thumb_offset, state_offset]:
        raise ValueError(f"{path.name}: header/frame offset mismatch {offsets}")
    if len(raw) - state_offset != compressed_size:
        raise ValueError(f"{path.name}: compressed state size field mismatch")

    thumbnail = zstd.decompress(raw[thumb_offset:state_offset])
    blob = zstd.decompress(raw[state_offset:])
    if len(thumbnail) != 256 * 192 * 4:
        raise ValueError(f"{path.name}: thumbnail is not 256x192 BGRA")
    if len(blob) != state_size:
        raise ValueError(f"{path.name}: decompressed state size mismatch")
    if struct.pack("<I", 3) + b"Bus" not in blob or GPU_VRAM_MARKER not in blob:
        raise ValueError(f"{path.name}: state frame lacks Bus/GPU-VRAM structure")

    bus = section_end(blob, "Bus")
    ram_base = bus + 64
    vram_base = locate_vram(blob)
    ram = blob[ram_base : ram_base + RAM_SIZE]
    vram = blob[vram_base : vram_base + VRAM_SIZE]
    if len(ram) != RAM_SIZE or len(vram) != VRAM_SIZE:
        raise ValueError(f"{path.name}: incomplete RAM or VRAM")
    game_id = raw[8:40].split(b"\0", 1)[0].decode("ascii", "replace")
    return {
        "path": path,
        "file_sha256": sha256_bytes(raw),
        "file_size": len(raw),
        "game_id": game_id,
        "thumb_offset": thumb_offset,
        "state_offset": state_offset,
        "compressed_size": compressed_size,
        "state_size": state_size,
        "zstd_offsets": offsets,
        "thumbnail": thumbnail,
        "blob": blob,
        "ram": ram,
        "vram": vram,
        "ram_base": ram_base,
        "vram_base": vram_base,
        "media_paths": media_paths(blob),
    }


def load_source_ranges() -> list[tuple[str, int, int]]:
    result = []
    with SOURCE_RANGES.open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        fields = reader.fieldnames or []
        offset_key = "offset" if "offset" in fields else "byte offset"
        for row in reader:
            raw = bytes.fromhex(row["raw bytes as hex"].replace(" ", ""))
            result.append((row["source file"], int(row[offset_key], 0), len(raw)))
    return result


def load_translations() -> dict[tuple[str, int], str]:
    result = {}
    with TRANSLATIONS.open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            result[(row["source file"], int(row["offset"], 0))] = row["korean"]
    return result


def load_dialogue_spans() -> dict[str, list[tuple[int, int]]]:
    result: dict[str, list[tuple[int, int]]] = defaultdict(list)
    with DIALOGUE_SITES.open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            result[row["file"]].append((int(row["offset"], 0), int(row["bytes"])))
    return result


def load_verified_e2_translations() -> dict[tuple[str, int], str]:
    """Load the runtime-verified return-scene phrases recorded by v17.

    These composite inline sites are absent from script_translated_full.csv
    because their visible text lives in E2 slots split around original E4/E6
    controls.  The report is a project-owned, hash-stable historical record.
    """
    result: dict[tuple[str, int], str] = {}
    pattern = re.compile(r"^(\S+)\s+(0x[0-9A-Fa-f]+).*?\btext=(.*)$")
    with VERIFIED_E2_RETURNS.open(encoding="utf-8") as handle:
        for line in handle:
            match = pattern.match(line.rstrip("\n"))
            if match:
                result[(match.group(1), int(match.group(2), 0))] = match.group(3)
    return result


def load_mappings() -> dict[str, object]:
    physical_chars: dict[int, set[str]] = defaultdict(set)
    physical_sources: dict[int, set[str]] = defaultdict(set)
    token_char: dict[bytes, str] = {}
    token_physical: dict[bytes, int] = {}

    with ATLAS_MAPPING.open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            if row["char"]:
                index = int(row["index"])
                physical_chars[index].add(row["char"])
                physical_sources[index].add("atlas_mapping")

    with ASSIGNMENTS.open(encoding="utf-8-sig", newline="") as handle:
        assignment_rows = list(csv.DictReader(handle))
    for row in assignment_rows:
        token = bytes.fromhex(row["code_hex"])
        char = row["char"]
        physical = int(row["physical_index"])
        old_char = token_char.setdefault(token, char)
        old_physical = token_physical.setdefault(token, physical)
        if old_char != char or old_physical != physical:
            raise ValueError(f"assignment token conflict for {token.hex()}")
        physical_chars[physical].add(char)
        physical_sources[physical].add("character_assignments")
    return {
        "physical_chars": physical_chars,
        "physical_sources": physical_sources,
        "token_char": token_char,
        "token_physical": token_physical,
        "assignment_rows": assignment_rows,
    }


def lookup_get(exe: bytes, slot: int) -> int | None:
    if not 0 <= slot < LOOKUP_SLOTS:
        return None
    bit = slot * 11
    byte_index, shift = divmod(bit, 8)
    at = LOOKUP_RAM - RAM_TO_FILE + byte_index
    packed = exe[at] | (exe[at + 1] << 8) | (exe[at + 2] << 16)
    return (packed >> shift) & 0x7FF


def direct_index(token: bytes) -> int | None:
    if len(token) == 1:
        return token[0] - 1 if 1 <= token[0] <= 0xDC else None
    if len(token) != 2:
        return None
    lead, trail = token
    if lead in (0xE9, 0xEA) or not (lead >= 0xDD and 1 <= trail <= 0xFE):
        return None
    return (lead - 0xDD) * 255 + trail + 0xDB


def resolve_token_physical(token: bytes, exe: bytes, mapping: dict[str, object]) -> int | None:
    known = mapping["token_physical"]
    assert isinstance(known, dict)
    if token in known:
        return int(known[token])
    if len(token) == 2 and token[0] in (0xE9, 0xEA) and 1 <= token[1] <= 0xFE:
        slot = (token[0] - 0xE9) * 254 + token[1] - 1
        return lookup_get(exe, slot)
    return direct_index(token)


def is_control(data: bytes, offset: int) -> bool:
    value = data[offset]
    return value == 0xE2 or 0xE3 <= value <= 0xE8


def disk_slot(value: int) -> int | None:
    if 0x81 <= value <= 0xA8:
        return value - 0x81
    if 0xAA <= value <= 0xD0:
        return value - 0x82
    return None


def visible_region(data: bytes, site: int) -> tuple[int, int, int | None]:
    if data[site] != 0xE2:
        raise ValueError("inline region end must be supplied separately")
    slot = disk_slot(data[site + 1])
    if slot is None:
        raise ValueError(f"invalid E2 disk id at 0x{site:X}")
    start = SLOT_BASE + slot * SLOT_SIZE
    end = data.index(0, start, start + SLOT_SIZE)
    return start, end, slot


def decode_region(
    data: bytes,
    start: int,
    end: int,
    exe: bytes,
    mapping: dict[str, object],
) -> tuple[str, list[dict[str, object]]]:
    token_char = mapping["token_char"]
    physical_chars = mapping["physical_chars"]
    assert isinstance(token_char, dict) and isinstance(physical_chars, dict)
    output = []
    rows = []
    offset = start
    while offset < end:
        if is_control(data, offset):
            if offset + 2 > end:
                break
            token = data[offset : offset + 2]
            if token == b"\xE6\x01":
                output.append("\n")
            rows.append({"file_offset": offset, "token_hex": token.hex(" ").upper(), "control": True})
            offset += 2
            continue
        width = 1 if data[offset] < 0xDD else 2
        if offset + width > end:
            break
        token = data[offset : offset + width]
        physical = resolve_token_physical(token, exe, mapping)
        char = token_char.get(token)
        if char is None and physical is not None:
            candidates = sorted(physical_chars.get(physical, set()))
            if len(candidates) == 1:
                char = candidates[0]
        if char is None:
            char = f"<{token.hex().upper()}>"
        output.append(char)
        rows.append(
            {
                "file_offset": offset,
                "token_hex": token.hex(" ").upper(),
                "control": False,
                "physical_index": physical,
                "render_physical_index": (
                    None
                    if physical is None
                    or (len(token) == 2 and token[0] in (0xE9, 0xEA) and physical >= 0x600)
                    else physical % (COLS * (256 // CELL) * PLANES)
                ),
                "char": char,
            }
        )
        offset += width
    return "".join(output).rstrip(), rows


def read_plane(comm: bytes, index: int) -> tuple[int, ...]:
    cell, plane = divmod(index, PLANES)
    col, row = cell % COLS, cell // COLS
    bit = 1 << plane
    rows = []
    for y in range(CELL):
        value = 0
        base = (row * CELL + y) * COMM_ROW_BYTES + col * (CELL // 2)
        for x in range(CELL):
            at = base + x // 2
            shift = 0 if x % 2 == 0 else 4
            if ((comm[at] >> shift) & 0xF) & bit:
                value |= 1 << (CELL - 1 - x)
        rows.append(value)
    return tuple(rows)


def runtime_comm(vram: bytes) -> bytes:
    return b"".join(
        vram[y * VRAM_ROW_BYTES + COMM_VRAM_X_BYTES : y * VRAM_ROW_BYTES + COMM_VRAM_X_BYTES + COMM_ROW_BYTES]
        for y in range(512)
    )


def physical_from_packet(u: int, v: int, clut: int) -> int | None:
    if u % CELL or v % CELL or not 0x7FC0 <= clut <= 0x7FCF:
        return None
    return (v // CELL) * (COLS * PLANES) + (u // CELL) * PLANES + ((clut - 0x7FC0) & 3)


def packets_at(
    ram: bytes,
    base: int,
    count: int,
    mapping: dict[str, object],
) -> list[dict[str, object]]:
    physical_chars = mapping["physical_chars"]
    assert isinstance(physical_chars, dict)
    packets = []
    for ordinal in range(count):
        at = base + ordinal * PACKET_STRIDE
        u, v = ram[at + 0x28], ram[at + 0x29]
        w, h = ram[at + 0x2A], ram[at + 0x2B] & 0x7F
        x, y = s16(ram, at + 0x2C), s16(ram, at + 0x2E)
        clut = u16(ram, at + 0x30)
        physical = physical_from_packet(u, v, clut)
        candidates = sorted(physical_chars.get(physical, set())) if physical is not None else []
        char = candidates[0] if len(candidates) == 1 else (
            "/".join(candidates) if candidates else f"<{physical}>"
        )
        packets.append(
            {
                "ordinal": ordinal,
                "packet_address": f"0x{0x80000000 + at:08X}",
                "x": x,
                "y": y,
                "u": u,
                "v": v,
                "w": w,
                "h": h,
                "clut": f"0x{clut:04X}",
                "plane": (clut - 0x7FC0) & 3 if 0x7FC0 <= clut <= 0x7FCF else "",
                "physical_index": physical,
                "char": char,
            }
        )
    return packets


def object_at(
    ram: bytes,
    header: int,
    mapping: dict[str, object],
) -> tuple[dict[str, object], list[dict[str, object]]]:
    base_address = u32(ram, header)
    base = ram_offset(base_address)
    limit = u16(ram, header + 4)
    count = u16(ram, header + 0x0A)
    if not 0 <= count <= limit <= 128:
        raise ValueError(
            f"text object drift: base=0x{base_address:08X} count={count} limit={limit}"
        )
    packets = packets_at(ram, base, count, mapping)
    state = {
        "header_address": f"0x{0x80000000 + header:08X}",
        "base_address": f"0x{base_address:08X}",
        "limit": limit,
        "count": count,
        "x": s16(ram, header + 6),
        "y": s16(ram, header + 8),
        "style": ram[header + 0x0C],
        "D": ram[header + 0x0D],
        "E": ram[header + 0x0E],
        "F": ram[header + 0x0F],
        "line_extra": ram[header + 0x10],
        "source_pointer": f"0x{u32(ram, ram_offset(TEXT_POINTER)):08X}",
    }
    # The dialogue global aliases header+0x14, but every other object carries
    # its own source pointer at the same relative offset.
    state["source_pointer"] = f"0x{u32(ram, header + 0x14):08X}"
    return state, packets


def fixed_text_object(
    ram: bytes,
    mapping: dict[str, object],
    header_address: int,
    expected_packet_base: int,
) -> tuple[dict[str, object], list[dict[str, object]]]:
    header = ram_offset(header_address)
    state, packets = object_at(ram, header, mapping)
    if int(str(state["base_address"]), 16) != expected_packet_base:
        raise ValueError(
            f"fixed text packet base drift at 0x{header_address:08X}: "
            f"{state['base_address']}"
        )
    return state, packets


def find_text_objects(ram: bytes, mapping: dict[str, object]) -> list[dict[str, object]]:
    """Find every verified [limit*52 packet array][68-byte header] object."""
    objects = []
    for header in range(0, RAM_SIZE - 68, 2):
        base_address = u32(ram, header)
        base = ram_offset(base_address)
        limit = u16(ram, header + 4)
        count = u16(ram, header + 0x0A)
        if not 1 <= limit <= 128 or count > limit:
            continue
        if base + limit * PACKET_STRIDE != header or base >= RAM_SIZE:
            continue
        if base_address & 0xFFE00000 not in (0x80000000, 0xA0000000):
            continue
        state, packets = object_at(ram, header, mapping)
        plausible = sum(
            0 < int(packet["w"]) <= 64
            and 0 < int(packet["h"]) <= 64
            and -64 <= int(packet["x"]) <= 384
            and -64 <= int(packet["y"]) <= 320
            for packet in packets
        )
        if count and plausible * 2 < count:
            continue
        objects.append({"state": state, "packets": packets})
    return objects


def vram_text_score(
    vram: bytes,
    comm: bytes,
    packets: list[dict[str, object]],
) -> dict[str, object]:
    """Measure expected white glyph pixels in each 320x240 framebuffer.

    Dialogue sprites use a verified drawing Y offset of -8.  A stale object can
    remain structurally valid in RAM, but it will not reproduce its expected
    white pixels in the current framebuffer.
    """
    expected = 0
    matches = [0, 0]
    for packet in packets:
        index = packet.get("physical_index")
        if not isinstance(index, int) or not 0 <= index < COLS * (256 // CELL) * PLANES:
            continue
        rows = read_plane(comm, index)
        x0, y0 = int(packet["x"]), int(packet["y"]) - 8
        for y, row_bits in enumerate(rows):
            for x in range(CELL):
                if not (row_bits >> (CELL - 1 - x)) & 1:
                    continue
                screen_x, screen_y = x0 + x, y0 + y
                if not (0 <= screen_x < 320 and 0 <= screen_y < 240):
                    continue
                expected += 1
                for buffer_index, buffer_y in enumerate((screen_y, screen_y + 240)):
                    pixel = u16(vram, (buffer_y * 1024 + screen_x) * 2)
                    if pixel == 0x7FFF:
                        matches[buffer_index] += 1
    ratios = [value / expected if expected else 0.0 for value in matches]
    return {
        "expected_ink": expected,
        "buffer0_white": matches[0],
        "buffer1_white": matches[1],
        "buffer0_ratio": ratios[0],
        "buffer1_ratio": ratios[1],
        "best_ratio": max(ratios),
    }


def packet_text(packets: list[dict[str, object]]) -> str:
    output = []
    last_y = None
    for packet in packets:
        y = int(packet["y"])
        if last_y is not None and y != last_y:
            output.append("\n")
        output.append(str(packet["char"]))
        last_y = y
    return "".join(output).rstrip()


def rank_dat(ram: bytes, archive: ZipFile) -> list[dict[str, object]]:
    candidates = []
    for info in archive.infolist():
        if info.is_dir() or not info.filename.upper().endswith(".DAT") or info.file_size < 0x48000:
            continue
        data = archive.read(info.filename)
        for base in (0xCF000, 0xCF800):
            start, end = 0x45000, min(len(data), 0x48000)
            ram_start, ram_end = base + start, base + end
            if ram_end > len(ram):
                continue
            left = data[start:end]
            right = ram[ram_start:ram_end]
            equal = sum(a == b for a, b in zip(left, right, strict=True))
            candidates.append(
                {
                    "name": info.filename,
                    "base": base,
                    "equal": equal,
                    "size": len(left),
                    "ratio": equal / len(left),
                }
            )
    return sorted(candidates, key=lambda row: (-float(row["ratio"]), -int(row["equal"]), str(row["name"])))


def select_message(
    member: str,
    data: bytes,
    dat_base: int,
    pointer: int,
    ranges: list[tuple[str, int, int]],
    dialogue_spans: dict[str, list[tuple[int, int]]],
) -> dict[str, object]:
    file_pointer = ram_offset(pointer) - dat_base
    file_ranges = [(offset, size) for name, offset, size in ranges if name == member]

    # External E2 pointer: the cursor sits in the slot bank.  Link the slot back
    # to the one inline source site that names it.
    if SLOT_BASE <= file_pointer < 0x47800:
        slot = (file_pointer - SLOT_BASE) // SLOT_SIZE
        payload_start = SLOT_BASE + slot * SLOT_SIZE
        payload_end = data.index(0, payload_start, payload_start + SLOT_SIZE)
        sites = [
            offset
            for offset, _size in file_ranges
            if offset + 2 <= len(data)
            and data[offset] == 0xE2
            and disk_slot(data[offset + 1]) == slot
        ]
        site = sites[0] if len(sites) == 1 else None
        return {
            "file_pointer": file_pointer,
            "site": site,
            "payload_start": payload_start,
            "payload_end": payload_end,
            "external_slot": slot,
            "pointer_delta_to_end": file_pointer - payload_end,
            "site_candidates": sites,
        }

    exact = [(offset, size) for offset, size in file_ranges if offset + size == file_pointer]
    containing = [(offset, size) for offset, size in file_ranges if offset <= file_pointer <= offset + size]
    pool = exact or containing
    if not pool:
        # Composite return-scene sites were deliberately excluded from the
        # canonical script ranges.  Their end is nevertheless recorded in the
        # exhaustive dialogue catalog.  A three-byte delta is accepted for the
        # S1031 E2 site because that catalog counts only visible source bytes,
        # while the live cursor also passes its preserved E6/filler tail.
        catalog = [
            (offset, size)
            for offset, size in dialogue_spans.get(member, [])
            if data[offset] == 0xE2 and 0 <= file_pointer - (offset + size) <= 3
        ]
        if catalog:
            site, size = min(catalog, key=lambda row: file_pointer - (row[0] + row[1]))
            return {
                "file_pointer": file_pointer,
                "site": site,
                "payload_start": site,
                "payload_end": file_pointer,
                "external_slot": None,
                "pointer_delta_to_end": 0,
                "site_candidates": [row[0] for row in catalog],
                "composite_e2": True,
            }
    if not pool and file_ranges:
        pool = sorted(file_ranges, key=lambda row: abs((row[0] + row[1]) - file_pointer))[:1]
    if not pool:
        return {
            "file_pointer": file_pointer,
            "site": None,
            "payload_start": None,
            "payload_end": None,
            "external_slot": None,
            "pointer_delta_to_end": None,
            "site_candidates": [],
            "composite_e2": False,
        }
    site, size = pool[0]
    if data[site] == 0xE2:
        payload_start, payload_end, slot = visible_region(data, site)
    else:
        payload_start, payload_end, slot = site, site + size, None
    return {
        "file_pointer": file_pointer,
        "site": site,
        "payload_start": payload_start,
        "payload_end": payload_end,
        "external_slot": slot,
        "pointer_delta_to_end": file_pointer - payload_end,
        "site_candidates": [row[0] for row in pool],
        "composite_e2": False,
    }


def decode_selected_message(
    data: bytes,
    message: dict[str, object],
    exe: bytes,
    mapping: dict[str, object],
) -> tuple[str, list[dict[str, object]], list[dict[str, object]]]:
    start = message["payload_start"]
    end = message["payload_end"]
    if start is None or end is None:
        return "", [], []
    if not message.get("composite_e2"):
        text, tokens = decode_region(data, int(start), int(end), exe, mapping)
        return text, tokens, []

    output: list[str] = []
    tokens: list[dict[str, object]] = []
    segments: list[dict[str, object]] = []
    offset = int(start)
    while offset < int(end):
        if data[offset] == 0xE2 and offset + 1 < int(end):
            slot = disk_slot(data[offset + 1])
            if slot is None:
                raise ValueError(f"invalid composite E2 id at 0x{offset:X}")
            payload_start = SLOT_BASE + slot * SLOT_SIZE
            payload_end = data.index(0, payload_start, payload_start + SLOT_SIZE)
            segment_text, segment_tokens = decode_region(
                data, payload_start, payload_end, exe, mapping
            )
            output.append(segment_text)
            tokens.extend(segment_tokens)
            segments.append(
                {
                    "command_offset": offset,
                    "slot": slot,
                    "payload_start": payload_start,
                    "payload_end": payload_end,
                    "decoded": segment_text,
                }
            )
            offset += 2
            continue
        if offset + 1 < int(end) and data[offset : offset + 2] == b"\xE6\x01":
            output.append("\n")
            offset += 2
            continue
        if 0xE3 <= data[offset] <= 0xE8 and offset + 1 < int(end):
            offset += 2
            continue
        # Everything else is the skipped original text/filler retained solely
        # to preserve inline command boundaries.
        offset += 1
    return "".join(output).rstrip(), tokens, segments


def code_at_ram(ram: bytes, address: int) -> int:
    return u32(ram, ram_offset(address))


def exe_diff_words(ram: bytes, exe: bytes) -> tuple[int, int]:
    runtime = ram[ram_offset(EXE_LOAD_ADDRESS) : ram_offset(EXE_LOAD_ADDRESS) + EXE_TEXT_SIZE]
    disk = exe[EXE_TEXT_FILE_OFFSET : EXE_TEXT_FILE_OFFSET + EXE_TEXT_SIZE]
    words = len(disk) // 4
    different = sum(
        runtime[offset : offset + 4] != disk[offset : offset + 4]
        for offset in range(0, words * 4, 4)
    )
    return different, words


def save_thumbnail(thumbnail: bytes, path: Path) -> Image.Image:
    image = Image.frombytes("RGBA", (256, 192), thumbnail, "raw", "BGRA")
    image.save(path)
    return image


def write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    if not rows:
        return
    fields = []
    for row in rows:
        for key in row:
            if key not in fields:
                fields.append(key)
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("states", nargs="*", type=Path)
    parser.add_argument("--build", type=Path, default=DEFAULT_BUILD)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    states = tuple(args.states) or DEFAULT_STATES
    if len(states) != 6:
        raise SystemExit(f"expected six states, got {len(states)}")
    if sha256_file(args.build) != BUILD_SHA256:
        raise SystemExit("V320C build hash drift")
    args.output.mkdir(parents=True, exist_ok=True)

    mapping = load_mappings()
    ranges = load_source_ranges()
    translations = load_translations()
    translations.update(load_verified_e2_translations())
    dialogue_spans = load_dialogue_spans()
    state_rows: list[dict[str, object]] = []
    packet_rows: list[dict[str, object]] = []
    token_rows: list[dict[str, object]] = []
    object_rows: list[dict[str, object]] = []
    detail_records = []
    thumbnails = []

    with ZipFile(args.build) as archive:
        exe = archive.read("PSX.EXE")
        comm = archive.read("COMM.IMG")
        if sha256_bytes(exe) != PSX_SHA256:
            raise SystemExit("V320C PSX.EXE hash drift")

        for slot, path in enumerate(states, 1):
            parsed = parse_state(path)
            ram = parsed["ram"]
            vram = parsed["vram"]
            assert isinstance(ram, bytes) and isinstance(vram, bytes)
            thumb_path = args.output / f"state{slot}.png"
            thumbnails.append(save_thumbnail(parsed["thumbnail"], thumb_path))

            signatures_bad = [
                f"0x{address:08X}"
                for address, expected in CODE_SIGNATURES.items()
                if code_at_ram(ram, address) != expected
            ]
            exe_different, exe_words = exe_diff_words(ram, exe)
            live_comm = runtime_comm(vram)
            comm_equal = live_comm == comm
            comm_font_exact = all(
                live_comm[y * COMM_ROW_BYTES : y * COMM_ROW_BYTES + 120]
                == comm[y * COMM_ROW_BYTES : y * COMM_ROW_BYTES + 120]
                for y in range(208)
            )

            fixed_objects = []
            for header_address, packet_base in FIXED_TEXT_OBJECTS:
                state, packets_for_object = fixed_text_object(
                    ram, mapping, header_address, packet_base
                )
                fixed_objects.append({"state": state, "packets": packets_for_object})
            primary_state = fixed_objects[0]["state"]
            primary_packets = fixed_objects[0]["packets"]
            objects_by_header = {
                str(obj["state"]["header_address"]): obj for obj in fixed_objects
            }
            for obj in find_text_objects(ram, mapping):
                objects_by_header.setdefault(str(obj["state"]["header_address"]), obj)
            objects = list(objects_by_header.values())
            scored_objects = []
            for obj in objects:
                score = vram_text_score(vram, comm, obj["packets"])
                state = obj["state"]
                packets_for_object = obj["packets"]
                text = packet_text(packets_for_object)
                record = {
                    "state": slot,
                    "header": state["header_address"],
                    "base": state["base_address"],
                    "limit": state["limit"],
                    "count": state["count"],
                    "source_pointer": state["source_pointer"],
                    "D": state["D"],
                    "E": state["E"],
                    "F": state["F"],
                    "line_extra": state["line_extra"],
                    "text": text,
                    **score,
                }
                object_rows.append(record)
                scored_objects.append((score, state, packets_for_object, text))
            # A live object reproduces its expected white glyph pixels in one
            # of the two framebuffers.  Prefer the longest such object so a
            # simultaneously visible speaker label cannot displace dialogue.
            visible = [
                item
                for item in scored_objects
                if float(item[0]["best_ratio"]) >= 0.90 and int(item[0]["expected_ink"]) > 0
            ]
            if visible:
                selected = max(
                    visible,
                    key=lambda item: (
                        len(item[2]),
                        float(item[0]["best_ratio"]),
                        int(item[0]["expected_ink"]),
                    ),
                )
                selected_score, text_state, packets, _selected_text = selected
                object_selection = "framebuffer_verified"
            else:
                text_state, packets = primary_state, primary_packets
                selected_score = vram_text_score(vram, comm, packets)
                object_selection = "primary_fallback"
            source_pointer = int(str(text_state["source_pointer"]), 16)
            dat_ranking = rank_dat(ram, archive)
            best = dat_ranking[0]
            member = str(best["name"])
            dat_base = int(best["base"])
            data = archive.read(member)
            message = select_message(
                member, data, dat_base, source_pointer, ranges, dialogue_spans
            )
            site = message["site"]
            payload_start = message["payload_start"]
            payload_end = message["payload_end"]
            if payload_start is not None and payload_end is not None:
                disk_text, tokens, e2_segments = decode_selected_message(
                    data, message, exe, mapping
                )
                loaded = ram[dat_base + int(payload_start) : dat_base + int(payload_end)]
                loaded_equal = loaded == data[int(payload_start) : int(payload_end)]
            else:
                disk_text, tokens, e2_segments, loaded_equal = "", [], [], False
            rendered_text = packet_text(packets)
            expected_translation = translations.get((member, int(site))) if site is not None else None

            token_visible = [row for row in tokens if not row.get("control")]
            token_physical = [row.get("render_physical_index") for row in token_visible]
            packet_physical = [row.get("physical_index") for row in packets]
            physical_match = token_physical == packet_physical
            geometry = sorted({(int(row["w"]), int(row["h"])) for row in packets})
            x_steps = sorted(
                {
                    int(right["x"]) - int(left["x"])
                    for left, right in zip(packets, packets[1:])
                    if int(left["y"]) == int(right["y"])
                }
            )
            y_values = sorted({int(row["y"]) for row in packets})
            y_steps = [right - left for left, right in zip(y_values, y_values[1:])]

            state_row = {
                "state": slot,
                "savestate": path.name,
                "sha256": parsed["file_sha256"],
                "file_size": parsed["file_size"],
                "game_id": parsed["game_id"],
                "state_size": parsed["state_size"],
                "ram_base": f"0x{int(parsed['ram_base']):X}",
                "vram_base": f"0x{int(parsed['vram_base']):X}",
                "media_paths": " | ".join(parsed["media_paths"]),
                "code_signature_failures": " ".join(signatures_bad),
                "exe_different_words": exe_different,
                "exe_total_words": exe_words,
                "runtime_COMM_exact": int(comm_equal),
                "runtime_COMM_font_area_exact": int(comm_font_exact),
                "DAT": member,
                "DAT_base": f"0x{dat_base:X}",
                "DAT_match": f"{int(best['equal'])}/{int(best['size'])}",
                "DAT_ratio": f"{float(best['ratio']):.6f}",
                "source_pointer": f"0x{source_pointer:08X}",
                "text_header": text_state["header_address"],
                "object_selection": object_selection,
                "framebuffer_ratio": f"{float(selected_score['best_ratio']):.6f}",
                "file_pointer": f"0x{int(message['file_pointer']):X}",
                "site": "" if site is None else f"0x{int(site):X}",
                "payload": "" if payload_start is None else f"0x{int(payload_start):X}-0x{int(payload_end):X}",
                "external_slot": "" if message["external_slot"] is None else message["external_slot"],
                "composite_e2": int(bool(message.get("composite_e2"))),
                "e2_segments": " | ".join(
                    f"slot{row['slot']}=0x{int(row['payload_start']):X}-0x{int(row['payload_end']):X}"
                    for row in e2_segments
                ),
                "pointer_delta_to_end": message["pointer_delta_to_end"],
                "loaded_payload_exact": int(loaded_equal),
                "expected_translation": expected_translation or "",
                "disk_decoded": disk_text,
                "packet_decoded": rendered_text,
                "token_packet_physical_exact": int(physical_match),
                "packet_count": len(packets),
                "geometry": repr(geometry),
                "x_steps": repr(x_steps),
                "y_steps": repr(y_steps),
                "D": text_state["D"],
                "E": text_state["E"],
                "F": text_state["F"],
                "line_extra": text_state["line_extra"],
            }
            state_rows.append(state_row)

            for packet in packets:
                index = packet.get("physical_index")
                bitmap_hash = ""
                if isinstance(index, int) and 0 <= index < COLS * (256 // CELL) * PLANES:
                    bitmap_hash = sha256_bytes(
                        b"".join(row.to_bytes(2, "big") for row in read_plane(comm, index))
                    )
                packet_rows.append({"state": slot, **packet, "bitmap_sha256": bitmap_hash})
            for token in tokens:
                token_rows.append({"state": slot, "DAT": member, "site": state_row["site"], **token})

            detail_records.append(
                {
                    "state": slot,
                    "header": {
                        key: value
                        for key, value in parsed.items()
                        if key not in {"path", "thumbnail", "blob", "ram", "vram"}
                    },
                    "text_state": text_state,
                    "dat_top5": dat_ranking[:5],
                    "message": message,
                    "e2_segments": e2_segments,
                    "expected_translation": expected_translation,
                    "disk_decoded": disk_text,
                    "packet_decoded": rendered_text,
                    "token_packet_physical_exact": physical_match,
                }
            )
            print(
                f"state{slot}: {member} site "
                f"{state_row['site'] or '?'} | disk={disk_text!r} | packets={rendered_text!r}"
            )

    montage = Image.new("RGBA", (256 * 3, (192 + 20) * 2), (25, 25, 25, 255))
    draw = ImageDraw.Draw(montage)
    for index, image in enumerate(thumbnails):
        col, row = index % 3, index // 3
        x, y = col * 256, row * (192 + 20)
        montage.paste(image, (x, y + 20))
        draw.text((x + 6, y + 3), f"state {index + 1}", fill=(255, 255, 255, 255))
    montage.save(args.output / "states_montage.png")

    write_csv(args.output / "state_summary.csv", state_rows)
    write_csv(args.output / "packets.csv", packet_rows)
    write_csv(args.output / "message_tokens.csv", token_rows)
    write_csv(args.output / "text_objects.csv", object_rows)
    (args.output / "runtime_audit.json").write_text(
        json.dumps(detail_records, ensure_ascii=False, indent=2, default=str) + "\n",
        encoding="utf-8",
    )
    report = [
        "Arc the Lad 1 V320C - six-save runtime forensic audit",
        f"build_sha256={BUILD_SHA256}",
        "format=DUCCU; frame at +0xC4 is 256x192 BGRA thumbnail; frame at +0xD4 is state",
        "",
    ]
    for row in state_rows:
        report.extend(
            [
                f"state{row['state']} sha256={row['sha256']}",
                f"  build={row['game_id']} media={row['media_paths']}",
                f"  DAT={row['DAT']} base={row['DAT_base']} match={row['DAT_match']} site={row['site']} payload={row['payload']}",
                f"  expected={row['expected_translation']}",
                f"  disk={row['disk_decoded']}",
                f"  packet={row['packet_decoded']}",
                f"  loaded_exact={row['loaded_payload_exact']} token_packet_exact={row['token_packet_physical_exact']} COMM_full_exact={row['runtime_COMM_exact']} COMM_font_exact={row['runtime_COMM_font_area_exact']}",
                f"  geometry={row['geometry']} x_steps={row['x_steps']} y_steps={row['y_steps']} D/E/F/extra={row['D']}/{row['E']}/{row['F']}/{row['line_extra']}",
                "",
            ]
        )
    (args.output / "runtime_audit.txt").write_text("\n".join(report), encoding="utf-8")
    print(f"wrote {args.output}")


if __name__ == "__main__":
    main()
