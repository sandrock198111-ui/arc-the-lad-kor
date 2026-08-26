"""Build the clean Arc the Lad 1 Pilgi johab-font flow-fix proof of concept.

This is deliberately *not* a continuation of v312-v317.  It starts from the
pristine Japanese ``00_original/arc.zip`` and changes exactly three members:

* ``COMM.IMG``: 29 static 12x12 Hangul component planes.
* ``PSX.EXE``: one cursor-advance helper and one jump hook.
* ``1/S1071.DAT``: three fixed-length diagnostic strings whose original
  terminator boundaries and runtime-proven line-break skeleton are preserved.

There is no dynamic cache, E2 external text, UI repack, expanded executable,
or bulk translation in this build.  The result is TEST_ONLY until a cold-boot
emulator run confirms the font path and checks nearby graphics consumers.
"""

from __future__ import annotations

import argparse
import csv
import functools
import hashlib
import io
import json
import os
import pickle
import struct
import sys
import time
import zlib
from collections import defaultdict
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo


ROOT = Path(__file__).resolve().parents[1]
LOCAL_PACKAGES = ROOT / "06_tools/python_packages"
if LOCAL_PACKAGES.is_dir():
    sys.path.insert(0, str(LOCAL_PACKAGES))

import PIL  # noqa: E402
import capstone  # noqa: E402
from PIL import Image, ImageDraw, ImageFont, features  # noqa: E402


BASE_ZIP = ROOT / "00_original/arc.zip"
OUTPUT_DIR = ROOT / "03_output"
ANALYSIS_DIR = ROOT / "01_work/analysis/johab_font_poc_flowfix"
OUTPUT_STEM = "arc1_johab_font_poc_pilgi_FLOWFIX_TEST_ONLY"

BASE_ZIP_SHA256 = "AE9F4366A1E7DA3805BB3BED3DDA9567E4CD4E669AF890E4E2A620D7861F11DD"
BASE_MEMBER_GUARDS = {
    "PSX.EXE": (581_632, "947EBF893F2D46207EC7E32CA514E4EA670E0BED34EF2144B5F7FB0FDD15BC67"),
    "COMM.IMG": (458_752, "6C7565B6C326A99A29266482868F17A144FF7D15B871D7D8F8B852EC41014A26"),
    "1/S1071.DAT": (305_152, "775B1439BB3613DCFDC4DE9A6F4CC7868C762F502A6B99718DCAA023CBFD1116"),
}

FONT_PROFILES = {
    "pilgi": {
        "member": "Pilgi_8x4x4.ttf",
        "zip_sha256": "31084434DC45D383B21A8A3BE10A47869BB31E92D7C2C5AEEF91BD439D956A78",
        "font_size": 454_256,
        "font_sha256": "30EC39649ECBE2DC1E716F0FF7C8793AA364CFB7D5AB37C4401FE0936E1417A9",
    }
}

EXPECTED_PILLOW = "12.3.0"
EXPECTED_FREETYPE = "2.14.3"

PSX = "PSX.EXE"
COMM = "COMM.IMG"
TEST_DAT = "1/S1071.DAT"
EXPECTED_CHANGED_MEMBERS = {PSX, COMM, TEST_DAT}

ROW_BYTES = 896
GLYPH_SIZE = 12
GLYPH_COLS = 21
PLANES = 4
MAX_GLYPH_INDEX = 0xDB + 3 * 255 + 254
# Clean-original builds use the stock blank ASCII-space plane (index 0).
# 0x9C was blank only after the older Korean atlas had cleared index 155.
SPACE_BYTE = 0x01

# Every selected index is blank and unreferenced in the conservative catalog.
# Its physical atlas cell had text reads and zero non-text reads in 509 states.
CHO_START = 1041
CHO_CAPACITY = 13
REST_START = 1125
REST_CAPACITY = 16
# The immediately following plane is already blank in the pristine COMM.IMG,
# absent from the deliberately over-counted reference catalog, and belongs to
# a cell with 82 text reads / zero non-text reads across the 509-state audit.
# It is never written: it is only decoded as an invisible, non-advancing
# fixed-length filler so an inline body reaches its original 0x00 boundary.
SAFE_FILLER_INDEX = REST_START + REST_CAPACITY
NONADVANCE_COUNT = REST_CAPACITY + 1

EXE_LOAD = 0x8011B000
ADVANCE_HOOK = 0x8016B63C
ADVANCE_HELPER = 0x8018FCD0
CAVE_END = 0x8018FDC5

ORIGINAL_ADVANCE_WORDS = (
    0x90C3000D,  # lbu v1,0xD(a2)
    0x90C5000F,  # lbu a1,0xF(a2)
    0x94C20006,  # lhu v0,6(a2)
    0x94C4000A,  # lhu a0,0xA(a2)
    0x00651821,  # addu v1,v1,a1
    0x00431021,  # addu v0,v0,v1
    0xA4C20006,  # sh v0,6(a2)
    0x24840001,  # addiu a0,a0,1
    0xA4C4000A,  # sh a0,0xA(a2)
    0x03E00008,  # jr ra
    0x00000000,  # nop
)

# SHA-256 over every inked, encodable original glyph plane.  Blank target
# planes are excluded, so this must remain identical after insertion.
ORIGINAL_INKED_PLANES_SHA256 = "C6E90BF76B176D384561248A95D7929F9D26D8B9B985BE04A3BFFBA9B6876D7C"

# Official iolo/8x4x4-fonts generate_hangul_syllables.py rules.  The raw
# upstream source was independently fetched and hashed on 2026-08-20; the
# build stays offline and records this immutable provenance in its manifest.
RULE_SOURCE_URL = (
    "https://raw.githubusercontent.com/iolo/8x4x4-fonts/"
    "main/generate_hangul_syllables.py"
)
RULE_SOURCE_SHA256 = "A498B4F7B7DC840AD637B093711ED6DB650EEEA96DAFA46728B4F30E730B3052"
RULE_SOURCE_SIZE = 3_201
# Vowel order: ㅏ ㅐ ㅑ ㅒ ㅓ ㅔ ㅕ ㅖ ㅗ ㅘ ㅙ ㅚ ㅛ ㅜ ㅝ ㅞ ㅟ ㅠ ㅡ ㅢ ㅣ
CHO_KIND_WITHOUT_JONG = (
    0, 0, 0, 0, 0, 0, 0, 0, 1, 3, 3, 3, 1, 2, 4, 4, 4, 2, 1, 3, 0,
)
CHO_KIND_WITH_JONG = (
    5, 5, 5, 5, 5, 5, 5, 5, 6, 7, 7, 7, 6, 6, 7, 7, 7, 6, 6, 7, 5,
)
JONG_KIND_BY_JUNG = (
    0, 2, 0, 2, 1, 2, 1, 2, 3, 0, 2, 1, 3, 3, 1, 2, 1, 3, 3, 1, 1,
)

TEST_SITES = (
    (0x478D6, 39, "출 홀 줄 하 허 호"),
    (0x47932, 41, "각 객 걱 곡"),
    (0x4798E, 55, "가 나 고 구 과 워"),
)

# story_test_07_stable.zip (SHA-256
# 2A09829F936BD6BF6D4EB8D9A614656B3E993ECE93B7F86B71D8637488E63125)
# passed all four S1071 dialogues with these E6 01 counts and the original
# terminator offsets.  Unknown FF/E6/EA pairs removed by that accepted build
# are therefore not reintroduced by this narrow font PoC.
PROVEN_LINEBREAK_COUNTS = (2, 1, 2)
NEWLINE = b"\xE6\x01"
ORIGINAL_SPEAKER_PREFIX = bytes.fromhex("DD 0B D4 25")
TEXT_OBJECT_GLYPH_LIMIT = 64

DIALOGUE_SITES = ROOT / "05_docs/dialogue_sites_full.csv"
EXE_POINTER_STRINGS = ROOT / "01_work/analysis/exe_ptr_strings.pkl"
CELL_CONSUMERS = ROOT / "01_work/analysis/font_cell_audit_full/cell_consumers.csv"
CELL_AUDIT_REPORT = ROOT / "01_work/analysis/font_cell_audit_full/report.txt"


class BuildError(RuntimeError):
    """A guard failed; no final output should be trusted."""


def step(message: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {message}", flush=True)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest().upper()


def clone_zipinfo(info: ZipInfo) -> ZipInfo:
    clone = ZipInfo(info.filename, info.date_time)
    for attr in (
        "compress_type",
        "comment",
        "extra",
        "create_system",
        "create_version",
        "extract_version",
        "flag_bits",
        "volume",
        "internal_attr",
        "external_attr",
    ):
        setattr(clone, attr, getattr(info, attr))
    return clone


def encode_index(index: int) -> bytes | None:
    if 0 <= index < 220:
        return bytes((index + 1,))
    rel = index - 0xDB
    lead, trail = divmod(rel, 255)
    if 0 <= lead <= 3 and 1 <= trail <= 254:
        return bytes((0xDD + lead, trail))
    return None


def cell_of(index: int) -> tuple[int, int, int]:
    cell, plane = divmod(index, PLANES)
    return cell % GLYPH_COLS, cell // GLYPH_COLS, plane


def read_plane(buf: bytes | bytearray, index: int) -> tuple[int, ...]:
    col, row, plane = cell_of(index)
    if (row + 1) * GLYPH_SIZE > 504 or (col + 1) * GLYPH_SIZE > 252:
        raise BuildError(f"glyph index {index} is outside the 252x504 text atlas")
    bit = 1 << plane
    rows: list[int] = []
    for y in range(GLYPH_SIZE):
        base = (row * GLYPH_SIZE + y) * ROW_BYTES + col * (GLYPH_SIZE // 2)
        value = 0
        for x in range(GLYPH_SIZE):
            at = base + x // 2
            shift = 0 if x % 2 == 0 else 4
            nibble = (buf[at] >> shift) & 0x0F
            if nibble & bit:
                value |= 1 << (GLYPH_SIZE - 1 - x)
        rows.append(value)
    return tuple(rows)


def put_plane(buf: bytearray, index: int, rows: tuple[int, ...]) -> set[int]:
    if len(rows) != GLYPH_SIZE:
        raise BuildError(f"glyph index {index}: expected {GLYPH_SIZE} rows, got {len(rows)}")
    col, row, plane = cell_of(index)
    bit = 1 << plane
    touched: set[int] = set()
    for y in range(GLYPH_SIZE):
        base = (row * GLYPH_SIZE + y) * ROW_BYTES + col * (GLYPH_SIZE // 2)
        src = rows[y]
        for x in range(GLYPH_SIZE):
            at = base + x // 2
            shift = 0 if x % 2 == 0 else 4
            nibble = (buf[at] >> shift) & 0x0F
            if (src >> (GLYPH_SIZE - 1 - x)) & 1:
                nibble |= bit
            else:
                nibble &= ~bit & 0x0F
            buf[at] = (buf[at] & (0xF0 if shift == 0 else 0x0F)) | (nibble << shift)
            touched.add(at)
    return touched


def inked_planes_hash(buf: bytes | bytearray, original_inked: list[int]) -> str:
    data = bytearray()
    for index in original_inked:
        for row in read_plane(buf, index):
            data += row.to_bytes(2, "little")
    return sha256_bytes(bytes(data))


def component_keys(ch: str) -> tuple[tuple[str, int, int], ...]:
    if not "가" <= ch <= "힣":
        raise BuildError(f"diagnostic text contains unsupported character U+{ord(ch):04X}")
    value = ord(ch) - 0xAC00
    cho, remainder = divmod(value, 588)
    jung, jong = divmod(remainder, 28)
    cho_beol = (CHO_KIND_WITH_JONG if jong else CHO_KIND_WITHOUT_JONG)[jung]
    if jong:
        jung_beol = 2 if cho in (0, 15) else 3
    else:
        jung_beol = 0 if cho in (0, 15) else 1
    result: list[tuple[str, int, int]] = [("v", jung_beol, jung)]
    if jong:
        result.append(("t", JONG_KIND_BY_JUNG[jung], jong))
    # Choseong is emitted last.  It is the one component that advances X.
    result.append(("c", cho_beol, cho))
    return tuple(result)


def component_pua(key: tuple[str, int, int]) -> int:
    kind, beol, jamo = key
    if kind == "c":
        offset = beol * 20 + jamo + 1
    elif kind == "v":
        offset = 160 + beol * 22 + jamo + 1
    elif kind == "t":
        offset = 248 + beol * 28 + jamo
    else:
        raise BuildError(f"unknown component kind {kind!r}")
    if not 0 <= offset < 360:
        raise BuildError(f"component offset out of range: {key} -> {offset}")
    return 0xF600 + offset


def render_component(face: ImageFont.FreeTypeFont, key: tuple[str, int, int]) -> tuple[int, ...]:
    image = Image.new("L", (GLYPH_SIZE, GLYPH_SIZE), 0)
    ImageDraw.Draw(image).text((0, 0), chr(component_pua(key)), font=face, fill=255)
    pixels = image.load()
    return tuple(
        sum(
            1 << (GLYPH_SIZE - 1 - x)
            for x in range(GLYPH_SIZE)
            if pixels[x, y] > 96
        )
        for y in range(GLYPH_SIZE)
    )


def render_syllable(face: ImageFont.FreeTypeFont, ch: str) -> tuple[int, ...]:
    image = Image.new("L", (GLYPH_SIZE, GLYPH_SIZE), 0)
    ImageDraw.Draw(image).text((0, 0), ch, font=face, fill=255)
    pixels = image.load()
    return tuple(
        sum(
            1 << (GLYPH_SIZE - 1 - x)
            for x in range(GLYPH_SIZE)
            if pixels[x, y] > 96
        )
        for y in range(GLYPH_SIZE)
    )


def or_rows(parts: list[tuple[int, ...]]) -> tuple[int, ...]:
    return tuple(
        0 if not parts else functools.reduce(int.__or__, (part[y] for part in parts))
        for y in range(GLYPH_SIZE)
    )


def parse_indices(data: bytes) -> set[int]:
    """Parse established DD-E0 glyph pairs while skipping E1+ control pairs."""
    result: set[int] = set()
    pos = 0
    while pos < len(data):
        value = data[pos]
        if value >= 0xE1:
            pos += 2
            continue
        if value >= 0xDD:
            if pos + 1 < len(data) and 1 <= data[pos + 1] <= 0xFE:
                result.add((value - 0xDD) * 255 + data[pos + 1] + 0xDB)
            pos += 2
            continue
        if 1 <= value <= 0xDC:
            result.add(value - 1)
        pos += 1
    return result


def profile_inline_body(data: bytes) -> tuple[int, list[bytes]]:
    """Validate one fixed-length body and return glyph/control token counts."""
    glyphs = 0
    controls: list[bytes] = []
    pos = 0
    while pos < len(data):
        lead = data[pos]
        if lead == 0:
            raise BuildError(f"inline body contains an early 0x00 at byte {pos}")
        if lead >= 0xE1:
            if pos + 1 >= len(data):
                raise BuildError("inline body ends in a truncated control token")
            controls.append(data[pos : pos + 2])
            pos += 2
            continue
        if lead >= 0xDD:
            if pos + 1 >= len(data) or not 1 <= data[pos + 1] <= 0xFE:
                raise BuildError(f"invalid two-byte glyph at inline byte {pos}")
            glyphs += 1
            pos += 2
            continue
        if not 1 <= lead <= 0xDC:
            raise BuildError(f"invalid one-byte glyph 0x{lead:02X} at inline byte {pos}")
        glyphs += 1
        pos += 1
    return glyphs, controls


def collect_conservative_references(
    members: dict[str, bytes],
) -> tuple[set[int], int, int]:
    # dialogue_sites_full.csv describes the v104+ layout and deliberately
    # over-counts references when applied to the clean original.  That makes
    # it valid only as a conservative exclusion set here; never reuse this
    # result to claim that a glyph is actually referenced by the original.
    references: set[int] = set()
    dialogue_count = 0
    with DIALOGUE_SITES.open(encoding="utf-8-sig", newline="") as stream:
        for row in csv.DictReader(stream):
            dialogue_count += 1
            name = row["file"]
            offset = int(row["offset"], 0)
            length = int(row["bytes"])
            if name not in members or offset + length > len(members[name]):
                raise BuildError(f"invalid dialogue site {name} {offset:#x}+{length}")
            references |= parse_indices(members[name][offset : offset + length])
    with EXE_POINTER_STRINGS.open("rb") as stream:
        exe_sites = pickle.load(stream)
    if not isinstance(exe_sites, dict):
        raise BuildError("exe_ptr_strings.pkl is not a dictionary")
    if dialogue_count != 39_457 or len(exe_sites) != 1_736:
        raise BuildError(
            "conservative catalog size drifted: "
            f"dialogue {dialogue_count}, EXE {len(exe_sites)}"
        )
    exe = members[PSX]
    for offset, length in exe_sites.items():
        if offset < 0 or length < 0 or offset + length > len(exe):
            raise BuildError(f"invalid EXE string site {offset:#x}+{length}")
        references |= parse_indices(exe[offset : offset + length])
    if len(references) != 892:
        raise BuildError(f"conservative reference catalog drifted: expected 892, got {len(references)}")
    return references, dialogue_count, len(exe_sites)


def load_cell_audit() -> tuple[dict[tuple[int, int], tuple[int, int]], int]:
    result: dict[tuple[int, int], tuple[int, int]] = {}
    with CELL_CONSUMERS.open(encoding="utf-8-sig", newline="") as stream:
        for row in csv.DictReader(stream):
            result[(int(row["row"]), int(row["col"]))] = (
                int(row["text_reads"]),
                int(row["nontext_reads"]),
            )
    states = None
    for line in CELL_AUDIT_REPORT.read_text(encoding="utf-8-sig").splitlines():
        if line.startswith("states_read="):
            states = int(line.split("=", 1)[1])
    if states != 509:
        raise BuildError(f"font-cell audit state count drifted: expected 509, got {states}")
    return result, states


def file_offset(exe: bytes | bytearray, address: int) -> int:
    if exe[:8] != b"PS-X EXE":
        raise BuildError("PSX.EXE has no PS-X EXE header")
    text_address, text_size = struct.unpack_from("<II", exe, 0x18)
    if text_address != EXE_LOAD:
        raise BuildError(f"unexpected PSX.EXE load address {text_address:#x}")
    if not text_address <= address < text_address + text_size:
        raise BuildError(f"address {address:#x} is outside the PSX.EXE text image")
    return 0x800 + address - text_address


def i_word(op: int, rs: int, rt: int, immediate: int) -> int:
    return (op << 26) | (rs << 21) | (rt << 16) | (immediate & 0xFFFF)


def r_word(rs: int, rt: int, rd: int, shift: int, function: int) -> int:
    return (rs << 21) | (rt << 16) | (rd << 11) | (shift << 6) | function


def j_word(address: int) -> int:
    if address & 3:
        raise BuildError(f"unaligned jump address {address:#x}")
    return 0x08000000 | ((address >> 2) & 0x03FFFFFF)


def branch_word(op: int, rs: int, rt: int, pc: int, target: int) -> int:
    delta = target - (pc + 4)
    if delta & 3:
        raise BuildError(f"unaligned branch target {target:#x}")
    offset = delta // 4
    if not -0x8000 <= offset <= 0x7FFF:
        raise BuildError("branch target is out of range")
    return i_word(op, rs, rt, offset)


def make_advance_helper(rest_start: int, rest_count: int) -> bytes:
    """Return a range-aware replacement for the original cursor tail.

    The jump hook's delay slot loads ``v1`` (glyph width).  The helper adds
    spacing and advances X for every glyph except indices in the single
    contiguous jung/jong range.  The glyph ordinal always advances.
    """
    if not 0 <= rest_start <= 0x7FFF:
        raise BuildError("rest_start cannot be represented by addiu")
    if not 1 <= rest_count <= 0xFFFF:
        raise BuildError("rest_count cannot be represented by sltiu")
    base = ADVANCE_HELPER
    no_advance = base + 9 * 4
    words = (
        i_word(0x24, 6, 5, 0x000F),                  # lbu   a1,0xF(a2)
        i_word(0x09, 4, 1, -rest_start),             # addiu at,a0,-rest_start
        i_word(0x0B, 1, 1, rest_count),              # sltiu at,at,rest_count
        i_word(0x25, 6, 4, 0x000A),                  # lhu   a0,0xA(a2)
        i_word(0x25, 6, 2, 0x0006),                  # lhu   v0,6(a2)
        branch_word(0x05, 1, 0, base + 5 * 4, no_advance),  # bne at,zero,no_advance
        r_word(3, 5, 3, 0, 0x21),                   #  addu v1,v1,a1 (delay)
        r_word(2, 3, 2, 0, 0x21),                   # addu  v0,v0,v1
        i_word(0x29, 6, 2, 0x0006),                  # sh    v0,6(a2)
        i_word(0x09, 4, 4, 1),                       # no_advance: addiu a0,a0,1
        i_word(0x29, 6, 4, 0x000A),                  # sh    a0,0xA(a2)
        r_word(31, 0, 0, 0, 0x08),                  # jr    ra
        0x00000000,                                  # nop
    )
    expected = (
        0x90C5000F,
        0x24810000 | ((-rest_start) & 0xFFFF),
        0x2C210000 | rest_count,
        0x94C4000A,
        0x94C20006,
        0x14200003,
        0x00651821,
        0x00431021,
        0xA4C20006,
        0x24840001,
        0xA4C4000A,
        0x03E00008,
        0x00000000,
    )
    if words != expected:
        raise BuildError("MIPS helper encoder did not match the independently specified words")
    return struct.pack(f"<{len(words)}I", *words)


def disassemble_helper(blob: bytes) -> list[str]:
    md = capstone.Cs(
        capstone.CS_ARCH_MIPS,
        capstone.CS_MODE_MIPS32 + capstone.CS_MODE_LITTLE_ENDIAN,
    )
    instructions = list(md.disasm(blob, ADVANCE_HELPER))
    if len(instructions) != 13:
        raise BuildError(f"Capstone decoded {len(instructions)} helper instructions, expected 13")
    mnemonics = [insn.mnemonic for insn in instructions]
    expected = [
        "lbu", "addiu", "sltiu", "lhu", "lhu", "bnez", "addu",
        "addu", "sh", "addiu", "sh", "jr", "nop",
    ]
    if mnemonics != expected:
        raise BuildError(f"unexpected helper disassembly: {mnemonics}")
    if any("$t0" in insn.op_str.lower() for insn in instructions):
        raise BuildError("helper unexpectedly clobbers t0")
    if "0x8018fcf4" not in instructions[5].op_str.lower():
        raise BuildError(f"helper branch target drifted: {instructions[5].op_str}")
    return [
        f"{insn.address:08X}  {struct.unpack('<I', insn.bytes)[0]:08X}  "
        f"{insn.mnemonic:<8s}{insn.op_str}"
        for insn in instructions
    ]


def group_shapes(
    keys: set[tuple[str, int, int]],
    bitmaps: dict[tuple[str, int, int], tuple[int, ...]],
) -> list[tuple[tuple[int, ...], list[tuple[str, int, int]]]]:
    groups: dict[tuple[int, ...], list[tuple[str, int, int]]] = defaultdict(list)
    for key in keys:
        groups[bitmaps[key]].append(key)
    return sorted(
        ((shape, sorted(group)) for shape, group in groups.items()),
        key=lambda item: (item[0], item[1]),
    )


def coalesce_offsets(offsets: set[int]) -> list[tuple[int, int]]:
    if not offsets:
        return []
    result: list[tuple[int, int]] = []
    start = previous = min(offsets)
    for value in sorted(offsets)[1:]:
        if value != previous + 1:
            result.append((start, previous + 1))
            start = value
        previous = value
    result.append((start, previous + 1))
    return result


def diff_offsets(before: bytes, after: bytes) -> set[int]:
    if len(before) != len(after):
        raise BuildError("cannot diff differently sized members")
    return {index for index, (left, right) in enumerate(zip(before, after)) if left != right}


def write_csv(path: Path, fieldnames: list[str], rows: list[dict[str, object]]) -> None:
    with path.open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--font-zip", type=Path, required=True, help="8x4x4-fonts-all.zip path")
    parser.add_argument("--font-profile", choices=sorted(FONT_PROFILES), default="pilgi")
    parser.add_argument("--base", type=Path, default=BASE_ZIP)
    parser.add_argument("--output-dir", type=Path, default=OUTPUT_DIR)
    parser.add_argument("--analysis-dir", type=Path, default=ANALYSIS_DIR)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    profile = FONT_PROFILES[args.font_profile]

    step("입력 해시와 렌더러 버전 확인")
    if sha256_file(args.base) != BASE_ZIP_SHA256:
        raise BuildError(f"base ZIP is not the pinned Japanese original: {args.base}")
    if not args.font_zip.is_file():
        raise BuildError(f"font ZIP does not exist: {args.font_zip}")
    font_zip_hash = sha256_file(args.font_zip)
    if font_zip_hash != profile["zip_sha256"]:
        raise BuildError(f"font ZIP hash mismatch: {font_zip_hash}")
    freetype_version = features.version_module("freetype2")
    if PIL.__version__ != EXPECTED_PILLOW or freetype_version != EXPECTED_FREETYPE:
        raise BuildError(
            "font renderer version drift: "
            f"Pillow {PIL.__version__}/{EXPECTED_PILLOW}, "
            f"FreeType {freetype_version}/{EXPECTED_FREETYPE}"
        )

    with ZipFile(args.font_zip) as archive:
        try:
            font_bytes = archive.read(str(profile["member"]))
        except KeyError as error:
            raise BuildError(f"font member missing: {profile['member']}") from error
    if len(font_bytes) != profile["font_size"] or sha256_bytes(font_bytes) != profile["font_sha256"]:
        raise BuildError("font member size/hash mismatch")
    face = ImageFont.truetype(io.BytesIO(font_bytes), GLYPH_SIZE)

    step("원본 arc.zip 읽기")
    with ZipFile(args.base) as archive:
        infos = archive.infolist()
        if len({info.filename for info in infos}) != len(infos):
            raise BuildError("base ZIP contains duplicate member names")
        members = {
            info.filename: archive.read(info.filename)
            for info in infos
            if not info.is_dir()
        }
    for name, (size, digest) in BASE_MEMBER_GUARDS.items():
        if name not in members:
            raise BuildError(f"base ZIP is missing {name}")
        if len(members[name]) != size or sha256_bytes(members[name]) != digest:
            raise BuildError(f"base member guard failed: {name}")

    original_comm = members[COMM]
    encodable = [index for index in range(MAX_GLYPH_INDEX + 1) if encode_index(index) is not None]
    original_inked = [index for index in encodable if any(read_plane(original_comm, index))]
    if len(original_inked) != 996:
        raise BuildError(f"original inked glyph count drifted: {len(original_inked)}")
    if inked_planes_hash(original_comm, original_inked) != ORIGINAL_INKED_PLANES_SHA256:
        raise BuildError("original inked-plane hash guard failed")
    if any(read_plane(original_comm, SPACE_BYTE - 1)):
        raise BuildError("clean-original space glyph is not pixel-empty")
    if REST_START <= SPACE_BYTE - 1 < REST_START + NONADVANCE_COUNT:
        raise BuildError("space code overlaps the non-advancing component range")
    safe_filler_code = encode_index(SAFE_FILLER_INDEX)
    if safe_filler_code != b"\xE0\x9D":
        raise BuildError("safe filler encoding drifted from E0 9D")

    step("공식 8x4x4 규칙으로 진단 문구 조각 렌더")
    all_keys: set[tuple[str, int, int]] = set()
    all_syllables: set[str] = set()
    for _offset, _capacity, text in TEST_SITES:
        for ch in text:
            if ch == " ":
                continue
            all_syllables.add(ch)
            all_keys.update(component_keys(ch))
    bitmaps = {key: render_component(face, key) for key in all_keys}
    blank_keys = [key for key, bitmap in bitmaps.items() if not any(bitmap)]
    if blank_keys:
        raise BuildError(f"font rendered blank components: {blank_keys}")
    cho_keys = {key for key in all_keys if key[0] == "c"}
    rest_keys = all_keys - cho_keys
    cho_groups = group_shapes(cho_keys, bitmaps)
    rest_groups = group_shapes(rest_keys, bitmaps)
    if (len(cho_keys), len(cho_groups), len(rest_keys), len(rest_groups)) != (13, 13, 19, 16):
        raise BuildError(
            "diagnostic component census drifted: "
            f"cho {len(cho_keys)}/{len(cho_groups)}, rest {len(rest_keys)}/{len(rest_groups)}"
        )
    if len(cho_groups) > CHO_CAPACITY or len(rest_groups) > REST_CAPACITY:
        raise BuildError("component shapes exceed their fixed PoC ranges")

    mapping: dict[tuple[str, int, int], int] = {}
    shape_at: dict[int, tuple[int, ...]] = {}
    for index, (shape, keys) in zip(range(CHO_START, CHO_START + CHO_CAPACITY), cho_groups):
        shape_at[index] = shape
        for key in keys:
            mapping[key] = index
    for index, (shape, keys) in zip(range(REST_START, REST_START + REST_CAPACITY), rest_groups):
        shape_at[index] = shape
        for key in keys:
            mapping[key] = index
    if set(mapping) != all_keys or len(shape_at) != 29:
        raise BuildError("component mapping is incomplete")
    if any(len(encode_index(index) or b"") != 2 for index in shape_at):
        raise BuildError("PoC component unexpectedly lacks a two-byte encoding")

    # The official component rule is authoritative.  This metric is recorded
    # only as a rasterization diagnostic, never used to choose a beol.
    raster_hamming: dict[str, int] = {}
    for ch in sorted(all_syllables):
        composed = or_rows([bitmaps[key] for key in component_keys(ch)])
        direct = render_syllable(face, ch)
        raster_hamming[ch] = sum(
            (left ^ right).bit_count()
            for left, right in zip(composed, direct)
        )

    step("보수적 참조 목록과 비문자 GPU 소비 기록으로 29개 칸 검증")
    references, dialogue_site_count, exe_site_count = collect_conservative_references(members)
    cell_audit, audit_states = load_cell_audit()
    if SAFE_FILLER_INDEX in shape_at:
        raise BuildError("safe filler overlaps a rendered component plane")
    slot_audit: dict[int, dict[str, int | bool]] = {}
    audited_indices = set(shape_at) | {SAFE_FILLER_INDEX}
    for index in sorted(audited_indices):
        col, row, plane = cell_of(index)
        if index in references:
            raise BuildError(f"planned glyph index is referenced by original text: {index}")
        if any(read_plane(original_comm, index)):
            raise BuildError(f"planned glyph index is not blank: {index}")
        if (row, col) not in cell_audit:
            raise BuildError(f"planned glyph cell is absent from runtime audit: row {row}, col {col}")
        text_reads, nontext_reads = cell_audit[(row, col)]
        if text_reads <= 0 or nontext_reads != 0:
            raise BuildError(
                f"planned glyph cell is not text-only in the audit: "
                f"index {index}, text={text_reads}, nontext={nontext_reads}"
            )
        slot_audit[index] = {
            "row": row,
            "col": col,
            "plane": plane,
            "text_reads": text_reads,
            "nontext_reads": nontext_reads,
            "referenced": False,
            "original_ink": False,
        }

    scratch = dict(members)
    expected_allowed: dict[str, set[int]] = {name: set() for name in EXPECTED_CHANGED_MEMBERS}

    step("COMM.IMG에 29개 조합 부품 삽입")
    comm = bytearray(original_comm)
    target_indices = set(shape_at)
    target_cells = {index // PLANES for index in target_indices}
    neighbour_before = {
        index: read_plane(original_comm, index)
        for cell in target_cells
        for index in range(cell * PLANES, cell * PLANES + PLANES)
        if index not in target_indices
    }
    for index, shape in sorted(shape_at.items()):
        expected_allowed[COMM] |= put_plane(comm, index, shape)
        if read_plane(comm, index) != shape:
            raise BuildError(f"glyph round-trip mismatch at index {index}")
    for index, before in neighbour_before.items():
        if read_plane(comm, index) != before:
            raise BuildError(f"neighbour plane changed at index {index}")
    if inked_planes_hash(comm, original_inked) != ORIGINAL_INKED_PLANES_SHA256:
        raise BuildError("an original inked glyph plane changed")
    scratch[COMM] = bytes(comm)

    step("세 개의 S1071 진단 본문을 고정 길이로 삽입")
    dat = bytearray(members[TEST_DAT])
    text_rows: list[dict[str, object]] = []

    def encode_text(text: str) -> bytes:
        encoded = bytearray()
        for ch in text:
            if ch == " ":
                encoded.append(SPACE_BYTE)
                continue
            for key in component_keys(ch):
                code = encode_index(mapping[key])
                if code is None:
                    raise BuildError(f"unencodable mapped component {key}")
                encoded += code
        return bytes(encoded)

    # Keep the line-break counts used by the accepted story_test_07 skeleton.
    # The final one-byte blank makes each remainder divisible by the two-byte
    # E0 9D filler without introducing a premature terminator.  E0 9D draws
    # the untouched blank plane at index 1141 and the helper suppresses X
    # advance for it; its ordinal still advances like every rendered glyph.
    layout_cores = (
        ORIGINAL_SPEAKER_PREFIX
        + NEWLINE
        + encode_text("\uCD9C\uD640\uC904")  # 출홀줄
        + NEWLINE
        + encode_text("\uD558\uD5C8\uD638")  # 하허호
        + bytes((SPACE_BYTE,)),
        encode_text("\uAC01 \uAC1D")          # 각 객
        + NEWLINE
        + encode_text("\uAC71 \uACE1")       # 걱 곡
        + bytes((SPACE_BYTE,)),
        ORIGINAL_SPEAKER_PREFIX
        + NEWLINE
        + encode_text("\uAC00 \uB098 \uACE0")  # 가 나 고
        + NEWLINE
        + encode_text("\uAD6C \uACFC \uC6CC")  # 구 과 워
        + bytes((SPACE_BYTE,)),
    )
    if len(layout_cores) != len(TEST_SITES):
        raise BuildError("diagnostic layout count drifted")

    for site_no, ((offset, capacity, text), core) in enumerate(
        zip(TEST_SITES, layout_cores, strict=True)
    ):
        original_boundary = bytes(dat[offset + capacity : offset + capacity + 8])
        if not original_boundary or original_boundary[0] != 0:
            raise BuildError(f"S1071 test body at {offset:#x} has no expected terminator")
        remaining = capacity - len(core)
        if remaining < 0 or remaining % len(safe_filler_code):
            raise BuildError(
                f"diagnostic layout at {offset:#x} cannot reach its fixed boundary: "
                f"core {len(core)}, capacity {capacity}"
            )
        filler_count = remaining // len(safe_filler_code)
        payload = core + safe_filler_code * filler_count
        if len(payload) != capacity:
            raise BuildError(f"diagnostic body length drifted at {offset:#x}")
        glyph_count, controls = profile_inline_body(payload)
        expected_controls = [NEWLINE] * PROVEN_LINEBREAK_COUNTS[site_no]
        if controls != expected_controls:
            raise BuildError(
                f"diagnostic control skeleton drifted at {offset:#x}: "
                f"{[token.hex() for token in controls]}"
            )
        if glyph_count >= TEXT_OBJECT_GLYPH_LIMIT:
            raise BuildError(
                f"diagnostic body at {offset:#x} needs {glyph_count} glyph packets"
            )
        dat[offset : offset + capacity] = payload
        if bytes(dat[offset + capacity : offset + capacity + 8]) != original_boundary:
            raise BuildError(f"terminator/trailer changed at {offset:#x}")
        expected_allowed[TEST_DAT].update(range(offset, offset + capacity))
        text_rows.append(
            {
                "member": TEST_DAT,
                "offset": f"0x{offset:X}",
                "capacity": capacity,
                "body_bytes": len(payload),
                "safe_filler_bytes": filler_count * len(safe_filler_code),
                "safe_filler_tokens": filler_count,
                "glyph_tokens": glyph_count,
                "linebreak_tokens": len(controls),
                "terminator_offset": f"0x{offset + capacity:X}",
                "internal_zero_bytes": payload.count(0),
                "text": text,
                "encoded_hex": payload.hex(" ").upper(),
            }
        )
    scratch[TEST_DAT] = bytes(dat)

    step("범위 판정 커서 전진 helper와 단일 훅 삽입")
    exe = bytearray(members[PSX])
    hook_offset = file_offset(exe, ADVANCE_HOOK)
    helper_offset = file_offset(exe, ADVANCE_HELPER)
    cave_end_offset = file_offset(exe, CAVE_END - 1) + 1
    original_words = struct.unpack_from(f"<{len(ORIGINAL_ADVANCE_WORDS)}I", exe, hook_offset)
    if original_words != ORIGINAL_ADVANCE_WORDS:
        raise BuildError("original cursor-advance instruction guard failed")
    if any(exe[helper_offset:cave_end_offset]):
        raise BuildError("selected PSX.EXE cave is not all zero")
    helper = make_advance_helper(REST_START, NONADVANCE_COUNT)
    if helper_offset + len(helper) > cave_end_offset:
        raise BuildError("advance helper overflows the zero cave")
    disassembly = disassemble_helper(helper)
    exe[helper_offset : helper_offset + len(helper)] = helper
    struct.pack_into("<I", exe, hook_offset, j_word(ADVANCE_HELPER))
    struct.pack_into("<I", exe, hook_offset + 4, 0x90C3000D)  # lbu v1,0xD(a2), jump delay
    expected_allowed[PSX].update(range(helper_offset, helper_offset + len(helper)))
    expected_allowed[PSX].update(range(hook_offset, hook_offset + 8))
    scratch[PSX] = bytes(exe)

    # Boundary truth table for the unsigned subtraction + sltiu range test.
    for index in (0, REST_START - 1, REST_START, REST_START + NONADVANCE_COUNT - 1,
                  REST_START + NONADVANCE_COUNT, MAX_GLYPH_INDEX):
        machine_inside = ((index - REST_START) & 0xFFFFFFFF) < NONADVANCE_COUNT
        expected_inside = REST_START <= index < REST_START + NONADVANCE_COUNT
        if machine_inside != expected_inside:
            raise BuildError(f"advance-helper range predicate failed for index {index}")

    step("Expected Write와 최종 멤버 diff 검증")
    for name in members:
        if len(scratch[name]) != len(members[name]):
            raise BuildError(f"member size changed: {name}")
    changed = {name for name in members if scratch[name] != members[name]}
    if changed != EXPECTED_CHANGED_MEMBERS:
        raise BuildError(f"changed-member set mismatch: {sorted(changed)}")

    actual_diffs: dict[str, set[int]] = {}
    for name in sorted(EXPECTED_CHANGED_MEMBERS):
        actual = diff_offsets(members[name], scratch[name])
        actual_diffs[name] = actual
        unexpected = actual - expected_allowed[name]
        if unexpected:
            first = min(unexpected)
            raise BuildError(f"unexpected write in {name} at {first:#x}")
        if not actual:
            raise BuildError(f"expected changed member has no byte differences: {name}")

    step("재현 가능한 전체 arc.zip TEST_ONLY 출력")
    args.output_dir.mkdir(parents=True, exist_ok=True)
    temp = args.output_dir / f".{OUTPUT_STEM}_{os.getpid()}.building.zip"
    if temp.exists():
        raise BuildError(f"temporary output already exists: {temp}")
    try:
        with ZipFile(temp, "w", ZIP_DEFLATED, compresslevel=1) as archive:
            for info in infos:
                if info.is_dir():
                    archive.writestr(clone_zipinfo(info), b"")
                else:
                    archive.writestr(clone_zipinfo(info), scratch[info.filename])
        output_hash = sha256_file(temp)
        output = args.output_dir / f"{OUTPUT_STEM}_{output_hash[:8]}.zip"
        if output.exists():
            if sha256_file(output) != output_hash:
                raise BuildError(f"output-name collision: {output}")
            temp.unlink()
        else:
            temp.replace(output)
    finally:
        if temp.exists():
            temp.unlink()

    with ZipFile(output) as archive:
        out_names = archive.namelist()
        if out_names != [info.filename for info in infos]:
            raise BuildError("output ZIP member order/name list drifted")
        for info in infos:
            if info.is_dir():
                continue
            data = archive.read(info.filename)
            if data != scratch[info.filename]:
                raise BuildError(f"output ZIP round-trip mismatch: {info.filename}")

    # The full archive is the reproducible build container.  Disc packaging
    # uses a three-member patch-only archive so validators do not mistake raw
    # XA/STR sector streams (or non-ISO license_data.dat) for ordinary cooked
    # ISO files.
    step("변경 멤버 3개 patch-only ZIP 출력")
    patch_temp = args.output_dir / f".{OUTPUT_STEM}_patch_{os.getpid()}.building.zip"
    if patch_temp.exists():
        raise BuildError(f"temporary patch output already exists: {patch_temp}")
    try:
        with ZipFile(patch_temp, "w", ZIP_DEFLATED, compresslevel=1) as archive:
            for info in infos:
                if not info.is_dir() and info.filename in EXPECTED_CHANGED_MEMBERS:
                    archive.writestr(clone_zipinfo(info), scratch[info.filename])
        patch_hash = sha256_file(patch_temp)
        patch_output = args.output_dir / f"{OUTPUT_STEM}_patch_{patch_hash[:8]}.zip"
        if patch_output.exists():
            if sha256_file(patch_output) != patch_hash:
                raise BuildError(f"patch output-name collision: {patch_output}")
            patch_temp.unlink()
        else:
            patch_temp.replace(patch_output)
    finally:
        if patch_temp.exists():
            patch_temp.unlink()

    with ZipFile(patch_output) as archive:
        patch_names = [info.filename for info in archive.infolist() if not info.is_dir()]
        expected_patch_names = [
            info.filename
            for info in infos
            if not info.is_dir() and info.filename in EXPECTED_CHANGED_MEMBERS
        ]
        if patch_names != expected_patch_names:
            raise BuildError(f"patch-only member order/list drifted: {patch_names}")
        for name in patch_names:
            if archive.read(name) != scratch[name]:
                raise BuildError(f"patch-only ZIP round-trip mismatch: {name}")

    step("분석 매니페스트 작성")
    args.analysis_dir.mkdir(parents=True, exist_ok=True)

    component_rows: list[dict[str, object]] = []
    for key in sorted(mapping):
        index = mapping[key]
        kind, beol, jamo = key
        bitmap = bitmaps[key]
        component_rows.append(
            {
                "kind": kind,
                "beol": beol,
                "jamo_index": jamo,
                "pua": f"U+{component_pua(key):04X}",
                "glyph_index": index,
                "encoded_hex": (encode_index(index) or b"").hex(" ").upper(),
                "bitmap_sha256": sha256_bytes(
                    b"".join(row.to_bytes(2, "big") for row in bitmap)
                ),
                "atlas_row": slot_audit[index]["row"],
                "atlas_col": slot_audit[index]["col"],
                "plane": slot_audit[index]["plane"],
                "text_reads": slot_audit[index]["text_reads"],
                "nontext_reads": slot_audit[index]["nontext_reads"],
            }
        )
    write_csv(
        args.analysis_dir / "component_map.csv",
        [
            "kind", "beol", "jamo_index", "pua", "glyph_index", "encoded_hex",
            "bitmap_sha256", "atlas_row", "atlas_col", "plane", "text_reads",
            "nontext_reads",
        ],
        component_rows,
    )
    write_csv(
        args.analysis_dir / "text_manifest.csv",
        [
            "member", "offset", "capacity", "body_bytes", "safe_filler_bytes",
            "safe_filler_tokens", "glyph_tokens", "linebreak_tokens",
            "terminator_offset", "internal_zero_bytes", "text", "encoded_hex",
        ],
        text_rows,
    )

    write_rows: list[dict[str, object]] = []
    for name in sorted(actual_diffs):
        for start, end in coalesce_offsets(actual_diffs[name]):
            write_rows.append(
                {
                    "member": name,
                    "start": f"0x{start:X}",
                    "end_exclusive": f"0x{end:X}",
                    "length": end - start,
                    "before_hex": members[name][start:end].hex(" ").upper(),
                    "after_hex": scratch[name][start:end].hex(" ").upper(),
                }
            )
    write_csv(
        args.analysis_dir / "actual_writes.csv",
        ["member", "start", "end_exclusive", "length", "before_hex", "after_hex"],
        write_rows,
    )

    (args.analysis_dir / "mips_disassembly.txt").write_text(
        "hook:\n"
        f"{ADVANCE_HOOK:08X}  {j_word(ADVANCE_HELPER):08X}  j 0x{ADVANCE_HELPER:08X}\n"
        f"{ADVANCE_HOOK + 4:08X}  90C3000D  lbu v1,0xD(a2)  # delay slot\n\n"
        "helper:\n" + "\n".join(disassembly) + "\n",
        encoding="utf-8",
    )

    manifest = {
        "status": "TEST_ONLY_STATIC_PASS_RUNTIME_PENDING_FLOWFIX",
        "base": {"path": str(args.base), "sha256": BASE_ZIP_SHA256},
        "font": {
            "profile": args.font_profile,
            "zip_path": str(args.font_zip),
            "zip_sha256": font_zip_hash,
            "member": profile["member"],
            "member_sha256": profile["font_sha256"],
            "pixel_size": GLYPH_SIZE,
            "threshold": ">96",
            "pillow": PIL.__version__,
            "freetype": freetype_version,
        },
        "official_rule": {
            "source_url": RULE_SOURCE_URL,
            "source_sha256": RULE_SOURCE_SHA256,
            "source_size": RULE_SOURCE_SIZE,
            "cho_without_jong": CHO_KIND_WITHOUT_JONG,
            "cho_with_jong": CHO_KIND_WITH_JONG,
            "jong_by_jung": JONG_KIND_BY_JUNG,
            "jung_rule": "0/2 for choseong indices 0 or 15; otherwise 1/3",
        },
        "component_counts": {
            "logical_cho": len(cho_keys),
            "unique_cho_bitmaps": len(cho_groups),
            "logical_jung_jong": len(rest_keys),
            "unique_jung_jong_bitmaps": len(rest_groups),
            "written_planes": len(shape_at),
        },
        "ranges": {
            "advancing_cho": [CHO_START, CHO_START + len(cho_groups) - 1],
            "nonadvancing_jung_jong": [REST_START, REST_START + len(rest_groups) - 1],
            "nonadvancing_blank_filler": SAFE_FILLER_INDEX,
            "nonadvancing_helper": [REST_START, REST_START + NONADVANCE_COUNT - 1],
        },
        "fixed_length_flow": {
            "proven_story_test_07_linebreak_counts": PROVEN_LINEBREAK_COUNTS,
            "safe_filler_index": SAFE_FILLER_INDEX,
            "safe_filler_code": safe_filler_code.hex(" ").upper(),
            "early_zero_bytes": sum(int(row["internal_zero_bytes"]) for row in text_rows),
            "original_terminators_preserved": True,
            "site_rows": text_rows,
        },
        "reference_catalog": {
            "dialogue_sites": dialogue_site_count,
            "exe_pointer_strings": exe_site_count,
            "referenced_glyph_indices": len(references),
            "runtime_audit_states": audit_states,
        },
        "mips": {
            "hook": f"0x{ADVANCE_HOOK:08X}",
            "helper": f"0x{ADVANCE_HELPER:08X}",
            "helper_bytes": len(helper),
            "cave_end": f"0x{CAVE_END:08X}",
        },
        "diagnostic_raster_hamming": raster_hamming,
        "zip_runtime": {
            "zlib_compile_version": zlib.ZLIB_VERSION,
            "zlib_runtime_version": zlib.ZLIB_RUNTIME_VERSION,
            "compresslevel": 1,
        },
        "changed_members": sorted(changed),
        "changed_byte_counts": {name: len(actual_diffs[name]) for name in sorted(actual_diffs)},
        "full_output": {
            "path": str(output),
            "sha256": output_hash,
            "size": output.stat().st_size,
        },
        "patch_output": {
            "path": str(patch_output),
            "sha256": patch_hash,
            "size": patch_output.stat().st_size,
            "members": patch_names,
        },
        "runtime": "PENDING_USER_COLD_BOOT_NATURAL_DIALOGUE_PROGRESSION",
    }
    (args.analysis_dir / "build_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    report = [
        "Arc the Lad 1 clean Pilgi johab font flow-fix PoC",
        "status=TEST_ONLY STATIC PASS; runtime=PENDING USER COLD BOOT + NATURAL DIALOGUE PROGRESSION",
        f"base_sha256={BASE_ZIP_SHA256}",
        f"font_zip_sha256={font_zip_hash}",
        f"font_member={profile['member']} sha256={profile['font_sha256']}",
        f"renderer=Pillow {PIL.__version__}; FreeType {freetype_version}; 12px; threshold >96",
        "rule=official iolo/8x4x4-fonts generate_hangul_syllables.py arrays; "
        f"source_sha256={RULE_SOURCE_SHA256}",
        f"zip_runtime=zlib compile {zlib.ZLIB_VERSION}; runtime {zlib.ZLIB_RUNTIME_VERSION}; level 1",
        f"components=cho {len(cho_keys)} logical/{len(cho_groups)} bitmaps; "
        f"jung+jong {len(rest_keys)} logical/{len(rest_groups)} bitmaps; total {len(shape_at)} planes",
        f"atlas=cho {CHO_START}..{CHO_START + len(cho_groups) - 1}; "
        f"jung+jong {REST_START}..{REST_START + len(rest_groups) - 1}",
        f"safe_filler=index {SAFE_FILLER_INDEX} code {safe_filler_code.hex(' ').upper()}; "
        f"helper_nonadvance={REST_START}..{REST_START + NONADVANCE_COUNT - 1}",
        f"safety=blank+unreferenced 30/30; text-read 30/30; nontext-read 0/30 across {audit_states} states",
        "fixed_length_flow=early_zero 0/3 bodies; original terminators 3/3; "
        f"linebreak_counts={'/'.join(map(str, PROVEN_LINEBREAK_COUNTS))}",
        f"conservative_referenced_indices={len(references)}",
        f"original_inked_planes=996 sha256={ORIGINAL_INKED_PLANES_SHA256} unchanged",
        f"mips=range-aware helper {len(helper)}B at 0x{ADVANCE_HELPER:08X}; hook 0x{ADVANCE_HOOK:08X}",
        "features_absent=dynamic cache, E2, external slots, UI repack, bulk translation, expanded EXE",
        "changed_members=" + ", ".join(sorted(changed)),
        "changed_byte_counts=" + ", ".join(f"{name}:{len(actual_diffs[name])}" for name in sorted(actual_diffs)),
        f"output={output.name}",
        f"output_size={output.stat().st_size}",
        f"output_sha256={output_hash}",
        f"patch_output={patch_output.name}",
        f"patch_output_size={patch_output.stat().st_size}",
        f"patch_output_sha256={patch_hash}",
        "next=package patch-only ZIP with arc1_original_layout.xml, verify 506/506 LBA, then DuckStation cold boot",
    ]
    (args.analysis_dir / "build_report.txt").write_text("\n".join(report) + "\n", encoding="utf-8")
    print("\n".join(report))


if __name__ == "__main__":
    try:
        main()
    except BuildError as error:
        raise SystemExit(f"GUARD FAILED: {error}") from error
