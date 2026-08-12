"""v159: replace four fixed VRAM strips with a 20-slot on-demand glyph cache.

The cache uses exact completed 12x12 bitmaps.  It is not a compositional font.  Every
dynamic glyph is stored as twelve references into a dictionary of exact 12-bit rows.

The build keeps v151's 5,356-byte reserved-RAM boundary unchanged, restores the stock
single-page text renderer, restores the original COMM.IMG font grid, and writes Korean
only into planes whose original counterpart was non-blank.  Twenty original-text
planes become cache slots.  On each E9/EA dynamic lookup the decoder marks one slot
active; at the verified frame boundary the slot's cell is read back, one bitplane is
replaced, and the whole cell is returned to VRAM.
"""
from __future__ import annotations

import csv
import hashlib
import pickle
import struct
import sys
import zipfile
from collections import defaultdict
from pathlib import Path
from zipfile import ZipFile, ZipInfo

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))
sys.path.insert(0, str(ROOT / "06_tools/python_packages"))

from capstone import Cs, CS_ARCH_MIPS, CS_MODE_LITTLE_ENDIAN, CS_MODE_MIPS32  # noqa: E402
from build_ui_hud_e7_v73_dual_tpage_renderer import (  # noqa: E402
    Assembler, i_type, j, jal, r_type,
)
from audit_dynamic_cache_requirements import (  # noqa: E402
    BUILD as BASE_ZIP, BUILD_SHA as BASE_SHA, ORIGINAL, active_slots, bitmap, glyph_index,
    read_lut, source_ranges,
)
from plan_bulk_insertion import (  # noqa: E402
    CACHE, CELL, IPR, PLANES, SLOT_BASE, SLOT_COUNT, SLOT_SIZE, tokens,
)

PLAN = ROOT / "01_work/analysis/dynamic_cache_v153_widthsafe"
ASSIGNMENTS = PLAN / "glyph_assignments.csv"
CACHE_SLOTS = PLAN / "cache_slots.csv"
PROTECTED_RELOCATIONS = PLAN / "protected_virtual_relocations.csv"
PLANNED_LOOKUP = PLAN / "lookup_table.bin"
PLANNED_DICTIONARY = PLAN / "row_dictionary.bin"
PLANNED_GLYPHS = PLAN / "dynamic_glyph_rows.bin"

OUT_DIR = ROOT / "03_output"
OUT_STEM = "arc1_v159_dynamic_cache"
ANALYSIS = ROOT / "01_work/analysis/arc1_v159_dynamic_cache"
REPORT = ANALYSIS / "build_report.txt"
DISASSEMBLY = ANALYSIS / "mips_disassembly.txt"
BUILD_TITLE = "v159 on-demand 20-slot completed-glyph cache"
USE_VRAM_READBACK = True

PSX, COMM = "PSX.EXE", "COMM.IMG"
RAM_TO_FILE = 0x8011A800
SOURCE_BASE, RESIDENT_BASE, COPY_N = 0x801A86EC, 0x801FE3C4, 5356
HEAP_BASE = RESIDENT_BASE + COPY_N
LOOKUP_RAM, LOOKUP_N = 0x801A7520, 409
CACHE_N = 20

LOADIMAGE, STOREIMAGE = 0x80177E4C, 0x801780FC
FRAMESWAP, FRAME_HOOK = 0x8011C814, 0x8011C4AC
DECODER_ENTRY = 0x801A74B8
DECODE_RETURN, SINGLE_PATH, WIDE_PATH = 0x8016B410, 0x8016B3E0, 0x8016B3F0
GLYPH_INDEX_RETURN = 0x8016B410
REMAP_HOOK, GLYPH_PACKET_HOOK, RENDER_HOOK = 0x8016B410, 0x8016B5D8, 0x8016B764
MEMCPY_LEN_AT, HEAP_BASE_AT = 0x801757CC, 0x80175810

# MIPS registers.
ZERO, AT, V0, V1 = 0, 1, 2, 3
A0, A1, A2, A3 = 4, 5, 6, 7
T0, T1, T2, T3, T4, T5, T6, T7 = 8, 9, 10, 11, 12, 13, 14, 15
S0, S1, S2, S3, S4, S5, S6, S7 = 16, 17, 18, 19, 20, 21, 22, 23
T8, T9, SP, RA = 24, 25, 29, 31
NOP = 0
JR_RA = r_type(RA, ZERO, ZERO, 0, 0x08)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def clone(info: ZipInfo) -> ZipInfo:
    out = ZipInfo(info.filename, info.date_time)
    for attr in ("compress_type", "comment", "extra", "create_system", "create_version",
                 "extract_version", "flag_bits", "volume", "internal_attr",
                 "external_attr"):
        setattr(out, attr, getattr(info, attr))
    return out


def file_at(address: int) -> int:
    return address - RAM_TO_FILE


def word(buf: bytes | bytearray, address: int) -> int:
    return struct.unpack_from("<I", buf, file_at(address))[0]


def put_word(buf: bytearray, address: int, value: int) -> None:
    struct.pack_into("<I", buf, file_at(address), value)


def load_address(asm: Assembler, register: int, address: int) -> None:
    asm.emit(i_type(0x0F, ZERO, register, address >> 16))
    asm.emit(i_type(0x0D, register, register, address & 0xFFFF))


def move(rd: int, rs: int) -> int:
    return r_type(rs, ZERO, rd, 0, 0x21)


def make_cache_state(font: bytes | bytearray,
                     cache_rows: list[dict[str, str]]) -> bytes:
    """Return v159's single-cell GPU readback scratch buffer."""
    del font, cache_rows
    return bytes(72)


def build_decoder(address: int, owners: int, active: int, next_slot: int,
                  cache_indices: int) -> bytes:
    """Resolve E9/EA, assigning a cache slot when the table entry has bit 15 set."""
    asm = Assembler(address)
    asm.emit(i_type(0x09, V1, T0, -0xE9))                 # lead - E9
    asm.emit(i_type(0x0B, T0, T1, 2))
    asm.branch(0x04, T1, ZERO, "not_lookup")
    asm.emit(NOP)

    asm.emit(i_type(0x24, A1, T1, 1))                    # trail
    asm.emit(r_type(ZERO, T0, T2, 8, 0x00))              # lead * 256
    asm.emit(r_type(T2, T0, T2, 0, 0x23))                # - lead
    asm.emit(r_type(T2, T0, T2, 0, 0x23))                # * 254
    asm.emit(r_type(T2, T1, T2, 0, 0x21))
    asm.emit(i_type(0x09, T2, T2, -1))                   # virtual slot
    asm.emit(i_type(0x0B, T2, T9, LOOKUP_N))
    asm.branch(0x04, T9, ZERO, "invalid_lookup")
    asm.emit(NOP)
    asm.emit(r_type(ZERO, T2, T3, 1, 0x00))
    load_address(asm, T4, LOOKUP_RAM)
    asm.emit(r_type(T4, T3, T3, 0, 0x21))
    asm.emit(i_type(0x25, T3, T4, 0))                    # table entry
    asm.emit(NOP)
    asm.emit(i_type(0x0C, T4, T5, 0x8000))
    asm.branch(0x04, T5, ZERO, "static")
    asm.emit(NOP)

    asm.emit(i_type(0x0C, T4, T4, 0x7FFF))               # source id
    load_address(asm, T5, owners)
    asm.emit(move(T6, ZERO))
    asm.label("scan")
    asm.emit(i_type(0x25, T5, T7, 0))
    asm.emit(NOP)
    asm.branch(0x04, T7, T4, "cache_ready")
    asm.emit(NOP)
    asm.emit(i_type(0x09, T6, T6, 1))
    asm.emit(i_type(0x0B, T6, T7, CACHE_N))
    asm.branch(0x05, T7, ZERO, "scan")
    asm.emit(i_type(0x09, T5, T5, 2))                    # delay: next owner

    # Miss: round-robin replacement. Owners hold source ids; the lookup stays immutable.
    load_address(asm, T5, next_slot)
    asm.emit(i_type(0x24, T5, T6, 0))
    asm.emit(NOP)
    asm.emit(i_type(0x09, T6, T7, 1))
    asm.emit(i_type(0x0B, T7, T8, CACHE_N))
    asm.branch(0x05, T8, ZERO, "next_ok")
    asm.emit(NOP)
    asm.emit(move(T7, ZERO))
    asm.label("next_ok")
    asm.emit(i_type(0x28, T5, T7, 0))
    load_address(asm, T5, owners)
    asm.emit(r_type(ZERO, T6, T7, 1, 0x00))
    asm.emit(r_type(T5, T7, T5, 0, 0x21))
    asm.emit(i_type(0x29, T5, T4, 0))

    asm.label("cache_ready")
    asm.emit(i_type(0x0D, ZERO, T7, 1))
    asm.emit(r_type(T6, T7, T7, 0, 0x04))                # 1 << cache slot
    load_address(asm, T5, active)
    asm.emit(i_type(0x23, T5, T8, 0))
    asm.emit(NOP)
    asm.emit(r_type(T8, T7, T8, 0, 0x25))
    asm.emit(i_type(0x2B, T5, T8, 0))
    load_address(asm, T5, cache_indices)
    asm.emit(r_type(ZERO, T6, T7, 1, 0x00))
    asm.emit(r_type(T5, T7, T5, 0, 0x21))
    asm.emit(i_type(0x25, T5, V1, 0))
    asm.emit(NOP)
    asm.branch(0x04, ZERO, ZERO, "finish")
    asm.emit(NOP)

    asm.label("invalid_lookup")
    asm.emit(move(V1, ZERO))                             # blank glyph
    asm.branch(0x04, ZERO, ZERO, "finish")
    asm.emit(NOP)
    asm.label("static")
    asm.emit(move(V1, T4))
    asm.label("finish")
    asm.emit(i_type(0x09, A1, V0, 2))
    asm.emit(i_type(0x2B, A2, V0, 0))
    asm.emit(j(DECODE_RETURN))
    asm.emit(NOP)

    asm.label("not_lookup")
    asm.emit(i_type(0x0B, V1, V0, 0xDD))
    asm.branch(0x04, V0, ZERO, "wide")
    asm.emit(NOP)
    asm.emit(j(SINGLE_PATH))
    asm.emit(NOP)
    asm.label("wide")
    asm.emit(j(WIDE_PATH))
    asm.emit(NOP)
    return asm.finish()


def build_frame(address: int, owners: int, active: int, cache_indices: int,
                row_dictionary: int, glyph_rows: int, rect: int, scratch: int) -> bytes:
    """Upload active cache planes at the proven GPU-idle frame boundary."""
    asm = Assembler(address)
    asm.emit(i_type(0x09, SP, SP, -0x50))
    for reg, offset in ((RA, 0x4C), (S0, 0x48), (S1, 0x44), (S2, 0x40),
                        (S3, 0x3C), (S4, 0x38), (S5, 0x34), (S6, 0x30),
                        (S7, 0x2C)):
        asm.emit(i_type(0x2B, SP, reg, offset))
    asm.emit(i_type(0x2B, SP, A0, 0x20))                 # frame-swap argument

    load_address(asm, T0, active)
    asm.emit(i_type(0x23, T0, S0, 0))
    asm.emit(NOP)
    asm.emit(i_type(0x2B, T0, ZERO, 0))                  # consume this frame's mask
    asm.branch(0x04, S0, ZERO, "swap")
    asm.emit(NOP)
    asm.emit(move(S1, ZERO))
    load_address(asm, S2, owners)
    load_address(asm, S3, cache_indices)
    load_address(asm, S4, row_dictionary)
    load_address(asm, S5, glyph_rows)
    load_address(asm, S6, rect)
    load_address(asm, S7, scratch)

    asm.label("slot_loop")
    asm.emit(i_type(0x0D, ZERO, T0, 1))
    asm.emit(r_type(S1, T0, T0, 0, 0x04))                # 1 << slot
    asm.emit(r_type(S0, T0, T0, 0, 0x24))
    asm.branch(0x04, T0, ZERO, "slot_next")
    asm.emit(NOP)

    asm.emit(r_type(ZERO, S1, T0, 1, 0x00))
    asm.emit(r_type(S2, T0, T3, 0, 0x21))
    asm.emit(i_type(0x25, T3, T1, 0))                    # source id
    asm.emit(r_type(S3, T0, T3, 0, 0x21))
    asm.emit(i_type(0x25, T3, T2, 0))                    # physical index
    asm.emit(NOP)
    asm.emit(i_type(0x29, SP, T1, 0x10))

    asm.emit(i_type(0x0D, ZERO, T3, IPR))
    asm.emit(r_type(T2, T3, ZERO, 0, 0x1A))              # div index,84
    asm.emit(NOP)
    asm.emit(NOP)
    asm.emit(r_type(ZERO, ZERO, T4, 0, 0x12))            # row
    asm.emit(r_type(ZERO, ZERO, T5, 0, 0x10))            # remainder
    asm.emit(i_type(0x0D, ZERO, T3, PLANES))
    asm.emit(r_type(T5, T3, ZERO, 0, 0x1A))              # div remainder,4
    asm.emit(NOP)
    asm.emit(NOP)
    asm.emit(r_type(ZERO, ZERO, T5, 0, 0x12))            # column
    asm.emit(r_type(ZERO, ZERO, T6, 0, 0x10))            # plane
    asm.emit(i_type(0x29, SP, T6, 0x12))

    asm.emit(r_type(ZERO, T5, T7, 1, 0x00))
    asm.emit(r_type(T7, T5, T7, 0, 0x21))                # column * 3
    asm.emit(i_type(0x09, T7, T7, 320))                  # VRAM x in 16-bit units
    asm.emit(i_type(0x29, S6, T7, 0))
    asm.emit(r_type(ZERO, T4, T7, 1, 0x00))
    asm.emit(r_type(T7, T4, T7, 0, 0x21))
    asm.emit(r_type(ZERO, T7, T7, 2, 0x00))              # row * 12
    asm.emit(i_type(0x29, S6, T7, 2))
    asm.emit(i_type(0x0D, ZERO, T7, 3))
    asm.emit(i_type(0x29, S6, T7, 4))
    asm.emit(i_type(0x0D, ZERO, T7, 12))
    asm.emit(i_type(0x29, S6, T7, 6))

    if USE_VRAM_READBACK:
        asm.emit(move(A0, S6))
        asm.emit(move(A1, S7))
        asm.emit(jal(STOREIMAGE))
        asm.emit(NOP)

    # Source pointer = glyph_rows + source_id * 12.
    asm.emit(i_type(0x25, SP, T1, 0x10))
    asm.emit(i_type(0x25, SP, T6, 0x12))
    asm.emit(NOP)
    asm.emit(r_type(ZERO, T1, T2, 1, 0x00))
    asm.emit(r_type(T2, T1, T2, 0, 0x21))
    asm.emit(r_type(ZERO, T2, T2, 2, 0x00))
    asm.emit(r_type(S5, T2, T2, 0, 0x21))

    # Clear mask for both nibbles and the unshifted plane bit.
    asm.emit(i_type(0x0D, ZERO, T9, 1))
    asm.emit(r_type(T6, T9, T9, 0, 0x04))
    asm.emit(i_type(0x29, SP, T9, 0x14))
    asm.emit(r_type(ZERO, T9, T8, 4, 0x00))
    asm.emit(r_type(T8, T9, T8, 0, 0x25))
    asm.emit(r_type(T8, ZERO, T8, 0, 0x27))
    asm.emit(i_type(0x0C, T8, T8, 0x00FF))

    asm.emit(move(T0, ZERO))                              # row counter
    if USE_VRAM_READBACK:
        asm.emit(move(T4, S7))                            # scratch row pointer
    else:
        # Five physical cells back the 20 planes.  Keep a persistent 72-byte
        # RAM shadow per cell, so no GPU->RAM readback is needed.
        asm.emit(r_type(ZERO, S1, T4, 2, 0x02))           # cell = slot / 4
        asm.emit(r_type(ZERO, T4, T7, 3, 0x00))           # cell * 8
        asm.emit(r_type(ZERO, T4, T4, 6, 0x00))           # cell * 64
        asm.emit(r_type(T4, T7, T4, 0, 0x21))             # cell * 72
        asm.emit(r_type(S7, T4, T4, 0, 0x21))             # shadow cell
    asm.label("row_loop")
    asm.emit(i_type(0x24, T2, T1, 0))                    # row dictionary id
    asm.emit(i_type(0x09, T2, T2, 1))
    asm.emit(r_type(ZERO, T1, T1, 1, 0x00))
    asm.emit(r_type(S4, T1, T1, 0, 0x21))
    asm.emit(i_type(0x25, T1, T3, 0))                    # 12-bit row
    asm.emit(NOP)
    asm.emit(move(T5, ZERO))                              # x
    asm.emit(i_type(0x0D, ZERO, T6, 0x0800))             # leftmost row bit
    asm.label("pixel_loop")
    asm.emit(r_type(ZERO, T5, T7, 1, 0x02))              # x / 2
    asm.emit(r_type(T4, T7, T7, 0, 0x21))
    asm.emit(i_type(0x24, T7, T9, 0))
    asm.emit(NOP)
    asm.emit(r_type(T9, T8, T9, 0, 0x24))                # clear cache plane
    asm.emit(r_type(T3, T6, A3, 0, 0x24))
    asm.branch(0x04, A3, ZERO, "no_set")
    asm.emit(i_type(0x0C, T5, A3, 1))                    # delay: odd pixel?
    asm.emit(i_type(0x25, SP, A2, 0x14))
    asm.emit(NOP)
    asm.branch(0x04, A3, ZERO, "bit_ready")
    asm.emit(NOP)
    asm.emit(r_type(ZERO, A2, A2, 4, 0x00))              # high nibble
    asm.label("bit_ready")
    asm.emit(r_type(T9, A2, T9, 0, 0x25))
    asm.label("no_set")
    asm.emit(i_type(0x28, T7, T9, 0))
    asm.emit(r_type(ZERO, T6, T6, 1, 0x02))
    asm.emit(i_type(0x09, T5, T5, 1))
    asm.emit(i_type(0x0B, T5, A3, CELL))
    asm.branch(0x05, A3, ZERO, "pixel_loop")
    asm.emit(NOP)
    asm.emit(i_type(0x09, T0, T0, 1))
    asm.emit(i_type(0x09, T4, T4, 6))
    asm.emit(i_type(0x0B, T0, T1, CELL))
    asm.branch(0x05, T1, ZERO, "row_loop")
    asm.emit(NOP)

    asm.emit(move(A0, S6))
    if USE_VRAM_READBACK:
        asm.emit(move(A1, S7))
    else:
        asm.emit(i_type(0x09, T4, A1, -72))               # row loop advanced 72
    asm.emit(jal(LOADIMAGE))
    asm.emit(NOP)

    asm.label("slot_next")
    asm.emit(i_type(0x09, S1, S1, 1))
    asm.emit(i_type(0x0B, S1, T0, CACHE_N))
    asm.branch(0x05, T0, ZERO, "slot_loop")
    asm.emit(NOP)

    asm.label("swap")
    asm.emit(i_type(0x23, SP, A0, 0x20))
    asm.emit(NOP)
    asm.emit(jal(FRAMESWAP))
    asm.emit(NOP)
    for reg, offset in ((RA, 0x4C), (S0, 0x48), (S1, 0x44), (S2, 0x40),
                        (S3, 0x3C), (S4, 0x38), (S5, 0x34), (S6, 0x30),
                        (S7, 0x2C)):
        asm.emit(i_type(0x23, SP, reg, offset))
    asm.emit(i_type(0x09, SP, SP, 0x50))
    asm.emit(JR_RA)
    asm.emit(NOP)
    return asm.finish()


def put_plane(font: bytearray, index: int, bits: tuple[int, ...]) -> None:
    row, remainder = divmod(index, IPR)
    column, plane = divmod(remainder, PLANES)
    for y in range(CELL):
        for x in range(CELL):
            px, py = column * CELL + x, row * CELL + y
            at, shift = py * 0x380 + px // 2, (0 if px % 2 == 0 else 4)
            nibble = (font[at] >> shift) & 0xF
            if bits[y * CELL + x]:
                nibble |= 1 << plane
            else:
                nibble &= ~(1 << plane) & 0xF
            font[at] = (font[at] & ~(0xF << shift)) | (nibble << shift)


def plain_bitmap(font: bytes | bytearray, index: int) -> tuple[int, ...]:
    """Read one low-page 12x12 bitplane without any legacy P6 remapping."""
    row, remainder = divmod(index, IPR)
    column, plane = divmod(remainder, PLANES)
    if row >= 21:
        raise ValueError(f"low-page index outside COMM.IMG grid: {index}")
    bits = []
    for y in range(CELL):
        for x in range(CELL):
            px, py = column * CELL + x, row * CELL + y
            at, shift = py * 0x380 + px // 2, (0 if px % 2 == 0 else 4)
            bits.append(((font[at] >> shift) & 0xF) >> plane & 1)
    return tuple(bits)


def main() -> None:
    if digest(BASE_ZIP.read_bytes()) != BASE_SHA:
        raise SystemExit("base archive is not the frozen v151 build")
    for path in (ASSIGNMENTS, CACHE_SLOTS, PROTECTED_RELOCATIONS, PLANNED_LOOKUP,
                 PLANNED_DICTIONARY, PLANNED_GLYPHS):
        if not path.exists():
            raise SystemExit(f"missing plan artifact: {path}")

    with ZipFile(BASE_ZIP) as archive:
        infos = archive.infolist()
        members = {info.filename: archive.read(info.filename) for info in infos}
    base_members = dict(members)
    with ZipFile(ORIGINAL) as archive:
        pristine_exe = archive.read(PSX)
        original_font = archive.read(COMM)

    base_exe, base_font = members[PSX], members[COMM]
    old_lut = read_lut(base_exe)
    shapes: dict[tuple[int, ...], str] = pickle.loads(CACHE.read_bytes())
    bits_by_char = {char: bits for bits, char in shapes.items()}

    with ASSIGNMENTS.open(encoding="utf-8-sig", newline="") as handle:
        assignment_rows = list(csv.DictReader(handle))
    with CACHE_SLOTS.open(encoding="utf-8-sig", newline="") as handle:
        cache_rows = list(csv.DictReader(handle))
    with PROTECTED_RELOCATIONS.open(encoding="utf-8-sig", newline="") as handle:
        relocation_rows = list(csv.DictReader(handle))
    if len(cache_rows) != CACHE_N:
        raise SystemExit(f"cache plan has {len(cache_rows)} slots")
    cache_indices = [int(row["physical_index"]) for row in cache_rows]

    code_by_width: dict[tuple[str, int], bytes] = {}
    static_index: dict[str, int] = {}
    source_char: dict[int, str] = {}
    for row in assignment_rows:
        char = row["char"]
        if row["code_1byte"]:
            code_by_width[(char, 1)] = bytes.fromhex(row["code_1byte"])
        if row["code_2byte"]:
            code_by_width[(char, 2)] = bytes.fromhex(row["code_2byte"])
        if row["kind"] == "static":
            static_index[char] = int(row["physical_index"])
        else:
            source_char[int(row["source_id"])] = char
    if sorted(source_char) != list(range(len(source_char))):
        raise SystemExit("dynamic source ids are not contiguous")

    # Restore the full 21-column font grid to the untouched disc.  Everything outside
    # the grid retains v151's successful UI work.
    font = bytearray(base_font)
    for y in range(512):
        at = y * 0x380
        font[at:at + 126] = original_font[at:at + 126]
    for char, index in static_index.items():
        bits = bits_by_char.get(char)
        if bits is None or not any(bits):
            raise SystemExit(f"missing bitmap for {char!r}")
        put_plane(font, index, bits)

    relocation_bits: dict[int, tuple[int, ...]] = {}
    relocation_destinations: set[int] = set()
    static_destinations = set(static_index.values())
    for relocation in relocation_rows:
        slot = int(relocation["virtual_slot"])
        source_index = int(relocation["source_index"])
        destination_index = int(relocation["destination_index"])
        if destination_index in static_destinations or destination_index in cache_indices:
            raise SystemExit(f"protected relocation {slot} overlaps another glyph")
        bits = bitmap(base_exe, base_font, source_index)
        if not bits or not any(bits) or destination_index in relocation_destinations:
            raise SystemExit(f"invalid protected relocation for virtual slot {slot}")
        put_plane(font, destination_index, bits)
        relocation_destinations.add(destination_index)
        relocation_bits[destination_index] = bits
    if any(font[y * 0x380 + 126:(y + 1) * 0x380]
           != base_font[y * 0x380 + 126:(y + 1) * 0x380] for y in range(512)):
        raise SystemExit("COMM.IMG changed outside the 21-column font grid")
    for char, index in static_index.items():
        if shapes.get(plain_bitmap(font, index)) != char:
            raise SystemExit(f"static glyph readback failed: {char!r} at {index}")

    for destination_index, bits in relocation_bits.items():
        if plain_bitmap(font, destination_index) != bits:
            raise SystemExit(f"protected glyph readback failed at {destination_index}")
    for index in cache_indices:
        row, remainder = divmod(index, IPR)
        column, plane = divmod(remainder, PLANES)
        if row >= 21 or not any(
            ((original_font[(row * CELL + y) * 0x380 + (column * CELL + x) // 2]
              >> (0 if (column * CELL + x) % 2 == 0 else 4)) & 0xF) & (1 << plane)
            for y in range(CELL) for x in range(CELL)
        ):
            raise SystemExit(f"cache index {index} is not an original nonblank plane")
    members[COMM] = bytes(font)

    # Rewrite only bounded text regions, preserving every token width.
    items = source_ranges()
    assigned_slots = active_slots(base_members, items)

    def rewrite(payload: bytes) -> tuple[bytes, int]:
        out, hits = bytearray(), 0
        for token in tokens(payload):
            index = glyph_index(token, old_lut)
            bits = bitmap(base_exe, base_font, index) if index is not None else None
            char = shapes.get(bits) if bits else None
            code = code_by_width.get((char, len(token)))
            if code is None:
                out += token
                continue
            if len(code) != len(token):
                raise SystemExit(f"rewrite width changed for {char!r}")
            out += code
            hits += token != code
        if len(out) != len(payload):
            raise SystemExit("rewrite changed payload length")
        return bytes(out), hits

    by_file: dict[str, list[tuple[int, int]]] = defaultdict(list)
    for name, offset, size in items:
        by_file[name].append((offset, size))
    rewrite_hits = 0
    for name, ranges in by_file.items():
        if name not in members:
            continue
        data = bytearray(members[name])
        for offset, size in ranges:
            payload, count = rewrite(bytes(data[offset:offset + size]))
            data[offset:offset + size] = payload
            rewrite_hits += count
        for slot in assigned_slots.get(name, ()):
            at = SLOT_BASE + slot * SLOT_SIZE
            if any(offset < at + SLOT_SIZE and offset + size > at
                   for offset, size in ranges):
                raise SystemExit(f"active slot overlaps a body: {name}:{slot}")
            block = bytes(data[at:at + SLOT_SIZE])
            if 0 not in block[:SLOT_SIZE - 1]:
                raise SystemExit(f"active slot has no terminator: {name}:{slot}")
            end = block.index(0)
            if not end:
                raise SystemExit(f"active slot is empty: {name}:{slot}")
            payload, count = rewrite(block[:end])
            data[at:at + end] = payload
            rewrite_hits += count
        members[name] = bytes(data)

    exe = bytearray(members[PSX])
    payload, count = rewrite(bytes(exe[0x78000:0x83000]))
    exe[0x78000:0x83000] = payload
    rewrite_hits += count

    # Restore the original low-page index return and packet/renderer entries.
    for address, size in ((REMAP_HOOK, 8), (GLYPH_PACKET_HOOK, 8), (RENDER_HOOK, 8)):
        exe[file_at(address):file_at(address) + size] = \
            pristine_exe[file_at(address):file_at(address) + size]

    # Persistent 409-entry lookup table in its pre-v118 executable location.
    lookup_blob = PLANNED_LOOKUP.read_bytes()
    if len(lookup_blob) != LOOKUP_N * 2:
        raise SystemExit("planned lookup size differs")
    planned_lookup = struct.unpack(f"<{LOOKUP_N}H", lookup_blob)
    for relocation in relocation_rows:
        slot = int(relocation["virtual_slot"])
        destination_index = int(relocation["destination_index"])
        if planned_lookup[slot] != destination_index:
            raise SystemExit(f"protected lookup relocation differs at slot {slot}")
    exe[file_at(LOOKUP_RAM):file_at(LOOKUP_RAM) + len(lookup_blob)] = lookup_blob

    dictionary_blob = PLANNED_DICTIONARY.read_bytes()
    glyph_blob = PLANNED_GLYPHS.read_bytes()
    if len(dictionary_blob) % 2 or len(glyph_blob) != len(source_char) * CELL:
        raise SystemExit("planned glyph data sizes differ")

    # Resident layout.  Keep the v151 copy length and heap boundary exactly unchanged.
    cache_state_blob = make_cache_state(font, cache_rows)
    if not cache_state_blob or len(cache_state_blob) & 3:
        raise SystemExit("cache state must have a nonzero word-aligned size")
    row_dictionary = RESIDENT_BASE
    glyph_rows = row_dictionary + len(dictionary_blob)
    cache_index_ram = glyph_rows + len(glyph_blob)
    owners = cache_index_ram + CACHE_N * 2
    # active is read with lw/sw.  R3000 word accesses must be 4-byte aligned.
    active = (owners + CACHE_N * 2 + 3) & ~3
    next_slot = active + 4
    rect = next_slot + 4
    scratch = rect + 8
    if cache_index_ram & 1 or owners & 1 or active & 3 or rect & 1 or scratch & 1:
        raise SystemExit("resident cache state is not naturally aligned")
    decoder = (scratch + len(cache_state_blob) + 3) & ~3
    decoder_blob = build_decoder(decoder, owners, active, next_slot, cache_index_ram)
    frame = (decoder + len(decoder_blob) + 3) & ~3
    frame_blob = build_frame(frame, owners, active, cache_index_ram,
                             row_dictionary, glyph_rows, rect, scratch)
    used_end = frame + len(frame_blob)
    if used_end > RESIDENT_BASE + COPY_N:
        raise SystemExit(f"resident block exceeds v151 by {used_end - RESIDENT_BASE - COPY_N}")

    resident = bytearray(COPY_N)
    resident[row_dictionary - RESIDENT_BASE:glyph_rows - RESIDENT_BASE] = dictionary_blob
    resident[glyph_rows - RESIDENT_BASE:cache_index_ram - RESIDENT_BASE] = glyph_blob
    struct.pack_into(f"<{CACHE_N}H", resident, cache_index_ram - RESIDENT_BASE,
                     *cache_indices)
    struct.pack_into(f"<{CACHE_N}H", resident, owners - RESIDENT_BASE,
                     *([0xFFFF] * CACHE_N))
    resident[scratch - RESIDENT_BASE:scratch - RESIDENT_BASE + len(cache_state_blob)] = \
        cache_state_blob
    resident[decoder - RESIDENT_BASE:decoder - RESIDENT_BASE + len(decoder_blob)] = decoder_blob
    resident[frame - RESIDENT_BASE:frame - RESIDENT_BASE + len(frame_blob)] = frame_blob
    exe[file_at(SOURCE_BASE):file_at(SOURCE_BASE) + COPY_N] = resident

    # Route the shared E9/EA decoder and frame boundary to the resident routines.
    struct.pack_into("<II", exe, file_at(DECODER_ENTRY), j(decoder), NOP)
    put_word(exe, FRAME_HOOK, jal(frame))

    # Static guards for the unchanged reservation and linked GPU routines.
    copy_ins = word(exe, MEMCPY_LEN_AT)
    if (copy_ins >> 26, (copy_ins >> 16) & 31, copy_ins & 0xFFFF) != (0x09, A2, COPY_N):
        raise SystemExit(f"startup copy is no longer {COPY_N} bytes: 0x{copy_ins:08X}")
    heap_ins = word(exe, HEAP_BASE_AT)
    heap_imm = heap_ins & 0xFFFF
    heap_imm = heap_imm - 0x10000 if heap_imm & 0x8000 else heap_imm
    if 0x80200000 + heap_imm != HEAP_BASE:
        raise SystemExit("v151 heap boundary changed")
    for address in (LOADIMAGE, STOREIMAGE):
        if word(exe, address) != 0x27BDFFD0:
            raise SystemExit(f"GPU transfer prologue differs at 0x{address:08X}")
    if word(exe, GLYPH_INDEX_RETURN) != 0x03E00008 or \
       word(exe, GLYPH_INDEX_RETURN + 4) != 0x00601021:
        raise SystemExit("stock glyph-index return was not restored")
    if word(exe, GLYPH_PACKET_HOOK) != 0x90C2000E or \
       word(exe, RENDER_HOOK) != 0x27BDFFD0:
        raise SystemExit("stock packet builder or renderer was not restored")
    if word(exe, DECODER_ENTRY) != j(decoder) or word(exe, FRAME_HOOK) != jal(frame):
        raise SystemExit("new hooks did not read back")
    if len(exe) != len(base_exe):
        raise SystemExit("PSX.EXE size changed")
    members[PSX] = bytes(exe)

    # Verify all rewritten bounded Hangul through the new table and new font/source.
    new_lut = struct.unpack_from(f"<{LOOKUP_N}H", exe, file_at(LOOKUP_RAM))
    row_dictionary_values = struct.unpack(f"<{len(dictionary_blob)//2}H", dictionary_blob)

    def new_shape(token: bytes) -> tuple[int, ...] | None:
        if len(token) == 1:
            index = token[0] - 1
            return plain_bitmap(font, index)
        if token[0] in (0xE9, 0xEA):
            slot = (token[0] - 0xE9) * 254 + token[1] - 1
            if not 0 <= slot < LOOKUP_N:
                return None
            entry = new_lut[slot]
            if entry & 0x8000:
                source = entry & 0x7FFF
                if source not in source_char:
                    return None
                rows = glyph_blob[source * CELL:(source + 1) * CELL]
                return tuple(
                    1 if row_dictionary_values[rows[y]] & (1 << (CELL - 1 - x)) else 0
                    for y in range(CELL) for x in range(CELL)
                )
            return plain_bitmap(font, entry)
        index = glyph_index(token, ())
        return plain_bitmap(font, index) if index is not None and index < 21 * IPR else None

    verified_tokens = 0
    for name, ranges in by_file.items():
        if name not in members:
            continue
        for offset, size in ranges:
            for token in tokens(members[name][offset:offset + size]):
                bits = new_shape(token)
                char = shapes.get(bits) if bits else None
                if char and any("가" <= c <= "힣" for c in char):
                    verified_tokens += 1
    if not verified_tokens:
        raise SystemExit("no rewritten Hangul token verified")

    # Assemble/disassemble readback and archive round-trip.
    md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN)
    disasm = []
    for start, blob, label in ((decoder, decoder_blob, "decoder"),
                               (frame, frame_blob, "frame")):
        disasm.append(f"--- {label} 0x{start:08X} ({len(blob)} bytes) ---")
        instructions = list(md.disasm(blob, start))
        if sum(ins.size for ins in instructions) != len(blob):
            raise SystemExit(f"{label} contains undecodable bytes")
        disasm.extend(f"{ins.address:08X}  {ins.mnemonic:<8} {ins.op_str}"
                      for ins in instructions)

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    tmp = OUT_DIR / f"{OUT_STEM}_building.zip"
    with ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as archive:
        for info in infos:
            archive.writestr(clone(info), members[info.filename])
    with ZipFile(tmp) as archive:
        rebuilt = {info.filename: archive.read(info.filename) for info in archive.infolist()}
    if rebuilt != members:
        raise SystemExit("archive readback differs")
    stamp = digest(tmp.read_bytes())
    final = OUT_DIR / f"{OUT_STEM}_{stamp[:8]}.zip"
    if final.exists():
        raise SystemExit(f"refusing to reuse existing output name: {final.name}")
    tmp.replace(final)

    changed_members = sorted(name for name in members
                             if name not in {PSX, COMM} and members[name] != base_members[name])
    ANALYSIS.mkdir(parents=True, exist_ok=True)
    DISASSEMBLY.write_text("\n".join(disasm) + "\n", encoding="utf-8")
    lines = [
        BUILD_TITLE,
        "",
        f"base    {BASE_ZIP.name}",
        f"        sha256 {BASE_SHA}",
        f"output  {final.name}",
        f"        sha256 {stamp}",
        f"PSX.EXE {len(exe)} bytes, unchanged",
        f"reserved RAM {COPY_N} bytes, unchanged; heap still 0x{HEAP_BASE:08X}",
        "",
        f"static glyphs  {len(static_index)}",
        f"dynamic glyphs {len(source_char)}",
        f"protected UI glyph relocations {len(relocation_rows)}",
        f"cache slots    {CACHE_N} in {len({(int(r['row']), int(r['column'])) for r in cache_rows})} cells",
        f"row dictionary {len(dictionary_blob)//2} entries / {len(dictionary_blob)} bytes",
        f"glyph row ids  {len(glyph_blob)} bytes",
        f"resident used  {used_end - RESIDENT_BASE}/{COPY_N} bytes",
        f"decoder        0x{decoder:08X} / {len(decoder_blob)} bytes",
        f"frame routine  0x{frame:08X} / {len(frame_blob)} bytes",
        f"text rewrites  {rewrite_hits}",
        f"verified Hangul tokens {verified_tokens}",
        f"changed DAT members {len(changed_members)}",
        "",
        "restored",
        "  stock glyph index return at 0x8016B410",
        "  stock packet builder at 0x8016B5D8",
        "  stock single-page renderer at 0x8016B764",
        "  original COMM.IMG 21-column grid before writing safe static glyph planes",
        "",
        "removed",
        "  fixed per-frame strip A/B/C/D uploads",
        "  high-page two-pass renderer and strip-D remap",
        "",
        "static verification PASS; runtime verification PENDING",
        "rollback: v151",
    ]
    REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
