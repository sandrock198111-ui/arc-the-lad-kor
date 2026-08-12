"""Build v171: restore native UI art and repack all displaced Hangul.

The v170 dialogue-spacing repair remains intact.  This build restores the 26
complete native UI cells proven to contain controller symbols, punctuation and
the 16x24 battle-damage digits.  The 92 displaced Hangul planes join the proven
v165 fail-closed dynamic sources without changing a text token's byte width.

To keep the frozen 5,356-byte reservation and heap boundary, the runtime lookup
is packed to eleven bits, the final blank bitmap row is omitted, transient cell
scratch lives on the frame wrapper's stack, and small helpers occupy only
hash-guarded unreachable executable windows.  The cache grows by one complete
physical cell (24 -> 28 planes) after a 206-state stock/v163 regression scan
found no nonzero halfword in that seventh destination cell.
"""
from __future__ import annotations

import csv
import hashlib
import struct
import sys
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))
sys.path.insert(0, str(ROOT / "06_tools/python_packages"))

from capstone import Cs, CS_ARCH_MIPS, CS_MODE_LITTLE_ENDIAN, CS_MODE_MIPS32  # noqa: E402
import build_arc1_v165_failclosed_cache as old  # noqa: E402
import build_arc1_v166_persistent_ot_guard as v166  # noqa: E402
import plan_arc1_v171_ui_asset_recovery as plan  # noqa: E402
from build_ui_full_v26 import PSX_LOAD_BASE, raw_string  # noqa: E402


BASE = plan.BASE
BASE_SHA256 = plan.BASE_SHA256
ORIGINAL = plan.ORIGINAL
ORIGINAL_SHA256 = plan.ORIGINAL_SHA256
CONTROL = plan.CONTROL
CONTROL_SHA256 = plan.CONTROL_SHA256
OUT_DIR = ROOT / "03_output"
OUT_STEM = "arc1_v171_native_ui_assets_28slot_cache"
ANALYSIS = ROOT / "01_work/analysis/arc1_v171_native_ui_assets_28slot_cache"
REPORT = ANALYSIS / "build_report.txt"
DISASSEMBLY = ANALYSIS / "mips_disassembly.txt"
EXPECTED_WRITES = ANALYSIS / "expected_writes.csv"
SYSTEM_READBACK = ANALYSIS / "system_string_readback.csv"
SYSTEM_EXTERNAL_READBACK = ANALYSIS / "system_external_pointer_readback.csv"

PSX, COMM = "PSX.EXE", "COMM.IMG"
SOURCE_BASE, RESIDENT_BASE, COPY_N = old.SOURCE_BASE, old.RESIDENT_BASE, old.COPY_N
HEAP_BASE = old.HEAP_BASE

# Persistent executable windows.  Each is already loaded before the BSS clear.
RANGE_RAM = 0x801A74C0                    # old decoder body, 96 bytes
RANGE_BYTES = 96
PACKED_LOOKUP_RAM = 0x801A7520
PACKED_LOOKUP_BYTES = 563
HUFFMAN_COUNTS_RAM = 0x801A7753
HUFFMAN_CHECKPOINTS_RAM = 0x801A7760
PARSER_HELPER = 0x801A779C
PARSER_HELPER_CAPACITY = 88
LOOKUP_HELPER = 0x801A77F4
LOOKUP_HELPER_CAPACITY = 84
LOOKUP_REGION_END = old.LOOKUP_RAM + old.LOOKUP_N * 2
LOW_HELPER = 0x801A2060
LOW_CLASSIFIER = 0x801A2084
LOW_REGION_END = 0x801A20B0

PARSER_FIRST = 0x801A7460
PARSER_SECOND = 0x801A748C
FIRST_GLYPH, FIRST_CONTROL = 0x8016BB6C, 0x8016BB54
SECOND_GLYPH, SECOND_CONTROL = 0x8016BB80, 0x8016BB9C

CACHE_N = plan.CACHE_N
CACHE_CELLS = CACHE_N // old.PLANES
CACHE_INDEX_BASE = old.CACHE_ROW * old.IPR
CACHE_X, CACHE_Y, CACHE_U, CACHE_V = old.CACHE_X, old.CACHE_Y, old.CACHE_U, old.CACHE_V
SOURCE_N = plan.SOURCE_N
RANGE_N = 48
ENCODED_ROWS = plan.ENCODED_ROWS
CHECKPOINT_GROUP = plan.CHECKPOINT_GROUP

# v151's proven duplicate button bank is still requested by the current E7
# hook.  v159 restored these cells from the untouched atlas, so restore the
# duplicate bank after native-cell recovery.
ICON_CELLS = tuple((19, col) for col in range(15, 20))
PUNCTUATION_INDICES = {
    "comma": 955,
    "exclamation": 956,
    "question": 1055,
    "period": 1080,
}
SPACE_INDEX = 155

OMITTED_POOLS = (
    (0x8237C, 0x823A4), (0x823C0, 0x823D8), (0x823E4, 0x82444),
    (0x82468, 0x82474), (0x82478, 0x82498), (0x824A0, 0x82518),
    (0x8255C, 0x825C8), (0x82618, 0x8262C), (0x82640, 0x8293C),
)
# These two words are live pointers embedded at the edge of historical string
# storage.  Earlier broad clearing would have destroyed them.  They are excluded
# byte-for-byte before the allocator is allowed to use the surrounding ranges.
PROTECTED_POOL_POINTER_WORDS = ((0x82470, 0x82474), (0x82938, 0x8293C))
EXPECTED_EXTERNAL_POOL_POINTERS = (
    0x81E58, 0x81EEC, 0x8219C, 0x821A0, 0x8234C, 0x82350,
    0x82534, 0x82550, 0x82558, 0x825F0, 0x825F4, 0x825F8,
    0x82630, 0x82634, 0x8299C, 0x82A68,
)
SYSTEM_CSV = ROOT / "05_docs/ui_nonstory_system_v39.csv"

# MIPS register aliases.
ZERO, AT, V0, V1 = old.ZERO, old.AT, old.V0, old.V1
A0, A1, A2, A3 = old.A0, old.A1, old.A2, old.A3
T0, T1, T2, T3, T4, T5, T6, T7 = (
    old.T0, old.T1, old.T2, old.T3, old.T4, old.T5, old.T6, old.T7
)
T8, T9, SP, RA = old.T8, old.T9, old.SP, old.RA
S0, S1, S2, S3, S4, S5, S6, S7 = (
    old.S0, old.S1, old.S2, old.S3, old.S4, old.S5, old.S6, old.S7
)
NOP, JR_RA = old.NOP, old.JR_RA


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def align(value: int, boundary: int = 4) -> int:
    return (value + boundary - 1) & -boundary


def cell_bytes(font: bytes | bytearray, row: int, col: int) -> bytes:
    return b"".join(
        font[(row * old.CELL + y) * 0x380 + col * 6:
             (row * old.CELL + y) * 0x380 + (col + 1) * 6]
        for y in range(old.CELL)
    )


def restore_cell(font: bytearray, source: bytes, row: int, col: int) -> None:
    for y in range(old.CELL):
        at = (row * old.CELL + y) * 0x380 + col * 6
        font[at:at + 6] = source[at:at + 6]


def copy_plane(font: bytearray, source: bytes, index: int) -> None:
    row, within = divmod(index, old.IPR)
    col, plane = divmod(within, old.PLANES)
    bit = 1 << plane
    for y in range(old.CELL):
        for x in range(old.CELL):
            at = (row * old.CELL + y) * 0x380 + col * 6 + x // 2
            shift = 4 * (x & 1)
            mask = bit << shift
            font[at] = (font[at] & ~mask) | (source[at] & mask)


def plane_bitmap(font: bytes | bytearray, index: int) -> tuple[int, ...]:
    row, within = divmod(index, old.IPR)
    col, plane = divmod(within, old.PLANES)
    result = []
    for y in range(old.CELL):
        for x in range(old.CELL):
            value = font[(row * old.CELL + y) * 0x380 + col * 6 + x // 2]
            result.append((value >> (4 * (x & 1) + plane)) & 1)
    return tuple(result)


def resident_layout() -> tuple[dict[str, tuple[int, int]], dict[str, bytes], int]:
    blobs = {
        "huffman_rows": plan.HUFFMAN_ROWS.read_bytes(),
        "source_bitstream": plan.SOURCE_BITSTREAM.read_bytes(),
        "nibble_expand": old.plan.NIBBLE_EXPAND.read_bytes(),
        "owners": bytes(CACHE_N * 2),
        "active_mask": bytes(4),
        "next_slot": bytes(4),
        "upload_rect": bytes(8),
    }
    alignments = {
        "huffman_rows": 2, "source_bitstream": 1, "nibble_expand": 2,
        "owners": 2, "active_mask": 4, "next_slot": 4, "upload_rect": 2,
    }
    cursor = RESIDENT_BASE
    layout: dict[str, tuple[int, int]] = {}
    for name, blob in blobs.items():
        cursor = align(cursor, alignments[name])
        layout[name] = (cursor, len(blob))
        cursor += len(blob)
    return layout, blobs, align(cursor)


def build_lookup_helper(address: int) -> bytes:
    """T2=lookup slot; return normalized 11-bit value in T4 via jr AT."""
    asm = old.Assembler(address)
    asm.emit(old.r_type(ZERO, T2, T3, 3, 0x00))          # slot * 8
    asm.emit(old.r_type(ZERO, T2, T4, 1, 0x00))          # slot * 2
    asm.emit(old.r_type(T3, T4, T3, 0, 0x21))
    asm.emit(old.r_type(T3, T2, T3, 0, 0x21))            # slot * 11 bits
    asm.emit(old.i_type(0x0C, T3, T4, 7))                # bit shift
    asm.emit(old.r_type(ZERO, T3, T3, 3, 0x02))          # byte offset
    old.load_address(asm, T5, PACKED_LOOKUP_RAM)
    asm.emit(old.r_type(T5, T3, T5, 0, 0x21))
    asm.emit(old.i_type(0x24, T5, T0, 0))
    asm.emit(old.i_type(0x24, T5, T1, 1))                # load spacer for T0
    asm.emit(old.i_type(0x24, T5, T6, 2))                # load spacer for T1
    asm.emit(old.r_type(ZERO, T1, T1, 8, 0x00))
    asm.emit(old.r_type(ZERO, T6, T6, 16, 0x00))
    asm.emit(old.r_type(T0, T1, T0, 0, 0x25))
    asm.emit(old.r_type(T0, T6, T0, 0, 0x25))
    asm.emit(old.r_type(T4, T0, T4, 0, 0x06))
    asm.emit(old.i_type(0x0C, T4, T4, 0x07FF))
    asm.emit(old.r_type(AT, ZERO, ZERO, 0, 0x08))
    asm.emit(NOP)
    return asm.finish()


def build_parser_helper(address: int) -> bytes:
    """T8/T9 are caller-specific glyph/control continuation addresses."""
    asm = old.Assembler(address)
    asm.emit(old.i_type(0x09, V0, T0, -0xE1))
    asm.branch(0x04, T0, ZERO, "e1")
    asm.emit(old.i_type(0x09, V0, T1, -0xE9))
    asm.emit(old.i_type(0x0B, T1, T1, 2))
    asm.branch(0x05, T1, ZERO, "glyph")
    asm.emit(old.i_type(0x0B, V0, T0, 0xE1))
    asm.branch(0x05, T0, ZERO, "glyph")
    asm.emit(NOP)
    asm.emit(old.r_type(T9, ZERO, ZERO, 0, 0x08))
    asm.emit(NOP)

    asm.label("e1")
    asm.emit(old.i_type(0x23, S0, T0, 0x14))
    asm.emit(NOP)
    asm.emit(old.i_type(0x24, T0, T1, 1))
    asm.emit(NOP)
    asm.emit(old.i_type(0x09, T1, T1, -0xBE))
    asm.emit(old.i_type(0x0B, T1, T0, 0x33))
    asm.branch(0x05, T0, ZERO, "glyph")
    asm.emit(NOP)
    asm.emit(old.r_type(T9, ZERO, ZERO, 0, 0x08))
    asm.emit(NOP)
    asm.label("glyph")
    asm.emit(old.r_type(T8, ZERO, ZERO, 0, 0x08))
    asm.emit(NOP)
    return asm.finish()


def build_parser_entry(address: int, glyph: int, control: int) -> bytes:
    delta = control - glyph
    if not -0x8000 <= delta <= 0x7FFF or glyph >> 16 != 0x8016:
        raise SystemExit("parser continuation does not fit the compact entry")
    asm = old.Assembler(address)
    asm.emit(old.i_type(0x0F, ZERO, T8, glyph >> 16))
    asm.emit(old.i_type(0x0D, T8, T8, glyph & 0xFFFF))
    asm.emit(old.i_type(0x09, T8, T9, delta))
    asm.emit(old.j(PARSER_HELPER))
    asm.emit(NOP)
    return asm.finish()


def build_low_helper(address: int) -> bytes:
    """Add U=4 only to row-40 packets and preserve the displaced stock load."""
    asm = old.Assembler(address)
    asm.emit(old.i_type(0x09, T0, A3, -old.CACHE_ROW))
    asm.branch(0x05, A3, ZERO, "out")
    asm.emit(old.i_type(0x24, A2, V0, 0x0E))
    asm.emit(old.i_type(0x24, A1, A3, 0x28))
    asm.emit(NOP)
    asm.emit(old.i_type(0x09, A3, A3, CACHE_U))
    asm.emit(old.i_type(0x28, A1, A3, 0x28))
    asm.label("out")
    asm.emit(old.j(old.GLYPH_PACKET_RETURN))
    asm.emit(NOP)
    return asm.finish()


def build_low_classifier(address: int) -> bytes:
    asm = old.Assembler(address)
    asm.emit(old.i_type(0x24, V1, V0, 0x29))
    asm.emit(old.i_type(0x25, V1, T8, 0x30))
    asm.emit(old.i_type(0x09, V0, V0, -CACHE_V))
    asm.emit(old.i_type(0x0B, V0, V0, 1))
    asm.emit(old.i_type(0x09, T8, T8, -0x7FC0))
    asm.emit(old.i_type(0x0B, T8, T8, 16))
    asm.emit(old.r_type(V0, T8, V0, 0, 0x24))
    asm.emit(JR_RA)
    asm.emit(NOP)
    return asm.finish()


def build_decoder(address: int, layout: dict[str, tuple[int, int]]) -> bytes:
    owners = layout["owners"][0]
    active = layout["active_mask"][0]
    next_slot = layout["next_slot"][0]
    asm = old.Assembler(address)

    asm.emit(old.i_type(0x09, V1, T0, -0xE9))
    asm.emit(old.i_type(0x0B, T0, T1, 2))
    asm.branch(0x05, T1, ZERO, "lookup")
    asm.emit(NOP)
    asm.emit(old.i_type(0x0B, V1, T0, 0xDD))
    asm.branch(0x05, T0, ZERO, "direct_single")
    asm.emit(NOP)
    asm.emit(old.i_type(0x0B, V1, T0, 0xE9))
    asm.branch(0x04, T0, ZERO, "stock_wide")
    asm.emit(NOP)
    asm.emit(old.i_type(0x24, A1, T1, 1))
    asm.emit(old.i_type(0x09, V1, T0, -0xDD))
    asm.emit(old.r_type(ZERO, T0, T2, 8, 0x00))
    asm.emit(old.r_type(T2, T0, T2, 0, 0x23))
    asm.emit(old.r_type(T2, T1, T2, 0, 0x21))
    asm.emit(old.i_type(0x09, T2, T2, 0xDB))
    asm.emit(old.i_type(0x0D, ZERO, T9, 2))
    asm.branch(0x04, ZERO, ZERO, "range_start")
    asm.emit(NOP)
    asm.label("direct_single")
    asm.emit(old.i_type(0x09, V1, T2, -1))
    asm.emit(old.i_type(0x0D, ZERO, T9, 1))

    asm.label("range_start")
    old.load_address(asm, T3, RANGE_RAM)
    asm.emit(old.i_type(0x0D, ZERO, T4, RANGE_N))
    asm.emit(old.move(T7, ZERO))                         # cumulative source base
    asm.label("range_loop")
    asm.emit(old.i_type(0x25, T3, T5, 0))
    asm.emit(old.i_type(0x09, T3, T3, 2))               # load spacer
    asm.emit(old.i_type(0x0C, T5, T6, 0x07FF))
    asm.emit(old.r_type(T2, T6, T8, 0, 0x2B))
    asm.branch(0x05, T8, ZERO, "direct_static")
    asm.emit(old.i_type(0x09, T4, T4, -1))
    asm.emit(old.r_type(ZERO, T5, T0, 11, 0x02))
    asm.emit(old.i_type(0x0D, ZERO, T1, 31))
    asm.branch(0x05, T0, T1, "length_ready")
    asm.emit(old.i_type(0x09, T0, T1, 1))
    asm.emit(old.i_type(0x0D, ZERO, T1, 39))
    asm.label("length_ready")
    asm.emit(old.r_type(T2, T6, T8, 0, 0x23))
    asm.emit(old.r_type(T8, T1, T5, 0, 0x2B))
    asm.branch(0x05, T5, ZERO, "range_hit")
    asm.emit(NOP)
    asm.emit(old.r_type(T7, T1, T7, 0, 0x21))
    asm.branch(0x05, T4, ZERO, "range_loop")
    asm.emit(NOP)
    asm.branch(0x04, ZERO, ZERO, "direct_static")
    asm.emit(NOP)
    asm.label("range_hit")
    asm.emit(old.r_type(T7, T8, T4, 0, 0x21))
    asm.branch(0x04, ZERO, ZERO, "cache")
    asm.emit(NOP)

    asm.label("direct_static")
    asm.emit(old.i_type(0x09, T9, T0, -1))
    asm.branch(0x04, T0, ZERO, "stock_single")
    asm.emit(NOP)
    asm.label("stock_wide")
    asm.emit(old.j(old.WIDE_PATH))
    asm.emit(NOP)
    asm.label("stock_single")
    asm.emit(old.j(old.SINGLE_PATH))
    asm.emit(NOP)

    asm.label("lookup")
    asm.emit(old.i_type(0x24, A1, T1, 1))
    asm.emit(old.r_type(ZERO, T0, T2, 8, 0x00))
    asm.emit(old.r_type(T2, T0, T2, 0, 0x23))
    asm.emit(old.r_type(T2, T0, T2, 0, 0x23))
    asm.emit(old.r_type(T2, T1, T2, 0, 0x21))
    asm.emit(old.i_type(0x09, T2, T2, -1))
    asm.emit(old.i_type(0x0B, T2, T3, old.LOOKUP_N))
    asm.branch(0x04, T3, ZERO, "lookup_invalid")
    asm.emit(NOP)
    old.load_address(asm, T8, LOOKUP_HELPER)
    asm.emit(old.r_type(T8, ZERO, AT, 0, 0x09))          # jalr AT,T8; preserve RA
    asm.emit(NOP)
    asm.emit(old.i_type(0x0D, ZERO, T5, plan.SPECIAL_STATIC_TAG))
    asm.branch(0x04, T4, T5, "lookup_special")
    asm.emit(NOP)
    asm.emit(old.i_type(0x0B, T4, T5, plan.DYNAMIC_TAG))
    asm.branch(0x05, T5, ZERO, "lookup_static")
    asm.emit(NOP)
    asm.emit(old.i_type(0x09, T4, T4, -plan.DYNAMIC_TAG))
    asm.branch(0x04, ZERO, ZERO, "cache")
    asm.emit(NOP)
    asm.label("lookup_special")
    asm.emit(old.i_type(0x0D, ZERO, T4, plan.SPECIAL_STATIC_VALUE))
    asm.label("lookup_static")
    asm.branch(0x04, ZERO, ZERO, "finish")
    asm.emit(old.move(V1, T4))

    asm.label("cache")
    old.load_address(asm, T5, owners)
    asm.emit(old.move(T6, ZERO))
    asm.label("owner_scan")
    asm.emit(old.i_type(0x25, T5, T7, 0))
    asm.emit(old.i_type(0x09, T5, T5, 2))
    asm.branch(0x04, T7, T4, "cache_ready")
    asm.emit(NOP)
    asm.emit(old.i_type(0x09, T6, T6, 1))
    asm.emit(old.i_type(0x0B, T6, T7, CACHE_N))
    asm.branch(0x05, T7, ZERO, "owner_scan")
    asm.emit(NOP)

    old.load_address(asm, T5, active)
    asm.emit(old.i_type(0x23, T5, T8, 0))
    old.load_address(asm, T5, next_slot)
    asm.emit(old.i_type(0x24, T5, T6, 0))
    asm.emit(old.i_type(0x0D, ZERO, T7, CACHE_N))
    asm.label("free_scan")
    asm.emit(old.i_type(0x0D, ZERO, T0, 1))
    asm.emit(old.r_type(T6, T0, T0, 0, 0x04))
    asm.emit(old.r_type(T8, T0, T1, 0, 0x24))
    asm.branch(0x04, T1, ZERO, "free_found")
    asm.emit(old.i_type(0x09, T7, T7, -1))
    asm.emit(old.i_type(0x09, T6, T6, 1))
    asm.emit(old.i_type(0x0B, T6, T1, CACHE_N))
    asm.branch(0x05, T1, ZERO, "free_nowrap")
    asm.emit(NOP)
    asm.emit(old.move(T6, ZERO))
    asm.label("free_nowrap")
    asm.branch(0x05, T7, ZERO, "free_scan")
    asm.emit(NOP)
    asm.branch(0x04, ZERO, ZERO, "finish")
    asm.emit(old.move(V1, ZERO))

    asm.label("free_found")
    asm.emit(old.i_type(0x09, T6, T7, 1))
    asm.emit(old.i_type(0x0B, T7, T1, CACHE_N))
    asm.branch(0x05, T1, ZERO, "next_ready")
    asm.emit(NOP)
    asm.emit(old.move(T7, ZERO))
    asm.label("next_ready")
    asm.emit(old.i_type(0x28, T5, T7, 0))
    old.load_address(asm, T5, owners)
    asm.emit(old.r_type(ZERO, T6, T7, 1, 0x00))
    asm.emit(old.r_type(T5, T7, T5, 0, 0x21))
    asm.emit(old.i_type(0x29, T5, T4, 0))
    asm.branch(0x04, ZERO, ZERO, "cache_ready")
    asm.emit(NOP)

    asm.label("cache_ready")
    asm.emit(old.i_type(0x0D, ZERO, T0, 1))
    asm.emit(old.r_type(T6, T0, T0, 0, 0x04))
    old.load_address(asm, T5, active)
    asm.emit(old.i_type(0x23, T5, T8, 0))
    asm.emit(NOP)
    asm.emit(old.r_type(T8, T0, T8, 0, 0x25))
    asm.emit(old.i_type(0x2B, T5, T8, 0))
    asm.branch(0x04, ZERO, ZERO, "finish")
    asm.emit(old.i_type(0x09, T6, V1, CACHE_INDEX_BASE))

    asm.label("lookup_invalid")
    asm.emit(old.i_type(0x0D, ZERO, T9, 2))
    asm.branch(0x04, ZERO, ZERO, "finish")
    asm.emit(old.move(V1, ZERO))
    asm.label("finish")
    asm.emit(old.r_type(A1, T9, V0, 0, 0x21))
    asm.emit(old.i_type(0x2B, A2, V0, 0))
    asm.emit(old.j(old.DECODE_RETURN))
    asm.emit(NOP)
    return asm.finish()


def build_huffman(address: int, layout: dict[str, tuple[int, int]]) -> bytes:
    rows = layout["huffman_rows"][0]
    bitstream = layout["source_bitstream"][0]
    maximum_code_bits = len(plan.HUFFMAN_COUNTS.read_bytes())
    asm = old.Assembler(address)
    asm.emit(old.r_type(ZERO, A0, T0, 4, 0x02))
    asm.emit(old.r_type(ZERO, T0, T0, 1, 0x00))
    old.load_address(asm, T1, HUFFMAN_CHECKPOINTS_RAM)
    asm.emit(old.r_type(T1, T0, T0, 0, 0x21))
    asm.emit(old.i_type(0x25, T0, T0, 0))
    asm.emit(old.i_type(0x0C, A0, T1, CHECKPOINT_GROUP - 1))
    asm.emit(old.r_type(ZERO, T1, T2, 1, 0x00))
    asm.emit(old.r_type(T2, T1, T2, 0, 0x21))           # within * 3
    asm.emit(old.r_type(ZERO, T1, T1, 3, 0x00))         # within * 8
    asm.emit(old.r_type(T1, T2, T1, 0, 0x21))           # within * 11
    asm.emit(old.i_type(0x0D, ZERO, T2, ENCODED_ROWS))
    old.load_address(asm, A2, HUFFMAN_COUNTS_RAM)
    old.load_address(asm, A3, rows)
    old.load_address(asm, V0, bitstream)
    asm.label("symbol")
    asm.emit(old.move(T3, ZERO))
    asm.emit(old.move(T4, ZERO))
    asm.emit(old.move(T5, ZERO))
    asm.emit(old.move(T6, A2))
    asm.emit(old.i_type(0x0D, ZERO, T9, maximum_code_bits))
    asm.label("bit")
    asm.emit(old.r_type(ZERO, T0, T7, 3, 0x02))
    asm.emit(old.r_type(V0, T7, T7, 0, 0x21))
    asm.emit(old.i_type(0x24, T7, T7, 0))
    asm.emit(old.i_type(0x0C, T0, T8, 7))
    asm.emit(old.i_type(0x0E, T8, T8, 7))
    asm.emit(old.r_type(T8, T7, T7, 0, 0x06))
    asm.emit(old.i_type(0x0C, T7, T7, 1))
    asm.emit(old.r_type(ZERO, T3, T3, 1, 0x00))
    asm.emit(old.r_type(T3, T7, T3, 0, 0x25))
    asm.emit(old.i_type(0x09, T0, T0, 1))
    asm.emit(old.i_type(0x24, T6, T7, 0))
    asm.emit(old.i_type(0x09, T6, T6, 1))
    asm.emit(old.r_type(T3, T4, T8, 0, 0x23))
    asm.emit(old.r_type(T8, T7, A0, 0, 0x2B))
    asm.branch(0x05, A0, ZERO, "found")
    asm.emit(old.i_type(0x09, T9, T9, -1))
    asm.emit(old.r_type(T5, T7, T5, 0, 0x21))
    asm.emit(old.r_type(T4, T7, T4, 0, 0x21))
    asm.emit(old.r_type(ZERO, T4, T4, 1, 0x00))
    asm.branch(0x05, T9, ZERO, "bit")
    asm.emit(NOP)
    asm.branch(0x04, ZERO, ZERO, "process")
    asm.emit(old.move(T7, ZERO))
    asm.label("found")
    asm.emit(old.r_type(T5, T8, T8, 0, 0x21))
    asm.emit(old.r_type(ZERO, T8, T8, 1, 0x00))
    asm.emit(old.r_type(A3, T8, T8, 0, 0x21))
    asm.emit(old.i_type(0x25, T8, T7, 0))
    asm.label("process")
    asm.branch(0x04, T1, ZERO, "store")
    asm.emit(NOP)
    asm.branch(0x04, ZERO, ZERO, "symbol")
    asm.emit(old.i_type(0x09, T1, T1, -1))
    asm.label("store")
    asm.emit(old.i_type(0x29, A1, T7, 0))
    asm.emit(old.i_type(0x09, T2, T2, -1))
    asm.branch(0x05, T2, ZERO, "symbol")
    asm.emit(old.i_type(0x09, A1, A1, 2))
    asm.emit(JR_RA)
    asm.emit(old.i_type(0x29, A1, ZERO, 0))              # omitted row 11 / delay
    return asm.finish()


def build_frame(address: int, huffman: int,
                layout: dict[str, tuple[int, int]]) -> bytes:
    owners = layout["owners"][0]
    active = layout["active_mask"][0]
    rect = layout["upload_rect"][0]
    expand = layout["nibble_expand"][0]
    stack_size = 0xB0
    save = {RA: 0xAC, S0: 0xA8, S1: 0xA4, S2: 0xA0, S3: 0x9C,
            S4: 0x98, S5: 0x94, S6: 0x90, S7: 0x8C}
    saved_a0 = 0x80
    decoded_at = 0x48

    asm = old.Assembler(address)
    asm.emit(old.i_type(0x09, SP, SP, -stack_size))
    for reg, offset in save.items():
        asm.emit(old.i_type(0x2B, SP, reg, offset))
    asm.emit(old.i_type(0x2B, SP, A0, saved_a0))
    old.load_address(asm, T0, active)
    asm.emit(old.i_type(0x23, T0, S0, 0))
    asm.emit(old.i_type(0x0F, ZERO, S1, owners >> 16))   # load-delay work
    asm.branch(0x04, S0, ZERO, "protect")
    asm.emit(old.i_type(0x0D, S1, S1, owners & 0xFFFF))  # branch delay slot
    asm.emit(old.i_type(0x09, SP, S2, 0))                # 72-byte cell scratch
    asm.emit(old.i_type(0x09, SP, S3, decoded_at))       # 24-byte decoded rows
    old.load_address(asm, S4, rect)
    asm.emit(old.move(S5, ZERO))
    asm.label("cell_loop")
    asm.emit(old.i_type(0x0C, S0, S7, 0x0F))
    asm.emit(old.r_type(ZERO, S0, S0, 4, 0x02))
    asm.branch(0x04, S7, ZERO, "cell_next")
    asm.emit(NOP)
    asm.emit(old.move(T0, S2))
    asm.emit(old.i_type(0x0D, ZERO, T1, 18))
    asm.label("clear_loop")
    asm.emit(old.i_type(0x2B, T0, ZERO, 0))
    asm.emit(old.i_type(0x09, T1, T1, -1))
    asm.branch(0x05, T1, ZERO, "clear_loop")
    asm.emit(old.i_type(0x09, T0, T0, 4))
    asm.emit(old.move(S6, ZERO))
    asm.label("plane_loop")
    asm.emit(old.r_type(ZERO, S5, T0, 3, 0x00))
    asm.emit(old.r_type(ZERO, S6, T1, 1, 0x00))
    asm.emit(old.r_type(T0, T1, T0, 0, 0x21))
    asm.emit(old.r_type(S1, T0, T0, 0, 0x21))
    asm.emit(old.i_type(0x25, T0, A0, 0))
    asm.emit(old.move(A1, S3))
    asm.emit(old.i_type(0x09, A0, T8, 1))
    asm.branch(0x04, T8, ZERO, "plane_next")
    asm.emit(NOP)
    asm.emit(old.jal(huffman))
    asm.emit(NOP)
    old.load_address(asm, A2, expand)
    asm.emit(old.move(T0, S3))
    asm.emit(old.move(T1, S2))
    asm.emit(old.i_type(0x0D, ZERO, T2, old.CELL))
    asm.label("row_loop")
    asm.emit(old.i_type(0x25, T0, T3, 0))
    asm.emit(old.i_type(0x0D, ZERO, T4, 8))
    asm.label("nibble_loop")
    asm.emit(old.r_type(T4, T3, T6, 0, 0x06))
    asm.emit(old.i_type(0x0C, T6, T6, 0x0F))
    asm.emit(old.r_type(ZERO, T6, T6, 1, 0x00))
    asm.emit(old.r_type(A2, T6, T6, 0, 0x21))
    asm.emit(old.i_type(0x25, T6, T6, 0))
    asm.emit(old.i_type(0x25, T1, T7, 0))
    asm.emit(old.r_type(S6, T6, T6, 0, 0x04))
    asm.emit(old.r_type(T7, T6, T7, 0, 0x25))
    asm.emit(old.i_type(0x29, T1, T7, 0))
    asm.emit(old.i_type(0x09, T4, T4, -4))
    asm.branch(0x01, T4, 1, "nibble_loop")              # bgez T4
    asm.emit(old.i_type(0x09, T1, T1, 2))
    asm.emit(old.i_type(0x09, T2, T2, -1))
    asm.branch(0x05, T2, ZERO, "row_loop")
    asm.emit(old.i_type(0x09, T0, T0, 2))
    asm.label("plane_next")
    asm.emit(old.i_type(0x09, S6, S6, 1))
    asm.emit(old.i_type(0x0B, S6, T0, old.PLANES))
    asm.branch(0x05, T0, ZERO, "plane_loop")
    asm.emit(NOP)
    asm.emit(old.r_type(ZERO, S5, T0, 1, 0x00))
    asm.emit(old.r_type(T0, S5, T0, 0, 0x21))
    asm.emit(old.i_type(0x09, T0, T0, CACHE_X))
    asm.emit(old.i_type(0x29, S4, T0, 0))
    asm.emit(old.move(A0, S4))
    asm.emit(old.move(A1, S2))
    asm.emit(old.jal(old.LOADIMAGE))
    asm.emit(NOP)
    asm.label("cell_next")
    asm.emit(old.i_type(0x09, S5, S5, 1))
    asm.emit(old.i_type(0x0B, S5, T0, CACHE_CELLS))
    asm.branch(0x05, T0, ZERO, "cell_loop")
    asm.emit(NOP)

    asm.label("protect")
    asm.emit(old.i_type(0x23, SP, T1, saved_a0))
    asm.emit(old.move(T8, ZERO))
    asm.emit(old.i_type(0x23, T1, T1, 0))
    old.load_address(asm, T2, v166.RAM_LIMIT)
    asm.emit(old.r_type(ZERO, T1, T1, 8, 0x00))
    asm.emit(old.r_type(ZERO, T1, T1, 8, 0x02))
    asm.emit(old.i_type(0x0D, ZERO, T9, v166.OT_WALK_LIMIT))
    asm.label("ot_loop")
    asm.branch(0x04, T1, ZERO, "ot_done")
    asm.emit(NOP)
    asm.emit(old.r_type(T1, T2, T3, 0, 0x2B))
    asm.branch(0x04, T3, ZERO, "ot_done")
    asm.emit(NOP)
    old.load_address(asm, T3, 0x80000000)
    asm.emit(old.r_type(T3, T1, T3, 0, 0x25))
    asm.emit(old.i_type(0x23, T3, T4, 0))
    asm.emit(old.i_type(0x24, T3, T5, 7))
    asm.emit(old.r_type(ZERO, T4, T6, 24, 0x02))
    asm.emit(old.i_type(0x09, T6, T6, -4))
    asm.branch(0x05, T6, ZERO, "ot_next")
    asm.emit(old.i_type(0x0C, T5, T5, 0xFC))
    asm.emit(old.i_type(0x0D, ZERO, T6, 0x64))
    asm.branch(0x05, T5, T6, "ot_next")
    asm.emit(NOP)
    asm.emit(old.i_type(0x24, T3, T5, 13))
    asm.emit(NOP)
    asm.emit(old.i_type(0x09, T5, T5, -CACHE_V))
    asm.branch(0x05, T5, ZERO, "ot_next")
    asm.emit(NOP)
    asm.emit(old.i_type(0x24, T3, T6, 12))
    asm.emit(NOP)
    asm.emit(old.i_type(0x09, T6, T6, -CACHE_U))
    asm.emit(old.i_type(0x0B, T6, T5, CACHE_CELLS * old.CELL))
    asm.branch(0x04, T5, ZERO, "ot_next")
    asm.emit(old.move(T7, ZERO))
    asm.label("u_loop")
    asm.branch(0x04, T6, ZERO, "u_ready")
    asm.emit(old.i_type(0x09, T6, T6, -old.CELL))
    asm.emit(old.i_type(0x09, T7, T7, old.PLANES))
    asm.emit(old.i_type(0x0A, T6, T5, 0))               # signed T6 < 0
    asm.branch(0x04, T5, ZERO, "u_loop")
    asm.emit(NOP)
    asm.branch(0x04, ZERO, ZERO, "ot_next")
    asm.emit(NOP)
    asm.label("u_ready")
    asm.emit(old.i_type(0x25, T3, T5, 14))
    asm.emit(NOP)
    asm.emit(old.i_type(0x09, T5, T5, -v166.FONT_CLUT_MIN))
    asm.emit(old.i_type(0x0B, T5, T6, 16))
    asm.branch(0x04, T6, ZERO, "ot_next")
    asm.emit(old.i_type(0x0C, T5, T5, 3))
    asm.emit(old.r_type(T7, T5, T7, 0, 0x21))
    asm.emit(old.i_type(0x0D, ZERO, T5, 1))
    asm.emit(old.r_type(T7, T5, T5, 0, 0x04))
    asm.emit(old.r_type(T8, T5, T8, 0, 0x25))
    asm.label("ot_next")
    asm.emit(old.r_type(ZERO, T4, T1, 8, 0x00))
    asm.emit(old.r_type(ZERO, T1, T1, 8, 0x02))
    asm.emit(old.i_type(0x09, T9, T9, -1))
    asm.branch(0x05, T9, ZERO, "ot_loop")
    asm.emit(NOP)
    asm.label("ot_done")
    old.load_address(asm, T0, active)
    asm.emit(old.i_type(0x2B, T0, T8, 0))
    asm.emit(old.i_type(0x23, SP, A0, saved_a0))
    asm.emit(NOP)
    asm.emit(old.jal(old.DRAWOT))
    asm.emit(NOP)
    for reg, offset in save.items():
        asm.emit(old.i_type(0x23, SP, reg, offset))
    asm.emit(JR_RA)
    asm.emit(old.i_type(0x09, SP, SP, stack_size))
    return asm.finish()


def current_char_mapping() -> dict[str, bytes]:
    rows = plan.read_csv(plan.ASSIGNMENTS)
    result: dict[str, bytes] = {}
    for row in rows:
        if not row["char"]:
            continue
        encoded = row["code_1byte"] or row["code_2byte"]
        if not encoded:
            raise SystemExit(f"assignment has no code: {row['char']!r}")
        result[row["char"]] = bytes.fromhex(encoded)
    return result


def encode_system(text: str, mapping: dict[str, bytes]) -> bytes:
    output = bytearray()
    at = 0
    if text.startswith("LV"):
        output.append(0x6C)
        at = 2
    punctuation = {"!": bytes.fromhex("DF E3"), ".": bytes.fromhex("E0 60")}
    for char in text[at:]:
        if char == " ":
            output.append(0x9C)
        elif char.isascii() and char.isdigit():
            output.append(0x11 + int(char))
        elif char in punctuation:
            output.extend(punctuation[char])
        elif char in mapping:
            output.extend(mapping[char])
        else:
            raise SystemExit(f"system string has no current code: {text!r} {char!r}")
    if not output or 0 in output:
        raise SystemExit(f"invalid encoded system string: {text!r}")
    return bytes(output)


def system_storage_ranges() -> tuple[tuple[int, int], ...]:
    result: list[tuple[int, int]] = []
    for start, end in OMITTED_POOLS:
        pieces = [(start, end)]
        for protected_start, protected_end in PROTECTED_POOL_POINTER_WORDS:
            next_pieces: list[tuple[int, int]] = []
            for left, right in pieces:
                if protected_end <= left or protected_start >= right:
                    next_pieces.append((left, right))
                    continue
                if left < protected_start:
                    next_pieces.append((left, protected_start))
                if protected_end < right:
                    next_pieces.append((protected_end, right))
            pieces = next_pieces
        result.extend(piece for piece in pieces if piece[0] < piece[1])
    return tuple(result)


def repack_system_strings(
    exe: bytearray,
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    rows = [row for row in plan.read_csv(SYSTEM_CSV)
            if row["status"] != "battle_hud_pointer_repaired"]
    if len(rows) != 123 or len({int(row["pointer_offset"], 0) for row in rows}) != 123:
        raise SystemExit("system-string manifest is not exactly 123 pointers")
    mapping = current_char_mapping()
    owned = {int(row["pointer_offset"], 0): row for row in rows}
    desired: dict[int, bytes] = {
        pointer: encode_system(row["korean"], mapping)
        for pointer, row in owned.items()
    }

    storage = system_storage_ranges()
    protected_before = {
        start: bytes(exe[start:end]) for start, end in PROTECTED_POOL_POINTER_WORDS
    }

    # A valid RAM pointer inside writable storage is non-text data, even when its
    # four bytes happen to sit between translated strings.  The two measured words
    # above must be the complete set; otherwise stop instead of clearing it.
    embedded_pointers: list[int] = []
    for start, end in storage:
        for offset in range((start + 3) & ~3, end - 3, 4):
            value = struct.unpack_from("<I", exe, offset)[0]
            if PSX_LOAD_BASE <= value < PSX_LOAD_BASE + len(exe):
                embedded_pointers.append(offset)
    if embedded_pointers:
        raise SystemExit(
            "unreserved pointer word inside system storage at "
            f"0x{embedded_pointers[0]:X}"
        )

    # Preserve every other aligned consumer of the historical pools.  This is
    # where item/skill quotation fragments, world names and two unresolved stock
    # labels live.  Their payload is copied exactly; no translation is guessed.
    external: dict[int, tuple[int, bytes]] = {}
    for offset in range(0, len(exe) - 3, 4):
        target = struct.unpack_from("<I", exe, offset)[0] - PSX_LOAD_BASE
        if any(start <= target < end for start, end in OMITTED_POOLS) \
                and offset not in owned:
            external[offset] = (target, raw_string(exe, target))
    if tuple(sorted(external)) != EXPECTED_EXTERNAL_POOL_POINTERS:
        raise SystemExit(
            "external system-pool pointer set differs: "
            + " ".join(f"0x{offset:X}" for offset in sorted(external))
        )
    for pointer, (_target, payload) in external.items():
        desired[pointer] = payload

    if any(any(start <= pointer < end for start, end in storage) for pointer in desired):
        raise SystemExit("a system pointer word overlaps writable string storage")
    if any(b"\0" in payload for payload in desired.values()):
        raise SystemExit("a system payload contains an embedded terminator")

    # Best-fit decreasing over only the pointer-free ranges.  Identical payloads
    # share one copy; all 123 semantic strings and all 16 external fragments must
    # fit before a byte is changed.
    free = list(storage)
    locations: dict[bytes, int] = {}
    for payload in sorted(set(desired.values()), key=lambda value: (-len(value), value)):
        choices = [
            (end - start, index)
            for index, (start, end) in enumerate(free)
            if start + len(payload) + 1 <= end
        ]
        if not choices:
            raise SystemExit(f"pointer-safe system storage overflow: {payload.hex(' ')}")
        _remaining, which = min(choices)
        target, end = free[which]
        locations[payload] = target
        free[which] = (target + len(payload) + 1, end)

    for start, end in storage:
        exe[start:end] = bytes(end - start)
    for payload, target in locations.items():
        exe[target:target + len(payload)] = payload
        exe[target + len(payload)] = 0
    for pointer, payload in desired.items():
        struct.pack_into("<I", exe, pointer, PSX_LOAD_BASE + locations[payload])

    for start, expected in protected_before.items():
        if exe[start:start + len(expected)] != expected:
            raise SystemExit(f"protected system pointer changed at 0x{start:X}")

    readback: list[dict[str, object]] = []
    for row in rows:
        pointer = int(row["pointer_offset"], 0)
        text = row["korean"]
        target = struct.unpack_from("<I", exe, pointer)[0] - PSX_LOAD_BASE
        payload = raw_string(exe, target)
        if payload != desired[pointer]:
            raise SystemExit(f"system payload readback differs at 0x{pointer:X}")
        readback.append({
            "pointer_offset": f"0x{pointer:X}", "target_offset": f"0x{target:X}",
            "korean": text, "encoded_bytes": len(payload),
            "encoded_hex": payload.hex(" ").upper(),
        })
    external_readback: list[dict[str, object]] = []
    for pointer, (old_target, expected) in sorted(external.items()):
        target = struct.unpack_from("<I", exe, pointer)[0] - PSX_LOAD_BASE
        payload = raw_string(exe, target)
        if payload != expected:
            raise SystemExit(f"external payload readback differs at 0x{pointer:X}")
        external_readback.append({
            "pointer_offset": f"0x{pointer:X}",
            "old_target_offset": f"0x{old_target:X}",
            "new_target_offset": f"0x{target:X}",
            "encoded_bytes": len(payload),
            "encoded_hex": payload.hex(" ").upper(),
        })
    return readback, external_readback


def main() -> None:
    plan.main()
    for path, expected in (
        (BASE, BASE_SHA256), (ORIGINAL, ORIGINAL_SHA256), (CONTROL, CONTROL_SHA256),
    ):
        if digest(path.read_bytes()) != expected:
            raise SystemExit(f"archive hash differs: {path.name}")

    layout, resident_blobs, code_base = resident_layout()
    parser = build_parser_helper(PARSER_HELPER)
    lookup_helper = build_lookup_helper(LOOKUP_HELPER)
    parser_first = build_parser_entry(PARSER_FIRST, FIRST_GLYPH, FIRST_CONTROL)
    parser_second = build_parser_entry(PARSER_SECOND, SECOND_GLYPH, SECOND_CONTROL)
    low_helper = build_low_helper(LOW_HELPER)
    low_classifier = build_low_classifier(LOW_CLASSIFIER)
    if len(parser) != PARSER_HELPER_CAPACITY or len(lookup_helper) > LOOKUP_HELPER_CAPACITY:
        raise SystemExit("persistent helper sizes differ")
    if len(parser_first) != 20 or len(parser_second) != 20:
        raise SystemExit("parser entry size differs")
    if LOW_HELPER + len(low_helper) > LOW_CLASSIFIER or \
            LOW_CLASSIFIER + len(low_classifier) > LOW_REGION_END:
        raise SystemExit("low helper/classifier window overflow")

    decoder = code_base
    decoder_blob = build_decoder(decoder, layout)
    huffman = align(decoder + len(decoder_blob))
    huffman_blob = build_huffman(huffman, layout)
    frame = align(huffman + len(huffman_blob))
    frame_blob = build_frame(frame, huffman, layout)
    used_end = frame + len(frame_blob)
    print(
        f"resident layout data={code_base - RESIDENT_BASE} "
        f"decoder={len(decoder_blob)} huffman={len(huffman_blob)} "
        f"frame={len(frame_blob)} used={used_end - RESIDENT_BASE}/{COPY_N}",
        flush=True,
    )
    if used_end > HEAP_BASE:
        raise SystemExit(f"resident overflow by {used_end - HEAP_BASE} bytes")

    routines = (
        ("parser_helper", PARSER_HELPER, parser),
        ("lookup_helper", LOOKUP_HELPER, lookup_helper),
        ("parser_first", PARSER_FIRST, parser_first),
        ("parser_second", PARSER_SECOND, parser_second),
        ("low_helper", LOW_HELPER, low_helper),
        ("low_classifier", LOW_CLASSIFIER, low_classifier),
        ("decoder", decoder, decoder_blob),
        ("huffman", huffman, huffman_blob),
        ("frame", frame, frame_blob),
    )
    routine_notes: list[str] = []
    for name, address, blob in routines:
        routine_notes.extend(old.validate_routine(name, address, blob))

    with ZipFile(BASE) as archive:
        infos = archive.infolist()
        members = {info.filename: archive.read(info.filename) for info in infos}
    before_members = dict(members)
    with ZipFile(ORIGINAL) as archive:
        original_font = archive.read(COMM)
    with ZipFile(CONTROL) as archive:
        control_font = archive.read(COMM)

    exe = bytearray(members[PSX])
    before_exe = bytes(exe)
    font = bytearray(members[COMM])
    before_font = bytes(font)

    # Complete native-cell recovery, then exact v151 overlays for assets whose
    # proven Korean-era location differs from the untouched disc.
    for row, col in plan.UI_CELLS:
        restore_cell(font, original_font, row, col)
    for row, col in ICON_CELLS:
        restore_cell(font, control_font, row, col)
    for index in PUNCTUATION_INDICES.values():
        copy_plane(font, control_font, index)
    if any(plane_bitmap(font, SPACE_INDEX)):
        raise SystemExit("v170 blank 0x9C plane was not preserved")
    for row, col in plan.UI_CELLS:
        expected = bytearray(cell_bytes(original_font, row, col))
        # Punctuation overlays may intentionally change planes inside two cells;
        # per-plane assertions below are authoritative for those cells.
        if (row, col) not in {(11, 7), (11, 8)} and cell_bytes(font, row, col) != bytes(expected):
            raise SystemExit(f"native UI cell restore differs: {row},{col}")
    for row, col in ICON_CELLS:
        if cell_bytes(font, row, col) != cell_bytes(control_font, row, col):
            raise SystemExit(f"button icon cell differs from v151: {row},{col}")
    for name, index in PUNCTUATION_INDICES.items():
        if plane_bitmap(font, index) != plane_bitmap(control_font, index):
            raise SystemExit(f"punctuation plane differs from v151: {name}")
    members[COMM] = bytes(font)

    # Resident data and state.
    resident = bytearray(COPY_N)
    for name, blob in resident_blobs.items():
        address, size = layout[name]
        if len(blob) != size:
            raise SystemExit(f"resident blob size differs: {name}")
        resident[address - RESIDENT_BASE:address - RESIDENT_BASE + size] = blob
    struct.pack_into(
        f"<{CACHE_N}H", resident, layout["owners"][0] - RESIDENT_BASE,
        *([0xFFFF] * CACHE_N),
    )
    struct.pack_into(
        "<4H", resident, layout["upload_rect"][0] - RESIDENT_BASE,
        CACHE_X, CACHE_Y, 3, old.CELL,
    )
    for address, blob in ((decoder, decoder_blob), (huffman, huffman_blob), (frame, frame_blob)):
        at = address - RESIDENT_BASE
        resident[at:at + len(blob)] = blob
    if any(resident[used_end - RESIDENT_BASE:]):
        raise SystemExit("resident tail is not zero")
    exe[old.file_at(SOURCE_BASE):old.file_at(SOURCE_BASE) + COPY_N] = resident

    # Persistent tables and helpers.
    range_blob = plan.CONFLICT_RANGES.read_bytes()
    if len(range_blob) != RANGE_BYTES:
        raise SystemExit("packed range table is not 96 bytes")
    exe[old.file_at(RANGE_RAM):old.file_at(RANGE_RAM) + RANGE_BYTES] = range_blob
    lookup_blob = plan.LOOKUP_TABLE.read_bytes()
    counts_blob = plan.HUFFMAN_COUNTS.read_bytes()
    checkpoints_blob = plan.SOURCE_CHECKPOINTS.read_bytes()
    exe[old.file_at(PACKED_LOOKUP_RAM):old.file_at(PACKED_LOOKUP_RAM) + PACKED_LOOKUP_BYTES] = lookup_blob
    exe[old.file_at(HUFFMAN_COUNTS_RAM):old.file_at(HUFFMAN_COUNTS_RAM) + len(counts_blob)] = counts_blob
    exe[old.file_at(HUFFMAN_CHECKPOINTS_RAM):old.file_at(HUFFMAN_CHECKPOINTS_RAM) + len(checkpoints_blob)] = checkpoints_blob
    for address, blob in (
        (PARSER_HELPER, parser), (LOOKUP_HELPER, lookup_helper),
        (PARSER_FIRST, parser_first), (PARSER_SECOND, parser_second),
        (LOW_HELPER, low_helper), (LOW_CLASSIFIER, low_classifier),
    ):
        exe[old.file_at(address):old.file_at(address) + len(blob)] = blob

    writes = (
        (old.DECODER_ENTRY, old.j(decoder), "dynamic decoder"),
        (old.GLYPH_PACKET_HOOK, old.j(LOW_HELPER), "row40 U helper"),
        (old.CLASSIFIER_CALL, old.jal(LOW_CLASSIFIER), "row40 text classifier"),
        (old.LATE_HOOK, old.jal(frame), "pre-DrawOT 28-slot wrapper"),
    )
    for address, value, _reason in writes:
        old.put_word(exe, address, value)

    system_rows, system_external_rows = repack_system_strings(exe)
    members[PSX] = bytes(exe)

    # Frozen topology and capacity guards.
    for address, expected, label in (
        (old.EARLY_HOOK, old.jal(old.STOCK_FRAME), "early stock frame"),
        (old.EARLY_DELAY, NOP, "early delay"),
        (old.LATE_DELAY, 0x26040070, "DrawOT argument delay"),
        (old.RENDER_HOOK, old.j(old.STATELESS_DRIVER), "stateless renderer"),
        (old.RENDER_HOOK + 4, NOP, "renderer delay"),
        (old.TPAGE_WORD, 0x34E7001F, "high tpage"),
        (old.DECODER_ENTRY + 4, NOP, "decoder delay"),
        (old.GLYPH_PACKET_HOOK + 4, NOP, "U helper delay"),
    ):
        if old.word(exe, address) != expected:
            raise SystemExit(f"hook guard differs: {label}")
    if old.word(exe, old.MEMCPY_LEN_AT) & 0xFFFF != COPY_N:
        raise SystemExit("startup copy length changed")
    heap_word = old.word(exe, old.HEAP_BASE_AT)
    heap_imm = struct.unpack("<h", struct.pack("<H", heap_word & 0xFFFF))[0]
    if 0x80200000 + heap_imm != HEAP_BASE:
        raise SystemExit("heap boundary changed")
    if len(exe) != len(before_exe):
        raise SystemExit("PSX.EXE size changed")

    changed_members = sorted(name for name in members if members[name] != before_members[name])
    if changed_members != [COMM, PSX]:
        raise SystemExit(f"changed member set differs: {changed_members}")
    if any(len(members[name]) != len(before_members[name]) for name in members):
        raise SystemExit("archive member length changed")

    # Disassembly readback.
    md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN)
    disassembly: list[str] = []
    for name, address, blob in routines:
        decoded = list(md.disasm(blob, address))
        if sum(item.size for item in decoded) != len(blob):
            raise SystemExit(f"Capstone could not decode all of {name}")
        disassembly.append(f"--- {name} 0x{address:08X} ({len(blob)} bytes) ---")
        disassembly.extend(
            f"{item.address:08X}  {item.mnemonic:<8} {item.op_str}" for item in decoded
        )

    ANALYSIS.mkdir(parents=True, exist_ok=True)
    DISASSEMBLY.write_text("\n".join(disassembly) + "\n", encoding="utf-8")
    with EXPECTED_WRITES.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(("runtime_address", "after", "reason"))
        for address, value, reason in writes:
            writer.writerow((f"0x{address:08X}", f"0x{value:08X}", reason))
    with SYSTEM_READBACK.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(system_rows[0]))
        writer.writeheader()
        writer.writerows(system_rows)
    with SYSTEM_EXTERNAL_READBACK.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(system_external_rows[0]))
        writer.writeheader()
        writer.writerows(system_external_rows)

    temporary = OUT_DIR / f"{OUT_STEM}_building.zip"
    if temporary.exists():
        raise SystemExit(f"refusing to reuse temporary output: {temporary.name}")
    with ZipFile(temporary, "w", ZIP_DEFLATED) as archive:
        for info in infos:
            archive.writestr(old.clone(info), members[info.filename])
    with ZipFile(temporary) as archive:
        if archive.namelist() != [info.filename for info in infos]:
            raise SystemExit("archive member order changed")
        for name, expected in members.items():
            if archive.read(name) != expected:
                raise SystemExit(f"archive roundtrip differs: {name}")
    stamp = digest(temporary.read_bytes())
    output = OUT_DIR / f"{OUT_STEM}_{stamp[:8]}.zip"
    if output.exists():
        raise SystemExit(f"refusing to overwrite existing output: {output.name}")
    temporary.replace(output)

    lines = [
        "v171 native UI asset recovery and 28-slot cache",
        "",
        f"base={BASE.name}", f"base_sha256={BASE_SHA256}",
        f"output={output.name}", f"sha256={stamp}",
        "changed_members=PSX.EXE COMM.IMG", "changed_other_members=0",
        "",
        "native_UI_complete_cells_restored=26",
        "v151_button_duplicate_cells_restored=5",
        f"v151_punctuation_planes_restored={len(PUNCTUATION_INDICES)}",
        "v170_blank_0x9C_plane=preserved",
        "battle_damage_digit_source_V208_V220=untouched-code/original-pixels-restored",
        f"system_fixed_strings_reencoded={len(system_rows)}",
        "system_string_semantics=unchanged Korean manifest text",
        f"external_system_fragments_preserved={len(system_external_rows)}",
        "embedded_system_pointer_words_preserved=2/2 PASS",
        f"pointer_safe_system_storage_bytes={sum(end - start for start, end in system_storage_ranges())}",
        "",
        f"dynamic_sources={SOURCE_N}", "Huffman_readback=462/462 PASS",
        "direct_dynamic_indices=254/254 PASS", "lookup_readback=409/409 PASS",
        f"cache_slots={CACHE_N}", f"cache_cells={CACHE_CELLS}",
        f"cache_VRAM=x{CACHE_X}..{CACHE_X + CACHE_CELLS * 3 - 1},y{CACHE_Y}..{CACHE_Y + old.CELL - 1}",
        "bounded_max_simultaneous_dynamic=26", "cache_fail_closed_at_29th_miss",
        "seventh_cell_sample=0 nonzero / 206 stock+v163 states",
        "",
        f"resident_data_bytes={code_base - RESIDENT_BASE}",
        f"decoder 0x{decoder:08X} / {len(decoder_blob)} bytes",
        f"frame routine 0x{frame:08X} / {len(frame_blob)} bytes",
        f"decoder_bytes={len(decoder_blob)}", f"huffman_bytes={len(huffman_blob)}",
        f"frame_bytes={len(frame_blob)}", f"resident_used={used_end - RESIDENT_BASE}/{COPY_N}",
        f"resident_free={HEAP_BASE - used_end}",
        "heap_boundary=0x801FF8B0 unchanged", "startup_copy=5356 unchanged",
        *routine_notes,
        "capstone_disassembly=PASS", "archive_member_order=PASS",
        "archive_member_lengths=PASS", "archive_roundtrip=PASS",
        "runtime=PENDING user cold boot and slots 1..9",
        "promotion_to_bible=NO until runtime verification",
        "rollback=v170",
    ]
    REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    print(REPORT)


if __name__ == "__main__":
    main()
