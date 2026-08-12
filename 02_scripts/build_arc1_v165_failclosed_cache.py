"""Build v165: a fail-closed 24-slot completed-glyph cache.

v164 proved that the pre-DrawOT upload timing and the high-page text path work,
but its static Korean font planes still occupy 50 physical COMM.IMG cells that
sampled game states use as non-text art.  This build restores those complete
cells from the untouched disc and moves every displaced shape into the dynamic
cache planned by :mod:`plan_dynamic_cache_v165_failclosed`.

The cache is deliberately bounded and fail-closed:

* direct one/two-byte codes keep their exact byte widths;
* a 40-record range table redirects only the 162 restored physical indices;
* the old 207 dynamic shapes and protected virtual slot 405 remain dynamic;
* 370 exact 12x12 shapes are canonical-Huffman coded inside the existing
  5,356-byte resident reservation;
* 24 slots use six complete 4-plane cells at strip A (x=961..978, y=480..491);
* if all 24 slots are active in one frame, a new miss becomes a blank glyph
  rather than overwriting a slot already referenced by that frame's packets.

No original file is written.  The frozen v164 archive is read-only and the
output name includes its own digest, so an existing archive is never replaced.
"""
from __future__ import annotations

import csv
import hashlib
import pickle
import struct
import sys
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))
sys.path.insert(0, str(ROOT / "06_tools/python_packages"))

from capstone import Cs, CS_ARCH_MIPS, CS_MODE_LITTLE_ENDIAN, CS_MODE_MIPS32  # noqa: E402
from build_ui_hud_e7_v73_dual_tpage_renderer import (  # noqa: E402
    Assembler,
    i_type,
    j,
    jal,
    r_type,
)
from audit_dynamic_cache_requirements import glyph_index, source_ranges  # noqa: E402
from plan_bulk_insertion import CACHE, CELL, IPR, PLANES, tokens  # noqa: E402
import plan_dynamic_cache_v165_failclosed as plan  # noqa: E402


BASE = plan.BASE
BASE_SHA256 = plan.BASE_SHA256
ORIGINAL = ROOT / "00_original/arc.zip"
ORIGINAL_SHA256 = "AE9F4366A1E7DA3805BB3BED3DDA9567E4CD4E669AF890E4E2A620D7861F11DD"
OUT_DIR = ROOT / "03_output"
OUT_STEM = "arc1_v165c_failclosed_24slot_cache_checkpoint_fix"
ANALYSIS = ROOT / "01_work/analysis/arc1_v165_failclosed_24slot_cache"
REPORT = ANALYSIS / "build_report.txt"
DISASSEMBLY = ANALYSIS / "mips_disassembly.txt"
EXPECTED_WRITES = ANALYSIS / "expected_writes.csv"
RESTORE_REPORT = ANALYSIS / "restored_cells.csv"

PSX, COMM = "PSX.EXE", "COMM.IMG"
RAM_TO_FILE = 0x8011A800
SOURCE_BASE, RESIDENT_BASE, COPY_N = 0x801A86EC, 0x801FE3C4, 5356
HEAP_BASE = RESIDENT_BASE + COPY_N
LOOKUP_RAM, LOOKUP_N = 0x801A7520, 409
DECODER_ENTRY = 0x801A74B8
DECODE_RETURN, SINGLE_PATH, WIDE_PATH = 0x8016B410, 0x8016B3E0, 0x8016B3F0
GLYPH_PACKET_HOOK = 0x8016B5D8
GLYPH_PACKET_RETURN = 0x8016B5E0
RENDER_HOOK = 0x8016B764
STATELESS_DRIVER = 0x801A20B0
CLASSIFIER_CALL = 0x801A2204
TPAGE_WORD = 0x801A2194
EARLY_HOOK, EARLY_DELAY = 0x8011C4AC, 0x8011C4B0
LATE_HOOK, LATE_DELAY = 0x8011C860, 0x8011C864
STOCK_FRAME, DRAWOT, LOADIMAGE = 0x8011C814, 0x80176E1C, 0x80177E4C
MEMCPY_LEN_AT, HEAP_BASE_AT = 0x801757CC, 0x80175810

CACHE_N, CACHE_CELLS = 24, 6
CACHE_ROW, CACHE_INDEX_BASE = 40, 40 * IPR
CACHE_X, CACHE_Y, CACHE_U, CACHE_V = 961, 480, 4, 224
RANGE_N = 40
SOURCE_N = 370
CHECKPOINT_GROUP = plan.CHECKPOINT_GROUP

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
    copied = ZipInfo(info.filename, info.date_time)
    for name in (
        "compress_type", "comment", "extra", "create_system", "create_version",
        "extract_version", "flag_bits", "volume", "internal_attr", "external_attr",
    ):
        setattr(copied, name, getattr(info, name))
    return copied


def file_at(address: int) -> int:
    return address - RAM_TO_FILE


def source_at(runtime_address: int) -> int:
    return file_at(SOURCE_BASE + runtime_address - RESIDENT_BASE)


def word(buf: bytes | bytearray, address: int) -> int:
    return struct.unpack_from("<I", buf, file_at(address))[0]


def put_word(buf: bytearray, address: int, value: int) -> None:
    struct.pack_into("<I", buf, file_at(address), value)


def load_address(asm: Assembler, register: int, address: int) -> None:
    asm.emit(i_type(0x0F, ZERO, register, address >> 16))
    asm.emit(i_type(0x0D, register, register, address & 0xFFFF))


def move(rd: int, rs: int) -> int:
    return r_type(rs, ZERO, rd, 0, 0x21)


def align(value: int, boundary: int = 4) -> int:
    return (value + boundary - 1) & -boundary


def read_layout() -> dict[str, tuple[int, int]]:
    with plan.LAYOUT.open(encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    result = {
        row["name"]: (int(row["runtime_address"], 0), int(row["size"]))
        for row in rows
    }
    expected = {
        "huffman_rows", "huffman_counts", "conflict_ranges",
        "source_checkpoints", "source_bitstream", "nibble_expand", "owners",
        "active_mask", "next_slot", "upload_rect", "cell_scratch",
        "decoded_glyph_rows",
    }
    if set(result) != expected:
        raise SystemExit(f"resident layout fields differ: {sorted(set(result) ^ expected)}")
    return result


def build_decoder(address: int, layout: dict[str, tuple[int, int]]) -> bytes:
    """Resolve old and newly displaced glyphs while preserving token widths."""
    ranges = layout["conflict_ranges"][0]
    owners = layout["owners"][0]
    active = layout["active_mask"][0]
    next_slot = layout["next_slot"][0]

    asm = Assembler(address)

    # E9/EA use the existing 409-entry virtual lookup namespace.
    asm.emit(i_type(0x09, V1, T0, -0xE9))
    asm.emit(i_type(0x0B, T0, T1, 2))
    asm.branch(0x05, T1, ZERO, "lookup")
    asm.emit(NOP)

    # Direct one-byte 01..DC and direct two-byte DD..E8 retain their exact
    # original widths.  Other wide leads return to the stock decoder.
    asm.emit(i_type(0x0B, V1, T0, 0xDD))
    asm.branch(0x05, T0, ZERO, "direct_single")
    asm.emit(NOP)
    asm.emit(i_type(0x0B, V1, T0, 0xE9))
    asm.branch(0x04, T0, ZERO, "stock_wide")
    asm.emit(NOP)

    asm.emit(i_type(0x24, A1, T1, 1))                    # trail
    asm.emit(i_type(0x09, V1, T0, -0xDD))
    asm.emit(r_type(ZERO, T0, T2, 8, 0x00))              # lead delta * 256
    asm.emit(r_type(T2, T0, T2, 0, 0x23))                # * 255
    asm.emit(r_type(T2, T1, T2, 0, 0x21))
    asm.emit(i_type(0x09, T2, T2, 0xDB))                 # +219; DD 01 -> 220
    asm.emit(i_type(0x0D, ZERO, T9, 2))
    asm.branch(0x04, ZERO, ZERO, "range_start")
    asm.emit(NOP)

    asm.label("direct_single")
    asm.emit(i_type(0x09, V1, T2, -1))
    asm.emit(i_type(0x0D, ZERO, T9, 1))

    # Forty sorted runs represent exactly the 162 restored physical indices.
    # An early index-before-start exit keeps common low direct codes inexpensive.
    asm.label("range_start")
    load_address(asm, T3, ranges)
    asm.emit(i_type(0x0D, ZERO, T4, RANGE_N))
    asm.label("range_loop")
    asm.emit(i_type(0x25, T3, T5, 0))                    # start
    asm.emit(i_type(0x24, T3, T6, 2))                    # length
    asm.emit(i_type(0x24, T3, T7, 3))                    # source base
    asm.emit(r_type(T2, T5, T8, 0, 0x2B))               # index < start
    asm.branch(0x05, T8, ZERO, "direct_static")
    asm.emit(i_type(0x09, T4, T4, -1))
    asm.emit(r_type(T2, T5, T8, 0, 0x23))               # delta
    asm.emit(r_type(T8, T6, T0, 0, 0x2B))               # delta < length
    asm.branch(0x05, T0, ZERO, "range_hit")
    asm.emit(i_type(0x09, T3, T3, 4))
    asm.branch(0x05, T4, ZERO, "range_loop")
    asm.emit(NOP)
    asm.branch(0x04, ZERO, ZERO, "direct_static")
    asm.emit(NOP)
    asm.label("range_hit")
    asm.emit(r_type(T7, T8, T4, 0, 0x21))                # dynamic source id
    asm.branch(0x04, ZERO, ZERO, "cache")
    asm.emit(NOP)

    asm.label("direct_static")
    asm.emit(i_type(0x09, T9, T0, -1))
    asm.branch(0x04, T0, ZERO, "stock_single")
    asm.emit(NOP)
    asm.label("stock_wide")
    asm.emit(j(WIDE_PATH))
    asm.emit(NOP)
    asm.label("stock_single")
    asm.emit(j(SINGLE_PATH))
    asm.emit(NOP)

    asm.label("lookup")
    asm.emit(i_type(0x24, A1, T1, 1))
    asm.emit(r_type(ZERO, T0, T2, 8, 0x00))
    asm.emit(r_type(T2, T0, T2, 0, 0x23))
    asm.emit(r_type(T2, T0, T2, 0, 0x23))                # lead delta * 254
    asm.emit(r_type(T2, T1, T2, 0, 0x21))
    asm.emit(i_type(0x09, T2, T2, -1))
    asm.emit(i_type(0x0B, T2, T3, LOOKUP_N))
    asm.branch(0x04, T3, ZERO, "lookup_invalid")
    asm.emit(NOP)
    asm.emit(r_type(ZERO, T2, T3, 1, 0x00))
    load_address(asm, T4, LOOKUP_RAM)
    asm.emit(r_type(T4, T3, T3, 0, 0x21))
    asm.emit(i_type(0x25, T3, T4, 0))
    asm.emit(i_type(0x0D, ZERO, T9, 2))                  # load-delay spacer
    asm.emit(i_type(0x0C, T4, T5, 0x8000))
    asm.branch(0x04, T5, ZERO, "lookup_static")
    asm.emit(NOP)
    asm.emit(i_type(0x0C, T4, T4, 0x7FFF))

    # Owner lookup.  Owners are source IDs, not physical indices.
    asm.label("cache")
    load_address(asm, T5, owners)
    asm.emit(move(T6, ZERO))
    asm.label("owner_scan")
    asm.emit(i_type(0x25, T5, T7, 0))
    asm.emit(i_type(0x09, T5, T5, 2))                   # load-delay spacer
    asm.branch(0x04, T7, T4, "cache_ready")
    asm.emit(NOP)
    asm.emit(i_type(0x09, T6, T6, 1))
    asm.emit(i_type(0x0B, T6, T7, CACHE_N))
    asm.branch(0x05, T7, ZERO, "owner_scan")
    asm.emit(NOP)

    # Miss: choose the next slot that is not already referenced by this frame.
    # If all 24 are active, fail closed with a blank glyph instead of corrupting
    # an earlier packet by reusing its physical slot.
    load_address(asm, T5, active)
    asm.emit(i_type(0x23, T5, T8, 0))
    load_address(asm, T5, next_slot)                     # load-delay spacing
    asm.emit(i_type(0x24, T5, T6, 0))
    asm.emit(i_type(0x0D, ZERO, T7, CACHE_N))
    asm.label("free_scan")
    asm.emit(i_type(0x0D, ZERO, T0, 1))
    asm.emit(r_type(T6, T0, T0, 0, 0x04))
    asm.emit(r_type(T8, T0, T1, 0, 0x24))
    asm.branch(0x04, T1, ZERO, "free_found")
    asm.emit(i_type(0x09, T7, T7, -1))
    asm.emit(i_type(0x09, T6, T6, 1))
    asm.emit(i_type(0x0B, T6, T1, CACHE_N))
    asm.branch(0x05, T1, ZERO, "free_nowrap")
    asm.emit(NOP)
    asm.emit(move(T6, ZERO))
    asm.label("free_nowrap")
    asm.branch(0x05, T7, ZERO, "free_scan")
    asm.emit(NOP)
    asm.emit(move(V1, ZERO))
    asm.branch(0x04, ZERO, ZERO, "finish")
    asm.emit(NOP)

    asm.label("free_found")
    asm.emit(i_type(0x09, T6, T7, 1))
    asm.emit(i_type(0x0B, T7, T1, CACHE_N))
    asm.branch(0x05, T1, ZERO, "next_ready")
    asm.emit(NOP)
    asm.emit(move(T7, ZERO))
    asm.label("next_ready")
    asm.emit(i_type(0x28, T5, T7, 0))
    load_address(asm, T5, owners)
    asm.emit(r_type(ZERO, T6, T7, 1, 0x00))
    asm.emit(r_type(T5, T7, T5, 0, 0x21))
    asm.emit(i_type(0x29, T5, T4, 0))
    asm.branch(0x04, ZERO, ZERO, "cache_ready")
    asm.emit(NOP)

    asm.label("cache_ready")
    asm.emit(i_type(0x0D, ZERO, T0, 1))
    asm.emit(r_type(T6, T0, T0, 0, 0x04))
    load_address(asm, T5, active)
    asm.emit(i_type(0x23, T5, T8, 0))
    asm.emit(NOP)
    asm.emit(r_type(T8, T0, T8, 0, 0x25))
    asm.emit(i_type(0x2B, T5, T8, 0))
    asm.emit(i_type(0x09, T6, V1, CACHE_INDEX_BASE))
    asm.branch(0x04, ZERO, ZERO, "finish")
    asm.emit(NOP)

    asm.label("lookup_invalid")
    asm.emit(i_type(0x0D, ZERO, T9, 2))
    asm.emit(move(V1, ZERO))
    asm.branch(0x04, ZERO, ZERO, "finish")
    asm.emit(NOP)
    asm.label("lookup_static")
    asm.emit(move(V1, T4))
    asm.label("finish")
    asm.emit(r_type(A1, T9, V0, 0, 0x21))
    asm.emit(i_type(0x2B, A2, V0, 0))
    asm.emit(j(DECODE_RETURN))
    asm.emit(NOP)
    return asm.finish()


def build_huffman_decoder(address: int, layout: dict[str, tuple[int, int]]) -> bytes:
    """Leaf routine: A0=source ID, A1=24-byte destination row buffer."""
    rows = layout["huffman_rows"][0]
    counts = layout["huffman_counts"][0]
    checkpoints = layout["source_checkpoints"][0]
    bitstream = layout["source_bitstream"][0]
    maximum_code_bits = layout["huffman_counts"][1]

    if CHECKPOINT_GROUP < 1 or CHECKPOINT_GROUP & (CHECKPOINT_GROUP - 1):
        raise SystemExit("checkpoint group must be a power of two")
    group_shift = CHECKPOINT_GROUP.bit_length() - 1
    group_mask = CHECKPOINT_GROUP - 1

    asm = Assembler(address)
    asm.emit(r_type(ZERO, A0, T0, group_shift, 0x02))     # source / group
    asm.emit(r_type(ZERO, T0, T0, 1, 0x00))
    load_address(asm, T1, checkpoints)
    asm.emit(r_type(T1, T0, T0, 0, 0x21))
    asm.emit(i_type(0x25, T0, T0, 0))                    # bit checkpoint
    asm.emit(i_type(0x0C, A0, T1, group_mask))           # load-delay spacer
    asm.emit(r_type(ZERO, T1, T2, 1, 0x00))
    asm.emit(r_type(T1, T2, T1, 0, 0x21))                # within * 3
    asm.emit(r_type(ZERO, T1, T1, 2, 0x00))              # skip = within * 12
    asm.emit(i_type(0x0D, ZERO, T2, CELL))               # rows to store
    load_address(asm, A2, counts)
    load_address(asm, A3, rows)
    load_address(asm, V0, bitstream)

    asm.label("symbol")
    asm.emit(move(T3, ZERO))                             # code
    asm.emit(move(T4, ZERO))                             # first code
    asm.emit(move(T5, ZERO))                             # first symbol
    asm.emit(move(T6, A2))                               # count pointer
    asm.emit(i_type(0x0D, ZERO, T9, maximum_code_bits))
    asm.label("bit")
    asm.emit(r_type(ZERO, T0, T7, 3, 0x02))              # byte index
    asm.emit(r_type(V0, T7, T7, 0, 0x21))
    asm.emit(i_type(0x24, T7, T7, 0))
    asm.emit(i_type(0x0C, T0, T8, 7))                    # load-delay spacer
    asm.emit(i_type(0x0E, T8, T8, 7))                    # 7 - bit-in-byte
    asm.emit(r_type(T8, T7, T7, 0, 0x06))
    asm.emit(i_type(0x0C, T7, T7, 1))
    asm.emit(r_type(ZERO, T3, T3, 1, 0x00))
    asm.emit(r_type(T3, T7, T3, 0, 0x25))
    asm.emit(i_type(0x09, T0, T0, 1))
    asm.emit(i_type(0x24, T6, T7, 0))                    # count at this length
    asm.emit(i_type(0x09, T6, T6, 1))                   # load-delay spacer
    asm.emit(r_type(T3, T4, T8, 0, 0x23))               # delta
    asm.emit(r_type(T8, T7, A0, 0, 0x2B))
    asm.branch(0x05, A0, ZERO, "found")
    asm.emit(i_type(0x09, T9, T9, -1))
    asm.emit(r_type(T5, T7, T5, 0, 0x21))
    asm.emit(r_type(T4, T7, T4, 0, 0x21))
    asm.emit(r_type(ZERO, T4, T4, 1, 0x00))
    asm.branch(0x05, T9, ZERO, "bit")
    asm.emit(NOP)
    asm.emit(move(T7, ZERO))                             # corrupt stream: blank row
    asm.branch(0x04, ZERO, ZERO, "process")
    asm.emit(NOP)

    asm.label("found")
    asm.emit(r_type(T5, T8, T8, 0, 0x21))
    asm.emit(r_type(ZERO, T8, T8, 1, 0x00))
    asm.emit(r_type(A3, T8, T8, 0, 0x21))
    asm.emit(i_type(0x25, T8, T7, 0))                    # decoded 12-bit row
    asm.label("process")
    asm.branch(0x04, T1, ZERO, "store")
    asm.emit(NOP)                                        # row load delay
    asm.emit(i_type(0x09, T1, T1, -1))
    asm.branch(0x04, ZERO, ZERO, "symbol")
    asm.emit(NOP)
    asm.label("store")
    asm.emit(i_type(0x29, A1, T7, 0))
    asm.emit(i_type(0x09, A1, A1, 2))
    asm.emit(i_type(0x09, T2, T2, -1))
    asm.branch(0x05, T2, ZERO, "symbol")
    asm.emit(NOP)
    asm.emit(JR_RA)
    asm.emit(NOP)
    return asm.finish()


def build_helper(address: int) -> bytes:
    """Add U=4 only to row-40 packets, then run the displaced stock load."""
    asm = Assembler(address)
    asm.emit(i_type(0x09, T0, A3, -CACHE_ROW))
    asm.emit(i_type(0x0B, A3, A3, 1))
    asm.branch(0x04, A3, ZERO, "out")
    asm.emit(NOP)
    asm.emit(i_type(0x24, A1, A3, 0x28))
    asm.emit(NOP)
    asm.emit(i_type(0x09, A3, A3, CACHE_U))
    asm.emit(i_type(0x28, A1, A3, 0x28))
    asm.label("out")
    asm.emit(i_type(0x24, A2, V0, 0x0E))
    asm.emit(j(GLYPH_PACKET_RETURN))
    asm.emit(NOP)
    return asm.finish()


def build_classifier(address: int) -> bytes:
    """High page only for row-40 V and the proven stock text CLUT family."""
    asm = Assembler(address)
    asm.emit(i_type(0x24, V1, V0, 0x29))
    asm.emit(i_type(0x25, V1, T8, 0x30))
    asm.emit(i_type(0x09, V0, V0, -CACHE_V))
    asm.emit(i_type(0x0B, V0, V0, 1))
    asm.emit(i_type(0x09, T8, T8, -0x7FC0))
    asm.emit(i_type(0x0B, T8, T8, 16))
    asm.emit(r_type(V0, T8, V0, 0, 0x24))
    asm.emit(JR_RA)
    asm.emit(NOP)
    return asm.finish()


def build_frame(address: int, huffman: int,
                layout: dict[str, tuple[int, int]]) -> bytes:
    """Rebuild active complete cells, upload them, then preserve DrawOT."""
    owners = layout["owners"][0]
    active = layout["active_mask"][0]
    rect = layout["upload_rect"][0]
    scratch = layout["cell_scratch"][0]
    decoded = layout["decoded_glyph_rows"][0]
    expand = layout["nibble_expand"][0]

    asm = Assembler(address)
    asm.emit(i_type(0x09, SP, SP, -0x50))
    for reg, offset in (
        (RA, 0x4C), (S0, 0x48), (S1, 0x44), (S2, 0x40),
        (S3, 0x3C), (S4, 0x38), (S5, 0x34), (S6, 0x30), (S7, 0x2C),
    ):
        asm.emit(i_type(0x2B, SP, reg, offset))
    asm.emit(i_type(0x2B, SP, A0, 0x20))                 # DrawOT argument

    load_address(asm, T0, active)
    asm.emit(i_type(0x23, T0, S0, 0))
    asm.emit(NOP)
    asm.emit(i_type(0x2B, T0, ZERO, 0))                  # consume this OT's mask
    asm.branch(0x04, S0, ZERO, "draw")
    asm.emit(NOP)
    load_address(asm, S1, owners)
    load_address(asm, S2, scratch)
    load_address(asm, S3, decoded)
    load_address(asm, S4, rect)
    asm.emit(move(S5, ZERO))                             # cell 0..5

    asm.label("cell_loop")
    asm.emit(i_type(0x0C, S0, S7, 0x0F))
    asm.emit(r_type(ZERO, S0, S0, 4, 0x02))
    asm.branch(0x04, S7, ZERO, "cell_next")
    asm.emit(NOP)

    # Clear one complete 3x12 16-bit cell (72 bytes / 18 words).
    asm.emit(move(T0, S2))
    asm.emit(i_type(0x0D, ZERO, T1, 18))
    asm.label("clear_loop")
    asm.emit(i_type(0x2B, T0, ZERO, 0))
    asm.emit(i_type(0x09, T0, T0, 4))
    asm.emit(i_type(0x09, T1, T1, -1))
    asm.branch(0x05, T1, ZERO, "clear_loop")
    asm.emit(NOP)

    asm.emit(move(S6, ZERO))                             # plane 0..3
    asm.label("plane_loop")
    asm.emit(i_type(0x0D, ZERO, T0, 1))
    asm.emit(r_type(S6, T0, T0, 0, 0x04))
    asm.emit(r_type(S7, T0, T0, 0, 0x24))
    asm.branch(0x04, T0, ZERO, "plane_next")
    asm.emit(NOP)

    asm.emit(r_type(ZERO, S5, T0, 3, 0x00))              # cell * 8 owner bytes
    asm.emit(r_type(ZERO, S6, T1, 1, 0x00))
    asm.emit(r_type(T0, T1, T0, 0, 0x21))
    asm.emit(r_type(S1, T0, T0, 0, 0x21))
    asm.emit(i_type(0x25, T0, A0, 0))                    # source ID
    asm.emit(move(A1, S3))                               # load-delay spacer
    asm.emit(jal(huffman))
    asm.emit(NOP)

    # Expand three four-pixel nibbles per row.  The 32-byte table stores plane
    # zero; shifting its result by S6 composes any of the four planes without
    # touching a neighbour plane.
    load_address(asm, A2, expand)
    asm.emit(move(T0, S3))
    asm.emit(move(T1, S2))
    asm.emit(i_type(0x0D, ZERO, T2, CELL))
    asm.label("row_loop")
    asm.emit(i_type(0x25, T0, T3, 0))
    asm.emit(i_type(0x09, T0, T0, 2))                   # load-delay spacer
    asm.emit(i_type(0x0D, ZERO, T4, 8))
    asm.emit(i_type(0x0D, ZERO, T5, 3))
    asm.label("nibble_loop")
    asm.emit(r_type(T4, T3, T6, 0, 0x06))
    asm.emit(i_type(0x0C, T6, T6, 0x0F))
    asm.emit(r_type(ZERO, T6, T6, 1, 0x00))
    asm.emit(r_type(A2, T6, T6, 0, 0x21))
    asm.emit(i_type(0x25, T6, T6, 0))
    asm.emit(i_type(0x25, T1, T7, 0))
    asm.emit(r_type(S6, T6, T6, 0, 0x04))               # load-delay spacing
    asm.emit(r_type(T7, T6, T7, 0, 0x25))
    asm.emit(i_type(0x29, T1, T7, 0))
    asm.emit(i_type(0x09, T1, T1, 2))
    asm.emit(i_type(0x09, T4, T4, -4))
    asm.emit(i_type(0x09, T5, T5, -1))
    asm.branch(0x05, T5, ZERO, "nibble_loop")
    asm.emit(NOP)
    asm.emit(i_type(0x09, T2, T2, -1))
    asm.branch(0x05, T2, ZERO, "row_loop")
    asm.emit(NOP)

    asm.label("plane_next")
    asm.emit(i_type(0x09, S6, S6, 1))
    asm.emit(i_type(0x0B, S6, T0, PLANES))
    asm.branch(0x05, T0, ZERO, "plane_loop")
    asm.emit(NOP)

    asm.emit(r_type(ZERO, S5, T0, 1, 0x00))
    asm.emit(r_type(T0, S5, T0, 0, 0x21))                # cell * 3
    asm.emit(i_type(0x09, T0, T0, CACHE_X))
    asm.emit(i_type(0x29, S4, T0, 0))
    asm.emit(move(A0, S4))
    asm.emit(move(A1, S2))
    asm.emit(jal(LOADIMAGE))
    asm.emit(NOP)

    asm.label("cell_next")
    asm.emit(i_type(0x09, S5, S5, 1))
    asm.emit(i_type(0x0B, S5, T0, CACHE_CELLS))
    asm.branch(0x05, T0, ZERO, "cell_loop")
    asm.emit(NOP)

    asm.label("draw")
    asm.emit(i_type(0x23, SP, A0, 0x20))
    asm.emit(NOP)
    asm.emit(jal(DRAWOT))
    asm.emit(NOP)
    for reg, offset in (
        (RA, 0x4C), (S0, 0x48), (S1, 0x44), (S2, 0x40),
        (S3, 0x3C), (S4, 0x38), (S5, 0x34), (S6, 0x30), (S7, 0x2C),
    ):
        asm.emit(i_type(0x23, SP, reg, offset))
    asm.emit(i_type(0x09, SP, SP, 0x50))
    asm.emit(JR_RA)
    asm.emit(NOP)
    return asm.finish()


LOAD_OPS = {0x20, 0x21, 0x23, 0x24, 0x25}
CONTROL_OPS = {0x02, 0x03, 0x04, 0x05, 0x06, 0x07}


def instruction_reads(word_value: int) -> set[int]:
    op = word_value >> 26
    rs, rt = (word_value >> 21) & 31, (word_value >> 16) & 31
    if op == 0:
        function = word_value & 0x3F
        if function == 0x08:                             # jr
            return {rs}
        if function in (0x00, 0x02, 0x03):              # immediate shifts
            return {rt}
        return {rs, rt} - {ZERO}
    if op in (0x02, 0x03, 0x0F):
        return set()
    if op in (0x04, 0x05):
        return {rs, rt} - {ZERO}
    if op in (0x06, 0x07):
        return {rs} - {ZERO}
    if op in (0x28, 0x29, 0x2B):                        # stores
        return {rs, rt} - {ZERO}
    return {rs} - {ZERO}


def validate_routine(name: str, address: int, blob: bytes) -> list[str]:
    if len(blob) % 4:
        raise SystemExit(f"{name} is not word-sized")
    words = struct.unpack(f"<{len(blob) // 4}I", blob)
    notes: list[str] = []
    for index, value in enumerate(words):
        pc = address + index * 4
        op = value >> 26
        if op in LOAD_OPS and index + 1 < len(words):
            target = (value >> 16) & 31
            if target and target in instruction_reads(words[index + 1]):
                raise SystemExit(
                    f"R3000 load delay hazard in {name} at 0x{pc:08X}: r{target}"
                )
        is_jr = op == 0 and (value & 0x3F) == 0x08
        if (op in CONTROL_OPS or is_jr) and index + 1 >= len(words):
            raise SystemExit(f"control transfer lacks a delay slot: {name} 0x{pc:08X}")
        if op in CONTROL_OPS and index + 1 < len(words):
            next_word = words[index + 1]
            next_op = next_word >> 26
            next_jr = next_op == 0 and (next_word & 0x3F) == 0x08
            if next_op in CONTROL_OPS or next_jr:
                raise SystemExit(f"control transfer in delay slot: {name} 0x{pc + 4:08X}")
        if op in (0x04, 0x05, 0x06, 0x07):
            immediate = value & 0xFFFF
            immediate = immediate - 0x10000 if immediate & 0x8000 else immediate
            target = pc + 4 + immediate * 4
            if not address <= target < address + len(blob):
                raise SystemExit(
                    f"branch leaves {name}: 0x{pc:08X} -> 0x{target:08X}"
                )
    notes.append(f"{name}=0x{address:08X}/{len(blob)} bytes")
    notes.append(f"{name}_r3000_load_delay=PASS")
    notes.append(f"{name}_branch_delay=PASS")
    return notes


def unpack_ranges(blob: bytes) -> dict[int, int]:
    if len(blob) != RANGE_N * 4:
        raise SystemExit("conflict range artifact size differs")
    result: dict[int, int] = {}
    for at in range(0, len(blob), 4):
        start, length, source = struct.unpack_from("<HBB", blob, at)
        for delta in range(length):
            if start + delta in result:
                raise SystemExit("conflict ranges overlap")
            result[start + delta] = source + delta
    return result


def decode_sources(layout: dict[str, tuple[int, int]]) -> list[tuple[int, ...]]:
    rows = struct.unpack(
        f"<{plan.HUFFMAN_ROWS.stat().st_size // 2}H", plan.HUFFMAN_ROWS.read_bytes()
    )
    counts = plan.HUFFMAN_COUNTS.read_bytes()
    checkpoints = struct.unpack(
        f"<{plan.SOURCE_CHECKPOINTS.stat().st_size // 2}H",
        plan.SOURCE_CHECKPOINTS.read_bytes(),
    )
    stream = plan.SOURCE_BITSTREAM.read_bytes()

    def symbol(bit_position: int) -> tuple[int, int]:
        code = first_code = first_symbol = 0
        for count in counts:
            byte, bit = divmod(bit_position, 8)
            if byte >= len(stream):
                raise SystemExit("Python Huffman read escaped bitstream")
            code = (code << 1) | ((stream[byte] >> (7 - bit)) & 1)
            bit_position += 1
            delta = code - first_code
            if 0 <= delta < count:
                return rows[first_symbol + delta], bit_position
            first_symbol += count
            first_code = (first_code + count) << 1
        raise SystemExit("Python Huffman read found an invalid code")

    result = []
    for source in range(SOURCE_N):
        group, within = divmod(source, CHECKPOINT_GROUP)
        bit_position = checkpoints[group]
        decoded = []
        for ordinal in range((within + 1) * CELL):
            row, bit_position = symbol(bit_position)
            if ordinal >= within * CELL:
                decoded.append(row)
        result.append(tuple(decoded))
    if len(result) != SOURCE_N or any(len(value) != CELL for value in result):
        raise SystemExit("decoded source dimensions differ")
    del layout
    return result


def rows_to_bitmap(rows: tuple[int, ...]) -> tuple[int, ...]:
    return tuple(
        1 if rows[y] & (1 << (CELL - 1 - x)) else 0
        for y in range(CELL) for x in range(CELL)
    )


def cell_bytes(font: bytes | bytearray, row: int, col: int) -> bytes:
    return b"".join(
        font[(row * CELL + y) * 0x380 + col * (CELL // 2):
             (row * CELL + y) * 0x380 + (col + 1) * (CELL // 2)]
        for y in range(CELL)
    )


def restore_cell(font: bytearray, original: bytes, row: int, col: int) -> None:
    for y in range(CELL):
        at = (row * CELL + y) * 0x380 + col * (CELL // 2)
        font[at:at + CELL // 2] = original[at:at + CELL // 2]


def main() -> None:
    # Regenerate every analysis artifact from the hash-locked v164 input first.
    plan.main()
    if digest(BASE.read_bytes()) != BASE_SHA256:
        raise SystemExit("v164 archive hash differs")
    if digest(ORIGINAL.read_bytes()) != ORIGINAL_SHA256:
        raise SystemExit("untouched original archive hash differs")

    layout = read_layout()
    artifact_for = {
        "huffman_rows": plan.HUFFMAN_ROWS,
        "huffman_counts": plan.HUFFMAN_COUNTS,
        "conflict_ranges": plan.CONFLICT_RANGES,
        "source_checkpoints": plan.SOURCE_CHECKPOINTS,
        "source_bitstream": plan.SOURCE_BITSTREAM,
        "nibble_expand": plan.NIBBLE_EXPAND,
    }
    for name, path in artifact_for.items():
        if path.stat().st_size != layout[name][1]:
            raise SystemExit(f"artifact/layout size differs: {name}")

    with ZipFile(BASE) as archive:
        infos = archive.infolist()
        members = {info.filename: archive.read(info.filename) for info in infos}
    base_members = dict(members)
    with ZipFile(ORIGINAL) as archive:
        original_font = archive.read(COMM)
    base_exe, base_font = members[PSX], members[COMM]
    if len(base_exe) != 587776 or struct.unpack_from("<II", base_exe, 0x18) != \
            (0x8011B000, 0x8F000):
        raise SystemExit("v164 executable layout differs")
    if len(base_font) != len(original_font) != 458752:
        raise SystemExit("COMM.IMG size differs")

    # Parse the exact plan and verify its source bitmaps independently.
    with plan.SOURCE_MANIFEST.open(encoding="utf-8-sig", newline="") as handle:
        source_rows = list(csv.DictReader(handle))
    if [int(row["source_id"]) for row in source_rows] != list(range(SOURCE_N)):
        raise SystemExit("source manifest is not exactly 0..369")
    source_char = {int(row["source_id"]): row["char"] for row in source_rows}
    conflict_source = {
        int(row["old_physical_index"]): int(row["source_id"])
        for row in source_rows if row["kind"] == "restored_static_conflict"
    }
    old_source_to_new = {
        int(row["old_source_id"]): int(row["source_id"])
        for row in source_rows if row["kind"] == "existing_dynamic"
    }
    if len(conflict_source) != 162 or len(old_source_to_new) != 207:
        raise SystemExit("source manifest categories differ")
    range_map = unpack_ranges(plan.CONFLICT_RANGES.read_bytes())
    if range_map != conflict_source:
        raise SystemExit("direct range map differs from the 162 restored indices")

    with plan.ASSIGNMENTS.open(encoding="utf-8-sig", newline="") as handle:
        assignments = list(csv.DictReader(handle))
    index_char = {
        int(row["physical_index"]): row["char"]
        for row in assignments if row["physical_index"]
    }
    old_source_char = {
        int(row["source_id"]): row["char"]
        for row in assignments if row["source_id"]
    }
    shapes: dict[tuple[int, ...], str] = pickle.loads(CACHE.read_bytes())
    decoded_rows = decode_sources(layout)
    decoded_bitmaps = [rows_to_bitmap(value) for value in decoded_rows]
    for source, bitmap in enumerate(decoded_bitmaps):
        char = source_char[source]
        if char.startswith("<VIRTUAL:"):
            continue
        if shapes.get(bitmap) != char:
            raise SystemExit(f"source bitmap identity differs: {source} {char!r}")

    # Restore all 50 complete physical cells, never just one plane in a shared cell.
    with plan.RESTORE_CELLS.open(encoding="utf-8-sig", newline="") as handle:
        restore_rows = list(csv.DictReader(handle))
    if len(restore_rows) != 50:
        raise SystemExit("restore manifest no longer has 50 cells")
    font = bytearray(base_font)
    restore_details = []
    for row_data in restore_rows:
        row, col = int(row_data["row"]), int(row_data["col"])
        before_cell = cell_bytes(font, row, col)
        original_cell = cell_bytes(original_font, row, col)
        restore_cell(font, original_font, row, col)
        if cell_bytes(font, row, col) != original_cell:
            raise SystemExit(f"cell restore readback differs: {row},{col}")
        restore_details.append((row, col, digest(before_cell), digest(original_cell)))
    allowed_font_bytes = set()
    for row_data in restore_rows:
        row, col = int(row_data["row"]), int(row_data["col"])
        for y in range(CELL):
            at = (row * CELL + y) * 0x380 + col * (CELL // 2)
            allowed_font_bytes.update(range(at, at + CELL // 2))
    actual_font_diff = {i for i, (a, b) in enumerate(zip(base_font, font)) if a != b}
    if not actual_font_diff or not actual_font_diff <= allowed_font_bytes:
        raise SystemExit("COMM.IMG changed outside the 50 restored cells")
    members[COMM] = bytes(font)

    old_lut = plan.read_runtime_lut(base_exe)
    new_lut = struct.unpack(f"<{LOOKUP_N}H", plan.LOOKUP_TABLE.read_bytes())
    if len(old_lut) != LOOKUP_N or len(new_lut) != LOOKUP_N:
        raise SystemExit("runtime lookup size differs")
    if new_lut[plan.PROTECTED_DYNAMIC_SLOT] != 0x8000 | 369:
        raise SystemExit("protected slot 405 is not dynamic source 369")
    if any(not (value & 0x8000) and value in conflict_source for value in new_lut):
        raise SystemExit("a lookup alias still points into a restored cell")
    if any((value & 0x7FFF) >= SOURCE_N for value in new_lut if value & 0x8000):
        raise SystemExit("a lookup source ID exceeds 369")

    # All direct assignment codes must agree with the game's real *255 formula.
    for row in assignments:
        if not row["code_2byte"] or not row["physical_index"]:
            continue
        code = bytes.fromhex(row["code_2byte"])
        if code[0] not in range(0xDD, 0xE9):
            continue
        expected = int(row["physical_index"])
        actual = (code[0] - 0xDD) * 255 + code[1] + 0xDB
        if actual != expected:
            raise SystemExit(
                f"direct wide formula differs for {row['char']!r}: {actual} != {expected}"
            )

    # Verify semantic identity for every bounded Hangul token without rewriting a
    # single byte.  The protected non-Hangul slot is checked separately.
    def old_char(token: bytes) -> str | None:
        if len(token) == 2 and token[0] in (0xE9, 0xEA):
            slot = (token[0] - 0xE9) * 254 + token[1] - 1
            if not 0 <= slot < LOOKUP_N:
                return None
            if slot == plan.PROTECTED_DYNAMIC_SLOT:
                return source_char[369]
            value = old_lut[slot]
            return old_source_char.get(value & 0x7FFF) if value & 0x8000 \
                else index_char.get(value)
        value = glyph_index(token, old_lut)
        return index_char.get(value) if value is not None else None

    def new_char(token: bytes) -> str | None:
        if len(token) == 2 and token[0] in (0xE9, 0xEA):
            slot = (token[0] - 0xE9) * 254 + token[1] - 1
            if not 0 <= slot < LOOKUP_N:
                return None
            value = new_lut[slot]
            return source_char.get(value & 0x7FFF) if value & 0x8000 \
                else index_char.get(value)
        value = glyph_index(token, old_lut)
        if value is None:
            return None
        return source_char[range_map[value]] if value in range_map else index_char.get(value)

    units = (
        list(plan.body_units(members, source_ranges()))
        + list(plan.active_slot_units(members, source_ranges()))
        + list(plan.exe_units(members))
    )
    semantic_tokens = protected_tokens = 0
    for _label, payload in units:
        for token in tokens(payload):
            before_char = old_char(token)
            if before_char is None:
                continue
            after_char = new_char(token)
            if after_char != before_char:
                raise SystemExit(
                    f"bounded token semantic change: {token.hex(' ').upper()} "
                    f"{before_char!r} -> {after_char!r}"
                )
            semantic_tokens += 1
            protected_tokens += before_char == source_char[369]
    if not semantic_tokens or protected_tokens != 2:
        raise SystemExit(
            f"bounded semantic coverage differs: {semantic_tokens}, protected={protected_tokens}"
        )

    # Build the resident block inside the unchanged v151-v164 reservation.
    code_base = align(
        layout["decoded_glyph_rows"][0] + layout["decoded_glyph_rows"][1]
    )
    decoder = code_base
    decoder_blob = build_decoder(decoder, layout)
    huffman = align(decoder + len(decoder_blob))
    huffman_blob = build_huffman_decoder(huffman, layout)
    helper = align(huffman + len(huffman_blob))
    helper_blob = build_helper(helper)
    classifier = align(helper + len(helper_blob))
    classifier_blob = build_classifier(classifier)
    frame = align(classifier + len(classifier_blob))
    frame_blob = build_frame(frame, huffman, layout)
    used_end = frame + len(frame_blob)
    if used_end > HEAP_BASE:
        raise SystemExit(
            f"resident routines exceed the 5,356-byte reservation by {used_end - HEAP_BASE}"
        )

    routine_notes = []
    for name, address, blob in (
        ("decoder", decoder, decoder_blob),
        ("huffman", huffman, huffman_blob),
        ("helper", helper, helper_blob),
        ("classifier", classifier, classifier_blob),
        ("frame", frame, frame_blob),
    ):
        routine_notes.extend(validate_routine(name, address, blob))

    resident = bytearray(COPY_N)
    for name, path in artifact_for.items():
        address, size = layout[name]
        blob = path.read_bytes()
        resident[address - RESIDENT_BASE:address - RESIDENT_BASE + size] = blob
    owners = layout["owners"][0]
    struct.pack_into(f"<{CACHE_N}H", resident, owners - RESIDENT_BASE,
                     *([0xFFFF] * CACHE_N))
    rect = layout["upload_rect"][0]
    struct.pack_into("<4H", resident, rect - RESIDENT_BASE,
                     CACHE_X, CACHE_Y, 3, CELL)
    for address, blob in (
        (decoder, decoder_blob), (huffman, huffman_blob), (helper, helper_blob),
        (classifier, classifier_blob), (frame, frame_blob),
    ):
        at = address - RESIDENT_BASE
        resident[at:at + len(blob)] = blob
    if any(resident[used_end - RESIDENT_BASE:]):
        raise SystemExit("resident bytes after the used boundary are nonzero")

    exe = bytearray(base_exe)
    before_exe = bytes(exe)
    exe[file_at(SOURCE_BASE):file_at(SOURCE_BASE) + COPY_N] = resident
    exe[file_at(LOOKUP_RAM):file_at(LOOKUP_RAM) + LOOKUP_N * 2] = \
        plan.LOOKUP_TABLE.read_bytes()

    writes = (
        (DECODER_ENTRY, word(exe, DECODER_ENTRY), j(decoder), "decoder jump"),
        (GLYPH_PACKET_HOOK, word(exe, GLYPH_PACKET_HOOK), j(helper), "U helper jump"),
        (CLASSIFIER_CALL, word(exe, CLASSIFIER_CALL), jal(classifier), "text classifier call"),
        (LATE_HOOK, word(exe, LATE_HOOK), jal(frame), "pre-DrawOT cache wrapper"),
    )
    for address, _before, after, _reason in writes:
        put_word(exe, address, after)

    # Fixed call topology and the displaced instructions must remain intact.
    guards = (
        (EARLY_HOOK, jal(STOCK_FRAME), "early stock-frame call"),
        (EARLY_DELAY, NOP, "early delay slot"),
        (LATE_DELAY, 0x26040070, "late DrawOT argument delay slot"),
        (RENDER_HOOK, j(STATELESS_DRIVER), "stateless high-page driver"),
        (RENDER_HOOK + 4, NOP, "renderer hook delay slot"),
        (TPAGE_WORD, 0x34E7001F, "high-page tpage 0x1F"),
        (DECODER_ENTRY + 4, NOP, "decoder hook delay slot"),
        (GLYPH_PACKET_HOOK + 4, NOP, "glyph helper delay slot"),
    )
    for address, expected, label in guards:
        if word(exe, address) != expected:
            raise SystemExit(
                f"guard failed at 0x{address:08X}: 0x{word(exe, address):08X} "
                f"!= 0x{expected:08X} ({label})"
            )
    copy_ins = word(exe, MEMCPY_LEN_AT)
    if (copy_ins >> 26, (copy_ins >> 16) & 31, copy_ins & 0xFFFF) != \
            (0x09, A2, COPY_N):
        raise SystemExit("startup resident copy length changed")
    heap_ins = word(exe, HEAP_BASE_AT)
    heap_imm = heap_ins & 0xFFFF
    heap_imm = heap_imm - 0x10000 if heap_imm & 0x8000 else heap_imm
    if 0x80200000 + heap_imm != HEAP_BASE:
        raise SystemExit("heap boundary changed")
    if word(exe, LOADIMAGE) != 0x27BDFFD0:
        raise SystemExit("LoadImage prologue differs")
    if len(exe) != len(base_exe):
        raise SystemExit("PSX.EXE size changed")
    members[PSX] = bytes(exe)

    if any(
        name not in (PSX, COMM) and members[name] != base_members[name]
        for name in members
    ):
        raise SystemExit("a member other than PSX.EXE/COMM.IMG changed")

    # Every EXE byte change must be in a declared hook, lookup, or resident source.
    allowed_exe = set(range(file_at(SOURCE_BASE), file_at(SOURCE_BASE) + COPY_N))
    allowed_exe.update(range(file_at(LOOKUP_RAM), file_at(LOOKUP_RAM) + LOOKUP_N * 2))
    for address, _before, _after, _reason in writes:
        allowed_exe.update(range(file_at(address), file_at(address) + 4))
    actual_exe_diff = {i for i, (a, b) in enumerate(zip(before_exe, exe)) if a != b}
    if not actual_exe_diff or not actual_exe_diff <= allowed_exe:
        extra = sorted(actual_exe_diff - allowed_exe)[:20]
        raise SystemExit(f"PSX.EXE changed outside declared ranges: {extra}")

    # Full Capstone readback; no instruction bytes may be undecodable.
    md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN)
    disassembly = []
    for name, address, blob in (
        ("decoder", decoder, decoder_blob),
        ("huffman", huffman, huffman_blob),
        ("helper", helper, helper_blob),
        ("classifier", classifier, classifier_blob),
        ("frame", frame, frame_blob),
    ):
        instructions = list(md.disasm(blob, address))
        if sum(instruction.size for instruction in instructions) != len(blob):
            raise SystemExit(f"Capstone could not decode all of {name}")
        disassembly.append(f"--- {name} 0x{address:08X} ({len(blob)} bytes) ---")
        disassembly.extend(
            f"{instruction.address:08X}  {instruction.mnemonic:<8} {instruction.op_str}"
            for instruction in instructions
        )

    ANALYSIS.mkdir(parents=True, exist_ok=True)
    DISASSEMBLY.write_text("\n".join(disassembly) + "\n", encoding="utf-8")
    with EXPECTED_WRITES.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(("runtime_address", "before", "after", "reason"))
        for address, before, after, reason in writes:
            writer.writerow((f"0x{address:08X}", f"0x{before:08X}",
                             f"0x{after:08X}", reason))
    with RESTORE_REPORT.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(("row", "col", "v164_cell_sha256", "original_cell_sha256"))
        writer.writerows(restore_details)

    temporary = OUT_DIR / f"{OUT_STEM}_building.zip"
    if temporary.exists():
        raise SystemExit(f"refusing to reuse temporary output: {temporary.name}")
    with ZipFile(temporary, "w", ZIP_DEFLATED) as archive:
        for info in infos:
            archive.writestr(clone(info), members[info.filename])
    with ZipFile(temporary) as archive:
        rebuilt_infos = archive.infolist()
        if [info.filename for info in rebuilt_infos] != [info.filename for info in infos]:
            raise SystemExit("archive member order changed")
        for name, expected in members.items():
            if archive.read(name) != expected:
                raise SystemExit(f"archive readback differs: {name}")
    stamp = digest(temporary.read_bytes())
    output = OUT_DIR / f"{OUT_STEM}_{stamp[:8]}.zip"
    if output.exists():
        raise SystemExit(f"refusing to overwrite existing output: {output.name}")
    temporary.replace(output)

    routine_bytes = used_end - code_base
    lines = [
        "v165 fail-closed 24-slot completed-glyph cache",
        "",
        f"base={BASE.name}",
        f"base_sha256={BASE_SHA256}",
        f"output={output.name}",
        f"sha256={stamp}",
        f"archive_members={len(members)}",
        "changed_members=PSX.EXE COMM.IMG",
        "changed_other_members=0",
        "",
        "restored_complete_COMM_cells=50",
        "restored_static_Hangul_sources=162",
        "existing_dynamic_sources=207",
        "protected_dynamic_sources=1",
        "dynamic_sources_total=370",
        f"bounded_semantic_tokens_verified={semantic_tokens}",
        "text_token_width_changes=0",
        "direct_range_entries=40",
        "direct_range_indices=162/162 PASS",
        "protected_virtual_slot_405=source 369 PASS",
        "Huffman_source_readback=370/370 PASS",
        "",
        f"cache_slots={CACHE_N}",
        f"cache_cells={CACHE_CELLS}",
        f"cache_VRAM=x{CACHE_X}..{CACHE_X + CACHE_CELLS * 3 - 1},y{CACHE_Y}..{CACHE_Y + CELL - 1}",
        "cache_overflow=blank glyph; never overwrite an active slot",
        "cache_cell_backing=72-byte complete-cell rebuild scratch",
        "cache_upload_timing=after stock update/display setup, immediately before DrawOT",
        "",
        f"resident_data_bytes={code_base - RESIDENT_BASE}",
        f"resident_code_bytes={routine_bytes}",
        f"resident_used_bytes={used_end - RESIDENT_BASE}",
        f"resident_free_bytes={HEAP_BASE - used_end}",
        f"resident_budget={COPY_N}",
        "heap_boundary=0x801FF8B0 unchanged",
        "startup_copy=5356 bytes unchanged",
        "",
        *routine_notes,
        "capstone_disassembly=PASS",
        "declared_EXE_diff_ranges=PASS",
        "COMM_diff_within_50_restored_cells=PASS",
        "archive_roundtrip=PASS",
        "",
        "runtime_verification=PENDING user cold boot",
        "promotion_to_bible=NO until runtime verification",
        "rollback=v164",
    ]
    REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
