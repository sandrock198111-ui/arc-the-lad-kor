"""Build a clean-original Pilgi 16px johab runtime proof of concept.

This is a deliberately narrow successor to ``build_arc1_johab_font_poc.py``.
It keeps the stock 12x12 renderer for Japanese text, menus, battle UI, icons,
and every non-diagnostic path.  Only the two dialogue glyph-builder calls are
routed through a wrapper.  For the 31 diagnostic component/blank codes the
wrapper:

* keeps the text state at its stock 12x12 values,
* lets the original builder allocate and initialize the packet,
* replaces that packet's U/V and W/H with a guarded 16x16 physical slot, and
* adjusts X by +2 for cho/blank or -12 for jung/jong/filler, producing a
  14px syllable advance without leaking custom dimensions into later text.

The physical component planes are packed into scattered, non-overlapping
16x16 rectangles below V=204.  Every overlapped original 12x12 plane is blank,
outside the conservative text-reference set, and belongs to a cell with text
reads but zero non-text reads across the existing 509-state audit.

There is no dynamic cache, global 15-column atlas, global code rewrite, E2,
expanded executable, UI repack, or bulk translation.  The result is TEST_ONLY
until a cold-boot run confirms the lower four rows and normal progression.
"""

from __future__ import annotations

import argparse
import csv
import functools
import hashlib
import io
import json
import os
import struct
import sys
import time
import zlib
from collections import Counter
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile


ROOT = Path(__file__).resolve().parents[1]
LOCAL_PACKAGES = ROOT / "06_tools/python_packages"
if LOCAL_PACKAGES.is_dir():
    sys.path.insert(0, str(LOCAL_PACKAGES))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import PIL  # noqa: E402
import capstone  # noqa: E402
from PIL import Image, ImageDraw, ImageFont, features  # noqa: E402

import build_arc1_johab_font_poc as base  # noqa: E402


BuildError = base.BuildError

BASE_ZIP = base.BASE_ZIP
OUTPUT_DIR = base.OUTPUT_DIR
ANALYSIS_DIR = ROOT / "01_work/analysis/johab_font_16px_poc"
OUTPUT_STEM = "arc1_johab_font_16px_poc_pilgi_TEST_ONLY"

PSX = base.PSX
COMM = base.COMM
TEST_DAT = base.TEST_DAT
EXPECTED_CHANGED_MEMBERS = base.EXPECTED_CHANGED_MEMBERS

FONT_SIZE = 16
HORIZONTAL_ADVANCE = 14
STATE_VERTICAL_SPACING = 2
THRESHOLD = 96
ROW_BYTES = base.ROW_BYTES
ORIGINAL_CELL = base.GLYPH_SIZE
ORIGINAL_COLS = base.GLYPH_COLS
PLANES = base.PLANES

# The 13 advancing choseong shapes are followed by one custom 16px blank.
# Keeping both in one range makes the runtime classifier compact.  A normal
# byte 0x01 is used once at the beginning of each body solely to make the odd
# fixed capacities reachable before the object switches from 12px to 16px.
ADVANCE_START = 1041
ADVANCE_SHAPES = 13
CUSTOM_SPACE_INDEX = ADVANCE_START + ADVANCE_SHAPES
ADVANCE_COUNT = ADVANCE_SHAPES + 1

# Sixteen unique jung/jong shapes plus the established invisible flow filler.
REST_START = 1125
REST_SHAPES = 16
SAFE_FILLER_INDEX = REST_START + REST_SHAPES
REST_COUNT = REST_SHAPES + 1
LEADING_BLANK_BYTE = 0x01

# The selected grid deliberately stays in the original low texture page.
GRID_X_OFFSET = 4
GRID_Y_OFFSET = 12
GRID_STEP = 16
MAX_U = 236
MAX_V = 236
EXPECTED_SAFE_RECTANGLES = 20
EXPECTED_SAFE_SLOTS = 60
EXPECTED_SAFE_PLANES = {0: 13, 1: 16, 2: 11, 3: 20}

EXE_LOAD = base.EXE_LOAD
GLYPH_BUILDER = 0x8016B518
DIALOGUE_CALLS = (0x8016BB8C, 0x8016BDA0)
ORIGINAL_GLYPH_CALL = 0x0C05AD46
ORIGINAL_DIALOGUE_DELAY = 0x02002821  # move a1,s0

# The 245-byte original cave is enough for the 196-byte wrapper.  The U/V
# table uses the first 62 bytes of the independently runtime-accepted 1 KiB
# v0.41 E9/EA cave.  Both ranges are zero in the pristine executable.
WRAPPER_ADDRESS = 0x8018FCD0
WRAPPER_CAVE_END = 0x8018FDC5
COORD_TABLE_ADDRESS = 0x801A7460
COORD_TABLE_CAPACITY = 128

# A raw scan of the whole EXE image sees these ten words in two monotonic data
# tables as PC-relative branches into the zero cave.  They are not executable
# code (the surrounding words form the same numeric sequence), and v0.41 used
# this exact 1 KiB cave successfully at runtime.  Pinning every source word is
# stricter than silently ignoring apparent branches while avoiding the false
# positive that stopped the first 16px build attempt.
KNOWN_TABLE_DATA_EDGES = (
    (0x801A23E4, 0x801A74B0, "branch-op5", 0x144C1432),
    (0x801A3A40, 0x801A7468, "branch-op1", 0x06AA0E89),
    (0x801A3A44, 0x801A7478, "branch-op1", 0x06A40E8C),
    (0x801A3A48, 0x801A7488, "branch-op1", 0x069E0E8F),
    (0x801A3A4C, 0x801A7494, "branch-op1", 0x06990E91),
    (0x801A3A50, 0x801A74A4, "branch-op1", 0x06930E94),
    (0x801A3A54, 0x801A74B0, "branch-op1", 0x068D0E96),
    (0x801A3A58, 0x801A74C0, "branch-op1", 0x06870E99),
    (0x801A3A5C, 0x801A74CC, "branch-op1", 0x06820E9B),
    (0x801A3A60, 0x801A74DC, "branch-op1", 0x067C0E9E),
)

# The original D941 cave has no apparent incoming control edge.  Relocation
# probes may override this with an exact tuple of data-table false positives;
# an unlisted edge still fails closed.
KNOWN_WRAPPER_DATA_EDGES: tuple[tuple[int, int, str, int], ...] = ()

TEST_SITES = base.TEST_SITES
NEWLINE = base.NEWLINE
ORIGINAL_SPEAKER_PREFIX = base.ORIGINAL_SPEAKER_PREFIX
PROVEN_LINEBREAK_COUNTS = base.PROVEN_LINEBREAK_COUNTS
TEXT_OBJECT_GLYPH_LIMIT = base.TEXT_OBJECT_GLYPH_LIMIT


def step(message: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {message}", flush=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--font-zip", type=Path, required=True)
    parser.add_argument("--font-profile", choices=sorted(base.FONT_PROFILES), default="pilgi")
    parser.add_argument("--base", type=Path, default=BASE_ZIP)
    parser.add_argument("--output-dir", type=Path, default=OUTPUT_DIR)
    parser.add_argument("--analysis-dir", type=Path, default=ANALYSIS_DIR)
    return parser.parse_args()


def jal_word(address: int) -> int:
    if address & 3:
        raise BuildError(f"unaligned jal address {address:#x}")
    return 0x0C000000 | ((address >> 2) & 0x03FFFFFF)


def render_component(
    face: ImageFont.FreeTypeFont,
    key: tuple[str, int, int],
) -> tuple[int, ...]:
    image = Image.new("L", (FONT_SIZE, FONT_SIZE), 0)
    ImageDraw.Draw(image).text((0, 0), chr(base.component_pua(key)), font=face, fill=255)
    pixels = image.load()
    return tuple(
        sum(
            1 << (FONT_SIZE - 1 - x)
            for x in range(FONT_SIZE)
            if pixels[x, y] > THRESHOLD
        )
        for y in range(FONT_SIZE)
    )


def render_syllable(face: ImageFont.FreeTypeFont, ch: str) -> tuple[int, ...]:
    image = Image.new("L", (FONT_SIZE, FONT_SIZE), 0)
    ImageDraw.Draw(image).text((0, 0), ch, font=face, fill=255)
    pixels = image.load()
    return tuple(
        sum(
            1 << (FONT_SIZE - 1 - x)
            for x in range(FONT_SIZE)
            if pixels[x, y] > THRESHOLD
        )
        for y in range(FONT_SIZE)
    )


def compose_rows(
    bitmaps: dict[tuple[str, int, int], tuple[int, ...]],
    ch: str,
) -> tuple[int, ...]:
    keys = base.component_keys(ch)
    return tuple(
        functools.reduce(int.__or__, (bitmaps[key][y] for key in keys))
        for y in range(FONT_SIZE)
    )


def read_rect_plane(
    buf: bytes | bytearray,
    u: int,
    v: int,
    plane: int,
) -> tuple[int, ...]:
    if not (0 <= plane < PLANES):
        raise BuildError(f"invalid plane {plane}")
    if not (0 <= u <= 252 - FONT_SIZE and 0 <= v <= 256 - FONT_SIZE):
        raise BuildError(f"16px rectangle is outside the low text page: U={u}, V={v}")
    bit = 1 << plane
    rows: list[int] = []
    for y in range(FONT_SIZE):
        value = 0
        for x in range(FONT_SIZE):
            px = u + x
            at = (v + y) * ROW_BYTES + px // 2
            shift = 0 if px % 2 == 0 else 4
            nibble = (buf[at] >> shift) & 0x0F
            if nibble & bit:
                value |= 1 << (FONT_SIZE - 1 - x)
        rows.append(value)
    return tuple(rows)


def put_rect_plane(
    buf: bytearray,
    u: int,
    v: int,
    plane: int,
    rows: tuple[int, ...],
) -> set[int]:
    if len(rows) != FONT_SIZE:
        raise BuildError(f"expected {FONT_SIZE} rows, got {len(rows)}")
    # Validate bounds through the reader before writing anything.
    read_rect_plane(buf, u, v, plane)
    bit = 1 << plane
    touched: set[int] = set()
    for y, source in enumerate(rows):
        for x in range(FONT_SIZE):
            px = u + x
            at = (v + y) * ROW_BYTES + px // 2
            shift = 0 if px % 2 == 0 else 4
            nibble = (buf[at] >> shift) & 0x0F
            if (source >> (FONT_SIZE - 1 - x)) & 1:
                nibble |= bit
            else:
                nibble &= ~bit & 0x0F
            keep = 0xF0 if shift == 0 else 0x0F
            buf[at] = (buf[at] & keep) | (nibble << shift)
            touched.add(at)
    return touched


def overlapped_original_cells(u: int, v: int) -> tuple[tuple[int, int], ...]:
    return tuple(
        (row, col)
        for row in range(v // ORIGINAL_CELL, (v + FONT_SIZE - 1) // ORIGINAL_CELL + 1)
        for col in range(u // ORIGINAL_CELL, (u + FONT_SIZE - 1) // ORIGINAL_CELL + 1)
    )


def find_safe_physical_slots(
    original_comm: bytes,
    references: set[int],
    cell_audit: dict[tuple[int, int], tuple[int, int]],
) -> tuple[list[tuple[int, int, int]], dict[tuple[int, int, int], tuple[tuple[int, int], ...]]]:
    slots: list[tuple[int, int, int]] = []
    coverage: dict[tuple[int, int, int], tuple[tuple[int, int], ...]] = {}
    for v in range(GRID_Y_OFFSET, MAX_V + 1, GRID_STEP):
        for u in range(GRID_X_OFFSET, MAX_U + 1, GRID_STEP):
            cells = overlapped_original_cells(u, v)
            for plane in range(PLANES):
                safe = True
                for row, col in cells:
                    index = (row * ORIGINAL_COLS + col) * PLANES + plane
                    text_reads, nontext_reads = cell_audit.get((row, col), (-1, -1))
                    if (
                        index in references
                        or any(base.read_plane(original_comm, index))
                        or text_reads <= 0
                        or nontext_reads != 0
                    ):
                        safe = False
                        break
                if safe:
                    slot = (u, v, plane)
                    slots.append(slot)
                    coverage[slot] = cells
    rectangle_count = len({(u, v) for u, v, _plane in slots})
    plane_counts = dict(Counter(plane for _u, _v, plane in slots))
    if rectangle_count != EXPECTED_SAFE_RECTANGLES or len(slots) != EXPECTED_SAFE_SLOTS:
        raise BuildError(
            "16px safe-slot census drifted: "
            f"rectangles {rectangle_count}/{EXPECTED_SAFE_RECTANGLES}, "
            f"slots {len(slots)}/{EXPECTED_SAFE_SLOTS}"
        )
    if plane_counts != EXPECTED_SAFE_PLANES:
        raise BuildError(f"16px safe-slot plane census drifted: {plane_counts}")
    return slots, coverage


def make_wrapper() -> bytes:
    """Build the 49-word dialogue-only 16px packet wrapper.

    v242 looked best because it reduced the common 16px state value to 14,
    but that one value fed both width and height and persisted across strings.
    This wrapper never changes the state dimensions.  The stock builder first
    advances by 12; the wrapper then applies +2 to cho/blank or -12 to the
    overlapping pieces and changes only the new packet to 16x16.  Every R3000
    load has an independent instruction before its destination is consumed.
    """
    base_address = WRAPPER_ADDRESS
    cho_label = base_address + 10 * 4
    rest_label = base_address + 14 * 4
    setup_label = base_address + 16 * 4
    table_hi = (COORD_TABLE_ADDRESS >> 16) & 0xFFFF
    table_lo = COORD_TABLE_ADDRESS & 0xFFFF
    if table_lo & 0x8000:
        raise BuildError("coordinate table low half requires adjusted LUI")

    words = (
        base.i_word(0x09, 4, 2, -ADVANCE_START),           # addiu v0,a0,-advance_start
        base.i_word(0x0B, 2, 3, ADVANCE_COUNT),            # sltiu v1,v0,advance_count
        base.branch_word(0x05, 3, 0, base_address + 2 * 4, cho_label),
        0x00000000,
        base.i_word(0x09, 4, 2, -REST_START),              # addiu v0,a0,-rest_start
        base.i_word(0x0B, 2, 3, REST_COUNT),               # sltiu v1,v0,rest_count
        base.branch_word(0x05, 3, 0, base_address + 6 * 4, rest_label),
        0x00000000,
        base.j_word(GLYPH_BUILDER),                        # normal: tail-call original builder
        0x00000000,
        base.r_word(2, 0, 8, 0, 0x21),                    # cho: move t0,v0
        base.i_word(0x09, 0, 9, HORIZONTAL_ADVANCE - ORIGINAL_CELL),
        base.j_word(setup_label),                          # j     setup
        0x00000000,
        base.i_word(0x09, 2, 8, ADVANCE_COUNT),            # rest: addiu t0,v0,advance_count
        base.i_word(0x09, 0, 9, -ORIGINAL_CELL),           # addiu t1,zero,-12
        base.i_word(0x09, 29, 29, -24),                    # setup: addiu sp,sp,-24
        base.i_word(0x2B, 29, 31, 20),                     # sw    ra,20(sp)
        base.i_word(0x2B, 29, 5, 16),                      # sw    a1,16(sp)
        base.r_word(0, 8, 8, 1, 0x00),                    # sll   t0,t0,1
        base.i_word(0x0F, 0, 10, table_hi),                # lui   t2,table_hi
        base.r_word(10, 8, 10, 0, 0x21),                  # addu  t2,t2,t0
        base.i_word(0x25, 10, 11, table_lo),               # lhu   t3,table_lo(t2)
        base.i_word(0x2B, 29, 9, 8),                       # sw    X delta,8(sp) (load gap)
        base.i_word(0x2B, 29, 11, 12),                     # sw    t3,12(sp)
        jal_word(GLYPH_BUILDER),                           # allocate original packet
        0x00000000,
        base.i_word(0x23, 29, 10, 16),                     # lw    t2,16(sp) (state)
        base.i_word(0x23, 29, 11, 12),                     # lw    t3,12(sp) (load gap)
        base.i_word(0x23, 29, 9, 8),                       # lw    t1,8(sp) (X delta)
        base.i_word(0x25, 10, 8, 0x0A),                    # lhu   t0,0xA(t2)
        base.i_word(0x23, 10, 7, 0),                       # lw    a3,0(t2) (load gap)
        base.i_word(0x09, 8, 8, -1),                       # addiu t0,t0,-1
        base.r_word(0, 8, 12, 5, 0x00),                   # sll   t4,t0,5
        base.r_word(0, 8, 3, 4, 0x00),                    # sll   v1,t0,4
        base.r_word(12, 3, 12, 0, 0x21),                  # addu  t4,t4,v1
        base.r_word(0, 8, 3, 2, 0x00),                    # sll   v1,t0,2
        base.r_word(12, 3, 12, 0, 0x21),                  # addu  t4,t4,v1 (= *52)
        base.r_word(12, 7, 12, 0, 0x21),                  # addu  t4,t4,a3
        base.i_word(0x29, 12, 11, 0x28),                   # sh    t3,0x28(t4)
        base.i_word(0x0D, 0, 11, 0x1010),                 # ori   t3,zero,0x1010
        base.i_word(0x29, 12, 11, 0x2A),                   # sh    t3,0x2A(t4)
        base.i_word(0x25, 10, 8, 6),                       # lhu   t0,6(t2)
        base.i_word(0x23, 29, 31, 20),                     # lw    ra,20(sp) (load gap)
        base.r_word(8, 9, 8, 0, 0x21),                    # addu  t0,t0,t1
        base.i_word(0x29, 10, 8, 6),                       # sh    t0,6(t2)
        base.i_word(0x09, 29, 29, 24),                     # addiu sp,sp,24
        base.r_word(31, 0, 0, 0, 0x08),                   # jr    ra
        0x00000000,
    )
    if len(words) != 49:
        raise BuildError(f"wrapper word count drifted: {len(words)}")
    blob = struct.pack(f"<{len(words)}I", *words)
    if len(blob) != 196:
        raise BuildError(f"wrapper byte count drifted: {len(blob)}")
    return blob


def disassemble_wrapper(blob: bytes) -> list[str]:
    md = capstone.Cs(
        capstone.CS_ARCH_MIPS,
        capstone.CS_MODE_MIPS32 + capstone.CS_MODE_LITTLE_ENDIAN,
    )
    md.detail = True
    instructions = list(md.disasm(blob, WRAPPER_ADDRESS))
    if len(instructions) != 49:
        raise BuildError(f"Capstone decoded {len(instructions)} wrapper instructions")
    calls = [insn for insn in instructions if insn.mnemonic == "jal"]
    if len(calls) != 1 or "0x8016b518" not in calls[0].op_str.lower():
        raise BuildError(f"wrapper call targets drifted: {[i.op_str for i in calls]}")
    branches = [insn for insn in instructions if insn.mnemonic in {"bnez", "beqz"}]
    expected_targets = [
        f"0x{WRAPPER_ADDRESS + 10 * 4:08x}",
        f"0x{WRAPPER_ADDRESS + 14 * 4:08x}",
    ]
    if [insn.op_str.lower().split(",")[-1].strip() for insn in branches] != expected_targets:
        raise BuildError(f"wrapper branch targets drifted: {[i.op_str for i in branches]}")
    jumps = [insn.op_str.lower() for insn in instructions if insn.mnemonic == "j"]
    if jumps != ["0x8016b518", f"0x{WRAPPER_ADDRESS + 16 * 4:08x}"]:
        raise BuildError(f"wrapper non-linking jump targets drifted: {jumps}")
    # The bundled Capstone build can disassemble MIPS but reports CS_ERR_ARCH
    # for regs_access().  Decode the GPR read set directly so the PS1/R3000
    # one-instruction load delay remains a hard build guard on every machine.
    def gpr_reads(word: int) -> set[int]:
        op = word >> 26
        rs = (word >> 21) & 0x1F
        rt = (word >> 16) & 0x1F
        if op == 0:
            funct = word & 0x3F
            if funct in {0x00, 0x02, 0x03}:       # fixed shifts
                return {rt}
            if funct in {0x08, 0x09, 0x11, 0x13}: # jr/jalr/mthi/mtlo
                return {rs}
            if funct in {0x10, 0x12}:             # mfhi/mflo
                return set()
            return {rs, rt}
        if op in {0x02, 0x03, 0x0F}:              # j/jal/lui
            return set()
        if op in {0x04, 0x05}:                    # beq/bne
            return {rs, rt}
        if op in {0x01, 0x06, 0x07}:              # regimm/blez/bgtz
            return {rs}
        if op in {0x28, 0x29, 0x2A, 0x2B, 0x2E}:  # stores
            return {rs, rt}
        return {rs}                                # immediates and loads

    words = struct.unpack(f"<{len(blob) // 4}I", blob)
    if any(
        word >> 26 == 0x28
        and (word >> 21) & 0x1F == 5
        and (word & 0xFFFF) in {0x000D, 0x000E}
        for word in words
    ):
        raise BuildError("wrapper must not leak custom width/height into the text state")
    load_ops = {0x20, 0x21, 0x23, 0x24, 0x25}
    for index, (current_word, next_word) in enumerate(zip(words, words[1:])):
        if current_word >> 26 not in load_ops:
            continue
        loaded_register = (current_word >> 16) & 0x1F
        if loaded_register in gpr_reads(next_word):
            current_address = WRAPPER_ADDRESS + index * 4
            raise BuildError(
                f"R3000 load-delay hazard at 0x{current_address:08X}: "
                f"r{loaded_register} read by 0x{current_address + 4:08X}"
            )
    return [
        f"{insn.address:08X}  {struct.unpack('<I', insn.bytes)[0]:08X}  "
        f"{insn.mnemonic:<8s}{insn.op_str}"
        for insn in instructions
    ]


def direct_control_edges(exe: bytes) -> list[tuple[int, int, str, int]]:
    """Collect apparent direct control edges, retaining their source words.

    The PS-X EXE text image contains large data tables.  Some table words decode
    as branch opcodes by coincidence, so callers must validate both source and
    destination instead of treating a whole-image branch scan as code truth.
    """
    text_address, text_size = struct.unpack_from("<II", exe, 0x18)
    edges: list[tuple[int, int, str, int]] = []
    for offset in range(0x800, 0x800 + text_size - 3, 4):
        pc = text_address + offset - 0x800
        word = struct.unpack_from("<I", exe, offset)[0]
        op = word >> 26
        if op in (2, 3):
            target = ((pc + 4) & 0xF0000000) | ((word & 0x03FFFFFF) << 2)
            edges.append((pc, target, "j" if op == 2 else "jal", word))
        elif op in (1, 4, 5, 6, 7):
            immediate = word & 0xFFFF
            if immediate & 0x8000:
                immediate -= 0x10000
            edges.append((pc, pc + 4 + immediate * 4, f"branch-op{op}", word))
    return edges


def encode_body_text(
    text: str,
    mapping: dict[tuple[str, int, int], int],
    custom_space_code: bytes,
) -> bytes:
    encoded = bytearray()
    for ch in text:
        if ch == " ":
            encoded += custom_space_code
            continue
        for key in base.component_keys(ch):
            code = base.encode_index(mapping[key])
            if code is None or len(code) != 2:
                raise BuildError(f"component code is not a two-byte glyph: {key}")
            encoded += code
    return bytes(encoded)


def write_preview(
    path: Path,
    face: ImageFont.FreeTypeFont,
    bitmaps: dict[tuple[str, int, int], tuple[int, ...]],
) -> None:
    labels = ("출홀줄", "각객걱곡", "가나고구과워")
    scale = 8
    margin = 8
    width = max(len(label) for label in labels) * FONT_SIZE * scale + margin * 2
    height = len(labels) * (FONT_SIZE * scale + margin) + margin
    image = Image.new("RGB", (width, height), "white")
    draw = ImageDraw.Draw(image)
    for row_no, label in enumerate(labels):
        top = margin + row_no * (FONT_SIZE * scale + margin)
        for col_no, ch in enumerate(label):
            left = margin + col_no * FONT_SIZE * scale
            rows = compose_rows(bitmaps, ch)
            for y, bits in enumerate(rows):
                for x in range(FONT_SIZE):
                    if (bits >> (FONT_SIZE - 1 - x)) & 1:
                        draw.rectangle(
                            (left + x * scale, top + y * scale,
                             left + (x + 1) * scale - 1, top + (y + 1) * scale - 1),
                            fill="black",
                        )
            # Red line marks the first row that a 12px packet would cut off.
            draw.line(
                (left, top + 12 * scale, left + FONT_SIZE * scale - 1, top + 12 * scale),
                fill=(220, 0, 0),
            )
    image.save(path)


def main() -> None:
    args = parse_args()
    profile = base.FONT_PROFILES[args.font_profile]

    step("입력 해시와 16px 렌더러 버전 확인")
    if base.sha256_file(args.base) != base.BASE_ZIP_SHA256:
        raise BuildError(f"base ZIP is not the pinned Japanese original: {args.base}")
    if not args.font_zip.is_file():
        raise BuildError(f"font ZIP does not exist: {args.font_zip}")
    font_zip_hash = base.sha256_file(args.font_zip)
    if font_zip_hash != profile["zip_sha256"]:
        raise BuildError(f"font ZIP hash mismatch: {font_zip_hash}")
    freetype_version = features.version_module("freetype2")
    if PIL.__version__ != base.EXPECTED_PILLOW or freetype_version != base.EXPECTED_FREETYPE:
        raise BuildError(
            "font renderer version drift: "
            f"Pillow {PIL.__version__}/{base.EXPECTED_PILLOW}, "
            f"FreeType {freetype_version}/{base.EXPECTED_FREETYPE}"
        )
    with ZipFile(args.font_zip) as archive:
        try:
            font_bytes = archive.read(str(profile["member"]))
        except KeyError as error:
            raise BuildError(f"font member missing: {profile['member']}") from error
    if len(font_bytes) != profile["font_size"] or base.sha256_bytes(font_bytes) != profile["font_sha256"]:
        raise BuildError("font member size/hash mismatch")
    face = ImageFont.truetype(io.BytesIO(font_bytes), FONT_SIZE)

    step("고정된 일본판 원본 arc.zip 읽기")
    with ZipFile(args.base) as archive:
        infos = archive.infolist()
        if len({info.filename for info in infos}) != len(infos):
            raise BuildError("base ZIP contains duplicate member names")
        members = {
            info.filename: archive.read(info.filename)
            for info in infos
            if not info.is_dir()
        }
    for name, (size, digest) in base.BASE_MEMBER_GUARDS.items():
        if name not in members:
            raise BuildError(f"base ZIP is missing {name}")
        if len(members[name]) != size or base.sha256_bytes(members[name]) != digest:
            raise BuildError(f"base member guard failed: {name}")

    original_comm = members[COMM]
    encodable = [
        index for index in range(base.MAX_GLYPH_INDEX + 1)
        if base.encode_index(index) is not None
    ]
    original_inked = [index for index in encodable if any(base.read_plane(original_comm, index))]
    if len(original_inked) != 996:
        raise BuildError(f"original inked glyph count drifted: {len(original_inked)}")
    if base.inked_planes_hash(original_comm, original_inked) != base.ORIGINAL_INKED_PLANES_SHA256:
        raise BuildError("original inked-plane hash guard failed")
    if any(base.read_plane(original_comm, LEADING_BLANK_BYTE - 1)):
        raise BuildError("original one-byte leading blank is not empty")

    step("공식 iolo 벌 규칙으로 Pilgi 16px 진단 조각 렌더")
    all_keys: set[tuple[str, int, int]] = set()
    all_syllables: set[str] = set()
    for _offset, _capacity, text in TEST_SITES:
        for ch in text:
            if ch == " ":
                continue
            all_syllables.add(ch)
            all_keys.update(base.component_keys(ch))
    bitmaps = {key: render_component(face, key) for key in all_keys}
    if any(not any(bitmap) for bitmap in bitmaps.values()):
        raise BuildError("Pilgi rendered a required 16px component blank")
    cho_keys = {key for key in all_keys if key[0] == "c"}
    rest_keys = all_keys - cho_keys
    cho_groups = base.group_shapes(cho_keys, bitmaps)
    rest_groups = base.group_shapes(rest_keys, bitmaps)
    census = (len(cho_keys), len(cho_groups), len(rest_keys), len(rest_groups))
    if census != (13, 13, 19, 16):
        raise BuildError(f"16px diagnostic component census drifted: {census}")

    mapping: dict[tuple[str, int, int], int] = {}
    shape_by_code: dict[int, tuple[int, ...]] = {}
    for code, (shape, keys) in zip(
        range(ADVANCE_START, ADVANCE_START + ADVANCE_SHAPES),
        cho_groups,
        strict=True,
    ):
        shape_by_code[code] = shape
        for key in keys:
            mapping[key] = code
    for code, (shape, keys) in zip(
        range(REST_START, REST_START + REST_SHAPES),
        rest_groups,
        strict=True,
    ):
        shape_by_code[code] = shape
        for key in keys:
            mapping[key] = code
    blank_shape = (0,) * FONT_SIZE
    shape_by_code[CUSTOM_SPACE_INDEX] = blank_shape
    shape_by_code[SAFE_FILLER_INDEX] = blank_shape
    if set(mapping) != all_keys or len(shape_by_code) != ADVANCE_COUNT + REST_COUNT:
        raise BuildError("16px component/code mapping is incomplete")

    hamming: dict[str, int] = {}
    bottom_rows: dict[str, dict[str, object]] = {}
    for ch in sorted(all_syllables):
        composed = compose_rows(bitmaps, ch)
        direct = render_syllable(face, ch)
        hamming[ch] = sum((left ^ right).bit_count() for left, right in zip(composed, direct))
        bottom_rows[ch] = {
            "row12": f"{composed[12]:04X}",
            "row13": f"{composed[13]:04X}",
            "row14": f"{composed[14]:04X}",
            "row15": f"{composed[15]:04X}",
            "uses_rows_12_15": any(composed[12:]),
            "uses_row_15": bool(composed[15]),
        }
    for ch in "출홀줄":
        if hamming[ch] != 0:
            raise BuildError(f"official Pilgi composition is not exact for {ch}: {hamming[ch]}")
    for ch in ("각", "걱"):
        composed = compose_rows(bitmaps, ch)
        if not composed[15] or composed != render_syllable(face, ch):
            raise BuildError(f"bottom-row proof syllable no longer uses an exact row 15: {ch}")

    step("코드 슬롯과 16x16 물리 슬롯을 509-state 감사로 검증")
    references, dialogue_site_count, exe_site_count = base.collect_conservative_references(members)
    cell_audit, audit_states = base.load_cell_audit()
    all_codes = (
        list(range(ADVANCE_START, ADVANCE_START + ADVANCE_COUNT))
        + list(range(REST_START, REST_START + REST_COUNT))
    )
    for code in all_codes:
        encoded = base.encode_index(code)
        col, row, _plane = base.cell_of(code)
        text_reads, nontext_reads = cell_audit.get((row, col), (-1, -1))
        if encoded is None or len(encoded) != 2:
            raise BuildError(f"custom code {code} is not a two-byte glyph")
        if code in references or any(base.read_plane(original_comm, code)):
            raise BuildError(f"custom code namespace is not blank/unreferenced: {code}")
        if text_reads <= 0 or nontext_reads != 0:
            raise BuildError(f"custom code cell is not text-only in audit: {code}")

    safe_slots, slot_coverage = find_safe_physical_slots(
        original_comm, references, cell_audit
    )
    available_by_plane: dict[int, list[tuple[int, int, int]]] = {
        plane: [slot for slot in safe_slots if slot[2] == plane]
        for plane in range(PLANES)
    }
    physical_by_code: dict[int, tuple[int, int, int]] = {}
    for code in all_codes:
        plane = code & 3
        if not available_by_plane[plane]:
            raise BuildError(f"ran out of safe 16px slots for plane {plane}")
        physical_by_code[code] = available_by_plane[plane].pop(0)
    if len(set(physical_by_code.values())) != len(all_codes):
        raise BuildError("16px physical slot assignment contains duplicates")
    for code, (_u, _v, plane) in physical_by_code.items():
        if plane != (code & 3):
            raise BuildError(f"CLUT plane mismatch for code {code}")

    scratch = dict(members)
    expected_allowed: dict[str, set[int]] = {
        name: set() for name in EXPECTED_CHANGED_MEMBERS
    }

    step("COMM.IMG에 선택된 Pilgi 16x16 조각 평면 삽입")
    comm = bytearray(original_comm)
    used_rectangles = {(u, v) for u, v, _plane in physical_by_code.values()}
    neighbour_before = {
        (u, v, plane): read_rect_plane(original_comm, u, v, plane)
        for u, v in used_rectangles
        for plane in range(PLANES)
        if (u, v, plane) not in set(physical_by_code.values())
    }
    for code in all_codes:
        u, v, plane = physical_by_code[code]
        expected_allowed[COMM] |= put_rect_plane(comm, u, v, plane, shape_by_code[code])
        if read_rect_plane(comm, u, v, plane) != shape_by_code[code]:
            raise BuildError(f"16px rectangle round-trip mismatch for code {code}")
    for slot, before in neighbour_before.items():
        if read_rect_plane(comm, *slot) != before:
            raise BuildError(f"neighbour plane changed at 16px rectangle {slot}")
    if base.inked_planes_hash(comm, original_inked) != base.ORIGINAL_INKED_PLANES_SHA256:
        raise BuildError("an original inked glyph plane changed")
    scratch[COMM] = bytes(comm)

    step("S1071 진단 본문을 원래 종료 경계까지 안전 토큰으로 삽입")
    custom_space_code = base.encode_index(CUSTOM_SPACE_INDEX)
    filler_code = base.encode_index(SAFE_FILLER_INDEX)
    if custom_space_code is None or filler_code is None:
        raise BuildError("custom blank encoding failed")
    dat = bytearray(members[TEST_DAT])
    text_rows: list[dict[str, object]] = []
    lead = bytes((LEADING_BLANK_BYTE,))
    enc = lambda text: encode_body_text(text, mapping, custom_space_code)  # noqa: E731
    layout_cores = (
        ORIGINAL_SPEAKER_PREFIX + NEWLINE + lead + enc("출홀줄") + NEWLINE + enc("하허호"),
        lead + enc("각 객") + NEWLINE + enc("걱 곡"),
        ORIGINAL_SPEAKER_PREFIX + NEWLINE + lead + enc("가 나 고") + NEWLINE + enc("구 과 워"),
    )
    for site_no, ((offset, capacity, text), core) in enumerate(
        zip(TEST_SITES, layout_cores, strict=True)
    ):
        original_boundary = bytes(dat[offset + capacity : offset + capacity + 8])
        if not original_boundary or original_boundary[0] != 0:
            raise BuildError(f"S1071 body at {offset:#x} has no expected terminator")
        remaining = capacity - len(core)
        if remaining < 0 or remaining % len(filler_code):
            raise BuildError(
                f"diagnostic layout cannot reach fixed boundary at {offset:#x}: "
                f"core={len(core)}, capacity={capacity}"
            )
        filler_tokens = remaining // len(filler_code)
        payload = core + filler_code * filler_tokens
        glyph_count, controls = base.profile_inline_body(payload)
        if len(payload) != capacity or payload.count(0):
            raise BuildError(f"fixed-length payload contains drift/early zero at {offset:#x}")
        if controls != [NEWLINE] * PROVEN_LINEBREAK_COUNTS[site_no]:
            raise BuildError(f"control skeleton drifted at {offset:#x}")
        if glyph_count >= TEXT_OBJECT_GLYPH_LIMIT:
            raise BuildError(f"diagnostic body needs {glyph_count} packets at {offset:#x}")
        dat[offset : offset + capacity] = payload
        if bytes(dat[offset + capacity : offset + capacity + 8]) != original_boundary:
            raise BuildError(f"terminator/trailer changed at {offset:#x}")
        expected_allowed[TEST_DAT].update(range(offset, offset + capacity))
        text_rows.append(
            {
                "member": TEST_DAT,
                "offset": f"0x{offset:X}",
                "capacity": capacity,
                "core_bytes": len(core),
                "filler_tokens": filler_tokens,
                "glyph_packets": glyph_count,
                "linebreak_tokens": len(controls),
                "internal_zero_bytes": payload.count(0),
                "terminator_offset": f"0x{offset + capacity:X}",
                "text": text,
                "encoded_hex": payload.hex(" ").upper(),
            }
        )
    scratch[TEST_DAT] = bytes(dat)

    step("대화 전용 16px 래퍼, U/V 표, 두 JAL 훅 삽입")
    exe = bytearray(members[PSX])
    wrapper_offset = base.file_offset(exe, WRAPPER_ADDRESS)
    wrapper_end_offset = base.file_offset(exe, WRAPPER_CAVE_END - 1) + 1
    table_offset = base.file_offset(exe, COORD_TABLE_ADDRESS)
    if any(exe[wrapper_offset:wrapper_end_offset]):
        raise BuildError("wrapper cave is not zero in the pinned original")
    if any(exe[table_offset : table_offset + COORD_TABLE_CAPACITY]):
        raise BuildError("coordinate-table cave is not zero in the pinned original")
    original_edges = direct_control_edges(bytes(exe))
    wrapper_edges = tuple(
        edge for edge in original_edges
        if WRAPPER_ADDRESS <= edge[1] < WRAPPER_CAVE_END
    )
    if wrapper_edges != KNOWN_WRAPPER_DATA_EDGES:
        raise BuildError(f"wrapper apparent-edge census drifted: {wrapper_edges}")
    table_edges = tuple(
        edge for edge in original_edges
        if COORD_TABLE_ADDRESS <= edge[1] < COORD_TABLE_ADDRESS + COORD_TABLE_CAPACITY
    )
    if table_edges != KNOWN_TABLE_DATA_EDGES:
        raise BuildError(f"coordinate-table apparent-edge census drifted: {table_edges}")

    wrapper = make_wrapper()
    disassembly = disassemble_wrapper(wrapper)
    if wrapper_offset + len(wrapper) > wrapper_end_offset:
        raise BuildError("16px wrapper overflows its original zero cave")
    exe[wrapper_offset : wrapper_offset + len(wrapper)] = wrapper
    expected_allowed[PSX].update(range(wrapper_offset, wrapper_offset + len(wrapper)))

    table_codes = (
        list(range(ADVANCE_START, ADVANCE_START + ADVANCE_COUNT))
        + list(range(REST_START, REST_START + REST_COUNT))
    )
    table_values = [
        physical_by_code[code][0] | (physical_by_code[code][1] << 8)
        for code in table_codes
    ]
    table_blob = struct.pack(f"<{len(table_values)}H", *table_values)
    if len(table_blob) != 62 or len(table_blob) > COORD_TABLE_CAPACITY:
        raise BuildError(f"coordinate table size drifted: {len(table_blob)}")
    exe[table_offset : table_offset + len(table_blob)] = table_blob
    expected_allowed[PSX].update(range(table_offset, table_offset + len(table_blob)))

    for call in DIALOGUE_CALLS:
        offset = base.file_offset(exe, call)
        before_call, delay = struct.unpack_from("<II", exe, offset)
        if before_call != ORIGINAL_GLYPH_CALL or delay != ORIGINAL_DIALOGUE_DELAY:
            raise BuildError(f"dialogue glyph call guard failed at {call:#x}")
        struct.pack_into("<I", exe, offset, jal_word(WRAPPER_ADDRESS))
        expected_allowed[PSX].update(range(offset, offset + 4))
    # The shared cursor tail and all seven v238 global 16px sites stay original.
    cursor_offset = base.file_offset(exe, 0x8016B63C)
    if struct.unpack_from("<II", exe, cursor_offset) != (0x90C3000D, 0x90C5000F):
        raise BuildError("shared cursor tail was not preserved")
    for address, expected in (
        (0x8016B160, 0x3402000C),
        (0x8016B6E0, 0x3402000C),
        (0x8016B348, 0x3405000C),
        (0x8016B394, 0x3404000C),
        (0x8016B398, 0x3405000C),
        (0x8016B170, 0x34020002),
        (0x8016B174, 0xA2220010),
    ):
        if struct.unpack_from("<I", exe, base.file_offset(exe, address))[0] != expected:
            raise BuildError(f"global 12px literal changed at {address:#x}")
    scratch[PSX] = bytes(exe)

    step("Expected Write, 크기 불변, 원본 UI 비변경 검증")
    for name in members:
        if len(scratch[name]) != len(members[name]):
            raise BuildError(f"member size changed: {name}")
    changed = {name for name in members if scratch[name] != members[name]}
    if changed != EXPECTED_CHANGED_MEMBERS:
        raise BuildError(f"changed-member set mismatch: {sorted(changed)}")
    actual_diffs: dict[str, set[int]] = {}
    for name in sorted(EXPECTED_CHANGED_MEMBERS):
        actual = base.diff_offsets(members[name], scratch[name])
        actual_diffs[name] = actual
        unexpected = actual - expected_allowed[name]
        if unexpected:
            raise BuildError(f"unexpected write in {name} at {min(unexpected):#x}")
        if not actual:
            raise BuildError(f"expected changed member has no diff: {name}")

    # Explicit canary: outside the three declared write sets, every member and
    # every byte is already covered above.  These v238 sites are also compared
    # directly so this PoC cannot silently become a global 16px renderer.
    for address in (0x8016B58C, 0x8016B590, 0x8016B594, 0x8016B59C, 0x8016B5A0, 0x8016B5A4):
        offset = base.file_offset(exe, address)
        if scratch[PSX][offset : offset + 4] != members[PSX][offset : offset + 4]:
            raise BuildError(f"stock 12px U/V arithmetic changed at {address:#x}")

    step("재현 가능한 전체 ZIP과 3-member patch-only ZIP 출력")
    args.output_dir.mkdir(parents=True, exist_ok=True)
    temp = args.output_dir / f".{OUTPUT_STEM}_{os.getpid()}.building.zip"
    patch_temp = args.output_dir / f".{OUTPUT_STEM}_patch_{os.getpid()}.building.zip"
    for path in (temp, patch_temp):
        if path.exists():
            raise BuildError(f"temporary output already exists: {path}")
    try:
        with ZipFile(temp, "w", ZIP_DEFLATED, compresslevel=1) as archive:
            for info in infos:
                archive.writestr(base.clone_zipinfo(info), b"" if info.is_dir() else scratch[info.filename])
        output_hash = base.sha256_file(temp)
        output = args.output_dir / f"{OUTPUT_STEM}_{output_hash[:8]}.zip"
        if output.exists():
            if base.sha256_file(output) != output_hash:
                raise BuildError(f"output-name collision: {output}")
            temp.unlink()
        else:
            temp.replace(output)

        with ZipFile(patch_temp, "w", ZIP_DEFLATED, compresslevel=1) as archive:
            for info in infos:
                if not info.is_dir() and info.filename in EXPECTED_CHANGED_MEMBERS:
                    archive.writestr(base.clone_zipinfo(info), scratch[info.filename])
        patch_hash = base.sha256_file(patch_temp)
        patch_output = args.output_dir / f"{OUTPUT_STEM}_patch_{patch_hash[:8]}.zip"
        if patch_output.exists():
            if base.sha256_file(patch_output) != patch_hash:
                raise BuildError(f"patch output-name collision: {patch_output}")
            patch_temp.unlink()
        else:
            patch_temp.replace(patch_output)
    finally:
        for path in (temp, patch_temp):
            if path.exists():
                path.unlink()

    with ZipFile(output) as archive:
        if archive.namelist() != [info.filename for info in infos]:
            raise BuildError("full output ZIP member order drifted")
        for info in infos:
            if not info.is_dir() and archive.read(info.filename) != scratch[info.filename]:
                raise BuildError(f"full output ZIP readback failed: {info.filename}")
    with ZipFile(patch_output) as archive:
        patch_names = [info.filename for info in archive.infolist() if not info.is_dir()]
        expected_patch_names = [
            info.filename for info in infos
            if not info.is_dir() and info.filename in EXPECTED_CHANGED_MEMBERS
        ]
        if patch_names != expected_patch_names:
            raise BuildError(f"patch-only member list drifted: {patch_names}")
        for name in patch_names:
            if archive.read(name) != scratch[name]:
                raise BuildError(f"patch-only ZIP readback failed: {name}")

    step("분석 CSV, MIPS 해독, 16px 하단행 프리뷰 기록")
    args.analysis_dir.mkdir(parents=True, exist_ok=True)
    component_rows: list[dict[str, object]] = []
    for key in sorted(mapping):
        code = mapping[key]
        u, v, plane = physical_by_code[code]
        kind, beol, jamo = key
        bitmap = bitmaps[key]
        component_rows.append(
            {
                "kind": kind,
                "beol": beol,
                "jamo_index": jamo,
                "pua": f"U+{base.component_pua(key):04X}",
                "code_index": code,
                "encoded_hex": (base.encode_index(code) or b"").hex(" ").upper(),
                "physical_u": u,
                "physical_v": v,
                "plane": plane,
                "uses_rows_12_15": any(bitmap[12:]),
                "uses_row_15": bool(bitmap[15]),
                "bitmap_sha256": base.sha256_bytes(
                    b"".join(row.to_bytes(2, "big") for row in bitmap)
                ),
            }
        )
    base.write_csv(
        args.analysis_dir / "component_map_16px.csv",
        [
            "kind", "beol", "jamo_index", "pua", "code_index", "encoded_hex",
            "physical_u", "physical_v", "plane", "uses_rows_12_15",
            "uses_row_15", "bitmap_sha256",
        ],
        component_rows,
    )

    slot_rows: list[dict[str, object]] = []
    for code in all_codes:
        u, v, plane = physical_by_code[code]
        cells = slot_coverage[(u, v, plane)]
        slot_rows.append(
            {
                "code_index": code,
                "role": (
                    "advancing_space" if code == CUSTOM_SPACE_INDEX
                    else "nonadvancing_filler" if code == SAFE_FILLER_INDEX
                    else "advancing_cho" if code < ADVANCE_START + ADVANCE_SHAPES
                    else "nonadvancing_jung_jong"
                ),
                "encoded_hex": (base.encode_index(code) or b"").hex(" ").upper(),
                "u": u,
                "v": v,
                "plane": plane,
                "covered_original_cells": " ".join(f"r{row}c{col}" for row, col in cells),
                "blank_shape": not any(shape_by_code[code]),
            }
        )
    base.write_csv(
        args.analysis_dir / "physical_slots_16px.csv",
        [
            "code_index", "role", "encoded_hex", "u", "v", "plane",
            "covered_original_cells", "blank_shape",
        ],
        slot_rows,
    )
    base.write_csv(
        args.analysis_dir / "text_manifest.csv",
        [
            "member", "offset", "capacity", "core_bytes", "filler_tokens",
            "glyph_packets", "linebreak_tokens", "internal_zero_bytes",
            "terminator_offset", "text", "encoded_hex",
        ],
        text_rows,
    )

    write_rows: list[dict[str, object]] = []
    for name in sorted(actual_diffs):
        for start, end in base.coalesce_offsets(actual_diffs[name]):
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
    base.write_csv(
        args.analysis_dir / "actual_writes.csv",
        ["member", "start", "end_exclusive", "length", "before_hex", "after_hex"],
        write_rows,
    )
    (args.analysis_dir / "mips_disassembly.txt").write_text(
        "dialogue hooks:\n"
        + "\n".join(
            f"{address:08X}  {jal_word(WRAPPER_ADDRESS):08X}  jal 0x{WRAPPER_ADDRESS:08X}"
            for address in DIALOGUE_CALLS
        )
        + "\n\nwrapper:\n"
        + "\n".join(disassembly)
        + "\n",
        encoding="utf-8",
    )
    write_preview(args.analysis_dir / "font_preview_16px.png", face, bitmaps)

    manifest = {
        "status": "TEST_ONLY_STATIC_PASS_RUNTIME_PENDING_16PX_LOWER_ROW",
        "base": {"path": str(args.base), "sha256": base.BASE_ZIP_SHA256},
        "font": {
            "profile": args.font_profile,
            "zip_path": str(args.font_zip),
            "zip_sha256": font_zip_hash,
            "member": profile["member"],
            "member_sha256": profile["font_sha256"],
            "pixel_size": FONT_SIZE,
            "threshold": f">{THRESHOLD}",
            "pillow": PIL.__version__,
            "freetype": freetype_version,
        },
        "official_rule": {
            "source_url": base.RULE_SOURCE_URL,
            "source_sha256": base.RULE_SOURCE_SHA256,
            "cho_without_jong": base.CHO_KIND_WITHOUT_JONG,
            "cho_with_jong": base.CHO_KIND_WITH_JONG,
            "jong_by_jung": base.JONG_KIND_BY_JUNG,
        },
        "renderer": {
            "mode": "dialogue-only post-build packet override",
            "stock_renderer_preserved_for_noncustom_codes": True,
            "custom_packet_width_height": [FONT_SIZE, FONT_SIZE],
            "custom_horizontal_advance": HORIZONTAL_ADVANCE,
            "state_dimensions_unchanged": [ORIGINAL_CELL, ORIGINAL_CELL],
            "state_vertical_spacing": STATE_VERTICAL_SPACING,
            "expected_vertical_pitch": ORIGINAL_CELL + STATE_VERTICAL_SPACING,
            "dialogue_call_hooks": [f"0x{address:08X}" for address in DIALOGUE_CALLS],
            "wrapper": f"0x{WRAPPER_ADDRESS:08X}",
            "wrapper_bytes": len(wrapper),
            "coordinate_table": f"0x{COORD_TABLE_ADDRESS:08X}",
            "coordinate_table_bytes": len(table_blob),
        },
        "ranges": {
            "advancing_cho_and_space": [ADVANCE_START, ADVANCE_START + ADVANCE_COUNT - 1],
            "custom_space": CUSTOM_SPACE_INDEX,
            "nonadvancing_jung_jong_and_filler": [REST_START, REST_START + REST_COUNT - 1],
            "safe_filler": SAFE_FILLER_INDEX,
        },
        "physical_atlas": {
            "grid_offset": [GRID_X_OFFSET, GRID_Y_OFFSET],
            "grid_step": GRID_STEP,
            "candidate_rectangles": EXPECTED_SAFE_RECTANGLES,
            "candidate_plane_slots": EXPECTED_SAFE_SLOTS,
            "candidate_plane_counts": EXPECTED_SAFE_PLANES,
            "assigned_slots": len(physical_by_code),
            "max_u": max(u for u, _v, _p in physical_by_code.values()),
            "max_v": max(v for _u, v, _p in physical_by_code.values()),
            "max_pixel_y": max(v for _u, v, _p in physical_by_code.values()) + FONT_SIZE - 1,
            "runtime_audit_states": audit_states,
            "requirements": "all overlapped planes blank+unreferenced; all cells text_reads>0 and nontext_reads=0",
        },
        "components": {
            "logical": len(all_keys),
            "unique_cho_shapes": len(cho_groups),
            "unique_rest_shapes": len(rest_groups),
            "physical_shape_planes": len(shape_by_code) - 2,
            "blank_planes": 2,
        },
        "bottom_row_proof": bottom_rows,
        "diagnostic_raster_hamming": hamming,
        "fixed_length_flow": {
            "linebreak_counts": PROVEN_LINEBREAK_COUNTS,
            "original_terminators_preserved": True,
            "early_zero_bytes": 0,
            "sites": text_rows,
        },
        "reference_catalog": {
            "dialogue_sites": dialogue_site_count,
            "exe_pointer_strings": exe_site_count,
            "referenced_glyph_indices": len(references),
        },
        "features_absent": [
            "dynamic cache", "global 15-column atlas", "global code rewrite",
            "E2 external slots", "UI repack", "expanded EXE", "bulk translation",
        ],
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
        "zip_runtime": {
            "zlib_compile_version": zlib.ZLIB_VERSION,
            "zlib_runtime_version": zlib.ZLIB_RUNTIME_VERSION,
            "compresslevel": 1,
        },
        "runtime": "PENDING_USER_COLD_BOOT_NATURAL_S1071_PROGRESSION",
    }
    (args.analysis_dir / "build_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    report = [
        "Arc the Lad 1 clean Pilgi johab 16px dialogue PoC",
        "status=TEST_ONLY STATIC PASS; runtime=PENDING cold boot + natural S1071 progression",
        f"base_sha256={base.BASE_ZIP_SHA256}",
        f"font={profile['member']} 16px sha256={profile['font_sha256']}",
        f"renderer=Pillow {PIL.__version__}; FreeType {freetype_version}; threshold >{THRESHOLD}",
        "mode=stock 12px globally; custom dialogue packets 16x16 only",
        f"v242_density=horizontal advance {HORIZONTAL_ADVANCE}px; "
        f"packet {FONT_SIZE}x{FONT_SIZE}; state remains {ORIGINAL_CELL}x{ORIGINAL_CELL}",
        f"wrapper={len(wrapper)}B at 0x{WRAPPER_ADDRESS:08X}; hooks="
        + ",".join(f"0x{address:08X}" for address in DIALOGUE_CALLS),
        f"uv_table={len(table_blob)}B at 0x{COORD_TABLE_ADDRESS:08X}",
        f"components={len(shape_by_code) - 2} shapes + advancing blank + nonadvancing filler",
        f"physical_slots={len(physical_by_code)}/{EXPECTED_SAFE_SLOTS} guarded candidates; "
        f"max_V={max(v for _u, v, _p in physical_by_code.values())}; "
        f"last_pixel_Y={max(v for _u, v, _p in physical_by_code.values()) + 15}",
        "bottom_row=각/걱 use row 15 and match Pilgi completed syllables exactly",
        "readability=출/홀/줄 official composition matches Pilgi completed syllables exactly",
        "flow=3/3 original terminators; early 0x00=0; packet counts="
        + "/".join(str(row["glyph_packets"]) for row in text_rows),
        "UI isolation=global size literals, U/V arithmetic, cursor tail all byte-identical",
        f"original_inked_planes=996 sha256={base.ORIGINAL_INKED_PLANES_SHA256} unchanged",
        "features_absent=dynamic cache, global repack, E2, expanded EXE, UI repack, bulk translation",
        "changed_members=" + ", ".join(sorted(changed)),
        "changed_byte_counts=" + ", ".join(
            f"{name}:{len(actual_diffs[name])}" for name in sorted(actual_diffs)
        ),
        f"output={output.name}",
        f"output_sha256={output_hash}",
        f"patch_output={patch_output.name}",
        f"patch_output_sha256={patch_hash}",
        "next=package patch-only ZIP with --layout original; verify 506/506 LBA; cold boot",
    ]
    (args.analysis_dir / "build_report.txt").write_text(
        "\n".join(report) + "\n", encoding="utf-8"
    )
    print("\n".join(report))


if __name__ == "__main__":
    try:
        main()
    except BuildError as error:
        raise SystemExit(f"GUARD FAILED: {error}") from error
