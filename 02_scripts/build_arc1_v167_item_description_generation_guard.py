"""Build v167: retain persistent item-description cache slots.

v166 fixed complete-cell reconstruction and main-OT lifetime, but the item
description object at 0x801F031C keeps row-40 metadata even when its sprites are
not present in the final main OT.  This build scans that bounded 32-entry object
at the end of each frame and carries its cache slots into the next allocator
pass.

No RAM/VRAM boundary grows.  To fit the bounded scanner, Huffman checkpoints are
stored every eight sources instead of every four.  The bitstream and all 370
glyph shapes remain byte-identical.
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


BASE = ROOT / "03_output/arc1_v166_persistent_ot_guard_fullcell_8EB4F3A4.zip"
BASE_SHA256 = "8EB4F3A4F9031455D07F285456CF0859B6CD848399FB53E55E10FF9D8E2BD930"
OUT_STEM = "arc1_v167_item_description_generation_guard"
ANALYSIS = ROOT / "01_work/analysis/arc1_v167_item_description_generation_guard"
REPORT = ANALYSIS / "build_report.txt"
DISASSEMBLY = ANALYSIS / "resident_disassembly.txt"
LAYOUT_CSV = ANALYSIS / "resident_layout.csv"
CHECKPOINT_GROUP = 8
ITEM_DESCRIPTION_HEADER = 0x801F031C
OT_WALK_LIMIT = v166.OT_WALK_LIMIT
FONT_CLUT_MIN = v166.FONT_CLUT_MIN


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def pack_layout(checkpoints: bytes) -> tuple[dict[str, tuple[int, int]], dict[str, bytes]]:
    blobs = {
        "huffman_rows": old.plan.HUFFMAN_ROWS.read_bytes(),
        "huffman_counts": old.plan.HUFFMAN_COUNTS.read_bytes(),
        "conflict_ranges": old.plan.CONFLICT_RANGES.read_bytes(),
        "source_checkpoints": checkpoints,
        "source_bitstream": old.plan.SOURCE_BITSTREAM.read_bytes(),
        "nibble_expand": old.plan.NIBBLE_EXPAND.read_bytes(),
        "owners": bytes(48),
        "active_mask": bytes(4),
        "next_slot": bytes(4),
        "upload_rect": bytes(8),
        "cell_scratch": bytes(72),
        "decoded_glyph_rows": bytes(24),
    }
    alignments = {
        "huffman_rows": 2,
        "huffman_counts": 1,
        "conflict_ranges": 4,
        "source_checkpoints": 2,
        "source_bitstream": 1,
        "nibble_expand": 2,
        "owners": 2,
        "active_mask": 4,
        "next_slot": 4,
        "upload_rect": 2,
        "cell_scratch": 4,
        "decoded_glyph_rows": 2,
    }
    cursor = old.RESIDENT_BASE
    layout: dict[str, tuple[int, int]] = {}
    for name in blobs:
        cursor = old.align(cursor, alignments[name])
        layout[name] = (cursor, len(blobs[name]))
        cursor += len(blobs[name])
    return layout, blobs


def build_item_guard(address: int) -> bytes:
    """OR row-40 slots from the bounded item-description metadata into T8."""
    asm = old.Assembler(address)
    old.load_address(asm, old.T5, ITEM_DESCRIPTION_HEADER)
    asm.emit(old.i_type(0x25, old.T5, old.T6, 0x0A))       # glyph count
    asm.emit(old.i_type(0x23, old.T5, old.T5, 0x00))       # metadata-array base
    asm.branch(0x04, old.T6, old.ZERO, "done")
    asm.emit(old.i_type(0x24, old.T5, old.T0, 0x29))       # preload V

    asm.label("loop")
    asm.emit(old.i_type(0x24, old.T5, old.T1, 0x28))       # U; V load spacer
    asm.emit(old.i_type(0x09, old.T0, old.T0, -old.CACHE_V))
    asm.emit(old.i_type(0x0B, old.T0, old.T0, 1))          # V == 224
    asm.emit(old.i_type(0x09, old.T1, old.T1, -old.CACHE_U))
    asm.emit(old.i_type(0x0B, old.T1, old.T2,
                        old.CACHE_CELLS * old.CELL))       # U in cache span
    asm.emit(old.r_type(old.T0, old.T2, old.T0, 0, 0x24)) # validity bit
    asm.emit(old.i_type(0x25, old.T5, old.T4, 0x30))       # CLUT

    # For valid U values 4+12*n: q=(U-4)>>2=3*n and
    # slot_base=4*n=(11*q)>>3.  Shift/add avoids HI/LO timing hazards.
    asm.emit(old.r_type(old.ZERO, old.T1, old.T2, 2, 0x02))
    asm.emit(old.r_type(old.ZERO, old.T2, old.T3, 3, 0x00))
    asm.emit(old.r_type(old.ZERO, old.T2, old.T7, 1, 0x00))
    asm.emit(old.r_type(old.T3, old.T7, old.T3, 0, 0x21))
    asm.emit(old.r_type(old.T3, old.T2, old.T3, 0, 0x21))
    asm.emit(old.r_type(old.ZERO, old.T3, old.T3, 3, 0x02))

    asm.emit(old.i_type(0x09, old.T4, old.T4, -FONT_CLUT_MIN))
    asm.emit(old.i_type(0x0B, old.T4, old.T2, 16))
    asm.emit(old.r_type(old.T0, old.T2, old.T0, 0, 0x24))
    asm.emit(old.i_type(0x0C, old.T4, old.T4, 3))
    asm.emit(old.r_type(old.T3, old.T4, old.T3, 0, 0x21))
    asm.emit(old.r_type(old.T0, old.T0, old.T0, 0, 0x04))
    asm.emit(old.r_type(old.T8, old.T0, old.T8, 0, 0x25))

    asm.emit(old.i_type(0x09, old.T5, old.T5, 52))
    asm.emit(old.i_type(0x09, old.T6, old.T6, -1))
    asm.branch(0x05, old.T6, old.ZERO, "loop")
    asm.emit(old.i_type(0x24, old.T5, old.T0, 0x29))       # preload next V
    asm.label("done")
    asm.emit(old.JR_RA)
    asm.emit(old.NOP)
    return asm.finish()


def build_frame(address: int, huffman: int, item_guard: int,
                layout: dict[str, tuple[int, int]]) -> bytes:
    owners = layout["owners"][0]
    active = layout["active_mask"][0]
    rect = layout["upload_rect"][0]
    scratch = layout["cell_scratch"][0]
    decoded = layout["decoded_glyph_rows"][0]
    expand = layout["nibble_expand"][0]

    asm = old.Assembler(address)
    asm.emit(old.i_type(0x09, old.SP, old.SP, -0x50))
    for reg, offset in (
        (old.RA, 0x4C), (old.S0, 0x48), (old.S1, 0x44), (old.S2, 0x40),
        (old.S3, 0x3C), (old.S4, 0x38), (old.S5, 0x34), (old.S6, 0x30),
        (old.S7, 0x2C),
    ):
        asm.emit(old.i_type(0x2B, old.SP, reg, offset))
    asm.emit(old.i_type(0x2B, old.SP, old.A0, 0x20))

    old.load_address(asm, old.T0, active)
    asm.emit(old.i_type(0x23, old.T0, old.S0, 0))
    asm.emit(old.NOP)
    asm.branch(0x04, old.S0, old.ZERO, "protect")
    asm.emit(old.NOP)
    old.load_address(asm, old.S1, owners)
    old.load_address(asm, old.S2, scratch)
    old.load_address(asm, old.S3, decoded)
    old.load_address(asm, old.S4, rect)
    asm.emit(old.move(old.S5, old.ZERO))

    asm.label("cell_loop")
    asm.emit(old.i_type(0x0C, old.S0, old.S7, 0x0F))
    asm.emit(old.r_type(old.ZERO, old.S0, old.S0, 4, 0x02))
    asm.branch(0x04, old.S7, old.ZERO, "cell_next")
    asm.emit(old.NOP)

    asm.emit(old.move(old.T0, old.S2))
    asm.emit(old.i_type(0x0D, old.ZERO, old.T1, 18))
    asm.label("clear_loop")
    asm.emit(old.i_type(0x2B, old.T0, old.ZERO, 0))
    asm.emit(old.i_type(0x09, old.T0, old.T0, 4))
    asm.emit(old.i_type(0x09, old.T1, old.T1, -1))
    asm.branch(0x05, old.T1, old.ZERO, "clear_loop")
    asm.emit(old.NOP)

    asm.emit(old.move(old.S6, old.ZERO))
    asm.label("plane_loop")
    asm.emit(old.r_type(old.ZERO, old.S5, old.T0, 3, 0x00))
    asm.emit(old.r_type(old.ZERO, old.S6, old.T1, 1, 0x00))
    asm.emit(old.r_type(old.T0, old.T1, old.T0, 0, 0x21))
    asm.emit(old.r_type(old.S1, old.T0, old.T0, 0, 0x21))
    asm.emit(old.i_type(0x25, old.T0, old.A0, 0))
    asm.emit(old.move(old.A1, old.S3))
    asm.emit(old.i_type(0x09, old.A0, old.T8, 1))
    asm.branch(0x04, old.T8, old.ZERO, "plane_next")
    asm.emit(old.NOP)
    asm.emit(old.jal(huffman))
    asm.emit(old.NOP)

    old.load_address(asm, old.A2, expand)
    asm.emit(old.move(old.T0, old.S3))
    asm.emit(old.move(old.T1, old.S2))
    asm.emit(old.i_type(0x0D, old.ZERO, old.T2, old.CELL))
    asm.label("row_loop")
    asm.emit(old.i_type(0x25, old.T0, old.T3, 0))
    asm.emit(old.i_type(0x09, old.T0, old.T0, 2))
    asm.emit(old.i_type(0x0D, old.ZERO, old.T4, 8))
    asm.emit(old.i_type(0x0D, old.ZERO, old.T5, 3))
    asm.label("nibble_loop")
    asm.emit(old.r_type(old.T4, old.T3, old.T6, 0, 0x06))
    asm.emit(old.i_type(0x0C, old.T6, old.T6, 0x0F))
    asm.emit(old.r_type(old.ZERO, old.T6, old.T6, 1, 0x00))
    asm.emit(old.r_type(old.A2, old.T6, old.T6, 0, 0x21))
    asm.emit(old.i_type(0x25, old.T6, old.T6, 0))
    asm.emit(old.i_type(0x25, old.T1, old.T7, 0))
    asm.emit(old.r_type(old.S6, old.T6, old.T6, 0, 0x04))
    asm.emit(old.r_type(old.T7, old.T6, old.T7, 0, 0x25))
    asm.emit(old.i_type(0x29, old.T1, old.T7, 0))
    asm.emit(old.i_type(0x09, old.T1, old.T1, 2))
    asm.emit(old.i_type(0x09, old.T4, old.T4, -4))
    asm.emit(old.i_type(0x09, old.T5, old.T5, -1))
    asm.branch(0x05, old.T5, old.ZERO, "nibble_loop")
    asm.emit(old.NOP)
    asm.emit(old.i_type(0x09, old.T2, old.T2, -1))
    asm.branch(0x05, old.T2, old.ZERO, "row_loop")
    asm.emit(old.NOP)

    asm.label("plane_next")
    asm.emit(old.i_type(0x09, old.S6, old.S6, 1))
    asm.emit(old.i_type(0x0B, old.S6, old.T0, old.PLANES))
    asm.branch(0x05, old.T0, old.ZERO, "plane_loop")
    asm.emit(old.NOP)

    asm.emit(old.r_type(old.ZERO, old.S5, old.T0, 1, 0x00))
    asm.emit(old.r_type(old.T0, old.S5, old.T0, 0, 0x21))
    asm.emit(old.i_type(0x09, old.T0, old.T0, old.CACHE_X))
    asm.emit(old.i_type(0x29, old.S4, old.T0, 0))
    asm.emit(old.move(old.A0, old.S4))
    asm.emit(old.move(old.A1, old.S2))
    asm.emit(old.jal(old.LOADIMAGE))
    asm.emit(old.NOP)

    asm.label("cell_next")
    asm.emit(old.i_type(0x09, old.S5, old.S5, 1))
    asm.emit(old.i_type(0x0B, old.S5, old.T0, old.CACHE_CELLS))
    asm.branch(0x05, old.T0, old.ZERO, "cell_loop")
    asm.emit(old.NOP)

    asm.label("protect")
    asm.emit(old.i_type(0x23, old.SP, old.T1, 0x20))
    asm.emit(old.move(old.T8, old.ZERO))
    asm.emit(old.i_type(0x23, old.T1, old.T1, 0))
    asm.emit(old.i_type(0x0D, old.ZERO, old.T9, OT_WALK_LIMIT))
    asm.emit(old.r_type(old.ZERO, old.T1, old.T1, 8, 0x00))
    asm.emit(old.r_type(old.ZERO, old.T1, old.T1, 8, 0x02))

    asm.label("ot_loop")
    asm.branch(0x04, old.T1, old.ZERO, "ot_done")
    asm.emit(old.r_type(old.ZERO, old.T1, old.T3, 21, 0x02))
    asm.branch(0x05, old.T3, old.ZERO, "ot_done")
    asm.emit(old.i_type(0x0F, old.ZERO, old.T3, 0x8000))
    asm.emit(old.r_type(old.T3, old.T1, old.T3, 0, 0x25))
    asm.emit(old.i_type(0x23, old.T3, old.T4, 0))
    asm.emit(old.i_type(0x24, old.T3, old.T5, 7))
    asm.emit(old.r_type(old.ZERO, old.T4, old.T6, 24, 0x02))
    asm.emit(old.i_type(0x09, old.T6, old.T6, -4))
    asm.branch(0x05, old.T6, old.ZERO, "ot_next")
    asm.emit(old.i_type(0x0C, old.T5, old.T5, 0xFC))
    asm.emit(old.i_type(0x0D, old.ZERO, old.T6, 0x64))
    asm.branch(0x05, old.T5, old.T6, "ot_next")
    asm.emit(old.NOP)
    asm.emit(old.i_type(0x24, old.T3, old.T5, 13))
    asm.emit(old.NOP)
    asm.emit(old.i_type(0x09, old.T5, old.T5, -old.CACHE_V))
    asm.branch(0x05, old.T5, old.ZERO, "ot_next")
    asm.emit(old.NOP)
    asm.emit(old.i_type(0x24, old.T3, old.T6, 12))
    asm.emit(old.NOP)
    asm.emit(old.i_type(0x09, old.T6, old.T6, -old.CACHE_U))
    asm.emit(old.i_type(0x0B, old.T6, old.T5, old.CACHE_CELLS * old.CELL))
    asm.branch(0x04, old.T5, old.ZERO, "ot_next")
    asm.emit(old.move(old.T7, old.ZERO))

    asm.label("u_loop")
    asm.branch(0x04, old.T6, old.ZERO, "u_ready")
    asm.emit(old.NOP)
    asm.emit(old.i_type(0x09, old.T6, old.T6, -old.CELL))
    asm.emit(old.i_type(0x09, old.T7, old.T7, old.PLANES))
    asm.emit(old.i_type(0x0B, old.T6, old.T5, old.CACHE_CELLS * old.CELL))
    asm.branch(0x05, old.T5, old.ZERO, "u_loop")
    asm.emit(old.NOP)
    asm.branch(0x04, old.ZERO, old.ZERO, "ot_next")
    asm.emit(old.NOP)

    asm.label("u_ready")
    asm.emit(old.i_type(0x25, old.T3, old.T5, 14))
    asm.emit(old.NOP)
    asm.emit(old.i_type(0x09, old.T5, old.T5, -FONT_CLUT_MIN))
    asm.emit(old.i_type(0x0B, old.T5, old.T6, 16))
    asm.branch(0x04, old.T6, old.ZERO, "ot_next")
    asm.emit(old.i_type(0x0C, old.T5, old.T5, 3))
    asm.emit(old.r_type(old.T7, old.T5, old.T7, 0, 0x21))
    asm.emit(old.i_type(0x0D, old.ZERO, old.T5, 1))
    asm.emit(old.r_type(old.T7, old.T5, old.T5, 0, 0x04))
    asm.emit(old.r_type(old.T8, old.T5, old.T8, 0, 0x25))

    asm.label("ot_next")
    asm.emit(old.r_type(old.ZERO, old.T4, old.T1, 8, 0x00))
    asm.emit(old.r_type(old.ZERO, old.T1, old.T1, 8, 0x02))
    asm.emit(old.i_type(0x09, old.T9, old.T9, -1))
    asm.branch(0x05, old.T9, old.ZERO, "ot_loop")
    asm.emit(old.NOP)

    asm.label("ot_done")
    asm.emit(old.jal(item_guard))
    asm.emit(old.NOP)
    old.load_address(asm, old.T0, active)
    asm.emit(old.i_type(0x2B, old.T0, old.T8, 0))

    asm.emit(old.i_type(0x23, old.SP, old.A0, 0x20))
    asm.emit(old.NOP)
    asm.emit(old.jal(old.DRAWOT))
    asm.emit(old.NOP)
    for reg, offset in (
        (old.RA, 0x4C), (old.S0, 0x48), (old.S1, 0x44), (old.S2, 0x40),
        (old.S3, 0x3C), (old.S4, 0x38), (old.S5, 0x34), (old.S6, 0x30),
        (old.S7, 0x2C),
    ):
        asm.emit(old.i_type(0x23, old.SP, reg, offset))
    asm.emit(old.JR_RA)
    asm.emit(old.i_type(0x09, old.SP, old.SP, 0x50))
    return asm.finish()


def main() -> None:
    if digest(BASE.read_bytes()) != BASE_SHA256:
        raise SystemExit("v166 base archive hash differs")
    old_checkpoints = struct.unpack(
        f"<{old.plan.SOURCE_CHECKPOINTS.stat().st_size // 2}H",
        old.plan.SOURCE_CHECKPOINTS.read_bytes(),
    )
    checkpoints = struct.pack(f"<{len(old_checkpoints[::2])}H", *old_checkpoints[::2])
    if len(checkpoints) != 94:
        raise SystemExit("group-8 checkpoint size differs")
    layout, blobs = pack_layout(checkpoints)

    with ZipFile(BASE) as archive:
        infos = archive.infolist()
        members = {info.filename: archive.read(info.filename) for info in infos}
    before_members = dict(members)
    exe = bytearray(members[old.PSX])
    before_exe = bytes(exe)

    old.CHECKPOINT_GROUP = CHECKPOINT_GROUP
    code_base = old.align(
        layout["decoded_glyph_rows"][0] + layout["decoded_glyph_rows"][1]
    )
    decoder = code_base
    decoder_blob = old.build_decoder(decoder, layout)
    huffman = old.align(decoder + len(decoder_blob))
    huffman_blob = old.build_huffman_decoder(huffman, layout)
    helper = old.align(huffman + len(huffman_blob))
    helper_blob = old.build_helper(helper)
    classifier = old.align(helper + len(helper_blob))
    classifier_blob = old.build_classifier(classifier)
    frame = old.align(classifier + len(classifier_blob))

    probe_frame = build_frame(frame, huffman, frame, layout)
    item_guard = old.align(frame + len(probe_frame))
    frame_blob = build_frame(frame, huffman, item_guard, layout)
    if len(frame_blob) != len(probe_frame):
        raise SystemExit("frame size changed when item-guard target was resolved")
    item_guard_blob = build_item_guard(item_guard)
    used_end = item_guard + len(item_guard_blob)
    if used_end > old.HEAP_BASE:
        raise SystemExit(
            f"v167 exceeds resident reservation by {used_end - old.HEAP_BASE} bytes"
        )

    resident = bytearray(old.COPY_N)
    for name, blob in blobs.items():
        address, size = layout[name]
        if len(blob) != size:
            raise SystemExit(f"layout size differs for {name}")
        resident[address - old.RESIDENT_BASE:address - old.RESIDENT_BASE + size] = blob
    struct.pack_into(
        "<24H", resident, layout["owners"][0] - old.RESIDENT_BASE,
        *([0xFFFF] * 24),
    )
    struct.pack_into(
        "<4H", resident, layout["upload_rect"][0] - old.RESIDENT_BASE,
        old.CACHE_X, old.CACHE_Y, 3, old.CELL,
    )
    routines = (
        ("decoder", decoder, decoder_blob),
        ("huffman", huffman, huffman_blob),
        ("helper", helper, helper_blob),
        ("classifier", classifier, classifier_blob),
        ("frame", frame, frame_blob),
        ("item_guard", item_guard, item_guard_blob),
    )
    for _name, address, blob in routines:
        at = address - old.RESIDENT_BASE
        resident[at:at + len(blob)] = blob
    if any(resident[used_end - old.RESIDENT_BASE:]):
        raise SystemExit("resident bytes beyond used end are nonzero")

    exe[old.file_at(old.SOURCE_BASE):old.file_at(old.SOURCE_BASE) + old.COPY_N] = resident
    writes = (
        (old.DECODER_ENTRY, old.j(decoder), "decoder jump"),
        (old.GLYPH_PACKET_HOOK, old.j(helper), "U helper jump"),
        (old.CLASSIFIER_CALL, old.jal(classifier), "classifier call"),
        (old.LATE_HOOK, old.jal(frame), "pre-DrawOT frame call"),
    )
    for address, value, _label in writes:
        old.put_word(exe, address, value)
    members[old.PSX] = bytes(exe)

    if any(name != old.PSX and members[name] != before_members[name] for name in members):
        raise SystemExit("v167 changed a member other than PSX.EXE")
    if len(exe) != len(before_exe):
        raise SystemExit("PSX.EXE size changed")
    for address, expected, label in (
        (old.EARLY_HOOK, old.jal(old.STOCK_FRAME), "stock early frame"),
        (old.EARLY_DELAY, old.NOP, "early delay"),
        (old.LATE_DELAY, 0x26040070, "late DrawOT argument"),
        (old.RENDER_HOOK, old.j(old.STATELESS_DRIVER), "stateless renderer"),
        (old.RENDER_HOOK + 4, old.NOP, "renderer delay"),
        (old.TPAGE_WORD, 0x34E7001F, "high tpage"),
    ):
        if old.word(exe, address) != expected:
            raise SystemExit(f"guard differs: {label}")
    copy_word = old.word(exe, old.MEMCPY_LEN_AT)
    if (copy_word & 0xFFFF) != old.COPY_N:
        raise SystemExit("startup copy length changed")
    heap_word = old.word(exe, old.HEAP_BASE_AT)
    heap_imm = struct.unpack("<h", struct.pack("<H", heap_word & 0xFFFF))[0]
    if 0x80200000 + heap_imm != old.HEAP_BASE:
        raise SystemExit("heap boundary changed")

    allowed = set(range(old.file_at(old.SOURCE_BASE),
                        old.file_at(old.SOURCE_BASE) + old.COPY_N))
    for address, _value, _label in writes:
        allowed.update(range(old.file_at(address), old.file_at(address) + 4))
    actual_diff = {i for i, (a, b) in enumerate(zip(before_exe, exe)) if a != b}
    if not actual_diff or not actual_diff <= allowed:
        raise SystemExit("PSX.EXE changed outside resident source/hooks")

    notes = []
    md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN)
    disassembly = []
    for name, address, blob in routines:
        notes.extend(old.validate_routine(name, address, blob))
        instructions = list(md.disasm(blob, address))
        if sum(ins.size for ins in instructions) != len(blob):
            raise SystemExit(f"Capstone could not decode {name}")
        disassembly.append(f"--- {name} 0x{address:08X} ({len(blob)} bytes) ---")
        disassembly.extend(
            f"{ins.address:08X}  {ins.mnemonic:<8} {ins.op_str}" for ins in instructions
        )

    ANALYSIS.mkdir(parents=True, exist_ok=True)
    DISASSEMBLY.write_text("\n".join(disassembly) + "\n", encoding="utf-8")
    with LAYOUT_CSV.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(("name", "runtime_address", "size"))
        for name, (address, size) in layout.items():
            writer.writerow((name, f"0x{address:08X}", size))
        for name, address, blob in routines:
            writer.writerow((name, f"0x{address:08X}", len(blob)))

    temporary = old.OUT_DIR / f"{OUT_STEM}_building.zip"
    if temporary.exists():
        raise SystemExit(f"refusing to reuse temporary output: {temporary.name}")
    with ZipFile(temporary, "w", ZIP_DEFLATED) as archive:
        for info in infos:
            archive.writestr(old.clone(info), members[info.filename])
    stamp = digest(temporary.read_bytes())
    output = old.OUT_DIR / f"{OUT_STEM}_{stamp[:8]}.zip"
    if output.exists():
        raise SystemExit(f"refusing to overwrite existing output: {output.name}")
    temporary.replace(output)

    lines = [
        "v167 item-description generation guard",
        f"base={BASE.name}",
        f"base_sha256={BASE_SHA256}",
        f"output={output.name}",
        f"sha256={stamp}",
        "changed_members=PSX.EXE only",
        "COMM.IMG_and_all_translation_members=v166 byte-identical",
        f"checkpoint_group={CHECKPOINT_GROUP}",
        f"checkpoint_bytes={len(checkpoints)} (v166 186; saved 92)",
        f"item_description_header=0x{ITEM_DESCRIPTION_HEADER:08X}",
        "item_guard=V224 + U cache span + CLUT7FC0..7FCF",
        "cache_slots=24 unchanged",
        "cache_VRAM=x961..978,y480..491 unchanged",
        f"frame_bytes={len(frame_blob)}",
        f"item_guard_bytes={len(item_guard_blob)}",
        f"resident_used={used_end - old.RESIDENT_BASE}/{old.COPY_N}",
        f"resident_free={old.HEAP_BASE - used_end}",
        "heap_boundary=0x801FF8B0 unchanged",
        "startup_copy=5356 unchanged",
        *notes,
        "static_build=PASS",
        "runtime=PENDING user cold boot",
        "rollback=v166",
    ]
    REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
