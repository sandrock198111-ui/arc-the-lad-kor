#!/usr/bin/env python3
"""Build v190: repair superseded text glyph owners inside the dynamic cache.

This successor to v189 does not modify COMM.IMG.  It appends four sources to
the resident Huffman library, extends the packed lookup from 409 to 413 entries
and applies only the 83 owner-scoped repairs emitted by the v190 plan.

The resident data grows by 60 bytes after alignment.  Exactly 64 bytes are
recovered from equivalent R3000 scheduling in the Huffman/frame routines, so
the frozen 5,356-byte reservation and 0x801FF8B0 heap boundary do not move.
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
import build_arc1_v171_ui_asset_recovery as v171  # noqa: E402
import build_arc1_v186_runtime_text_choice_fixes as v186  # noqa: E402
import build_arc1_v189_dialogue_timing_choice_rows as v189  # noqa: E402
import plan_arc1_v190_dynamic_owner_repair as plan  # noqa: E402


BASE = plan.BASE
BASE_SHA256 = plan.BASE_SHA256
OUT_DIR = ROOT / "03_output"
OUT_STEM = "arc1_v190_dynamic_owner_repair"
ANALYSIS = ROOT / "01_work/analysis/arc1_v190_dynamic_owner_repair"
REPORT = ANALYSIS / "build_report.txt"
DISASSEMBLY = ANALYSIS / "mips_disassembly.txt"

PSX, COMM = "PSX.EXE", "COMM.IMG"
old = v171.old
RESIDENT_BASE, SOURCE_BASE = v171.RESIDENT_BASE, v171.SOURCE_BASE
COPY_N, HEAP_BASE = v171.COPY_N, v171.HEAP_BASE
CACHE_N, CACHE_CELLS = v171.CACHE_N, v171.CACHE_CELLS

ZERO, AT, V0, V1 = v171.ZERO, v171.AT, v171.V0, v171.V1
A0, A1, A2, A3 = v171.A0, v171.A1, v171.A2, v171.A3
T0, T1, T2, T3, T4, T5, T6, T7 = (
    v171.T0, v171.T1, v171.T2, v171.T3,
    v171.T4, v171.T5, v171.T6, v171.T7,
)
T8, T9, SP, RA = v171.T8, v171.T9, v171.SP, v171.RA
S0, S1, S2, S3, S4, S5, S6, S7 = (
    v171.S0, v171.S1, v171.S2, v171.S3,
    v171.S4, v171.S5, v171.S6, v171.S7,
)
NOP, JR_RA = v171.NOP, v171.JR_RA


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def align(value: int, boundary: int = 4) -> int:
    return (value + boundary - 1) & -boundary


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def resident_layout() -> tuple[dict[str, tuple[int, int]], dict[str, bytes], int]:
    blobs = {
        "huffman_rows": plan.HUFFMAN_ROWS.read_bytes(),
        "source_bitstream": plan.SOURCE_BITSTREAM.read_bytes(),
        "huffman_counts": plan.HUFFMAN_COUNTS.read_bytes(),
        "nibble_expand": v171.old.plan.NIBBLE_EXPAND.read_bytes(),
        "owners": bytes(CACHE_N * 2),
        "active_mask": bytes(4),
        "next_slot": bytes(4),
        "upload_rect": bytes(8),
    }
    alignments = {
        "huffman_rows": 2,
        "source_bitstream": 1,
        "huffman_counts": 1,
        "nibble_expand": 2,
        "owners": 2,
        "active_mask": 4,
        "next_slot": 4,
        "upload_rect": 2,
    }
    cursor = RESIDENT_BASE
    layout: dict[str, tuple[int, int]] = {}
    for name, blob in blobs.items():
        cursor = align(cursor, alignments[name])
        layout[name] = (cursor, len(blob))
        cursor += len(blob)
    return layout, blobs, align(cursor)


def build_decoder(address: int, layout: dict[str, tuple[int, int]]) -> bytes:
    """v171 decoder plus v172's width fix and a 413-entry lookup bound."""
    blob = bytearray(v171.build_decoder(address, layout))
    width_fix = old.i_type(0x0D, ZERO, T9, 2)
    if struct.unpack_from("<I", blob, 12)[0] != NOP:
        raise SystemExit("decoder lookup delay is no longer the v171 NOP")
    struct.pack_into("<I", blob, 12, width_fix)

    before = old.i_type(0x0B, T2, T3, plan.OLD_LOOKUP_N)
    after = old.i_type(0x0B, T2, T3, plan.LOOKUP_N)
    words = list(struct.unpack(f"<{len(blob) // 4}I", blob))
    hits = [i for i, word in enumerate(words) if word == before]
    if len(hits) != 1:
        raise SystemExit(f"decoder has {len(hits)} old lookup-bound instructions")
    struct.pack_into("<I", blob, hits[0] * 4, after)
    return bytes(blob)


def build_huffman(address: int, layout: dict[str, tuple[int, int]]) -> bytes:
    """v171 Huffman decoder with three same-block addresses loaded in four ops."""
    rows, rows_n = layout["huffman_rows"]
    bitstream, stream_n = layout["source_bitstream"]
    counts = layout["huffman_counts"][0]
    if bitstream - rows != rows_n or counts - bitstream != stream_n:
        raise SystemExit("compact Huffman layout is not contiguous")
    if not -0x8000 <= rows_n <= 0x7FFF or not -0x8000 <= stream_n <= 0x7FFF:
        raise SystemExit("compact Huffman address deltas do not fit addiu")
    maximum_code_bits = len(plan.HUFFMAN_COUNTS.read_bytes())
    asm = old.Assembler(address)
    asm.emit(old.r_type(ZERO, A0, T0, 4, 0x02))
    asm.emit(old.r_type(ZERO, T0, T0, 1, 0x00))
    old.load_address(asm, T1, v171.HUFFMAN_CHECKPOINTS_RAM)
    asm.emit(old.r_type(T1, T0, T0, 0, 0x21))
    asm.emit(old.i_type(0x25, T0, T0, 0))
    asm.emit(old.i_type(0x0C, A0, T1, plan.CHECKPOINT_GROUP - 1))
    asm.emit(old.r_type(ZERO, T1, T2, 1, 0x00))
    asm.emit(old.r_type(T2, T1, T2, 0, 0x21))
    asm.emit(old.r_type(ZERO, T1, T1, 3, 0x00))
    asm.emit(old.r_type(T1, T2, T1, 0, 0x21))
    asm.emit(old.i_type(0x0D, ZERO, T2, plan.ENCODED_ROWS))
    old.load_address(asm, A3, rows)
    asm.emit(old.i_type(0x09, A3, V0, rows_n))
    asm.emit(old.i_type(0x09, V0, A2, stream_n))
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
    asm.emit(old.i_type(0x29, A1, ZERO, 0))
    return asm.finish()


def build_frame(address: int, huffman_address: int,
                layout: dict[str, tuple[int, int]]) -> bytes:
    """v171 frame routine with fourteen proven-equivalent instructions folded."""
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
    asm.emit(old.i_type(0x0F, ZERO, S1, owners >> 16))
    asm.branch(0x04, S0, ZERO, "protect")
    asm.emit(old.i_type(0x0D, S1, S1, owners & 0xFFFF))
    asm.emit(old.i_type(0x09, SP, S2, 0))
    asm.emit(old.i_type(0x09, SP, S3, decoded_at))
    old.load_address(asm, S4, rect)
    asm.emit(old.move(S5, ZERO))
    asm.label("cell_loop")
    asm.emit(old.i_type(0x0C, S0, S7, 0x0F))
    asm.emit(old.r_type(ZERO, S0, S0, 4, 0x02))
    asm.branch(0x04, S7, ZERO, "cell_next")
    asm.emit(old.move(T0, S2))                           # folded branch delay
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
    asm.emit(old.move(A1, S3))                           # R3000 load spacer
    asm.emit(old.i_type(0x09, A0, T8, 1))
    asm.branch(0x04, T8, ZERO, "plane_next")
    asm.emit(NOP)
    asm.emit(old.jal(huffman_address))
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
    asm.branch(0x01, T4, 1, "nibble_loop")
    asm.emit(old.i_type(0x09, T1, T1, 2))
    asm.emit(old.i_type(0x09, T2, T2, -1))
    asm.branch(0x05, T2, ZERO, "row_loop")
    asm.emit(old.i_type(0x09, T0, T0, 2))
    asm.label("plane_next")
    asm.emit(old.i_type(0x09, S6, S6, 1))
    asm.emit(old.i_type(0x0B, S6, T0, old.PLANES))
    asm.branch(0x05, T0, ZERO, "plane_loop")
    asm.emit(old.r_type(ZERO, S5, T0, 1, 0x00))         # folded branch delay
    asm.emit(old.r_type(T0, S5, T0, 0, 0x21))
    asm.emit(old.i_type(0x09, T0, T0, v171.CACHE_X))
    asm.emit(old.i_type(0x29, S4, T0, 0))
    asm.emit(old.move(A0, S4))
    asm.emit(old.move(A1, S2))
    asm.emit(old.jal(old.LOADIMAGE))
    asm.emit(NOP)
    asm.label("cell_next")
    asm.emit(old.i_type(0x09, S5, S5, 1))
    asm.emit(old.i_type(0x0B, S5, T0, CACHE_CELLS))
    asm.branch(0x05, T0, ZERO, "cell_loop")
    asm.emit(old.i_type(0x23, SP, T1, saved_a0))        # folded branch delay

    asm.label("protect")
    asm.emit(old.move(T8, ZERO))
    asm.emit(old.i_type(0x23, T1, T1, 0))
    if v171.v166.RAM_LIMIT != 0x00200000:
        raise SystemExit("RAM limit no longer fits a single LUI")
    asm.emit(old.i_type(0x0F, ZERO, T2, 0x0020))        # no redundant ori zero
    asm.emit(old.r_type(ZERO, T1, T1, 8, 0x00))
    asm.emit(old.r_type(ZERO, T1, T1, 8, 0x02))
    asm.emit(old.i_type(0x0D, ZERO, T9, v171.v166.OT_WALK_LIMIT))
    asm.label("ot_loop")
    asm.branch(0x04, T1, ZERO, "ot_done")
    asm.emit(old.r_type(T1, T2, T3, 0, 0x2B))          # folded branch delay
    asm.branch(0x04, T3, ZERO, "ot_done")
    asm.emit(old.i_type(0x0F, ZERO, T3, 0x8000))        # exact 0x80000000
    asm.emit(old.r_type(T3, T1, T3, 0, 0x25))
    asm.emit(old.i_type(0x23, T3, T4, 0))
    asm.emit(old.i_type(0x24, T3, T5, 7))
    asm.emit(old.r_type(ZERO, T4, T6, 24, 0x02))
    asm.emit(old.i_type(0x09, T6, T6, -4))
    asm.branch(0x05, T6, ZERO, "ot_next")
    asm.emit(old.i_type(0x0C, T5, T5, 0xFC))
    asm.emit(old.i_type(0x0D, ZERO, T6, 0x64))
    asm.branch(0x05, T5, T6, "ot_next")
    asm.emit(old.i_type(0x24, T3, T5, 13))              # folded branch delay
    asm.emit(old.i_type(0x24, T3, T6, 12))              # load spacer for T5
    asm.emit(old.i_type(0x09, T5, T5, -v171.CACHE_V))
    asm.branch(0x05, T5, ZERO, "ot_next")
    asm.emit(old.i_type(0x09, T6, T6, -v171.CACHE_U))   # folded branch delay
    asm.emit(old.i_type(0x0B, T6, T5, CACHE_CELLS * old.CELL))
    asm.branch(0x04, T5, ZERO, "ot_next")
    asm.emit(old.move(T7, ZERO))
    asm.label("u_loop")
    asm.branch(0x04, T6, ZERO, "u_ready")
    asm.emit(old.i_type(0x09, T6, T6, -old.CELL))
    asm.emit(old.i_type(0x09, T7, T7, old.PLANES))
    asm.branch(0x01, T6, 1, "u_loop")                  # bgez; folded slti
    asm.emit(NOP)
    asm.branch(0x04, ZERO, ZERO, "ot_next")
    asm.emit(NOP)
    asm.label("u_ready")
    asm.emit(old.i_type(0x25, T3, T5, 14))
    asm.emit(NOP)
    asm.emit(old.i_type(0x09, T5, T5, -v171.v166.FONT_CLUT_MIN))
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
    asm.emit(old.jal(old.DRAWOT))                        # load-delay spacer
    asm.emit(NOP)
    for reg, offset in save.items():
        asm.emit(old.i_type(0x23, SP, reg, offset))
    asm.emit(JR_RA)
    asm.emit(old.i_type(0x09, SP, SP, stack_size))
    return asm.finish()


def current_resident() -> bytes:
    """Reconstruct v172+ resident bytes and use them as the v189 base guard."""
    layout, blobs, code_base = v171.resident_layout()
    decoder = code_base
    decoder_blob = bytearray(v171.build_decoder(decoder, layout))
    struct.pack_into("<I", decoder_blob, 12, old.i_type(0x0D, ZERO, T9, 2))
    huffman_address = align(decoder + len(decoder_blob))
    huffman_blob = v171.build_huffman(huffman_address, layout)
    frame = align(huffman_address + len(huffman_blob))
    frame_blob = v171.build_frame(frame, huffman_address, layout)
    resident = bytearray(COPY_N)
    for name, blob in blobs.items():
        at = layout[name][0] - RESIDENT_BASE
        resident[at:at + len(blob)] = blob
    struct.pack_into(
        f"<{CACHE_N}H", resident, layout["owners"][0] - RESIDENT_BASE,
        *([0xFFFF] * CACHE_N),
    )
    struct.pack_into(
        "<4H", resident, layout["upload_rect"][0] - RESIDENT_BASE,
        v171.CACHE_X, v171.CACHE_Y, 3, old.CELL,
    )
    for address, blob in (
        (decoder, bytes(decoder_blob)), (huffman_address, huffman_blob), (frame, frame_blob)
    ):
        at = address - RESIDENT_BASE
        resident[at:at + len(blob)] = blob
    return bytes(resident)


def main() -> None:
    plan.main()
    if digest(BASE.read_bytes()) != BASE_SHA256:
        raise SystemExit("v189 base archive hash differs")
    with ZipFile(BASE) as archive:
        infos = archive.infolist()
        members = {info.filename: archive.read(info.filename) for info in infos}
    before = dict(members)
    exe = bytearray(members[PSX])

    source_at = old.file_at(SOURCE_BASE)
    if bytes(exe[source_at:source_at + COPY_N]) != current_resident():
        raise SystemExit("v189 resident source differs from reconstructed v172+ baseline")
    if members[COMM] != before[COMM]:
        raise SystemExit("internal COMM baseline guard failed")

    layout, resident_blobs, code_base = resident_layout()
    decoder = code_base
    decoder_blob = build_decoder(decoder, layout)
    huffman_address = align(decoder + len(decoder_blob))
    huffman_blob = build_huffman(huffman_address, layout)
    frame = align(huffman_address + len(huffman_blob))
    frame_blob = build_frame(frame, huffman_address, layout)
    used_end = frame + len(frame_blob)
    if (len(decoder_blob), len(huffman_blob), len(frame_blob)) != (568, 232, 584):
        raise SystemExit(
            "compact routine sizes differ: "
            f"{len(decoder_blob)}/{len(huffman_blob)}/{len(frame_blob)}"
        )
    if used_end != HEAP_BASE:
        raise SystemExit(
            f"resident end is 0x{used_end:08X}, expected the frozen heap boundary"
        )

    routines = (
        ("decoder", decoder, decoder_blob),
        ("huffman", huffman_address, huffman_blob),
        ("frame", frame, frame_blob),
    )
    routine_notes: list[str] = []
    for name, address, blob in routines:
        routine_notes.extend(old.validate_routine(name, address, blob))

    resident = bytearray(COPY_N)
    for name, blob in resident_blobs.items():
        address, size = layout[name]
        if len(blob) != size:
            raise SystemExit(f"resident blob size differs: {name}")
        at = address - RESIDENT_BASE
        resident[at:at + size] = blob
    struct.pack_into(
        f"<{CACHE_N}H", resident, layout["owners"][0] - RESIDENT_BASE,
        *([0xFFFF] * CACHE_N),
    )
    struct.pack_into(
        "<4H", resident, layout["upload_rect"][0] - RESIDENT_BASE,
        v171.CACHE_X, v171.CACHE_Y, 3, old.CELL,
    )
    for _name, address, blob in routines:
        at = address - RESIDENT_BASE
        resident[at:at + len(blob)] = blob
    if any(resident[used_end - RESIDENT_BASE:]):
        raise SystemExit("resident tail is not zero")
    exe[source_at:source_at + COPY_N] = resident

    # Extend the packed lookup into the old, now-relocated count-table bytes.
    lookup_blob = plan.LOOKUP_TABLE.read_bytes()
    if len(lookup_blob) != 568:
        raise SystemExit("v190 packed lookup is not 568 bytes")
    lookup_at = old.file_at(v171.PACKED_LOOKUP_RAM)
    exe[lookup_at:lookup_at + len(lookup_blob)] = lookup_blob
    checkpoints = plan.SOURCE_CHECKPOINTS.read_bytes()
    if len(checkpoints) != v171.PARSER_HELPER - v171.HUFFMAN_CHECKPOINTS_RAM:
        raise SystemExit("v190 checkpoints do not exactly end at parser helper")
    checkpoint_at = old.file_at(v171.HUFFMAN_CHECKPOINTS_RAM)
    exe[checkpoint_at:checkpoint_at + len(checkpoints)] = checkpoints

    old.put_word(exe, old.DECODER_ENTRY, old.j(decoder))
    old.put_word(exe, old.LATE_HOOK, old.jal(frame))
    if old.word(exe, old.DECODER_ENTRY + 4) != NOP or old.word(exe, old.LATE_DELAY) != 0x26040070:
        raise SystemExit("hook delay-slot guard differs")
    members[PSX] = bytes(exe)

    # Apply only the exact owner/offset repairs from the plan.  Seven 페 records
    # intentionally keep EA 9E and become valid through the extended lookup.
    repair_rows = read_csv(plan.OWNER_REPAIRS)
    if len(repair_rows) != 83:
        raise SystemExit("v190 owner repair manifest is not exactly 83 records")
    actual_byte_repairs = 0
    for row in repair_rows:
        member = row["member"]
        offset = int(row["offset"], 0)
        old_bytes = bytes.fromhex(row["old_hex"])
        new_bytes = bytes.fromhex(row["new_hex"])
        data = bytearray(members[member])
        if bytes(data[offset:offset + len(old_bytes)]) != old_bytes:
            raise SystemExit(f"repair build guard differs: {member} 0x{offset:X}")
        data[offset:offset + len(old_bytes)] = new_bytes
        members[member] = bytes(data)
        actual_byte_repairs += old_bytes != new_bytes

    # The font and every member length are frozen; choice control geometry is
    # rechecked against the v189 before-image after all owner writes.
    if members[COMM] != before[COMM]:
        raise SystemExit("COMM.IMG changed in a dynamic-only build")
    if any(len(members[name]) != len(before[name]) for name in members):
        raise SystemExit("archive member length changed")
    choice_checked = 0
    for name, bodies in v186.choice_bodies().items():
        if name not in members:
            continue
        for offset, raw in bodies:
            left = before[name][offset:offset + len(raw)]
            right = members[name][offset:offset + len(raw)]
            if v186.structural.markers(left) != v186.structural.markers(right):
                raise SystemExit(f"choice geometry changed: {name} 0x{offset:X}")
            choice_checked += 1
    if choice_checked != 357:
        raise SystemExit(f"choice body audit count is {choice_checked}, not 357")

    # Full routine disassembly must consume every byte.
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

    changed = sorted(name for name in members if members[name] != before[name])
    if PSX not in changed or COMM in changed:
        raise SystemExit(f"changed member set violates dynamic-only contract: {changed}")

    temporary = OUT_DIR / f"{OUT_STEM}_building.zip"
    if temporary.exists():
        raise SystemExit(f"refusing to overwrite temporary output: {temporary}")
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
        raise SystemExit(f"refusing to overwrite existing output: {output}")
    temporary.replace(output)

    report = [
        "v190 dynamic-only glyph owner repair",
        f"base={BASE.name}",
        f"base_sha256={BASE_SHA256}",
        f"output={output.name}",
        f"sha256={stamp}",
        "COMM.IMG=byte-identical to v189 PASS",
        "existing_lookup_entries=409/409 preserved",
        "lookup_entries=413; new codes EA9C..EA9F",
        "dynamic_sources=466; old sources 462/462 preserved",
        "Huffman_readback=466/466 PASS",
        "cache_slots=28",
        "bounded_max_simultaneous_dynamic=26",
        f"owner_records={len(repair_rows)}",
        f"owner_actual_byte_replacements={actual_byte_repairs}",
        f"choice_bodies_checked={choice_checked}",
        "choice_E5_E6_geometry=unchanged PASS",
        f"changed_members={','.join(changed)}",
        f"resident_data_bytes={code_base - RESIDENT_BASE}",
        f"decoder 0x{decoder:08X} / {len(decoder_blob)} bytes",
        f"frame routine 0x{frame:08X} / {len(frame_blob)} bytes",
        f"huffman 0x{huffman_address:08X} / {len(huffman_blob)} bytes",
        f"resident_used={used_end - RESIDENT_BASE}/{COPY_N}",
        f"resident_free={HEAP_BASE - used_end}",
        "heap_boundary=0x801FF8B0 unchanged",
        "startup_copy=5356 unchanged",
        *routine_notes,
        "capstone_disassembly=PASS",
        "archive_member_order=PASS",
        "archive_member_lengths=PASS",
        "archive_roundtrip=PASS",
        "emulator_run=NO",
        "runtime=PENDING user cold boot",
        "rollback=v189",
    ]
    REPORT.write_text("\n".join(report) + "\n", encoding="utf-8")
    print("\n".join(report))
    print(REPORT)


if __name__ == "__main__":
    main()
