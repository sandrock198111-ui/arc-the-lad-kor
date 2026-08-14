"""Build v212 TEST ONLY: select cache destination A or B for each frame.

The proven v210 cache stays canonical at virtual row 40.  Before its upload,
this build scans the current OT.  Destination A is retained unless a non-font
SPRT on 4bpp tpage 31 overlaps A; only then is destination B selected.  Cache
SPRTs left at B's V by a persistent OT are canonicalised to V=224 during the
same scan, and the frame routine rewrites proven cache packets to the selected
V immediately before DrawOT.

No resident RAM is added and no archive member changes size.  The selector is
split across three guarded executable windows already present in v210.
"""
from __future__ import annotations

import hashlib
import struct
import sys
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))
sys.path.insert(0, str(ROOT / "06_tools/python_packages"))

from capstone import Cs, CS_ARCH_MIPS, CS_MODE_LITTLE_ENDIAN, CS_MODE_MIPS32  # noqa: E402
import build_arc1_v171_ui_asset_recovery as v171  # noqa: E402
import build_arc1_v190_dynamic_owner_repair as v190  # noqa: E402


BASE = ROOT / "03_output/arc1_v210_sd031_slots_controls.zip"
BASE_SHA256 = "7FB963135C753CBF509F9E722BF826856B04D456D29743A0B1D8CB5A9B34CAF9"
OUT_DIR = ROOT / "03_output"
OUT_STEM = "arc1_v212_ab_cache_selector_TEST_ONLY"
ANALYSIS = ROOT / "01_work/analysis" / OUT_STEM
REPORT = ANALYSIS / "build_report.txt"
DISASSEMBLY = ANALYSIS / "mips_disassembly.txt"

PSX = "PSX.EXE"
old = v171.old
R2F = 0x8011A800

SELECTOR_ENTRY, ENTRY_CAP = 0x80193B44, 128
SELECTOR_CHECK, CHECK_CAP = 0x8019D0D0, 104
SELECTOR_FINISH, FINISH_CAP = 0x801A2060, 36
LIVE_DISPATCH, LIVE_DISPATCH_N = 0x8019D074, 92
LIVE_DISPATCH_HOOK = 0x8016B5D8

CACHE_A_Y, CACHE_A_V = 480, 224
CACHE_B_Y, CACHE_B_V = 384, 128
CACHE_U0 = v171.CACHE_U
CACHE_U1 = CACHE_U0 + v171.CACHE_CELLS * old.CELL
TPAGE_4BPP_X15_Y1 = 31

ZERO, V0, V1 = v171.ZERO, v171.V0, v171.V1
A0, A1, A2, A3 = v171.A0, v171.A1, v171.A2, v171.A3
T0, T1, T2, T3, T4, T5, T6, T7 = (
    v171.T0, v171.T1, v171.T2, v171.T3,
    v171.T4, v171.T5, v171.T6, v171.T7,
)
T8, T9, K0, K1 = v171.T8, v171.T9, 26, 27
SP, RA = v171.SP, v171.RA
S0, S1, S2, S3, S4, S5, S6, S7 = (
    v171.S0, v171.S1, v171.S2, v171.S3,
    v171.S4, v171.S5, v171.S6, v171.S7,
)
NOP, JR_RA = v171.NOP, v171.JR_RA


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def clone(info: ZipInfo) -> ZipInfo:
    result = ZipInfo(info.filename, info.date_time)
    for attr in (
        "compress_type", "comment", "extra", "create_system", "create_version",
        "extract_version", "flag_bits", "volume", "internal_attr", "external_attr",
    ):
        setattr(result, attr, getattr(info, attr))
    return result


def branch(op: int, rs: int, rt: int, pc: int, target: int) -> int:
    delta = target - (pc + 4)
    if delta & 3 or not -0x20000 <= delta < 0x20000:
        raise SystemExit(f"branch out of range: 0x{pc:08X} -> 0x{target:08X}")
    return (op << 26) | (rs << 21) | (rt << 16) | ((delta >> 2) & 0xFFFF)


def direct_refs(exe: bytes | bytearray, lo: int, hi: int) -> list[tuple[int, str, int]]:
    result: list[tuple[int, str, int]] = []
    for offset in range(0x800, min(len(exe), 0x8E000), 4):
        word = struct.unpack_from("<I", exe, offset)[0]
        op = word >> 26
        if op not in (2, 3):
            continue
        pc = R2F + offset
        target = ((pc + 4) & 0xF0000000) | ((word & 0x03FFFFFF) << 2)
        if lo <= target < hi:
            result.append((pc, "j" if op == 2 else "jal", target))
    return result


def selector_blobs(frame: int, rect: int) -> tuple[bytes, bytes, bytes]:
    """Build three no-call selector fragments; RA remains the hook caller's RA."""
    loop = SELECTOR_ENTRY + 5 * 4
    not_tpage = SELECTOR_ENTRY + 18 * 4
    dynamic = SELECTOR_CHECK + 4 * 4
    game = SELECTOR_CHECK + 8 * 4
    next_packet = SELECTOR_CHECK + 21 * 4

    entry = [
        old.move(A3, ZERO),
        old.i_type(0x23, A0, T0, 0),
        old.move(A2, ZERO),                              # load spacer
        old.r_type(ZERO, T0, T0, 8, 0x00),
        old.r_type(ZERO, T0, T0, 8, 0x02),
        branch(0x04, T0, ZERO, SELECTOR_ENTRY + 5 * 4, SELECTOR_FINISH),
        old.i_type(0x0F, ZERO, T2, 0x8000),
        old.r_type(T2, T0, T2, 0, 0x25),
        old.i_type(0x23, T2, T3, 0),
        old.i_type(0x24, T2, T5, 7),
        old.i_type(0x25, T2, T4, 4),
        old.i_type(0x09, T5, T6, -0xE1),
        branch(0x05, T6, ZERO, SELECTOR_ENTRY + 12 * 4, not_tpage),
        old.i_type(0x0C, T4, T6, 0x01FF),
        old.i_type(0x09, T6, T6, -TPAGE_4BPP_X15_Y1),
        old.i_type(0x0B, T6, A2, 1),
        branch(0x04, ZERO, ZERO, SELECTOR_ENTRY + 16 * 4, next_packet),
        NOP,
        branch(0x04, A2, ZERO, not_tpage, next_packet),
        old.i_type(0x0C, T5, T6, 0xFC),
        old.i_type(0x09, T6, T6, -0x64),
        branch(0x05, T6, ZERO, SELECTOR_ENTRY + 21 * 4, next_packet),
        NOP,
        old.j(SELECTOR_CHECK),
        NOP,
        old.i_type(0x25, T2, T6, 14),
        old.i_type(0x24, T2, T7, 12),
        old.i_type(0x24, T2, T9, 13),
        old.i_type(0x09, T6, V0, -v171.v166.FONT_CLUT_MIN),
        old.i_type(0x0B, V0, V0, 16),
        branch(0x04, V0, ZERO, SELECTOR_ENTRY + 30 * 4, game),
        old.i_type(0x09, T9, V1, -CACHE_B_V),
    ]
    if len(entry) * 4 != ENTRY_CAP:
        raise SystemExit(f"selector entry is {len(entry) * 4}, expected {ENTRY_CAP}")

    check = [
        branch(0x04, V1, ZERO, SELECTOR_CHECK + 0 * 4, dynamic),
        old.i_type(0x09, T9, V0, -CACHE_A_V),
        branch(0x05, V0, ZERO, SELECTOR_CHECK + 2 * 4, game),
        NOP,
        old.i_type(0x0D, ZERO, V0, CACHE_A_V),
        old.i_type(0x28, T2, V0, 13),
        branch(0x04, ZERO, ZERO, SELECTOR_CHECK + 6 * 4, next_packet),
        NOP,
        old.i_type(0x0B, T7, V0, CACHE_U1),
        branch(0x04, V0, ZERO, SELECTOR_CHECK + 9 * 4, next_packet),
        old.i_type(0x24, T2, V1, 16),
        old.i_type(0x24, T2, K0, 17),                  # width-load spacer
        old.r_type(T7, V1, V1, 0, 0x21),
        old.i_type(0x0B, V1, V1, CACHE_U0 + 1),
        branch(0x05, V1, ZERO, SELECTOR_CHECK + 14 * 4, next_packet),
        old.r_type(T9, K0, K1, 0, 0x21),
        old.i_type(0x0B, T9, V0, CACHE_A_V + old.CELL),
        branch(0x04, V0, ZERO, SELECTOR_CHECK + 17 * 4, next_packet),
        old.i_type(0x0B, K1, V1, CACHE_A_V + 1),
        old.i_type(0x0E, V1, V1, 1),
        old.r_type(A3, V1, A3, 0, 0x25),
        old.r_type(ZERO, T3, T0, 8, 0x00),
        branch(0x05, T0, ZERO, SELECTOR_CHECK + 22 * 4, loop),
        old.r_type(ZERO, T0, T0, 8, 0x02),
        old.j(SELECTOR_FINISH),
        NOP,
    ]
    if len(check) * 4 != CHECK_CAP:
        raise SystemExit(f"selector check is {len(check) * 4}, expected {CHECK_CAP}")

    finish = [
        branch(0x04, A3, ZERO, SELECTOR_FINISH + 0 * 4, SELECTOR_FINISH + 3 * 4),
        old.i_type(0x0D, ZERO, A1, CACHE_A_V),
        old.i_type(0x0D, ZERO, A1, CACHE_B_V),
        old.i_type(0x09, A1, T7, 256),
        old.i_type(0x0F, ZERO, T8, rect >> 16),
        old.i_type(0x0D, T8, T8, rect & 0xFFFF),
        old.i_type(0x29, T8, T7, 2),
        old.j(frame),
        NOP,
    ]
    if len(finish) * 4 != FINISH_CAP:
        raise SystemExit(f"selector finish is {len(finish) * 4}, expected {FINISH_CAP}")
    return (
        struct.pack(f"<{len(entry)}I", *entry),
        struct.pack(f"<{len(check)}I", *check),
        struct.pack(f"<{len(finish)}I", *finish),
    )


def build_frame(address: int, huffman_address: int,
                layout: dict[str, tuple[int, int]]) -> bytes:
    """v190 frame, with per-frame selected V and a valid zero-active path."""
    owners = layout["owners"][0]
    active = layout["active_mask"][0]
    rect = layout["upload_rect"][0]
    expand = layout["nibble_expand"][0]
    if active - rect != -8:
        raise SystemExit("active mask is no longer eight bytes before upload_rect")
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
    old.load_address(asm, S4, rect)
    asm.emit(old.move(S7, A1))                           # selector's V
    old.load_address(asm, T0, active)
    asm.emit(old.i_type(0x23, T0, S0, 0))
    asm.emit(old.i_type(0x0F, ZERO, S1, owners >> 16))
    asm.branch(0x04, S0, ZERO, "protect")
    asm.emit(old.i_type(0x0D, S1, S1, owners & 0xFFFF))
    asm.emit(old.i_type(0x09, SP, S2, 0))
    asm.emit(old.i_type(0x09, SP, S3, decoded_at))
    asm.emit(old.move(S5, ZERO))
    asm.label("cell_loop")
    asm.emit(old.i_type(0x0C, S0, K0, 0x0F))
    asm.emit(old.r_type(ZERO, S0, S0, 4, 0x02))
    asm.branch(0x04, K0, ZERO, "cell_next")
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
    asm.emit(old.r_type(ZERO, S5, T0, 1, 0x00))
    asm.emit(old.r_type(T0, S5, T0, 0, 0x21))
    asm.emit(old.i_type(0x09, T0, T0, v171.CACHE_X))
    asm.emit(old.i_type(0x29, S4, T0, 0))
    asm.emit(old.move(A0, S4))
    asm.emit(old.jal(old.LOADIMAGE))
    asm.emit(old.move(A1, S2))                           # safe call delay slot
    asm.label("cell_next")
    asm.emit(old.i_type(0x09, S5, S5, 1))
    asm.emit(old.i_type(0x0B, S5, T0, v190.CACHE_CELLS))
    asm.branch(0x05, T0, ZERO, "cell_loop")
    asm.emit(NOP)

    asm.label("protect")
    asm.emit(old.i_type(0x23, SP, T1, saved_a0))
    asm.emit(old.move(T8, ZERO))                         # load spacer
    asm.emit(old.i_type(0x23, T1, T1, 0))
    if v171.v166.RAM_LIMIT != 0x00200000:
        raise SystemExit("RAM limit no longer fits a single LUI")
    asm.emit(old.i_type(0x0F, ZERO, T2, 0x0020))
    asm.emit(old.r_type(ZERO, T1, T1, 8, 0x00))
    asm.emit(old.r_type(ZERO, T1, T1, 8, 0x02))
    asm.emit(old.i_type(0x0D, ZERO, T9, v171.v166.OT_WALK_LIMIT))
    asm.label("ot_loop")
    asm.branch(0x04, T1, ZERO, "ot_done")
    asm.emit(old.r_type(T1, T2, T3, 0, 0x2B))
    asm.branch(0x04, T3, ZERO, "ot_done")
    asm.emit(old.i_type(0x0F, ZERO, T3, 0x8000))
    asm.emit(old.r_type(T3, T1, T3, 0, 0x25))
    asm.emit(old.i_type(0x23, T3, T4, 0))
    asm.emit(old.i_type(0x24, T3, T5, 7))
    asm.emit(old.r_type(ZERO, T4, T6, 24, 0x02))
    asm.emit(old.i_type(0x09, T6, T6, -4))
    asm.branch(0x05, T6, ZERO, "ot_next")
    asm.emit(old.i_type(0x0C, T5, T5, 0xFC))
    asm.emit(old.i_type(0x0D, ZERO, T6, 0x64))
    asm.branch(0x05, T5, T6, "ot_next")
    asm.emit(old.i_type(0x24, T3, T5, 13))
    asm.emit(old.i_type(0x24, T3, T6, 12))
    asm.emit(old.i_type(0x09, T5, T5, -v171.CACHE_V))
    asm.branch(0x05, T5, ZERO, "ot_next")
    asm.emit(old.i_type(0x09, T6, T6, -v171.CACHE_U))
    asm.emit(old.i_type(0x0B, T6, T5, v190.CACHE_CELLS * old.CELL))
    asm.branch(0x04, T5, ZERO, "ot_next")
    asm.emit(old.move(T7, ZERO))
    asm.label("u_loop")
    asm.branch(0x04, T6, ZERO, "u_ready")
    asm.emit(old.i_type(0x09, T6, T6, -old.CELL))
    asm.emit(old.i_type(0x09, T7, T7, old.PLANES))
    asm.branch(0x01, T6, 1, "u_loop")
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
    asm.emit(old.i_type(0x28, T3, S7, 13))              # selected cache V
    asm.label("ot_next")
    asm.emit(old.r_type(ZERO, T4, T1, 8, 0x00))
    asm.emit(old.r_type(ZERO, T1, T1, 8, 0x02))
    asm.emit(old.i_type(0x09, T9, T9, -1))
    asm.branch(0x05, T9, ZERO, "ot_loop")
    asm.emit(NOP)
    asm.label("ot_done")
    asm.emit(old.i_type(0x2B, S4, T8, active - rect))
    asm.emit(old.i_type(0x23, SP, A0, saved_a0))
    asm.emit(old.jal(old.DRAWOT))
    asm.emit(NOP)
    for reg, offset in save.items():
        asm.emit(old.i_type(0x23, SP, reg, offset))
    asm.emit(JR_RA)
    asm.emit(old.i_type(0x09, SP, SP, stack_size))
    return asm.finish()


def selector_model(packets: list[dict[str, int]]) -> tuple[int, list[int]]:
    """Python mirror used only for deterministic selector edge tests."""
    conflict_a = False
    current_tpage = None
    out_v: list[int] = []
    for packet in packets:
        if packet["cmd"] == 0xE1:
            current_tpage = packet["tpage"] & 0x1FF
            continue
        v = packet.get("v", 0)
        if current_tpage != TPAGE_4BPP_X15_Y1 or packet["cmd"] & 0xFC != 0x64:
            out_v.append(v)
            continue
        clut = packet.get("clut", 0)
        if v in (CACHE_A_V, CACHE_B_V) and v171.v166.FONT_CLUT_MIN <= clut < v171.v166.FONT_CLUT_MIN + 16:
            out_v.append(CACHE_A_V)
            continue
        u, w, h = packet["u"], packet["w"], packet["h"]
        if u < CACHE_U1 and u + w > CACHE_U0 and v < CACHE_A_V + old.CELL and v + h > CACHE_A_V:
            conflict_a = True
        out_v.append(v)
    return (CACHE_B_V if conflict_a else CACHE_A_V), out_v


def validate_selector(address: int, blob: bytes,
                      ranges: tuple[tuple[int, int], ...], frame: int) -> list[str]:
    words = struct.unpack(f"<{len(blob) // 4}I", blob)
    notes: list[str] = []
    for index, word in enumerate(words):
        pc = address + index * 4
        op = word >> 26
        if op in (0x01, 0x04, 0x05, 0x06, 0x07):
            simm = ((word & 0xFFFF) ^ 0x8000) - 0x8000
            target = pc + 4 + simm * 4
            if not any(lo <= target < hi for lo, hi in ranges):
                raise SystemExit(f"selector branch leaves guarded code: 0x{pc:08X} -> 0x{target:08X}")
        elif op == 0x02:
            target = ((pc + 4) & 0xF0000000) | ((word & 0x03FFFFFF) << 2)
            if target not in {SELECTOR_CHECK, SELECTOR_FINISH, frame}:
                raise SystemExit(f"selector jump target differs: 0x{pc:08X} -> 0x{target:08X}")
    notes.append(f"selector_0x{address:08X}_branches=PASS")
    return notes


def main() -> None:
    if digest(BASE.read_bytes()) != BASE_SHA256:
        raise SystemExit("v210 base archive SHA256 differs")
    with ZipFile(BASE) as archive:
        infos = archive.infolist()
        before = {info.filename: archive.read(info.filename) for info in infos}
    with ZipFile(ROOT / "00_original/arc.zip") as archive:
        stock_exe = archive.read(PSX)
    members = dict(before)
    exe = bytearray(members[PSX])

    layout, _resident_blobs, code_base = v190.resident_layout()
    decoder = code_base
    decoder_blob = v190.build_decoder(decoder, layout)
    huffman = (decoder + len(decoder_blob) + 3) & ~3
    huffman_blob = v190.build_huffman(huffman, layout)
    frame = (huffman + len(huffman_blob) + 3) & ~3
    baseline_frame = v190.build_frame(frame, huffman, layout)
    frame_blob = build_frame(frame, huffman, layout)
    if (decoder, len(decoder_blob), huffman, len(huffman_blob), frame, len(frame_blob)) != (
        0x801FF348, 568, 0x801FF580, 232, 0x801FF668, 584,
    ):
        raise SystemExit("resident routine layout no longer matches v210")
    if len(frame_blob) != len(baseline_frame):
        raise SystemExit("frame size changed")

    source_at = old.file_at(v171.SOURCE_BASE)
    frame_at = source_at + frame - v171.RESIDENT_BASE
    rect = layout["upload_rect"][0]
    rect_at = source_at + rect - v171.RESIDENT_BASE
    if bytes(exe[frame_at:frame_at + len(baseline_frame)]) != baseline_frame:
        raise SystemExit("v210 resident frame differs from reconstructed v190 frame")
    if struct.unpack_from("<4H", exe, rect_at) != (v171.CACHE_X, CACHE_A_Y, 3, old.CELL):
        raise SystemExit("v210 upload rectangle is not canonical destination A")

    if old.word(exe, old.LATE_HOOK) != old.jal(frame):
        raise SystemExit("v210 late hook does not call the canonical frame")
    if old.word(exe, LIVE_DISPATCH_HOOK) != old.j(LIVE_DISPATCH):
        raise SystemExit("live control dispatcher hook differs")
    live_dispatch_before = bytes(exe[old.file_at(LIVE_DISPATCH):old.file_at(LIVE_DISPATCH) + LIVE_DISPATCH_N])

    entry_at = old.file_at(SELECTOR_ENTRY)
    check_at = old.file_at(SELECTOR_CHECK)
    finish_at = old.file_at(SELECTOR_FINISH)
    if any(exe[entry_at:entry_at + ENTRY_CAP]) or any(stock_exe[entry_at:entry_at + ENTRY_CAP]):
        raise SystemExit("selector entry cave is not zero in both stock and v210")
    if any(exe[check_at:check_at + CHECK_CAP]):
        raise SystemExit("v176 dispatcher tail is no longer zero")
    before_refs = {
        "entry": direct_refs(exe, SELECTOR_ENTRY, SELECTOR_ENTRY + ENTRY_CAP),
        "check": direct_refs(exe, SELECTOR_CHECK, SELECTOR_CHECK + CHECK_CAP),
        "finish": direct_refs(exe, SELECTOR_FINISH, SELECTOR_FINISH + FINISH_CAP),
    }
    if any(before_refs.values()):
        raise SystemExit(f"selector cave has a pre-existing direct reference: {before_refs}")

    entry_blob, check_blob, finish_blob = selector_blobs(frame, rect)
    exe[entry_at:entry_at + len(entry_blob)] = entry_blob
    exe[check_at:check_at + len(check_blob)] = check_blob
    exe[finish_at:finish_at + len(finish_blob)] = finish_blob
    exe[frame_at:frame_at + len(frame_blob)] = frame_blob
    old.put_word(exe, old.LATE_HOOK, old.jal(SELECTOR_ENTRY))

    if bytes(exe[old.file_at(LIVE_DISPATCH):old.file_at(LIVE_DISPATCH) + LIVE_DISPATCH_N]) != live_dispatch_before:
        raise SystemExit("live multi-control dispatcher changed")
    if old.word(exe, LIVE_DISPATCH_HOOK) != old.j(LIVE_DISPATCH):
        raise SystemExit("live dispatcher hook changed")

    members[PSX] = bytes(exe)
    changed = [name for name in members if members[name] != before[name]]
    if changed != [PSX]:
        raise SystemExit(f"unexpected changed archive members: {changed}")
    if any(len(members[name]) != len(before[name]) for name in members):
        raise SystemExit("archive member length changed")

    allowed = set(range(frame_at, frame_at + len(frame_blob)))
    allowed.update(range(entry_at, entry_at + ENTRY_CAP))
    allowed.update(range(check_at, check_at + CHECK_CAP))
    allowed.update(range(finish_at, finish_at + FINISH_CAP))
    allowed.update(range(old.file_at(old.LATE_HOOK), old.file_at(old.LATE_HOOK) + 4))
    diffs = [i for i, (a, b) in enumerate(zip(before[PSX], members[PSX])) if a != b]
    if not diffs or any(i not in allowed for i in diffs):
        raise SystemExit(f"PSX.EXE changed outside guarded ranges: {diffs[:20]}")

    refs_after = {
        "entry": direct_refs(exe, SELECTOR_ENTRY, SELECTOR_ENTRY + ENTRY_CAP),
        "check": direct_refs(exe, SELECTOR_CHECK, SELECTOR_CHECK + CHECK_CAP),
        "finish": direct_refs(exe, SELECTOR_FINISH, SELECTOR_FINISH + FINISH_CAP),
    }
    expected_refs = {
        "entry": [(old.LATE_HOOK, "jal", SELECTOR_ENTRY)],
        "check": [(SELECTOR_ENTRY + 23 * 4, "j", SELECTOR_CHECK)],
        "finish": [(SELECTOR_CHECK + 24 * 4, "j", SELECTOR_FINISH)],
    }
    if refs_after != expected_refs:
        raise SystemExit(f"selector direct-reference graph differs: {refs_after}")

    ranges = (
        (SELECTOR_ENTRY, SELECTOR_ENTRY + ENTRY_CAP),
        (SELECTOR_CHECK, SELECTOR_CHECK + CHECK_CAP),
        (SELECTOR_FINISH, SELECTOR_FINISH + FINISH_CAP),
    )
    routine_notes = old.validate_routine("frame", frame, frame_blob)
    for address, blob in (
        (SELECTOR_ENTRY, entry_blob), (SELECTOR_CHECK, check_blob),
        (SELECTOR_FINISH, finish_blob),
    ):
        routine_notes.extend(validate_selector(address, blob, ranges, frame))

    md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN)
    disassembly: list[str] = []
    for name, address, blob in (
        ("selector_entry", SELECTOR_ENTRY, entry_blob),
        ("selector_check", SELECTOR_CHECK, check_blob),
        ("selector_finish", SELECTOR_FINISH, finish_blob),
        ("frame", frame, frame_blob),
    ):
        decoded = list(md.disasm(blob, address))
        if sum(item.size for item in decoded) != len(blob):
            raise SystemExit(f"Capstone did not consume all of {name}")
        disassembly.append(f"--- {name} 0x{address:08X} ({len(blob)} bytes) ---")
        disassembly.extend(
            f"{item.address:08X}  {item.mnemonic:<8} {item.op_str}" for item in decoded
        )

    tpage = {"cmd": 0xE1, "tpage": TPAGE_4BPP_X15_Y1}
    dynamic_a = {"cmd": 0x64, "u": 4, "v": 224, "w": 12, "h": 12,
                 "clut": v171.v166.FONT_CLUT_MIN}
    dynamic_b = dict(dynamic_a, v=128)
    conflict_a = {"cmd": 0x64, "u": 4, "v": 224, "w": 12, "h": 12, "clut": 0x0010}
    conflict_b_only = {"cmd": 0x64, "u": 4, "v": 128, "w": 12, "h": 12, "clut": 0x0010}
    if selector_model([tpage, dynamic_a]) != (CACHE_A_V, [CACHE_A_V]):
        raise SystemExit("selector model failed canonical A")
    if selector_model([tpage, dynamic_b]) != (CACHE_A_V, [CACHE_A_V]):
        raise SystemExit("selector model failed persistent-B canonicalisation")
    if selector_model([tpage, dynamic_b, conflict_a]) != (CACHE_B_V, [CACHE_A_V, CACHE_A_V]):
        raise SystemExit("selector model failed A-conflict switch")
    if selector_model([tpage, conflict_b_only, dynamic_a]) != (CACHE_A_V, [CACHE_B_V, CACHE_A_V]):
        raise SystemExit("selector model failed B-only retention of A")

    ANALYSIS.mkdir(parents=True, exist_ok=True)
    DISASSEMBLY.write_text("\n".join(disassembly) + "\n", encoding="utf-8")
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    temporary = OUT_DIR / f"{OUT_STEM}_building.zip"
    if temporary.exists():
        raise SystemExit(f"refusing to overwrite temporary output: {temporary}")
    with ZipFile(temporary, "w", ZIP_DEFLATED) as archive:
        for info in infos:
            archive.writestr(clone(info), members[info.filename])
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
        "v212 TEST ONLY - per-frame A/B dynamic-cache destination selector",
        f"base={BASE.name}",
        f"base_sha256={BASE_SHA256}",
        f"output={output.name}",
        f"sha256={stamp}",
        "release_status=DIAGNOSTIC; DO NOT DISTRIBUTE",
        "canonical_virtual_row=40 unchanged",
        f"destination_A=x961..981,y{CACHE_A_Y}..{CACHE_A_Y + 11},V={CACHE_A_V}",
        f"destination_B=x961..981,y{CACHE_B_Y}..{CACHE_B_Y + 11},V={CACHE_B_V}",
        "selection=A unless a non-font variable SPRT on 4bpp tpage31 overlaps A",
        "persistent_B_packets=canonicalised_to_V224_before_frame_scan",
        "measured_pre_v211_states=432",
        "measured_A_conflicts=3",
        "measured_B_conflicts=7",
        "measured_simultaneous_A_B_conflicts=0",
        "scope_limit=selector guards measured SPRT conflicts; whole-game runtime remains pending",
        "COMM.IMG=byte-identical to v210 PASS",
        "all_DAT_members=byte-identical to v210 PASS",
        f"changed_members={','.join(changed)}",
        f"PSX_changed_bytes={len(diffs)}",
        "resident_growth=0",
        "resident_used=5356/5356",
        "resident_free=0",
        "heap_boundary=0x801FF8B0 unchanged",
        "startup_copy=5356 unchanged",
        f"selector entry 0x{SELECTOR_ENTRY:08X} / {len(entry_blob)} bytes",
        f"selector check 0x{SELECTOR_CHECK:08X} / {len(check_blob)} bytes",
        f"selector finish 0x{SELECTOR_FINISH:08X} / {len(finish_blob)} bytes",
        f"decoder 0x{decoder:08X} / {len(decoder_blob)} bytes",
        f"frame routine 0x{frame:08X} / {len(frame_blob)} bytes",
        f"huffman 0x{huffman:08X} / {len(huffman_blob)} bytes",
        "live_dispatch_0x8019D074=byte-identical PASS",
        "live_dispatch_hook=unchanged PASS",
        "selector_reference_graph=PASS",
        "selector_model_A=PASS",
        "selector_model_persistent_B=PASS",
        "selector_model_A_conflict=PASS",
        "selector_model_B_only=PASS",
        *routine_notes,
        "archive_member_order=PASS",
        "archive_member_lengths=PASS",
        "archive_roundtrip=PASS",
        "capstone_disassembly=PASS",
        "emulator_run=NO",
        "runtime=PENDING user cold boot",
        "rollback=v210; v211 is a failed fixed-B probe",
    ]
    REPORT.write_text("\n".join(report) + "\n", encoding="utf-8")
    print("\n".join(report))
    print(REPORT)


if __name__ == "__main__":
    main()
