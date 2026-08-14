"""Build v213 TEST ONLY: strict per-frame A/B dynamic-cache selector.

This is rebuilt directly from v210.  A packet is canonicalised as a dynamic
cache glyph only when all of these are true: DMA word count 4, variable SPRT,
physical 4bpp page x15/y1 (ABR ignored), font CLUT, 12x12 dimensions, cache U
sequence, and V equal to A or B.  Other SPRTs are tested as game readers.

Destination B is selected only when A is occupied and B is free.  The measured
432-state corpus has no simultaneous A/B conflict; an unmeasured simultaneous
case falls back to A rather than pretending B is safe.
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
import build_arc1_v212_ab_cache_selector as v212  # noqa: E402


BASE = ROOT / "03_output/arc1_v210_sd031_slots_controls.zip"
BASE_SHA256 = "7FB963135C753CBF509F9E722BF826856B04D456D29743A0B1D8CB5A9B34CAF9"
OUT_DIR = ROOT / "03_output"
OUT_STEM = "arc1_v213_strict_ab_cache_selector_TEST_ONLY"
ANALYSIS = ROOT / "01_work/analysis" / OUT_STEM
REPORT = ANALYSIS / "build_report.txt"
DISASSEMBLY = ANALYSIS / "mips_disassembly.txt"

PSX = "PSX.EXE"
old = v171.old
R2F = 0x8011A800

OVERLAP, OVERLAP_N = 0x80193A2C, 96
ENTRY, ENTRY_N = 0x80193B44, 128
CLASSIFY, CLASSIFY_N = 0x8019D0D0, 104
FINISH, FINISH_N = 0x801A2060, 36
LIVE_DISPATCH, LIVE_DISPATCH_N = 0x8019D074, 92
LIVE_DISPATCH_HOOK = 0x8016B5D8

CACHE_A_Y, CACHE_A_V = 480, 224
CACHE_B_Y, CACHE_B_V = 384, 128
CACHE_U0 = v171.CACHE_U
CACHE_U1 = CACHE_U0 + v171.CACHE_CELLS * old.CELL
PHYSICAL_TPAGE_MASK = 0x019F
PHYSICAL_TPAGE_X15_Y1_4BPP = 0x001F

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
NOP = v171.NOP


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


def selector_blobs(frame: int, rect: int) -> tuple[bytes, bytes, bytes, bytes]:
    next_packet = OVERLAP + 17 * 4
    game = OVERLAP
    loop = ENTRY + 5 * 4
    dynamic = CLASSIFY + 19 * 4
    canonical = CLASSIFY + 23 * 4

    entry = [
        old.move(A3, ZERO),
        old.i_type(0x23, A0, T0, 0),
        old.move(A2, ZERO),
        old.r_type(ZERO, T0, T0, 8, 0x00),
        old.r_type(ZERO, T0, T0, 8, 0x02),
        old.i_type(0x0B, T0, T2, 1),
        old.r_type(ZERO, T0, T1, 21, 0x02),
        old.r_type(T2, T1, T2, 0, 0x25),
        branch(0x05, T2, ZERO, ENTRY + 8 * 4, FINISH),
        old.i_type(0x0F, ZERO, T2, 0x8000),
        old.r_type(T2, T0, T2, 0, 0x25),
        old.i_type(0x23, T2, T3, 0),
        old.i_type(0x24, T2, T5, 7),
        old.i_type(0x25, T2, T4, 4),
        old.i_type(0x09, T5, T6, -0xE1),
        branch(0x05, T6, ZERO, ENTRY + 15 * 4, ENTRY + 21 * 4),
        old.i_type(0x0C, T4, T6, PHYSICAL_TPAGE_MASK),
        old.i_type(0x09, T6, T6, -PHYSICAL_TPAGE_X15_Y1_4BPP),
        old.i_type(0x0B, T6, A2, 1),
        branch(0x04, ZERO, ZERO, ENTRY + 19 * 4, next_packet),
        NOP,
        branch(0x04, A2, ZERO, ENTRY + 21 * 4, next_packet),
        old.i_type(0x0C, T5, T6, 0xFC),
        old.i_type(0x09, T6, T6, -0x64),
        branch(0x05, T6, ZERO, ENTRY + 24 * 4, next_packet),
        old.r_type(ZERO, T3, T1, 24, 0x02),
        old.i_type(0x09, T1, T1, -4),
        branch(0x05, T1, ZERO, ENTRY + 27 * 4, next_packet),
        old.i_type(0x25, T2, T6, 14),
        old.i_type(0x24, T2, T7, 12),
        old.j(CLASSIFY),
        old.i_type(0x24, T2, T9, 13),
    ]
    if len(entry) * 4 != ENTRY_N:
        raise SystemExit("strict selector entry size differs")

    classify = [
        old.i_type(0x24, T2, V1, 16),
        old.i_type(0x24, T2, K0, 17),
        old.i_type(0x09, T6, V0, -v171.v166.FONT_CLUT_MIN),
        old.i_type(0x0B, V0, V0, 16),
        branch(0x04, V0, ZERO, CLASSIFY + 4 * 4, game),
        old.i_type(0x09, V1, V0, -old.CELL),
        branch(0x05, V0, ZERO, CLASSIFY + 6 * 4, game),
        old.i_type(0x09, K0, V0, -old.CELL),
        branch(0x05, V0, ZERO, CLASSIFY + 8 * 4, game),
        old.i_type(0x09, T7, V0, -CACHE_U0),
        old.i_type(0x0B, V0, V1, CACHE_U1 - CACHE_U0),
        branch(0x04, V1, ZERO, CLASSIFY + 11 * 4, game),
        old.move(K1, V0),
        branch(0x04, K1, ZERO, CLASSIFY + 13 * 4, dynamic),
        old.i_type(0x09, K1, K1, -old.CELL),
        branch(0x01, K1, 1, CLASSIFY + 13 * 4),
        NOP,
        branch(0x04, ZERO, ZERO, CLASSIFY + 17 * 4, game),
        NOP,
        old.i_type(0x09, T9, V0, -CACHE_B_V),
        branch(0x04, V0, ZERO, CLASSIFY + 20 * 4, canonical),
        old.i_type(0x09, T9, V0, -CACHE_A_V),
        branch(0x05, V0, ZERO, CLASSIFY + 22 * 4, game),
        old.i_type(0x0D, ZERO, V0, CACHE_A_V),
        branch(0x04, ZERO, ZERO, CLASSIFY + 24 * 4, next_packet),
        old.i_type(0x28, T2, V0, 13),
    ]
    if len(classify) * 4 != CLASSIFY_N:
        raise SystemExit("strict selector classifier size differs")

    overlap = [
        old.i_type(0x0B, T7, V0, CACHE_U1),
        branch(0x04, V0, ZERO, OVERLAP + 1 * 4, next_packet),
        old.r_type(T7, V1, V1, 0, 0x21),
        old.i_type(0x0B, V1, V1, CACHE_U0 + 1),
        branch(0x05, V1, ZERO, OVERLAP + 4 * 4, next_packet),
        old.r_type(T9, K0, K1, 0, 0x21),
        old.i_type(0x0B, T9, V0, CACHE_A_V + old.CELL),
        branch(0x04, V0, ZERO, OVERLAP + 7 * 4, OVERLAP + 11 * 4),
        old.i_type(0x0B, K1, V1, CACHE_A_V + 1),
        old.i_type(0x0E, V1, V1, 1),
        old.r_type(A3, V1, A3, 0, 0x25),
        old.i_type(0x0B, T9, V0, CACHE_B_V + old.CELL),
        branch(0x04, V0, ZERO, OVERLAP + 12 * 4, next_packet),
        old.i_type(0x0B, K1, V1, CACHE_B_V + 1),
        old.i_type(0x0E, V1, V1, 1),
        old.r_type(ZERO, V1, V1, 1, 0x00),
        old.r_type(A3, V1, A3, 0, 0x25),
        old.r_type(ZERO, T3, T0, 8, 0x00),
        old.r_type(ZERO, T0, T0, 8, 0x02),
        branch(0x04, ZERO, ZERO, OVERLAP + 19 * 4, loop),
        NOP,
        NOP,
        NOP,
        NOP,
    ]
    if len(overlap) * 4 != OVERLAP_N:
        raise SystemExit("strict selector overlap size differs")

    rect_store_offset = ((rect + 2) - 0x80200000) & 0xFFFF
    finish = [
        old.i_type(0x0D, ZERO, A1, CACHE_B_V),
        old.i_type(0x09, A3, V0, -1),
        branch(0x04, V0, ZERO, FINISH + 2 * 4, FINISH + 5 * 4),
        NOP,
        old.i_type(0x0D, A1, A1, CACHE_A_V - CACHE_B_V),
        old.i_type(0x09, A1, T7, 256),
        old.i_type(0x0F, ZERO, T8, 0x8020),
        old.j(frame),
        old.i_type(0x29, T8, T7, rect_store_offset),
    ]
    if len(finish) * 4 != FINISH_N:
        raise SystemExit("strict selector finish size differs")
    return (
        struct.pack(f"<{len(overlap)}I", *overlap),
        struct.pack(f"<{len(entry)}I", *entry),
        struct.pack(f"<{len(classify)}I", *classify),
        struct.pack(f"<{len(finish)}I", *finish),
    )


def selector_model(packets: list[dict[str, int]]) -> tuple[int, list[int], int]:
    current_page = False
    flags = 0
    packet_vs: list[int] = []
    for packet in packets:
        cmd = packet["cmd"]
        if cmd == 0xE1:
            current_page = (packet["tpage"] & PHYSICAL_TPAGE_MASK) == PHYSICAL_TPAGE_X15_Y1_4BPP
            continue
        v = packet.get("v", 0)
        if not current_page or cmd & 0xFC != 0x64 or packet.get("count", 4) != 4:
            packet_vs.append(v)
            continue
        u = packet["u"]
        font = (
            v171.v166.FONT_CLUT_MIN <= packet["clut"] < v171.v166.FONT_CLUT_MIN + 16
            and packet["w"] == old.CELL and packet["h"] == old.CELL
            and CACHE_U0 <= u < CACHE_U1 and (u - CACHE_U0) % old.CELL == 0
            and v in (CACHE_A_V, CACHE_B_V)
        )
        if font:
            packet_vs.append(CACHE_A_V)
            continue
        if u < CACHE_U1 and u + packet["w"] > CACHE_U0:
            bottom = v + packet["h"]
            if v < CACHE_A_V + old.CELL and bottom > CACHE_A_V:
                flags |= 1
            if v < CACHE_B_V + old.CELL and bottom > CACHE_B_V:
                flags |= 2
        packet_vs.append(v)
    return (CACHE_B_V if flags == 1 else CACHE_A_V), packet_vs, flags


def validate_fragment(address: int, blob: bytes,
                      ranges: tuple[tuple[int, int], ...], frame: int) -> list[str]:
    for index, word in enumerate(struct.unpack(f"<{len(blob) // 4}I", blob)):
        pc = address + index * 4
        op = word >> 26
        if op in (0x01, 0x04, 0x05, 0x06, 0x07):
            simm = ((word & 0xFFFF) ^ 0x8000) - 0x8000
            target = pc + 4 + simm * 4
            if not any(lo <= target < hi for lo, hi in ranges):
                raise SystemExit(f"selector branch leaves guarded fragments: 0x{pc:08X}->0x{target:08X}")
        elif op == 0x02:
            target = ((pc + 4) & 0xF0000000) | ((word & 0x03FFFFFF) << 2)
            allowed = {OVERLAP + 17 * 4, CLASSIFY, frame}
            if target not in allowed:
                raise SystemExit(f"selector jump target differs: 0x{pc:08X}->0x{target:08X}")
    return [f"selector_0x{address:08X}_branches=PASS"]


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

    layout, _blobs, code_base = v190.resident_layout()
    decoder = code_base
    decoder_blob = v190.build_decoder(decoder, layout)
    huffman = (decoder + len(decoder_blob) + 3) & ~3
    huffman_blob = v190.build_huffman(huffman, layout)
    frame = (huffman + len(huffman_blob) + 3) & ~3
    baseline_frame = v190.build_frame(frame, huffman, layout)
    frame_blob = v212.build_frame(frame, huffman, layout)
    if (decoder, len(decoder_blob), huffman, len(huffman_blob), frame, len(frame_blob)) != (
        0x801FF348, 568, 0x801FF580, 232, 0x801FF668, 584,
    ):
        raise SystemExit("resident layout differs from v210")

    source_at = old.file_at(v171.SOURCE_BASE)
    frame_at = source_at + frame - v171.RESIDENT_BASE
    rect = layout["upload_rect"][0]
    rect_at = source_at + rect - v171.RESIDENT_BASE
    if bytes(exe[frame_at:frame_at + len(baseline_frame)]) != baseline_frame:
        raise SystemExit("v210 resident frame differs from reconstructed baseline")
    if struct.unpack_from("<4H", exe, rect_at) != (v171.CACHE_X, CACHE_A_Y, 3, old.CELL):
        raise SystemExit("v210 upload rectangle is not destination A")
    if old.word(exe, old.LATE_HOOK) != old.jal(frame):
        raise SystemExit("v210 late hook differs")
    if old.word(exe, LIVE_DISPATCH_HOOK) != old.j(LIVE_DISPATCH):
        raise SystemExit("live dispatcher hook differs")
    live_dispatch = bytes(exe[old.file_at(LIVE_DISPATCH):old.file_at(LIVE_DISPATCH) + LIVE_DISPATCH_N])

    caves = ((OVERLAP, OVERLAP_N), (ENTRY, ENTRY_N), (CLASSIFY, CLASSIFY_N))
    for address, size in caves[:2]:
        at = old.file_at(address)
        if any(exe[at:at + size]) or any(stock_exe[at:at + size]):
            raise SystemExit(f"stock-zero selector cave differs at 0x{address:08X}")
    classify_at = old.file_at(CLASSIFY)
    if any(exe[classify_at:classify_at + CLASSIFY_N]):
        raise SystemExit("v176 dispatcher tail is no longer zero")
    for address, size in (*caves, (FINISH, FINISH_N)):
        if direct_refs(exe, address, address + size):
            raise SystemExit(f"selector cave has a pre-existing direct reference at 0x{address:08X}")

    overlap_blob, entry_blob, classify_blob, finish_blob = selector_blobs(frame, rect)
    for address, blob in (
        (OVERLAP, overlap_blob), (ENTRY, entry_blob),
        (CLASSIFY, classify_blob), (FINISH, finish_blob),
    ):
        at = old.file_at(address)
        exe[at:at + len(blob)] = blob
    exe[frame_at:frame_at + len(frame_blob)] = frame_blob
    old.put_word(exe, old.LATE_HOOK, old.jal(ENTRY))

    if bytes(exe[old.file_at(LIVE_DISPATCH):old.file_at(LIVE_DISPATCH) + LIVE_DISPATCH_N]) != live_dispatch:
        raise SystemExit("live dispatcher changed")
    if old.word(exe, LIVE_DISPATCH_HOOK) != old.j(LIVE_DISPATCH):
        raise SystemExit("live dispatcher hook changed")

    members[PSX] = bytes(exe)
    changed = [name for name in members if members[name] != before[name]]
    if changed != [PSX]:
        raise SystemExit(f"unexpected changed members: {changed}")
    if any(len(members[name]) != len(before[name]) for name in members):
        raise SystemExit("archive member length changed")

    allowed = set(range(frame_at, frame_at + len(frame_blob)))
    for address, blob in ((OVERLAP, overlap_blob), (ENTRY, entry_blob),
                          (CLASSIFY, classify_blob), (FINISH, finish_blob)):
        at = old.file_at(address)
        allowed.update(range(at, at + len(blob)))
    allowed.update(range(old.file_at(old.LATE_HOOK), old.file_at(old.LATE_HOOK) + 4))
    diffs = [i for i, (a, b) in enumerate(zip(before[PSX], members[PSX])) if a != b]
    if not diffs or any(i not in allowed for i in diffs):
        raise SystemExit(f"PSX.EXE changed outside guarded ranges: {diffs[:20]}")

    ranges = tuple((address, address + len(blob)) for address, blob in (
        (OVERLAP, overlap_blob), (ENTRY, entry_blob),
        (CLASSIFY, classify_blob), (FINISH, finish_blob),
    ))
    notes: list[str] = []
    for address, blob in ((OVERLAP, overlap_blob), (ENTRY, entry_blob),
                          (CLASSIFY, classify_blob), (FINISH, finish_blob)):
        notes.extend(validate_fragment(address, blob, ranges, frame))
    notes.extend(old.validate_routine("frame", frame, frame_blob))

    md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN)
    disassembly: list[str] = []
    for name, address, blob in (
        ("selector_overlap", OVERLAP, overlap_blob),
        ("selector_entry", ENTRY, entry_blob),
        ("selector_classify", CLASSIFY, classify_blob),
        ("selector_finish", FINISH, finish_blob),
        ("frame", frame, frame_blob),
    ):
        decoded = list(md.disasm(blob, address))
        if sum(i.size for i in decoded) != len(blob):
            raise SystemExit(f"Capstone did not consume all of {name}")
        disassembly.append(f"--- {name} 0x{address:08X} ({len(blob)} bytes) ---")
        disassembly.extend(f"{i.address:08X}  {i.mnemonic:<8} {i.op_str}" for i in decoded)

    tpage31 = {"cmd": 0xE1, "tpage": 31}
    tpage63 = {"cmd": 0xE1, "tpage": 63}  # same physical page, ABR differs
    font_a = {"cmd": 0x64, "count": 4, "u": 4, "v": 224, "w": 12, "h": 12,
              "clut": v171.v166.FONT_CLUT_MIN}
    font_b = dict(font_a, v=128)
    game_a = {"cmd": 0x64, "count": 4, "u": 0, "v": 160, "w": 128, "h": 96,
              "clut": 0x79C0}
    game_b = {"cmd": 0x64, "count": 4, "u": 4, "v": 128, "w": 12, "h": 12,
              "clut": 0x0010}
    if selector_model([tpage31, font_a]) != (224, [224], 0):
        raise SystemExit("strict model canonical A failed")
    if selector_model([tpage63, font_b]) != (224, [224], 0):
        raise SystemExit("strict model ABR/persistent B failed")
    if selector_model([tpage31, font_b, game_a]) != (128, [224, 160], 1):
        raise SystemExit("strict model A conflict failed")
    if selector_model([tpage31, game_b, font_a]) != (224, [128, 224], 2):
        raise SystemExit("strict model B-only conflict failed")
    both = dict(game_a, v=120, h=128)
    if selector_model([tpage31, both, font_a]) != (224, [120, 224], 3):
        raise SystemExit("strict model simultaneous fallback failed")

    ANALYSIS.mkdir(parents=True, exist_ok=True)
    DISASSEMBLY.write_text("\n".join(disassembly) + "\n", encoding="utf-8")
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
        "v213 TEST ONLY - strict per-frame A/B dynamic-cache selector",
        f"base={BASE.name}",
        f"base_sha256={BASE_SHA256}",
        f"output={output.name}",
        f"sha256={stamp}",
        "release_status=DIAGNOSTIC; DO NOT DISTRIBUTE",
        "canonical_virtual_row=40 unchanged",
        "destination_A=x961..981,y480..491,V224",
        "destination_B=x961..981,y384..395,V128",
        "dynamic_identity=DMA4+SPRT+physical_tpage+font_CLUT+12x12+cache_U+V(A/B)",
        "tpage_ABR_bits=ignored for physical-page identity",
        "selection=B only for conflict_flags==A_only",
        "simultaneous_A_B_conflict=fallback_A (unseen in 432 measured states)",
        "measured_pre_v211_states=432",
        "measured_A_conflicts=3",
        "measured_B_conflicts=7",
        "measured_simultaneous_A_B_conflicts=0",
        "COMM.IMG=byte-identical to v210 PASS",
        "all_DAT_members=byte-identical to v210 PASS",
        f"changed_members={','.join(changed)}",
        f"PSX_changed_bytes={len(diffs)}",
        "resident_growth=0",
        "resident_used=5356/5356",
        "resident_free=0",
        "heap_boundary=0x801FF8B0 unchanged",
        "startup_copy=5356 unchanged",
        f"selector overlap 0x{OVERLAP:08X} / {len(overlap_blob)} bytes",
        f"selector entry 0x{ENTRY:08X} / {len(entry_blob)} bytes",
        f"selector classify 0x{CLASSIFY:08X} / {len(classify_blob)} bytes",
        f"selector finish 0x{FINISH:08X} / {len(finish_blob)} bytes",
        f"decoder 0x{decoder:08X} / {len(decoder_blob)} bytes",
        f"frame routine 0x{frame:08X} / {len(frame_blob)} bytes",
        f"huffman 0x{huffman:08X} / {len(huffman_blob)} bytes",
        "live_dispatch=byte-identical PASS",
        "strict_model_A=PASS",
        "strict_model_ABR_B=PASS",
        "strict_model_A_conflict=PASS",
        "strict_model_B_conflict=PASS",
        "strict_model_simultaneous=PASS",
        *notes,
        "archive_member_order=PASS",
        "archive_member_lengths=PASS",
        "archive_roundtrip=PASS",
        "capstone_disassembly=PASS",
        "emulator_run=NO",
        "runtime=PENDING user cold boot",
        "rollback=v210; v211 and v212-series are failed/nonpackaged probes",
    ]
    REPORT.write_text("\n".join(report) + "\n", encoding="utf-8")
    print("\n".join(report))
    print(REPORT)


if __name__ == "__main__":
    main()
