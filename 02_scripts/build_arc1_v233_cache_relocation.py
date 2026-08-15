#!/usr/bin/env python3
"""Build v233: move the dynamic cache from (961,480) to (999,420).

Complete specification: 05_docs/v233_cache_relocation_design.md.
Read that document first; this builder implements it 1:1.

Design invariants enforced here as guards:
  * logical cache row stays 40 (gatekeeper -40 and index base 40*84 untouched)
  * strip rows 63/53/52 keep their U+4 (dedicated ROW40 split, section 3-2)
  * only PSX.EXE changes, and only at the 8 documented edit sites
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

import build_arc1_v171_ui_asset_recovery as v171  # noqa: E402
import build_arc1_v190_dynamic_owner_repair as v190  # noqa: E402

BASE = ROOT / "03_output/arc1_v232_static_promotion_huffman_source_TEST_ONLY_BC602EF6.zip"
BASE_SHA256 = "14B84F46F425AFCC0F9D9C256B2FE89F86B44DA9218C2E807FE17855B50989B6"
OUT_DIR = ROOT / "03_output"
OUT_STEM = "arc1_v233_cache_relocation_TEST_ONLY"
ANALYSIS = ROOT / "01_work/analysis/arc1_v233_cache_relocation"
ANALYSIS.mkdir(parents=True, exist_ok=True)
PSX = "PSX.EXE"

old = v171.old
R2F = 0x8011A800

OLD_V, NEW_V = 224, 164
OLD_X, NEW_X = 961, 999
OLD_U, NEW_U = 4, 156
DELTA = (NEW_U - OLD_U + OLD_U) + ((NEW_V - OLD_V) << 8)  # +156 | (-60)<<8
assert DELTA == 156 - 15360 == -15204

BLOCK_RAM, BLOCK_WORDS = 0x8019D074, 23
GAME_RETURN = 0x8016B5E0

ZERO, V0, A1, A2, A3, T0 = 0, 2, 5, 6, 7, 8


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def i_type(op: int, rs: int, rt: int, imm: int) -> int:
    return (op << 26) | (rs << 21) | (rt << 16) | (imm & 0xFFFF)


def branch(op: int, rs: int, rt: int, at: int, target: int) -> int:
    return i_type(op, rs, rt, (target - (at + 4)) >> 2)


def jump(target: int) -> int:
    return (2 << 26) | ((target >> 2) & 0x3FFFFFF)


NOP = 0


def old_block() -> list[int]:
    """Section 3-1: the 23 words currently on disk (guard: must match)."""
    a = BLOCK_RAM
    w = []
    for k, row in enumerate((0x28, 0x3F, 0x35, 0x34)):
        at = a + k * 16
        w += [i_type(0x09, T0, A3, -row), i_type(0x0B, A3, A3, 1)]
        if k < 3:
            w += [branch(0x05, A3, ZERO, at + 8, a + 0x40), NOP]
        else:
            w += [branch(0x04, A3, ZERO, at + 8, a + 0x50), NOP]
    w += [i_type(0x24, A1, A3, 0x28), NOP, i_type(0x09, A3, A3, 4),
          i_type(0x28, A1, A3, 0x28)]
    w += [i_type(0x24, A2, V0, 0x0E), jump(GAME_RETURN), NOP]
    return w


def new_block() -> list[int]:
    """Section 3-2: ROW40 split.  22 instructions + 1 spare nop."""
    a = BLOCK_RAM
    common, row40, fin = a + 0x24, a + 0x3C, a + 0x4C
    w = [
        i_type(0x09, T0, A3, -0x28),                    # 74 row-40
        branch(0x04, A3, ZERO, a + 0x04, row40),        # 78 beqz -> ROW40
        i_type(0x09, T0, A3, -0x3F),                    # 7C (delay) row-63
        branch(0x04, A3, ZERO, a + 0x0C, common),       # 80 beqz -> COMMON
        i_type(0x09, T0, A3, -0x35),                    # 84 (delay) row-53
        branch(0x04, A3, ZERO, a + 0x14, common),       # 88 beqz -> COMMON
        i_type(0x09, T0, A3, -0x34),                    # 8C (delay) row-52
        branch(0x05, A3, ZERO, a + 0x1C, fin),          # 90 bnez -> FIN
        NOP,                                            # 94 (delay)
        i_type(0x24, A1, A3, 0x28),                     # 98 COMMON lbu U
        NOP,                                            # 9C load delay
        i_type(0x09, A3, A3, OLD_U),                    # A0 U += 4
        i_type(0x28, A1, A3, 0x28),                     # A4 sb U
        branch(0x04, ZERO, ZERO, a + 0x34, fin),        # A8 b FIN
        NOP,                                            # AC (delay)
        i_type(0x25, A1, A3, 0x28),                     # B0 ROW40 lhu U|V<<8
        NOP,                                            # B4 load delay
        i_type(0x09, A3, A3, DELTA),                    # B8 += 0xC49C
        i_type(0x29, A1, A3, 0x28),                     # BC sh
        i_type(0x24, A2, V0, 0x0E),                     # C0 FIN lbu v0,0xe(a2)
        jump(GAME_RETURN),                              # C4
        NOP,                                            # C8 delay slot
        NOP,                                            # CC spare
    ]
    assert len(w) == BLOCK_WORDS
    assert common == a + 0x24 and row40 == a + 0x3C and fin == a + 0x4C
    return w


def simulate(words: list[int], row: int, u: int, v: int) -> tuple[int, int]:
    """Minimal R3000 model of the block: branch delay implemented."""
    packet = bytearray(0x30)
    packet[0x28], packet[0x29] = u, v
    a2buf = bytearray(0x10)
    a2buf[0x0E] = 0x5A
    reg = {ZERO: 0, T0: row, A1: 0, A2: 0, A3: 0, V0: 0}
    pc, steps, pending = 0, 0, None
    while steps < 200:
        steps += 1
        idx = pc // 4
        if not 0 <= idx < len(words):
            raise SystemExit(f"model: pc left the block at 0x{BLOCK_RAM + pc:X}")
        ins = words[idx]
        nxt = pc + 4
        op = ins >> 26
        rs, rt, imm = (ins >> 21) & 31, (ins >> 16) & 31, ins & 0xFFFF
        simm = imm - 0x10000 if imm & 0x8000 else imm
        if ins == 0:
            pass
        elif op == 0x09:
            reg[rt] = (reg[rs] + simm) & 0xFFFFFFFF
        elif op == 0x0B:
            reg[rt] = 1 if (reg[rs] & 0xFFFFFFFF) < (simm & 0xFFFFFFFF) else 0
        elif op in (0x04, 0x05):
            taken = (reg[rs] == reg[rt]) if op == 0x04 else (reg[rs] != reg[rt])
            if taken:
                pending = pc + 4 + (simm << 2)
        elif op == 0x24:
            buf = packet if rs == A1 else a2buf
            reg[rt] = buf[simm]
        elif op == 0x25:
            buf = packet if rs == A1 else a2buf
            reg[rt] = buf[simm] | (buf[simm + 1] << 8)
        elif op == 0x28:
            (packet if rs == A1 else a2buf)[simm] = reg[rt] & 0xFF
        elif op == 0x29:
            buf = packet if rs == A1 else a2buf
            buf[simm] = reg[rt] & 0xFF
            buf[simm + 1] = (reg[rt] >> 8) & 0xFF
        elif op == 0x02:
            # delay slot then leave
            idx2 = (pc + 4) // 4
            if 0 <= idx2 < len(words) and words[idx2] != 0:
                raise SystemExit("model: jump delay slot is not nop")
            if reg[V0] != 0x5A:
                raise SystemExit("model: finish lbu v0,0xe(a2) was skipped")
            return packet[0x28], packet[0x29]
        else:
            raise SystemExit(f"model: unhandled op {op:#x}")
        reg[ZERO] = 0
        if pending is not None and op not in (0x04, 0x05):
            pc, pending = pending, None
        else:
            pc = nxt
        # branch: execute delay slot next, then land
        if pending is not None and op in (0x04, 0x05):
            continue
    raise SystemExit("model: no exit")


def clone(info: ZipInfo) -> ZipInfo:
    out = ZipInfo(info.filename, info.date_time)
    for attr in ("compress_type", "comment", "extra", "create_system",
                 "create_version", "extract_version", "flag_bits", "volume",
                 "internal_attr", "external_attr"):
        setattr(out, attr, getattr(info, attr))
    return out


def main() -> None:
    if digest(BASE.read_bytes()) != BASE_SHA256:
        raise SystemExit("GUARD: v232 base sha mismatch")
    with ZipFile(BASE) as z:
        infos = z.infolist()
        members = {i.filename: z.read(i.filename) for i in infos}
    exe = bytearray(members[PSX])

    # frozen resident layout (same check as v222)
    layout, _blobs, code_base = v190.resident_layout()
    decoder = code_base
    decoder_size = len(v190.build_decoder(decoder, layout))
    huffman = (decoder + decoder_size + 3) & ~3
    huffman_size = len(v190.build_huffman(huffman, layout))
    frame = (huffman + huffman_size + 3) & ~3
    frame_size = len(v190.build_frame(frame, huffman, layout))
    if (decoder, decoder_size, huffman, huffman_size, frame, frame_size) != (
            0x801FF348, 568, 0x801FF580, 232, 0x801FF668, 584):
        raise SystemExit("GUARD: resident layout differs from frozen v190")

    source_at = old.file_at(v171.SOURCE_BASE)
    span_at, span_n = source_at, v171.COPY_N
    rect_at = source_at + layout["upload_rect"][0] - v171.RESIDENT_BASE
    low_row_at = old.file_at(v171.LOW_HELPER)
    low_len = len(v171.build_low_helper(v171.LOW_HELPER))

    def unique(word: int, label: str, start: int, size: int,
               follow: int | None = None) -> int:
        hits = [o for o in range(start, start + size, 4)
                if struct.unpack_from("<I", exe, o)[0] == word
                and (follow is None
                     or struct.unpack_from("<I", exe, o + 4)[0] == follow)]
        if len(hits) != 1:
            raise SystemExit(f"GUARD: {label} found {len(hits)} times, need 1")
        return hits[0]

    I = i_type
    # --- invariants: gatekeeper row and index base must still be the 40 ones
    unique(I(0x09, T0, A3, -40), "virtual row gatekeeper (must stay -40)",
           low_row_at, low_len)
    unique(I(0x09, 14, 3, 40 * old.IPR), "cache index base (must stay 40*84)",
           span_at, span_n)

    # --- edit sites 2..5 (values change), same discovery as v222
    U_FOLLOW = I(0x0B, 14, 13, v171.CACHE_CELLS * old.CELL)
    edits = []
    for label, word_old, word_new, start, size, follow in (
        ("classifier V", I(0x09, V0, V0, -OLD_V), I(0x09, V0, V0, -NEW_V),
         old.file_at(v171.LOW_CLASSIFIER), 36, None),
        ("frame V", I(0x09, 13, 13, -OLD_V), I(0x09, 13, 13, -NEW_V),
         span_at, span_n, None),
        ("frame U", I(0x09, 14, 14, -OLD_U), I(0x09, 14, 14, -NEW_U),
         source_at + frame - v171.RESIDENT_BASE, frame_size, U_FOLLOW),
        ("cache X", I(0x09, T0, T0, OLD_X), I(0x09, T0, T0, NEW_X),
         span_at, span_n, None),
    ):
        edits.append((label, unique(word_old, label, start, size, follow),
                      word_old, word_new))
    for label, at, want, fresh in edits:
        actual = struct.unpack_from("<I", exe, at)[0]
        if actual != want:
            raise SystemExit(f"GUARD: {label} 0x{actual:08X} != 0x{want:08X}")
        struct.pack_into("<I", exe, at, fresh)

    # --- edit site 6: upload rectangle
    rect_before = struct.unpack_from("<4H", exe, rect_at)
    if rect_before != (OLD_X, 480, 3, old.CELL):
        raise SystemExit(f"GUARD: upload rect differs: {rect_before}")
    struct.pack_into("<2H", exe, rect_at, NEW_X, 420)

    # --- edit site 1: the 23-word bias block
    blk_at = BLOCK_RAM - R2F
    want = old_block()
    have = list(struct.unpack_from(f"<{BLOCK_WORDS}I", exe, blk_at))
    if have != want:
        for k, (a, b) in enumerate(zip(have, want)):
            if a != b:
                raise SystemExit(
                    f"GUARD: block word {k} at 0x{BLOCK_RAM + k * 4:X}: "
                    f"0x{a:08X} != expected 0x{b:08X}")
    fresh = new_block()
    struct.pack_into(f"<{BLOCK_WORDS}I", exe, blk_at, *fresh)

    # --- model verification (design section 6.2)
    cases = [
        (40, 36, 224, (36 + 156) & 0xFF, NEW_V),   # cache row moves
        (40, 72, 224, (72 + 156) & 0xFF, NEW_V),
        (63, 36, 244, 40, 244),                    # strip rows keep U+4
        (53, 24, 124, 28, 124),
        (52, 0, 112, 4, 112),
        (12, 60, 144, 60, 144),                    # ordinary rows untouched
    ]
    for row, u, v, eu, ev in cases:
        gu, gv = simulate(fresh, row, u, v)
        if (gu, gv) != (eu, ev):
            raise SystemExit(f"GUARD: model row {row}: got ({gu},{gv}), "
                             f"want ({eu},{ev})")

    # --- whole-file diff guard
    base_exe = members[PSX]
    allowed = set(range(blk_at, blk_at + BLOCK_WORDS * 4))
    allowed |= set(range(rect_at, rect_at + 4))
    for _, at, _, _ in edits:
        allowed |= set(range(at, at + 4))
    bad = [i for i, (a, b) in enumerate(zip(base_exe, bytes(exe)))
           if a != b and i not in allowed]
    if bad:
        raise SystemExit(f"GUARD: EXE changed outside sites: {[hex(x) for x in bad[:8]]}")
    changed = sum(1 for a, b in zip(base_exe, bytes(exe)) if a != b)

    members[PSX] = bytes(exe)
    payload = b"".join(members[n] for n in sorted(members))
    tag = digest(payload)[:8]
    out = OUT_DIR / f"{OUT_STEM}_{tag}.zip"
    with ZipFile(out, "w", ZIP_DEFLATED) as z:
        for info in infos:
            z.writestr(clone(info), members[info.filename])
    report = [
        f"base={BASE.name}",
        f"cache rect (961,480) -> (999,420); packet U +4 -> +156, V 224 -> 164",
        "row system kept at 40 (gatekeeper/index base verified untouched)",
        f"strip rows 63/53/52 keep U+4 (model verified)",
        f"exe_changed_bytes={changed}",
        f"zip={out.name}",
        f"zip_sha256={digest(out.read_bytes())}",
    ]
    (ANALYSIS / "build_report.txt").write_text("\n".join(report) + "\n",
                                               encoding="utf-8")
    print("\n".join(report))


if __name__ == "__main__":
    main()
