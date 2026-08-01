"""v112: two glyph strips resident at once, which is all the capacity now needs.

The measured requirement came down twice today. Removing the CTRL:00 false positives
fixed the script at 2,878 dialogue rows rather than 5,795, which drops the projection
from 904 distinct syllables to 686; five rounds of rewording took the new-glyph count
from 201 to 114. With 28 free atlas cells that leaves about 86 to hold in VRAM, and two
13-column strips hold 104. Everything is resident, so nothing has to be chosen at
runtime and no cache logic is needed -- this is the existing one-strip upload done
twice.

v106 tried the same thing and rendered blanks. The v108 bisection then showed each
change on its own is fine: the row move, the page and U move, the classifier moving into
a subroutine, and both pairs of those. Only the two-strip split was never isolated, so
it is the remaining suspect, and this build changes one thing about how it was done:

    v106's classifier used t0 and t1. t0 is the register carrying the glyph row.

Whether that is what broke it will be visible immediately -- either the expanded glyphs
render or they do not. t8 and t9 are used here, and neither is read anywhere in the
calling loop between 0x801A21DC and 0x801A229C.

Layout, from the VRAM survey over 139 savestates: page 15,1 at x 961 is the only pair
of 13-column positions sharing an x and a page, and the renderer has one U offset and
one tpage word, so they must share both.

    strip A   y 480   V = 224   row 40   columns 0..12
    strip B   y 500   V = 244   row 63   columns 0..12

Neither V is a value the base rows produce, so the classifier can tell them apart from
ordinary glyphs. Nothing grows: v103 already padded its appended sector, and the code
fits in what is left.
"""
from __future__ import annotations

import hashlib
import struct
from pathlib import Path
from zipfile import ZipFile, ZipInfo

ROOT = Path(__file__).resolve().parents[1]
BASE_ZIP = ROOT / "03_output/ui_hud_e7_v103_heap_reserved_glyphs_patch_only.zip"
BASE_SHA = "9EE40993E72962F26DAFBD61CA565D4646E247D9990B79EF5122776838584FD3"
OUTPUT = ROOT / "03_output/ui_hud_e7_v112_two_strips_resident_patch_only.zip"
REPORT = ROOT / "01_work/analysis/ui_hud_e7_v112_two_strips_resident/build_report.txt"

PSX, IMG = "PSX.EXE", "COMM.IMG"
RAM_TO_FILE, T_ADDR, T_SIZE = 0x8011A800, 0x8011B000, 0x8E000
IMAGE_END = T_ADDR + T_SIZE
LOADIMAGE = 0x80177E4C

# --- the store ---
COLS_OLD, COLS_NEW, PLANES, CELL = 15, 13, 4, 12
IPR = 21 * PLANES
LOOKUP, LOOKUP_N = 0x801A7520, 409
OLD_ROW, ROW_A, ROW_B = 24, 40, 63
STRIP_W = COLS_NEW * 3                       # 39 units
STRIP_BYTES = STRIP_W * 2 * CELL             # 936
NEW_X, TPAGE, U_OFF = 961, 0x1F, 4
Y_A, Y_B = 480, 500

# where the old strip sits inside COMM.IMG
STRIP_ROW, STRIP_X0 = 896, 1280
OLD_X4, OLD_Y = 2856, 288
OLD_W = COLS_OLD * 3

# --- reserved RAM, filled by the one startup memcpy ---
HELPER_SRC, HELPER_DST, HELPER_N = 0x801A86EC, 0x801FE3C4, 276
GA_SRC, GA_DST = HELPER_SRC + HELPER_N, HELPER_DST + HELPER_N
GB_SRC, GB_DST = GA_SRC + STRIP_BYTES, GA_DST + STRIP_BYTES
CODE_SRC, CODE_DST = GB_SRC + STRIP_BYTES, GB_DST + STRIP_BYTES
HEAP_HI, HEAP_SEEN_USED = 0x80200000, 0x801FFA60

MEMCPY_LEN_AT, HEAP_BASE_AT = 0x801757CC, 0x80175810
TPAGE_AT, CLS, STUB_CALL = 0x801A2194, 0x801A2204, 0x801A208C
RECT_A, RECT_B = 0x801A22E4, 0x801A22EC
HELPER_ROW_OFF, HELPER_U_OFF = 0x00, 0x4C

ZERO, V0, V1, A0, A1, A2, A3, T0, S4, S5, T8, T9, SP, RA = \
    0, 2, 3, 4, 5, 6, 7, 8, 20, 21, 24, 25, 29, 31


def addiu(rt, rs, i): return 0x24000000 | (rs << 21) | (rt << 16) | (i & 0xFFFF)
def sltiu(rt, rs, i): return 0x2C000000 | (rs << 21) | (rt << 16) | (i & 0xFFFF)
def ori(rt, rs, i): return 0x34000000 | (rs << 21) | (rt << 16) | (i & 0xFFFF)
def lui(rt, i): return 0x3C000000 | (rt << 16) | (i & 0xFFFF)
def lbu(rt, rs, o): return 0x90000000 | (rs << 21) | (rt << 16) | (o & 0xFFFF)
def sb(rt, rs, o): return 0xA0000000 | (rs << 21) | (rt << 16) | (o & 0xFFFF)
def lw(rt, rs, o): return 0x8C000000 | (rs << 21) | (rt << 16) | (o & 0xFFFF)
def sw(rt, rs, o): return 0xAC000000 | (rs << 21) | (rt << 16) | (o & 0xFFFF)
def beq(rs, rt, o): return 0x10000000 | (rs << 21) | (rt << 16) | (o & 0xFFFF)
def bne(rs, rt, o): return 0x14000000 | (rs << 21) | (rt << 16) | (o & 0xFFFF)
def or_(rd, rs, rt): return (rs << 21) | (rt << 16) | (rd << 11) | 0x25
def addu(rd, rs, rt): return (rs << 21) | (rt << 16) | (rd << 11) | 0x21
def jal(t): return 0x0C000000 | ((t & 0x0FFFFFFF) >> 2)
def j(t): return 0x08000000 | ((t & 0x0FFFFFFF) >> 2)


NOP, JR_RA = 0, 0x03E00008
def hi(a): return (a >> 16) & 0xFFFF
def lo(a): return a & 0xFFFF


def build_helper():
    """Entered by `j` from 0x8016B5D8 with t0 = row, a1 = packet, a2 = object."""
    return [
        (addiu(A3, T0, -ROW_A), f"addiu a3,t0,-{ROW_A}"),
        (sltiu(A3, A3, 1), "sltiu a3,a3,1"),
        (bne(A3, ZERO, 4), "bne   a3,zero,add"),
        (addiu(A3, T0, -ROW_B), f"addiu a3,t0,-{ROW_B}    ; delay slot"),
        (sltiu(A3, A3, 1), "sltiu a3,a3,1"),
        (beq(A3, ZERO, 5), "beq   a3,zero,out"),
        (NOP, "nop"),
        (lbu(A3, A1, 0x28), "add: lbu a3,0x28(a1)"),
        (NOP, "nop"),
        (addiu(A3, A3, U_OFF), f"addiu a3,a3,{U_OFF}"),
        (sb(A3, A1, 0x28), "sb    a3,0x28(a1)"),
        (lbu(V0, A2, 0x0E), "out: lbu v0,0xE(a2)"),
        (j(0x8016B5E0), "j     0x8016B5E0"),
        (NOP, "nop"),
    ]


def build_classify():
    """v0 = 1 when the packet's V belongs to either strip.

    t8 and t9, not t0 and t1: t0 carries the glyph row, and v106 -- the build that
    rendered blanks -- used it here.
    """
    return [
        (lbu(V0, V1, 0x29), "lbu   v0,0x29(v1)     ; V"),
        (NOP, "nop"),
        (addiu(T8, V0, -(Y_A % 256)), f"addiu t8,v0,-{Y_A % 256}"),
        (sltiu(T8, T8, 1), "sltiu t8,t8,1"),
        (addiu(T9, V0, -(Y_B % 256)), f"addiu t9,v0,-{Y_B % 256}"),
        (sltiu(T9, T9, 1), "sltiu t9,t9,1"),
        (or_(V0, T8, T9), "or    v0,t8,t9"),
        (JR_RA, "jr    ra"),
        (NOP, "nop"),
    ]


def build_frame():
    out = [(addiu(SP, SP, -24), "addiu sp,sp,-24"), (sw(RA, SP, 0x14), "sw ra,0x14(sp)")]
    for rect, src, tag in ((RECT_A, GA_DST, "A"), (RECT_B, GB_DST, "B")):
        out += [
            (lui(A0, hi(rect)), f"lui   a0,hi(rect {tag})"),
            (ori(A0, A0, lo(rect)), "ori   a0,a0,lo"),
            (lui(A1, hi(src)), f"lui   a1,hi(strip {tag})"),
            (jal(LOADIMAGE), "jal   LoadImage"),
            (ori(A1, A1, lo(src)), "ori   a1,a1,lo   ; delay slot"),
        ]
    out += [(lw(RA, SP, 0x14), "lw ra,0x14(sp)"), (addiu(SP, SP, 24), "addiu sp,sp,24"),
            (JR_RA, "jr ra"), (NOP, "nop")]
    return out


KEEP = {
    TPAGE_AT: ori(A3, A3, 0x001B),
    CLS + 0x00: lbu(V0, V1, 0x29),
    CLS + 0x04: NOP,
    CLS + 0x08: addiu(V0, V0, -32),
    CLS + 0x0C: sltiu(V0, V0, 1),
    CLS + 0x10: bne(V0, S5, 0x1A),
    CLS + 0x14: addu(A1, V1, S4),
    RECT_A: (OLD_Y << 16) | 714,
    RECT_A + 4: (CELL << 16) | OLD_W,
    STUB_CALL: jal(LOADIMAGE),
    MEMCPY_LEN_AT: addiu(A2, ZERO, HELPER_N + OLD_W * 2 * CELL),
    HELPER_SRC + HELPER_ROW_OFF: addiu(A3, T0, -OLD_ROW),
    HELPER_SRC + HELPER_U_OFF: addiu(A3, A3, 40),
    0x8016B5D8: j(HELPER_DST),
    LOADIMAGE: 0x27BDFFD0,
}


def sha256(b): return hashlib.sha256(b).hexdigest().upper()
def word(buf, ram): return struct.unpack_from("<I", buf, ram - RAM_TO_FILE)[0]
def put(buf, ram, v): struct.pack_into("<I", buf, ram - RAM_TO_FILE, v)


def clone(i: ZipInfo) -> ZipInfo:
    t = ZipInfo(i.filename, i.date_time)
    for a in ("compress_type", "comment", "extra", "create_system", "create_version",
              "extract_version", "flag_bits", "volume", "internal_attr",
              "external_attr"):
        setattr(t, a, getattr(i, a))
    return t


def main() -> None:
    if sha256(BASE_ZIP.read_bytes()) != BASE_SHA:
        raise SystemExit("base archive is not the verified v103 build")
    with ZipFile(BASE_ZIP) as a:
        infos = a.infolist()
        members = {i.filename: a.read(i.filename) for i in infos}
    exe, comm = bytearray(members[PSX]), members[IMG]

    pc0, gp0, t_addr, t_size = struct.unpack_from("<4I", exe, 0x10)
    if (t_addr, t_size) != (T_ADDR, T_SIZE):
        raise SystemExit(f"unexpected t_size 0x{t_size:X}")
    for ram, val in KEEP.items():
        if word(exe, ram) != val:
            raise SystemExit(f"guard failed at 0x{ram:08X}: 0x{word(exe, ram):08X} "
                             f"!= 0x{val:08X}")

    # geometry must be self-consistent before anything is written
    if (U_OFF + COLS_NEW * CELL) > 256:
        raise SystemExit("a strip leaves its texture page")
    if Y_A + CELL > Y_B or Y_B + CELL > 512:
        raise SystemExit("strips overlap or leave VRAM")
    if (NEW_X % 64) * 4 != U_OFF or NEW_X // 64 != (TPAGE & 0xF):
        raise SystemExit("x, U offset and tpage disagree")
    base_v = {(12 * r) & 0xFF for r in range(OLD_ROW)}
    for r, y in ((ROW_A, Y_A), (ROW_B, Y_B)):
        v = (12 * r) & 0xFF
        if v != y % 256 or ((TPAGE >> 4) & 1) * 256 + v != y:
            raise SystemExit(f"row {r} gives V={v}, which is not y {y}")
        if (y % 256) in base_v:
            raise SystemExit(f"V={y % 256} collides with a base row")

    helper, classify, frame = build_helper(), build_classify(), build_frame()
    code_n = (len(classify) + len(frame)) * 4
    if CODE_SRC + code_n > IMAGE_END:
        raise SystemExit(f"code needs {code_n} bytes, image ends at 0x{IMAGE_END:08X}")
    if any(exe[CODE_SRC - RAM_TO_FILE: CODE_SRC - RAM_TO_FILE + code_n]):
        raise SystemExit("the landing area for the code is not padding")
    copy_n = (CODE_DST + code_n) - HELPER_DST
    heap = CODE_DST + code_n
    if heap >= HEAP_SEEN_USED:
        raise SystemExit("the reservation reaches heap the game uses")

    # --- repack the pixels: columns 0..12 to strip A, 13..14 to strip B ---
    off = (OLD_X4 - STRIP_X0) // 2
    old = [comm[y * STRIP_ROW + off: y * STRIP_ROW + off + OLD_W * 2]
           for y in range(OLD_Y, OLD_Y + CELL)]
    if any(len(r) != OLD_W * 2 for r in old) or not any(b for r in old for b in r):
        raise SystemExit("could not read the current strip out of COMM.IMG")
    cut = COLS_NEW * (CELL // 2)
    strip_a = b"".join(r[:cut].ljust(STRIP_W * 2, b"\x00") for r in old)
    strip_b = b"".join(r[cut:].ljust(STRIP_W * 2, b"\x00") for r in old)
    for name, s in (("A", strip_a), ("B", strip_b)):
        if len(s) != STRIP_BYTES:
            raise SystemExit(f"strip {name} is {len(s)} bytes")
        if not any(s):
            raise SystemExit(f"strip {name} came out blank")

    # --- remap the lookup table ---
    lo_off = LOOKUP - RAM_TO_FILE
    entries = list(struct.unpack_from(f"<{LOOKUP_N}H", exe, lo_off))
    moved = 0
    for i, idx in enumerate(entries):
        if idx // IPR != OLD_ROW:
            continue
        col, plane = (idx % IPR) // PLANES, idx % PLANES
        row, ncol = (ROW_A, col) if col < COLS_NEW else (ROW_B, col - COLS_NEW)
        entries[i] = row * IPR + ncol * PLANES + plane
        moved += 1
    if not moved:
        raise SystemExit("no lookup entry sits on the old row")
    for v in entries:
        r, rem = divmod(v, IPR)
        if r in (ROW_A, ROW_B) and rem // PLANES >= COLS_NEW:
            raise SystemExit(f"remap produced column {rem // PLANES} on row {r}")
    struct.pack_into(f"<{LOOKUP_N}H", exe, lo_off, *entries)

    # --- write ---
    exe[HELPER_SRC - RAM_TO_FILE: HELPER_SRC - RAM_TO_FILE + HELPER_N] = b"\x00" * HELPER_N
    for i, (v, _) in enumerate(helper):
        put(exe, HELPER_SRC + i * 4, v)
    exe[GA_SRC - RAM_TO_FILE: GA_SRC - RAM_TO_FILE + STRIP_BYTES] = strip_a
    exe[GB_SRC - RAM_TO_FILE: GB_SRC - RAM_TO_FILE + STRIP_BYTES] = strip_b
    for i, (v, _) in enumerate(classify):
        put(exe, CODE_SRC + i * 4, v)
    for i, (v, _) in enumerate(frame):
        put(exe, CODE_SRC + len(classify) * 4 + i * 4, v)

    classify_at = CODE_DST
    frame_at = CODE_DST + len(classify) * 4
    PATCH = [
        (MEMCPY_LEN_AT, addiu(A2, ZERO, copy_n), f"memcpy length -> {copy_n}"),
        (HEAP_BASE_AT, addiu(A0, A0, (heap - 4) - HEAP_HI), f"heap base -> 0x{heap:08X}"),
        (TPAGE_AT, ori(A3, A3, TPAGE), f"tpage 0x1B -> 0x{TPAGE:02X}"),
        (CLS + 0x00, jal(classify_at), f"classifier -> 0x{classify_at:08X}"),
        (CLS + 0x04, addu(A1, V1, S4), "its delay slot, hoisted from +0x14"),
        (CLS + 0x08, NOP, "was the inline compare"),
        (CLS + 0x0C, NOP, "was the inline test"),
        (CLS + 0x14, NOP, "branch delay slot, a1 already set"),
        (STUB_CALL, jal(frame_at), f"frame routine -> 0x{frame_at:08X}"),
        (RECT_A, (Y_A << 16) | NEW_X, f"rect A x={NEW_X} y={Y_A}"),
        (RECT_A + 4, (CELL << 16) | STRIP_W, f"rect A {STRIP_W}x{CELL}"),
        (RECT_B, (Y_B << 16) | NEW_X, f"rect B x={NEW_X} y={Y_B}"),
        (RECT_B + 4, (CELL << 16) | STRIP_W, f"rect B {STRIP_W}x{CELL}"),
    ]
    for ram, val, _ in PATCH:
        put(exe, ram, val)

    # --- readback and address check ---
    for ram, val, note in PATCH:
        if word(exe, ram) != val:
            raise SystemExit(f"readback failed at 0x{ram:08X} ({note})")
    for ram, words in ((HELPER_SRC, helper), (CODE_SRC, classify),
                       (CODE_SRC + len(classify) * 4, frame)):
        for i, (v, _) in enumerate(words):
            if word(exe, ram + i * 4) != v:
                raise SystemExit(f"code readback failed at 0x{ram + i*4:08X}")
    if exe[GA_SRC - RAM_TO_FILE:][:STRIP_BYTES] != strip_a or \
            exe[GB_SRC - RAM_TO_FILE:][:STRIP_BYTES] != strip_b:
        raise SystemExit("glyph readback failed")
    if HELPER_DST + copy_n != heap:
        raise SystemExit("the copy does not reach the end of the code")
    want = {RECT_A, RECT_B, GA_DST, GB_DST}
    reg, formed = {}, set()
    for i in range(len(frame)):
        ins = word(exe, CODE_SRC + len(classify) * 4 + i * 4)
        op, rs, rt, imm = ins >> 26, (ins >> 21) & 31, (ins >> 16) & 31, ins & 0xFFFF
        if op == 0x0F:
            reg[rt] = imm << 16
        elif op == 0x0D and rs in reg:
            reg[rt] = reg[rs] | imm
            formed.add(reg[rt])
    if formed != want:
        raise SystemExit(f"frame routine forms {sorted(map(hex, formed))}, "
                         f"expected {sorted(map(hex, want))}")
    if len(exe) != len(members[PSX]):
        raise SystemExit("the executable changed size")

    members[PSX] = bytes(exe)
    if OUTPUT.exists():
        raise SystemExit(f"{OUTPUT.name} already exists")
    with ZipFile(OUTPUT, "w") as t:
        for i in infos:
            t.writestr(clone(i), members[i.filename])
    with ZipFile(OUTPUT) as a:
        for n in members:
            if a.read(n) != members[n]:
                raise SystemExit(f"archive readback of {n} failed")

    lines = [
        "v112 two glyph strips resident at once",
        "",
        f"base    {BASE_ZIP.name}",
        f"output  {OUTPUT.name}",
        f"        sha256 {sha256(OUTPUT.read_bytes())}",
        f"PSX.EXE {len(members[PSX])} bytes, unchanged; v104 disc layout still applies",
        "",
        f"tpage 0x{TPAGE:02X} (page {TPAGE & 0xF},{TPAGE >> 4})  x {NEW_X}.."
        f"{NEW_X + STRIP_W - 1}  U offset {U_OFF}",
        f"  strip A  y {Y_A}..{Y_A + 11}  V={Y_A % 256}  row {ROW_A}",
        f"  strip B  y {Y_B}..{Y_B + 11}  V={Y_B % 256}  row {ROW_B}",
        f"  {COLS_NEW} columns each, {COLS_NEW * PLANES * 2} slots, {moved} in use",
        "",
        "reserved RAM",
        f"  0x{HELPER_DST:08X} helper   {HELPER_N:>5}",
        f"  0x{GA_DST:08X} strip A  {STRIP_BYTES:>5}",
        f"  0x{GB_DST:08X} strip B  {STRIP_BYTES:>5}",
        f"  0x{classify_at:08X} classify {len(classify)*4:>5}",
        f"  0x{frame_at:08X} frame    {len(frame)*4:>5}",
        f"  0x{heap:08X} heap starts here "
        f"({HEAP_SEEN_USED - heap} bytes clear of heap the game uses)",
        f"  one memcpy moves {copy_n} bytes",
        "",
        "words changed",
    ]
    for ram, val, note in PATCH:
        lines.append(f"  0x{ram:08X}  {val:08X}  {note}")
    lines += ["", f"classifier at 0x{classify_at:08X}  (t8/t9, not t0/t1 as in v106)"]
    for i, (v, note) in enumerate(classify):
        lines.append(f"  0x{classify_at + i*4:08X}  {v:08X}  {note}")
    lines += ["", "rollback: v103 + arc1_v104.xml", "",
              "Rebuild with arc1_v104.xml, then run:",
              f"  python 02_scripts/verify_iso_layout.py E:\\arc\\arc1_v104.bin "
              f"{OUTPUT.name}"]
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
