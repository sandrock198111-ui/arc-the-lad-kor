"""v106: move the glyphs to two strips of VRAM the game never draws into.

v105 borrows the P6 rectangle while text is on screen and returns it after, and that
fixed every reported case but one. The skill range overlay still breaks, because the
range is shown while the skill name is on screen: the patch holds the rectangle exactly
when the game wants it. Time-sharing cannot resolve that, so the glyphs move instead.

Where they can go, measured over 139 savestates as "no savestate ever has a non-zero
pixel there", subject to U + 12*columns <= 256 so a strip stays inside one texture page:

    15 columns (what the store uses today)   no free position
    14 columns                               no free position
    13 columns                               7 free positions

A single 13-column strip holds 52 glyphs and 57 are in use, so one strip would cost
five. Exactly one pair of 13-column strips shares an x and a texture page, and a pair
holds 104:

    page 15,1   tpage word 0x1F   x 961..999   U = 4
      strip A   y 480   V = 224   row 40
      strip B   y 500   V = 244   row 63

Two V values do not fit the inline four-instruction classifier. A one-bit mask test is
exact and does fit, but it forces the two values one bit apart, which only admits
six-column strips -- fewer glyphs than today. A range test cannot work either: the base
rows put a V value every 12, so any range wide enough for two strips swallows one. The
test therefore moves into a subroutine, which also generalises: the full script needs
roughly 947 glyphs, about eighteen strips.

Calling from that loop is safe. It already contains jal 0x80178F84, ra is saved by the
prologue at 0x801A21DC and reloaded at 0x801A2294 after the loop, and at and t0..t9 are
never read or written anywhere between 0x801A21DC and 0x801A229C.

The relocated helper is rewritten rather than patched. Its row test and its U offset
both change, and its sidecar query at 0x801FE460 has had no caller since v92 replaced
the stateful classifier, so dropping it leaves ample room.

PSX.EXE grows by one sector. That is free now: under the v104 layout it sits at the end
of the disc, so nothing behind it moves.
"""
from __future__ import annotations

import hashlib
import struct
from pathlib import Path
from zipfile import ZipFile, ZipInfo

ROOT = Path(__file__).resolve().parents[1]
BASE_ZIP = ROOT / "03_output/ui_hud_e7_v105_borrow_and_return_patch_only.zip"
OUTPUT = ROOT / "03_output/ui_hud_e7_v106_two_strips_patch_only.zip"
REPORT = ROOT / "01_work/analysis/ui_hud_e7_v106_two_strips/build_report.txt"
BASE_SHA256 = "25ED1A9D23C69519A279A2989F166BA5C3E373333494630CBB520D0BCF1265A5"

PSX, IMG = "PSX.EXE", "COMM.IMG"
RAM_TO_FILE = 0x8011A800
T_ADDR, OLD_T_SIZE = 0x8011B000, 0x8E000
ENTRY = 0x801757BC
SECTOR = 2048

LOADIMAGE, STOREIMAGE, DR_TPAGE = 0x80177E4C, 0x801780FC, 0x80177484

# --- the glyph store ---
GLYPH_COLUMNS, PLANES = 21, 4
INDICES_PER_ROW = GLYPH_COLUMNS * PLANES        # 84
LOOKUP_ADDRESS, LOOKUP_COUNT = 0x801A7520, 409
OLD_ROW, OLD_COLS = 24, 15
NEW_COLS = 13
ROW_A, ROW_B = 40, 63
STRIP_W = NEW_COLS * 3                          # 16-bit units
STRIP_BYTES = STRIP_W * 2 * 12                  # 936
NEW_X, NEW_TPAGE, U_OFFSET = 961, 0x1F, 4
Y_A, Y_B = 480, 500

# where the old strip lives inside COMM.IMG
STRIP_ROW, STRIP_X0 = 896, 1280
OLD_X4, OLD_Y, OLD_H = 2856, 288, 12
OLD_W = OLD_COLS * 3

# --- reserved RAM, filled by the one startup memcpy ---
HELPER_SRC, HELPER_DST, HELPER_N = 0x801A86EC, 0x801FE3C4, 276
GLYPH_A_DST = HELPER_DST + HELPER_N             # 0x801FE4D8
GLYPH_B_DST = GLYPH_A_DST + STRIP_BYTES
CODE_DST = GLYPH_B_DST + STRIP_BYTES
GLYPH_A_SRC = HELPER_SRC + HELPER_N             # == the old image end, 0x801A8800
GLYPH_B_SRC = GLYPH_A_SRC + STRIP_BYTES
CODE_SRC = GLYPH_B_SRC + STRIP_BYTES

SHIM_N, FRAME_N, CLASSIFY_N, STATE_N = 16, 0, 36, 8   # FRAME_N filled in below
HEAP_HI, HEAP_SEEN_USED = 0x80200000, 0x801FFA60

MEMCPY_LEN_AT, HEAP_BASE_AT = 0x801757CC, 0x80175810
TPAGE_AT = 0x801A2194                           # ori a3,a3,0x001B
TPAGE_CALL_AT = 0x801A2198
CLASSIFY_AT = 0x801A2204                        # the four inline classifier words
STUB_CALL_AT = 0x801A208C
STUB = 0x801A2074
RECT_A, RECT_B = 0x801A22E4, 0x801A22EC
FRAMESWAP, HOOK = 0x8011C814, 0x8011C4AC
HELPER_RETURN = 0x8016B5E0
COUNTDOWN = 8

ZERO, AT, V0, V1, A0, A1, A2, A3, T0, T1, S0, S4, S5, SP, RA = \
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 16, 20, 21, 29, 31


def lui(rt, i): return 0x3C000000 | (rt << 16) | (i & 0xFFFF)
def ori(rt, rs, i): return 0x34000000 | (rs << 21) | (rt << 16) | (i & 0xFFFF)
def addiu(rt, rs, i): return 0x24000000 | (rs << 21) | (rt << 16) | (i & 0xFFFF)
def sltiu(rt, rs, i): return 0x2C000000 | (rs << 21) | (rt << 16) | (i & 0xFFFF)
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
def hi_adj(a): return ((a >> 16) + (1 if a & 0x8000 else 0)) & 0xFFFF
def signed(v): return v - 0x10000 if v & 0x8000 else v


def build_helper():
    """Entered by `j` from 0x8016B5D8 with t0 = row, a1 = packet, a2 = object.

    Adds the U offset for either glyph row and returns the way the original did, with
    v0 holding the byte at 0xE(a2). The sidecar bookkeeping the v83 renderer kept here
    is gone: its only reader was the query at 0x801FE460, which has had no caller since
    v92 made the classifier stateless.
    """
    return [
        (addiu(A3, T0, -ROW_A), f"addiu a3,t0,-{ROW_A}"),                    # 0
        (sltiu(A3, A3, 1), "sltiu a3,a3,1"),                                 # 1
        (bne(A3, ZERO, 4), "bne   a3,zero,add"),                             # 2
        (addiu(A3, T0, -ROW_B), f"addiu a3,t0,-{ROW_B}   ; delay slot"),     # 3
        (sltiu(A3, A3, 1), "sltiu a3,a3,1"),                                 # 4
        (beq(A3, ZERO, 5), "beq   a3,zero,out"),                             # 5
        (NOP, "nop"),                                                        # 6
        (lbu(A3, A1, 0x28), "add: lbu a3,0x28(a1)   ; U"),                   # 7
        (NOP, "nop"),                                                        # 8
        (addiu(A3, A3, U_OFFSET), f"addiu a3,a3,{U_OFFSET}"),                # 9
        (sb(A3, A1, 0x28), "sb    a3,0x28(a1)"),                             # 10
        (lbu(V0, A2, 0x0E), "out: lbu v0,0xE(a2)"),                          # 11
        (j(HELPER_RETURN), f"j     0x{HELPER_RETURN:08X}"),                  # 12
        (NOP, "nop"),                                                        # 13
    ]


def build_classify():
    """v0 = 1 when the packet's V byte belongs to either glyph strip.

    Only v0, t0 and t1 are written, and none of them is live anywhere in the calling
    loop. v1 still holds the packet pointer across the call.
    """
    return [
        (lbu(V0, V1, 0x29), "lbu   v0,0x29(v1)    ; V"),
        (NOP, "nop"),
        (addiu(T0, V0, -(Y_A % 256)), f"addiu t0,v0,-{Y_A % 256}"),
        (sltiu(T0, T0, 1), "sltiu t0,t0,1"),
        (addiu(T1, V0, -(Y_B % 256)), f"addiu t1,v0,-{Y_B % 256}"),
        (sltiu(T1, T1, 1), "sltiu t1,t1,1"),
        (or_(V0, T0, T1), "or    v0,t0,t1"),
        (JR_RA, "jr    ra"),
        (NOP, "nop"),
    ]


def build_shim(state):
    if (hi_adj(state) << 16) + signed(lo(state)) != state:
        raise SystemExit("shim address arithmetic is wrong")
    return [
        (lui(AT, hi_adj(state)), f"lui   at,0x{hi_adj(state):04X}"),
        (addiu(T0, ZERO, COUNTDOWN), f"addiu t0,zero,{COUNTDOWN}"),
        (j(DR_TPAGE), f"j     0x{DR_TPAGE:08X}   ; tail call"),
        (sw(T0, AT, lo(state)), f"sw    t0,{signed(lo(state))}(at)  -> 0x{state:08X}"),
    ]


def build_frame(state, backup_a, backup_b):
    """Borrow both strips while text is on screen, and give both back after.

    Kept from v105. The new location is one the game was never seen to draw into, so
    this should never have to restore anything; leaving it in place means a wrong
    measurement costs a glitch while text is up rather than a permanently damaged
    texture.
    """
    body = []

    def blit(fn, rect, src):
        body.extend([
            (lui(A0, hi(rect)), "lui   a0,hi(rect)"),
            (ori(A0, A0, lo(rect)), "ori   a0,a0,lo(rect)"),
            (lui(A1, hi(src)), "lui   a1,hi(buf)"),
            (jal(fn), f"jal   0x{fn:08X}"),
            (ori(A1, A1, lo(src)), "ori   a1,a1,lo(buf)   ; delay slot"),
        ])

    head = [
        (addiu(SP, SP, -24), "addiu sp,sp,-24"),
        (sw(RA, SP, 0x14), "sw    ra,0x14(sp)"),
        (sw(S0, SP, 0x10), "sw    s0,0x10(sp)"),
        (lui(S0, hi(state)), "lui   s0,hi(state)"),
        (ori(S0, S0, lo(state)), "ori   s0,s0,lo(state)"),
        (lw(T0, S0, 0), "lw    t0,0x0(s0)      ; countdown"),
        (NOP, "nop"),
    ]
    body.extend(head)
    i_beq_release = len(body)
    body.append((0, "beq   t0,zero,release"))
    body.extend([
        (NOP, "nop"),
        (addiu(T0, T0, -1), "addiu t0,t0,-1"),
        (sw(T0, S0, 0), "sw    t0,0x0(s0)"),
        (lw(T1, S0, 4), "lw    t1,0x4(s0)      ; borrowed?"),
        (NOP, "nop"),
    ])
    i_bne_upload = len(body)
    body.append((0, "bne   t1,zero,upload"))
    body.append((NOP, "nop"))
    blit(STOREIMAGE, RECT_A, backup_a)
    blit(STOREIMAGE, RECT_B, backup_b)
    body.extend([
        (addiu(T1, ZERO, 1), "addiu t1,zero,1"),
        (sw(T1, S0, 4), "sw    t1,0x4(s0)      ; borrowed"),
    ])
    i_upload = len(body)
    blit(LOADIMAGE, RECT_A, GLYPH_A_DST)
    blit(LOADIMAGE, RECT_B, GLYPH_B_DST)
    i_beq_done = len(body)
    body.append((0, "beq   zero,zero,done"))
    body.append((NOP, "nop"))
    i_release = len(body)
    body.extend([
        (lw(T1, S0, 4), "release: lw t1,0x4(s0)"),
        (NOP, "nop"),
    ])
    i_beq_done2 = len(body)
    body.append((0, "beq   t1,zero,done"))
    body.append((NOP, "nop"))
    body.append((sw(ZERO, S0, 4), "sw    zero,0x4(s0)    ; returned"))
    blit(LOADIMAGE, RECT_A, backup_a)
    blit(LOADIMAGE, RECT_B, backup_b)
    i_done = len(body)
    body.extend([
        (lw(RA, SP, 0x14), "done: lw ra,0x14(sp)"),
        (lw(S0, SP, 0x10), "lw    s0,0x10(sp)"),
        (addiu(SP, SP, 24), "addiu sp,sp,24"),
        (JR_RA, "jr    ra"),
        (NOP, "nop"),
    ])

    body[i_beq_release] = (beq(T0, ZERO, i_release - i_beq_release - 1),
                           body[i_beq_release][1])
    body[i_bne_upload] = (bne(T1, ZERO, i_upload - i_bne_upload - 1),
                          body[i_bne_upload][1])
    body[i_beq_done] = (beq(ZERO, ZERO, i_done - i_beq_done - 1),
                        body[i_beq_done][1])
    body[i_beq_done2] = (beq(T1, ZERO, i_done - i_beq_done2 - 1),
                         body[i_beq_done2][1])
    return body


def sha256(b): return hashlib.sha256(b).hexdigest().upper()


def clone(i: ZipInfo) -> ZipInfo:
    t = ZipInfo(i.filename, i.date_time)
    for a in ("compress_type", "comment", "extra", "create_system", "create_version",
              "extract_version", "flag_bits", "volume", "internal_attr", "external_attr"):
        setattr(t, a, getattr(i, a))
    return t


def word(buf, ram): return struct.unpack_from("<I", buf, ram - RAM_TO_FILE)[0]


def main() -> None:
    if sha256(BASE_ZIP.read_bytes()) != BASE_SHA256:
        raise SystemExit("base archive is not the verified v105 build")
    with ZipFile(BASE_ZIP, "r") as a:
        infos = a.infolist()
        members = {i.filename: a.read(i.filename) for i in infos}
    exe = bytearray(members[PSX])
    comm = members[IMG]

    pc0, gp0, t_addr, t_size = struct.unpack_from("<4I", exe, 0x10)
    if (pc0, t_addr, t_size) != (ENTRY, T_ADDR, OLD_T_SIZE):
        raise SystemExit(f"unexpected header t_size=0x{t_size:X}")

    KEEP = [
        (TPAGE_AT, ori(A3, A3, 0x001B), "the v97 tpage word this build replaces"),
        (TPAGE_CALL_AT, jal(0x801FE910), "v105 countdown shim call"),
        (CLASSIFY_AT, lbu(V0, V1, 0x29), "inline classifier, first word"),
        (CLASSIFY_AT + 8, addiu(V0, V0, -32), "inline classifier, compare"),
        (CLASSIFY_AT + 12, sltiu(V0, V0, 1), "inline classifier, test"),
        (CLASSIFY_AT + 16, bne(V0, S5, 0x1A), "inline classifier, branch"),
        (CLASSIFY_AT + 20, addu(A1, V1, S4), "the branch's delay slot"),
        (0x8016B5D8, j(HELPER_DST), "jump into the relocated helper"),
        (LOADIMAGE, 0x27BDFFD0, "LoadImage prologue"),
        (STOREIMAGE, 0x27BDFFD0, "StoreImage prologue"),
        (HOOK, jal(STUB), "frame-swap hook"),
        (STUB, 0x27BDFFE0, "stub prologue"),
        (RECT_A, (288 << 16) | 714, "the v103 rectangle this build replaces"),
    ]
    for ram, val, label in KEEP:
        if word(exe, ram) != val:
            raise SystemExit(f"scope guard failed at 0x{ram:08X} ({label}): "
                             f"found 0x{word(exe, ram):08X} expected 0x{val:08X}")

    # nothing may still call the sidecar query this build drops
    dead = jal(0x801FE460)
    callers = [o + RAM_TO_FILE for o in range(0x800, len(exe) - 4, 4)
               if struct.unpack_from("<I", exe, o)[0] in (dead, j(0x801FE460))]
    if callers:
        raise SystemExit("the sidecar query still has callers: "
                         + ", ".join(f"0x{c:08X}" for c in callers))

    # ---- lay the code out ----
    helper, classify = build_helper(), build_classify()
    if len(helper) * 4 > HELPER_N:
        raise SystemExit("rewritten helper does not fit its 276-byte slot")
    shim_at = CODE_DST
    classify_at = shim_at + SHIM_N
    frame_at = classify_at + len(classify) * 4
    # the frame routine's length depends on nothing that follows it
    probe = build_frame(0, 0, 0)
    state = frame_at + len(probe) * 4
    backup_a = state + STATE_N
    backup_b = backup_a + STRIP_BYTES
    new_heap = backup_b + STRIP_BYTES
    shim = build_shim(state)
    frame = build_frame(state, backup_a, backup_b)
    if len(frame) != len(probe):
        raise SystemExit("frame routine length is not stable")
    copy_n = (state + STATE_N) - HELPER_DST

    if new_heap >= HEAP_SEEN_USED:
        raise SystemExit(f"reservation reaches 0x{new_heap:08X}, into heap the game "
                         f"has been seen to use at 0x{HEAP_SEEN_USED:08X}")
    if Y_A + 12 > Y_B or Y_B + 12 > 512:
        raise SystemExit("the two strips overlap or leave VRAM")
    if (NEW_X % 64) * 4 + NEW_COLS * 12 > 256:
        raise SystemExit("a strip does not fit inside its texture page")
    if (NEW_X % 64) * 4 != U_OFFSET or NEW_X // 64 != (NEW_TPAGE & 0xF):
        raise SystemExit("x, U offset and tpage disagree")
    base_v = {(12 * r) & 0xFF for r in range(OLD_ROW)}
    for r, y in ((ROW_A, Y_A), (ROW_B, Y_B)):
        if (12 * r) & 0xFF != y % 256:
            raise SystemExit(f"row {r} does not produce V={y % 256}")
        if (y % 256) in base_v:
            raise SystemExit(f"V={y % 256} collides with a base row")

    # ---- repack the glyph pixels ----
    off = (OLD_X4 - STRIP_X0) // 2
    old = [comm[y * STRIP_ROW + off: y * STRIP_ROW + off + OLD_W * 2]
           for y in range(OLD_Y, OLD_Y + OLD_H)]
    if any(len(r) != OLD_W * 2 for r in old) or not any(b for r in old for b in r):
        raise SystemExit("could not read the current glyph strip from COMM.IMG")
    # a column is 12 pixels, 4bpp, so 6 bytes; columns 0..12 keep their places in
    # strip A and columns 13..14 become strip B's columns 0..1
    cut = NEW_COLS * 6
    strip_a = b"".join(r[:cut].ljust(STRIP_W * 2, b"\x00") for r in old)
    strip_b = b"".join(r[cut:].ljust(STRIP_W * 2, b"\x00") for r in old)
    if len(strip_a) != STRIP_BYTES or len(strip_b) != STRIP_BYTES:
        raise SystemExit("repacked strips are the wrong size")
    if not any(strip_a) or not any(strip_b):
        raise SystemExit("a repacked strip came out blank")

    # ---- remap the lookup table ----
    lo_off = LOOKUP_ADDRESS - RAM_TO_FILE
    entries = list(struct.unpack_from(f"<{LOOKUP_COUNT}H", exe, lo_off))
    remap, moved = {}, 0
    for i, idx in enumerate(entries):
        if idx // INDICES_PER_ROW != OLD_ROW:
            continue
        col, plane = (idx % INDICES_PER_ROW) // PLANES, idx % PLANES
        if col < NEW_COLS:
            new = ROW_A * INDICES_PER_ROW + col * PLANES + plane
        else:
            new = ROW_B * INDICES_PER_ROW + (col - NEW_COLS) * PLANES + plane
        entries[i] = new
        remap[idx] = new
        moved += 1
    if not moved:
        raise SystemExit("no lookup entries pointed at the old glyph row")
    for old_i, new_i in remap.items():
        r, rem = divmod(new_i, INDICES_PER_ROW)
        c, p = divmod(rem, PLANES)
        if r not in (ROW_A, ROW_B) or c >= NEW_COLS or p >= PLANES:
            raise SystemExit(f"remap produced an out-of-range index {new_i}")
    struct.pack_into(f"<{LOOKUP_COUNT}H", exe, lo_off, *entries)

    # ---- grow the image and write everything ----
    need = (CODE_SRC + SHIM_N + len(classify) * 4 + len(frame) * 4 + STATE_N)
    grow = 0
    while T_ADDR + t_size + grow < need:
        grow += SECTOR
    exe += b"\x00" * grow
    struct.pack_into("<I", exe, 0x1C, t_size + grow)

    def put(ram, words):
        for k, (v, _) in enumerate(words):
            struct.pack_into("<I", exe, ram + k * 4 - RAM_TO_FILE, v)

    exe[HELPER_SRC - RAM_TO_FILE: HELPER_SRC - RAM_TO_FILE + HELPER_N] = \
        b"\x00" * HELPER_N
    put(HELPER_SRC, helper)
    exe[GLYPH_A_SRC - RAM_TO_FILE: GLYPH_A_SRC - RAM_TO_FILE + STRIP_BYTES] = strip_a
    exe[GLYPH_B_SRC - RAM_TO_FILE: GLYPH_B_SRC - RAM_TO_FILE + STRIP_BYTES] = strip_b
    put(CODE_SRC, shim)
    put(CODE_SRC + SHIM_N, classify)
    put(CODE_SRC + SHIM_N + len(classify) * 4, frame)
    struct.pack_into("<II", exe,
                     CODE_SRC + SHIM_N + (len(classify) + len(frame)) * 4 - RAM_TO_FILE,
                     0, 0)

    PATCH = [
        (MEMCPY_LEN_AT, addiu(A2, ZERO, copy_n), f"memcpy length -> {copy_n}"),
        (HEAP_BASE_AT, addiu(A0, A0, (new_heap - 4) - HEAP_HI),
         f"heap base -> 0x{new_heap:08X}"),
        (TPAGE_AT, ori(A3, A3, NEW_TPAGE),
         f"tpage 0x1B -> 0x{NEW_TPAGE:02X}, page {NEW_TPAGE & 0xF},{NEW_TPAGE >> 4}"),
        (TPAGE_CALL_AT, jal(shim_at), "countdown shim, relocated"),
        (CLASSIFY_AT, jal(classify_at), "classifier moved into a subroutine"),
        (CLASSIFY_AT + 4, addu(A1, V1, S4), "its delay slot, hoisted from +20"),
        (CLASSIFY_AT + 8, NOP, "was the inline compare"),
        (CLASSIFY_AT + 12, NOP, "was the inline test"),
        (CLASSIFY_AT + 20, NOP, "the branch delay slot, a1 is already set"),
        (STUB_CALL_AT, jal(frame_at), "frame routine, relocated"),
        (RECT_A, (Y_A << 16) | NEW_X, f"strip A rect x={NEW_X} y={Y_A}"),
        (RECT_A + 4, (12 << 16) | STRIP_W, f"strip A rect w={STRIP_W} h=12"),
        (RECT_B, (Y_B << 16) | NEW_X, f"strip B rect x={NEW_X} y={Y_B}"),
        (RECT_B + 4, (12 << 16) | STRIP_W, f"strip B rect w={STRIP_W} h=12"),
    ]
    for ram, val, _ in PATCH:
        struct.pack_into("<I", exe, ram - RAM_TO_FILE, val)

    # ---- readback ----
    for ram, val, note in PATCH:
        if word(exe, ram) != val:
            raise SystemExit(f"readback failed at 0x{ram:08X} ({note})")
    for ram, words in ((HELPER_SRC, helper), (CODE_SRC, shim),
                       (CODE_SRC + SHIM_N, classify),
                       (CODE_SRC + SHIM_N + len(classify) * 4, frame)):
        for k, (v, _) in enumerate(words):
            if word(exe, ram + k * 4) != v:
                raise SystemExit(f"code readback failed at 0x{ram + k*4:08X}")
    if exe[GLYPH_A_SRC - RAM_TO_FILE:][:STRIP_BYTES] != strip_a or \
            exe[GLYPH_B_SRC - RAM_TO_FILE:][:STRIP_BYTES] != strip_b:
        raise SystemExit("glyph readback failed")
    if HELPER_DST + copy_n != state + STATE_N:
        raise SystemExit("the copy does not reach the end of the state words")

    # every address the new code forms must be one we meant to form
    want = {state, RECT_A, RECT_B, backup_a, backup_b, GLYPH_A_DST, GLYPH_B_DST}
    reg, formed = {}, set()
    for ram, words in ((CODE_SRC, shim), (CODE_SRC + SHIM_N, classify),
                       (CODE_SRC + SHIM_N + len(classify) * 4, frame)):
        for k in range(len(words)):
            ins = word(exe, ram + k * 4)
            op, rs, rt, imm = ins >> 26, (ins >> 21) & 31, (ins >> 16) & 31, ins & 0xFFFF
            if op == 0x0F:
                reg[rt] = imm << 16
            elif op == 0x0D and rs in reg:
                reg[rt] = reg[rs] | imm
                formed.add(reg[rt])
            elif op in (0x23, 0x2B, 0x20, 0x24, 0x28) and rs in reg:
                formed.add((reg[rs] + signed(imm)) & 0xFFFFFFFF)
    stray = {v for v in formed if v not in want and not (state <= v < state + STATE_N)}
    if stray:
        raise SystemExit("code forms unintended addresses: "
                         + ", ".join(f"0x{v:08X}" for v in sorted(stray)))
    if not want <= formed:
        raise SystemExit("code never forms: "
                         + ", ".join(f"0x{v:08X}" for v in sorted(want - formed)))

    members[PSX] = bytes(exe)
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with ZipFile(OUTPUT, "w") as t:
        for i in infos:
            t.writestr(clone(i), members[i.filename])
    with ZipFile(OUTPUT, "r") as a:
        for name in members:
            if a.read(name) != members[name]:
                raise SystemExit(f"archive readback of {name} failed")

    lines = [
        "v106 two glyph strips in VRAM the game never draws into",
        "",
        f"base    {BASE_ZIP.name}",
        f"output  {OUTPUT.name}",
        f"        sha256 {sha256(OUTPUT.read_bytes())}",
        f"PSX.EXE {len(members[PSX])} bytes (grew {grow}); PSX.EXE is last on the disc "
        f"under the v104 layout, so nothing else moves",
        "",
        "VRAM",
        f"  tpage 0x{NEW_TPAGE:02X}, page {NEW_TPAGE & 0xF},{NEW_TPAGE >> 4}   "
        f"x {NEW_X}..{NEW_X + STRIP_W - 1}   U offset {U_OFFSET}",
        f"  strip A  y {Y_A}..{Y_A + 11}   V={Y_A % 256}   row {ROW_A}",
        f"  strip B  y {Y_B}..{Y_B + 11}   V={Y_B % 256}   row {ROW_B}",
        f"  {NEW_COLS} columns each, {NEW_COLS * PLANES * 2} glyph slots, "
        f"{moved} in use",
        "",
        "reserved RAM",
        f"  0x{HELPER_DST:08X}  helper        {HELPER_N:>5}",
        f"  0x{GLYPH_A_DST:08X}  glyph strip A {STRIP_BYTES:>5}",
        f"  0x{GLYPH_B_DST:08X}  glyph strip B {STRIP_BYTES:>5}",
        f"  0x{shim_at:08X}  countdown shim{SHIM_N:>5}",
        f"  0x{classify_at:08X}  classifier    {len(classify)*4:>5}",
        f"  0x{frame_at:08X}  frame routine {len(frame)*4:>5}",
        f"  0x{state:08X}  state         {STATE_N:>5}",
        f"  0x{backup_a:08X}  backup A      {STRIP_BYTES:>5}",
        f"  0x{backup_b:08X}  backup B      {STRIP_BYTES:>5}",
        f"  0x{new_heap:08X}  heap starts here "
        f"({HEAP_SEEN_USED - new_heap} bytes clear of heap the game uses)",
        f"  one memcpy moves {copy_n} bytes",
        "",
        f"lookup table: {moved} entries moved off row {OLD_ROW}",
        "",
        "words changed",
    ]
    for ram, val, note in PATCH:
        lines.append(f"  0x{ram:08X}  {val:08X}  {note}")
    lines += ["", f"helper, rewritten at 0x{HELPER_DST:08X}"]
    for k, (v, note) in enumerate(helper):
        lines.append(f"  0x{HELPER_DST + k*4:08X}  {v:08X}  {note}")
    lines += ["", f"classifier at 0x{classify_at:08X}"]
    for k, (v, note) in enumerate(classify):
        lines.append(f"  0x{classify_at + k*4:08X}  {v:08X}  {note}")
    lines += [
        "",
        "rollback: 99_backup/baselines/ui_hud_e7_v104_runtime_success_2026-08-01/",
        "",
        "Rebuild with arc1_v104.xml and run 02_scripts/verify_iso_layout.py before "
        "playing.",
    ]
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
