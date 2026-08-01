"""v105: borrow the P6 rectangle while text is on screen, and give it back after.

v104 uploads the glyph strip to VRAM every frame unconditionally. That fixed the
glyphs decaying as the game reused the area, but it created the opposite fault: in
scenes where the game legitimately puts a texture there, the game's graphics render as
glyph pixels. The field screen showed it.

The two are one conflict seen from either side. Across 35 v98 savestates the rectangle
held the atlas in 26 and a real game texture in 9, so the game and the patch want the
same VRAM. Deciding who wins loses either way.

So the upload stops being unconditional:

    text on screen   save what the game put there, then upload the glyphs
    text gone        put the game's content back

In a scene with no text the rectangle is never touched at all.

The signal comes from 0x801A2198, the call that builds the high-page tpage primitive
for a text object. It sits immediately before AddPrim, and AddPrim runs once per frame
because the ordering table is rebuilt every frame, so it is a live "text is being
drawn" signal rather than a one-off. It is redirected through a four-instruction shim
that arms a countdown and tail-calls the real constructor.

The countdown, rather than a plain flag, means one missed frame cannot drop the glyphs
mid-sentence, and the rectangle still returns to the game a fraction of a second after
the last text disappears.

Nothing grows. v103 already padded the appended sector to 2048 bytes and only 1080 are
used, so the new code fits in the padding: PSX.EXE stays 583,680 bytes and the v104
disc layout is unchanged.
"""
from __future__ import annotations

import hashlib
import struct
from pathlib import Path
from zipfile import ZipFile, ZipInfo

ROOT = Path(__file__).resolve().parents[1]
BASE_ZIP = ROOT / "03_output/ui_hud_e7_v103_heap_reserved_glyphs_patch_only.zip"
OUTPUT = ROOT / "03_output/ui_hud_e7_v105_borrow_and_return_patch_only.zip"
REPORT = ROOT / "01_work/analysis/ui_hud_e7_v105_borrow_and_return/build_report.txt"
BASE_SHA256 = "9EE40993E72962F26DAFBD61CA565D4646E247D9990B79EF5122776838584FD3"

PSX, IMG = "PSX.EXE", "COMM.IMG"
RAM_TO_FILE = 0x8011A800
T_ADDR, T_SIZE = 0x8011B000, 0x8E000
ENTRY = 0x801757BC

# --- library entry points, both confirmed by the GPU command byte they stamp ---
LOADIMAGE = 0x80177E4C          # 0xA0, CPU to VRAM
STOREIMAGE = 0x801780FC         # 0xC0, VRAM to CPU
DR_TPAGE = 0x80177484

# --- what the startup relocates, and where it lands ---
HELPER_SRC, HELPER_DST, HELPER_N = 0x801A86EC, 0x801FE3C4, 276
GLYPH_SRC, GLYPH_DST, BLOCK = 0x801A8800, 0x801FE4D8, 1080
CODE_SRC, CODE_DST = GLYPH_SRC + BLOCK, GLYPH_DST + BLOCK
SHIM_N = 16
FRAME_N = 176
STATE_N = 8                     # countdown, then the borrowed flag
SHIM = CODE_DST
FRAME = CODE_DST + SHIM_N
STATE = FRAME + FRAME_N
BACKUP = STATE + STATE_N
COPY_N = (STATE + STATE_N) - HELPER_DST
NEW_HEAP_BASE = BACKUP + BLOCK
HEAP_HI = 0x80200000
HEAP_SEEN_USED = 0x801FFA60     # lowest heap address written in 133 savestates

MEMCPY_LEN_AT = 0x801757CC
HEAP_BASE_AT = 0x80175810
TPAGE_CALL_AT = 0x801A2198      # jal DR_TPAGE, the per-frame text signal
STUB_CALL_AT = 0x801A208C       # jal LoadImage inside the frame-boundary stub
STUB = 0x801A2074
RECT = 0x801A22E4
FRAMESWAP, HOOK = 0x8011C814, 0x8011C4AC
COUNTDOWN = 8                   # frames the glyphs stay up after the last text draw

ZERO, AT, A0, A1, A2, T0, T1, S0, SP, RA = 0, 1, 4, 5, 6, 8, 9, 16, 29, 31


def lui(rt, i): return 0x3C000000 | (rt << 16) | (i & 0xFFFF)
def ori(rt, rs, i): return 0x34000000 | (rs << 21) | (rt << 16) | (i & 0xFFFF)
def addiu(rt, rs, i): return 0x24000000 | (rs << 21) | (rt << 16) | (i & 0xFFFF)
def lw(rt, rs, o): return 0x8C000000 | (rs << 21) | (rt << 16) | (o & 0xFFFF)
def sw(rt, rs, o): return 0xAC000000 | (rs << 21) | (rt << 16) | (o & 0xFFFF)
def beq(rs, rt, o): return 0x10000000 | (rs << 21) | (rt << 16) | (o & 0xFFFF)
def bne(rs, rt, o): return 0x14000000 | (rs << 21) | (rt << 16) | (o & 0xFFFF)
def jal(t): return 0x0C000000 | ((t & 0x0FFFFFFF) >> 2)
def j(t): return 0x08000000 | ((t & 0x0FFFFFFF) >> 2)


NOP = 0
JR_RA = 0x03E00008


def hi(a): return (a >> 16) & 0xFFFF
def lo(a): return a & 0xFFFF


def hi_adj(a):
    """High half for a lui paired with a SIGNED 16-bit displacement.

    Loads, stores and addiu sign-extend their immediate, so an address whose low half
    has bit 15 set needs the high half incremented. ori does not, which is why the
    address constructions below use it and only the shim's store needs this.
    """
    return ((a >> 16) + (1 if a & 0x8000 else 0)) & 0xFFFF


def signed(v): return v - 0x10000 if v & 0x8000 else v


def build_shim():
    """Arm the countdown, then hand over to the real DR_TPAGE constructor.

    at and t0 are caller-saved and the constructor's arguments live in a0..a3, so
    nothing the caller relies on is disturbed. The tail call keeps ra, so the
    constructor returns straight to the original caller.
    """
    if (hi_adj(STATE) << 16) + signed(lo(STATE)) != STATE:
        raise SystemExit("shim address arithmetic is wrong")
    return [
        (lui(AT, hi_adj(STATE)), f"lui   at,0x{hi_adj(STATE):04X}"),
        (addiu(T0, ZERO, COUNTDOWN), f"addiu t0,zero,{COUNTDOWN}"),
        (j(DR_TPAGE), f"j     0x{DR_TPAGE:08X}      ; tail call"),
        (sw(T0, AT, lo(STATE)),
         f"sw    t0,{signed(lo(STATE))}(at)  ; delay slot, -> 0x{STATE:08X}"),
    ]


def build_frame():
    """Run once per frame at the frame boundary, with the GPU idle."""
    UPLOAD, RELEASE, DONE = 22, 29, 39
    code = [
        (addiu(SP, SP, -24), "addiu sp,sp,-24"),                       # 0
        (sw(RA, SP, 0x14), "sw    ra,0x14(sp)"),                       # 1
        (sw(S0, SP, 0x10), "sw    s0,0x10(sp)"),                       # 2
        (lui(S0, hi(STATE)), "lui   s0,hi(state)"),                    # 3
        (ori(S0, S0, lo(STATE)), "ori   s0,s0,lo(state)"),             # 4
        (lw(T0, S0, 0), "lw    t0,0x0(s0)      ; countdown"),          # 5
        (NOP, "nop"),                                                  # 6
        (beq(T0, ZERO, RELEASE - 8), "beq   t0,zero,release"),         # 7
        (NOP, "nop"),                                                  # 8
        (addiu(T0, T0, -1), "addiu t0,t0,-1"),                         # 9
        (sw(T0, S0, 0), "sw    t0,0x0(s0)"),                           # 10
        (lw(T1, S0, 4), "lw    t1,0x4(s0)     ; borrowed?"),           # 11
        (NOP, "nop"),                                                  # 12
        (bne(T1, ZERO, UPLOAD - 14), "bne   t1,zero,upload"),          # 13
        (NOP, "nop"),                                                  # 14
        (lui(A0, hi(RECT)), "lui   a0,hi(rect)"),                      # 15
        (ori(A0, A0, lo(RECT)), "ori   a0,a0,lo(rect)"),               # 16
        (lui(A1, hi(BACKUP)), "lui   a1,hi(backup)"),                  # 17
        (jal(STOREIMAGE), "jal   StoreImage     ; save the game's pixels"),  # 18
        (ori(A1, A1, lo(BACKUP)), "ori   a1,a1,lo(backup)"),           # 19
        (addiu(T1, ZERO, 1), "addiu t1,zero,1"),                       # 20
        (sw(T1, S0, 4), "sw    t1,0x4(s0)     ; borrowed"),            # 21
        (lui(A0, hi(RECT)), "upload: lui a0,hi(rect)"),                # 22
        (ori(A0, A0, lo(RECT)), "ori   a0,a0,lo(rect)"),               # 23
        (lui(A1, hi(GLYPH_DST)), "lui   a1,hi(glyphs)"),               # 24
        (jal(LOADIMAGE), "jal   LoadImage      ; put the glyphs up"),  # 25
        (ori(A1, A1, lo(GLYPH_DST)), "ori   a1,a1,lo(glyphs)"),        # 26
        (beq(ZERO, ZERO, DONE - 28), "beq   zero,zero,done"),          # 27
        (NOP, "nop"),                                                  # 28
        (lw(T1, S0, 4), "release: lw t1,0x4(s0)"),                     # 29
        (NOP, "nop"),                                                  # 30
        (beq(T1, ZERO, DONE - 32), "beq   t1,zero,done"),              # 31
        (NOP, "nop"),                                                  # 32
        (sw(ZERO, S0, 4), "sw    zero,0x4(s0)  ; no longer borrowed"), # 33
        (lui(A0, hi(RECT)), "lui   a0,hi(rect)"),                      # 34
        (ori(A0, A0, lo(RECT)), "ori   a0,a0,lo(rect)"),               # 35
        (lui(A1, hi(BACKUP)), "lui   a1,hi(backup)"),                  # 36
        (jal(LOADIMAGE), "jal   LoadImage      ; give the area back"), # 37
        (ori(A1, A1, lo(BACKUP)), "ori   a1,a1,lo(backup)"),           # 38
        (lw(RA, SP, 0x14), "done: lw ra,0x14(sp)"),                    # 39
        (lw(S0, SP, 0x10), "lw    s0,0x10(sp)"),                       # 40
        (addiu(SP, SP, 24), "addiu sp,sp,24"),                         # 41
        (JR_RA, "jr    ra"),                                           # 42
        (NOP, "nop"),                                                  # 43
    ]
    return code


KEEP = [
    (0x8016B764, 0x080688A8, "v98 render-path hook"),
    (0x801A2194, 0x34E7001B, "v97 high-page tpage value"),
    (0x801A2204, 0x90620029, "v92 stateless P6 classifier"),
    (0x801A2168, 0x2463FFCC, "v98 slot reservation"),
    (LOADIMAGE, 0x27BDFFD0, "LoadImage prologue"),
    (STOREIMAGE, 0x27BDFFD0, "StoreImage prologue"),
    (DR_TPAGE, 0x27BDFFE0, "DR_TPAGE constructor prologue"),
    (HOOK, jal(STUB), "frame-swap hook calls the stub"),
    (STUB, 0x27BDFFE0, "stub prologue"),
    (STUB + 9 * 4, jal(FRAMESWAP), "stub tail-calls the frame swap"),
    (RECT, (288 << 16) | 714, "rect x/y"),
    (RECT + 4, (12 << 16) | 45, "rect w/h"),
    (TPAGE_CALL_AT, jal(DR_TPAGE), "the tpage call this build redirects"),
    (STUB_CALL_AT, jal(LOADIMAGE), "the stub's LoadImage call this build redirects"),
    (MEMCPY_LEN_AT, addiu(A2, ZERO, HELPER_N + BLOCK), "v103 memcpy length"),
    (HEAP_BASE_AT, addiu(A0, A0, (GLYPH_DST + BLOCK - 4) - HEAP_HI), "v103 heap base"),
]


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
        raise SystemExit("base archive is not the verified v103 build")
    with ZipFile(BASE_ZIP, "r") as a:
        infos = a.infolist()
        members = {i.filename: a.read(i.filename) for i in infos}
    exe = bytearray(members[PSX])

    pc0, gp0, t_addr, t_size = struct.unpack_from("<4I", exe, 0x10)
    if (pc0, t_addr, t_size) != (ENTRY, T_ADDR, T_SIZE):
        raise SystemExit(f"unexpected header t_size=0x{t_size:X}")
    for ram, val, label in KEEP:
        if word(exe, ram) != val:
            raise SystemExit(f"scope guard failed at 0x{ram:08X} ({label}): "
                             f"found 0x{word(exe, ram):08X} expected 0x{val:08X}")

    shim, frame = build_shim(), build_frame()
    if len(shim) * 4 != SHIM_N:
        raise SystemExit(f"shim is {len(shim)*4} bytes, layout reserves {SHIM_N}")
    if len(frame) * 4 != FRAME_N:
        raise SystemExit(f"frame routine is {len(frame)*4} bytes, layout reserves "
                         f"{FRAME_N}")

    # everything the copy carries has to be inside the loaded image and clear of the
    # padding boundary, and the reservation has to stay below heap the game uses
    code_end_src = CODE_SRC + SHIM_N + FRAME_N + STATE_N
    if code_end_src > T_ADDR + t_size:
        raise SystemExit(f"copy source ends at 0x{code_end_src:08X}, past the image "
                         f"end 0x{T_ADDR + t_size:08X}")
    if any(exe[CODE_SRC - RAM_TO_FILE: code_end_src - RAM_TO_FILE]):
        raise SystemExit("the landing area for the new code is not padding")
    if COPY_N != code_end_src - GLYPH_SRC + HELPER_N + BLOCK - BLOCK - HELPER_N + \
            HELPER_N + BLOCK:
        pass                                    # arithmetic checked directly below
    if HELPER_DST + COPY_N != STATE + STATE_N:
        raise SystemExit("copy length does not reach the end of the state words")
    if NEW_HEAP_BASE >= HEAP_SEEN_USED:
        raise SystemExit("reservation reaches heap the game has been seen to use")
    if BACKUP + BLOCK > NEW_HEAP_BASE:
        raise SystemExit("backup buffer overruns the new heap base")

    # write the code into the padding, then redirect the four call sites
    for i, (v, _) in enumerate(shim):
        struct.pack_into("<I", exe, CODE_SRC + i * 4 - RAM_TO_FILE, v)
    for i, (v, _) in enumerate(frame):
        struct.pack_into("<I", exe, CODE_SRC + SHIM_N + i * 4 - RAM_TO_FILE, v)
    # the state words travel with the copy so they start at zero rather than garbage
    struct.pack_into("<II", exe, CODE_SRC + SHIM_N + FRAME_N - RAM_TO_FILE, 0, 0)

    PATCH = [
        (MEMCPY_LEN_AT, addiu(A2, ZERO, COPY_N),
         f"memcpy length {HELPER_N + BLOCK} -> {COPY_N}, carrying the code and state"),
        (HEAP_BASE_AT, addiu(A0, A0, (NEW_HEAP_BASE - 4) - HEAP_HI),
         f"heap base -> 0x{NEW_HEAP_BASE:08X}, above the backup buffer"),
        (TPAGE_CALL_AT, jal(SHIM),
         "the per-frame text tpage call now arms the countdown first"),
        (STUB_CALL_AT, jal(FRAME),
         "the frame-boundary stub now runs borrow/return instead of a bare upload"),
    ]
    for ram, val, _ in PATCH:
        struct.pack_into("<I", exe, ram - RAM_TO_FILE, val)

    # readback
    for ram, val, note in PATCH:
        if word(exe, ram) != val:
            raise SystemExit(f"readback failed at 0x{ram:08X} ({note})")
    for i, (v, _) in enumerate(shim):
        if word(exe, CODE_SRC + i * 4) != v:
            raise SystemExit(f"shim readback failed at word {i}")
    for i, (v, _) in enumerate(frame):
        if word(exe, CODE_SRC + SHIM_N + i * 4) != v:
            raise SystemExit(f"frame routine readback failed at word {i}")
    # Walk the emitted code the way the CPU forms addresses and check every one of
    # them, rather than trusting that the encoders were paired correctly. The first
    # build got this wrong: a lui paired with a store's sign-extended displacement
    # pointed 0x10000 low.
    want = {STATE, RECT, BACKUP, GLYPH_DST}
    reg, formed = {}, set()
    for a in range(CODE_SRC, CODE_SRC + SHIM_N + FRAME_N, 4):
        ins = word(exe, a)
        op, rs, rt, imm = ins >> 26, (ins >> 21) & 31, (ins >> 16) & 31, ins & 0xFFFF
        if op == 0x0F:                                   # lui
            reg[rt] = imm << 16
        elif op == 0x0D and rs in reg:                   # ori, unsigned
            reg[rt] = reg[rs] | imm
            formed.add(reg[rt])
        elif op in (0x23, 0x2B) and rs in reg:           # lw / sw, signed
            formed.add((reg[rs] + signed(imm)) & 0xFFFFFFFF)
        elif op in (0x23, 0x2B):
            pass
        elif op == 0x09 and rs in reg:                   # addiu, signed
            reg[rt] = (reg[rs] + signed(imm)) & 0xFFFFFFFF
    stray = {v for v in formed if v not in want and not (STATE <= v < STATE + STATE_N)}
    if stray:
        raise SystemExit("code forms addresses that were not intended: "
                         + ", ".join(f"0x{v:08X}" for v in sorted(stray)))
    if not want <= formed | {v for v in formed}:
        missing = want - formed
        raise SystemExit("code never forms: "
                         + ", ".join(f"0x{v:08X}" for v in sorted(missing)))

    edited = {r for r, _, _ in PATCH}
    for ram, val, label in KEEP:
        if ram not in edited and word(exe, ram) != val:
            raise SystemExit(f"scope guard broken at 0x{ram:08X} ({label})")
    if len(exe) != len(members[PSX]):
        raise SystemExit("the executable changed size; it must not")

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
        "v105 borrow the P6 rectangle while text is on screen, and return it after",
        "",
        f"base    {BASE_ZIP.name}",
        f"        sha256 {BASE_SHA256}",
        f"output  {OUTPUT.name}",
        f"        sha256 {sha256(OUTPUT.read_bytes())}",
        f"PSX.EXE {len(members[PSX])} bytes, unchanged in size, so the v104 disc "
        f"layout still applies",
        "",
        "reserved RAM after the startup copy",
        f"  0x{HELPER_DST:08X}  P6 helper        {HELPER_N:>5} bytes",
        f"  0x{GLYPH_DST:08X}  glyph strip      {BLOCK:>5}",
        f"  0x{SHIM:08X}  countdown shim   {SHIM_N:>5}",
        f"  0x{FRAME:08X}  frame routine    {FRAME_N:>5}",
        f"  0x{STATE:08X}  state            {STATE_N:>5}  (copied as zeros)",
        f"  0x{BACKUP:08X}  backup buffer    {BLOCK:>5}  (written at runtime)",
        f"  0x{NEW_HEAP_BASE:08X}  heap starts here",
        f"  one memcpy moves {COPY_N} bytes from 0x{HELPER_SRC:08X}",
        f"  lowest heap address seen written in 133 savestates: 0x{HEAP_SEEN_USED:08X}",
        "",
        "words changed",
    ]
    for ram, val, note in PATCH:
        lines.append(f"  0x{ram:08X}  {val:08X}  {note}")
    lines += ["", "countdown shim @ 0x%08X" % SHIM]
    for i, (v, note) in enumerate(shim):
        lines.append(f"  0x{SHIM + i*4:08X}  {v:08X}  {note}")
    lines += ["", "frame routine @ 0x%08X" % FRAME]
    for i, (v, note) in enumerate(frame):
        lines.append(f"  0x{FRAME + i*4:08X}  {v:08X}  {note}")
    lines += [
        "",
        f"the glyphs stay up for {COUNTDOWN} frames after the last text draw",
        "",
        "rollback: 99_backup/baselines/ui_hud_e7_v104_runtime_success_2026-08-01/",
        "",
        "PSX.EXE is the same size as v103, so rebuild with arc1_v104.xml and run",
        "02_scripts/verify_iso_layout.py before playing.",
    ]
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
