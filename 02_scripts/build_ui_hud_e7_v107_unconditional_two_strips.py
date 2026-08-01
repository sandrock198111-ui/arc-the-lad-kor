"""v107: upload both strips every frame, and stop shipping glyphs at the old location.

Two faults in v106, with separate causes.

The skill range still showed letters. The cause is not the upload: the original
COMM.IMG is all zeros at 4bpp x 2856..3035, y 288..299, and the glyph store was written
into that space. The game uploads COMM.IMG itself, so it paints our glyphs onto that
rectangle whether or not the patch touches it, and the range overlay is what shares it.
Blanking those 1080 bytes restores the file to what it originally held there. The
glyphs no longer need to be in COMM.IMG at all: since v103 they travel in the
executable and are uploaded from reserved RAM.

The expanded glyphs came out blank. Both strips were empty in VRAM while everything
else -- helper, glyph data, shim, classifier, frame routine, both rectangles -- was
correctly in place, and the state words read (0, 0): the countdown was not armed at the
captured moment, so nothing was uploaded.

Rather than chase when the countdown arms, the countdown goes away. It existed because
v105 shared the rectangle with the game and had to give it back. The new location was
chosen precisely because no savestate ever has a non-zero pixel there, so there is
nothing to share and nothing to return; uploading unconditionally is what v104 did, and
that upload demonstrably worked. This also drops the backup buffers and the state, and
returns the tpage call at 0x801A2198 to the real DR_TPAGE constructor.

The two-strip layout, the relocated helper and the subroutine classifier are unchanged
from v106.
"""
from __future__ import annotations

import hashlib
import struct
from pathlib import Path
from zipfile import ZipFile, ZipInfo

ROOT = Path(__file__).resolve().parents[1]
BASE_ZIP = ROOT / "03_output/ui_hud_e7_v106_two_strips_patch_only.zip"
OUTPUT = ROOT / "03_output/ui_hud_e7_v107_unconditional_two_strips_patch_only.zip"
REPORT = ROOT / "01_work/analysis/ui_hud_e7_v107_unconditional_two_strips/build_report.txt"
BASE_SHA256 = "312DCBE1BD0A0EA4D11CFEBC23E91F69D1AADFCEDD2429AC86D10303B751B523"

PSX, IMG = "PSX.EXE", "COMM.IMG"
RAM_TO_FILE = 0x8011A800
T_ADDR = 0x8011B000
ENTRY = 0x801757BC
SECTOR = 2048

LOADIMAGE, DR_TPAGE = 0x80177E4C, 0x80177484

STRIP_W, STRIP_BYTES = 39, 936
NEW_X, Y_A, Y_B = 961, 480, 500

# the old glyph rectangle inside COMM.IMG, which the original file leaves blank
STRIP_ROW, STRIP_X0 = 896, 1280
OLD_X4, OLD_Y, OLD_W, OLD_H = 2856, 288, 45, 12

HELPER_SRC, HELPER_DST, HELPER_N = 0x801A86EC, 0x801FE3C4, 276
GLYPH_A_DST = HELPER_DST + HELPER_N
GLYPH_B_DST = GLYPH_A_DST + STRIP_BYTES
CODE_DST = GLYPH_B_DST + STRIP_BYTES
GLYPH_A_SRC = HELPER_SRC + HELPER_N
GLYPH_B_SRC = GLYPH_A_SRC + STRIP_BYTES
CODE_SRC = GLYPH_B_SRC + STRIP_BYTES

HEAP_HI, HEAP_SEEN_USED = 0x80200000, 0x801FFA60
MEMCPY_LEN_AT, HEAP_BASE_AT = 0x801757CC, 0x80175810
TPAGE_CALL_AT = 0x801A2198
CLASSIFY_AT, STUB_CALL_AT = 0x801A2204, 0x801A208C
RECT_A, RECT_B = 0x801A22E4, 0x801A22EC

ZERO, A0, A1, SP, RA = 0, 4, 5, 29, 31


def lui(rt, i): return 0x3C000000 | (rt << 16) | (i & 0xFFFF)
def ori(rt, rs, i): return 0x34000000 | (rs << 21) | (rt << 16) | (i & 0xFFFF)
def addiu(rt, rs, i): return 0x24000000 | (rs << 21) | (rt << 16) | (i & 0xFFFF)
def lw(rt, rs, o): return 0x8C000000 | (rs << 21) | (rt << 16) | (o & 0xFFFF)
def sw(rt, rs, o): return 0xAC000000 | (rs << 21) | (rt << 16) | (o & 0xFFFF)
def jal(t): return 0x0C000000 | ((t & 0x0FFFFFFF) >> 2)


NOP, JR_RA = 0, 0x03E00008


def hi(a): return (a >> 16) & 0xFFFF
def lo(a): return a & 0xFFFF
def signed(v): return v - 0x10000 if v & 0x8000 else v


def build_frame():
    """Put both strips up, once per frame, with the GPU idle at the frame boundary."""
    out = [
        (addiu(SP, SP, -24), "addiu sp,sp,-24"),
        (sw(RA, SP, 0x14), "sw    ra,0x14(sp)"),
    ]
    for rect, src, name in ((RECT_A, GLYPH_A_DST, "A"), (RECT_B, GLYPH_B_DST, "B")):
        out += [
            (lui(A0, hi(rect)), f"lui   a0,hi(rect {name})"),
            (ori(A0, A0, lo(rect)), "ori   a0,a0,lo"),
            (lui(A1, hi(src)), f"lui   a1,hi(glyphs {name})"),
            (jal(LOADIMAGE), "jal   LoadImage"),
            (ori(A1, A1, lo(src)), "ori   a1,a1,lo   ; delay slot"),
        ]
    out += [
        (lw(RA, SP, 0x14), "lw    ra,0x14(sp)"),
        (addiu(SP, SP, 24), "addiu sp,sp,24"),
        (JR_RA, "jr    ra"),
        (NOP, "nop"),
    ]
    return out


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
        raise SystemExit("base archive is not the verified v106 build")
    with ZipFile(BASE_ZIP, "r") as a:
        infos = a.infolist()
        members = {i.filename: a.read(i.filename) for i in infos}
    exe = bytearray(members[PSX])
    comm = bytearray(members[IMG])

    pc0, gp0, t_addr, t_size = struct.unpack_from("<4I", exe, 0x10)
    if (pc0, t_addr) != (ENTRY, T_ADDR):
        raise SystemExit("unexpected header")

    KEEP = [
        (0x801A2194, 0x34E7001F, "v106 tpage word"),
        (CLASSIFY_AT, jal(0x801FEC38), "v106 classifier call"),
        (RECT_A, (Y_A << 16) | NEW_X, "strip A rect"),
        (RECT_B, (Y_B << 16) | NEW_X, "strip B rect"),
        (RECT_A + 4, (12 << 16) | STRIP_W, "strip A size"),
        (RECT_B + 4, (12 << 16) | STRIP_W, "strip B size"),
        (0x8016B5D8, 0x0807F8F1, "jump into the relocated helper"),
        (LOADIMAGE, 0x27BDFFD0, "LoadImage prologue"),
        (TPAGE_CALL_AT, jal(0x801FEC28), "v106 countdown shim call"),
        (STUB_CALL_AT, jal(0x801FEC5C), "v106 frame routine call"),
    ]
    for ram, val, label in KEEP:
        if word(exe, ram) != val:
            raise SystemExit(f"scope guard failed at 0x{ram:08X} ({label}): "
                             f"found 0x{word(exe, ram):08X} expected 0x{val:08X}")

    # ---- the classifier stays where v106 put it; the frame routine follows it ----
    classify_at = CODE_DST
    classify_n = 36
    frame = build_frame()
    frame_at = classify_at + classify_n
    copy_n = (frame_at + len(frame) * 4) - HELPER_DST
    new_heap = frame_at + len(frame) * 4
    if new_heap >= HEAP_SEEN_USED:
        raise SystemExit("reservation reaches heap the game uses")

    # move the classifier down to where the shim used to be, and drop the shim
    old_classify = 0x801FEC38
    classify_src = CODE_SRC + 16
    classify_words = [word(exe, classify_src + i * 4) for i in range(classify_n // 4)]
    if classify_words[0] != 0x90620029:
        raise SystemExit("the classifier is not where v106 left it")

    # ---- write the new code layout ----
    exe[CODE_SRC - RAM_TO_FILE: CODE_SRC - RAM_TO_FILE + 0x400] = b"\x00" * 0x400
    for i, v in enumerate(classify_words):
        struct.pack_into("<I", exe, CODE_SRC + i * 4 - RAM_TO_FILE, v)
    for i, (v, _) in enumerate(frame):
        struct.pack_into("<I", exe, CODE_SRC + classify_n + i * 4 - RAM_TO_FILE, v)

    PATCH = [
        (MEMCPY_LEN_AT, addiu(6, ZERO, copy_n), f"memcpy length -> {copy_n}"),
        (HEAP_BASE_AT, addiu(A0, A0, (new_heap - 4) - HEAP_HI),
         f"heap base -> 0x{new_heap:08X}"),
        (TPAGE_CALL_AT, jal(DR_TPAGE),
         "tpage call restored to the real DR_TPAGE constructor"),
        (CLASSIFY_AT, jal(classify_at), f"classifier -> 0x{classify_at:08X}"),
        (STUB_CALL_AT, jal(frame_at),
         f"frame routine -> 0x{frame_at:08X}, unconditional upload"),
    ]
    for ram, val, _ in PATCH:
        struct.pack_into("<I", exe, ram - RAM_TO_FILE, val)

    # ---- stop shipping glyphs at the old VRAM location ----
    off = (OLD_X4 - STRIP_X0) // 2
    before = sum(1 for y in range(OLD_Y, OLD_Y + OLD_H)
                 for b in comm[y * STRIP_ROW + off: y * STRIP_ROW + off + OLD_W * 2] if b)
    if before == 0:
        raise SystemExit("the old glyph rectangle in COMM.IMG is already blank")
    for y in range(OLD_Y, OLD_Y + OLD_H):
        s = y * STRIP_ROW + off
        comm[s: s + OLD_W * 2] = b"\x00" * (OLD_W * 2)
    after = sum(1 for y in range(OLD_Y, OLD_Y + OLD_H)
                for b in comm[y * STRIP_ROW + off: y * STRIP_ROW + off + OLD_W * 2] if b)
    if after:
        raise SystemExit("failed to blank the old glyph rectangle")
    if len(comm) != len(members[IMG]):
        raise SystemExit("COMM.IMG changed size")

    # ---- readback ----
    for ram, val, note in PATCH:
        if word(exe, ram) != val:
            raise SystemExit(f"readback failed at 0x{ram:08X} ({note})")
    for i, v in enumerate(classify_words):
        if word(exe, CODE_SRC + i * 4) != v:
            raise SystemExit("classifier readback failed")
    for i, (v, _) in enumerate(frame):
        if word(exe, CODE_SRC + classify_n + i * 4) != v:
            raise SystemExit("frame routine readback failed")
    if HELPER_DST + copy_n != new_heap:
        raise SystemExit("the copy does not reach the end of the code")
    for ram, val, label in KEEP:
        if ram in {r for r, _, _ in PATCH}:
            continue
        if word(exe, ram) != val:
            raise SystemExit(f"scope guard broken at 0x{ram:08X} ({label})")
    if exe[GLYPH_A_SRC - RAM_TO_FILE:][:16] == b"\x00" * 16:
        raise SystemExit("strip A source went blank")

    # every address the frame routine forms must be one we meant
    want = {RECT_A, RECT_B, GLYPH_A_DST, GLYPH_B_DST}
    reg, formed = {}, set()
    for i in range(len(frame)):
        ins = word(exe, CODE_SRC + classify_n + i * 4)
        op, rs, rt, imm = ins >> 26, (ins >> 21) & 31, (ins >> 16) & 31, ins & 0xFFFF
        if op == 0x0F:
            reg[rt] = imm << 16
        elif op == 0x0D and rs in reg:
            reg[rt] = reg[rs] | imm
            formed.add(reg[rt])
    if formed != want:
        raise SystemExit(f"frame routine forms {sorted(hex(v) for v in formed)}, "
                         f"expected {sorted(hex(v) for v in want)}")

    members[PSX], members[IMG] = bytes(exe), bytes(comm)
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with ZipFile(OUTPUT, "w") as t:
        for i in infos:
            t.writestr(clone(i), members[i.filename])
    with ZipFile(OUTPUT, "r") as a:
        for name in members:
            if a.read(name) != members[name]:
                raise SystemExit(f"archive readback of {name} failed")

    lines = [
        "v107 unconditional two-strip upload, and no glyphs at the old location",
        "",
        f"base    {BASE_ZIP.name}",
        f"output  {OUTPUT.name}",
        f"        sha256 {sha256(OUTPUT.read_bytes())}",
        f"PSX.EXE {len(members[PSX])} bytes, unchanged in size",
        f"COMM.IMG {len(members[IMG])} bytes, unchanged in size; "
        f"{before} non-zero bytes cleared from the old glyph rectangle",
        "",
        "why the old rectangle is cleared",
        f"  the original COMM.IMG is all zeros at 4bpp x {OLD_X4}..{OLD_X4 + OLD_W*4 - 1},"
        f" y {OLD_Y}..{OLD_Y + OLD_H - 1}",
        "  the game uploads COMM.IMG itself, so it painted the glyphs there regardless",
        "  of what the patch did, which is what the skill range overlay was showing",
        "",
        "why the countdown is gone",
        "  it existed so v105 could return a rectangle it shared with the game",
        "  the new location has no savestate with a non-zero pixel in it, so there is",
        "  nothing to share and nothing to return",
        "",
        "reserved RAM",
        f"  0x{HELPER_DST:08X}  helper        {HELPER_N:>5}",
        f"  0x{GLYPH_A_DST:08X}  glyph strip A {STRIP_BYTES:>5}",
        f"  0x{GLYPH_B_DST:08X}  glyph strip B {STRIP_BYTES:>5}",
        f"  0x{classify_at:08X}  classifier    {classify_n:>5}",
        f"  0x{frame_at:08X}  frame routine {len(frame)*4:>5}",
        f"  0x{new_heap:08X}  heap starts here "
        f"({HEAP_SEEN_USED - new_heap} bytes clear of heap the game uses)",
        f"  one memcpy moves {copy_n} bytes",
        "",
        "words changed",
    ]
    for ram, val, note in PATCH:
        lines.append(f"  0x{ram:08X}  {val:08X}  {note}")
    lines += ["", f"frame routine at 0x{frame_at:08X}"]
    for i, (v, note) in enumerate(frame):
        lines.append(f"  0x{frame_at + i*4:08X}  {v:08X}  {note}")
    lines += [
        "",
        "rollback: 99_backup/baselines/ui_hud_e7_v104_runtime_success_2026-08-01/",
        "",
        "Rebuild with arc1_v104.xml and run 02_scripts/verify_iso_layout.py first.",
    ]
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
