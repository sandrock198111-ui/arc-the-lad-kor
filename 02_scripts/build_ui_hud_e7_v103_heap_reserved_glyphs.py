"""v103: keep the P6 glyph pixels in reserved heap space and re-upload them each frame.

Same goal as v101 -- plan D-lite -- but built the other way round. v101 failed, and
v102 (v101 with the transfer removed) failed identically, which cleared the LoadImage
call but left two suspects standing: the write to 0x801CDE00, and the replacement
bootstrap with its split BSS clear. This build removes both rather than guessing
between them.

Where the glyphs live
  0x801CDE00 was chosen because it was zero in every savestate. That reasoning had
  already failed once, and it failed again: 54 bytes inside it are rewritten
  periodically, so the game owns it.

  This build instead reserves space by moving the heap boundary. The startup code
  calls InitHeap(0x801FE4DC, size); raising that address means the allocator is told
  the space is not its to hand out. That is a contract rather than an observation,
  which is the difference that matters -- every "this looked unused" conclusion this
  session has been wrong, and every structural one has held.

  The measurement is only there to confirm the game still has room: across 133
  savestates the heap never wrote below 0x801FFA60, so the 1092 bytes taken from the
  bottom leave more than 5 KB of untouched heap above them.

Why the bootstrap does not change
  The existing startup already copies the 276-byte P6 helper from 0x801A86EC to
  0x801FE3C4 and only then clears BSS. Two facts make that enough:

    0x801A86EC + 276 == 0x801A8800 == the end of the executable image
    the copy destination 0x801FE3C4 is exactly where the clear stops

  So appending the glyph block to the executable puts it immediately after the helper
  source, and widening the single memcpy from 276 to 1356 bytes carries both across in
  one call, to a destination the clear cannot reach. The appended source is zeroed
  afterwards, which is harmless: it has already been copied, and zero is what those
  BSS addresses are supposed to hold.

  That leaves the BSS clear byte-for-byte identical to v100's. v101 had to cut a hole
  in it and relocate the whole routine to do the same job.

Net change over v100, which is a runtime pass:
  1. executable grows by one 2048-byte sector, holding the 1080-byte glyph block
  2. 0x801757CC  memcpy length 276 -> 1356
  3. 0x80175810  heap base 0x801FE4DC -> 0x801FE920
  4. the v100 stub reads from 0x801FE4D8 instead of the executable head
  5. the stub's rectangle becomes the real P6 rectangle instead of the scratch block

The scratch rectangle also goes away, which should take the corner corruption on the
post-BIOS screen with it: that was this stub writing the executable's first bytes into
a visible part of the framebuffer.

NOTE: PSX.EXE changes size, so the ISO must be rebuilt with mkpsxiso. Swapping the
file into an existing image is not enough.
"""
from __future__ import annotations

import hashlib
import struct
from pathlib import Path
from zipfile import ZipFile, ZipInfo

ROOT = Path(__file__).resolve().parents[1]
BASE_ZIP = ROOT / "03_output/ui_hud_e7_v100_loadimage_frameboundary_patch_only.zip"
OUTPUT = ROOT / "03_output/ui_hud_e7_v103_heap_reserved_glyphs_patch_only.zip"
REPORT = ROOT / "01_work/analysis/ui_hud_e7_v103_heap_reserved_glyphs/build_report.txt"

BASE_SHA256 = "B0B94915DC89AFA259834A0B5EC32840130108AE1084A4DA02140FCC215AFBAF"
PSX, IMG = "PSX.EXE", "COMM.IMG"
RAM_TO_FILE = 0x8011A800
T_ADDR, T_SIZE = 0x8011B000, 0x8D800
ENTRY = 0x801757BC
SECTOR = 2048

# --- the P6 glyph block inside COMM.IMG (a 448x512 16bpp VRAM strip, 896 B/row) ---
STRIP_ROW, STRIP_X0 = 896, 1280
P6_X4, P6_Y, P6_W4, P6_H = 2856, 288, 180, 12         # 4bpp pixels
RECT_X, RECT_W = P6_X4 // 4, P6_W4 // 4               # 16-bit units, as LoadImage wants
BLOCK = RECT_W * 2 * P6_H                             # 1080 bytes

# --- startup relocation, all values read out of the base image and re-checked ---
HELPER_SRC, HELPER_DST, HELPER_N = 0x801A86EC, 0x801FE3C4, 276
GLYPH_SRC = HELPER_SRC + HELPER_N                     # == end of the executable image
GLYPH_DST = HELPER_DST + HELPER_N
COPY_N = HELPER_N + BLOCK
CLEAR_START, CLEAR_END = 0x801A86E8, HELPER_DST

MEMCPY_LEN_AT = 0x801757CC                            # addiu a2,zero,276
HEAP_BASE_AT = 0x80175810                             # addiu a0,a0,-6952
HEAP_HI = 0x80200000                                  # the lui feeding HEAP_BASE_AT
OLD_HEAP_BASE = 0x801FE4DC                            # after the +4 in the delay slot
NEW_HEAP_BASE = (GLYPH_DST + BLOCK + 15) & ~15        # 16-byte guard above the glyphs

STUB = 0x801A2074
RECT = 0x801A22E4
FRAMESWAP, HOOK = 0x8011C814, 0x8011C4AC
LOADIMAGE = 0x80177E4C

A0, A1, A2, ZERO = 4, 5, 6, 0


def lui(rt, i): return 0x3C000000 | (rt << 16) | (i & 0xFFFF)
def ori(rt, rs, i): return 0x34000000 | (rs << 21) | (rt << 16) | (i & 0xFFFF)
def addiu(rt, rs, i): return 0x24000000 | (rs << 21) | (rt << 16) | (i & 0xFFFF)
def jal(t): return 0x0C000000 | ((t & 0x0FFFFFFF) >> 2)


# Words that must already be present. Everything here is load-bearing for this build:
# the v97/v92/v98 renderer fixes it inherits, and the v100 stub it retargets.
KEEP = [
    (0x8016B764, 0x080688A8, "v98 render-path hook"),
    (0x801A2194, 0x34E7001B, "v97 high-page tpage"),
    (0x801A2204, 0x90620029, "v92 stateless P6 classifier"),
    (0x801A2168, 0x2463FFCC, "v98 slot reservation inside the driver"),
    (0x8016B148, 0xAE260000, "object initializer restored to game code"),
    (LOADIMAGE, 0x27BDFFD0, "LoadImage prologue"),
    (0x8011C49C, 0x0C05DAEA, "GPU sync call immediately before the hook"),
    (HOOK, jal(STUB), "v100 frame-swap hook calls the stub"),
    (STUB, 0x27BDFFE0, "v100 stub prologue"),
    (STUB + 6 * 4, jal(LOADIMAGE), "v100 stub calls LoadImage"),
    (STUB + 9 * 4, jal(FRAMESWAP), "v100 stub tail-calls the frame swap"),
    (STUB + 3 * 4, lui(A0, 0x801A), "stub rect pointer, high half"),
    (STUB + 5 * 4, ori(A0, A0, RECT & 0xFFFF), "stub rect pointer, low half"),
    # the startup words this build edits, at their v100 values
    (0x801757C0, addiu(A0, A0, -7228), "helper copy destination 0x801FE3C4"),
    (0x801757C8, addiu(A1, A1, -30996), "helper copy source 0x801A86EC"),
    (MEMCPY_LEN_AT, addiu(A2, ZERO, HELPER_N), "helper copy length"),
    (0x801757D0, jal(0x800000A0), "BIOS memcpy call"),
    (0x801757DC, addiu(3, 3, -31000), "BSS clear start 0x801A86E8"),
    (HEAP_BASE_AT, addiu(A0, A0, -6952), "heap base before InitHeap's +4"),
    # addi, not addiu -- the game's own encoding at this site
    (0x8017584C, 0x20840004, "InitHeap argument adjust in the delay slot"),
]

PATCH = [
    (MEMCPY_LEN_AT, addiu(A2, ZERO, COPY_N),
     f"memcpy length {HELPER_N} -> {COPY_N}: helper and glyphs in one call"),
    (HEAP_BASE_AT, addiu(A0, A0, NEW_HEAP_BASE - 4 - HEAP_HI),
     f"heap base 0x{OLD_HEAP_BASE:08X} -> 0x{NEW_HEAP_BASE:08X}"),
    (STUB + 4 * 4, lui(A1, GLYPH_DST >> 16), "stub source, high half"),
    (STUB + 7 * 4, ori(A1, A1, GLYPH_DST & 0xFFFF), "stub source, low half (delay slot)"),
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
    if not BASE_ZIP.exists():
        raise SystemExit(f"missing base archive {BASE_ZIP}")
    if sha256(BASE_ZIP.read_bytes()) != BASE_SHA256:
        raise SystemExit("base archive is not the verified v100 build")
    with ZipFile(BASE_ZIP, "r") as a:
        infos = a.infolist()
        members = {i.filename: a.read(i.filename) for i in infos}
    exe = bytearray(members[PSX])
    comm = members[IMG]

    pc0, gp0, t_addr, t_size = struct.unpack_from("<4I", exe, 0x10)
    if (pc0, t_addr, t_size) != (ENTRY, T_ADDR, T_SIZE):
        raise SystemExit(f"unexpected header pc0=0x{pc0:08X} t_addr=0x{t_addr:08X} "
                         f"t_size=0x{t_size:08X}")
    if len(exe) != 0x800 + t_size:
        raise SystemExit(f"executable is {len(exe)} bytes, header says {0x800 + t_size}")
    for ram, val, label in KEEP:
        if word(exe, ram) != val:
            raise SystemExit(f"scope guard failed at 0x{ram:08X} ({label}): "
                             f"found 0x{word(exe, ram):08X}, expected 0x{val:08X}")

    # The single memcpy only works because the two sources are adjacent and the glyph
    # block lands exactly at the end of the loaded image.
    if T_ADDR + t_size != GLYPH_SRC:
        raise SystemExit(f"image ends at 0x{T_ADDR + t_size:08X}, "
                         f"glyph source must be 0x{GLYPH_SRC:08X}")
    if HELPER_SRC + HELPER_N != GLYPH_SRC:
        raise SystemExit("helper source and glyph source are not adjacent")
    if HELPER_DST + HELPER_N != GLYPH_DST:
        raise SystemExit("helper destination and glyph destination are not adjacent")

    # Nothing that has to survive may sit inside the range the clear still covers.
    for name, lo, hi in (("P6 helper", HELPER_DST, HELPER_DST + HELPER_N),
                         ("glyph block", GLYPH_DST, GLYPH_DST + BLOCK)):
        if lo < CLEAR_END and CLEAR_START < hi:
            raise SystemExit(f"{name} 0x{lo:08X}..0x{hi:08X} overlaps the BSS clear "
                             f"0x{CLEAR_START:08X}..0x{CLEAR_END:08X}")
    # ...and the reserved space must end below the new heap.
    if GLYPH_DST + BLOCK > NEW_HEAP_BASE:
        raise SystemExit("glyph block runs past the new heap base")
    if NEW_HEAP_BASE <= OLD_HEAP_BASE:
        raise SystemExit("heap base did not move up")
    reserved = NEW_HEAP_BASE - OLD_HEAP_BASE
    # 0x801FFA60 is the lowest heap address ever written across 133 savestates.
    if NEW_HEAP_BASE >= 0x801FFA60:
        raise SystemExit("reservation reaches into heap the game has been seen to use")

    # extract the glyph block from COMM.IMG rather than trusting stored coordinates
    off = (P6_X4 - STRIP_X0) // 2
    block = b"".join(comm[y * STRIP_ROW + off: y * STRIP_ROW + off + RECT_W * 2]
                     for y in range(P6_Y, P6_Y + P6_H))
    if len(block) != BLOCK:
        raise SystemExit(f"glyph block is {len(block)} bytes, expected {BLOCK}")
    if not any(block):
        raise SystemExit("glyph block is blank; the coordinates are wrong")

    # grow the image by one sector and append the block
    pad = (-BLOCK) % SECTOR
    exe += block + b"\x00" * pad
    struct.pack_into("<I", exe, 0x1C, t_size + BLOCK + pad)

    for ram, val, _ in PATCH:
        struct.pack_into("<I", exe, ram - RAM_TO_FILE, val)
    struct.pack_into("<I", exe, RECT - RAM_TO_FILE, (P6_Y << 16) | RECT_X)
    struct.pack_into("<I", exe, RECT + 4 - RAM_TO_FILE, (P6_H << 16) | RECT_W)

    # readback
    for ram, val, label in PATCH:
        if word(exe, ram) != val:
            raise SystemExit(f"readback failed at 0x{ram:08X} ({label})")
    if word(exe, RECT) != ((P6_Y << 16) | RECT_X) or \
            word(exe, RECT + 4) != ((P6_H << 16) | RECT_W):
        raise SystemExit("rectangle readback failed")
    if exe[GLYPH_SRC - RAM_TO_FILE: GLYPH_SRC - RAM_TO_FILE + BLOCK] != block:
        raise SystemExit("appended glyph block readback failed")
    edited = {r for r, _, _ in PATCH}
    for ram, val, label in KEEP:
        if ram in edited:
            continue
        if word(exe, ram) != val:
            raise SystemExit(f"scope guard broken at 0x{ram:08X} ({label})")
    new_t_size = struct.unpack_from("<I", exe, 0x1C)[0]
    if len(exe) != 0x800 + new_t_size:
        raise SystemExit("header size and file size disagree after the grow")

    members[PSX] = bytes(exe)
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with ZipFile(OUTPUT, "w") as t:
        for i in infos:
            t.writestr(clone(i), members[i.filename])

    with ZipFile(OUTPUT, "r") as a:
        if a.read(PSX) != bytes(exe):
            raise SystemExit("archive readback of PSX.EXE failed")
        for name in members:
            if name != PSX and a.read(name) != members[name]:
                raise SystemExit(f"archive readback of {name} failed")

    lines = [
        "v103 heap-reserved glyph store, re-uploaded at the frame boundary",
        "",
        f"base    {BASE_ZIP.name}",
        f"        sha256 {BASE_SHA256}",
        f"output  {OUTPUT.name}",
        f"        sha256 {sha256(OUTPUT.read_bytes())}",
        f"PSX.EXE {len(members[PSX])} bytes, t_size 0x{new_t_size:X} "
        f"(was {0x800 + T_SIZE} / 0x{T_SIZE:X})",
        "",
        "glyph block",
        f"  COMM.IMG source   4bpp x {P6_X4}..{P6_X4 + P6_W4 - 1}, y {P6_Y}..{P6_Y + P6_H - 1}",
        f"  LoadImage rect    x {RECT_X}, y {P6_Y}, w {RECT_W}, h {P6_H} (16-bit units)",
        f"  size              {BLOCK} bytes",
        f"  appended at       0x{GLYPH_SRC:08X}, {pad} bytes of padding",
        f"  copied to         0x{GLYPH_DST:08X}..0x{GLYPH_DST + BLOCK - 1:08X}",
        "",
        "reservation",
        f"  one memcpy now moves {COPY_N} bytes from 0x{HELPER_SRC:08X} to 0x{HELPER_DST:08X}",
        f"  BSS clear unchanged: 0x{CLEAR_START:08X}..0x{CLEAR_END:08X}",
        f"  InitHeap base 0x{OLD_HEAP_BASE:08X} -> 0x{NEW_HEAP_BASE:08X} "
        f"({reserved} bytes reserved)",
        "  lowest heap address written in 133 savestates: 0x801FFA60",
        "",
        "words changed",
    ]
    for ram, val, note in PATCH:
        lines.append(f"  0x{ram:08X}  {val:08X}  {note}")
    lines += [
        f"  0x{RECT:08X}  {word(exe, RECT):08X}  rect x/y",
        f"  0x{RECT + 4:08X}  {word(exe, RECT + 4):08X}  rect w/h",
        "",
        "rollback: 99_backup/baselines/ui_hud_e7_v98_runtime_success_2026-07-31/",
        "",
        "PSX.EXE changed size; rebuild the ISO with mkpsxiso rather than replacing "
        "the file in place.",
    ]
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
