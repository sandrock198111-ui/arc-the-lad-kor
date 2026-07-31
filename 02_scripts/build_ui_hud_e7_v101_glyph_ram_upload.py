"""v101: put the P6 glyph pixels in RAM and re-upload them to VRAM every frame.

This is the first build that actually implements plan D-lite rather than probing it.

Established by the earlier probes:
  v99  calling LoadImage from the render path deadlocks; the GPU is busy mid-frame
  v100 calling it at the frame boundary works, because 0x8011C49C runs the GPU
       driver's sync entry immediately before the swap at 0x8011C4AC

What is new here:
  1. The 1080-byte P6 glyph block is extracted from COMM.IMG and appended to the
     executable, which grows by one 2048-byte sector.
  2. The entry bootstrap is replaced. It still relocates the 276-byte P6 helper, and
     it additionally copies the glyph block to 0x801CDE00, a region that was zero in
     every savestate checked. It then clears BSS in two ranges so the copy survives.
  3. The v100 stub now transfers from 0x801CDE00 to the real P6 rectangle instead of
     from the executable head to a scratch block.

Why the bootstrap moves out of line
  The clear cannot run from inside the range it clears. The new routine therefore
  lives at 0x80193B44, a 128-byte run that is below the clear start 0x801A86E8 and
  was zero in all 122 savestates. The appended glyph data sits at 0x801A8800, inside
  the cleared range, which is fine: it is copied out before the clear reaches it.

Why the destination changed too
  The v100 scratch rectangle turned out to be on screen in ordinary field scenes, not
  just the title. Its coordinates were chosen because the block never changed between
  savestates, which says nothing about whether it is displayed. Writing to the real P6
  rectangle removes that artefact and is the actual goal anyway; its coordinates were
  already proven correct by v97.

If this build fails, the bootstrap is the prime suspect. The rectangle change is
verifiable statically and reuses coordinates that already rendered correctly.

NOTE: PSX.EXE changes size, so the ISO has to be rebuilt with mkpsxiso. Replacing the
file in place is not enough.
"""
from __future__ import annotations

import hashlib
import struct
from pathlib import Path
from zipfile import ZipFile, ZipInfo

ROOT = Path(__file__).resolve().parents[1]
# Built on v100, not v98: v100 already carries the frame-boundary stub and the hook
# that calls it. v101 only retargets that stub's source and rectangle.
V98 = ROOT / "03_output/ui_hud_e7_v100_loadimage_frameboundary_patch_only.zip"
OUTPUT = ROOT / "03_output/ui_hud_e7_v101_glyph_ram_upload_patch_only.zip"
REPORT = ROOT / "01_work/analysis/ui_hud_e7_v101_glyph_ram_upload/build_report.txt"

V98_SHA256 = "B0B94915DC89AFA259834A0B5EC32840130108AE1084A4DA02140FCC215AFBAF"
PSX, IMG = "PSX.EXE", "COMM.IMG"
RAM_TO_FILE = 0x8011A800
T_ADDR = 0x8011B000

# --- the P6 glyph block inside COMM.IMG (a 448x512 16bpp VRAM strip, 896 B/row) ---
STRIP_ROW, STRIP_X0 = 896, 1280
P6_X4, P6_Y, P6_W4, P6_H = 2856, 288, 180, 12         # 4bpp pixels
RECT_X, RECT_W = P6_X4 // 4, P6_W4 // 4               # 16-bit units
BLOCK = RECT_W * 2 * P6_H                             # bytes

# --- memory map ---
GLYPH_SRC = 0x801A8800          # appended executable tail, cleared after the copy
GLYPH_DST = 0x801CDE00          # zero in all 122 savestates
HELPER_SRC, HELPER_DST, HELPER_N = 0x801A86EC, 0x801FE3C4, 276
# The clear must stop AT the relocated helper, not past it. The original bootstrap
# used the BIOS memcpy return value, which is the destination pointer 0x801FE3C4,
# so the helper sat just above the cleared range. v101's first attempt used
# 0x801FE4D8 (the helper's END, which is the v87 heap boundary) and therefore
# zeroed the helper it had just copied.
CLEAR_START, CLEAR_END = 0x801A86E8, HELPER_DST
BOOT = 0x80193B44               # 128 free bytes below CLEAR_START
ENTRY, RESUME = 0x801757BC, 0x801757F4
MEMCPY = 0x800000A0
STUB = 0x801A2074
RECT = 0x801A22E4
FRAMESWAP, HOOK = 0x8011C814, 0x8011C4AC
LOADIMAGE = 0x80177E4C
SECTOR = 2048


def jal(t): return 0x0C000000 | ((t & 0x0FFFFFFF) >> 2)
def j(t):   return 0x08000000 | ((t & 0x0FFFFFFF) >> 2)
def lui(r, i): return 0x3C000000 | (r << 16) | (i & 0xFFFF)
def ori(rt, rs, i): return 0x34000000 | (rs << 21) | (rt << 16) | (i & 0xFFFF)
def addiu(rt, rs, i): return 0x24000000 | (rs << 21) | (rt << 16) | (i & 0xFFFF)
def bne(rs, rt, off): return 0x14000000 | (rs << 21) | (rt << 16) | (off & 0xFFFF)


V0, V1, A0, A1, A2, T0, T1, ZERO = 2, 3, 4, 5, 6, 8, 9, 0


def build_bootstrap():
    end2 = GLYPH_DST + BLOCK
    return [
        # relocate the P6 helper, unchanged behaviour
        (lui(A0, HELPER_DST >> 16), "lui   a0,hi(helper dst)"),
        (ori(A0, A0, HELPER_DST & 0xFFFF), "ori   a0,a0,lo"),
        (lui(A1, HELPER_SRC >> 16), "lui   a1,hi(helper src)"),
        (ori(A1, A1, HELPER_SRC & 0xFFFF), "ori   a1,a1,lo"),
        (addiu(A2, ZERO, HELPER_N), f"addiu a2,zero,{HELPER_N}"),
        (jal(MEMCPY), "jal   BIOS memcpy"),
        (addiu(T1, ZERO, 42), "addiu t1,zero,42       ; A(2Ah)"),
        # copy the glyph block out of the executable tail
        (lui(A0, GLYPH_DST >> 16), "lui   a0,hi(glyph dst)"),
        (ori(A0, A0, GLYPH_DST & 0xFFFF), "ori   a0,a0,lo"),
        (lui(A1, GLYPH_SRC >> 16), "lui   a1,hi(glyph src)"),
        (ori(A1, A1, GLYPH_SRC & 0xFFFF), "ori   a1,a1,lo"),
        (addiu(A2, ZERO, BLOCK), f"addiu a2,zero,{BLOCK}"),
        (jal(MEMCPY), "jal   BIOS memcpy"),
        (addiu(T1, ZERO, 42), "addiu t1,zero,42"),
        # clear [CLEAR_START, GLYPH_DST)
        (lui(V1, CLEAR_START >> 16), "lui   v1,hi(clear start)"),
        (ori(V1, V1, CLEAR_START & 0xFFFF), "ori   v1,v1,lo"),
        (lui(T0, GLYPH_DST >> 16), "lui   t0,hi(glyph dst)"),
        (ori(T0, T0, GLYPH_DST & 0xFFFF), "ori   t0,t0,lo"),
        (addiu(V1, V1, 4), "addiu v1,v1,4          ; loop 1"),
        (bne(V1, T0, -2), "bne   v1,t0,-2"),
        (0xAC60FFFC, "sw    zero,-4(v1)      ; delay slot"),
        # clear [GLYPH_DST + BLOCK, CLEAR_END)
        (lui(V1, end2 >> 16), "lui   v1,hi(after block)"),
        (ori(V1, V1, end2 & 0xFFFF), "ori   v1,v1,lo"),
        (lui(T0, CLEAR_END >> 16), "lui   t0,hi(clear end)"),
        (ori(T0, T0, CLEAR_END & 0xFFFF), "ori   t0,t0,lo"),
        (addiu(V1, V1, 4), "addiu v1,v1,4          ; loop 2"),
        (bne(V1, T0, -2), "bne   v1,t0,-2"),
        (0xAC60FFFC, "sw    zero,-4(v1)      ; delay slot"),
        # resume the original startup
        (addiu(V0, ZERO, 4), "addiu v0,zero,4        ; original code expects v0=4"),
        (j(RESUME), f"j     0x{RESUME:08X}"),
        (0x00000000, "nop"),
    ]


STUB_PATCH = [
    (STUB + 4 * 4, lui(A1, GLYPH_DST >> 16), "lui a1,hi(glyph dst)"),
    (STUB + 7 * 4, ori(A1, A1, GLYPH_DST & 0xFFFF), "ori a1,a1,lo  (delay slot)"),
]

KEEP = [
    (0x8016B764, 0x080688A8, "render-path hook as in v98"),
    (0x801A2194, 0x34E7001B, "v97 high-page tpage"),
    (0x801A2204, 0x90620029, "v92 classifier"),
    (0x801A2168, 0x2463FFCC, "v98 slot reservation"),
    (0x8016B148, 0xAE260000, "initializer is original game code"),
    (LOADIMAGE, 0x27BDFFD0, "LoadImage prologue"),
    (0x8011C49C, 0x0C05DAEA, "GPU sync call before the hook"),
    # the v100 stub and its hook must already be in place; v101 only retargets them
    (HOOK, jal(STUB), "v100 frame-swap hook calls the stub"),
    (STUB, 0x27BDFFE0, "v100 stub prologue"),
    (STUB + 6 * 4, jal(LOADIMAGE), "v100 stub calls LoadImage"),
    (STUB + 9 * 4, jal(FRAMESWAP), "v100 stub tail-calls the frame swap"),
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
    if sha256(V98.read_bytes()) != V98_SHA256:
        raise SystemExit("v98 archive hash differs")
    with ZipFile(V98, "r") as a:
        infos = a.infolist()
        members = {i.filename: a.read(i.filename) for i in infos}
    exe = bytearray(members[PSX])
    comm = members[IMG]

    pc0, gp0, t_addr, t_size = struct.unpack_from("<4I", exe, 0x10)
    if t_addr != T_ADDR or pc0 != ENTRY:
        raise SystemExit(f"unexpected header pc0=0x{pc0:08X} t_addr=0x{t_addr:08X}")
    if T_ADDR + t_size != GLYPH_SRC:
        raise SystemExit(f"executable ends at 0x{T_ADDR+t_size:08X}, expected 0x{GLYPH_SRC:08X}")
    for ram, val, label in KEEP:
        if word(exe, ram) != val:
            raise SystemExit(f"scope guard failed at 0x{ram:08X} ({label})")

    # Nothing we relocate may fall inside a range the bootstrap clears afterwards.
    # The first v101 attempt zeroed the P6 helper this way, so the check is explicit.
    ranges = [(CLEAR_START, GLYPH_DST), (GLYPH_DST + BLOCK, CLEAR_END)]
    for lo, hi in ranges:
        if lo >= hi:
            raise SystemExit(f"empty or inverted clear range 0x{lo:08X}..0x{hi:08X}")
    for name, lo, hi in (("P6 helper", HELPER_DST, HELPER_DST + HELPER_N),
                         ("glyph block", GLYPH_DST, GLYPH_DST + BLOCK),
                         ("bootstrap", BOOT, BOOT + 128)):
        for clo, chi in ranges:
            if lo < chi and clo < hi:
                raise SystemExit(
                    f"{name} 0x{lo:08X}..0x{hi:08X} overlaps the clear range "
                    f"0x{clo:08X}..0x{chi:08X}")
    covered = sum(hi - lo for lo, hi in ranges) + BLOCK
    if covered != CLEAR_END - CLEAR_START:
        raise SystemExit(
            f"clear coverage {covered} != original span {CLEAR_END - CLEAR_START}")

    # the bootstrap landing zone must be free and below the clear start
    boot = build_bootstrap()
    if BOOT + len(boot) * 4 > CLEAR_START:
        raise SystemExit("bootstrap would sit inside the range it clears")
    for i in range(len(boot)):
        if word(exe, BOOT + i * 4) != 0:
            raise SystemExit(f"bootstrap landing zone busy at 0x{BOOT + i*4:08X}")
    if len(boot) * 4 > 128:
        raise SystemExit(f"bootstrap is {len(boot)*4} bytes, only 128 verified free")

    # extract the glyph block
    block = b"".join(
        comm[y * STRIP_ROW + (P6_X4 - STRIP_X0) // 2:
             y * STRIP_ROW + (P6_X4 - STRIP_X0) // 2 + RECT_W * 2]
        for y in range(P6_Y, P6_Y + P6_H))
    if len(block) != BLOCK:
        raise SystemExit(f"glyph block is {len(block)} bytes, expected {BLOCK}")
    if not any(block):
        raise SystemExit("glyph block is blank; wrong coordinates")

    # grow the executable by one sector and append the block
    pad = (-BLOCK) % SECTOR
    exe += block + b"\x00" * pad
    struct.pack_into("<I", exe, 0x1C, t_size + BLOCK + pad)

    # write the bootstrap, redirect the entry point, retarget the stub
    for i, (w, _) in enumerate(boot):
        struct.pack_into("<I", exe, BOOT + i * 4 - RAM_TO_FILE, w)
    struct.pack_into("<I", exe, ENTRY - RAM_TO_FILE, j(BOOT))
    struct.pack_into("<I", exe, ENTRY + 4 - RAM_TO_FILE, 0)
    for ram, w, _ in STUB_PATCH:
        struct.pack_into("<I", exe, ram - RAM_TO_FILE, w)
    struct.pack_into("<I", exe, RECT - RAM_TO_FILE, (P6_Y << 16) | RECT_X)
    struct.pack_into("<I", exe, RECT + 4 - RAM_TO_FILE, (P6_H << 16) | RECT_W)

    # readback
    if word(exe, ENTRY) != j(BOOT):
        raise SystemExit("entry redirect failed")
    for i, (w, _) in enumerate(boot):
        if word(exe, BOOT + i * 4) != w:
            raise SystemExit(f"bootstrap readback failed at {i}")
    if exe[GLYPH_SRC - RAM_TO_FILE: GLYPH_SRC - RAM_TO_FILE + BLOCK] != block:
        raise SystemExit("appended glyph block readback failed")
    for ram, val, label in KEEP:
        if word(exe, ram) != val:
            raise SystemExit(f"scope guard broken at 0x{ram:08X} ({label})")

    members[PSX] = bytes(exe)
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with ZipFile(OUTPUT, "w") as t:
        for i in infos:
            t.writestr(clone(i), members[i.filename])
    with ZipFile(OUTPUT, "r") as a, ZipFile(V98, "r") as src:
        for i in infos:
            out = a.read(i.filename)
            if i.filename != PSX and out != src.read(i.filename):
                raise SystemExit(f"unexpected change in {i.filename}")

    REPORT.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "Arc the Lad Korean patch v101 build report",
        "",
        f"base_v98={V98.name}",
        f"output={OUTPUT.name}",
        f"output_sha256={sha256(OUTPUT.read_bytes())}",
        f"psx_sha256={sha256(members[PSX])}",
        "",
        f"PSX.EXE {len(members[PSX]) - len(block) - pad} -> {len(members[PSX])} bytes "
        f"(t_size 0x{t_size:X} -> 0x{t_size + BLOCK + pad:X})",
        "*** the ISO must be rebuilt with mkpsxiso; replacing the file in place is not enough ***",
        "",
        f"glyph block: COMM.IMG y {P6_Y}..{P6_Y + P6_H - 1}, x4bpp {P6_X4}..{P6_X4 + P6_W4 - 1}"
        f"  ({BLOCK} bytes)",
        f"  appended at 0x{GLYPH_SRC:08X}, copied at boot to 0x{GLYPH_DST:08X}",
        f"VRAM rectangle: x={RECT_X} y={P6_Y} w={RECT_W} h={P6_H} (16-bit units)"
        f"  -> x4bpp {RECT_X*4}..{(RECT_X+RECT_W)*4-1}",
        "",
        f"entry 0x{ENTRY:08X}: j 0x{BOOT:08X}    (was the inline v85 bootstrap)",
        f"bootstrap 0x{BOOT:08X}..0x{BOOT + len(boot)*4 - 1:08X}  "
        f"({len(boot)*4} of 128 verified-free bytes)",
        "",
        "bootstrap listing:",
    ]
    for i, (w, txt) in enumerate(boot):
        lines.append(f"  0x{BOOT + i*4:08X}  {w:08X}  {txt}")
    lines += [
        "",
        f"BSS is cleared as [0x{CLEAR_START:08X}, 0x{GLYPH_DST:08X}) and "
        f"[0x{GLYPH_DST + BLOCK:08X}, 0x{CLEAR_END:08X}),",
        "so the glyph copy survives startup. The bootstrap itself sits below the clear",
        "start and therefore cannot erase itself while running.",
        "",
        "invariants held:",
    ]
    for ram, val, label in KEEP:
        lines.append(f"- 0x{ram:08X} == 0x{val:08X}   {label}")
    lines += [
        "",
        "expected result: item and skill names render correctly and stay correct, and the",
        "scratch corruption from v100 is gone because the transfer now targets P6.",
        "if it fails, the new bootstrap is the prime suspect.",
        "",
        "static_verification=PASS",
        "runtime_verification=PENDING",
        "rollback baseline=99_backup/baselines/ui_hud_e7_v98_runtime_success_2026-07-31",
    ]
    REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(OUTPUT)
    print(f"SHA256={sha256(OUTPUT.read_bytes())}")
    print(f"PSX.EXE now {len(members[PSX])} bytes; bootstrap {len(boot)*4} bytes at 0x{BOOT:08X}")
    print(f"glyph block {BLOCK} bytes -> RECT x={RECT_X} y={P6_Y} w={RECT_W} h={P6_H}")


if __name__ == "__main__":
    main()
