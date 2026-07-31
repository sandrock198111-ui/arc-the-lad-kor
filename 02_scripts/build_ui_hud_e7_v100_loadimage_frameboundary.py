"""v100: retry the LoadImage probe at the frame boundary.

v99 called LoadImage from the text-render hook and deadlocked. The savestate showed
the CPU inside LoadImage at 0x80177FD0, spinning on GPUSTAT & 0x04000000 with s6
holding LoadImage's own address. That hook fires while the frame is being drawn, so
the GPU is busy, LoadImage waits for it, and the frame can never finish. Sprites
vanished because drawing stopped mid-frame.

The frame loop ends like this:

    8011C49C  jal 0x80176BA8   with a0 = 0     -- dispatches [gpu_driver + 0x3C],
                                                  the driver's sync entry
    8011C4A4  a0 = [0x801F12EC]                -- render context
    8011C4AC  jal 0x8011C814                   -- frame swap, the only writer of
                                                  the buffer parity at ctx+0x870

Between the sync and the swap the GPU is idle by construction, so that is where a
transfer belongs. v100 replaces the swap call with a stub that runs LoadImage first
and then performs the original swap.

Everything else is identical to v98: the v99 render-path hook is not carried over,
so the only difference from the accepted baseline is this one call site.

Same rectangle as v99 on purpose: 16x12 halfwords at VRAM x=208, y=468, a block that
was byte-identical in every savestate and sits outside the visible framebuffer. A
successful transfer is invisible; a failed one damages nothing the player sees.

  runs normally -> the frame boundary is a usable upload point; D-lite can proceed
  hangs         -> LoadImage is not usable from the main loop either, and the plan
                   needs a different mechanism than the stock library call
"""
from __future__ import annotations

import hashlib
import struct
from pathlib import Path
from zipfile import ZipFile, ZipInfo

ROOT = Path(__file__).resolve().parents[1]
V98 = ROOT / "03_output/ui_hud_e7_v98_restore_object_capacity_patch_only.zip"
OUTPUT = ROOT / "03_output/ui_hud_e7_v100_loadimage_frameboundary_patch_only.zip"
REPORT = ROOT / "01_work/analysis/ui_hud_e7_v100_loadimage_frameboundary/build_report.txt"

V98_SHA256 = "526232330287EEF6AA66A1020B2C0E472DA936CABD90DD55FFA9A31F2ADB36B3"
PSX = "PSX.EXE"
RAM_TO_FILE = 0x8011A800

LOADIMAGE = 0x80177E4C
FRAMESWAP = 0x8011C814
HOOK = 0x8011C4AC              # the `jal FRAMESWAP` in the frame loop
STUB = 0x801A2074
RECT = 0x801A22E4

RX, RY, RW, RH = 208, 468, 16, 12
SRC = 0x8011B000


def jal(t): return 0x0C000000 | ((t & 0x0FFFFFFF) >> 2)


STUB_CODE = [
    (0x27BDFFE0, "addiu sp,sp,-32"),
    (0xAFBF0010, "sw    ra,0x10(sp)"),
    (0xAFA40014, "sw    a0,0x14(sp)     ; render context, needed by the swap"),
    (0x3C04801A, "lui   a0,0x801A"),
    (0x3C058011, "lui   a1,0x8011"),
    (0x348422E4, "ori   a0,a0,0x22E4    ; a0 = RECT"),
    (jal(LOADIMAGE), f"jal   0x{LOADIMAGE:08X}     ; LoadImage, GPU is idle here"),
    (0x34A5B000, "ori   a1,a1,0xB000    ; delay slot: a1 = source"),
    (0x8FA40014, "lw    a0,0x14(sp)     ; restore render context"),
    (jal(FRAMESWAP), f"jal   0x{FRAMESWAP:08X}     ; the original frame swap"),
    (0x00000000, "nop"),
    (0x8FBF0010, "lw    ra,0x10(sp)"),
    (0x27BD0020, "addiu sp,sp,32"),
    (0x03E00008, "jr    ra"),
    (0x00000000, "nop"),
]
RECT_WORDS = [(RY << 16) | RX, (RH << 16) | RW]
FREE = [STUB + i * 4 for i in range(len(STUB_CODE))] + [RECT, RECT + 4]

KEEP = [
    (0x8016B764, 0x080688A8, "render-path hook left exactly as v98 has it"),
    (0x801A22A0, 0x3C028020, "trampoline untouched"),
    (0x801A2194, 0x34E7001B, "v97 high-page tpage preserved"),
    (0x801A2204, 0x90620029, "v92 classifier preserved"),
    (0x801A2168, 0x2463FFCC, "v98 slot reservation preserved"),
    (0x8016B148, 0xAE260000, "initializer still original game code"),
    (LOADIMAGE, 0x27BDFFD0, "LoadImage prologue as expected"),
    (0x8011C49C, 0x0C05DAEA, "the sync call right before our hook"),
    (0x8011C4A8, 0x8C8412EC, "a0 is loaded with the render context before the hook"),
    (0x8011C4B0, 0x00000000, "hook delay slot is a nop"),
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

    if word(exe, HOOK) != jal(FRAMESWAP):
        raise SystemExit(f"0x{HOOK:08X} is not `jal 0x{FRAMESWAP:08X}`")
    for a in FREE:
        if word(exe, a) != 0:
            raise SystemExit(f"cave word 0x{a:08X} not free: 0x{word(exe, a):08X}")
    for ram, val, label in KEEP:
        if word(exe, ram) != val:
            raise SystemExit(f"scope guard failed at 0x{ram:08X} ({label})")
    if RX + RW > 1024 or RY + RH > 512:
        raise SystemExit("rectangle crosses the VRAM edge")

    for i, (w, _) in enumerate(STUB_CODE):
        struct.pack_into("<I", exe, STUB + i * 4 - RAM_TO_FILE, w)
    for i, wv in enumerate(RECT_WORDS):
        struct.pack_into("<I", exe, RECT + i * 4 - RAM_TO_FILE, wv)
    struct.pack_into("<I", exe, HOOK - RAM_TO_FILE, jal(STUB))

    if word(exe, HOOK) != jal(STUB):
        raise SystemExit("hook readback failed")
    for i, (w, _) in enumerate(STUB_CODE):
        if word(exe, STUB + i * 4) != w:
            raise SystemExit(f"stub readback failed at word {i}")
    for ram, val, label in KEEP:
        if word(exe, ram) != val:
            raise SystemExit(f"scope guard broken at 0x{ram:08X} ({label})")

    patched, original = bytes(exe), members[PSX]
    if len(patched) != len(original):
        raise SystemExit("EXE size changed")
    diff = [i for i, (x, y) in enumerate(zip(original, patched)) if x != y]
    allowed = set()
    for a in FREE + [HOOK]:
        allowed.update(range(a - RAM_TO_FILE, a - RAM_TO_FILE + 4))
    stray = [i for i in diff if i not in allowed]
    if stray:
        raise SystemExit(f"changes outside approved words: {[hex(i) for i in stray[:8]]}")

    members[PSX] = patched
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with ZipFile(OUTPUT, "w") as t:
        for i in infos:
            t.writestr(clone(i), members[i.filename])
    with ZipFile(OUTPUT, "r") as a, ZipFile(V98, "r") as src:
        if [i.filename for i in a.infolist()] != [i.filename for i in infos]:
            raise SystemExit("member order differs")
        for i in infos:
            out = a.read(i.filename)
            if out != members[i.filename]:
                raise SystemExit(f"member differs: {i.filename}")
            if i.filename != PSX and out != src.read(i.filename):
                raise SystemExit(f"unexpected change in {i.filename}")

    REPORT.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "Arc the Lad Korean patch v100 build report  (DIAGNOSTIC PROBE)",
        "",
        f"base_v98={V98.name}",
        f"base_v98_sha256={V98_SHA256}",
        f"output={OUTPUT.name}",
        f"output_sha256={sha256(OUTPUT.read_bytes())}",
        f"psx_sha256={sha256(patched)}",
        "",
        f"changed_members: {PSX} only",
        f"changed_bytes: {len(diff)}",
        "",
        f"hook 0x{HOOK:08X}: jal 0x{FRAMESWAP:08X} -> jal 0x{STUB:08X}",
        f"stub 0x{STUB:08X}..0x{STUB+len(STUB_CODE)*4-1:08X}",
        f"rect 0x{RECT:08X}: x={RX} y={RY} w={RW} h={RH}  ({RW*RH*2} bytes)",
        f"source 0x{SRC:08X}",
        "",
        "why here: 0x8011C49C calls the GPU driver's sync entry with a0 = 0 immediately",
        "before this point, so the GPU is idle between that call and the frame swap.",
        "v99 hooked the render path instead and deadlocked inside LoadImage waiting on",
        "GPUSTAT & 0x04000000 while the frame it was blocking could never complete.",
        "",
        "stub listing:",
    ]
    for i, (w, txt) in enumerate(STUB_CODE):
        lines.append(f"  0x{STUB+i*4:08X}  {w:08X}  {txt}")
    lines += [
        "",
        "invariants held:",
    ]
    for ram, val, label in KEEP:
        lines.append(f"- 0x{ram:08X} == 0x{val:08X}   {label}")
    lines += [
        "",
        "question under test: does the game still run normally?",
        "static_verification=PASS",
        "runtime_verification=PENDING",
        "rollback baseline=99_backup/baselines/ui_hud_e7_v98_runtime_success_2026-07-31",
    ]
    REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(OUTPUT)
    print(f"SHA256={sha256(OUTPUT.read_bytes())}")
    print(f"changed_bytes={len(diff)}")


if __name__ == "__main__":
    main()
