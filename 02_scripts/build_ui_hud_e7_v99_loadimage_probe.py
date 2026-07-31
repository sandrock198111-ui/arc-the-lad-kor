"""v99: diagnostic probe. Is it safe to call LoadImage from the text-render path?

Plan D-lite re-uploads glyph pixels to VRAM before drawing, so the whole plan rests
on one unproven assumption: that the game tolerates a CPU->VRAM transfer at that
moment. Nothing else in the plan can be trusted until that is established, so this
build tests only that, with the smallest change that can answer it.

What it does
  The renderer entry hook at 0x8016B764 is redirected to a stub in the injected cave.
  The stub calls the Psy-Q LoadImage already linked at 0x80177E4C, transferring a
  16x12 halfword rectangle, then falls through to the existing trampoline unchanged.

Why the target is deliberately boring
  The destination is VRAM x=208..223, y=468..479 in 16-bit units. That block never
  changed in any of the savestates and is off the visible framebuffer, so a successful
  transfer shows nothing and a failed one cannot corrupt anything the player sees.
  The source is the start of the loaded executable: always present, always aligned,
  and read-only, so the transfer content is meaningless on purpose.

What the result means
  runs normally   -> LoadImage is safe here; D-lite can proceed to a real upload
  hangs or breaks -> the transfer cannot happen at this point in the frame, and
                     D-lite needs a different hook site or a deferred trigger

LoadImage is linked into the executable but has zero callers, so nothing the game
does today depends on its behaviour.
"""
from __future__ import annotations

import hashlib
import struct
from pathlib import Path
from zipfile import ZipFile, ZipInfo

ROOT = Path(__file__).resolve().parents[1]
V98 = ROOT / "03_output/ui_hud_e7_v98_restore_object_capacity_patch_only.zip"
OUTPUT = ROOT / "03_output/ui_hud_e7_v99_loadimage_probe_patch_only.zip"
REPORT = ROOT / "01_work/analysis/ui_hud_e7_v99_loadimage_probe/build_report.txt"

V98_SHA256 = "526232330287EEF6AA66A1020B2C0E472DA936CABD90DD55FFA9A31F2ADB36B3"
PSX = "PSX.EXE"
RAM_TO_FILE = 0x8011A800

LOADIMAGE = 0x80177E4C
STUB = 0x801A2074
RECT = 0x801A22E4
TRAMPOLINE = 0x801A22A0
HOOK = 0x8016B764

# destination: 16-bit units. x 208..223, y 468..479 -- stable in every savestate,
# outside the visible framebuffer.
RX, RY, RW, RH = 208, 468, 16, 12
SRC = 0x8011B000                      # start of the loaded executable image


def jal(t): return 0x0C000000 | ((t & 0x0FFFFFFF) >> 2)
def j(t):   return 0x08000000 | ((t & 0x0FFFFFFF) >> 2)


STUB_CODE = [
    (0x27BDFFE0, "addiu sp,sp,-32"),
    (0xAFBF0010, "sw    ra,0x10(sp)"),
    (0xAFA40014, "sw    a0,0x14(sp)"),
    (0xAFA50018, "sw    a1,0x18(sp)"),
    (0x3C04801A, "lui   a0,0x801A"),
    (0x3C058011, "lui   a1,0x8011"),
    (0x348422E4, "ori   a0,a0,0x22E4      ; a0 = RECT"),
    (jal(LOADIMAGE), f"jal   0x{LOADIMAGE:08X}      ; LoadImage"),
    (0x34A5B000, "ori   a1,a1,0xB000      ; delay slot: a1 = source"),
    (0x8FBF0010, "lw    ra,0x10(sp)"),
    (0x8FA40014, "lw    a0,0x14(sp)"),
    (0x8FA50018, "lw    a1,0x18(sp)"),
    (0x27BD0020, "addiu sp,sp,32"),
    (j(TRAMPOLINE), f"j     0x{TRAMPOLINE:08X}      ; original trampoline"),
    (0x00000000, "nop"),
]

RECT_WORDS = [(RY << 16) | RX, (RH << 16) | RW]

MUST_BE_FREE = ([STUB + i * 4 for i in range(len(STUB_CODE))]
                + [RECT, RECT + 4])

KEEP = [
    (TRAMPOLINE, 0x3C028020, "trampoline entry preserved"),
    (0x801A20B0, 0x27BDFFB0, "two-pass driver preserved"),
    (0x801A2194, 0x34E7001B, "v97 high-page tpage preserved"),
    (0x801A2204, 0x90620029, "v92 classifier preserved"),
    (0x801A2168, 0x2463FFCC, "v98 slot reservation preserved"),
    (0x8016B148, 0xAE260000, "initializer still original game code"),
    (LOADIMAGE, 0x27BDFFD0, "LoadImage prologue as expected"),
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

    if word(exe, HOOK) != j(TRAMPOLINE):
        raise SystemExit(f"0x{HOOK:08X} is not `j 0x{TRAMPOLINE:08X}`")
    for a in MUST_BE_FREE:
        if word(exe, a) != 0:
            raise SystemExit(f"cave word 0x{a:08X} is not free: 0x{word(exe, a):08X}")
    for ram, val, label in KEEP:
        if word(exe, ram) != val:
            raise SystemExit(f"scope guard failed at 0x{ram:08X} ({label})")
    if not (0 <= RX < 1024 and 0 <= RY < 512 and 0 < RW <= 1024 and 0 < RH <= 512):
        raise SystemExit("rectangle outside VRAM")
    if RX + RW > 1024 or RY + RH > 512:
        raise SystemExit("rectangle crosses the VRAM edge")

    for i, (w, _) in enumerate(STUB_CODE):
        struct.pack_into("<I", exe, STUB + i * 4 - RAM_TO_FILE, w)
    for i, w in enumerate(RECT_WORDS):
        struct.pack_into("<I", exe, RECT + i * 4 - RAM_TO_FILE, w)
    struct.pack_into("<I", exe, HOOK - RAM_TO_FILE, j(STUB))

    if word(exe, HOOK) != j(STUB):
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
    for a in MUST_BE_FREE + [HOOK]:
        allowed.update(range(a - RAM_TO_FILE, a - RAM_TO_FILE + 4))
    stray = [i for i in diff if i not in allowed]
    if stray:
        raise SystemExit(f"changes outside the approved words: {[hex(i) for i in stray[:8]]}")

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
        "Arc the Lad Korean patch v99 build report  (DIAGNOSTIC PROBE, not a release)",
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
        f"hook  0x{HOOK:08X}: j 0x{TRAMPOLINE:08X} -> j 0x{STUB:08X}",
        f"stub  0x{STUB:08X}..0x{STUB + len(STUB_CODE)*4 - 1:08X}   (was free cave)",
        f"rect  0x{RECT:08X}: x={RX} y={RY} w={RW} h={RH}  (16-bit units)",
        f"source 0x{SRC:08X}  ({RW*RH*2} bytes transferred)",
        "",
        "stub listing:",
    ]
    for i, (w, txt) in enumerate(STUB_CODE):
        lines.append(f"  0x{STUB + i*4:08X}  {w:08X}  {txt}")
    lines += [
        "",
        "register safety: a0 and a1 are saved and restored because both the trampoline",
        "and the original renderer at 0x8016B764 consume them (a0 = text object,",
        "a1 = buffer index). ra is saved because the stub calls LoadImage.",
        "",
        "the destination is off-screen and was byte-identical in every savestate, so a",
        "successful transfer is invisible and a failed one damages nothing visible.",
        "",
        "question under test: does the game still run normally?",
        "  yes -> LoadImage is callable here; proceed to a real glyph upload",
        "  no  -> the transfer cannot happen at this point; change hook site or defer",
        "",
        "static_verification=PASS",
        "runtime_verification=PENDING",
        "rollback baseline=99_backup/baselines/ui_hud_e7_v98_runtime_success_2026-07-31",
    ]
    REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(OUTPUT)
    print(f"SHA256={sha256(OUTPUT.read_bytes())}")
    print(f"changed_bytes={len(diff)}")
    print(REPORT)


if __name__ == "__main__":
    main()
