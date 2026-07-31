"""v96: give the high-page DR_TPAGE the correct texture-page X.

v95 removed the freeze by restoring the reserved packet slot, and the savestates
confirm the classification and the U correction are both working: the item-name and
skill-name objects carry packets with V == 32 and U already shifted by +40. The glyphs
still rendered as garbage for one remaining reason.

The driver builds the high-page tpage like this:

    lhu  a3,0x2FFC(a3)   ; base tpage, 0x0005 in 107 of 108 savestates -> tx = 5
    andi a3,a3,0xFFE0    ; clears bits 0-4, so the texture-page X is destroyed
    ori  a3,a3,0x0010    ; sets only ty = 256

Bits 0-3 are the texture-page X. Masking them to zero points the sampler at VRAM
x = 0 + U, y = 256 + V, which lands inside the display framebuffer. The glyphs were
therefore textured with whatever was on screen.

The P6 pixels sit at a fixed VRAM location, x = 1576..1755, y = 288..299. Texture page 6
starts at x = 1536, and 1536 + 40 = 1576, which is exactly the `U += 40` correction the
glyph helper already applies. So the correct high-page tpage is tx = 6, ty = 256.

The fix is one word: `ori a3,a3,0x0010` becomes `ori a3,a3,0x0016`. The `andi` is kept so
the abr and colour-depth bits still come from the base tpage. tx is hardcoded rather than
derived as base+1 because the P6 pixels do not move with the base: one savestate shows the
base momentarily at 0x0000, and deriving would send that frame to the wrong page.

Draw ordering was checked and is already correct. AddPrim inserts at the head, so the OT is
walked as: high tpage, high-page glyphs, the game's own tpage, low-page glyphs.
"""
from __future__ import annotations

import hashlib
import struct
from pathlib import Path
from zipfile import ZipFile, ZipInfo

ROOT = Path(__file__).resolve().parents[1]
V95 = ROOT / "03_output/ui_hud_e7_v95_tpage_slot_reservation_patch_only.zip"
OUTPUT = ROOT / "03_output/ui_hud_e7_v96_high_tpage_x_fix_patch_only.zip"
REPORT = ROOT / "01_work/analysis/ui_hud_e7_v96_high_tpage_x_fix/build_report.txt"

V95_SHA256 = "2646E40C0543EBA95684767D97221FF01573FC9CDE0D4F981749A4B11F54AA8F"
PSX = "PSX.EXE"
RAM_TO_FILE = 0x8011A800

PATCH = [
    (0x801A2194, 0x34E70010, 0x34E70016, "ori a3,a3,0x0010 -> ori a3,a3,0x0016  (tx=6, ty=256)"),
]

KEEP = [
    (0x801A2188, 0x3C07801F, "base tpage load, high half"),
    (0x801A218C, 0x94E72FFC, "base tpage load from 0x801F2FFC"),
    (0x801A2190, 0x30E7FFE0, "andi keeps abr and colour depth from the base"),
    (0x801A2198, 0x0C05DD21, "DR_TPAGE constructor call"),
    (0x8016B148, 0x0C068820, "v95 slot reservation retained"),
    (0x801A2084, 0x2484FFFF, "v95 limit-1 retained"),
    (0x801A2204, 0x90620029, "v92 classifier retained (V at packet 0x29)"),
    (0x801A214C, 0x86420004, "tpage primitive still placed at base+52*limit"),
    (0x8016B764, 0x080688A8, "injected renderer entry retained"),
    (0x8016B5D8, 0x0807F8F1, "glyph-builder hook retained (applies U += 40)"),
]


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest().upper()


def clone(i: ZipInfo) -> ZipInfo:
    t = ZipInfo(i.filename, i.date_time)
    for a in ("compress_type", "comment", "extra", "create_system", "create_version",
              "extract_version", "flag_bits", "volume", "internal_attr", "external_attr"):
        setattr(t, a, getattr(i, a))
    return t


def word(buf, ram):
    return struct.unpack_from("<I", buf, ram - RAM_TO_FILE)[0]


def main() -> None:
    if sha256(V95.read_bytes()) != V95_SHA256:
        raise SystemExit("v95 archive hash differs")

    with ZipFile(V95, "r") as a:
        infos = a.infolist()
        members = {i.filename: a.read(i.filename) for i in infos}

    exe = bytearray(members[PSX])
    if struct.unpack_from("<8s", exe, 0)[0] != b"PS-X EXE":
        raise SystemExit("bad EXE header")

    for ram, cur, new, label in PATCH:
        got = word(exe, ram)
        if got != cur:
            raise SystemExit(f"0x{ram:08X}: expected 0x{cur:08X}, got 0x{got:08X} ({label})")
    for ram, val, label in KEEP:
        if word(exe, ram) != val:
            raise SystemExit(f"scope guard failed at 0x{ram:08X} ({label})")

    # geometry proof: tx=6 plus the helper's U += 40 must reach the documented P6 pixels
    tx = 6
    x_base = tx * 256                      # 4bpp pixels per texture page
    if x_base + 40 != 1576:
        raise SystemExit(f"geometry mismatch: {x_base} + 40 != 1576")
    if x_base + 40 + 14 * 12 + 11 != 1755:
        raise SystemExit("geometry mismatch: P6 right edge is not 1755")

    for ram, _, new, _ in PATCH:
        struct.pack_into("<I", exe, ram - RAM_TO_FILE, new)

    for ram, _, new, label in PATCH:
        if word(exe, ram) != new:
            raise SystemExit(f"readback failed at 0x{ram:08X} ({label})")
    for ram, val, label in KEEP:
        if word(exe, ram) != val:
            raise SystemExit(f"scope guard broken at 0x{ram:08X} ({label})")

    patched = bytes(exe)
    original = members[PSX]
    if len(patched) != len(original):
        raise SystemExit("EXE size changed")
    diff = [i for i, (x, y) in enumerate(zip(original, patched)) if x != y]
    allowed = set()
    for ram, _, _, _ in PATCH:
        allowed.update(range(ram - RAM_TO_FILE, ram - RAM_TO_FILE + 4))
    stray = [i for i in diff if i not in allowed]
    if stray:
        raise SystemExit(f"changes outside the approved word: {[hex(i) for i in stray[:8]]}")

    members[PSX] = patched
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with ZipFile(OUTPUT, "w") as t:
        for i in infos:
            t.writestr(clone(i), members[i.filename])

    with ZipFile(OUTPUT, "r") as a, ZipFile(V95, "r") as src:
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
        "Arc the Lad Korean patch v96 build report",
        "",
        f"base_v95={V95.name}",
        f"base_v95_sha256={V95_SHA256}",
        f"output={OUTPUT.name}",
        f"output_sha256={sha256(OUTPUT.read_bytes())}",
        f"psx_sha256={sha256(patched)}",
        "",
        f"changed_members: {PSX} only",
        f"changed_bytes: {len(diff)} in {len(PATCH)} word",
        "",
    ]
    for ram, cur, new, label in PATCH:
        lines.append(f"- 0x{ram:08X} / file 0x{ram - RAM_TO_FILE:05X}: {cur:08X} -> {new:08X}   {label}")
    lines += [
        "",
        "geometry:",
        "  texture page 6 starts at VRAM x = 1536 (4bpp pixels)",
        "  the glyph helper already adds 40 to U for row-24 cells",
        "  1536 + 40 = 1576, and the 15 cells span 1576..1755",
        "  ty bit gives y = 256, and V = 32 for row 24, so y = 288..299",
        "  this matches the documented P6 pixel area exactly",
        "",
        "before this fix the andi cleared the texture-page X, so the sampler read",
        "x = 0 + U, y = 256 + V, which is inside the display framebuffer.",
        "",
        "invariants held:",
    ]
    for ram, val, label in KEEP:
        lines.append(f"- 0x{ram:08X} == 0x{val:08X}   {label}")
    lines += [
        "",
        "static_verification=PASS",
        "runtime_verification=PENDING",
        "rollback baseline=99_backup/baselines/ui_hud_e7_v94_runtime_success_2026-07-31",
    ]
    REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(OUTPUT)
    print(f"SHA256={sha256(OUTPUT.read_bytes())}")
    print(f"changed_bytes={len(diff)}")
    print(REPORT)


if __name__ == "__main__":
    main()
