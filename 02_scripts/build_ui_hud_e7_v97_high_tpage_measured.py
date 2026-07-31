"""v97: set the high-page texture-page X from the measured pixel location.

v96 was wrong. It used tx = 6 because `codex_notes` records the P6 area as
"absolute texture area x=1576..1755". Those numbers are not absolute VRAM
coordinates; they are relative to the start of the COMM.IMG texture strip.

Measured facts, derived from the archives themselves rather than from notes:

  COMM.IMG is 458752 bytes = 512 rows of 896 bytes, i.e. a 448 x 512 16bpp VRAM
  strip. Matching COMM.IMG content against a savestate gives
      state_offset = 0x202058 + (o // 896) * 2048 + (o % 896)
  so COMM rows map 1:1 onto VRAM rows. The strip's left edge is VRAM x4bpp 1280,
  confirmed because low-page glyphs decode correctly there: the packet U=180 V=180
  cell at x = 1280 + 180, y = 180 contains a clean 12x12 Hangul bitmap.

  Diffing v85 (before the v86 repack) against the current COMM.IMG shows the 57
  relocated glyphs were written at y = 288..298, x4bpp 2856..3033, and that the
  destination was completely blank beforehand. Isolating the four bitplanes at that
  location shows clean Hangul glyphs.

  x4bpp 2856 lies in texture page 11, which starts at 11 * 256 = 2816.
  2856 - 2816 = 40, exactly the `addiu a3,a3,40` correction the glyph helper applies.
  y = 288 = 256 + 32, matching the ty bit plus V = 32 for atlas row 24.

So the high-page tpage must be tx = 11 with the ty bit set: (base & 0xFFE0) | 0x1B.
This build measures that geometry from COMM.IMG at build time and refuses to write
anything if the measurement disagrees.
"""
from __future__ import annotations

import hashlib
import struct
from pathlib import Path
from zipfile import ZipFile, ZipInfo

ROOT = Path(__file__).resolve().parents[1]
V96 = ROOT / "03_output/ui_hud_e7_v96_high_tpage_x_fix_patch_only.zip"
V85 = ROOT / "03_output/ui_hud_e7_v85_p6_highram_bootstrap_patch_only.zip"
OUTPUT = ROOT / "03_output/ui_hud_e7_v97_high_tpage_measured_patch_only.zip"
REPORT = ROOT / "01_work/analysis/ui_hud_e7_v97_high_tpage_measured/build_report.txt"

V96_SHA256 = "149622DBF9227EE3B8433C3AC8AB1F3E3A61A9558F2FFD9787187A2CED072650"
PSX, IMG = "PSX.EXE", "COMM.IMG"
RAM_TO_FILE = 0x8011A800

STRIP_ROW = 896          # bytes per COMM.IMG row
STRIP_X0 = 1280          # VRAM x4bpp of the strip's left edge
P6_Y = 288               # atlas row 24
HELPER_U_ADJ = 40        # addiu a3,a3,40 at 0x801FE410

TPAGE_INSN = 0x801A2194
KEEP = [
    (0x801A2190, 0x30E7FFE0, "andi keeps abr and colour depth from the base tpage"),
    (0x801A218C, 0x94E72FFC, "base tpage still loaded from 0x801F2FFC"),
    (0x801FE410 - 0x801FE3C4 + 0x801A86EC, 0x24E70028, "helper still applies U += 40"),
    (0x8016B148, 0x0C068820, "v95 slot reservation retained"),
    (0x801A2084, 0x2484FFFF, "v95 limit-1 retained"),
    (0x801A2204, 0x90620029, "v92 classifier retained (V at packet 0x29)"),
    (0x8016B764, 0x080688A8, "injected renderer entry retained"),
    (0x8016B5D8, 0x0807F8F1, "glyph-builder hook retained"),
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


def measure_p6(img: bytes, before: bytes) -> tuple[int, int]:
    """Locate the P6 glyphs by diffing against the pre-repack image.

    Atlas row 24 also carries game artwork across the low columns, so a plain
    "first non-zero byte" scan would report the artwork. Only the bytes the v86
    repack actually wrote are P6 glyph pixels, and those were blank before.
    """
    if len(img) != STRIP_ROW * 512 or len(before) != len(img):
        raise SystemExit(f"unexpected COMM.IMG size {len(img)}/{len(before)}")
    cols = set()
    for y in range(P6_Y, P6_Y + 12):
        base = y * STRIP_ROW
        for c in range(STRIP_ROW):
            if img[base + c] != before[base + c]:
                if before[base + c]:
                    raise SystemExit(
                        f"repack overwrote non-blank data at y={y} byte {c}; destination was not free"
                    )
                cols.add(c)
    if not cols:
        raise SystemExit("no repacked glyph pixels found on atlas row 24")
    return STRIP_X0 + min(cols) * 2, STRIP_X0 + max(cols) * 2 + 1


def main() -> None:
    if sha256(V96.read_bytes()) != V96_SHA256:
        raise SystemExit("v96 archive hash differs")

    with ZipFile(V96, "r") as a:
        infos = a.infolist()
        members = {i.filename: a.read(i.filename) for i in infos}

    with ZipFile(V85, "r") as a:
        pre_repack_img = a.read(IMG)
    first, last = measure_p6(members[IMG], pre_repack_img)
    tx = first // 256
    u_off = first - tx * 256
    if u_off != HELPER_U_ADJ:
        raise SystemExit(
            f"measured U offset {u_off} does not match the helper's +{HELPER_U_ADJ}; "
            f"P6 pixels start at x4bpp {first}, page {tx} starts at {tx*256}"
        )
    span = last - first + 1
    if not (150 <= span <= 200):
        raise SystemExit(f"measured P6 span {span} px is not the expected ~180 (15 cells)")
    new_imm = (tx & 0x0F) | 0x10
    new_word = 0x34E70000 | new_imm

    exe = bytearray(members[PSX])
    cur = word(exe, TPAGE_INSN)
    if (cur & 0xFFFF0000) != 0x34E70000:
        raise SystemExit(f"0x{TPAGE_INSN:08X} is not an `ori a3,a3,imm`: 0x{cur:08X}")
    if cur == new_word:
        raise SystemExit("already correct; nothing to do")
    for ram, val, label in KEEP:
        if word(exe, ram) != val:
            raise SystemExit(f"scope guard failed at 0x{ram:08X} ({label})")

    struct.pack_into("<I", exe, TPAGE_INSN - RAM_TO_FILE, new_word)
    if word(exe, TPAGE_INSN) != new_word:
        raise SystemExit("readback failed")
    for ram, val, label in KEEP:
        if word(exe, ram) != val:
            raise SystemExit(f"scope guard broken at 0x{ram:08X} ({label})")

    patched = bytes(exe)
    original = members[PSX]
    if len(patched) != len(original):
        raise SystemExit("EXE size changed")
    diff = [i for i, (x, y) in enumerate(zip(original, patched)) if x != y]
    allowed = set(range(TPAGE_INSN - RAM_TO_FILE, TPAGE_INSN - RAM_TO_FILE + 4))
    stray = [i for i in diff if i not in allowed]
    if stray:
        raise SystemExit(f"changes outside the approved word: {[hex(i) for i in stray[:8]]}")

    members[PSX] = patched
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with ZipFile(OUTPUT, "w") as t:
        for i in infos:
            t.writestr(clone(i), members[i.filename])

    with ZipFile(OUTPUT, "r") as a, ZipFile(V96, "r") as src:
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
        "Arc the Lad Korean patch v97 build report",
        "",
        f"base_v96={V96.name}",
        f"base_v96_sha256={V96_SHA256}",
        f"output={OUTPUT.name}",
        f"output_sha256={sha256(OUTPUT.read_bytes())}",
        f"psx_sha256={sha256(patched)}",
        "",
        f"changed_members: {PSX} only",
        f"changed_bytes: {len(diff)} in 1 word",
        f"- 0x{TPAGE_INSN:08X} / file 0x{TPAGE_INSN - RAM_TO_FILE:05X}: "
        f"{cur:08X} -> {new_word:08X}   ori a3,a3,0x{new_imm:04X}",
        "",
        "measured at build time from COMM.IMG (not taken from notes):",
        f"  strip geometry     : 512 rows x {STRIP_ROW} bytes, left edge VRAM x4bpp {STRIP_X0}",
        f"  atlas row 24 y     : {P6_Y}..{P6_Y + 11}",
        f"  P6 glyph pixels at : x4bpp {first}..{last}  ({span} px, {span // 12} cells)",
        f"  texture page       : {tx}  (starts at x4bpp {tx * 256})",
        f"  U offset           : {u_off}  == the helper's addiu a3,a3,{HELPER_U_ADJ}",
        f"  tpage immediate    : tx {tx} | ty bit 0x10 = 0x{new_imm:02X}",
        "",
        "why v96 was wrong: codex_notes records the P6 area as x=1576..1755 and calls it",
        "absolute, but those are strip-relative. 1576 + 1280 = 2856, the measured start.",
        "v96 therefore selected texture page 6 instead of 11.",
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
    print(f"P6 pixels x4bpp {first}..{last} -> texture page {tx}, U offset {u_off}")
    print(f"tpage immediate 0x{new_imm:02X}   changed_bytes={len(diff)}")


if __name__ == "__main__":
    main()
