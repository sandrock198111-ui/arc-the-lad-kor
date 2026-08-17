"""Build v242: tighten letter spacing from 16px to 14px.

The 16px cell is the texture cell, not the ink.  Measuring the 632 composed
syllables, the drawn part is 11..15px wide with 0..3px of margin on each side,
so a 16px step leaves a visible gap between letters.

    0x8016B160  ori v0,zero,16 -> 14      object width/height field (0xd, 0xe)

The sprite itself stays 16x16 (that comes from the packet w/h path), so nothing
is clipped -- only the step to the next character shrinks.  The widest glyph is
15px and still has margin, so letters do not touch.

Built on v241, which already fixed the half-width step (6 -> 8).
"""
from __future__ import annotations
import hashlib, struct, sys
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo
ROOT = Path(__file__).resolve().parents[1]
try: sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception: pass
OUT_DIR = ROOT / "03_output"
STEM = "arc1_v242_tight_TEST_ONLY"
R2F = 0x8011A800
SITE = 0x8016B160
OLD, NEW = 16, 14

def clone(i):
    o = ZipInfo(i.filename, i.date_time)
    for a in ("compress_type","comment","extra","create_system","create_version",
              "extract_version","flag_bits","volume","internal_attr","external_attr"):
        setattr(o, a, getattr(i, a))
    return o

def main():
    base = sorted(OUT_DIR.glob("arc1_v241_halfwidth_TEST_ONLY_*.zip"))[-1]
    with ZipFile(base) as z:
        infos = z.infolist(); before = {i.filename: z.read(i.filename) for i in infos}
    members = dict(before); exe = bytearray(members["PSX.EXE"])
    w = struct.unpack_from("<I", exe, SITE - R2F)[0]
    if (w >> 26) != 0x0D or (w & 0xFFFF) != OLD:
        raise SystemExit(f"0x{SITE:08X} is {w:08X}, not `ori rt,zero,16`")
    n = (w & ~0xFFFF) | NEW
    struct.pack_into("<I", exe, SITE - R2F, n)
    members["PSX.EXE"] = bytes(exe)
    diffs = [o for o,(x,y) in enumerate(zip(before["PSX.EXE"], members["PSX.EXE"])) if x != y]
    if not diffs or any(o not in range(SITE-R2F, SITE-R2F+4) for o in diffs):
        raise SystemExit(f"changed outside the guarded word: {diffs[:8]}")
    tmp = OUT_DIR / f"{STEM}_building.zip"
    if tmp.exists(): raise SystemExit("temp exists")
    with ZipFile(tmp, "w", ZIP_DEFLATED) as z:
        for i in infos: z.writestr(clone(i), members[i.filename])
    stamp = hashlib.sha256(tmp.read_bytes()).hexdigest().upper()
    out = OUT_DIR / f"{STEM}_{stamp[:8]}.zip"
    tmp.replace(out)
    print(f"v242 TEST ONLY - letter step {OLD} -> {NEW}")
    print(f"  base={base.name}\n  output={out.name}\n  sha256={stamp}")
    print(f"  0x{SITE:08X}  {w:08X} -> {n:08X}   PSX_changed_bytes={len(diffs)}")

if __name__ == "__main__": main()
