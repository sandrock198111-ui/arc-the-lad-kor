"""Build v243: revert the half-width bump and tighten the letter step further.

v241 raised the half-width step 6 -> 8 on the assumption that it scaled with the
cell.  On screen the gaps between words got wider instead, so that site is not
the space path -- 6 was already correct and is put back.

v242 set the letter step to 14.  The user still reads the text as loose and the
glyphs as oversized, so this goes to 13.  Measured ink is 11..15px, so 13 keeps
margin for all but the widest few, which have 0..1px of side bearing anyway.

    0x8016BEF4  addiu t0,t0,8 -> 6      half-width step, back to stock
    0x8016BEFC  addiu t1,t1,8 -> 6
    0x8016B160  ori v0,zero,14 -> 13    letter step

Sprites stay 16x16; only the step to the next character changes.
"""
from __future__ import annotations
import hashlib, struct, sys
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo
ROOT = Path(__file__).resolve().parents[1]
try: sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception: pass
OUT_DIR = ROOT / "03_output"
STEM = "arc1_v243_spacing_TEST_ONLY"
R2F = 0x8011A800
EDITS = ((0x8016BEF4, 0x09, 8, 6), (0x8016BEFC, 0x09, 8, 6), (0x8016B160, 0x0D, 14, 13))

def clone(i):
    o = ZipInfo(i.filename, i.date_time)
    for a in ("compress_type","comment","extra","create_system","create_version",
              "extract_version","flag_bits","volume","internal_attr","external_attr"):
        setattr(o, a, getattr(i, a))
    return o

def main():
    base = sorted(OUT_DIR.glob("arc1_v242_tight_TEST_ONLY_*.zip"))[-1]
    with ZipFile(base) as z:
        infos = z.infolist(); before = {i.filename: z.read(i.filename) for i in infos}
    members = dict(before); exe = bytearray(members["PSX.EXE"]); ok = set(); done = []
    for site, op, old, new in EDITS:
        w = struct.unpack_from("<I", exe, site - R2F)[0]
        if (w >> 26) != op or (w & 0xFFFF) != old:
            raise SystemExit(f"0x{site:08X} is {w:08X}, expected op {op:#x} imm {old}")
        n = (w & ~0xFFFF) | new
        struct.pack_into("<I", exe, site - R2F, n)
        ok.update(range(site - R2F, site - R2F + 4)); done.append((site, w, n))
    members["PSX.EXE"] = bytes(exe)
    if [n for n in members if members[n] != before[n]] != ["PSX.EXE"]:
        raise SystemExit("unexpected changed members")
    diffs = [o for o,(x,y) in enumerate(zip(before["PSX.EXE"], members["PSX.EXE"])) if x != y]
    if not diffs or any(o not in ok for o in diffs):
        raise SystemExit(f"changed outside guarded fields: {diffs[:8]}")
    tmp = OUT_DIR / f"{STEM}_building.zip"
    if tmp.exists(): raise SystemExit("temp exists")
    with ZipFile(tmp, "w", ZIP_DEFLATED) as z:
        for i in infos: z.writestr(clone(i), members[i.filename])
    stamp = hashlib.sha256(tmp.read_bytes()).hexdigest().upper()
    out = OUT_DIR / f"{STEM}_{stamp[:8]}.zip"
    tmp.replace(out)
    print("v243 TEST ONLY - half-width back to 6, letter step 13")
    print(f"  base={base.name}\n  output={out.name}\n  sha256={stamp}")
    for s,w,n in done: print(f"  0x{s:08X}  {w:08X} -> {n:08X}")
    print(f"  PSX_changed_bytes={len(diffs)}   COMM/DAT unchanged")

if __name__ == "__main__": main()
