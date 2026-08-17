"""Build v241: bring the half-width advance up from 6px to 8px.

v240 moved the glyph cell to 16px but left the half-width step at 6, which was
half of the old 12px cell.  Spaces and half-width runs therefore came out too
tight against the new letters.

    8016BEF4  addiu t0, t0, 6  ->  8
    8016BEFC  addiu t1, t1, 6  ->  8

Both sit behind `andi v0, a3, 1 ; beqz v0, ...`, the half-width branch.  The
full-width step is the 16px cell handled in v238, so these two are the only
places the old 12px geometry still shows.
"""
from __future__ import annotations
import hashlib, struct, sys
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo
ROOT = Path(__file__).resolve().parents[1]
try: sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception: pass
OUT_DIR = ROOT / "03_output"
STEM = "arc1_v241_halfwidth_TEST_ONLY"
R2F = 0x8011A800
SITES = (0x8016BEF4, 0x8016BEFC)
OLD, NEW = 6, 8

def clone(i):
    o = ZipInfo(i.filename, i.date_time)
    for a in ("compress_type","comment","extra","create_system","create_version",
              "extract_version","flag_bits","volume","internal_attr","external_attr"):
        setattr(o, a, getattr(i, a))
    return o

def main():
    base = sorted(OUT_DIR.glob("arc1_v240_johab_font_TEST_ONLY_*.zip"))[-1]
    with ZipFile(base) as z:
        infos = z.infolist(); before = {i.filename: z.read(i.filename) for i in infos}
    members = dict(before); exe = bytearray(members["PSX.EXE"]); edits = []
    for a in SITES:
        w = struct.unpack_from("<I", exe, a - R2F)[0]
        if (w >> 26) != 0x09 or (w & 0xFFFF) != OLD:
            raise SystemExit(f"0x{a:08X} is {w:08X}, not `addiu rt,rs,6`")
        n = (w & ~0xFFFF) | NEW
        struct.pack_into("<I", exe, a - R2F, n); edits.append((a, w, n))
    members["PSX.EXE"] = bytes(exe)
    if [n for n in members if members[n] != before[n]] != ["PSX.EXE"]:
        raise SystemExit("unexpected changed members")
    diffs = [o for o,(x,y) in enumerate(zip(before["PSX.EXE"], members["PSX.EXE"])) if x != y]
    ok = set()
    for a,_,_ in edits: ok.update(range(a-R2F, a-R2F+4))
    if not diffs or any(o not in ok for o in diffs):
        raise SystemExit(f"changed outside guarded fields: {diffs[:8]}")
    tmp = OUT_DIR / f"{STEM}_building.zip"
    if tmp.exists(): raise SystemExit("temp exists")
    with ZipFile(tmp, "w", ZIP_DEFLATED) as z:
        for i in infos: z.writestr(clone(i), members[i.filename])
    stamp = hashlib.sha256(tmp.read_bytes()).hexdigest().upper()
    out = OUT_DIR / f"{STEM}_{stamp[:8]}.zip"
    tmp.replace(out)
    print(f"v241 TEST ONLY - half-width advance {OLD} -> {NEW}")
    print(f"  base={base.name}\n  output={out.name}\n  sha256={stamp}")
    for a,w,n in edits: print(f"  0x{a:08X}  {w:08X} -> {n:08X}")
    print(f"  PSX_changed_bytes={len(diffs)}   COMM/DAT unchanged")

if __name__ == "__main__": main()
