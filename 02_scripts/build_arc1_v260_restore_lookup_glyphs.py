"""Build v260: bring the lookup-table glyphs back into the atlas as static pixels.

The world map has been destroying text since v197 because 300-odd glyphs are not
resident: the runtime decompresses them into a small VRAM rectangle on demand,
and the world map loads its own texture over that rectangle.  Every attempt to
move the rectangle failed, and moving to a 16px johab atlas failed for a
different reason -- renumbering the glyphs means rewriting the script, and only
2878 of the 60000-odd dialogue sites are known.

This build renumbers nothing.  v151 was the last build where these glyphs lived
as static pixels, so their pictures still exist; the atlas still has 870 empty
cells; and the E9/EA codes reach the atlas through a 508-entry lookup table in
PSX.EXE.  Copying a picture into an empty cell and pointing its lookup entry at
that cell leaves every byte of every DAT file untouched.

    271 lookup glyphs   picture carried from v151, lookup entry repointed
     87 direct glyphs   picture restored at its existing index, no table change

What stays behind: 47 lookup glyphs with no picture in v151 either, and 13
direct codes whose pictures were never static.  Those still need the cache, so
the cache is left in place here -- this build reduces the pressure on it and is
verified before the cache itself is removed.
"""
from __future__ import annotations
import collections
import hashlib
import struct
import sys
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))
sys.path.insert(0, str(ROOT / "06_tools/python_packages"))
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass
from plan_bulk_insertion import LOOKUP_N, LOOKUP_SRC, RAM_TO_FILE  # noqa: E402
import build_arc1_v231_static_promotion_restored162 as v231        # noqa: E402

OUT = ROOT / "03_output"
V151 = OUT / "arc1_v151_free_the_sprite_cell_A4358FEE.zip"
STEM = "arc1_v260_restore_lookup_TEST_ONLY"
ANALYSIS = ROOT / "01_work/analysis/arc1_v260_restore_lookup"
PSX, COMM = "PSX.EXE", "COMM.IMG"
ROW, CELL, COLS, PL = 896, 12, 21, 4
ROWS = 42


def digest(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest().upper()


def clone(i: ZipInfo) -> ZipInfo:
    o = ZipInfo(i.filename, i.date_time)
    for a in ("compress_type", "comment", "extra", "create_system", "create_version",
              "extract_version", "flag_bits", "volume", "internal_attr", "external_attr"):
        setattr(o, a, getattr(i, a))
    return o


def read(font: bytes, idx: int) -> list[int] | None:
    cell, pl = divmod(idx, PL)
    col, row = cell % COLS, cell // COLS
    if row >= ROWS:
        return None
    out = []
    for y in range(CELL):
        b = (row * CELL + y) * ROW + col * (CELL // 2)
        v = 0
        for x in range(CELL):
            if (font[b + x // 2] >> (0 if x % 2 == 0 else 4)) & 0x0F & (1 << pl):
                v |= 1 << (CELL - 1 - x)
        out.append(v)
    return out


def write(font: bytearray, idx: int, rows: list[int]) -> None:
    cell, pl = divmod(idx, PL)
    col, row = cell % COLS, cell // COLS
    bit = 1 << pl
    for y in range(CELL):
        base = (row * CELL + y) * ROW + col * (CELL // 2)
        src = rows[y]
        for x in range(CELL):
            at = base + x // 2
            sh = 0 if x % 2 == 0 else 4
            nib = (font[at] >> sh) & 0x0F
            nib = (nib | bit) if (src >> (CELL - 1 - x)) & 1 else (nib & ~bit & 0x0F)
            font[at] = (font[at] & (0xF0 if sh == 0 else 0x0F)) | (nib << sh)


def main() -> None:
    base_path = sorted(OUT.glob("arc1_v235_cache_row36_TEST_ONLY_*.zip"))[-1]
    with ZipFile(base_path) as z:
        infos = z.infolist()
        before = {i.filename: z.read(i.filename) for i in infos}
    with ZipFile(V151) as z:
        v151 = {n: z.read(n) for n in z.namelist()}
    members = dict(before)
    f151 = v151[COMM]
    font = bytearray(members[COMM])
    lut_cur = list(struct.unpack_from(f"<{LOOKUP_N}H", members[PSX], LOOKUP_SRC - RAM_TO_FILE))
    lut_151 = struct.unpack_from(f"<{LOOKUP_N}H", v151[PSX], LOOKUP_SRC - RAM_TO_FILE)

    # which E9/EA codes the script actually uses, and how often
    uses = collections.Counter()
    for name, s, e in v231.text_regions(before):
        d = before[name]
        i = s
        while i < e:
            b = d[i]
            if b == 0xE2 or 0xE3 <= b <= 0xE8:
                i += 2
                continue
            w = 1 if b < 0xDD else 2
            if w == 2 and b in (0xE9, 0xEA):
                uses[bytes(d[i:i + w])] += 1
            i += w

    # cells the atlas is not using, and cells the range table reserves
    reserved = v231.range_table_indices(members[PSX])
    occupied = set()
    for idx in range(COLS * ROWS * PL):
        r = read(bytes(font), idx)
        if r and any(r):
            occupied.add(idx)
    free = [i for i in range(COLS * ROWS * PL)
            if i not in occupied and i not in reserved]

    moved = []
    restored = 0
    for tok, n in sorted(uses.items(), key=lambda kv: -kv[1]):
        slot = (tok[0] - 0xE9) * 254 + tok[1] - 1
        if not (0 <= slot < LOOKUP_N):
            continue
        here = read(bytes(font), lut_cur[slot])
        if here and any(here):
            continue                       # already resident, leave it alone
        pic = read(f151, lut_151[slot])
        if not pic or not any(pic):
            continue                       # no picture anywhere; still needs the cache
        if lut_cur[slot] < COLS * ROWS * PL and lut_cur[slot] not in occupied \
                and lut_cur[slot] not in reserved:
            dest = lut_cur[slot]           # its own cell is empty -- just fill it
        else:
            if not free:
                break
            dest = free.pop(0)
        write(font, dest, pic)
        occupied.add(dest)
        if dest != lut_cur[slot]:
            lut_cur[slot] = dest
            moved.append((slot, dest, n))
        else:
            restored += 1

    struct.pack_into(f"<{LOOKUP_N}H", (exe := bytearray(members[PSX])),
                     LOOKUP_SRC - RAM_TO_FILE, *lut_cur)
    members[PSX] = bytes(exe)
    members[COMM] = bytes(font)
    for n in members:
        if len(members[n]) != len(before[n]):
            raise SystemExit(f"{n} size changed")
    changed = [n for n in members if members[n] != before[n]]
    if sorted(changed) != sorted([PSX, COMM]):
        raise SystemExit(f"unexpected changed members: {changed}")

    OUT.mkdir(parents=True, exist_ok=True)
    tmp = OUT / f"{STEM}_building.zip"
    if tmp.exists():
        raise SystemExit("temp exists")
    with ZipFile(tmp, "w", ZIP_DEFLATED) as z:
        for i in infos:
            z.writestr(clone(i), members[i.filename])
    st = digest(tmp.read_bytes())
    out = OUT / f"{STEM}_{st[:8]}.zip"
    tmp.replace(out)

    covered = sum(n for _, _, n in moved) + restored
    rep = [
        "v260 TEST ONLY - lookup glyphs restored as static atlas pixels",
        f"base={base_path.name}   pictures_from={V151.name}",
        f"output={out.name}", f"sha256={st}",
        "release_status=DIAGNOSTIC; DO NOT DISTRIBUTE",
        f"lookup codes used by the script={len(uses)}",
        f"repointed to a free cell={len(moved)}   filled in place={restored}",
        f"script uses covered={covered:,}",
        f"free cells before={len(free) + len(moved)}   after={len(free)}",
        "DAT files byte-identical; only COMM.IMG and the lookup table changed",
        "cache left in place: this build reduces its load, it does not remove it",
        "runtime=PENDING user cold boot",
    ]
    ANALYSIS.mkdir(parents=True, exist_ok=True)
    (ANALYSIS / "build_report.txt").write_text("\n".join(rep) + "\n", encoding="utf-8")
    print("\n".join(rep))


if __name__ == "__main__":
    main()
