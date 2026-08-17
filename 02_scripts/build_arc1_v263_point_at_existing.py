"""Build v263: finish the cache-free conversion by reusing glyphs already present.

v262 made 238 of the 309 cached entries static and the improvement showed on
screen -- dialogue reads, with only the last few characters of a line broken.
Those are the 71 entries still pointing above 0x600.

Two ways to finish, cheapest first:

    1. the same character already sits somewhere in the atlas below 1536
       -> just point the table entry at that cell.  No pixels move at all.
    2. otherwise reclaim one of the 167 cells that hold a picture the script
       never asks for, and copy the v151 picture into it.

Character identity comes from code_map_voted.pkl, built by aligning the script
against the Korean the translation files already hold (513 codes, 75%+ agreement
required).  Where identity is unknown and v151 has no picture, the entry keeps
using the cache -- guessing is what produced the wrong glyphs back in v231.

DAT files are untouched; only COMM.IMG and the packed table at 0x801A7520 change.
"""
from __future__ import annotations
import collections
import hashlib
import pickle
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
from audit_dynamic_cache_requirements import glyph_index           # noqa: E402
import build_arc1_v231_static_promotion_restored162 as v231        # noqa: E402

OUT = ROOT / "03_output"
V151 = OUT / "arc1_v151_free_the_sprite_cell_A4358FEE.zip"
MAP = ROOT / "01_work/analysis/hangul_johab_16px/code_map_voted.pkl"
STEM = "arc1_v263_point_existing_TEST_ONLY"
ANALYSIS = ROOT / "01_work/analysis/arc1_v263_point_existing"
PSX, COMM = "PSX.EXE", "COMM.IMG"
R2F = 0x8011A800
TABLE, SLOTS, STATIC_MAX = 0x801A7520, 0x19D, 0x600
ROW, CELL, COLS, ROWS, PL = 896, 12, 21, 42, 4


def digest(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest().upper()


def clone(i: ZipInfo) -> ZipInfo:
    o = ZipInfo(i.filename, i.date_time)
    for a in ("compress_type", "comment", "extra", "create_system", "create_version",
              "extract_version", "flag_bits", "volume", "internal_attr", "external_attr"):
        setattr(o, a, getattr(i, a))
    return o


def tget(exe: bytes, slot: int) -> int:
    bit = slot * 11
    byt, off = divmod(bit, 8)
    at = TABLE - R2F + byt
    return ((exe[at] | (exe[at + 1] << 8) | (exe[at + 2] << 16)) >> off) & 0x7FF


def tset(exe: bytearray, slot: int, value: int) -> None:
    bit = slot * 11
    byt, off = divmod(bit, 8)
    at = TABLE - R2F + byt
    v = exe[at] | (exe[at + 1] << 8) | (exe[at + 2] << 16)
    v = (v & ~(0x7FF << off)) | (value << off)
    exe[at], exe[at + 1], exe[at + 2] = v & 0xFF, (v >> 8) & 0xFF, (v >> 16) & 0xFF


def slot_token(slot: int) -> bytes:
    lead, trail = 0xE9 + slot // 254, slot % 254 + 1
    return bytes((lead, trail))


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


def put(font: bytearray, idx: int, rows: list[int]) -> None:
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
    base_path = sorted(OUT.glob("arc1_v262_real_lookup_TEST_ONLY_*.zip"))[-1]
    with ZipFile(base_path) as z:
        infos = z.infolist()
        before = {i.filename: z.read(i.filename) for i in infos}
    with ZipFile(V151) as z:
        v151 = {n: z.read(n) for n in z.namelist()}
    members = dict(before)
    exe = bytearray(members[PSX])
    font = bytearray(members[COMM])
    decoded = pickle.load(open(MAP, "rb")) if MAP.exists() else {}

    lut = struct.unpack_from(f"<{LOOKUP_N}H", members[PSX], LOOKUP_SRC - RAM_TO_FILE)
    uses = collections.Counter()
    char_at = {}
    for name, s, e in v231.text_regions(before):
        d = before[name]
        i = s
        while i < e:
            b = d[i]
            if b == 0xE2 or 0xE3 <= b <= 0xE8:
                i += 2
                continue
            w = 1 if b < 0xDD else 2
            tok = bytes(d[i:i + w])
            g = glyph_index(tok, lut)
            if g is not None:
                uses[g] += 1
                ch = decoded.get(tok)
                if ch and g < STATIC_MAX and (r := read(bytes(font), g)) and any(r):
                    char_at.setdefault(ch, g)
            i += w

    table_cells = {tget(bytes(exe), s) for s in range(SLOTS) if tget(bytes(exe), s) < STATIC_MAX}
    reclaimable = [i for i in range(STATIC_MAX)
                   if (r := read(bytes(font), i)) and any(r)
                   and uses.get(i, 0) == 0 and i not in table_cells]
    empty = [i for i in range(STATIC_MAX)
             if not ((r := read(bytes(font), i)) and any(r))
             and uses.get(i, 0) == 0 and i not in table_cells]
    free = empty + reclaimable

    still = [s for s in range(SLOTS) if tget(bytes(exe), s) >= STATIC_MAX]
    by_reuse = by_copy = 0
    left = []
    for slot in still:
        tok = slot_token(slot)
        ch = decoded.get(tok)
        if ch and ch in char_at:
            tset(exe, slot, char_at[ch])
            by_reuse += 1
            continue
        src = tget(v151[PSX], slot)
        pic = read(v151[COMM], src) if src < STATIC_MAX else None
        if pic and any(pic) and free:
            dest = free.pop(0)
            put(font, dest, pic)
            tset(exe, slot, dest)
            by_copy += 1
            continue
        left.append(slot)

    members[PSX] = bytes(exe)
    members[COMM] = bytes(font)
    for n in members:
        if len(members[n]) != len(before[n]):
            raise SystemExit(f"{n} size changed")
    changed = sorted(n for n in members if members[n] != before[n])
    if changed and changed != sorted([PSX, COMM]):
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

    n_static = sum(1 for s in range(SLOTS) if tget(bytes(exe), s) < STATIC_MAX)
    rep = [
        "v263 TEST ONLY - remaining cached entries pointed at real glyphs",
        f"base={base_path.name}   pictures_from={V151.name}",
        f"output={out.name}", f"sha256={st}",
        "release_status=DIAGNOSTIC; DO NOT DISTRIBUTE",
        f"entries still cached at start={len(still)}",
        f"reused a glyph already in the atlas={by_reuse}   copied from v151={by_copy}",
        f"still cached={len(left)}",
        f"table now static={n_static}/{SLOTS}",
        f"cells reclaimed from unused pictures={len(reclaimable)}   free left={len(free)}",
        "DAT files byte-identical; script not renumbered",
        "runtime=PENDING user cold boot",
    ]
    ANALYSIS.mkdir(parents=True, exist_ok=True)
    (ANALYSIS / "build_report.txt").write_text("\n".join(rep) + "\n", encoding="utf-8")
    print("\n".join(rep))


if __name__ == "__main__":
    main()
