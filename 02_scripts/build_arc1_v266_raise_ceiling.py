"""Build v264: make every cached glyph resident, using the game's own pixels.

The compressed glyphs are now decodable (decode_cache_glyphs.py reproduces the
routine at 0x801FF580), so all 309 cache entries have exact pictures -- no
guessing, no borrowing from v151, no character identification.

Placement rule, read off the dispatcher at 0x801FF464:

    table value <  0x600   ->  glyph index, drawn from the atlas
    table value >= 0x600   ->  cache request

So every entry needs a free cell below 1536 holding its decoded picture.

Occupancy is decided with the table the game actually reads.  v263 used
glyph_index(), which resolves E9/EA through 0x801A8FD4 -- a table the game
ignores -- and so counted live cells as unused and overwrote a working glyph.
Here E9/EA is resolved through 0x801A7520 like the hardware does.
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
import build_arc1_v231_static_promotion_restored162 as v231  # noqa: E402

OUT = ROOT / "03_output"
GLYPHS = ROOT / "01_work/analysis/cache_glyphs/glyphs.pkl"
STEM = "arc1_v266_raise_ceiling_TEST_ONLY"
ANALYSIS = ROOT / "01_work/analysis/arc1_v266_raise_ceiling"
PSX, COMM = "PSX.EXE", "COMM.IMG"
R2F = 0x8011A800
TABLE, SLOTS = 0x801A7520, 0x19D
CACHE_MARK = 0x600            # value >= this is a cache request today
STATIC_MAX = 0x7FF            # ceiling after the patch; 0x7FF stays 'absent'
RES_SRC, RES_BASE = 0x801A86EC, 0x801FE3C4
GATE_AT = 0x801FF464          # sltiu t5, t4, 0x600
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
    b = slot * 11
    byt, off = divmod(b, 8)
    a = TABLE - R2F + byt
    return ((exe[a] | (exe[a + 1] << 8) | (exe[a + 2] << 16)) >> off) & 0x7FF


def tset(exe: bytearray, slot: int, value: int) -> None:
    b = slot * 11
    byt, off = divmod(b, 8)
    a = TABLE - R2F + byt
    v = exe[a] | (exe[a + 1] << 8) | (exe[a + 2] << 16)
    v = (v & ~(0x7FF << off)) | (value << off)
    exe[a], exe[a + 1], exe[a + 2] = v & 0xFF, (v >> 8) & 0xFF, (v >> 16) & 0xFF


def index_of(tok: bytes, exe: bytes) -> int | None:
    """Glyph index exactly as the dispatcher at 0x801FF348 computes it."""
    if len(tok) == 1:
        return tok[0] - 1 if 0x01 <= tok[0] <= 0xDC else None
    lead, trail = tok
    if lead in (0xE9, 0xEA):
        slot = (lead - 0xE9) * 254 + trail - 1
        if not 0 <= slot < SLOTS:
            return None
        v = tget(exe, slot)
        return v if v < CACHE_MARK else None       # >= 0x600 is a cache request
    if 0xDD <= lead <= 0xE8 and 0x01 <= trail <= 0xFE:
        return (lead - 0xDD) * 255 + trail + 0xDB
    return None


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
        src = rows[y] if y < len(rows) else 0
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
    members = dict(before)
    exe = bytearray(members[PSX])
    font = bytearray(members[COMM])
    decoded = pickle.load(open(GLYPHS, "rb"))

    # The 0x600 ceiling is a single immediate.  Raising it to 0x7FF turns the
    # whole 11-bit range into glyph indices and leaves no cache path at all.
    gate = RES_SRC - R2F + (GATE_AT - RES_BASE)
    w = struct.unpack_from("<I", exe, gate)[0]
    if (w >> 26) != 0x0B or (w & 0xFFFF) != 0x600:
        raise SystemExit(f"gate site is {w:08X}, not `sltiu rt,rs,0x600`")
    struct.pack_into("<I", exe, gate, (w & ~0xFFFF) | STATIC_MAX)
    # from here on, "cached" means the value the table still holds, not the new gate

    # every index the script can reach, resolved the way the hardware does
    reachable = collections.Counter()
    for name, s, e in v231.text_regions(before):
        d = before[name]
        i = s
        while i < e:
            b = d[i]
            if b == 0xE2 or 0xE3 <= b <= 0xE8:
                i += 2
                continue
            w = 1 if b < 0xDD else 2
            g = index_of(bytes(d[i:i + w]), bytes(exe))
            if g is not None:
                reachable[g] += 1
            i += w

    table_cells = {tget(bytes(exe), s) for s in range(SLOTS)
                   if tget(bytes(exe), s) < CACHE_MARK}
    reserved = v231.range_table_indices(bytes(exe))
    inked = {i for i in range(STATIC_MAX) if (r := read(bytes(font), i)) and any(r)}
    free = [i for i in range(STATIC_MAX)
            if i not in inked and i not in reachable and i not in table_cells
            and i not in reserved]
    # cells that hold a picture nothing can reach -- safe to reuse, and this
    # time "reachable" was resolved through 0x801A7520 like the hardware does
    reclaim = [i for i in range(STATIC_MAX)
               if i in inked and i not in reachable and i not in table_cells
               and i not in reserved]
    free += reclaim

    todo = [s for s in range(SLOTS) if tget(bytes(exe), s) >= CACHE_MARK]
    placed, missing = [], 0
    for slot in todo:
        rows = decoded.get(slot)
        if not rows or not any(rows):
            missing += 1
            continue
        if not free:
            break
        dest = free.pop(0)
        put(font, dest, rows)
        tset(exe, slot, dest)
        placed.append((slot, dest))

    members[PSX] = bytes(exe)
    members[COMM] = bytes(font)
    for n in members:
        if len(members[n]) != len(before[n]):
            raise SystemExit(f"{n} size changed")
    changed = sorted(n for n in members if members[n] != before[n])
    if changed != sorted([PSX, COMM]):
        raise SystemExit(f"unexpected changed members: {changed}")
    for slot, dest in placed:
        if tget(bytes(exe), slot) != dest:
            raise SystemExit(f"table readback failed at slot {slot}")
        if read(bytes(font), dest) != decoded[slot][:CELL]:
            raise SystemExit(f"pixel readback failed at cell {dest}")
    # nothing that was visible before may have moved
    for i in sorted(inked):
        if i in reachable and read(bytes(font), i) != read(before[COMM], i):
            raise SystemExit(f"overwrote a reachable glyph: {i}")

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

    left = len(todo) - len(placed)
    n_static = sum(1 for s in range(SLOTS) if tget(bytes(exe), s) < CACHE_MARK)
    rep = [
        "v266 TEST ONLY - static ceiling raised 0x600 -> 0x7FF, cache path unused",
        f"base={base_path.name}   pixels=decoded from the resident Huffman stream",
        f"output={out.name}", f"sha256={st}",
        "release_status=DIAGNOSTIC; DO NOT DISTRIBUTE",
        f"entries that used the cache={len(todo)}   placed={len(placed)}   "
        f"still cached={left}   (no decoded pixels: {missing})",
        f"table now static={n_static}/{SLOTS}",
        f"free cells below {STATIC_MAX} left={len(free)}   reclaimed unreachable={len(reclaim)}",
        "occupancy resolved through 0x801A7520, the table the game reads",
        "verified: no glyph the script can reach was overwritten",
        "DAT files byte-identical; script not renumbered",
        "runtime=PENDING user cold boot",
    ]
    ANALYSIS.mkdir(parents=True, exist_ok=True)
    (ANALYSIS / "build_report.txt").write_text("\n".join(rep) + "\n", encoding="utf-8")
    print("\n".join(rep))


if __name__ == "__main__":
    main()
