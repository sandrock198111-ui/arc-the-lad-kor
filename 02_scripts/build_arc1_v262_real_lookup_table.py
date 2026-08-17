"""Build v262: edit the lookup table the game actually reads.

Every build from v260 on edited 0x801A8FD4, and the game never looks at it.  The
resident dispatcher at 0x801FF448 calls 0x801A77F4, and that routine reads
0x801A7520 as an 11-bit packed table:

    bit    = slot * 11
    value  = (three bytes at bit/8) >> (bit%8)  &  0x7FF

The dispatcher then decides on the value alone:

    value <  0x600   ->  glyph index, drawn straight from the atlas
    value >= 0x600   ->  value - 0x600 is a cache request

So a glyph becomes resident by having a picture in a free cell below index 1536
and having its table entry point there.  No DAT byte changes, no renumbering of
the script, and the range table at 0x801A74C0 is not involved on this path.

    413 entries       104 already static, 309 go to the cache
    238 free cells below 1536   ->  238 of the 309 can be made static
    the remaining 71 keep using the cache, which stays in place

Pictures come from v151, the last build where these glyphs were static pixels.
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
from audit_dynamic_cache_requirements import glyph_index           # noqa: E402
import build_arc1_v231_static_promotion_restored162 as v231        # noqa: E402

OUT = ROOT / "03_output"
V151 = OUT / "arc1_v151_free_the_sprite_cell_A4358FEE.zip"
STEM = "arc1_v262_real_lookup_TEST_ONLY"
ANALYSIS = ROOT / "01_work/analysis/arc1_v262_real_lookup"
PSX, COMM = "PSX.EXE", "COMM.IMG"
R2F = 0x8011A800
TABLE = 0x801A7520          # what 0x801A77F4 reads
SLOTS = 0x19D               # 413, the bound checked at 0x801FF43C
STATIC_MAX = 0x600          # below this the value is a glyph index
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
    v = exe[at] | (exe[at + 1] << 8) | (exe[at + 2] << 16)
    return (v >> off) & 0x7FF


def tset(exe: bytearray, slot: int, value: int) -> None:
    if not 0 <= value <= 0x7FF:
        raise ValueError(value)
    bit = slot * 11
    byt, off = divmod(bit, 8)
    at = TABLE - R2F + byt
    v = exe[at] | (exe[at + 1] << 8) | (exe[at + 2] << 16)
    v = (v & ~(0x7FF << off)) | (value << off)
    exe[at] = v & 0xFF
    exe[at + 1] = (v >> 8) & 0xFF
    exe[at + 2] = (v >> 16) & 0xFF


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
    base_path = sorted(OUT.glob("arc1_v235_cache_row36_TEST_ONLY_*.zip"))[-1]
    with ZipFile(base_path) as z:
        infos = z.infolist()
        before = {i.filename: z.read(i.filename) for i in infos}
    with ZipFile(V151) as z:
        v151 = {n: z.read(n) for n in z.namelist()}
    members = dict(before)
    exe = bytearray(members[PSX])
    font = bytearray(members[COMM])
    f151 = v151[COMM]

    # how often the script asks for each E9/EA slot
    lut_old = struct.unpack_from(f"<{LOOKUP_N}H", members[PSX], LOOKUP_SRC - RAM_TO_FILE)
    uses = collections.Counter()
    referenced = set()
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
            g = glyph_index(tok, lut_old)
            if g is not None:
                referenced.add(g)
            if w == 2 and b in (0xE9, 0xEA):
                slot = (b - 0xE9) * 254 + d[i + 1] - 1
                if 0 <= slot < SLOTS:
                    uses[slot] += 1
            i += w

    values = [tget(bytes(exe), s) for s in range(SLOTS)]
    taken = {v for v in values if v < STATIC_MAX}
    inked = {i for i in range(STATIC_MAX) if (r := read(bytes(font), i)) and any(r)}
    free = [i for i in range(STATIC_MAX)
            if i not in inked and i not in referenced and i not in taken]

    dynamic = [s for s in range(SLOTS) if values[s] >= STATIC_MAX]
    order = sorted(dynamic, key=lambda s: -uses[s])
    moved = []
    skipped_nopic = 0
    for slot in order:
        if not free:
            break
        pic = read(f151, tget(v151[PSX], slot)) if tget(v151[PSX], slot) < STATIC_MAX else None
        if not pic or not any(pic):
            skipped_nopic += 1
            continue
        dest = free.pop(0)
        put(font, dest, pic)
        tset(exe, slot, dest)
        moved.append((slot, dest, uses[slot]))

    members[PSX] = bytes(exe)
    members[COMM] = bytes(font)
    for n in members:
        if len(members[n]) != len(before[n]):
            raise SystemExit(f"{n} size changed")
    changed = sorted(n for n in members if members[n] != before[n])
    if changed != sorted([PSX, COMM]):
        raise SystemExit(f"unexpected changed members: {changed}")
    for slot, dest, _ in moved:
        if tget(bytes(exe), slot) != dest:
            raise SystemExit(f"table readback failed at slot {slot}")

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

    still = len(dynamic) - len(moved)
    rep = [
        "v262 TEST ONLY - the table the game actually reads (0x801A7520, 11-bit packed)",
        f"base={base_path.name}   pictures_from={V151.name}",
        f"output={out.name}", f"sha256={st}",
        "release_status=DIAGNOSTIC; DO NOT DISTRIBUTE",
        f"table slots={SLOTS}   were static={SLOTS - len(dynamic)}   were cached={len(dynamic)}",
        f"made static now={len(moved)}   still cached={still}"
        f"   (no picture in v151: {skipped_nopic})",
        f"script uses now resident={sum(n for _, _, n in moved):,}"
        f"   still via cache={sum(uses[s] for s in dynamic) - sum(n for _, _, n in moved):,}",
        f"free cells below {STATIC_MAX} remaining={len(free)}",
        "DAT files byte-identical; script not renumbered",
        "runtime=PENDING user cold boot",
    ]
    ANALYSIS.mkdir(parents=True, exist_ok=True)
    (ANALYSIS / "build_report.txt").write_text("\n".join(rep) + "\n", encoding="utf-8")
    print("\n".join(rep))


if __name__ == "__main__":
    main()
