"""Build v268: 16px atlas re-encode over the complete dialogue site list.

v258 did exactly this and failed for one reason: text_regions() only knows the
2878 sites recorded in script_original_full.csv, so two thirds of the script kept
its old code numbers and rendered as kanji.  dialogue_sites_full.csv now lists
39,457 sites, found from the file structure itself -- every DAT is 0x4A800 long
and holds 176 slots of 128 bytes from 0x45000, each holding null-terminated
dialogue.  Nothing is guessed.

Pictures need no decoding either:

    the old atlas has the glyph      -> copy the 12x12 into the new cell
    it was a cache glyph             -> use the pixels decoded from the
                                        resident Huffman stream (309 of them,
                                        decode_cache_glyphs.py, zero failures)

Widths are preserved, so pointers, body lengths and file sizes never move.  The
new atlas is 15 columns (row stride 84 -> 60) which is what the 16px cell needs
to stay inside the 255px U limit.
"""
from __future__ import annotations
import collections
import csv
import hashlib
import pickle
import struct
import sys
import time
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))
sys.path.insert(0, str(ROOT / "06_tools/python_packages"))
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

OUT = ROOT / "03_output"
SITES = ROOT / "05_docs/dialogue_sites_full.csv"
CACHE_PIX = ROOT / "01_work/analysis/cache_glyphs/glyphs.pkl"
STEM = "arc1_v268_full_sites_TEST_ONLY"
ANALYSIS = ROOT / "01_work/analysis/arc1_v268_full_sites"
PSX, COMM = "PSX.EXE", "COMM.IMG"
R2F = 0x8011A800
ROW = 896
OLDC, OLDCOLS = 12, 21
NEWC, COLS, PL = 16, 15, 4
ONE_MAX = 220
STRIDE_AT, OLD_STRIDE = 0x8016B530, 84
TABLE, SLOTS, CACHE_MARK = 0x801A7520, 0x19D, 0x600


def digest(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest().upper()


def clone(i: ZipInfo) -> ZipInfo:
    o = ZipInfo(i.filename, i.date_time)
    for a in ("compress_type", "comment", "extra", "create_system", "create_version",
              "extract_version", "flag_bits", "volume", "internal_attr", "external_attr"):
        setattr(o, a, getattr(i, a))
    return o


def encode(ix: int) -> bytes | None:
    if 0 <= ix < ONE_MAX:
        return bytes((ix + 1,))
    rel = ix - 0xDB
    lead, trail = divmod(rel, 255)
    if not (0 <= lead <= 3 and 1 <= trail <= 254):
        return None
    return bytes((0xDD + lead, trail))


def tget(exe: bytes, slot: int) -> int:
    b = slot * 11
    byt, off = divmod(b, 8)
    a = TABLE - R2F + byt
    return ((exe[a] | (exe[a + 1] << 8) | (exe[a + 2] << 16)) >> off) & 0x7FF


def index_of(tok: bytes, exe: bytes) -> tuple[int | None, int | None]:
    """(atlas index, cache slot) as the dispatcher computes it."""
    if len(tok) == 1:
        return (tok[0] - 1, None) if 0x01 <= tok[0] <= 0xDC else (None, None)
    lead, trail = tok
    if lead in (0xE9, 0xEA):
        s = (lead - 0xE9) * 254 + trail - 1
        if not 0 <= s < SLOTS:
            return None, None
        v = tget(exe, s)
        return (v, None) if v < CACHE_MARK else (None, s)
    if 0xDD <= lead <= 0xE8 and 0x01 <= trail <= 0xFE:
        return (lead - 0xDD) * 255 + trail + 0xDB, None
    return None, None


def read_old(font: bytes, idx: int) -> list[int] | None:
    cell, pl = divmod(idx, PL)
    col, row = cell % OLDCOLS, cell // OLDCOLS
    if (row + 1) * OLDC > 504 or (col + 1) * OLDC > 252:
        return None
    out = []
    for y in range(OLDC):
        b = (row * OLDC + y) * ROW + col * (OLDC // 2)
        v = 0
        for x in range(OLDC):
            if (font[b + x // 2] >> (0 if x % 2 == 0 else 4)) & 0x0F & (1 << pl):
                v |= 1 << (NEWC - 1 - x)
        out.append(v)
    return out + [0] * (NEWC - OLDC)


def put(font: bytearray, idx: int, rows: list[int]) -> None:
    cell, pl = divmod(idx, PL)
    col, row = cell % COLS, cell // COLS
    bit = 1 << pl
    for y in range(NEWC):
        base = (row * NEWC + y) * ROW + col * (NEWC // 2)
        src = rows[y] if y < len(rows) else 0
        for x in range(NEWC):
            at = base + x // 2
            sh = 0 if x % 2 == 0 else 4
            nib = (font[at] >> sh) & 0x0F
            nib = (nib | bit) if (src >> (NEWC - 1 - x)) & 1 else (nib & ~bit & 0x0F)
            font[at] = (font[at] & (0xF0 if sh == 0 else 0x0F)) | (nib << sh)


def sites() -> dict[str, list[tuple[int, int]]]:
    out = collections.defaultdict(list)
    with SITES.open(encoding="utf-8-sig", newline="") as f:
        for r in csv.DictReader(f):
            out[r["file"]].append((int(r["offset"], 16), int(r["bytes"])))
    return out


def step(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def main() -> None:
    step("base 열기")
    base_path = sorted(OUT.glob("arc1_v238_glyph_16px_TEST_ONLY_*.zip"))[-1]
    with ZipFile(base_path) as z:
        infos = z.infolist()
        before = {i.filename: z.read(i.filename) for i in infos}
    members = dict(before)
    exe0 = bytes(members[PSX])
    oldfont = members[COMM]
    cache_pix = pickle.load(open(CACHE_PIX, "rb"))
    site_map = sites()
    step(f"사이트 {sum(len(v) for v in site_map.values()):,}곳 로드")

    # every token the script uses, over the complete site list
    uses = collections.Counter()
    width = collections.defaultdict(set)
    for name, spans in site_map.items():
        if name not in before:
            continue
        d = before[name]
        for off, ln in spans:
            i, end = off, min(off + ln, len(d))
            while i < end:
                b = d[i]
                if b == 0xE2 or 0xE3 <= b <= 0xE8:
                    i += 2
                    continue
                w = 1 if b < 0xDD else 2
                if i + w > end:
                    break
                tok = bytes(d[i:i + w])
                uses[tok] += 1
                width[tok].add(w)
                i += w

    step(f"토큰 {len(uses)}종 수집")
    art = {}
    from_atlas = from_cache = 0
    for tok in uses:
        gi, cs = index_of(tok, exe0)
        pic = None
        if gi is not None:
            pic = read_old(oldfont, gi)
            if pic and any(pic):
                from_atlas += 1
            else:
                pic = None
        elif cs is not None and cs in cache_pix:
            rows = cache_pix[cs]
            pic = [(r << 4) & 0xFFFF for r in rows] + [0] * (NEWC - len(rows))
            pic = [r for r in pic][:NEWC]
            if any(pic):
                from_cache += 1
            else:
                pic = None
        if pic:
            art[tok] = pic

    step(f"그림 {len(art)}종 확보")
    # Many codes carry the same picture -- repeated rebasing left duplicates.
    # Folding by picture takes 2634 codes down to about 1299 cells, which is
    # what makes the 16px atlas fit at all (44 rows would exceed 504px).
    shape = {t: tuple(art[t]) for t in art}
    pic_uses = collections.Counter()
    for t in art:
        pic_uses[shape[t]] += uses[t]
    pics1 = sorted({shape[t] for t in art if 1 in width[t]}, key=lambda p: -pic_uses[p])
    pics2 = sorted({shape[t] for t in art if 2 in width[t]}, key=lambda p: -pic_uses[p])
    if len(pics1) > ONE_MAX - 1:
        raise SystemExit(f"{len(pics1)} one-byte pictures exceed {ONE_MAX - 1}")
    p1 = {p: n for n, p in enumerate(pics1)}
    blank1 = len(pics1)
    nxt = ONE_MAX
    # Two-byte codes only reach index 1238 (lead 0xDD..0xE0, trail 1..254), so
    # the atlas cannot hold every distinct picture.  Least-used ones overflow to
    # the blank cell rather than looping forever looking for a code.
    LAST = 0xDB + 3 * 255 + 254
    p2 = {}
    overflow = []
    for p in pics2:
        while nxt <= LAST and encode(nxt) is None:
            nxt += 1
        if nxt > LAST - 1:
            overflow.append(p)
            continue
        p2[p] = nxt
        nxt += 1
    while nxt <= LAST and encode(nxt) is None:
        nxt += 1
    a1 = {t: p1[shape[t]] for t in art if 1 in width[t]}
    a2 = {t: p2[shape[t]] for t in art if 2 in width[t] and shape[t] in p2}
    blank2 = min(nxt, LAST)
    cells = -(-(nxt + 1) // PL)
    need = -(-cells // COLS)
    if COLS * NEWC > 252 or need * NEWC > 504:
        raise SystemExit(f"atlas {COLS * NEWC}x{need * NEWC} leaves the glyph area")

    step(f"고유 그림 {len(pics1)+len(pics2)}종, 배치 시작")
    font = bytearray(members[COMM])
    for y in range(need * NEWC):
        b = y * ROW
        font[b:b + COLS * (NEWC // 2)] = bytes(COLS * (NEWC // 2))
    for pic, ix in list(p1.items()) + list(p2.items()):
        put(font, ix, list(pic))

    step("아틀라스 기록 완료")
    remap = {}
    for t in uses:
        for w in width[t]:
            tbl = a1 if w == 1 else a2
            ix = tbl.get(t, blank1 if w == 1 else blank2)
            c = encode(ix)
            if c is None or len(c) != w:
                raise SystemExit(f"no {w}-byte code for index {ix}")
            remap[(t, w)] = c

    step("대본 재인코딩 시작")
    scratch = {n: bytearray(v) for n, v in before.items()}
    done = 0
    for name, spans in site_map.items():
        if name not in scratch:
            continue
        buf = scratch[name]
        for off, ln in spans:
            i, end = off, min(off + ln, len(buf))
            while i < end:
                b = buf[i]
                if b == 0xE2 or 0xE3 <= b <= 0xE8:
                    i += 2
                    continue
                w = 1 if b < 0xDD else 2
                if i + w > end:
                    break
                key = (bytes(buf[i:i + w]), w)
                if key in remap:
                    buf[i:i + w] = remap[key]
                    done += 1
                i += w

    step(f"코드 {done:,}개 교체")
    exe = bytearray(members[PSX])
    w0 = struct.unpack_from("<I", exe, STRIDE_AT - R2F)[0]
    if (w0 >> 26) != 0x0D or (w0 & 0xFFFF) != OLD_STRIDE:
        raise SystemExit(f"stride site is {w0:08X}")
    struct.pack_into("<I", exe, STRIDE_AT - R2F, (w0 & ~0xFFFF) | (COLS * PL))

    members[PSX] = bytes(exe)
    members[COMM] = bytes(font)
    for n, v in scratch.items():
        if n not in (PSX, COMM):
            members[n] = bytes(v)
    for n in members:
        if len(members[n]) != len(before[n]):
            raise SystemExit(f"{n} size changed")

    OUT.mkdir(parents=True, exist_ok=True)
    tmp = OUT / f"{STEM}_building.zip"
    if tmp.exists():
        raise SystemExit("temp exists")
    step("zip 압축 시작")
    with ZipFile(tmp, "w", ZIP_DEFLATED, compresslevel=1) as z:
        for i in infos:
            z.writestr(clone(i), members[i.filename])
    st = digest(tmp.read_bytes())
    out = OUT / f"{STEM}_{st[:8]}.zip"
    tmp.replace(out)

    covered = sum(uses[t] for t in art)
    tot = sum(uses.values())
    rep = [
        "v268 TEST ONLY - 16px atlas re-encoded over the full 39,457-site list",
        f"base={base_path.name}   sites={SITES.name}",
        f"output={out.name}", f"sha256={st}",
        "release_status=DIAGNOSTIC; DO NOT DISTRIBUTE",
        f"dialogue sites={sum(len(v) for v in site_map.values()):,}"
        f"   (previous list had 2,878)",
        f"tokens in script={len(uses)}   drawn={len(art)}"
        f"  (atlas {from_atlas}, decoded cache {from_cache})",
        f"script glyphs covered={covered:,}/{tot:,}  ({covered * 100 // max(tot,1)}%)",
        f"atlas={cells} cells, {COLS}x{need}, {COLS * NEWC}x{need * NEWC} px",
        f"distinct pictures {len(p1)+len(p2)}  (one-byte {len(p1)}, two-byte {len(p2)})"
        f"   codes rewritten={done:,}   overflowed to blank={len(overflow)}",
        "widths preserved; pointers and file sizes unchanged",
        "runtime=PENDING user cold boot",
    ]
    ANALYSIS.mkdir(parents=True, exist_ok=True)
    (ANALYSIS / "build_report.txt").write_text("\n".join(rep) + "\n", encoding="utf-8")
    print("\n".join(rep))


if __name__ == "__main__":
    main()
