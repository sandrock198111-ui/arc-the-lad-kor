"""Build v297: E2 bank expansion on top of the 12px johab build.

v296 renders correctly but 2,338 of 2,679 lines are cut: Korean needs two-byte
codes and the original Japanese slot is not long enough.  The project already
solved this and the notes carry the whole recipe (codex_notes.txt, 2026-07-14/16):

    slots        0x45000 + slot*0x80 inside each scene file, up to 79 of them
                 (0x45000..0x477FF is reserved before dialogue near 0x47800)
    disk IDs     original text uses A9, so custom IDs are 81-A8 -> slots 0-39
                 and AA-D0 -> slots 40-78
    RAM          0x80114000 + slot*0x80   (the 0x4000 bank displacement is what
                 v0.5 omitted, leaving custom slot 0 pointing at zeroed RAM)
    layout       visible zero-terminated string at the slot base; metadata at
                 byte 0x7F holds original_capacity - 2
    hooks        one JAL at 0x8016BC84 -> lookup handler at 0x8018FCD0
                 completion handler at 0x8018FD28, resuming at 0x8016BE44
    rules        E6 01 does not work inside a secondary string -- rely on the
                 renderer's automatic wrapping.  Never pad the inline body with
                 visible 9C.  Keep the original bytes after E2 nn and the 00 00
                 boundary; the handler skips them without rendering.

Both handlers are copied verbatim from build_story_e2_bank79_v14.py, including
the R3000 load-delay spacers that v0.6-v0.10 lacked (that omission is what made
the earlier attempts fail, per the 2026-07-15 note).

Only lines that do not fit inline are moved to a slot; short lines stay where
they are, which keeps the change surface small.
"""
from __future__ import annotations
import collections
import csv
import functools
import hashlib
import io
import pickle
import struct
import sys
import time
import zipfile
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "06_tools/python_packages"))
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass
from PIL import Image, ImageFont, ImageDraw  # noqa: E402

ORIG = ROOT / "00_original/arc.zip"
FONTZIP = Path("C:/Users/Administrator/Downloads/8x4x4-fonts-all.zip")
FONT_NAME = "Sans_8x4x4.ttf"
ORIG_CSV = ROOT / "05_docs/script_original_full.csv"
TRANS_CSV = ROOT / "05_docs/script_translated_full.csv"
OUT = ROOT / "03_output"
STEM = "arc1_v304_ui_repack2_TEST_ONLY"
ANALYSIS = ROOT / "01_work/analysis/arc1_v304_ui_repack2"
PSX, COMM = "PSX.EXE", "COMM.IMG"
R2F = 0x8011A800
LOAD = 0x8011B000
ROW, CELL, COLS, PL = 896, 12, 21, 4
ONE_MAX = 220
LAST = 0xDB + 3 * 255 + 254
SLOT_BASE, SLOT_SIZE, SLOT_MAX = 0x45000, 0x80, 79
CAVE_START, CAVE_LIMIT = 0x8018FCD0, 0x8018FDC5
LOOKUP_HANDLER, COMPLETION_HANDLER = 0x8018FCD0, 0x8018FD28
LOOKUP, COMPLETION_TARGET = 0x8015EA44, 0x8016BE44
E2_CALL, COMPLETION_HOOK = 0x8016BC84, 0x8016BDC0
A = {0, 1, 2, 3, 4, 5, 6, 7, 20}
B = {8, 12, 18}
C = {13, 17}


def step(m: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {m}", flush=True)


def grp(j: int) -> int:
    return 0 if j in A else 1 if j in B else 2 if j in C else 3


def fo(addr: int) -> int:
    return addr - LOAD + 0x800


def j(addr: int) -> int:
    return 0x08000000 | ((addr >> 2) & 0x03FFFFFF)


def jal(addr: int) -> int:
    return 0x0C000000 | ((addr >> 2) & 0x03FFFFFF)


def branch(op: int, rs: int, rt: int, pc: int, target: int) -> int:
    d = (target - (pc + 4)) // 4
    if not -0x8000 <= d <= 0x7FFF:
        raise ValueError("branch out of range")
    return (op << 26) | (rs << 21) | (rt << 16) | (d & 0xFFFF)


def lookup_handler() -> bytes:
    normal, low, common = 0x8018FD1C, 0x8018FD00, 0x8018FD04
    w = [0x308800FF, 0x2D090080,
         branch(0x05, 9, 0, 0x8018FCD8, normal), 0x2D0900A8,
         branch(0x05, 9, 0, 0x8018FCE0, low), 0x250AFF58,
         branch(0x04, 10, 0, 0x8018FCE8, normal), 0x2D0900D0,
         branch(0x04, 9, 0, 0x8018FCF0, normal), 0x2508FF7F,
         branch(0x04, 0, 0, 0x8018FCF8, common), 0x00000000,
         0x2508FF80, 0x000811C0, 0x3C098011, 0x25294000, 0x00491021,
         0x03E00008, 0x00000000, j(LOOKUP), 0x00000000]
    return struct.pack(f"<{len(w)}I", *w)


def completion_handler() -> bytes:
    done, low, common = 0x8018FD88, 0x8018FD64, 0x8018FD68
    w = [0x8E080014, 0x00000000, 0x9109FFFF, 0x00000000, 0x2D2A0081,
         branch(0x05, 10, 0, 0x8018FD3C, done), 0x2D2A00A9,
         branch(0x05, 10, 0, 0x8018FD44, low), 0x252BFF57,
         branch(0x04, 11, 0, 0x8018FD4C, done), 0x2D2A00D1,
         branch(0x04, 10, 0, 0x8018FD54, done), 0x2529FF7E,
         branch(0x04, 0, 0, 0x8018FD5C, common), 0x00000000,
         0x2529FF7F, 0x000949C0, 0x3C0A8011, 0x254A4000, 0x012A4821,
         0x912A007F, 0x00000000, 0x010A4021, 0xAE080014, 0x34020001,
         j(COMPLETION_TARGET), 0x00000000]
    return struct.pack(f"<{len(w)}I", *w)


def disk_id(slot: int) -> int:
    return slot + 0x81 if slot < 40 else slot + 0x82


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


def indices(b: bytes) -> set[int]:
    out, i = set(), 0
    while i < len(b):
        x = b[i]
        if x == 0:
            break
        if x >= 0xE1:
            i += 2
            continue
        if x >= 0xDD:
            if 0x01 <= b[i + 1] <= 0xFE:
                out.add((x - 0xDD) * 255 + b[i + 1] + 0xDB)
            i += 2
            continue
        if 0x01 <= x <= 0xDC:
            out.add(x - 1)
        i += 1
    return out


def main() -> None:
    step("원본 열기")
    with ZipFile(ORIG) as z:
        infos = z.infolist()
        mem = {i.filename: z.read(i.filename) for i in infos if not i.filename.endswith("/")}
    font = bytearray(mem[COMM])

    def ink(idx):
        cell, pl = divmod(idx, PL)
        col, row = cell % COLS, cell // COLS
        if (row + 1) * CELL > 504 or (col + 1) * CELL > 252:
            return None
        for y in range(CELL):
            b = (row * CELL + y) * ROW + col * (CELL // 2)
            for x in range(CELL):
                if (font[b + x // 2] >> (0 if x % 2 == 0 else 4)) & 0x0F & (1 << pl):
                    return True
        return False

    def put(idx, rows):
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

    trans = {}
    with TRANS_CSV.open(encoding="utf-8-sig", newline="") as fh:
        for r in csv.DictReader(fh):
            t = (r.get("korean") or "").strip()
            if t:
                trans[(r["source file"], int(r["offset"], 0))] = t
    lines, keep = [], set()
    with ORIG_CSV.open(encoding="utf-8-sig", newline="") as fh:
        for r in csv.DictReader(fh):
            n = r["source file"]
            if n not in mem:
                continue
            off = int(r["byte offset"], 0)
            raw = bytes.fromhex(r["raw bytes as hex"].replace(" ", ""))
            lines.append((n, off, len(raw)))
            if (n, off) not in trans:
                keep |= indices(raw)
    step(f"대사 {len(lines):,}  번역 {len(trans):,}  남길 글리프 {len(keep)}")

    fz = zipfile.ZipFile(FONTZIP)
    ft = ImageFont.truetype(io.BytesIO(fz.read(FONT_NAME)), CELL)

    def render(ch):
        im = Image.new("L", (CELL, CELL), 0)
        ImageDraw.Draw(im).text((0, 0), ch, font=ft, fill=255)
        px = im.load()
        out = []
        for y in range(CELL):
            v = 0
            for x in range(CELL):
                if px[x, y] > 96:
                    v |= 1 << (CELL - 1 - x)
            out.append(v)
        return out

    pieces = [render(chr(0xF600 + i)) for i in range(360)]

    def compose(ch):
        if "가" <= ch <= "힣":
            x = ord(ch) - 0xAC00
            cho, r = divmod(x, 588)
            jung, jong = divmod(r, 28)
            cb = grp(jung) + (4 if jong else 0)
            if grp(jung) == 1 and jong:
                cb = 2
            p = [pieces[cb * 20 + cho + 1],
                 pieces[160 + ((1 if cho in (0, 15) else 0) + (2 if jong else 0)) * 22 + jung + 1]]
            if jong:
                p.append(pieces[248 + grp(jung) * 28 + jong])
            return [functools.reduce(lambda a, b: a | b, (q[y] for q in p)) for y in range(CELL)]
        g = render(ch)
        return g if any(g) else None

    # UI strings: bible_current says UI must be patched at its own string
    # location, never by overwriting Japanese glyph slots.  Positions and Korean
    # come from the ui_* tables this project already produced.
    def tlen(off):
        if not (0 <= off < len(mem[PSX])) or mem[PSX][off] == 0:
            return 0
        e = off
        while e < len(mem[PSX]) and mem[PSX][e]:
            e += 1
        return e - off

    ui = {}
    for fn, kcol in (("ui_full_v42.csv", "korean"), ("ui_safe_v39.csv", "korean_target"),
                     ("ui_system_v39.csv", "korean"), ("ui_world_name_v39.csv", "korean_target")):
        fp = ROOT / "05_docs" / fn
        if not fp.exists():
            continue
        with fp.open(encoding="utf-8-sig", newline="") as fh:
            rr = list(csv.DictReader(fh))
        if not rr:
            continue
        oc = next((c for c in ("string_offset", "source_offset") if c in rr[0]), None)
        if not oc:
            continue
        for r in rr:
            t = (r.get(kcol) or "").strip()
            if not t:
                continue
            try:
                off = int(r[oc], 0)
            except Exception:
                continue
            L = tlen(off)
            if L:
                ui.setdefault(off, (L, t))
    step(f"UI 문자열 {len(ui)}곳")

    need = collections.Counter()
    for t in trans.values():
        for ch in t:
            if ch != " ":
                need[ch] += 1
    # UI is short and repeats, so a missing one-byte code costs it more than it
    # costs dialogue.  Weight UI characters when choosing the one-byte set.
    for L, t in ui.values():
        for ch in t:
            if ch != " ":
                need[ch] += 8

    # codex_notes 2026-07-14: the battle cursor occupies x 0..31, y 128..159.
    # A glyph whose 12x12 rectangle intersects that must not be allocated --
    # row 10 spans y 120..131 and already overlaps, so rows 10..13 are all out.
    CX0, CY0, CX1, CY1 = 0, 128, 32, 160

    def hits_cursor(idx):
        c, _ = divmod(idx, PL)
        col, row = c % COLS, c // COLS
        x0, y0 = col * CELL, row * CELL
        return x0 < CX1 and CX0 < x0 + CELL and y0 < CY1 and CY0 < y0 + CELL

    SAFE1 = [c - 1 for c in list(range(0x68, 0xD1)) + [0xD4, 0xD8, 0xDC]]
    reach = SAFE1 + [i for i in range(ONE_MAX, LAST) if encode(i) is not None]
    avail = [i for i in reach if i not in keep and not hits_cursor(i)]
    space = next((i for i in avail if ink(i) is False), None)
    if space is None:
        raise SystemExit("no blank cell for space")
    avail = [i for i in avail if i != space]
    slot_ix, missing = {}, 0
    for ch, _ in need.most_common():
        g = compose(ch)
        if not g or not any(g) or not avail:
            missing += 1
            continue
        ix = avail.pop(0)
        put(ix, g)
        slot_ix[ch] = ix
    sp = encode(space)
    step(f"글자 {len(slot_ix)}자 배치, 자리없음 {missing}, 남은 칸 {len(avail)}")

    # which 128-byte slots are genuinely empty in each file
    free_slots = {}
    for n in {l[0] for l in lines}:
        d = mem[n]
        fs = []
        for s in range(SLOT_MAX):
            at = SLOT_BASE + s * SLOT_SIZE
            if at + SLOT_SIZE <= len(d) and not any(d[at:at + SLOT_SIZE]):
                fs.append(s)
        free_slots[n] = fs
    step(f"빈 슬롯 합계 {sum(len(v) for v in free_slots.values()):,}")

    scratch = {n: bytearray(v) for n, v in mem.items()}
    inline = moved = trunc = 0
    for n, off, ln in lines:
        txt = trans.get((n, off))
        if not txt:
            continue
        src = mem[n]
        e = off
        while e < len(src) and src[e]:
            e += 1
        body = src[off:e]
        spans, i = [], 0
        while i < len(body):
            b = body[i]
            if b >= 0xE1:
                i += 2
                continue
            k = i
            while k < len(body):
                if body[k] >= 0xE1:
                    break
                k += 1 if body[k] < 0xDD else 2
            spans.append((i, min(k, len(body))))
            i = k
        room = sum(b - a for a, b in spans)
        code = bytearray()
        for ch in txt:
            c = sp if ch == " " else (encode(slot_ix[ch]) if ch in slot_ix else None)
            if c:
                code += c
        if len(code) <= room:
            out = bytearray(code)
            while len(out) + len(sp) <= room:
                out += sp
            out += bytes((sp[0],)) * (room - len(out))
            buf = scratch[n]
            pos = 0
            for a, b in spans:
                w = b - a
                buf[off + a:off + b] = out[pos:pos + w]
                pos += w
            inline += 1
            continue
        # too long for the inline body -> external slot
        fs = free_slots.get(n) or []
        if not fs or len(code) > SLOT_SIZE - 2 or len(body) < 2:
            out = bytearray(code[:room])
            while len(out) + len(sp) <= room:
                out += sp
            out += bytes((sp[0],)) * (room - len(out))
            buf = scratch[n]
            pos = 0
            for a, b in spans:
                w = b - a
                buf[off + a:off + b] = out[pos:pos + w]
                pos += w
            trunc += 1
            continue
        s = fs.pop(0)
        at = SLOT_BASE + s * SLOT_SIZE
        buf = scratch[n]
        buf[at:at + len(code)] = code
        buf[at + len(code)] = 0
        buf[at + 0x7F] = max(len(body) - 2, 0) & 0xFF   # skip metadata
        buf[off] = 0xE2
        buf[off + 1] = disk_id(s)
        moved += 1
    step(f"인라인 {inline:,}  슬롯 이동 {moved:,}  여전히 잘림 {trunc:,}")

    exe = bytearray(mem[PSX])
    # The ui_* tables were built against another generation and their
    # string_offset sits 2-4 bytes past the real start.  Writing there cuts a
    # string in half and the game hangs when it reads it (item / skill menus).
    # Only offsets that a pointer actually targets are safe.
    # The ui_* tables' string_offset is 2-4 bytes off, so it cannot be trusted.
    # Instead each translation was matched to a pointer target by decoding the
    # target's original bytes back to Japanese and comparing with the table's
    # `japanese` column -- exact addresses, no guessing.
    byja = ROOT / "01_work/analysis/ui_by_japanese.pkl"
    if byja.exists():
        m = pickle.load(open(byja, "rb"))
        ui = {}
        for a, ko in m.items():
            e = a
            while e < len(exe) and exe[e]:
                e += 1
            if e > a:
                ui[a] = (e - a, ko)
    step(f"원본 일본어 대조로 주소를 확정한 UI 문자열 {len(ui)}곳")

    # v197's method: repack the whole UI string block and rewrite the pointers,
    # so a short original slot can hold a longer Korean string.  Safe now that
    # every address came from decoding the original Japanese, not from the
    # tables' drifted string_offset (that mismatch is what broke v301).
    BLK_LO, BLK_HI = 0x80224, 0x82420
    ptr_of = collections.defaultdict(list)
    for at in range(0, len(exe) - 4, 4):
        a = struct.unpack_from("<I", exe, at)[0] - R2F
        if BLK_LO <= a < BLK_HI:
            ptr_of[a].append(at)
    order = sorted(ptr_of)

    def orig_str(off):
        e = off
        while e < len(exe) and exe[e]:
            e += 1
        return bytes(exe[off:e])

    payload, newpos, ui_ok, ui_skip = bytearray(), {}, 0, 0
    for a in order:
        t = ui.get(a, (None, None))[1]
        code = None
        if t:
            c = bytearray()
            bad = False
            for ch in t:
                x = sp if ch == " " else (encode(slot_ix[ch]) if ch in slot_ix else None)
                if x is None:
                    bad = True
                    break
                c += x
            if not bad and c:
                code = bytes(c)
        if code is None:
            code = orig_str(a)
            ui_skip += 1
        else:
            ui_ok += 1
        newpos[a] = BLK_LO + len(payload)
        payload += code + bytes(1)
    if len(payload) > BLK_HI - BLK_LO:
        raise SystemExit(f"UI block overflow {len(payload)} > {BLK_HI - BLK_LO}")
    exe[BLK_LO:BLK_LO + len(payload)] = payload
    for k in range(BLK_LO + len(payload), BLK_HI):
        exe[k] = 0
    for a, ats in ptr_of.items():
        for at in ats:
            struct.pack_into("<I", exe, at, newpos[a] + R2F)
    step(f"UI 재배치 {len(order)}곳 (한글 {ui_ok}, 원본 유지 {ui_skip}),  "
         f"{len(payload):,}/{BLK_HI - BLK_LO:,}B")
    cave = fo(CAVE_START)
    if any(exe[cave:fo(CAVE_LIMIT)]):
        raise SystemExit("handler cave is not zero in the original")
    lk, cp = lookup_handler(), completion_handler()
    exe[cave:cave + len(lk)] = lk
    co = fo(COMPLETION_HANDLER)
    exe[co:co + len(cp)] = cp
    struct.pack_into("<I", exe, fo(E2_CALL), jal(LOOKUP_HANDLER))
    struct.pack_into("<I", exe, fo(COMPLETION_HOOK), j(COMPLETION_HANDLER))
    scratch[PSX] = exe
    scratch[COMM] = font
    for n in scratch:
        if len(scratch[n]) != len(mem[n]):
            raise SystemExit(f"{n} size changed")

    step("zip 압축")
    tmp = OUT / f"{STEM}_building.zip"
    if tmp.exists():
        tmp.unlink()
    with ZipFile(tmp, "w", ZIP_DEFLATED, compresslevel=1) as z:
        for i in infos:
            z.writestr(clone(i), b"" if i.filename.endswith("/") else bytes(scratch[i.filename]))
    st = hashlib.sha256(tmp.read_bytes()).hexdigest().upper()
    out = OUT / f"{STEM}_{st[:8]}.zip"
    tmp.replace(out)
    rep = [
        "v304 TEST ONLY - UI repacked at Japanese-confirmed addresses",
        f"output={out.name}", f"sha256={st}",
        "release_status=DIAGNOSTIC; DO NOT DISTRIBUTE",
        f"lines={len(lines):,}  inline={inline:,}  moved to slot={moved:,}  truncated={trunc:,}",
        f"Korean glyphs={len(slot_ix)}  no cell={missing}",
        f"UI strings applied={ui_ok}  deferred={ui_skip}",
        f"handlers at 0x{LOOKUP_HANDLER:08X} / 0x{COMPLETION_HANDLER:08X}, hooks 0x{E2_CALL:08X} / 0x{COMPLETION_HOOK:08X}",
        "runtime=PENDING user cold boot",
    ]
    ANALYSIS.mkdir(parents=True, exist_ok=True)
    (ANALYSIS / "build_report.txt").write_text("\n".join(rep) + "\n", encoding="utf-8")
    print("\n".join(rep))


if __name__ == "__main__":
    main()
