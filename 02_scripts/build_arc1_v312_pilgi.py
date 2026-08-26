"""Build v312: 12px johab, Pilgi body face.

Why johab, measured rather than assumed (codex_notes 2026-08-18):

    original atlas cells that already hold a glyph   996   <- never touched
    blank cells nobody references                    237   <- the whole budget
    syllables the translation uses                   672   -> completed form impossible
    pieces this translation actually needs           224   -> fits

The beol rule is not the textbook one -- it was derived by matching every piece
combination against this font's own completed syllables (see CHO_WITH_JONG).
Assuming the textbook rule put the RIEUL of 롭 in the upper-left corner, because
a jong-bearing horizontal vowel got a narrow choseong meant for vertical vowels.
The measured rule also needs fewer pieces: 168 instead of 224.

Encoding order is jung -> jong -> cho so the choseong is always last: the
renderer advances the cursor only for codes below BOUND, so jung/jong draw in
place and cho closes the syllable.

Three PSX.EXE edits, all inside the 245-byte zero cave at 0x8018FCD0:
    lookup handler      E2 nn -> external slot address
    completion handler  skip the swallowed inline bytes
    advance helper      zero the cursor step for piece codes

Text that does not fit its original room moves to an E2 slot.  Only the leading
run of text-and-newline is swallowed; E4/E5/E7 controls stay where they are.
"""
from __future__ import annotations
import collections
import csv
import functools
import hashlib
import io
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
FONT_NAME = "Pilgi_8x4x4.ttf"
ORIG_CSV = ROOT / "05_docs/script_original_full.csv"
TRANS_CSV = ROOT / "05_docs/script_translated_full.csv"
OUT = ROOT / "03_output"
STEM = "arc1_v312_pilgi_TEST_ONLY"
ANALYSIS = ROOT / "01_work/analysis/arc1_v312_pilgi"
PSX, COMM = "PSX.EXE", "COMM.IMG"

LOAD = 0x8011B000
ROW, CELL, COLS, PL = 896, 12, 21, 4
ONE_MAX = 220
LAST = 0xDB + 3 * 255 + 254
SLOT_BASE, SLOT_SIZE, SLOT_MAX = 0x45000, 0x80, 79

CAVE_START, CAVE_END = 0x8018FCD0, 0x8018FDC5
LOOKUP_HANDLER, COMPLETION_HANDLER, ADVANCE_HELPER = 0x8018FCD0, 0x8018FD28, 0x8018FD94
LOOKUP, COMPLETION_TARGET = 0x8015EA44, 0x8016BE44
E2_CALL, COMPLETION_HOOK, ADVANCE_HOOK = 0x8016BC84, 0x8016BDC0, 0x8016B63C

JUNG_A = {0, 1, 2, 3, 4, 5, 6, 7, 20}
JUNG_B = {8, 12, 18}
JUNG_C = {13, 17}
# Derived by matching every piece combination against this font's own completed
# syllables (646 of them, closest-pixel match).  The textbook "group + 4 when a
# jong is present" rule is wrong for this font:
#   - beol 4 is never selected; A-with-jong is beol 5, not 4
#   - B and C share beol 6 once a jong is present
#   - the jungseong does not switch on a g/k choseong at all
#   - every jongseong uses beol 1
# Getting this wrong is what put the RIEUL of 롭 in the upper-left corner.
CHO_WITH_JONG = {0: 5, 1: 6, 2: 6, 3: 7}
JONG_BEOL = 1

# A piece can come from a different 8x4x4 face than the body font.  Pieces are
# independent, so swapping one jamo changes only the syllables that use it.
# Sans draws choseong PIEUP with two thick horizontal bars and stubby verticals,
# which at 12px is indistinguishable from SSANGDIGEUT -- 파 read as 따 on the
# user's screen.  Iyagi's PIEUP keeps the bars thin and matches Sans in weight.
# Key is the choseong jamo index (0=G, ... 17=P, 18=H).
CHO_PIECE_FONT = {}


def step(m):
    print(f"[{time.strftime('%H:%M:%S')}] {m}", flush=True)


def grp(j):
    return 0 if j in JUNG_A else 1 if j in JUNG_B else 2 if j in JUNG_C else 3


def fo(a):
    return a - LOAD + 0x800


def jj(a):
    return 0x08000000 | ((a >> 2) & 0x03FFFFFF)


def jal(a):
    return 0x0C000000 | ((a >> 2) & 0x03FFFFFF)


def branch(op, rs, rt, pc, tgt):
    d = (tgt - (pc + 4)) // 4
    if not -0x8000 <= d <= 0x7FFF:
        raise ValueError("branch out of range")
    return (op << 26) | (rs << 21) | (rt << 16) | (d & 0xFFFF)


def encode(ix):
    if 0 <= ix < ONE_MAX:
        return bytes((ix + 1,))
    rel = ix - 0xDB
    lead, trail = divmod(rel, 255)
    if not (0 <= lead <= 3 and 1 <= trail <= 254):
        return None
    return bytes((0xDD + lead, trail))


def clone(i):
    o = ZipInfo(i.filename, i.date_time)
    for a in ("compress_type", "comment", "extra", "create_system", "create_version",
              "extract_version", "flag_bits", "volume", "internal_attr", "external_attr"):
        setattr(o, a, getattr(i, a))
    return o


def lookup_handler():
    normal, low, common = 0x8018FD1C, 0x8018FD00, 0x8018FD04
    w = [0x308800FF, 0x2D090080,
         branch(0x05, 9, 0, 0x8018FCD8, normal), 0x2D0900A8,
         branch(0x05, 9, 0, 0x8018FCE0, low), 0x250AFF58,
         branch(0x04, 10, 0, 0x8018FCE8, normal), 0x2D0900D0,
         branch(0x04, 9, 0, 0x8018FCF0, normal), 0x2508FF7F,
         branch(0x04, 0, 0, 0x8018FCF8, common), 0x00000000,
         0x2508FF80, 0x000811C0, 0x3C098011, 0x25294000, 0x00491021,
         0x03E00008, 0x00000000, jj(LOOKUP), 0x00000000]
    return struct.pack("<%dI" % len(w), *w)


def completion_handler():
    done, low, common = 0x8018FD88, 0x8018FD64, 0x8018FD68
    w = [0x8E080014, 0x00000000, 0x9109FFFF, 0x00000000, 0x2D2A0081,
         branch(0x05, 10, 0, 0x8018FD3C, done), 0x2D2A00A9,
         branch(0x05, 10, 0, 0x8018FD44, low), 0x252BFF57,
         branch(0x04, 11, 0, 0x8018FD4C, done), 0x2D2A00D1,
         branch(0x04, 10, 0, 0x8018FD54, done), 0x2529FF7E,
         branch(0x04, 0, 0, 0x8018FD5C, common), 0x00000000,
         0x2529FF7F, 0x000949C0, 0x3C0A8011, 0x254A4000, 0x012A4821,
         0x912A007F, 0x00000000, 0x010A4021, 0xAE080014, 0x34020001,
         jj(COMPLETION_TARGET), 0x00000000]
    return struct.pack("<%dI" % len(w), *w)


def advance_helper(bound):
    """Replaces 0x8016B63C..0x8016B664.  a2=state, a0=glyph index, v1=width.

           lbu   a1,0xF(a2)      ; letter spacing
           sltiu at,a0,bound     ; a0 is still the glyph index here; last use
           lhu   a0,0xA(a2)      ; reuse a0 for the glyph ordinal
           lhu   v0,6(a2)        ; screen X  (also fills a0's load delay)
           beq   at,zero,L       ; piece -> do not advance
            addu v1,v1,a1        ; delay: step = width + spacing
           addu  v0,v0,v1
           sh    v0,6(a2)
        L: addiu a0,a0,1
           sh    a0,0xA(a2)
           jr    ra
            nop

    v1 arrives holding the width: the hook's delay slot runs the original
    lbu v1,0xD(a2), and this routine's first instruction does not read v1, so
    the load delay is satisfied.
    """
    base = ADVANCE_HELPER
    label = base + 8 * 4
    if not 0 <= bound <= 0xFFFF:
        raise ValueError("bound out of range")
    w = [0x90C5000F,
         0x2C810000 | bound,
         0x94C4000A,
         0x94C20006,
         branch(0x04, 1, 0, base + 4 * 4, label),
         0x00651821,
         0x00431021,
         0xA4C20006,
         0x24840001,
         0xA4C4000A,
         0x03E00008, 0x00000000]
    return struct.pack("<%dI" % len(w), *w)


def main():
    step("원본 열기")
    with ZipFile(ORIG) as z:
        infos = z.infolist()
        mem = {i.filename: z.read(i.filename) for i in infos if not i.filename.endswith("/")}
    orig_font = mem[COMM]
    font = bytearray(orig_font)

    def cell_of(idx):
        cell, pl = divmod(idx, PL)
        return cell % COLS, cell // COLS, pl

    def ink(idx):
        col, row, pl = cell_of(idx)
        if (row + 1) * CELL > 504 or (col + 1) * CELL > 252:
            return None
        bit = 1 << pl
        for y in range(CELL):
            b = (row * CELL + y) * ROW + col * (CELL // 2)
            for x in range(CELL):
                if (orig_font[b + x // 2] >> (0 if x % 2 == 0 else 4)) & bit:
                    return True
        return False

    def put(idx, rows):
        col, row, pl = cell_of(idx)
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

    def read_cell(buf, idx):
        col, row, pl = cell_of(idx)
        bit = 1 << pl
        out = []
        for y in range(CELL):
            b = (row * CELL + y) * ROW + col * (CELL // 2)
            v = 0
            for x in range(CELL):
                if (buf[b + x // 2] >> (0 if x % 2 == 0 else 4)) & bit:
                    v |= 1 << (CELL - 1 - x)
            out.append(v)
        return out

    def indices(b):
        out, i = set(), 0
        while i < len(b):
            x = b[i]
            if x == 0:
                break
            if x >= 0xE1:
                i += 2
                continue
            if x >= 0xDD:
                if i + 1 < len(b) and 0x01 <= b[i + 1] <= 0xFE:
                    out.add((x - 0xDD) * 255 + b[i + 1] + 0xDB)
                i += 2
                continue
            if 0x01 <= x <= 0xDC:
                out.add(x - 1)
            i += 1
        return out

    step("번역문 / 원본 대사 읽기")
    trans = {}
    with TRANS_CSV.open(encoding="utf-8-sig", newline="") as fh:
        for r in csv.DictReader(fh):
            t = (r.get("korean") or "").strip()
            if t:
                trans[(r["source file"], int(r["offset"], 0))] = t
    lines = []
    referenced = set()
    with ORIG_CSV.open(encoding="utf-8-sig", newline="") as fh:
        for r in csv.DictReader(fh):
            n = r["source file"]
            if n not in mem:
                continue
            off = int(r["byte offset"], 0)
            lines.append((n, off))
            referenced |= indices(bytes.fromhex(r["raw bytes as hex"].replace(" ", "")))
    ui_sites = ROOT / "01_work/analysis/ui_string_sites.pkl"
    if ui_sites.exists():
        import pickle
        with ui_sites.open("rb") as fh:
            for off, ln in pickle.load(fh).items():
                referenced |= indices(mem[PSX][off:off + ln])
    step("대사 %d곳, 번역 %d줄" % (len(lines), len(trans)))

    step("원본 아틀라스 조사")
    reach = [i for i in range(LAST) if encode(i) is not None]
    inked = [i for i in reach if ink(i) is True]
    blank = [i for i in reach if ink(i) is False]
    free = sorted(set(blank) - referenced)
    step("글리프 있는 칸 %d  빈 칸 %d  쓸 수 있는 칸 %d" % (len(inked), len(blank), len(free)))
    def cell_bytes(buf, idx):
        return b"".join(v.to_bytes(2, "little") for v in read_cell(buf, idx))

    ink_hash_before = hashlib.sha256(
        b"".join(cell_bytes(orig_font, i) for i in inked)).hexdigest()

    step("조각 렌더")
    fz = zipfile.ZipFile(FONTZIP)
    faces = {}

    def face(name):
        if name not in faces:
            faces[name] = ImageFont.truetype(io.BytesIO(fz.read(name)), CELL)
        return faces[name]

    @functools.lru_cache(maxsize=None)
    def render_from(name, ch):
        im = Image.new("L", (CELL, CELL), 0)
        ImageDraw.Draw(im).text((0, 0), ch, font=face(name), fill=255)
        px = im.load()
        return tuple(sum((1 << (CELL - 1 - x)) for x in range(CELL) if px[x, y] > 96)
                     for y in range(CELL))

    def render(ch):
        return render_from(FONT_NAME, ch)

    piece = []
    swapped = 0
    for i in range(360):
        name = FONT_NAME
        if i < 160:                                  # choseong block, 20 per beol
            jamo = (i % 20) - 1                      # slot 0 of each beol is blank
            if jamo in CHO_PIECE_FONT:
                name = CHO_PIECE_FONT[jamo]
                swapped += 1
        piece.append(render_from(name, chr(0xF600 + i)))
    if swapped:
        step("조각 교체 %d개: %s" % (swapped, CHO_PIECE_FONT))

    def decompose(ch):
        x = ord(ch) - 0xAC00
        cho, r = divmod(x, 588)
        jung, jong = divmod(r, 28)
        cb = CHO_WITH_JONG[grp(jung)] if jong else grp(jung)
        vb = 2 if jong else 0
        return ("c", cb, cho), ("v", vb, jung), (("t", JONG_BEOL, jong) if jong else None)

    def bitmap(k):
        kind, beol, jamo = k
        if kind == "c":
            return piece[beol * 20 + jamo + 1]
        if kind == "v":
            return piece[160 + beol * 22 + jamo + 1]
        return piece[248 + beol * 28 + jamo]

    step("필요한 조각 집계")
    need_cho, need_rest, need_plain = set(), set(), collections.Counter()
    for t in trans.values():
        for ch in t:
            if ch == " ":
                continue
            if "가" <= ch <= "힣":
                c, v, j = decompose(ch)
                need_cho.add(c)
                need_rest.add(v)
                if j:
                    need_rest.add(j)
            else:
                need_plain[ch] += 1
    step("초성 %d  중성+종성 %d  음절 아닌 글자 %d종"
         % (len(need_cho), len(need_rest), len(need_plain)))

    run = [free[-1]]
    for i in reversed(free[:-1]):
        if i == run[-1] - 1:
            run.append(i)
        else:
            break
    run.reverse()
    if len(run) < len(need_rest):
        raise SystemExit("top contiguous run %d < jung/jong %d" % (len(run), len(need_rest)))
    rest_cells = run[-len(need_rest):]
    bound = rest_cells[0]
    below = [i for i in free if i < bound]
    plain_new = sum(1 for ch in need_plain
                    if not (0 <= ord(ch) - 32 < 95 and ink(ord(ch) - 32) is True))
    want = len(need_cho) + plain_new + (0 if ink(0) is False else 1)
    if len(below) < want:
        raise SystemExit("cells below bound %d < cho+new-plain+space %d" % (len(below), want))
    step("판정 경계 BOUND=%d  위 %d칸(중성/종성)  아래 %d칸"
         % (bound, len(rest_cells), len(below)))

    slot_of = {}
    for k, ix in zip(sorted(need_rest), rest_cells):
        put(ix, bitmap(k))
        slot_of[k] = ix
    it = iter(below)
    for k in sorted(need_cho):
        ix = next(it)
        put(ix, bitmap(k))
        slot_of[k] = ix
    # ASCII already exists in the original atlas at index = code - 32 (bible, 0..25
    # proven; 26..94 verified here by ink).  Reusing it costs no cell and gives a
    # one-byte code, which shortens every line that carries punctuation or digits.
    plain_of = {}
    reused = []
    missing_plain = []
    for ch, _ in need_plain.most_common():
        ix = ord(ch) - 32
        if 0 <= ix < 95 and ink(ix) is True:
            plain_of[ch] = ix
            reused.append(ch)
            continue
        g = render(ch)
        if not any(g):
            missing_plain.append(ch)
            continue
        nix = next(it)
        put(nix, list(g))
        plain_of[ch] = nix
    space_ix = 0 if ink(0) is False else next(it)
    step("ASCII 재사용 %d자, 새로 그린 글자 %d자, 그림 없음 %d: %s"
         % (len(reused), len(plain_of) - len(reused), len(missing_plain),
            "".join(missing_plain)))
    step("공백 코드 index %d (%s)" % (space_ix, encode(space_ix).hex()))

    ink_hash_after = hashlib.sha256(
        b"".join(cell_bytes(font, i) for i in inked)).hexdigest()
    if ink_hash_before != ink_hash_after:
        raise SystemExit("GUARD: an inked original cell changed")
    step("가드 통과: 원본 글리프 %d칸 픽셀 불변" % len(inked))

    sp = encode(space_ix)

    def enc_char(ch):
        if ch == " ":
            return sp
        if "가" <= ch <= "힣":
            c, v, j = decompose(ch)
            out = encode(slot_of[v])
            if j:
                out += encode(slot_of[j])
            return out + encode(slot_of[c])
        if ch in plain_of:
            return encode(plain_of[ch])
        return None

    def enc_units(t):
        """One entry per visible character, so a slot boundary never splits a syllable."""
        return [e for e in (enc_char(ch) for ch in t) if e]

    def enc_text(t):
        return b"".join(enc_units(t))

    def chunk(units, cap):
        out, cur = [], bytearray()
        for u in units:
            if len(cur) + len(u) > cap:
                out.append(bytes(cur))
                cur = bytearray()
            cur += u
        if cur:
            out.append(bytes(cur))
        return out

    step("빈 E2 슬롯 조사")
    free_slots = {}
    for n in set(l[0] for l in lines):
        d = mem[n]
        free_slots[n] = [s for s in range(SLOT_MAX)
                         if SLOT_BASE + (s + 1) * SLOT_SIZE <= len(d)
                         and not any(d[SLOT_BASE + s * SLOT_SIZE:SLOT_BASE + (s + 1) * SLOT_SIZE])]
    step("빈 슬롯 %d개" % sum(len(v) for v in free_slots.values()))

    def disk_id(slot):
        return slot + 0x81 if slot < 40 else slot + 0x82

    scratch = {n: bytearray(v) for n, v in mem.items()}
    inline = moved = trunc = no_slot = ctrl_kept = 0
    multi = few_slots = short_head = 0
    for n, off in lines:
        txt = trans.get((n, off))
        if not txt:
            continue
        src = mem[n]
        e = off
        while e < len(src) and src[e]:
            e += 1
        body = src[off:e]
        i = 0
        while i < len(body):
            b = body[i]
            if b >= 0xE1:
                if b == 0xE6 and i + 1 < len(body) and body[i + 1] == 0x01:
                    i += 2
                    continue
                break
            i += 1 if b < 0xDD else 2
        head = i
        if head < len(body):
            ctrl_kept += 1
        spans, k = [], 0
        while k < head:
            if body[k] >= 0xE1:
                k += 2
                continue
            j2 = k
            while j2 < head and body[j2] < 0xE1:
                j2 += 1 if body[j2] < 0xDD else 2
            spans.append((k, min(j2, head)))
            k = j2
        room = sum(b - a for a, b in spans)
        code = enc_text(txt)
        buf = scratch[n]

        def fill_inline(payload):
            out = bytearray(payload)
            while len(out) + len(sp) <= room:
                out += sp
            out += bytes((sp[0],)) * (room - len(out))
            pos = 0
            for a, b in spans:
                w = b - a
                buf[off + a:off + b] = out[pos:pos + w]
                pos += w

        if len(code) <= room:
            fill_inline(code)
            inline += 1
            continue
        # External slots.  A line longer than one slot uses several consecutive
        # E2 commands: every slot but the last carries skip 0, so the completion
        # handler leaves the inline pointer alone and the next E2 is parsed.
        fs = free_slots.get(n) or []
        parts = chunk(enc_units(txt), SLOT_SIZE - 2)
        k = len(parts)
        if head < 2 * k or len(fs) < k:
            fill_inline(code[:room])
            trunc += 1
            if not fs:
                no_slot += 1
            elif len(fs) < k:
                few_slots += 1
            else:
                short_head += 1
            continue
        for idx, part in enumerate(parts):
            s = fs.pop(0)
            at = SLOT_BASE + s * SLOT_SIZE
            buf[at:at + len(part)] = part
            buf[at + len(part)] = 0
            buf[at + 0x7F] = 0 if idx < k - 1 else (head - 2 * k) & 0xFF
            buf[off + idx * 2] = 0xE2
            buf[off + idx * 2 + 1] = disk_id(s)
        moved += 1
        multi += (k > 1)
    step("인라인 %d  슬롯 이동 %d (여러 슬롯 %d)  잘림 %d "
         "(슬롯 없음 %d, 슬롯 부족 %d, 자리 부족 %d)  뒤 제어코드 보존 %d"
         % (inline, moved, multi, trunc, no_slot, few_slots, short_head, ctrl_kept))

    step("PSX.EXE 패치")
    exe = bytearray(mem[PSX])
    cave = fo(CAVE_START)
    if any(exe[cave:fo(CAVE_END)]):
        raise SystemExit("GUARD: cave is not zero")
    if struct.unpack_from("<I", exe, fo(E2_CALL))[0] != jal(LOOKUP):
        raise SystemExit("GUARD: E2 call site is not jal 0x8015EA44")
    if struct.unpack_from("<I", exe, fo(COMPLETION_HOOK))[0] != jj(COMPLETION_TARGET):
        raise SystemExit("GUARD: completion hook is not j 0x8016BE44")
    if struct.unpack_from("<I", exe, fo(COMPLETION_HOOK + 4))[0] != 0:
        raise SystemExit("GUARD: completion hook delay slot is not nop")
    if struct.unpack_from("<I", exe, fo(ADVANCE_HOOK))[0] != 0x90C3000D:
        raise SystemExit("GUARD: advance hook is not lbu v1,0xD(a2)")
    lk, cp, ah = lookup_handler(), completion_handler(), advance_helper(bound)
    for addr, blob in ((LOOKUP_HANDLER, lk), (COMPLETION_HANDLER, cp), (ADVANCE_HELPER, ah)):
        if addr + len(blob) > CAVE_END:
            raise SystemExit("GUARD: %08X overflows the cave" % addr)
        exe[fo(addr):fo(addr) + len(blob)] = blob
    struct.pack_into("<I", exe, fo(E2_CALL), jal(LOOKUP_HANDLER))
    struct.pack_into("<I", exe, fo(COMPLETION_HOOK), jj(COMPLETION_HANDLER))
    struct.pack_into("<I", exe, fo(ADVANCE_HOOK), jj(ADVANCE_HELPER))
    struct.pack_into("<I", exe, fo(ADVANCE_HOOK + 4), 0x90C3000D)
    step("핸들러 3개 심음. cave 사용 %d / %dB"
         % (len(lk) + len(cp) + len(ah), CAVE_END - CAVE_START))

    scratch[PSX] = exe
    scratch[COMM] = font
    for n in scratch:
        if len(scratch[n]) != len(mem[n]):
            raise SystemExit("GUARD: %s size changed" % n)

    step("zip 압축")
    OUT.mkdir(parents=True, exist_ok=True)
    tmp = OUT / (STEM + "_building.zip")
    if tmp.exists():
        tmp.unlink()
    with ZipFile(tmp, "w", ZIP_DEFLATED, compresslevel=1) as z:
        for i in infos:
            z.writestr(clone(i), b"" if i.filename.endswith("/") else bytes(scratch[i.filename]))
    st = hashlib.sha256(tmp.read_bytes()).hexdigest().upper()
    out = OUT / ("%s_%s.zip" % (STEM, st[:8]))
    tmp.replace(out)
    changed = sorted(n for n in scratch if bytes(scratch[n]) != mem[n])
    rep = [
        "v312 TEST ONLY - 12px johab, Pilgi",
        "output=%s" % out.name,
        "sha256=%s" % st,
        "release_status=DIAGNOSTIC; DO NOT DISTRIBUTE",
        "font=%s at %dpx, beol rule measured against the font own syllables" % (FONT_NAME, CELL),
        "pieces placed: cho %d, jung+jong %d, plain %d, total %d"
        % (len(need_cho), len(need_rest), len(plain_of), len(slot_of) + len(plain_of)),
        "atlas: %d original glyph cells untouched (sha %s), %d blank cells available"
        % (len(inked), ink_hash_before[:16], len(free)),
        "advance bound = index %d; codes >= bound draw without moving the cursor" % bound,
        "lines %d  translated %d  inline %d  moved to slot %d (multi-slot %d)  truncated %d"
        % (len(lines), len(trans), inline, moved, multi, trunc),
        "truncation causes: no free slot %d, not enough slots %d, no room for E2 %d"
        % (no_slot, few_slots, short_head),
        "handlers 0x%08X / 0x%08X / 0x%08X"
        % (LOOKUP_HANDLER, COMPLETION_HANDLER, ADVANCE_HELPER),
        "hooks 0x%08X / 0x%08X / 0x%08X" % (E2_CALL, COMPLETION_HOOK, ADVANCE_HOOK),
        "changed members=%d" % len(changed),
        "runtime=PENDING user cold boot",
    ]
    ANALYSIS.mkdir(parents=True, exist_ok=True)
    (ANALYSIS / "build_report.txt").write_text("\n".join(rep) + "\n", encoding="utf-8")
    print("\n".join(rep))


if __name__ == "__main__":
    main()
