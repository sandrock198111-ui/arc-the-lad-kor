"""v108: three builds that each change one thing, to find why v106/v107 draw blanks.

v103 renders the expanded glyphs. v106 and v107 do not, and the savestate shows the
glyph is never even given a packet: on the item screen every glyph sprite has U ≡ 0
(mod 12) and a base-row V, so nothing took the P6 path. Everything checkable without
running the game already checks out -- the lookup entry for the failing character is
3367 (row 40, col 1, plane 3), the table in RAM matches the build, the pixels are in
VRAM at (964, 480), and the classifier and helper in RAM are byte-identical to what was
built.

Four things changed at once between v103 and v106, which is why the cause has not
narrowed. They are not four independent knobs, though: the classifier's compare value
is forced by the row, and the texture page, the U offset and the x coordinate are one
choice. So there are three groups, and this builds one variant per group:

    v108a   row 24 -> 40, and the classifier compare 32 -> 224 with it.
            Texture page, U offset and the inline classifier stay as v103.
            The strip moves to (714, 480), still inside page 11.

    v108b   texture page 0x1B -> 0x1F and U offset 40 -> 4, so the strip moves to
            (961, 288). The row, V and the inline classifier stay as v103.

    v108c   the inline classifier becomes a subroutine in reserved RAM, still
            comparing the single value 32. Row, page and U offset stay as v103.

Whichever fails is the cause. Run them in that order and stop at the first blank.
"""
from __future__ import annotations

import hashlib
import struct
import sys
from pathlib import Path
from zipfile import ZipFile, ZipInfo

ROOT = Path(__file__).resolve().parents[1]
BASE_ZIP = ROOT / "03_output/ui_hud_e7_v103_heap_reserved_glyphs_patch_only.zip"
BASE_SHA = "9EE40993E72962F26DAFBD61CA565D4646E247D9990B79EF5122776838584FD3"
PSX = "PSX.EXE"
RAM_TO_FILE = 0x8011A800

# --- v103's world ---
OLD_ROW, COLS, PLANES = 24, 15, 4
INDICES_PER_ROW = 21 * PLANES                      # 84
LOOKUP, LOOKUP_N = 0x801A7520, 409
STRIP_W, STRIP_BYTES = COLS * 3, COLS * 3 * 2 * 12  # 45 units, 1080 bytes
HELPER_SRC, HELPER_DST, HELPER_N = 0x801A86EC, 0x801FE3C4, 276
GLYPH_SRC, GLYPH_DST = 0x801A8800, 0x801FE4D8
IMAGE_END = 0x801A9000

TPAGE_AT = 0x801A2194                              # ori a3,a3,0x001B
CLS = 0x801A2204                                   # the inline classifier
RECT = 0x801A22E4
STUB_CALL = 0x801A208C
MEMCPY_LEN_AT, HEAP_BASE_AT = 0x801757CC, 0x80175810
HELPER_ROW_OFF = 0x00                              # addiu a3,t0,-24
HELPER_U_OFF = 0x4C                                # addiu a3,a3,40
HEAP_HI, HEAP_SEEN_USED = 0x80200000, 0x801FFA60

ZERO, V0, V1, A1, A3, T0, T8, T9, RA = 0, 2, 3, 5, 7, 8, 24, 25, 31


def addiu(rt, rs, i): return 0x24000000 | (rs << 21) | (rt << 16) | (i & 0xFFFF)
def sltiu(rt, rs, i): return 0x2C000000 | (rs << 21) | (rt << 16) | (i & 0xFFFF)
def ori(rt, rs, i): return 0x34000000 | (rs << 21) | (rt << 16) | (i & 0xFFFF)
def lbu(rt, rs, o): return 0x90000000 | (rs << 21) | (rt << 16) | (o & 0xFFFF)
def addu(rd, rs, rt): return (rs << 21) | (rt << 16) | (rd << 11) | 0x21
def bne(rs, rt, o): return 0x14000000 | (rs << 21) | (rt << 16) | (o & 0xFFFF)
def jal(t): return 0x0C000000 | ((t & 0x0FFFFFFF) >> 2)


NOP, JR_RA = 0, 0x03E00008

# words that must hold these values in the base archive
BASE_WORDS = {
    TPAGE_AT: ori(A3, A3, 0x001B),
    CLS + 0x00: lbu(V0, V1, 0x29),
    CLS + 0x04: NOP,
    CLS + 0x08: addiu(V0, V0, -32),
    CLS + 0x0C: sltiu(V0, V0, 1),
    CLS + 0x10: bne(V0, 21, 0x1A),
    CLS + 0x14: addu(A1, V1, 20),
    RECT: (288 << 16) | 714,
    RECT + 4: (12 << 16) | STRIP_W,
    MEMCPY_LEN_AT: addiu(6, ZERO, HELPER_N + STRIP_BYTES),
    HEAP_BASE_AT: addiu(4, 4, (GLYPH_DST + STRIP_BYTES - 4) - HEAP_HI),
    HELPER_SRC + HELPER_ROW_OFF: addiu(A3, T0, -OLD_ROW),
    HELPER_SRC + HELPER_U_OFF: addiu(A3, A3, 40),
    STUB_CALL: jal(0x80177E4C),
}


def sha256(b): return hashlib.sha256(b).hexdigest().upper()
def word(buf, ram): return struct.unpack_from("<I", buf, ram - RAM_TO_FILE)[0]
def put(buf, ram, v): struct.pack_into("<I", buf, ram - RAM_TO_FILE, v)


def clone(i: ZipInfo) -> ZipInfo:
    t = ZipInfo(i.filename, i.date_time)
    for a in ("compress_type", "comment", "extra", "create_system", "create_version",
              "extract_version", "flag_bits", "volume", "internal_attr",
              "external_attr"):
        setattr(t, a, getattr(i, a))
    return t


def load():
    if sha256(BASE_ZIP.read_bytes()) != BASE_SHA:
        raise SystemExit("base archive is not the verified v103 build")
    with ZipFile(BASE_ZIP) as a:
        infos = a.infolist()
        members = {i.filename: a.read(i.filename) for i in infos}
    exe = bytearray(members[PSX])
    for ram, val in BASE_WORDS.items():
        if word(exe, ram) != val:
            raise SystemExit(f"base word at 0x{ram:08X} is 0x{word(exe, ram):08X}, "
                             f"expected 0x{val:08X}")
    return infos, members, exe


def variant_a(exe):
    """Row 24 -> 40. V becomes 224, so the strip moves down to y 480 in the same page."""
    new_row, shift = 40, (40 - OLD_ROW) * INDICES_PER_ROW
    changes = []
    off = LOOKUP - RAM_TO_FILE
    entries = list(struct.unpack_from(f"<{LOOKUP_N}H", exe, off))
    moved = 0
    for i, idx in enumerate(entries):
        if idx // INDICES_PER_ROW == OLD_ROW:
            entries[i] = idx + shift
            moved += 1
    if not moved:
        raise SystemExit("no lookup entries on the old row")
    struct.pack_into(f"<{LOOKUP_N}H", exe, off, *entries)

    v = (new_row * 12) & 0xFF
    y = 256 + v                                  # texture page 0x1B has ty = 1
    for ram, val, note in (
        (HELPER_SRC + HELPER_ROW_OFF, addiu(A3, T0, -new_row),
         f"helper row test {OLD_ROW} -> {new_row}"),
        (CLS + 0x08, addiu(V0, V0, -v), f"classifier compare 32 -> {v}"),
        (RECT, (y << 16) | 714, f"rect y 288 -> {y}"),
    ):
        put(exe, ram, val)
        changes.append((ram, val, note))
    return changes, f"{moved} lookup entries moved to row {new_row}, V={v}, y={y}"


def variant_b(exe):
    """Texture page 0x1B -> 0x1F and U offset 40 -> 4: the strip moves to x 961."""
    tp, u = 0x1F, 4
    x = (tp & 0xF) * 64 + u // 4
    if (u + COLS * 12) > 256:
        raise SystemExit("the strip would leave its texture page")
    if x + STRIP_W > 1024:
        raise SystemExit("the strip would leave VRAM")
    changes = []
    for ram, val, note in (
        (TPAGE_AT, ori(A3, A3, tp), f"tpage 0x1B -> 0x{tp:02X}"),
        (HELPER_SRC + HELPER_U_OFF, addiu(A3, A3, u), f"helper U offset 40 -> {u}"),
        (RECT, (288 << 16) | x, f"rect x 714 -> {x}"),
    ):
        put(exe, ram, val)
        changes.append((ram, val, note))
    return changes, f"page {tp & 0xF},{tp >> 4}  x {x}..{x + STRIP_W - 1}  U offset {u}"


def variant_c(exe):
    """The inline classifier becomes a subroutine, still comparing 32.

    t8 and t9 are used rather than t0 and t1 because t0 still holds the glyph row when
    the helper runs later in the same glyph's path; neither is read anywhere in the
    calling loop (0x801A21DC..0x801A229C).
    """
    code_src = GLYPH_SRC + STRIP_BYTES               # the padding after the glyph block
    code_dst = GLYPH_DST + STRIP_BYTES
    body = [
        (lbu(V0, V1, 0x29), "lbu   v0,0x29(v1)   ; V"),
        (NOP, "nop"),
        (addiu(T8, V0, -32), "addiu t8,v0,-32"),
        (sltiu(V0, T8, 1), "sltiu v0,t8,1"),
        (JR_RA, "jr    ra"),
        (NOP, "nop"),
    ]
    n = len(body) * 4
    if code_src + n > IMAGE_END:
        raise SystemExit("the subroutine does not fit in the image")
    if any(exe[code_src - RAM_TO_FILE: code_src - RAM_TO_FILE + n]):
        raise SystemExit("the landing area is not padding")
    for i, (v, _) in enumerate(body):
        put(exe, code_src + i * 4, v)

    copy_n = (code_dst + n) - HELPER_DST
    heap = code_dst + n
    if heap >= HEAP_SEEN_USED:
        raise SystemExit("the reservation reaches heap the game uses")
    changes = []
    for ram, val, note in (
        (CLS + 0x00, jal(code_dst), f"classifier -> subroutine at 0x{code_dst:08X}"),
        (CLS + 0x04, addu(A1, V1, 20), "its delay slot, hoisted from +0x14"),
        (CLS + 0x08, NOP, "was the inline compare"),
        (CLS + 0x0C, NOP, "was the inline test"),
        (CLS + 0x14, NOP, "branch delay slot, a1 already set"),
        (MEMCPY_LEN_AT, addiu(6, ZERO, copy_n), f"memcpy length -> {copy_n}"),
        (HEAP_BASE_AT, addiu(4, 4, (heap - 4) - HEAP_HI), f"heap base -> 0x{heap:08X}"),
    ):
        put(exe, ram, val)
        changes.append((ram, val, note))
    # The subroutine is verified where it lives in the file, not where it runs: the
    # startup copy puts it at code_dst, which is past the end of the image.
    for i, (v, note) in enumerate(body):
        changes.append((code_src + i * 4, v,
                        f"  runs at 0x{code_dst + i*4:08X}: {note}"))
    return changes, f"subroutine at 0x{code_dst:08X}, {n} bytes; heap at 0x{heap:08X}"


def settle(exe, changes):
    """Collapse a composed change list to what the file actually holds.

    Composing variants means one can overwrite another's word, so the reported value
    has to come from the buffer rather than from whichever variant wrote last.
    """
    seen = {}
    for ram, _, note in changes:
        seen[ram] = note
    return [(ram, word(exe, ram), note) for ram, note in seen.items()]


def variant_d(exe):
    """a + b: row 40 and page 15 together, one 15-column strip at (961, 480).

    Each alone renders correctly, so the fault needs at least two of them. This is the
    pair v106 and v107 both carry.
    """
    ca, na = variant_a(exe)
    cb, nb = variant_b(exe)
    # variant_a and variant_b each rewrote the rectangle for their own move; redo it
    # from the two changes combined.
    tp, u, row = 0x1F, 4, 40
    x = (tp & 0xF) * 64 + u // 4
    y = ((tp >> 4) & 1) * 256 + ((row * 12) & 0xFF)
    put(exe, RECT, (y << 16) | x)
    changes = settle(exe, [c for c in ca + cb if c[0] != RECT]
                          + [(RECT, 0, f"rect -> x {x}, y {y}")])
    return changes, f"{na}; {nb}; strip at ({x}, {y})"


def variant_e(exe):
    """a + b + c: everything v106 changed except the split into two strips.

    If d renders and e does not, the subroutine form only fails in combination; if both
    render, what remains is the two-strip split itself -- the second row, the narrower
    13 columns, and the classifier accepting two values.
    """
    cd, nd = variant_d(exe)
    cc, nc = variant_c(exe)
    # variant_c wrote a subroutine comparing 32; the row moved, so it must compare 224
    code_src = GLYPH_SRC + STRIP_BYTES
    v = (40 * 12) & 0xFF
    put(exe, code_src + 8, addiu(T8, V0, -v))
    changes = settle(exe, cd + cc
                          + [(code_src + 8, 0, f"  subroutine compare 32 -> {v}")])
    return changes, f"{nd}; {nc}; subroutine compares {v}"


VARIANTS = [
    ("v108a", "row_only", variant_a,
     "row 24 -> 40 (V 32 -> 224); page, U offset and inline classifier unchanged"),
    ("v108b", "page_only", variant_b,
     "tpage 0x1B -> 0x1F and U offset 40 -> 4; row and classifier unchanged"),
    ("v108c", "classifier_only", variant_c,
     "inline classifier -> subroutine, still comparing 32; everything else unchanged"),
    ("v108d", "row_and_page", variant_d,
     "a + b: row 40 and page 15 together, one 15-column strip at (961, 480)"),
    ("v108e", "row_page_classifier", variant_e,
     "a + b + c: everything v106 changed except the split into two strips"),
]


def main() -> None:
    only = sys.argv[1:] or None
    for tag, slug, fn, headline in VARIANTS:
        if only and tag not in only:
            continue
        infos, members, exe = load()
        before = bytes(exe)
        changes, note = fn(exe)

        for ram, val, _ in changes:
            if word(exe, ram) != val:
                raise SystemExit(f"{tag}: readback failed at 0x{ram:08X}")
        if len(exe) != len(before):
            raise SystemExit(f"{tag}: the executable changed size")
        diff = [i for i in range(0, len(before), 4) if before[i:i+4] != exe[i:i+4]]
        touched = {r - RAM_TO_FILE for r, _, _ in changes}
        stray = [i for i in diff if i not in touched
                 and not (LOOKUP - RAM_TO_FILE <= i < LOOKUP - RAM_TO_FILE + LOOKUP_N * 2)]
        if stray:
            raise SystemExit(f"{tag}: {len(stray)} words changed that were not intended, "
                             f"first at 0x{stray[0] + RAM_TO_FILE:08X}")

        members[PSX] = bytes(exe)
        out = ROOT / f"03_output/ui_hud_e7_{tag}_{slug}_patch_only.zip"
        if out.exists():
            raise SystemExit(f"{out.name} already exists; refusing to overwrite")
        with ZipFile(out, "w") as t:
            for i in infos:
                t.writestr(clone(i), members[i.filename])
        with ZipFile(out) as a:
            for name in members:
                if a.read(name) != members[name]:
                    raise SystemExit(f"{tag}: archive readback of {name} failed")

        print(f"\n=== {tag}: {headline} ===")
        print(f"  {note}")
        print(f"  {out.name}")
        print(f"  sha256 {sha256(out.read_bytes())}")
        print(f"  PSX.EXE {len(members[PSX])} bytes (unchanged), "
              f"{len(diff)} words differ from v103")
        for ram, val, n2 in changes:
            print(f"    0x{ram:08X}  {val:08X}  {n2}")


if __name__ == "__main__":
    main()
