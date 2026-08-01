"""v109: give the battle range overlay its texture back.

The skill range renders as garbled letters. It is not the P6 glyph store: in the frame
where it happens, no primitive reads the P6 page at all, and there is only one copy of
the P6 atlas in VRAM. The unpatched disc renders the same range correctly, which made
the comparison possible.

In the unpatched savestate the four primitives that draw the cross -- at screen
(160,64), (128,96), (192,96) and (160,128) -- all sample texture page 5,0 at
VRAM x 328..336, y 128..160. Reading COMM.IMG there in the original shows a hollow
rectangular frame, which is exactly the tile the cross is made of. The patched file has
Hangul over it: 395 of the 594 bytes inside that rectangle differ.

So the Hangul font replacement wrote glyphs onto a UI texture that happens to live
inside the font atlas. That predates the glyph-store work entirely, which is why moving
the P6 strip never helped.

The rectangle covers base-atlas rows 10..13, columns 2..5 -- 64 glyph slots, of which
the lookup table references exactly two:

    table slot 42 -> row 11, column 5, plane 0
    table slot 46 -> row 11, column 4, plane 3

This build moves those two into free planes of the P6 strip and restores all sixteen
cells to their original pixels. Whole cells are restored rather than the sampled
rectangle alone, so no half-overwritten cell is left behind.

The P6 strip is the right home for them: it was blank in the original COMM.IMG, so
nothing else can be reading it, which is the property the base atlas turned out not to
have.
"""
from __future__ import annotations

import hashlib
import struct
from pathlib import Path
from zipfile import ZipFile, ZipInfo

ROOT = Path(__file__).resolve().parents[1]
BASE_ZIP = ROOT / "03_output/ui_hud_e7_v103_heap_reserved_glyphs_patch_only.zip"
BASE_SHA = "9EE40993E72962F26DAFBD61CA565D4646E247D9990B79EF5122776838584FD3"
OUTPUT = ROOT / "03_output/ui_hud_e7_v109_restore_range_overlay_patch_only.zip"
REPORT = ROOT / "01_work/analysis/ui_hud_e7_v109_restore_range_overlay/build_report.txt"
ORIG_ISO = Path(r"E:\arc\원본\arc1.bin")

PSX, IMG = "PSX.EXE", "COMM.IMG"
RAM_TO_FILE = 0x8011A800
RAW, COMM_LBA, COMM_SIZE = 2352, 667, 458752
STRIP_ROW, X0 = 896, 320                    # COMM.IMG uploads at 16-bit x 320
CELL, COLS, PLANES = 12, 21, 4
IPR = COLS * PLANES                         # 84 indices per atlas row
LOOKUP, LOOKUP_N = 0x801A7520, 409

# the rectangle the range overlay samples, rounded out to whole glyph cells
BAD_ROWS, BAD_COLS = range(10, 14), range(2, 6)
P6_ROW, P6_COLS = 24, 15                    # the strip the patch uploads every frame


def sha256(b): return hashlib.sha256(b).hexdigest().upper()


def clone(i: ZipInfo) -> ZipInfo:
    t = ZipInfo(i.filename, i.date_time)
    for a in ("compress_type", "comment", "extra", "create_system", "create_version",
              "extract_version", "flag_bits", "volume", "internal_attr",
              "external_attr"):
        setattr(t, a, getattr(i, a))
    return t


def read_original_comm() -> bytes:
    with ORIG_ISO.open("rb") as raw:
        def sector(l):
            raw.seek(l * RAW)
            s = raw.read(RAW)
            return s[24:24 + 2048] if s[15] == 2 else s[16:16 + 2048]
        return b"".join(sector(COMM_LBA + i) for i in range(COMM_SIZE // 2048))


def nib(buf, x4, y):
    """One 4bpp pixel, addressed by absolute 4bpp x and strip row y."""
    bx = (x4 - X0 * 4) // 2
    byt = buf[y * STRIP_ROW + bx]
    return (byt >> (0 if x4 % 2 == 0 else 4)) & 0xF


def set_plane(buf, x4, y, plane, on):
    bx = (x4 - X0 * 4) // 2
    o = y * STRIP_ROW + bx
    sh = 0 if x4 % 2 == 0 else 4
    v = (buf[o] >> sh) & 0xF
    v = (v | (1 << plane)) if on else (v & ~(1 << plane))
    buf[o] = (buf[o] & ~(0xF << sh)) | (v << sh)


BASE_X4, P6_X4 = X0 * 4, 2856                  # the two atlas origins, in 4bpp pixels


def cell_origin(row, col):
    """4bpp x and strip row for a cell.

    The P6 row does not sit beside the base atlas: the renderer gives it its own
    texture page and a U offset, and COMM.IMG carries it at 4bpp x 2856. Computing it
    from the base origin silently writes into the middle of the base atlas instead,
    which is what the first attempt did -- and its own readback agreed, because it read
    from the same wrong address.
    """
    x0 = P6_X4 if row == P6_ROW else BASE_X4
    return x0 + col * CELL, row * CELL


def main() -> None:
    if sha256(BASE_ZIP.read_bytes()) != BASE_SHA:
        raise SystemExit("base archive is not the verified v103 build")
    with ZipFile(BASE_ZIP) as a:
        infos = a.infolist()
        members = {i.filename: a.read(i.filename) for i in infos}
    exe = bytearray(members[PSX])
    comm = bytearray(members[IMG])
    orig = read_original_comm()
    if len(orig) != len(comm):
        raise SystemExit("COMM.IMG sizes differ")

    lut = list(struct.unpack_from(f"<{LOOKUP_N}H", exe, LOOKUP - RAM_TO_FILE))
    bad = {r * IPR + c * PLANES + p
           for r in BAD_ROWS for c in BAD_COLS for p in range(PLANES)}
    victims = [(i, v) for i, v in enumerate(lut) if v in bad]
    if not victims:
        raise SystemExit("no lookup entry sits on the overlay rectangle; nothing to do")

    # free planes inside the strip the patch actually uploads
    used = set(lut)
    free = [P6_ROW * IPR + c * PLANES + p
            for c in range(P6_COLS) for p in range(PLANES)
            if P6_ROW * IPR + c * PLANES + p not in used]
    if len(free) < len(victims):
        raise SystemExit(f"{len(victims)} glyphs to move but only {len(free)} free "
                         f"slots inside the uploaded strip")

    # 1. copy each victim's bitmap to its new slot, before anything is restored
    moves = []
    for (slot, old), new in zip(victims, free):
        orow, ocol, oplane = old // IPR, (old % IPR) // PLANES, old % PLANES
        nrow, ncol, nplane = new // IPR, (new % IPR) // PLANES, new % PLANES
        ox, oy = cell_origin(orow, ocol)
        nx, ny = cell_origin(nrow, ncol)
        painted = 0
        for dy in range(CELL):
            for dx in range(CELL):
                on = (nib(comm, ox + dx, oy + dy) >> oplane) & 1
                set_plane(comm, nx + dx, ny + dy, nplane, on)
                painted += on
        if not painted:
            raise SystemExit(f"table slot {slot} has a blank bitmap; refusing to guess")
        lut[slot] = new
        moves.append((slot, old, new, orow, ocol, oplane, nrow, ncol, nplane, painted))

    # 2. restore the sixteen cells to the original artwork
    restored = 0
    for r in BAD_ROWS:
        for c in BAD_COLS:
            x4, y = cell_origin(r, c)
            for dy in range(CELL):
                lo = (y + dy) * STRIP_ROW + (x4 - X0 * 4) // 2
                hi = lo + CELL // 2
                restored += sum(1 for k in range(lo, hi) if comm[k] != orig[k])
                comm[lo:hi] = orig[lo:hi]

    struct.pack_into(f"<{LOOKUP_N}H", exe, LOOKUP - RAM_TO_FILE, *lut)

    # --- checks ---
    for r in BAD_ROWS:
        for c in BAD_COLS:
            x4, y = cell_origin(r, c)
            for dy in range(CELL):
                lo = (y + dy) * STRIP_ROW + (x4 - X0 * 4) // 2
                if comm[lo:lo + CELL // 2] != orig[lo:lo + CELL // 2]:
                    raise SystemExit(f"cell row {r} col {c} did not restore")
    back = struct.unpack_from(f"<{LOOKUP_N}H", exe, LOOKUP - RAM_TO_FILE)
    if list(back) != lut:
        raise SystemExit("lookup table readback failed")
    if any(v in bad for v in back):
        raise SystemExit("a lookup entry still points at the overlay rectangle")
    if len(set(back)) != len(set(struct.unpack_from(
            f"<{LOOKUP_N}H", members[PSX], LOOKUP - RAM_TO_FILE))):
        raise SystemExit("the number of distinct glyph slots changed")
    off = (P6_X4 - X0 * 4) // 2
    strip = b"".join(comm[y * STRIP_ROW + off: y * STRIP_ROW + off + P6_COLS * 6]
                     for y in range(P6_ROW * CELL, P6_ROW * CELL + CELL))
    for _, _, new, _, _, _, nrow, ncol, nplane, painted in moves:
        if nrow != P6_ROW:
            raise SystemExit("relocation target is outside the uploaded strip")
        on = sum(1 for r in range(CELL) for px in range(ncol * CELL, (ncol + 1) * CELL)
                 if (strip[r * P6_COLS * 6 + px // 2] >> (0 if px % 2 == 0 else 4))
                 >> nplane & 1)
        if on != painted:
            raise SystemExit(f"glyph {new} has {on} pixels inside the uploaded strip, "
                             f"expected {painted}")
    if len(comm) != len(members[IMG]) or len(exe) != len(members[PSX]):
        raise SystemExit("a file changed size")

    members[PSX], members[IMG] = bytes(exe), bytes(comm)
    if OUTPUT.exists():
        raise SystemExit(f"{OUTPUT.name} already exists")
    with ZipFile(OUTPUT, "w") as t:
        for i in infos:
            t.writestr(clone(i), members[i.filename])
    with ZipFile(OUTPUT) as a:
        for name in members:
            if a.read(name) != members[name]:
                raise SystemExit(f"archive readback of {name} failed")

    lines = [
        "v109 restore the battle range overlay's texture",
        "",
        f"base    {BASE_ZIP.name}",
        f"output  {OUTPUT.name}",
        f"        sha256 {sha256(OUTPUT.read_bytes())}",
        "neither file changes size, so the v104 disc layout still applies",
        "",
        "what was wrong",
        "  the range overlay samples texture page 5,0 at VRAM x 328..336, y 128..160",
        "  the original COMM.IMG holds a hollow rectangular frame there",
        "  the Hangul font replacement wrote glyphs over it",
        "",
        f"restored: base-atlas rows {BAD_ROWS.start}..{BAD_ROWS.stop - 1}, "
        f"columns {BAD_COLS.start}..{BAD_COLS.stop - 1}  "
        f"({len(list(BAD_ROWS)) * len(list(BAD_COLS))} cells, {restored} bytes)",
        "",
        "glyphs moved out of the way",
    ]
    for slot, old, new, orow, ocol, oplane, nrow, ncol, nplane, painted in moves:
        lines.append(f"  table slot {slot:>3}: {old} -> {new}   "
                     f"row {orow} col {ocol} plane {oplane} -> "
                     f"row {nrow} col {ncol} plane {nplane}   {painted} pixels")
    lines += [
        "",
        "the P6 strip is safe for them: it is blank in the original COMM.IMG, which is",
        "the property the base atlas turned out not to have.",
        "",
        "rollback: 99_backup/baselines/ui_hud_e7_v104_runtime_success_2026-08-01/",
        "",
        "Rebuild with arc1_v104.xml, then run:",
        f"  python 02_scripts/verify_iso_layout.py E:\\arc\\arc1_v104.bin {OUTPUT.name}",
    ]
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
