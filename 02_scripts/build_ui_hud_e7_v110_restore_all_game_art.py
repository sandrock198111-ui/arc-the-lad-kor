"""v110: give back every piece of game artwork the font replacement overwrote.

v109 fixed one instance by hand: the battle range overlay's tile, which the Hangul font
had been written on top of. Auditing the whole file the same way -- a changed byte is
safe only if the original byte was zero -- finds 120 such cells, of which the range
overlay was four. Whatever draws the other 116 will look the same way when it appears,
which is how the range overlay went unnoticed until a skill levelled up and grew from
one tile to a cross.

117 of the cells carry no glyph at all. The artwork there was destroyed for nothing and
restoring it costs nothing. The remaining three hold a glyph, which has to move first.

Relocation targets are chosen by the property that matters, learned the hard way: a
cell is safe only if it is entirely blank in the ORIGINAL COMM.IMG. Being unreferenced
by the lookup table means nothing -- the range overlay's cells were unreferenced too,
and the game was drawing them.

Targets stay inside the base atlas, so no P6 machinery is involved and the glyphs
render through the ordinary path.
"""
from __future__ import annotations

import hashlib
import struct
from pathlib import Path
from zipfile import ZipFile, ZipInfo

ROOT = Path(__file__).resolve().parents[1]
BASE_ZIP = ROOT / "03_output/ui_hud_e7_v109_restore_range_overlay_patch_only.zip"
BASE_SHA = "C7976E965EC3BF3F30A2D6EE8EC8DC76EA59E316E6C5BD5D8FE85F2E35D4DC5D"
OUTPUT = ROOT / "03_output/ui_hud_e7_v110_restore_all_game_art_patch_only.zip"
REPORT = ROOT / "01_work/analysis/ui_hud_e7_v110_restore_all_game_art/build_report.txt"
ORIG_ISO = Path(r"E:\arc\원본\arc1.bin")

PSX, IMG = "PSX.EXE", "COMM.IMG"
RAM_TO_FILE = 0x8011A800
RAW, COMM_LBA, COMM_SIZE = 2352, 667, 458752
STRIP_ROW, X0 = 896, 320
CELL, COLS, PLANES = 12, 21, 4
IPR = COLS * PLANES
LOOKUP, LOOKUP_N = 0x801A7520, 409
BASE_ROWS = 24                                  # rows 0..23 are the ordinary atlas
BASE_X4, P6_X4, P6_ROW = X0 * 4, 2856, 24


def sha256(b): return hashlib.sha256(b).hexdigest().upper()


def clone(i: ZipInfo) -> ZipInfo:
    t = ZipInfo(i.filename, i.date_time)
    for a in ("compress_type", "comment", "extra", "create_system", "create_version",
              "extract_version", "flag_bits", "volume", "internal_attr",
              "external_attr"):
        setattr(t, a, getattr(i, a))
    return t


def read_original() -> bytes:
    with ORIG_ISO.open("rb") as raw:
        def sector(l):
            raw.seek(l * RAW)
            s = raw.read(RAW)
            return s[24:24 + 2048] if s[15] == 2 else s[16:16 + 2048]
        return b"".join(sector(COMM_LBA + i) for i in range(COMM_SIZE // 2048))


def origin(row, col):
    x0 = P6_X4 if row == P6_ROW else BASE_X4
    return x0 + col * CELL, row * CELL


def cell_bytes(row, col):
    """Every COMM.IMG byte offset belonging to one 12x12 cell."""
    x4, y = origin(row, col)
    lo = (x4 - BASE_X4) // 2
    return [(y + dy) * STRIP_ROW + lo + k
            for dy in range(CELL) for k in range(CELL // 2)]


def nib(buf, x4, y):
    return (buf[y * STRIP_ROW + (x4 - BASE_X4) // 2] >> (0 if x4 % 2 == 0 else 4)) & 0xF


def set_plane(buf, x4, y, plane, on):
    o = y * STRIP_ROW + (x4 - BASE_X4) // 2
    sh = 0 if x4 % 2 == 0 else 4
    v = (buf[o] >> sh) & 0xF
    v = (v | (1 << plane)) if on else (v & ~(1 << plane))
    buf[o] = (buf[o] & ~(0xF << sh)) | (v << sh)


def main() -> None:
    if sha256(BASE_ZIP.read_bytes()) != BASE_SHA:
        raise SystemExit("base archive is not the verified v109 build")
    with ZipFile(BASE_ZIP) as a:
        infos = a.infolist()
        members = {i.filename: a.read(i.filename) for i in infos}
    exe = bytearray(members[PSX])
    comm = bytearray(members[IMG])
    orig = read_original()
    if len(orig) != len(comm):
        raise SystemExit("COMM.IMG sizes differ")

    lut = list(struct.unpack_from(f"<{LOOKUP_N}H", exe, LOOKUP - RAM_TO_FILE))
    placed = {}
    for slot, v in enumerate(lut):
        placed.setdefault((v // IPR, (v % IPR) // PLANES), []).append((slot, v))

    # every cell where the patch destroyed something the original had drawn
    damaged = set()
    for i in range(len(orig)):
        if orig[i] and orig[i] != comm[i]:
            y, bx = divmod(i, STRIP_ROW)
            x4 = BASE_X4 + bx * 2
            row = y // CELL
            col = ((x4 - P6_X4) if x4 >= P6_X4 else (x4 - BASE_X4)) // CELL
            damaged.add((row, col))
    if not damaged:
        raise SystemExit("nothing to restore")

    # a cell is a safe home only if the ORIGINAL file leaves it entirely blank
    def blank_in_original(row, col):
        return not any(orig[i] for i in cell_bytes(row, col))

    free = [(r, c) for r in range(BASE_ROWS) for c in range(COLS)
            if (r, c) not in placed and (r, c) not in damaged
            and blank_in_original(r, c)]
    need = [cell for cell in sorted(damaged) if cell in placed]
    if len(free) < len(need):
        raise SystemExit(f"{len(need)} cells to vacate but only {len(free)} safe homes")

    # 1. move the glyphs that sit on damaged artwork
    moves = []
    for cell, home in zip(need, free):
        orow, ocol = cell
        nrow, ncol = home
        ox, oy = origin(orow, ocol)
        nx, ny = origin(nrow, ncol)
        for dy in range(CELL):
            for dx in range(CELL):
                v = nib(comm, ox + dx, oy + dy)
                for p in range(PLANES):
                    set_plane(comm, nx + dx, ny + dy, p, (v >> p) & 1)
        for slot, old in placed[cell]:
            lut[slot] = nrow * IPR + ncol * PLANES + (old % PLANES)
        moves.append((cell, home, [s for s, _ in placed[cell]]))

    # 2. restore every damaged cell
    restored_cells, restored_bytes = 0, 0
    for row, col in sorted(damaged):
        idx = cell_bytes(row, col)
        n = sum(1 for i in idx if comm[i] != orig[i])
        for i in idx:
            comm[i] = orig[i]
        restored_cells += 1
        restored_bytes += n

    struct.pack_into(f"<{LOOKUP_N}H", exe, LOOKUP - RAM_TO_FILE, *lut)

    # --- checks ---
    left = [i for i in range(len(orig)) if orig[i] and orig[i] != comm[i]]
    if left:
        raise SystemExit(f"{len(left)} bytes of original artwork are still overwritten")
    for cell, home, slots in moves:
        x4, y = origin(*home)
        if not any(nib(comm, x4 + dx, y + dy)
                   for dy in range(CELL) for dx in range(CELL)):
            raise SystemExit(f"glyph moved to {home} came out blank")
    back = struct.unpack_from(f"<{LOOKUP_N}H", exe, LOOKUP - RAM_TO_FILE)
    if list(back) != lut:
        raise SystemExit("lookup readback failed")
    moved_cells = {h for _, h, _ in moves}
    for v in back:
        c = (v // IPR, (v % IPR) // PLANES)
        if c in damaged and c not in moved_cells:
            raise SystemExit(f"a glyph still sits on damaged cell {c}")
    if len(comm) != len(members[IMG]) or len(exe) != len(members[PSX]):
        raise SystemExit("a file changed size")

    members[PSX], members[IMG] = bytes(exe), bytes(comm)
    if OUTPUT.exists():
        raise SystemExit(f"{OUTPUT.name} already exists")
    with ZipFile(OUTPUT, "w") as t:
        for i in infos:
            t.writestr(clone(i), members[i.filename])
    with ZipFile(OUTPUT) as a:
        for n2 in members:
            if a.read(n2) != members[n2]:
                raise SystemExit(f"archive readback of {n2} failed")

    lines = [
        "v110 restore every piece of game artwork the font replacement overwrote",
        "",
        f"base    {BASE_ZIP.name}",
        f"output  {OUTPUT.name}",
        f"        sha256 {sha256(OUTPUT.read_bytes())}",
        "neither file changes size, so the v104 disc layout still applies",
        "",
        f"cells restored : {restored_cells}",
        f"bytes restored : {restored_bytes}",
        f"glyphs moved   : {len(moves)}",
        "",
        "a cell counted as damaged when a byte the patch changed was non-zero in the",
        "original: that is artwork, not empty space. after this build no such byte",
        "remains anywhere in COMM.IMG.",
        "",
        "glyphs moved, and where to",
    ]
    for cell, home, slots in moves:
        x4, y = origin(*home)
        lines.append(f"  row {cell[0]:>2} col {cell[1]:>2} -> row {home[0]:>2} "
                     f"col {home[1]:>2}   table slots {slots}   "
                     f"VRAM x {x4 // 4}..{x4 // 4 + 2}, y {y}..{y + 11}")
    lines += [
        "",
        "homes were chosen by the only property that has held up: entirely blank in the",
        "original COMM.IMG. being unreferenced by the lookup table proves nothing -- the",
        "range overlay's cells were unreferenced and the game was drawing them.",
        "",
        "rollback: 99_backup/baselines/ui_hud_e7_v104_runtime_success_2026-08-01/",
        "",
        "Rebuild with arc1_v104.xml, then run:",
        f"  python 02_scripts/verify_iso_layout.py E:\\arc\\arc1_v104.bin {OUTPUT.name}",
        "  python 02_scripts/audit_overwritten_game_art.py " + OUTPUT.name,
    ]
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
