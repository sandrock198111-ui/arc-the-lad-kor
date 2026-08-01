"""v111: restore the overwritten artwork that costs nothing, and no more.

v109 and v110 asked the wrong question. They decided a glyph cell was empty by looking
at the lookup table at 0x801A7520, but only characters with lead byte 0xE9 or 0xEA go
through that table. Everything else computes its index straight from the code:

    single byte b < 221         index = b - 1
    two bytes, lead 0xDD..0xE8  index = (lead - 221) * 255 + trail + 219

Almost every Hangul character in this patch is of the second kind, so the table showed
110 occupied cells where the character maps show 152. Restoring "unoccupied" cells
therefore erased real glyphs -- 러 and 고 among them, both inside the battle range
overlay's rectangle.

That rectangle turns out to hold 48 characters. The overlay tile and those 48 want the
same sixteen cells, and nothing in this build can give both. So this build restores only
the damaged cells that no character uses, computed from the character maps rather than
the table. The range overlay stays broken; every glyph keeps working.

Fixing the overlay needs one of two larger changes, neither of which belongs in a build
whose job is to stop the bleeding:
  - re-encode those 48 characters to 0xE9/0xEA codes, which are table-indexed and can
    be relocated, and rewrite every occurrence in the script
  - repoint the overlay's own texture coordinates at blank VRAM and copy the tile there
"""
from __future__ import annotations

import csv
import hashlib
import struct
from pathlib import Path
from zipfile import ZipFile, ZipInfo

ROOT = Path(__file__).resolve().parents[1]
BASE_ZIP = ROOT / "03_output/ui_hud_e7_v103_heap_reserved_glyphs_patch_only.zip"
BASE_SHA = "9EE40993E72962F26DAFBD61CA565D4646E247D9990B79EF5122776838584FD3"
OUTPUT = ROOT / "03_output/ui_hud_e7_v111_restore_unoccupied_art_patch_only.zip"
REPORT = ROOT / "01_work/analysis/ui_hud_e7_v111_restore_unoccupied_art/build_report.txt"
ORIG_ISO = Path(r"E:\arc\원본\arc1.bin")
MAPS = ("korean_charmap.csv", "korean_charmap_extended.csv")

PSX, IMG = "PSX.EXE", "COMM.IMG"
RAM_TO_FILE = 0x8011A800
RAW, COMM_LBA, COMM_SIZE = 2352, 667, 458752
STRIP_ROW, X0 = 896, 320
CELL, COLS, PLANES = 12, 21, 4
IPR = COLS * PLANES
LOOKUP, LOOKUP_N = 0x801A7520, 409
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
    return (P6_X4 if row == P6_ROW else BASE_X4) + col * CELL, row * CELL


def cell_bytes(row, col):
    x4, y = origin(row, col)
    lo = (x4 - BASE_X4) // 2
    return [(y + dy) * STRIP_ROW + lo + k
            for dy in range(CELL) for k in range(CELL // 2)]


def load_charmaps() -> dict[str, int]:
    out = {}
    for name in MAPS:
        p = ROOT / "05_docs" / name
        if not p.exists():
            raise SystemExit(f"missing character map {name}")
        with p.open(encoding="utf-8") as f:
            for row in csv.DictReader(f):
                code = (row.get("code_hex") or "").strip()
                if code:
                    out[row["char"]] = int(code, 16)
    return out


def main() -> None:
    if sha256(BASE_ZIP.read_bytes()) != BASE_SHA:
        raise SystemExit("base archive is not the verified v103 build")
    with ZipFile(BASE_ZIP) as a:
        infos = a.infolist()
        members = {i.filename: a.read(i.filename) for i in infos}
    exe, comm = members[PSX], bytearray(members[IMG])
    orig = read_original()
    if len(orig) != len(comm):
        raise SystemExit("COMM.IMG sizes differ")

    lut = struct.unpack_from(f"<{LOOKUP_N}H", exe, LOOKUP - RAM_TO_FILE)
    chars = load_charmaps()

    def index_of(code):
        if code <= 0xFF:
            return code - 1
        lead, trail = code >> 8, code & 0xFF
        if lead in (0xE9, 0xEA):
            slot = (lead - 0xE9) * 254 + trail - 1
            return lut[slot] if 0 <= slot < LOOKUP_N else None
        if lead >= 0xDD:
            return (lead - 221) * 255 + trail + 219
        return None

    occupied = {}
    for ch, code in chars.items():
        idx = index_of(code)
        if idx is None:
            continue
        occupied.setdefault((idx // IPR, (idx % IPR) // PLANES), []).append(ch)
    # the lookup table can also point somewhere no character map mentions
    for v in lut:
        occupied.setdefault((v // IPR, (v % IPR) // PLANES), [])
    print(f"characters mapped: {len(chars)}; cells they occupy: {len(occupied)}")

    damaged = set()
    for i in range(len(orig)):
        if orig[i] and orig[i] != comm[i]:
            y, bx = divmod(i, STRIP_ROW)
            x4 = BASE_X4 + bx * 2
            col = ((x4 - P6_X4) if x4 >= P6_X4 else (x4 - BASE_X4)) // CELL
            damaged.add((y // CELL, col))

    safe = sorted(damaged - set(occupied))
    blocked = sorted(damaged & set(occupied))
    restored_bytes = 0
    for cell in safe:
        for i in cell_bytes(*cell):
            if comm[i] != orig[i]:
                restored_bytes += 1
            comm[i] = orig[i]

    # --- checks: nothing occupied may have moved, and every safe cell must match ---
    for cell in safe:
        idx = cell_bytes(*cell)
        if any(comm[i] != orig[i] for i in idx):
            raise SystemExit(f"cell {cell} did not restore")
    for cell in blocked:
        idx = cell_bytes(*cell)
        if bytes(comm[i] for i in idx) != bytes(members[IMG][i] for i in idx):
            raise SystemExit(f"occupied cell {cell} was modified")
    if bytes(exe) != members[PSX]:
        raise SystemExit("PSX.EXE must not change")
    if len(comm) != len(members[IMG]):
        raise SystemExit("COMM.IMG changed size")

    members[IMG] = bytes(comm)
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
        "v111 restore the overwritten artwork that costs no glyphs",
        "",
        f"base    {BASE_ZIP.name}   (v103, not v109 or v110)",
        f"output  {OUTPUT.name}",
        f"        sha256 {sha256(OUTPUT.read_bytes())}",
        "PSX.EXE is untouched; COMM.IMG keeps its size, so the v104 layout applies",
        "",
        f"cells with destroyed artwork : {len(damaged)}",
        f"  restored, no glyph on them : {len(safe)}  ({restored_bytes} bytes)",
        f"  left alone, a glyph is there: {len(blocked)}",
        "",
        "occupancy is computed from the character maps, not the lookup table:",
        "  single byte b < 221         index = b - 1",
        "  two bytes, lead 0xDD..0xE8  index = (lead - 221) * 255 + trail + 219",
        "  two bytes, lead 0xE9/0xEA   index = table[(lead - 0xE9) * 254 + trail - 1]",
        "only the last consults the table, which is what v109 and v110 got wrong.",
        "",
        "cells left alone, and what lives on them",
    ]
    for cell in blocked:
        who = "".join(occupied[cell]) or "(lookup table only)"
        lines.append(f"  row {cell[0]:>2} col {cell[1]:>2}  {who}")
    lines += [
        "",
        "the battle range overlay is still broken. its rectangle is rows 10..13,",
        "columns 2..5, and 48 characters live there; restoring it would erase them.",
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
