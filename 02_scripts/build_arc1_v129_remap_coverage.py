"""v129: give 러 and 뜨 the strip D slots v127 forgot to give them.

v127 restored the skill-range artwork and moved the Korean glyphs that had been
living in those 16 cells into a fourth resident strip, redirecting their physical
indices through a remap table. It moved 46 of them. Two were left behind:

    index 1021  러   direct code E0 25   436 occurrences in the shipped archive
    index 1023  뜨   direct code E0 27    98 occurrences

Their cells now hold artwork again and their remap entries are still FF, so both
codes draw artwork pixels. 러 does exist a second time at index 1305, but the text
uses E0 25 and nothing redirects it; 뜨 has no other home and cannot be drawn at all.

The repair is small because strip D was built with room: 47 of its 52 slots are used.
The two glyphs are copied out of v126 -- the last build in which those cells still
held them -- into slots 47 and 48, and their two remap entries are pointed there.

What the earlier verification missed is worth stating, because it is the general
lesson: it confirmed that the 46 relocated glyphs read back correctly at their new
address. Reading back what was moved says nothing about what was left. The check that
finds this walks every plane of the vacated region and requires each one that held a
character to have a destination. That check is run here, over all 64 planes, and it is
what makes this build's claim different from the one it repairs.
"""
from __future__ import annotations

import hashlib
import pickle
import sys
import zipfile
from pathlib import Path
from zipfile import ZipFile, ZipInfo

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))
sys.path.insert(0, str(ROOT / "06_tools" / "python_packages"))

from build_story_sf0b1_return_full import get_pixel  # noqa: E402

BASE_ZIP = ROOT / "03_output/arc1_v128_all_battle_choices_patch_only.zip"
BASE_SHA = "E41FDD3A7FEB4B8874E1D05D9C9B77E74928F3CA527C71288F5516CD63CBA200"
PRIOR_ZIP = ROOT / "03_output/arc1_v126_wording_patch_only.zip"
PRIOR_SHA = "C6152A6FEBAF1DD69398013A58A45E25F880ADBC150256EB9821CA3C42700195"
OUT_DIR, OUT_STEM = ROOT / "03_output", "arc1_v129_remap_coverage"
ANALYSIS = ROOT / "01_work/analysis/arc1_v129_remap_coverage"
CACHE = Path(
    r"C:\Users\ADMINI~1\AppData\Local\Temp\claude\E--korean"
    r"\328ae25b-6478-4de1-a913-c780c9b01e72\scratchpad\hangul_bitmaps.pkl"
)

RAM_TO_FILE = 0x8011A800
BLOCK_SRC, BLOCK_DST = 0x801A86EC, 0x801FE3C4
STRIP_D_RAM, REMAP_RAM = 0x801FF44C, 0x801FF7F4
STRIP_BYTES, STRIP_ROW_BYTES = 936, 78
CELL, PLANES, IPR = 12, 4, 84
STRIP_D_ROW = 52

# the restored artwork occupies COMM.IMG rows 10..13, columns 2..5
ROWS, COLS = range(10, 14), range(2, 6)
MISSING = {1021: 47, 1023: 48}          # physical index -> the strip D slot it gets


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def clone(info: ZipInfo) -> ZipInfo:
    out = ZipInfo(info.filename, info.date_time)
    for attr in ("compress_type", "comment", "extra", "create_system", "create_version",
                 "extract_version", "flag_bits", "volume", "internal_attr",
                 "external_attr"):
        setattr(out, attr, getattr(info, attr))
    return out


def comm_plane(font: bytes, index: int) -> tuple[int, ...]:
    row, remainder = divmod(index, IPR)
    column, plane = divmod(remainder, PLANES)
    bit = 1 << plane
    return tuple(1 if get_pixel(font, column * CELL + x, row * CELL + y) & bit else 0
                 for y in range(CELL) for x in range(CELL))


def strip_slot(strip: bytes, slot: int) -> tuple[int, ...]:
    column, plane = divmod(slot, PLANES)
    bit = 1 << plane
    out = []
    for y in range(CELL):
        for x in range(CELL):
            px = column * CELL + x
            byte = strip[y * STRIP_ROW_BYTES + px // 2]
            out.append(1 if (byte & 0x0F if px % 2 == 0 else byte >> 4) & bit else 0)
    return tuple(out)


def write_slot(strip: bytearray, slot: int, bits: tuple[int, ...]) -> None:
    column, plane = divmod(slot, PLANES)
    for y in range(CELL):
        for x in range(CELL):
            px = column * CELL + x
            off, shift = y * STRIP_ROW_BYTES + px // 2, (0 if px % 2 == 0 else 4)
            nib = (strip[off] >> shift) & 0xF
            nib = nib | (1 << plane) if bits[y * CELL + x] else nib & ~(1 << plane)
            strip[off] = (strip[off] & ~(0xF << shift)) | (nib << shift)


def remap_entry(index: int) -> int:
    """Where this physical index sits in the 64-byte table, in the builder's order."""
    row, remainder = divmod(index, IPR)
    column, plane = divmod(remainder, PLANES)
    if row not in ROWS or column not in COLS:
        raise SystemExit(f"index {index} is not in the restored region")
    return (row - 10) * 16 + (column - 2) * 4 + plane


def main() -> None:
    if digest(BASE_ZIP.read_bytes()) != BASE_SHA:
        raise SystemExit("base archive is not v128")
    if digest(PRIOR_ZIP.read_bytes()) != PRIOR_SHA:
        raise SystemExit("v126 is needed for the glyphs and its digest differs")
    with ZipFile(BASE_ZIP) as archive:
        infos = archive.infolist()
        members = {i.filename: archive.read(i.filename) for i in infos}
    with ZipFile(PRIOR_ZIP) as archive:
        prior_font = archive.read("COMM.IMG")

    exe = bytearray(members["PSX.EXE"])
    d_at = BLOCK_SRC + (STRIP_D_RAM - BLOCK_DST) - RAM_TO_FILE
    t_at = BLOCK_SRC + (REMAP_RAM - BLOCK_DST) - RAM_TO_FILE
    strip = bytearray(exe[d_at:d_at + STRIP_BYTES])
    table = bytearray(exe[t_at:t_at + 64])
    shapes: dict[tuple[int, ...], str] = pickle.loads(CACHE.read_bytes())

    placed = []
    for index, slot in MISSING.items():
        entry = remap_entry(index)
        if table[entry] != 0xFF:
            raise SystemExit(f"index {index} already maps to slot {table[entry]}")
        if any(strip_slot(bytes(strip), slot)):
            raise SystemExit(f"strip D slot {slot} is not empty")
        bits = comm_plane(prior_font, index)
        name = shapes.get(bits)
        if not any(bits) or name is None:
            raise SystemExit(f"v126 index {index} does not hold a named glyph")
        write_slot(strip, slot, bits)
        table[entry] = slot
        placed.append((index, slot, entry, name))

    exe[d_at:d_at + STRIP_BYTES] = strip
    exe[t_at:t_at + 64] = table

    # every plane of the vacated region must now have somewhere to go
    uncovered = []
    for row in ROWS:
        for column in COLS:
            for plane in range(PLANES):
                index = row * IPR + column * PLANES + plane
                bits = comm_plane(prior_font, index)
                name = shapes.get(bits)
                entry = table[remap_entry(index)]
                if name is not None and entry == 0xFF:
                    uncovered.append((index, name))
                if entry != 0xFF and strip_slot(bytes(strip), entry) != bits:
                    raise SystemExit(f"index {index} -> slot {entry} bitmap differs")
    if uncovered:
        raise SystemExit(f"still uncovered: {uncovered}")

    before = members["PSX.EXE"]
    changed = [i for i in range(len(before)) if before[i] != exe[i]]
    allowed = set(range(d_at, d_at + STRIP_BYTES)) | set(range(t_at, t_at + 64))
    stray = [i for i in changed if i not in allowed]
    if stray:
        raise SystemExit(f"{len(stray)} bytes changed outside strip D and the table")
    if len(exe) != len(before):
        raise SystemExit("PSX.EXE changed size")
    members["PSX.EXE"] = bytes(exe)

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    tmp = OUT_DIR / f"{OUT_STEM}_building.zip"
    with ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as archive:
        for info in infos:
            archive.writestr(clone(info), members[info.filename])
    with ZipFile(tmp) as check:
        rebuilt = {i.filename: check.read(i.filename) for i in check.infolist()}
    if rebuilt != members:
        raise SystemExit("the archive did not read back as written")
    with ZipFile(BASE_ZIP) as base:
        differing = sorted(n for n in rebuilt if rebuilt[n] != base.read(n))
    if differing != ["PSX.EXE"]:
        raise SystemExit(f"members differing from v128: {differing}")

    stamp = digest(tmp.read_bytes())
    final = OUT_DIR / f"{OUT_STEM}_{stamp[:8]}.zip"
    tmp.replace(final)
    (OUT_DIR / "LATEST.txt").write_text(
        f"ship this one\n  file    {final.name}\n  sha256  {stamp}\n", encoding="utf-8")

    lines = [
        "v129 the two glyphs v127's remap left behind",
        "",
        f"base    {BASE_ZIP.name}",
        f"output  {final.name}",
        f"        sha256 {stamp}",
        f"PSX.EXE {len(exe)} bytes, unchanged; every other member byte-identical to v128",
        "",
        "placed",
        *(f"  index {i:>5}  {n}  -> strip D slot {s}, remap entry {e}"
          for i, s, e, n in placed),
        "",
        f"bytes changed  {len(changed)}, all inside strip D and the 64-byte remap table",
        "",
        "why they were missing",
        "  v127 restored the skill-range artwork and moved 46 of the 48 Korean planes",
        "  that had been living in those cells into strip D. 러 and 뜨 kept their FF",
        "  entries, so their codes E0 25 and E0 27 -- 436 and 98 uses in the shipped",
        "  archive -- resolved to artwork. 뜨 had no second home and could not be drawn",
        "  anywhere in v128.",
        "",
        "verified",
        "  base digest matches v128 and v126's digest matches, since the glyphs come",
        "    from the last build that still held them",
        "  both target slots were empty and both remap entries were FF before writing",
        "  every plane of the restored region that names a character now has a slot",
        "  every mapped entry's slot holds exactly that plane's v126 bitmap",
        "  no byte changed outside strip D and the remap table; PSX.EXE keeps its size",
        "  only PSX.EXE differs from v128; the archive reads back as written",
        "",
        "NOT verified here: a cold boot. Look for 러 in ordinary dialogue -- 그러면,",
        "데리러 -- and 뜨 in 쓰러뜨리다, and check the skill-range cross is still whole.",
        "",
        "rollback: v128",
    ]
    ANALYSIS.mkdir(parents=True, exist_ok=True)
    (ANALYSIS / "build_report.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
