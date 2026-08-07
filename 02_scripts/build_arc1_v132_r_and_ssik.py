"""v132: give R and 씩 the last strip D slots, without changing any structure.

Two characters the translation needs and the build cannot draw:

  R    The original disc draws it at font index 732. A Korean syllable was written over
       that cell years of builds ago, so `LR 버튼` and every other line with an R has
       been refused. 17 uses in the current CSV.
  씩   Never existed anywhere. 6 uses.

Both fit in what v127 already built. Strip D has 52 slots and uses 49; the remap table
that redirects the restored skill-range cells has 64 entries and 16 still read 0xFF.
None of those 16 indices is used by any text, original or ours, so pointing two of them
at two free strip D slots costs a bitmap each and one table byte each. No new strip, no
new classifier test, no LoadImage, no code at all -- the same repair as v129.

R's picture is taken off the original disc rather than redrawn, so what appears in game
is the letter the game itself drew. 씩 comes from the gulim table every other Korean
glyph in this project came from.
"""
from __future__ import annotations

import csv
import hashlib
import pickle
import sys
import zipfile
from collections import Counter
from pathlib import Path
from zipfile import ZipFile, ZipInfo

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))
sys.path.insert(0, str(ROOT / "06_tools" / "python_packages"))

from plan_bulk_insertion import (  # noqa: E402
    CACHE, CELL, IPR, PLANES, RAM_TO_FILE, REMAP_ROWS, REMAP_SRC, STRIPS,
    STRIP_BYTES, STRIP_D_ROW, STRIP_ROW_BYTES, bitmap, original_cell, tokens,
)

BASE_ZIP = ROOT / "03_output/arc1_v131_full_code_space_049E9A2B.zip"
BASE_SHA = "049E9A2B38C250AE8BDD10A63598A9C5B4F211CED939F1B01136AC86542A24DA"
ORIGINAL_CSV = ROOT / "05_docs/script_original_full.csv"
OUT_DIR, OUT_STEM = ROOT / "03_output", "arc1_v132_r_and_ssik"
ANALYSIS = ROOT / "01_work/analysis/arc1_v132_r_and_ssik"

# physical index -> (strip D slot, what goes in it). Both indices are remap entries that
# still read 0xFF and that no text anywhere resolves to.
PLACEMENTS = {1016: (49, "R"), 1017: (50, "씩")}
R_ON_THE_ORIGINAL = 732


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def clone(info: ZipInfo) -> ZipInfo:
    out = ZipInfo(info.filename, info.date_time)
    for attr in ("compress_type", "comment", "extra", "create_system", "create_version",
                 "extract_version", "flag_bits", "volume", "internal_attr",
                 "external_attr"):
        setattr(out, attr, getattr(info, attr))
    return out


def slot_bits(strip: bytes, slot: int) -> tuple[int, ...]:
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
    row, remainder = divmod(index, IPR)
    column, plane = divmod(remainder, PLANES)
    if row not in REMAP_ROWS or column not in range(2, 6):
        raise SystemExit(f"index {index} is outside the remapped region")
    return (row - 10) * 16 + (column - 2) * 4 + plane


def main() -> None:
    if digest(BASE_ZIP.read_bytes()) != BASE_SHA:
        raise SystemExit("base archive is not v131")
    with ZipFile(BASE_ZIP) as archive:
        infos = archive.infolist()
        members = {i.filename: archive.read(i.filename) for i in infos}
    exe = bytearray(members["PSX.EXE"])
    font = members["COMM.IMG"]
    shapes: dict[tuple[int, ...], str] = pickle.loads(CACHE.read_bytes())
    by_name = {}
    for bits, name in shapes.items():
        by_name.setdefault(name, bits)

    d_at = STRIPS[STRIP_D_ROW] - RAM_TO_FILE
    t_at = REMAP_SRC - RAM_TO_FILE
    strip = bytearray(exe[d_at:d_at + STRIP_BYTES])
    table = bytearray(exe[t_at:t_at + 64])

    # Nothing may already be pointing at the indices about to be given a meaning.
    used: Counter = Counter()
    with ZipFile(BASE_ZIP) as archive, ORIGINAL_CSV.open(encoding="utf-8-sig",
                                                         newline="") as handle:
        blobs = {n: archive.read(n) for n in archive.namelist() if n.upper().endswith(".DAT")}
        reader = csv.DictReader(handle)
        key = "offset" if "offset" in (reader.fieldnames or []) else "byte offset"
        for row in reader:
            name = row["source file"]
            if name not in blobs:
                continue
            offset = int(row[key], 0)
            raw = bytes.fromhex(row["raw bytes as hex"].replace(" ", ""))
            for source in (raw, blobs[name][offset:offset + len(raw)]):
                for token in tokens(source):
                    index = (token[0] - 1 if len(token) == 1 else
                             (token[0] - 0xDD) * 255 + token[1] + 0xDB
                             if 0xDD <= token[0] <= 0xE8 else None)
                    if index in PLACEMENTS:
                        used[index] += 1
    if used:
        raise SystemExit(f"those indices are already in use: {dict(used)}")

    placed = []
    for index, (slot, char) in PLACEMENTS.items():
        entry = remap_entry(index)
        if table[entry] != 0xFF:
            raise SystemExit(f"remap entry {entry} already points at slot {table[entry]}")
        if any(slot_bits(bytes(strip), slot)):
            raise SystemExit(f"strip D slot {slot} is not empty")
        bits = original_cell(R_ON_THE_ORIGINAL) if char == "R" else by_name.get(char)
        if not bits or not any(bits):
            raise SystemExit(f"no bitmap for {char}")
        if char != "R" and shapes.get(bits) != char:
            raise SystemExit(f"the bitmap for {char} does not read back as {char}")
        write_slot(strip, slot, bits)
        table[entry] = slot
        placed.append((char, index, slot, entry))

    exe[d_at:d_at + STRIP_BYTES] = strip
    exe[t_at:t_at + 64] = table

    for char, index, slot, entry in placed:
        back = bitmap(bytes(exe), font, index)
        want = original_cell(R_ON_THE_ORIGINAL) if char == "R" else by_name[char]
        if back != want:
            raise SystemExit(f"{char} does not read back through the remap at {index}")
        if char != "R" and shapes.get(back) != char:
            raise SystemExit(f"index {index} does not name {char}")

    before = members["PSX.EXE"]
    changed = [i for i in range(len(before)) if before[i] != exe[i]]
    allowed = set(range(d_at, d_at + STRIP_BYTES)) | set(range(t_at, t_at + 64))
    if stray := [i for i in changed if i not in allowed]:
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
        if {i.filename: check.read(i.filename) for i in check.infolist()} != members:
            raise SystemExit("the archive did not read back as written")
    with ZipFile(BASE_ZIP) as base:
        differing = sorted(n for n in members if members[n] != base.read(n))
    if differing != ["PSX.EXE"]:
        raise SystemExit(f"members differing from v131: {differing}")

    stamp = digest(tmp.read_bytes())
    final = OUT_DIR / f"{OUT_STEM}_{stamp[:8]}.zip"
    tmp.replace(final)
    (OUT_DIR / "LATEST.txt").write_text(
        f"ship this one\n  file    {final.name}\n  sha256  {stamp}\n", encoding="utf-8")

    lines = [
        "v132 R and 씩, in the slots strip D already had",
        "",
        f"base    {BASE_ZIP.name}",
        f"output  {final.name}",
        f"        sha256 {stamp}",
        f"PSX.EXE {len(exe)} bytes, unchanged; every other member byte-identical to v131",
        "",
        "placed",
        *(f"  {c}  -> strip D slot {s}, remap entry {e}, reachable as index {i}"
          for c, i, s, e in placed),
        "",
        f"bytes changed  {len(changed)}, all inside strip D and the 64-byte remap table",
        "",
        "verified",
        "  base digest matches v131",
        "  neither index is resolved by any token, in the original script or in this",
        "    build, so nothing was already relying on them",
        "  both remap entries read 0xFF and both strip D slots were empty before writing",
        "  R's bitmap is the original disc's own cell at index 732, not a redrawing",
        "  씩 reads back as 씩 through the glyph table after the write",
        "  both indices resolve through the remap to the bitmap that was written",
        "  no byte changed outside strip D and the remap table; PSX.EXE keeps its size",
        "  only PSX.EXE differs from v131",
        "",
        "one strip D slot is still free (51), and 14 remap entries still read 0xFF.",
        "",
        "NOT verified here: a cold boot. Read a line with LR 버튼 in it, look for 씩,",
        "and check the skill-range cross is still whole.",
        "",
        "rollback: v131",
    ]
    ANALYSIS.mkdir(parents=True, exist_ok=True)
    (ANALYSIS / "build_report.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
