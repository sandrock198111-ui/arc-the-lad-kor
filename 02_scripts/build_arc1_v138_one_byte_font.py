"""v138: give the commonest Korean syllables a one-byte code.

A one-byte code is font index `code - 1`, and it costs half what a two-byte code costs.
The project has been spending two bytes on every syllable while 91 of those 220 cells
sit on glyphs nothing reads any more -- Japanese kana in text that has been translated
away. Moving the commonest syllables into them halves most of the script:

    일반 대사 슬롯 수요   2,252 → 1,591
    제자리에 들어가는 줄    148 →   809
    선택지에서 슬롯이 필요한 칸  166 →  92

That is the difference between "this file has no room" and "this fits where the
Japanese sat", and it is why 319 lines could not be inserted.

Which cells are safe is measured, not assumed. A one-byte code is off limits if any
pointer-referenced string in PSX.EXE uses it, or if any Korean the game actually draws
uses it -- counted over inline bodies and slot contents only, never over the Japanese
tail an E2 body skips, which is what made the first measurement say 217 were locked.
What is left is 91, and 80 of those are read only by Japanese that no longer renders as
Japanese anyway: 123 of these cells were overwritten years of builds ago, which is why
untranslated lines already come out as a mixture.

This build only moves glyphs. The encoder starts preferring the short code in the same
change, and the text is rewritten by the builds that follow.
"""
from __future__ import annotations

import collections
import csv
import hashlib
import pickle
import struct
import sys
import zipfile
from pathlib import Path
from zipfile import ZipFile, ZipInfo

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))
sys.path.insert(0, str(ROOT / "06_tools" / "python_packages"))

from build_story_sf0b1_return_full import ROW_BYTES, get_pixel  # noqa: E402
from plan_bulk_insertion import (  # noqa: E402
    CACHE, CELL, CHOICE, IPR, PLANES, RAM_TO_FILE, SLOT_BASE, SLOT_COUNT, SLOT_SIZE,
    has_marker, tokens,
)

BASE_ZIP = ROOT / "03_output/arc1_v137_choices_by_geometry_D6AAA475.zip"
BASE_SHA = "D6AAA475F60F0C2771D5C296E11CD97C0A9D717FE7BE3B6DBD20338A9686F9E0"
ORIGINAL_ZIP = ROOT / "00_original/arc.zip"
ORIGINAL_CSV = ROOT / "05_docs/script_original_full.csv"
TRANSLATED_CSV = ROOT / "05_docs/script_translated_full.csv"
OUT_DIR, OUT_STEM = ROOT / "03_output", "arc1_v138_one_byte_font"
ANALYSIS = ROOT / "01_work/analysis/arc1_v138_one_byte_font"
LINEBREAK = b"\xE6\x01"


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def clone(info: ZipInfo) -> ZipInfo:
    out = ZipInfo(info.filename, info.date_time)
    for attr in ("compress_type", "comment", "extra", "create_system", "create_version",
                 "extract_version", "flag_bits", "volume", "internal_attr",
                 "external_attr"):
        setattr(out, attr, getattr(info, attr))
    return out


def cell_bits(font: bytes, index: int) -> tuple[int, ...]:
    row, remainder = divmod(index, IPR)
    column, plane = divmod(remainder, PLANES)
    bit = 1 << plane
    return tuple(1 if get_pixel(font, column * CELL + x, row * CELL + y) & bit else 0
                 for y in range(CELL) for x in range(CELL))


def write_cell(font: bytearray, index: int, bits: tuple[int, ...]) -> None:
    """The inverse of get_pixel, which reads `data[y * ROW_BYTES + x // 2]`."""
    row, remainder = divmod(index, IPR)
    column, plane = divmod(remainder, PLANES)
    for y in range(CELL):
        for x in range(CELL):
            px, py = column * CELL + x, row * CELL + y
            offset = py * ROW_BYTES + px // 2
            shift = 0 if px % 2 == 0 else 4
            nib = (font[offset] >> shift) & 0xF
            nib = nib | (1 << plane) if bits[y * CELL + x] else nib & ~(1 << plane)
            font[offset] = (font[offset] & ~(0xF << shift)) | (nib << shift)


def used_codes(members: dict[str, bytes], originals: dict[str, bytes],
               bodies: dict[str, list]) -> tuple[set[int], set[int]]:
    """One-byte codes the UI needs, and ones the Korean the game draws needs.

    Only rendered text counts. An E2 body keeps its old Japanese tail and the renderer
    skips it, so counting those bytes marks nearly every code as in use -- the mistake
    that made this look impossible at first.
    """
    exe = members["PSX.EXE"]
    ui: set[int] = set()
    low, high = RAM_TO_FILE, RAM_TO_FILE + len(exe)
    targets = set()
    for i in range(0, len(exe) - 4, 4):
        value = struct.unpack_from("<I", exe, i)[0]
        if low <= value < high:
            at = value - RAM_TO_FILE
            if 0x77000 < at < 0x83000 and exe[at - 1] == 0:
                targets.add(at)
    for start in targets:
        end = start
        while end < len(exe) and exe[end] != 0:
            end += 1
        if end - start > 64:
            continue
        ui |= {t[0] for t in tokens(exe[start:end]) if len(t) == 1 and t[0]}

    korean: set[int] = set()

    def take(payload: bytes) -> None:
        korean.update(t[0] for t in tokens(payload) if len(t) == 1 and t[0])

    def slot_text(blob: bytes, disk: int) -> bytes:
        slot = disk - (0x81 if disk < 0xA9 else 0x82)
        if not 0 <= slot < SLOT_COUNT or len(blob) < SLOT_BASE + SLOT_COUNT * SLOT_SIZE:
            return b""
        seg = blob[SLOT_BASE + slot * SLOT_SIZE:SLOT_BASE + (slot + 1) * SLOT_SIZE]
        return seg[:seg.index(0)] if 0 in seg[:SLOT_SIZE - 1] else seg[:SLOT_SIZE - 1]

    for name, items in bodies.items():
        if name not in members or name not in originals:
            continue
        blob, pure = members[name], originals[name]
        for offset, raw in items:
            here = blob[offset:offset + len(raw)]
            if here == pure[offset:offset + len(raw)]:
                continue
            if has_marker(raw, CHOICE):
                run: list[bytes] = []
                for token in tokens(here):
                    if len(token) == 1 and token[0] == 0:
                        break
                    if token[0] == CHOICE or token == LINEBREAK:
                        if run and len(run[0]) == 2 and run[0][0] == 0xE2:
                            take(slot_text(blob, run[0][1]))
                        else:
                            take(b"".join(run))
                        run = []
                        continue
                    run.append(token)
                if run and len(run[0]) == 2 and run[0][0] == 0xE2:
                    take(slot_text(blob, run[0][1]))
                else:
                    take(b"".join(run))
                continue
            if here[:1] == b"\xE2":
                take(slot_text(blob, here[1]))
                continue
            take(here)
    return ui, korean


def main() -> None:
    if digest(BASE_ZIP.read_bytes()) != BASE_SHA:
        raise SystemExit("base archive is not v137")
    with ZipFile(BASE_ZIP) as archive:
        infos = archive.infolist()
        members = {i.filename: archive.read(i.filename) for i in infos}
    with ZipFile(ORIGINAL_ZIP) as pristine:
        originals = {n: pristine.read(n) for n in pristine.namelist() if n in members}

    font = bytearray(members["COMM.IMG"])

    bodies: dict[str, list] = collections.defaultdict(list)
    with ORIGINAL_CSV.open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        key = "offset" if "offset" in (reader.fieldnames or []) else "byte offset"
        for row in reader:
            bodies[row["source file"]].append(
                (int(row[key], 0), bytes.fromhex(row["raw bytes as hex"].replace(" ", ""))))

    ui, korean = used_codes(members, originals, bodies)
    locked = ui | korean | set(range(1, 27))       # ASCII, digits and punctuation
    free = [c for c in range(1, 0xDD) if c not in locked]

    shapes: dict[tuple[int, ...], str] = pickle.loads(CACHE.read_bytes())
    by_name: dict[str, tuple[int, ...]] = {}
    for bits, name in shapes.items():
        by_name.setdefault(name, bits)

    frequency: collections.Counter = collections.Counter()
    with TRANSLATED_CSV.open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            for ch in (row.get("korean") or ""):
                if "가" <= ch <= "힣":
                    frequency[ch] += 1

    # syllables that already have a one-byte code keep it and are not moved
    already = {shapes.get(cell_bits(bytes(font), c - 1)) for c in range(1, 0xDD)}
    wanted = [c for c, _ in frequency.most_common() if c not in already and c in by_name]

    placed = []
    for code, char in zip(free, wanted):
        write_cell(font, code - 1, by_name[char])
        placed.append((code, char, frequency[char]))

    for code, char, _ in placed:
        if shapes.get(cell_bits(bytes(font), code - 1)) != char:
            raise SystemExit(f"code {code:02X} does not read back as {char}")
    before = members["COMM.IMG"]
    touched = {code - 1 for code, _, _ in placed}
    for index in range(IPR * 42):   # the image is 512 rows, so 42 cell rows
        if index in touched:
            continue
        if cell_bits(before, index) != cell_bits(bytes(font), index):
            raise SystemExit(f"cell {index} changed but was not meant to")
    if len(font) != len(before):
        raise SystemExit("COMM.IMG changed size")
    members["COMM.IMG"] = bytes(font)

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
    if differing != ["COMM.IMG"]:
        raise SystemExit(f"members differing from v137: {differing}")

    stamp = digest(tmp.read_bytes())
    final = OUT_DIR / f"{OUT_STEM}_{stamp[:8]}.zip"
    tmp.replace(final)
    (OUT_DIR / "LATEST.txt").write_text(
        f"ship this one\n  file    {final.name}\n  sha256  {stamp}\n", encoding="utf-8")

    covered = sum(f for _, _, f in placed)
    total = sum(frequency.values())
    lines = [
        "v138 one-byte codes for the commonest syllables",
        "",
        f"base    {BASE_ZIP.name}",
        f"output  {final.name}",
        f"        sha256 {stamp}",
        "only COMM.IMG differs from v137; PSX.EXE and every DAT are untouched",
        "",
        f"one-byte codes            220",
        f"  used by a UI string     {len(ui)}",
        f"  used by drawn Korean    {len(korean)}",
        f"  ASCII, digits, marks    26",
        f"  free after all that     {len(free)}",
        "",
        f"syllables moved into them {len(placed)}",
        f"  they are {covered * 100 // total}% of every Korean character in the script",
        "",
        "verified",
        "  base digest matches v137",
        "  every code written reads back as the syllable intended",
        "  no other font cell changed, and COMM.IMG keeps its size",
        "  only COMM.IMG differs from v137",
        "",
        "NOT verified here: a cold boot. These cells held Japanese kana, so any line",
        "still in Japanese gets worse, and that is expected -- 123 of them were already",
        "overwritten. What to look at is Korean spacing: 괄, 량 and 덕 have been in low",
        "cells for a while and render at full width, which is why this is safe.",
        "",
        "rollback: v137",
        "",
        "codes assigned:",
        *(f"  {c:02X}  {ch}  {f}회" for c, ch, f in placed),
    ]
    ANALYSIS.mkdir(parents=True, exist_ok=True)
    (ANALYSIS / "build_report.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines[:24]))


if __name__ == "__main__":
    main()
