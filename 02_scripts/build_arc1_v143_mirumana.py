"""v143: rename 밀마나 to 미르마나 in the executable's three strings.

The save screen draws its country name from PSX.EXE, not from the script, so editing
the CSV could never change it. Three strings carry the name, and the pointer table says
there are exactly three -- they were found by walking every pointer into the image and
decoding what it points at, not by searching for bytes:

    0x781B1  밀마나          6B   pointer 0x81EEC          the save/load screen
    0x8194D  밀마나 공항    11B   pointers 0x81E58 0x8219C  the place-name table
    0x81A8E  밀마나 군본부  13B   pointer 0x821A0           the place-name table

Searching for bytes is what fails here, and it is worth writing down why. The same
syllable has several spellings: 마 is one byte 0xD4 since v138, two bytes 0xE0 0x9E in
the old wide range, and 0xE9 0x52 through the lookup table. The save screen string is
written entirely in the wide range and the two place names entirely through the lookup
table. So the replacement is built in whichever space the string it replaces already
used -- these are different renderers, and a byte below 0xDD may not mean a glyph to
the one that draws the place names.

밀마나 is three syllables and 미르마나 is four, so none of them can grow where it stands:
the pool is packed and the next string starts immediately after the terminator. They do
not have to. Every one is reached through a pointer, so the new text goes into the free
space after the reserved block and the pointer is rewritten -- the same mechanism the
earlier UI work used, recorded in `ui_system_v39.csv` as `source_offset`/`new_offset`.

Spelling: ミルマーナ is 미르마나, and the script already says 미르마나 in every line that
mentions the country. A save screen reading 미르마라 would disagree with the dialogue a
minute later, so this uses 미르마나.
"""
from __future__ import annotations

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

from plan_bulk_insertion import (  # noqa: E402
    CACHE, LOOKUP_N, LOOKUP_SRC, RAM_TO_FILE, bitmap, drawable, tokens,
)

BASE_ZIP = ROOT / "03_output/arc1_v142_choices_final_66219F2E.zip"
BASE_SHA = "66219F2E159F685318A4557B41C98DD1384857768CCC0682E288C15FAC150D59"
OUT_DIR, OUT_STEM = ROOT / "03_output", "arc1_v143_mirumana"
ANALYSIS = ROOT / "01_work/analysis/arc1_v143_mirumana"

OLD, NEW = "밀마나", "미르마나"
SPACE = 0x9C                                 # the one byte both spaces spell a space with
FREE_START, FREE_END = 0x8F3D8, 0x8F800      # after the reserved block, inside the image


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def clone(info: ZipInfo) -> ZipInfo:
    out = ZipInfo(info.filename, info.date_time)
    for attr in ("compress_type", "comment", "extra", "create_system", "create_version",
                 "extract_version", "flag_bits", "volume", "internal_attr",
                 "external_attr"):
        setattr(out, attr, getattr(info, attr))
    return out


def main() -> None:
    if digest(BASE_ZIP.read_bytes()) != BASE_SHA:
        raise SystemExit("base archive is not v142")
    with ZipFile(BASE_ZIP) as archive:
        infos = archive.infolist()
        members = {i.filename: archive.read(i.filename) for i in infos}
    exe = bytearray(members["PSX.EXE"])
    font = members["COMM.IMG"]
    shapes: dict[tuple[int, ...], str] = pickle.loads(CACHE.read_bytes())
    lut = struct.unpack_from(f"<{LOOKUP_N}H", exe, LOOKUP_SRC - RAM_TO_FILE)

    # the new text must land inside the part of the file the loader copies to RAM
    t_addr, t_size = struct.unpack_from("<II", exe, 0x18)
    image = (0x800, 0x800 + t_size)
    if not (image[0] <= FREE_START and FREE_END <= image[1]):
        raise SystemExit(f"free space is outside the loaded image {image}")
    if t_addr - 0x800 != RAM_TO_FILE:
        raise SystemExit("the exe header disagrees with the RAM mapping")

    def index_of(token: bytes) -> int | None:
        if len(token) == 1:
            return token[0] - 1
        if 0xDD <= token[0] <= 0xE8:
            return (token[0] - 0xDD) * 255 + token[1] + 0xDB
        if token[0] in (0xE9, 0xEA):
            slot = (token[0] - 0xE9) * 254 + token[1] - 1
            return lut[slot] if 0 <= slot < LOOKUP_N else None
        return None

    def reads_as(payload: bytes) -> str:
        out = []
        for token in tokens(payload):
            index = index_of(token)
            if index is None or not drawable(bytes(exe), index):
                return ""
            bits = bitmap(bytes(exe), font, index)
            char = shapes.get(bits)
            if char is None and any(bits):
                return ""
            out.append(char or " ")
        return "".join(out)

    # one code table per space, so a replacement is written the way its neighbours are
    spaces: dict[str, dict[str, bytes]] = {"wide": {}, "lookup": {}}
    for lead in range(0xDD, 0xE9):
        for trail in range(0x01, 0xFF):
            index = (lead - 0xDD) * 255 + trail + 0xDB
            if drawable(bytes(exe), index):
                if char := shapes.get(bitmap(bytes(exe), font, index)):
                    spaces["wide"].setdefault(char, bytes((lead, trail)))
    for slot, index in enumerate(lut):
        if drawable(bytes(exe), index):
            if char := shapes.get(bitmap(bytes(exe), font, index)):
                spaces["lookup"].setdefault(
                    char, bytes((0xE9 + slot // 254, slot % 254 + 1)))

    def space_of(payload: bytes) -> str:
        leads = {t[0] for t in tokens(payload) if len(t) == 2}
        if leads and leads <= {0xE9, 0xEA}:
            return "lookup"
        if leads and all(0xDD <= lead <= 0xE8 for lead in leads):
            return "wide"
        raise SystemExit(f"cannot tell which code space {payload.hex(' ')} is in")

    def spell(text: str, space: str) -> bytes:
        out = bytearray()
        for char in text:
            if char == " ":
                out.append(SPACE)
                continue
            code = spaces[space].get(char)
            if code is None:
                raise SystemExit(f"{char} has no code in the {space} space")
            out += code
        return bytes(out)

    # locate the strings through the pointer table, then by what they decode to
    low, high = RAM_TO_FILE, RAM_TO_FILE + len(exe)
    pointers: dict[int, list[int]] = {}
    for i in range(0, len(exe) - 4, 4):
        value = struct.unpack_from("<I", exe, i)[0]
        if low <= value < high:
            at = value - RAM_TO_FILE
            if 0 < at < len(exe) and exe[at - 1] == 0:
                pointers.setdefault(at, []).append(i)

    targets = []
    for start in sorted(pointers):
        end = start
        while end < len(exe) and exe[end] != 0:
            end += 1
        if not (2 <= end - start <= 48):
            continue
        text = bytes(exe[start:end])
        if OLD in reads_as(text):
            targets.append((start, end, text))
    if len(targets) != 3:
        raise SystemExit(f"expected 3 strings holding {OLD}, found {len(targets)}")

    if any(exe[FREE_START:FREE_END]):
        raise SystemExit("the space after the reserved block is not empty")
    cursor = FREE_START
    moved = []
    for start, end, text in targets:
        space = space_of(text)
        was = reads_as(text)
        now = was.replace(OLD, NEW)
        replacement = spell(now, space)
        if reads_as(replacement) != now:
            raise SystemExit(f"{now} did not read back from its own bytes")
        if cursor + len(replacement) + 1 > FREE_END:
            raise SystemExit("ran out of room after the reserved block")
        exe[cursor:cursor + len(replacement)] = replacement
        exe[cursor + len(replacement)] = 0
        address = struct.pack("<I", cursor + RAM_TO_FILE)
        for at in pointers[start]:
            exe[at:at + 4] = address
        moved.append((start, cursor, space, len(text), len(replacement),
                      was, now, pointers[start]))
        cursor += len(replacement) + 1

    before = members["PSX.EXE"]
    changed = [i for i in range(len(before)) if before[i] != exe[i]]
    allowed = set(range(FREE_START, cursor))
    for _, _, _, _, _, _, _, ps in moved:
        allowed |= {a + k for a in ps for k in range(4)}
    if stray := [i for i in changed if i not in allowed]:
        raise SystemExit(f"{len(stray)} bytes changed outside the new text and its pointers")
    if len(exe) != len(before):
        raise SystemExit("PSX.EXE changed size")
    # the old bytes stay where they were; no pointer reaches them any more
    if any(reads_as(bytes(exe[s:e])) != was
           for (s, e, _), (_, _, _, _, _, was, _, _) in zip(targets, moved)):
        raise SystemExit("the old strings were disturbed")
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
        raise SystemExit(f"members differing from v142: {differing}")

    stamp = digest(tmp.read_bytes())
    final = OUT_DIR / f"{OUT_STEM}_{stamp[:8]}.zip"
    tmp.replace(final)
    (OUT_DIR / "LATEST.txt").write_text(
        f"ship this one\n  file    {final.name}\n  sha256  {stamp}\n", encoding="utf-8")

    lines = [
        f"v143 {OLD} -> {NEW}",
        "",
        f"base    {BASE_ZIP.name}",
        f"output  {final.name}",
        f"        sha256 {stamp}",
        f"PSX.EXE {len(exe)} bytes, size unchanged; every other member identical to v142",
        "",
        "moved and repointed",
        *(f"  0x{a:X} -> 0x{b:X}  {sp:6s}  {n}B -> {m}B  {was!r} -> {now!r}  "
          f"포인터 {' '.join(f'0x{p:X}' for p in ps)}"
          for a, b, sp, n, m, was, now, ps in moved),
        "",
        f"bytes changed  {len(changed)}: the new text in the free space, and 4 per pointer",
        "",
        "why it had to move, and why bytes could not be searched for",
        "  밀마나 is 3 syllables and 미르마나 is 4, so each string grows by one glyph and",
        "  the pool is packed -- the next string begins right after the terminator.",
        "  The same syllable has three spellings: 마 is 0xD4 as a one-byte code since v138,",
        "  0xE0 0x9E in the wide range, and 0xE9 0x52 through the lookup table. The save",
        "  screen string is written in the wide range and the two place names through the",
        "  lookup table, so each replacement was built in the space its own string used.",
        "",
        "verified",
        "  base digest matches v142",
        "  found by walking every pointer into the image and decoding the target, so all",
        "    three are found and none is a byte-pattern coincidence; the count is exactly 3",
        "  each replacement reads back as its intended text from this build's own font",
        "  the free space was empty and lies inside the loaded image (header t_size checked)",
        "  no byte changed outside that space and the pointers; PSX.EXE keeps its size",
        "  only PSX.EXE differs from v142",
        "",
        "NOT verified here: a cold boot. Open the load screen and read the country column.",
        "",
        "rollback: v142",
    ]
    ANALYSIS.mkdir(parents=True, exist_ok=True)
    (ANALYSIS / "build_report.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
