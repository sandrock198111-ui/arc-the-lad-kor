"""Decide, for all 2,650 translated lines at once, how each one gets into the game.

There are two ways a line can be inserted and the choice is forced, not preferred:

  inline   the encoding fits in the bytes the Japanese sentence occupied, so it is
           written in place and the remainder padded
  e2       it does not fit, so the body's first two bytes become an `E2 <disk id>`
           command, the text moves to an external slot, and the slot's last byte
           carries `capacity - 2` so the renderer skips the rest of the old body

Everything here is a rule that has already cost this project a build:

  a scene file has 79 slots at 0x45000 + n * 0x80, not 16
  disk IDs are 81-A8 for slots 0..39 and AA-D0 for 40..78; A9 is the original
    dialogue's, which is why 80 IDs yield 79 slots
  a slot's byte 0x7F is metadata, so the text has at most 127 bytes and is
    zero-terminated before it
  `E6 01` is not interpreted inside a slot and renders as garbage, so a line break
    cannot survive the move; the renderer wraps on its own
  a body that mixes prose with `E5` choices must not get `capacity - 2` metadata,
    because that skip would swallow the choices
  slots must be tested in the actual file: some scenes keep real data in the bank

This writes a manifest and a verdict. It changes nothing.
"""
from __future__ import annotations

import csv
import pickle
import struct
import sys
import zipfile
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))
sys.path.insert(0, str(ROOT / "06_tools" / "python_packages"))

from build_story_sf0b1_return_full import get_pixel  # noqa: E402

BUILD = ROOT / "03_output/story_v122_slot_e6_swept_patch_only.zip"
ORIGINAL_ZIP = ROOT / "00_original/arc.zip"   # the untouched disc contents
ORIGINAL_CSV = ROOT / "05_docs/script_original_full.csv"
TRANSLATED_CSV = ROOT / "05_docs/script_translated_full.csv"
MANIFEST = ROOT / "05_docs/bulk_insertion_manifest.csv"
REPORT = ROOT / "01_work/analysis/bulk_insertion_plan.txt"
CACHE = Path(
    r"C:\Users\ADMINI~1\AppData\Local\Temp\claude\E--korean"
    r"\328ae25b-6478-4de1-a913-c780c9b01e72\scratchpad\hangul_bitmaps.pkl"
)

RAM_TO_FILE = 0x8011A800
LOOKUP_SRC, LOOKUP_N = 0x801A8FD4, 508
IPR, PLANES, CELL = 84, 4, 12
STRIP_ROW_BYTES, STRIP_BYTES = 78, 936
STRIPS = {40: 0x801A8800, 63: 0x801A8BA8, 53: 0x801A93CC, 52: 0x801A9774}
STRIP_D_ROW = 52

# v127 gave the 16 skill-range cells back to the artwork and moved the Korean glyphs
# that lived in them into strip D, leaving this table to redirect each plane.
REMAP_SRC = 0x801A9B1C
REMAP_ROWS, REMAP_COLS = range(10, 14), range(2, 6)

SLOT_BASE, SLOT_SIZE, SLOT_COUNT = 0x45000, 0x80, 79
# 128 bytes: text, a 0x00 terminator, then the completion metadata in byte 0x7F. A
# 127-byte payload fills 0..126 and the metadata write then lands on 127 anyway, so
# the string never ends and the renderer walks into the next slot. It hangs; seven
# slots shipped that way. The last byte a payload may occupy is 125.
SLOT_TEXT_MAX = SLOT_SIZE - 2
FILLER = 0x9C                           # the space glyph, and the safe pad
LINEBREAK = b"\xE6\x01"
CHOICE = 0xE5
BREAK = 0xE6            # a line break the E2 skip would swallow


def tokens(text: bytes):
    """Walk the byte stream the way the runtime does: 0x01..0xDC one byte, 0xDD.. two.

    A control byte is only a control at a token boundary. 0xE5 and 0xE6 also occur as
    the second byte of a two-byte glyph, and counting those as markers is a documented
    way to misjudge a body -- it cost a build once already.
    """
    i = 0
    while i < len(text):
        width = 1 if text[i] < 0xDD else 2
        yield text[i:i + width]
        i += width


def has_marker(raw: bytes, lead: int) -> bool:
    return any(len(tok) == 2 and tok[0] == lead for tok in tokens(raw))


def disk_id(slot: int) -> int:
    """81-A8 for slots 0..39, AA-D0 for 40..78. A9 belongs to original dialogue."""
    if not 0 <= slot < SLOT_COUNT:
        raise ValueError(slot)
    return slot + 0x81 if slot < 40 else slot + 0x82


def strip_bits(exe: bytes, src: int, slot: int) -> tuple[int, ...]:
    strip = exe[src - RAM_TO_FILE:][:STRIP_BYTES]
    column, plane = divmod(slot, PLANES)
    bit = 1 << plane
    out = []
    for y in range(CELL):
        for x in range(CELL):
            px = column * CELL + x
            byte = strip[y * STRIP_ROW_BYTES + px // 2]
            out.append(1 if (byte & 0x0F if px % 2 == 0 else byte >> 4) & bit else 0)
    return tuple(out)


def remap_slot(exe: bytes, index: int) -> int | None:
    """The strip D slot this index draws from, or None if it draws from the font.

    Reading the font for one of the restored skill-range planes returns artwork, not
    the glyph that used to be there, so the table has to be consulted before the font.
    """
    row, remainder = divmod(index, IPR)
    column, plane = divmod(remainder, PLANES)
    if row not in REMAP_ROWS or column not in REMAP_COLS:
        return None
    entry = exe[REMAP_SRC - RAM_TO_FILE + (row - 10) * 16 + (column - 2) * 4 + plane]
    return None if entry == 0xFF else entry


def drawable(exe: bytes, index: int) -> bool:
    """Whether the renderer can actually put this index on screen.

    The font occupies VRAM y 0..467 on one page column, which spans two texture pages
    vertically.  V is `(row * 12) & 0xFF` and is right for both halves; what separates
    them is the texture page, and the page is chosen per glyph by the classifier, which
    only knows the four strip V values.  An ordinary row on the second page therefore
    samples the first page at the same U and V and draws twelve rows of some other
    cell -- correct position, wrong pixels, which reads in game as one character
    smeared vertically into its neighbour.  Row 21 straddles the boundary and wraps,
    so it is no better.  25 characters shipped this way in v129.
    """
    if remap_slot(exe, index) is not None:
        return True
    row = index // IPR
    return row in STRIPS or (row + 1) * CELL <= 256


def bitmap(exe: bytes, font: bytes, index: int) -> tuple[int, ...] | None:
    row = index // IPR
    slot = remap_slot(exe, index)
    if slot is not None:
        return strip_bits(exe, STRIPS[STRIP_D_ROW], slot)
    if row in STRIPS and index - row * IPR < 52:
        return strip_bits(exe, STRIPS[row], index - row * IPR)
    if row >= 512 // CELL:
        return None
    column, plane = divmod(index - row * IPR, PLANES)
    bit = 1 << plane
    return tuple(1 if get_pixel(font, column * CELL + x, row * CELL + y) & bit else 0
                 for y in range(CELL) for x in range(CELL))


# Where each Latin capital sits in the ORIGINAL disc's font. Found by aligning the
# original script's own bytes against its own decoded text -- these are the only ASCII
# letters it uses -- and confirmed by reading the cells: unmistakable H, L, M, P, R.
LATIN_ON_THE_ORIGINAL = {"H": 469, "L": 825, "M": 553, "P": 363, "R": 732}
_original_font: list[bytes] = []


def original_cell(index: int) -> tuple[int, ...] | None:
    """A 12x12 cell as the untouched disc drew it, for use as a reference picture."""
    if not _original_font:
        with zipfile.ZipFile(ORIGINAL_ZIP) as archive:
            _original_font.append(archive.read("COMM.IMG"))
    row, remainder = divmod(index, IPR)
    column, plane = divmod(remainder, PLANES)
    bit = 1 << plane
    return tuple(1 if get_pixel(_original_font[0], column * CELL + x, row * CELL + y) & bit
                 else 0 for y in range(CELL) for x in range(CELL))


def build_encoder(exe: bytes, font: bytes) -> dict[str, bytes]:
    """char -> code, read out of the built archive rather than any CSV.

    Every code form lands in one continuous index space and the arithmetic is the
    decoder's own. A one-byte code 0x01..0xDC is index `code - 1`. The two-byte range
    continues exactly where that ends -- `DD 01` is index 220, and the one-byte range
    stops at 219 -- as `(lead - 0xDD) * 255 + trail + 0xDB`. E9/EA go through the
    lookup table. So the honest way to build this table is to enumerate all three,
    resolve each to an index, read the 12x12 cell back out of the build and name it.

    The one-byte half of that space was never looked at. The table was hardcoded to 26
    ASCII codes and the other 194 were invisible, though 118 of them hold Korean --
    괄, 량 and 덕 among them, which the editor called impossible while the game drew
    them on screen. The mapping is confirmed twice over: against the original script's
    own decoded text it agrees on all 18 ASCII codes that appear there, and the three
    Korean ones read back as their gulim renders at exactly `code - 1`.

    Two-byte codes are assigned first and one-byte codes only fill what is left. A
    character that already has a code keeps it: the same syllable can sit in several
    cells, the renderer's advance is a property of the cell, and swapping a working
    line onto a different cell to save a byte is not a trade this build should make
    silently.
    """
    lut = struct.unpack_from(f"<{LOOKUP_N}H", exe, LOOKUP_SRC - RAM_TO_FILE)
    shapes: dict[tuple[int, ...], str] = pickle.loads(CACHE.read_bytes())
    wide: dict[int, bytes] = {}
    for lead in range(0xDD, 0xE9):
        for trail in range(0x01, 0xFF):
            wide.setdefault((lead - 0xDD) * 255 + trail + 0xDB, bytes((lead, trail)))
    for slot, index in enumerate(lut):
        wide.setdefault(index, bytes((0xE9 + slot // 254, slot % 254 + 1)))
    narrow = {code - 1: bytes((code,)) for code in range(0x01, 0xDD)}

    # Short codes first. A one-byte code costs half what a two-byte one does, and v138
    # moved the commonest syllables into the low cells precisely so this preference has
    # something to find. Codes 1..26 are set before the sweep and keep the digits and
    # punctuation the UI depends on.
    table: dict[str, bytes] = {chr(i + 32): bytes((i + 1,)) for i in range(26)}
    by_bits: dict[tuple[int, ...], bytes] = {}
    for codes in (narrow, wide):
        for index, code in sorted(codes.items()):
            if not drawable(exe, index):
                continue    # lower index wins below, and the broken twin sorts first
            bits = bitmap(exe, font, index)
            if not bits or not any(bits):
                continue
            by_bits.setdefault(bits, code)
            if char := shapes.get(bits):
                table.setdefault(char, code)

    # Punctuation and Latin cannot be named this way: the rendered-glyph table only
    # holds Hangul, so a colon and a question mark read back as unknown even though
    # the game draws them. Take those from the charmaps, but do not take them on
    # trust -- resolve each declared code through the decoder's own arithmetic and
    # require the cell it lands on to be non-blank in this build.
    for name in ("korean_charmap.csv", "korean_charmap_extended.csv"):
        path = ROOT / "05_docs" / name
        if not path.exists():
            continue
        with path.open(encoding="utf-8-sig", newline="") as handle:
            for row in csv.DictReader(handle):
                char = (row.get("char") or "").strip()
                hexed = (row.get("code_hex") or "").replace(" ", "")
                if len(char) != 1 or char in table or len(hexed) != 4:
                    continue
                lead, trail = int(hexed[:2], 16), int(hexed[2:], 16)
                if not 0xDD <= lead < 0xE9:
                    continue
                index = (lead - 0xDD) * 255 + trail + 0xDB
                bits = bitmap(exe, font, index)
                if bits and any(bits) and drawable(exe, index):
                    table[char] = bytes((lead, trail))

    # The Latin capitals. The rendered-glyph table names only Hangul, so these were
    # invisible and every line with HP, MP or LR was refused for no reason. Naming them
    # by hand would be another guess, and guesses about glyphs have cost this project
    # several builds, so each one is taken as a picture off the ORIGINAL disc and looked
    # for in this build. Where it turns up, that is the code; a letter whose cell was
    # overwritten simply does not resolve, which is the right answer and needs no
    # special case. R is in exactly that state -- the original draws it at index 732 and
    # a Korean syllable now sits there -- so R stays unwritable until it is restored.
    for char, source in LATIN_ON_THE_ORIGINAL.items():
        want = original_cell(source)
        if char not in table and want and any(want) and (code := by_bits.get(want)):
            table[char] = code

    # The corner brackets, for wrapping an item name: 「비단 띠」. Unlike the Latin
    # capitals these are not named anywhere -- the original script never uses them in a
    # line that decodes cleanly -- so they are identified by shape, which is
    # unambiguous: 0x5B is a bar along the top with the stroke dropping from its left
    # end, 0x5A its 180-degree rotation. They run the full height of the cell rather
    # than the upper quarter a Japanese font would use, so they read as tall brackets.
    for char, code in {"「": b"\x5B", "」": b"\x5A"}.items():
        bits = bitmap(exe, font, code[0] - 1)
        if char not in table and bits and any(bits) and drawable(exe, code[0] - 1):
            table[char] = code
    return table


def encode(text: str, table: dict[str, bytes], keep_breaks: bool) -> tuple[bytes, list[str]]:
    out, missing = bytearray(), []
    for ch in text:
        if ch == " ":
            out.append(FILLER)
        elif ch == "|":
            out += LINEBREAK if keep_breaks else bytes((FILLER,))
        elif ch in table:
            out += table[ch]
        else:
            missing.append(ch)
    return bytes(out), missing


def main() -> None:
    with zipfile.ZipFile(BUILD) as archive:
        members = set(archive.namelist())
        exe, font = archive.read("PSX.EXE"), archive.read("COMM.IMG")
        table = build_encoder(exe, font)
        cached = {n: archive.read(n) for n in members if n.endswith(".DAT")}

    budgets: dict[tuple[str, str], tuple[int, bytes]] = {}
    with ORIGINAL_CSV.open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            budgets[(row["source file"], row["offset"] if "offset" in row
                     else row["byte offset"])] = (
                int(row["length"]), bytes.fromhex(row["raw bytes as hex"].replace(" ", "")))
    with TRANSLATED_CSV.open(encoding="utf-8-sig", newline="") as handle:
        rows = [r for r in csv.DictReader(handle)
                if any("\uac00" <= c <= "\ud7a3" for c in (r.get("korean") or ""))]

    # File content: the patch archive's copy where it has one, so earlier scene work
    # and the slots it already consumed are respected; the untouched disc otherwise.
    # 01_work is deliberately not used -- it is a working tree, not a known state.
    contents: dict[str, bytes] = {}
    absent: list[str] = []
    with zipfile.ZipFile(ORIGINAL_ZIP) as pristine:
        available = set(pristine.namelist())
        for name in sorted({r["source file"] for r in rows}):
            if name in cached:
                contents[name] = cached[name]
            elif name in available:
                contents[name] = pristine.read(name)
                absent.append(name)
            else:
                raise SystemExit(f"{name} is in neither the build nor the original disc")

    free: dict[str, list[int]] = {
        name: [s for s in range(SLOT_COUNT)
               if not any(data[SLOT_BASE + s * SLOT_SIZE:SLOT_BASE + (s + 1) * SLOT_SIZE])]
        for name, data in contents.items()
    }

    # Pass one: classify. Nothing is allocated yet, because a slot must go to the
    # line that needs it most, not to whichever line the CSV happens to list first.
    plan: list[dict[str, object]] = []
    blocked: list[tuple[str, str, str]] = []
    pending: dict[str, list[dict[str, object]]] = defaultdict(list)
    missing_chars: Counter = Counter()

    for row in rows:
        name, offset_text = row["source file"], row["offset"]
        text = (row["korean"] or "").strip()
        entry = budgets.get((name, offset_text))
        if entry is None:
            blocked.append((name, offset_text, "no original row for this offset"))
            continue
        capacity, raw = entry
        offset = int(offset_text, 0)
        data = contents[name]

        inline, miss = encode(text, table, keep_breaks=True)
        missing_chars.update(miss)
        if miss:
            blocked.append((name, offset_text, f"no code for {''.join(sorted(set(miss)))}"))
            continue
        if len(inline) <= capacity:
            plan.append({"file": name, "offset": offset_text, "mode": "inline",
                         "slot": "", "disk_id": "", "skip": "",
                         "bytes": len(inline), "capacity": capacity, "korean": text})
            continue

        # it has to move. every rule below has already cost a build.
        if has_marker(raw, CHOICE):
            blocked.append((name, offset_text, "body mixes prose with E5 choices; "
                                               "capacity-2 metadata would swallow them"))
            continue
        # A `capacity - 2` skip jumps the body's own E6 line breaks. The rule against
        # that is written entirely about menus: the renderer's row and *the menu
        # cursor's* row diverging, so options draw above the row that selects them.
        # After v121 this planner refused every body containing E6, which was wider
        # than the rule and blocked 1,557 lines to protect the 47 that hold choices.
        #
        # v123 settled it by measurement rather than by reading harder: 29 plain
        # multi-row bodies in 1/S1021.DAT were relocated whole and read correctly in
        # game, breaks and all. A body with no choice has no cursor to diverge from.
        #
        # So the guard is where the rule is: on E5, checked above. A break alone is
        # fine, and its `|` becomes a space because a slot does not interpret E6.
        if capacity < 2:
            blocked.append((name, offset_text,
                            f"capacity {capacity} has no room for the E2 command"))
            continue
        if data[offset + capacity:offset + capacity + 2] != bytes(2):
            blocked.append((name, offset_text, "body does not end at a 00 00 boundary"))
            continue
        payload, _ = encode(text, table, keep_breaks=False)   # E6 01 dies in a slot
        if len(payload) > SLOT_TEXT_MAX:
            blocked.append((name, offset_text,
                            f"{len(payload)} bytes exceeds a slot's {SLOT_TEXT_MAX}"))
            continue
        pending[name].append({"offset": offset_text, "capacity": capacity,
                              "payload": len(payload), "over": len(inline) - capacity,
                              "korean": text})

    # Pass two: allocate. A file can have fewer slots than lines that want one, so the
    # slots go to the lines that overflow by the most. What is left over is not blocked
    # work -- it is a known, measured edit, so it is reported with the exact deficit.
    trims: list[tuple[int, str, str, str]] = []
    for name, items in pending.items():
        items.sort(key=lambda i: -i["over"])
        for item in items:
            if not free[name]:
                trims.append((item["over"], name, item["offset"], item["korean"]))
                continue
            slot = free[name].pop(0)
            plan.append({"file": name, "offset": item["offset"], "mode": "e2",
                         "slot": slot, "disk_id": f"{disk_id(slot):02X}",
                         "skip": item["capacity"] - 2, "bytes": item["payload"],
                         "capacity": item["capacity"], "korean": item["korean"]})
    trims.sort()
    modes = Counter(str(entry["mode"]) for entry in plan)
    per_file_e2 = Counter(str(e["file"]) for e in plan if e["mode"] == "e2")

    with MANIFEST.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["file", "offset", "mode", "slot",
                                                    "disk_id", "skip", "bytes",
                                                    "capacity", "korean"])
        writer.writeheader()
        writer.writerows(plan)

    reasons = Counter(reason.split(";")[0] for _, _, reason in blocked)
    trim_files = Counter(name for _, name, _, _ in trims)
    slot_use = {n: (SLOT_COUNT - len(free[n])) for n in per_file_e2}
    lines = [
        "bulk insertion plan, against v122",
        "",
        f"translated lines            {len(rows)}",
        f"  planned inline            {modes['inline']}",
        f"  planned via an E2 slot    {modes['e2']}",
        f"  need a small trim         {len(trims)}",
        f"  blocked                   {len(blocked)}",
        "",
        f"files touched               {len(contents)}",
        f"  already in the base zip   {len(contents) - len(absent)}",
        f"  taken from the original   {len(absent)}   <- these become new archive members",
        "",
        "slot pressure, worst files (used / free before this plan):",
        *(f"  {slot_use[n]:>3} / {slot_use[n] + len(free[n]):>3}   {n}"
          for n, _ in per_file_e2.most_common(10)),
        "",
    ]
    if blocked:
        lines += [f"blocked, by reason:",
                  *(f"  {count:>5}  {reason}" for reason, count in reasons.most_common()),
                  ""]
        lines += ["first 25 blocked lines:"]
        for name, offset, reason in blocked[:25]:
            lines.append(f"  {name} {offset}  {reason}")
        lines.append("")
    if missing_chars:
        lines += [f"characters with no code: {len(missing_chars)} distinct",
                  "  " + " ".join(f"{c}x{n}" for c, n in missing_chars.most_common(30)), ""]
    if trims:
        lines += [
            f"lines whose file ran out of slots: {len(trims)} across {len(trim_files)} files.",
            "These are not blocked. Each needs its encoding shortened by the bytes shown,",
            "after which it fits in place and costs no slot at all.",
            "",
            f"  median deficit {sorted(d for d, *_ in trims)[len(trims) // 2]} bytes,"
            f" worst {trims[-1][0]}",
            "  files, and how many lines each needs trimmed:",
            *(f"    {count:>3}  {name}" for name, count in trim_files.most_common(10)),
            "",
            "  smallest deficits first, the cheapest edits:",
            *(f"    +{d:>3}  {n} {o}  {k[:44]}" for d, n, o, k in trims[:12]),
            "",
        ]
    lines += [
        "verdict",
        f"  {modes['inline'] + modes['e2']} of {len(rows)} lines have a place to go.",
        "  Nothing here is written. The builder consumes "
        f"{MANIFEST.relative_to(ROOT)}.",
    ]
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
