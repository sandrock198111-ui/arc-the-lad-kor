"""v120: put every strip C slot on screen, early, so the last unverified step can be seen.

v119 is verified as far as VRAM.  A save state from it shows the reserved-RAM copy of
strip C reaching x 961..999, y 380..391 intact, all 52 lookup entries resolving to row
53, and the existing text still rendering correctly with the rewritten classifier and
frame routine.  What no save state has shown is the last link: a code from those 52
slots actually drawing its own syllable on screen.

So this build changes no code at all.  PSX.EXE and COMM.IMG are carried over from v119
byte for byte, and two early external strings in 1/S1011.DAT are replaced with the 52
new codes, 26 to a page, exactly as v117 did for strips A and B.  If both pages read
correctly the chain is closed; if a glyph is wrong, its position names the slot.

Restoring the story file afterwards is the whole of the rollback: v119's executable is
already what ships.
"""
from __future__ import annotations

import csv
import hashlib
import struct
import sys
from pathlib import Path
from zipfile import ZipFile, ZipInfo

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))
sys.path.insert(0, str(ROOT / "06_tools" / "python_packages"))

BASE_ZIP = ROOT / "03_output/ui_hud_e7_v119_strip_c_patch_only.zip"
BASE_SHA = "7EFBE624E56433C28295FB51FB56611ABDB06A54678D0D4EFB9FEC9E740F5722"
OUTPUT = ROOT / "03_output/ui_hud_e7_v120_strip_c_probe_patch_only.zip"
PLAN_CSV = ROOT / "05_docs/v119_slot_assignment.csv"
ANALYSIS = ROOT / "01_work/analysis/ui_hud_e7_v120_strip_c_probe"

PSX, COMM, STORY = "PSX.EXE", "COMM.IMG", "1/S1011.DAT"
RAM_TO_FILE = 0x8011A800

LOOKUP_SRC, LOOKUP_N = 0x801A8FD4, 508      # the table's image in the executable tail
FIRST_SLOT, SLOT_COUNT = 456, 52
ROW_C, IPR = 53, 84
GA_SRC, GB_SRC = 0x801A8800, 0x801A8BA8
STRIP_BYTES, STRIP_ROW_BYTES = 936, 78
CACHE = Path(
    r"C:\Users\ADMINI~1\AppData\Local\Temp\claude\E--korean"
    r"\328ae25b-6478-4de1-a913-c780c9b01e72\scratchpad\hangul_bitmaps.pkl"
)

ROW_A, ROW_B = 40, 63
SLOT_BASE, SLOT_SIZE = 0x45000, 0x80
PAGE_SLOTS = (0, 1, 2)
INLINE = (0x478AA, 0x47902, 0x47954)
INLINE_COMMANDS = (b"\xE2\x81", b"\xE2\x82", b"\xE2\x83")
PER_PAGE = 26


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def clone(info: ZipInfo) -> ZipInfo:
    out = ZipInfo(info.filename, info.date_time)
    for attr in ("compress_type", "comment", "extra", "create_system", "create_version",
                 "extract_version", "flag_bits", "volume", "internal_attr",
                 "external_attr"):
        setattr(out, attr, getattr(info, attr))
    return out


def virtual_code(slot: int) -> bytes:
    """The byte pair the decoder turns back into this lookup slot."""
    lead, trail = 0xE9 + slot // 254, slot % 254 + 1
    if lead not in (0xE9, 0xEA) or not 1 <= trail <= 254:
        raise SystemExit(f"slot {slot} has no code")
    return bytes((lead, trail))


def read_back(exe: bytes, lut, slots: list[int]) -> dict[int, str]:
    """Name the control syllables by reading their pixels, not by trusting a map.

    The strips are the only record of what is actually stored; the CSV maps have been
    wrong before. Each slot's 12x12 bitplane is looked up in the rendered-glyph table.
    """
    import pickle
    shapes: dict[tuple[int, ...], str] = pickle.loads(CACHE.read_bytes())
    out: dict[int, str] = {}
    for slot in slots:
        index = lut[slot]
        base = GA_SRC if index < ROW_B * IPR else GB_SRC
        local = index - (ROW_A if index < ROW_B * IPR else ROW_B) * IPR
        strip = exe[base - RAM_TO_FILE:base - RAM_TO_FILE + STRIP_BYTES]
        column, plane = divmod(local, 4)
        bit = 1 << plane
        bits = []
        for y in range(12):
            for x in range(12):
                px = column * 12 + x
                byte = strip[y * STRIP_ROW_BYTES + px // 2]
                bits.append(1 if (byte & 0x0F if px % 2 == 0 else byte >> 4) & bit else 0)
        out[slot] = shapes.get(tuple(bits), "?")
    return out


def main() -> None:
    if digest(BASE_ZIP.read_bytes()) != BASE_SHA:
        raise SystemExit("base archive is not the v119 build")
    with ZipFile(BASE_ZIP) as archive:
        infos = archive.infolist()
        members = {i.filename: archive.read(i.filename) for i in infos}
    if {PSX, COMM, STORY} - members.keys():
        raise SystemExit("the archive is missing a member this build needs")

    exe = members[PSX]
    lut = struct.unpack_from(f"<{LOOKUP_N}H", exe, LOOKUP_SRC - RAM_TO_FILE)
    with PLAN_CSV.open(encoding="utf-8-sig", newline="") as handle:
        plan = list(csv.DictReader(handle))
    if len(plan) != SLOT_COUNT:
        raise SystemExit(f"the plan has {len(plan)} rows, expected {SLOT_COUNT}")

    # every slot this probe will print must already resolve into strip C
    codes: list[bytes] = []
    for offset, row in enumerate(plan):
        slot = FIRST_SLOT + offset
        if int(row["lookup_slot"]) != slot:
            raise SystemExit(f"plan row {offset} is slot {row['lookup_slot']}, not {slot}")
        index = lut[slot]
        if index != ROW_C * IPR + offset or index != int(row["physical_index"]):
            raise SystemExit(f"slot {slot} points at {index}, not strip C column {offset}")
        code = virtual_code(slot)
        if code.hex().upper() != row["code_hex"]:
            raise SystemExit(f"slot {slot} code {code.hex().upper()} != {row['code_hex']}")
        codes.append(code)

    # A third page of strips A and B, as a control.  Their 104 slots were verified in
    # game on v116, but v119 rewrote the classifier and the frame routine, so the code
    # serving them is not the code that was tested.  Ordinary menu text does not settle
    # it: those strings use DD..E0 physical codes and never reach the strips at all.
    # Thirteen from each strip on one page makes a single run decide all three.
    # Only slots whose glyph can be named by reading its pixels: a control the user
    # cannot check against a known syllable is not a control.
    control: list[int] = []
    control_chars: dict[int, str] = {}
    for row in (ROW_A, ROW_B):
        pool = [s for s, i in enumerate(lut) if row * IPR <= i < row * IPR + 52]
        named = read_back(exe, lut, pool)
        picked = [s for s in pool if named[s] != "?"][:PER_PAGE // 2]
        if len(picked) < PER_PAGE // 2:
            raise SystemExit(f"row {row} has only {len(picked)} readable control slots")
        control += picked
        control_chars |= {s: named[s] for s in picked}
    control_codes = [virtual_code(s) for s in control]

    story = bytearray(members[STORY])
    old_story = bytes(story)
    tails: list[int] = []
    for page, (slot, inline, command) in enumerate(zip(PAGE_SLOTS, INLINE, INLINE_COMMANDS)):
        if story[inline:inline + 2] != command:
            raise SystemExit(f"the early E2 command at 0x{inline:X} is not {command.hex()}")
        start = SLOT_BASE + slot * SLOT_SIZE
        tails.append(story[start + SLOT_SIZE - 1])
        chosen = control_codes if page == 2 else codes[page * PER_PAGE:(page + 1) * PER_PAGE]
        payload = b"".join(chosen)
        if len(payload) != PER_PAGE * 2:
            raise SystemExit(f"page {page + 1} is not {PER_PAGE} codes")
        story[start:start + SLOT_SIZE] = b"\x00" * SLOT_SIZE
        story[start:start + len(payload)] = payload
        story[start + SLOT_SIZE - 1] = tails[-1]

    allowed = set()
    for slot in PAGE_SLOTS:
        start = SLOT_BASE + slot * SLOT_SIZE
        allowed |= set(range(start, start + SLOT_SIZE))
    changed = [i for i, (a, b) in enumerate(zip(old_story, story)) if a != b]
    if not changed or any(i not in allowed for i in changed):
        raise SystemExit("the story file changed outside the two external test slots")
    if [story[SLOT_BASE + s * SLOT_SIZE + SLOT_SIZE - 1] for s in PAGE_SLOTS] != tails:
        raise SystemExit("an E2 inline-skip tail changed")
    for inline, command in zip(INLINE, INLINE_COMMANDS):
        if story[inline:inline + 2] != command:
            raise SystemExit("an inline E2 command changed")

    members[STORY] = bytes(story)
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with ZipFile(OUTPUT, "w") as archive:
        for info in infos:
            archive.writestr(clone(info), members[info.filename])

    with ZipFile(OUTPUT) as check:
        rebuilt = {i.filename: check.read(i.filename) for i in check.infolist()}
    differing = sorted(n for n in rebuilt if rebuilt[n] != ZipFile(BASE_ZIP).read(n))
    if differing != [STORY]:
        raise SystemExit(f"members differing from v119: {differing}, expected only {STORY}")

    lines = [
        "v120 strip C probe -- no code changes, story text only",
        "",
        f"base    {BASE_ZIP.name}",
        f"output  {OUTPUT.name}",
        f"        sha256 {digest(OUTPUT.read_bytes())}",
        f"PSX.EXE and COMM.IMG are byte-identical to v119. Only {STORY} differs,",
        f"and only inside external slots {', '.join(map(str, PAGE_SLOTS))}.",
        "",
        "what to look at, on a cold boot, in the first S1011 scene:",
        "  pages 1 and 2   the 52 new strip C syllables",
        "  page 3          a control drawn from strips A and B",
        "",
        "Each glyph is one lookup slot. A wrong or blank one names its slot by position,",
        "so note where it falls rather than what it looks like.",
        "",
        "Page 3 is the part that is easy to skip and should not be. Strips A and B were",
        "verified in game on v116, but v119 rewrote the classifier and the frame routine,",
        "so the code serving them today is not the code that was tested. Ordinary menu",
        "text does not settle it -- those strings use DD..E0 physical codes and never",
        "reach a strip at all. If page 3 is right, all three strips are proven together.",
        "",
    ]
    pages = [
        ("page 1  strip C, slots 456..481",
         [(r["char"], r["code_hex"]) for r in plan[:PER_PAGE]]),
        ("page 2  strip C, slots 482..507",
         [(r["char"], r["code_hex"]) for r in plan[PER_PAGE:]]),
        ("page 3  control: 13 from strip A, then 13 from strip B",
         [(control_chars[s], c.hex().upper()) for s, c in zip(control, control_codes)]),
    ]
    for title, entries in pages:
        lines += ["", title,
                  "  " + " ".join(ch for ch, _ in entries),
                  "  " + " ".join(code for _, code in entries[:13]),
                  "  " + " ".join(code for _, code in entries[13:])]
    lines += [
        "",
        "verified statically",
        "  base archive digest matches v119",
        f"  all {SLOT_COUNT} lookup slots resolve into strip C row {ROW_C}, in plan order",
        "  each code round-trips through the decoder's own arithmetic",
        f"  only {STORY} differs from v119, only in external slots"
        f" {', '.join(map(str, PAGE_SLOTS))}, and the",
        "  inline E2 commands and slot tails are preserved",
        "",
        "if every glyph is right",
        "  all three strips are proven and v119 is the build to accept, not this one.",
        "  This probe exists only to look at; it overwrites real story text.",
        "",
        "rollback: v119 unchanged, or v118 if the strip itself is at fault",
    ]
    ANALYSIS.mkdir(parents=True, exist_ok=True)
    (ANALYSIS / "build_report.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
