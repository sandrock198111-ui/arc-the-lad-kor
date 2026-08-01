"""v117: exercise every one of the 104 resident high-page glyph slots.

This is a test-only build on v116.  It preserves the visual identity of every
existing E9/EA character: all 57 virtual codes already using the resident
strips are included, then 47 ordinary virtual codes are copied in to fill the
remaining positions.  Their lookup entries are remapped one-to-one across
strip A (52 slots) and strip B (52 slots).

The first four external E2 strings in 1/S1011.DAT are replaced with 26 virtual
codes each.  Advancing those four early-game messages therefore exercises all
104 physical positions through the real story-secondary decoder, lookup table,
packet builder, two-pass renderer and per-frame upload path.

The canonical translation CSV and COMM.IMG are deliberately untouched.
"""
from __future__ import annotations

import csv
import hashlib
import struct
from pathlib import Path
from zipfile import ZipFile, ZipInfo

from PIL import Image, ImageDraw, ImageFont


ROOT = Path(__file__).resolve().parents[1]
BASE_ZIP = ROOT / "03_output/ui_hud_e7_v116_direct_stateless_renderer_patch_only.zip"
BASE_SHA256 = "DC59B6211598508211BF201DDBAECF8C51386379F665D9B303C4C6301A09AC34"
OUTPUT = ROOT / "03_output/ui_hud_e7_v117_104slot_story_probe_patch_only.zip"
ANALYSIS = ROOT / "01_work/analysis/ui_hud_e7_v117_104slot_story_probe"
REPORT = ANALYSIS / "build_report.txt"
REFERENCE_CSV = ANALYSIS / "reference.csv"
REFERENCE_PNG = ANALYSIS / "reference.png"
MAP_CSV = ROOT / "05_docs/ui_glyph_store_v42_map.csv"

PSX = "PSX.EXE"
COMM = "COMM.IMG"
STORY = "1/S1011.DAT"
RAM_TO_FILE = 0x8011A800

LOOKUP = 0x801A7520
LOOKUP_N = 409
GA_SRC = 0x801A8800
GB_SRC = 0x801A8BA8
STRIP_BYTES = 936
STRIP_ROW_BYTES = 78

IPR = 84
PLANES = 4
CELL = 12
COLS = 13
ROW_A = 40
ROW_B = 63
OLD_P6_ROW = 24
BASE_X4 = 1280
OLD_P6_X4 = 2856
COMM_ROW_BYTES = 896

SLOT_BASE = 0x45000
SLOT_SIZE = 0x80
PAGE_SLOTS = (0, 1, 2, 3)
INLINE = (0x478AA, 0x47902, 0x47954, 0x4799E)
INLINE_COMMANDS = (b"\xE2\x81", b"\xE2\x82", b"\xE2\x83", b"\xE2\x84")

RENDER_HOOK = 0x8016B764
STATELESS_DRIVER = 0x801A20B0
SECONDARY_DECODE_CALL = 0x8016BD94
GLYPH_DECODER = 0x8016B3C0
DECODER_HOOK = 0x8016B3D4
E9EA_DECODER = 0x801A74B8


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def jump(target: int) -> int:
    return 0x08000000 | ((target & 0x0FFFFFFF) >> 2)


def jal(target: int) -> int:
    return 0x0C000000 | ((target & 0x0FFFFFFF) >> 2)


def word(buf: bytes, ram: int) -> int:
    return struct.unpack_from("<I", buf, ram - RAM_TO_FILE)[0]


def clone_info(source: ZipInfo) -> ZipInfo:
    target = ZipInfo(source.filename, source.date_time)
    for attr in (
        "compress_type", "comment", "extra", "create_system", "create_version",
        "extract_version", "flag_bits", "volume", "internal_attr", "external_attr",
    ):
        setattr(target, attr, getattr(source, attr))
    return target


def rows(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def virtual_code(slot: int) -> bytes:
    if not 0 <= slot < LOOKUP_N:
        raise ValueError(slot)
    if slot < 0xFE:
        return bytes((0xE9, slot + 1))
    return bytes((0xEA, slot - 0xFE + 1))


def physical(slot: int) -> int:
    row = ROW_A if slot < 52 else ROW_B
    local = slot if slot < 52 else slot - 52
    column, plane = divmod(local, PLANES)
    return row * IPR + column * PLANES + plane


def source_location(index: int) -> tuple[int, int, int]:
    """Translate v116's resident positions back to their COMM.IMG source."""
    row, remainder = divmod(index, IPR)
    column, plane = divmod(remainder, PLANES)
    if row == ROW_A:
        return OLD_P6_ROW, column, plane
    if row == ROW_B:
        return OLD_P6_ROW, COLS + column, plane
    return row, column, plane


def comm_nibble(comm: bytes, x4: int, y: int) -> int:
    offset = y * COMM_ROW_BYTES + (x4 - BASE_X4) // 2
    shift = 0 if x4 % 2 == 0 else 4
    return (comm[offset] >> shift) & 0xF


def source_bitmap(comm: bytes, index: int) -> tuple[int, ...]:
    row, column, plane = source_location(index)
    x0 = (OLD_P6_X4 if row == OLD_P6_ROW else BASE_X4) + column * CELL
    y0 = row * CELL
    bit = 1 << plane
    result = tuple(
        1 if comm_nibble(comm, x0 + x, y0 + y) & bit else 0
        for y in range(CELL)
        for x in range(CELL)
    )
    if not any(result):
        raise SystemExit(
            f"source glyph is blank: index={index} row={row} col={column} plane={plane}"
        )
    return result


def strip_nibble(buf: bytes | bytearray, x4: int, y: int) -> int:
    offset = y * STRIP_ROW_BYTES + x4 // 2
    shift = 0 if x4 % 2 == 0 else 4
    return (buf[offset] >> shift) & 0xF


def set_strip_plane(buf: bytearray, x4: int, y: int, plane: int, on: int) -> None:
    offset = y * STRIP_ROW_BYTES + x4 // 2
    shift = 0 if x4 % 2 == 0 else 4
    nibble = (buf[offset] >> shift) & 0xF
    nibble = nibble | (1 << plane) if on else nibble & ~(1 << plane)
    buf[offset] = (buf[offset] & ~(0xF << shift)) | (nibble << shift)


def write_slot(buf: bytearray, slot: int, bitmap: tuple[int, ...]) -> None:
    local = slot if slot < 52 else slot - 52
    column, plane = divmod(local, PLANES)
    for y in range(CELL):
        for x in range(CELL):
            set_strip_plane(buf, column * CELL + x, y, plane, bitmap[y * CELL + x])


def slot_bitmap(buf: bytes | bytearray, slot: int) -> tuple[int, ...]:
    local = slot if slot < 52 else slot - 52
    column, plane = divmod(local, PLANES)
    bit = 1 << plane
    return tuple(
        1 if strip_nibble(buf, column * CELL + x, y) & bit else 0
        for y in range(CELL)
        for x in range(CELL)
    )


def render_reference(records: list[dict[str, object]], strips: tuple[bytes, bytes]) -> None:
    scale = 3
    cell_w, cell_h = 52, 54
    left, top = 16, 28
    page_gap = 26
    width = left * 2 + COLS * cell_w
    height = top + 4 * (2 * cell_h + page_gap)
    image = Image.new("RGB", (width, height), "#15171b")
    draw = ImageDraw.Draw(image)
    font = ImageFont.load_default()

    for page in range(4):
        base_y = top + page * (2 * cell_h + page_gap)
        store = "A" if page < 2 else "B"
        draw.text((left, base_y - 18), f"PAGE {page + 1} / STRIP {store}", fill="#f0f0f0", font=font)
        for within in range(26):
            global_slot = page * 26 + within
            line, column = divmod(within, COLS)
            x0 = left + column * cell_w
            y0 = base_y + line * cell_h
            draw.rectangle((x0, y0, x0 + cell_w - 3, y0 + cell_h - 3), outline="#4b515b")
            strip = strips[0] if global_slot < 52 else strips[1]
            bits = slot_bitmap(strip, global_slot)
            glyph = Image.new("1", (CELL, CELL))
            glyph.putdata(bits)
            glyph = glyph.resize((CELL * scale, CELL * scale), Image.Resampling.NEAREST)
            image.paste((242, 242, 239), (x0 + 7, y0 + 3), glyph)
            code = str(records[global_slot]["virtual_code"]).replace(" ", "")
            draw.text((x0 + 2, y0 + 40), f"{global_slot:03} {code}", fill="#9fb8dc", font=font)

    REFERENCE_PNG.parent.mkdir(parents=True, exist_ok=True)
    image.save(REFERENCE_PNG)


def main() -> None:
    if sha256(BASE_ZIP.read_bytes()) != BASE_SHA256:
        raise SystemExit("base archive is not the verified v116 build")

    with ZipFile(BASE_ZIP, "r") as source:
        infos = source.infolist()
        members = {info.filename: source.read(info.filename) for info in infos}
    before = dict(members)
    if {PSX, COMM, STORY} - members.keys():
        raise SystemExit("v116 archive lacks a required member")

    exe = bytearray(members[PSX])
    comm = members[COMM]
    story = bytearray(members[STORY])
    mapping_rows = rows(MAP_CSV)
    if len(mapping_rows) != LOOKUP_N:
        raise SystemExit(f"UI map count differs: {len(mapping_rows)}")
    for slot, item in enumerate(mapping_rows):
        if bytes.fromhex(item["virtual_code_hex"]) != virtual_code(slot):
            raise SystemExit(f"virtual-code order differs at table slot {slot}")

    guards = [
        (RENDER_HOOK, jump(STATELESS_DRIVER), "v116 direct stateless renderer entry"),
        (STATELESS_DRIVER, 0x27BDFFB0, "two-pass driver prologue"),
        (SECONDARY_DECODE_CALL, jal(GLYPH_DECODER), "E2 secondary string uses common glyph decoder"),
        (DECODER_HOOK, jump(E9EA_DECODER), "common decoder uses E9/EA lookup"),
    ]
    for address, expected, label in guards:
        got = word(exe, address)
        if got != expected:
            raise SystemExit(
                f"guard failed at 0x{address:08X}: 0x{got:08X} != 0x{expected:08X} ({label})"
            )

    lookup_offset = LOOKUP - RAM_TO_FILE
    old_lookup = list(struct.unpack_from(f"<{LOOKUP_N}H", exe, lookup_offset))
    old_p6 = [i for i, value in enumerate(old_lookup) if value // IPR in (ROW_A, ROW_B)]
    if len(old_p6) != 57:
        raise SystemExit(f"v116 P6 mapping count differs: {len(old_p6)} != 57")

    selected = set(old_p6)
    for table_slot in range(LOOKUP_N):
        if len(selected) == 104:
            break
        selected.add(table_slot)
    selected = sorted(selected)
    if len(selected) != 104 or not set(old_p6) <= set(selected):
        raise SystemExit("could not select 104 entries while preserving every existing P6 user")

    strip_a = bytearray(STRIP_BYTES)
    strip_b = bytearray(STRIP_BYTES)
    new_lookup = list(old_lookup)
    bitmaps: list[tuple[int, ...]] = []
    records: list[dict[str, object]] = []
    for target_slot, table_slot in enumerate(selected):
        bitmap = source_bitmap(comm, old_lookup[table_slot])
        bitmaps.append(bitmap)
        target = strip_a if target_slot < 52 else strip_b
        write_slot(target, target_slot, bitmap)
        target_index = physical(target_slot)
        new_lookup[table_slot] = target_index
        page, within = divmod(target_slot, 26)
        line, column = divmod(within, COLS)
        records.append(
            {
                "page": page + 1,
                "line": line + 1,
                "column": column + 1,
                "store": "A" if target_slot < 52 else "B",
                "global_slot": target_slot,
                "virtual_table_slot": table_slot,
                "virtual_code": virtual_code(table_slot).hex(" ").upper(),
                "char": mapping_rows[table_slot]["char"],
                "source_physical_index": old_lookup[table_slot],
                "target_physical_index": target_index,
            }
        )

    for slot, bitmap in enumerate(bitmaps):
        target = strip_a if slot < 52 else strip_b
        if slot_bitmap(target, slot) != bitmap:
            raise SystemExit(f"strip bitmap readback failed at slot {slot}")
    if any(not any(slot_bitmap(strip_a if slot < 52 else strip_b, slot)) for slot in range(104)):
        raise SystemExit("at least one of the 104 target slots is blank")

    struct.pack_into(f"<{LOOKUP_N}H", exe, lookup_offset, *new_lookup)
    exe[GA_SRC - RAM_TO_FILE:GA_SRC - RAM_TO_FILE + STRIP_BYTES] = strip_a
    exe[GB_SRC - RAM_TO_FILE:GB_SRC - RAM_TO_FILE + STRIP_BYTES] = strip_b

    expected_targets = [physical(slot) for slot in range(104)]
    actual_targets = [new_lookup[table_slot] for table_slot in selected]
    if actual_targets != expected_targets or len(set(actual_targets)) != 104:
        raise SystemExit("lookup does not cover every resident slot exactly once")
    outside_p6 = [
        i for i, value in enumerate(new_lookup)
        if i not in selected and value // IPR in (ROW_A, ROW_B)
    ]
    if outside_p6:
        raise SystemExit(f"unselected lookup entries still point into the test strips: {outside_p6}")

    old_story = bytes(story)
    old_tails: list[int] = []
    for page, (slot, inline, command) in enumerate(zip(PAGE_SLOTS, INLINE, INLINE_COMMANDS)):
        if story[inline:inline + 2] != command:
            raise SystemExit(f"early E2 command differs at 0x{inline:X}")
        start = SLOT_BASE + slot * SLOT_SIZE
        tail = story[start + SLOT_SIZE - 1]
        old_tails.append(tail)
        payload = b"".join(
            virtual_code(selected[index])
            for index in range(page * 26, (page + 1) * 26)
        )
        if len(payload) != 52 or any(byte not in (0xE9, 0xEA) for byte in payload[::2]):
            raise SystemExit(f"page {page + 1} payload is not 26 E9/EA glyphs")
        story[start:start + SLOT_SIZE] = b"\x00" * SLOT_SIZE
        story[start:start + len(payload)] = payload
        story[start + SLOT_SIZE - 1] = tail
        if story[inline:inline + 2] != command:
            raise SystemExit("inline E2 command changed")

    allowed_story = set()
    for slot in PAGE_SLOTS:
        start = SLOT_BASE + slot * SLOT_SIZE
        allowed_story.update(range(start, start + SLOT_SIZE))
    story_diff = [i for i, (a, b) in enumerate(zip(old_story, story)) if a != b]
    if not story_diff or any(i not in allowed_story for i in story_diff):
        raise SystemExit("S1011 changed outside the four external test slots")
    if [story[SLOT_BASE + slot * SLOT_SIZE + SLOT_SIZE - 1] for slot in PAGE_SLOTS] != old_tails:
        raise SystemExit("E2 inline-skip tails changed")

    old_exe = members[PSX]
    allowed_exe = set(range(LOOKUP - RAM_TO_FILE, LOOKUP - RAM_TO_FILE + LOOKUP_N * 2))
    allowed_exe.update(range(GA_SRC - RAM_TO_FILE, GA_SRC - RAM_TO_FILE + STRIP_BYTES))
    allowed_exe.update(range(GB_SRC - RAM_TO_FILE, GB_SRC - RAM_TO_FILE + STRIP_BYTES))
    exe_diff = [i for i, (a, b) in enumerate(zip(old_exe, exe)) if a != b]
    if not exe_diff or any(i not in allowed_exe for i in exe_diff):
        raise SystemExit("PSX.EXE changed outside lookup and resident strip sources")
    if len(exe) != len(old_exe) or len(story) != len(old_story):
        raise SystemExit("member size changed")

    members[PSX] = bytes(exe)
    members[STORY] = bytes(story)
    if members[COMM] != before[COMM]:
        raise SystemExit("COMM.IMG changed in a test that must leave it untouched")
    changed_members = [name for name in members if members[name] != before[name]]
    if set(changed_members) != {PSX, STORY} or len(changed_members) != 2:
        raise SystemExit(f"unexpected changed members: {changed_members}")

    if OUTPUT.exists():
        raise SystemExit(f"refusing to overwrite existing {OUTPUT.name}")
    with ZipFile(OUTPUT, "w") as target:
        for info in infos:
            target.writestr(clone_info(info), members[info.filename])
    with ZipFile(OUTPUT, "r") as built:
        if [info.filename for info in built.infolist()] != [info.filename for info in infos]:
            raise SystemExit("ZIP member order changed")
        for name, expected in members.items():
            if built.read(name) != expected:
                raise SystemExit(f"ZIP readback failed: {name}")

    ANALYSIS.mkdir(parents=True, exist_ok=True)
    with REFERENCE_CSV.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(records[0]))
        writer.writeheader()
        writer.writerows(records)
    render_reference(records, (bytes(strip_a), bytes(strip_b)))

    report = [
        "v117 104-slot story-path coverage probe",
        "",
        f"base    {BASE_ZIP.name}",
        f"output  {OUTPUT.name}",
        f"sha256  {sha256(OUTPUT.read_bytes())}",
        "",
        "coverage:",
        "  resident slots: 104/104, every target bitmap nonblank",
        "  strip A: 52/52; pages 1-2",
        "  strip B: 52/52; pages 3-4",
        f"  retained existing P6 virtual codes: {len(old_p6)}",
        f"  added ordinary virtual codes for empty-slot coverage: {104 - len(old_p6)}",
        "  early E2 secondary pages: 4 x 26 E9/EA glyphs",
        "",
        "changed members:",
        f"  {PSX}: lookup table plus the two resident strip source blocks only",
        f"  {STORY}: external slots 0-3 only; inline E2 commands and skip tails preserved",
        f"  {COMM}: byte-identical to v116",
        "  canonical translation CSVs: not modified",
        "",
        f"PSX changed bytes: {len(exe_diff)}",
        f"S1011 changed bytes: {len(story_diff)}",
        f"slot tails preserved: {' '.join(f'{value:02X}' for value in old_tails)}",
        f"reference CSV: {REFERENCE_CSV}",
        f"reference PNG: {REFERENCE_PNG}",
        "static verification: PASS",
        "runtime verification: PENDING",
        "",
        "runtime procedure:",
        "  cold boot and start a new game / reach the first S1011 sequence",
        "  capture four consecutive test messages",
        "  compare pages 1-4 with reference.png",
        "  advance past page 4 and confirm the scene continues",
        "  the known v103 skill-range cursor regression is outside this probe",
    ]
    REPORT.write_text("\n".join(report) + "\n", encoding="utf-8")
    print("\n".join(report))


if __name__ == "__main__":
    main()
