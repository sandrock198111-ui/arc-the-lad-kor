"""v118: add 47 syllables without touching a line of renderer code.

Storage the shipping renderer already reaches, and nothing else:

  strip B slots 5..51   47  uploaded from reserved RAM every frame, classifier
                            already answers to its V=244; five slots are in use

COMM.IMG is not touched at all.  The first version of this build also wrote one
syllable into what looked like a free plane in the font page -- index 1671, row 19
column 18, plane 3.  Plane 3 was indeed empty there, but the cell was not: it holds
the START button icon in the other three planes.  A 4bpp pixel indexes a CLUT with
all four planes at once, so setting plane 3 shifted every pixel of that icon to a
different colour and visibly corrupted it in game.  An empty plane is not free
space; only an empty cell is.  `cell_is_occupied` now enforces that.

Strip B's free slots need lookup entries and all 409 existing ones point at real
glyphs, so the table has to grow.  The decoder at 0x801A74B8 computes
`254 * (lead - 0xE9) + trail - 1` and indexes the table with **no bounds check**,
so slots up to 507 are already reachable -- only storage was missing.

Where the table goes matters more than it looks.  It cannot grow in place: the
original executable's zero run ends at 0x801A7860 and real game data begins
there, leaving room for 416 entries against the 456 needed.  It also cannot sit
in the sector the executable grows by, because that address range is live RAM
once the game is running.  It goes where strips A and B already live: the
reserved block, which the heap-base patch fenced off and which the two-strip
renderer has been reading from every frame since v112.

So the table is appended to the reserved block and its image is appended to the
block's source in the executable tail, which the existing boot-time memcpy
already copies.  The grown sector therefore only has to survive from the BIOS
EXE load to heap initialisation, not for the life of the process.

    source  0x801A8FB8 .. 0x801A93B0   72 bytes of existing tail + the new sector
    dest    0x801FEC90 .. 0x801FF088   appended to the reserved block
    heap    0x801FEC90 -> 0x801FF088   still below 0x801FFA60, the lowest address
                                       the game's heap has ever been seen to use

Four words change: the two that build the table address in the decoder, the
memcpy length, and the heap base.  Every one is verified against the rebuilt
bytes before the archive is written.
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

from build_story_sf0b1_return_full import get_pixel, render_glyph, set_pixel  # noqa: E402

BASE_ZIP = ROOT / "03_output/ui_hud_e7_v116_direct_stateless_renderer_patch_only.zip"
BASE_SHA256 = "DC59B6211598508211BF201DDBAECF8C51386379F665D9B303C4C6301A09AC34"
OUTPUT = ROOT / "03_output/ui_hud_e7_v118_strip_b_fill_patch_only.zip"
PLAN_CSV = ROOT / "05_docs/v118_slot_assignment.csv"
CHARMAP_OUT = ROOT / "05_docs/korean_charmap_virtual_v118.csv"
ANALYSIS = ROOT / "01_work/analysis/ui_hud_e7_v118_strip_b_fill"
REPORT = ANALYSIS / "build_report.txt"

PSX, COMM = "PSX.EXE", "COMM.IMG"
RAM_TO_FILE = 0x8011A800
SECTOR = 2048

OLD_LOOKUP, OLD_LOOKUP_N = 0x801A7520, 409
NEW_LOOKUP_N = 508                      # the largest slot the decoder can compute
LOOKUP_LUI, LOOKUP_ORI = 0x801A74E4, 0x801A74E8
OLD_LUI_WORD, OLD_ORI_WORD = 0x3C09801A, 0x35297520

RESERVED_SRC, RESERVED_DST = 0x801A86EC, 0x801FE3C4
MEMCPY_LEN_AT, HEAP_BASE_AT = 0x801757CC, 0x80175810
OLD_MEMCPY_LEN, OLD_HEAP_BASE = 2252, 0x801FEC90
HEAP_HI, HEAP_SEEN_USED = 0x80200000, 0x801FFA60

GB_SRC = 0x801A8BA8
STRIP_BYTES, STRIP_ROW_BYTES = 936, 78
CELL, PLANES, IPR = 12, 4, 84
STRIP_B_BASE = 63 * IPR
BLANK_INDEX = 0x9C - 1                  # the space filler: reachable and blank by design

HEADER_T_ADDR, HEADER_T_SIZE = 0x18, 0x1C
T0, A0 = 8, 4


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def addiu(rs: int, rt: int, imm: int) -> int:
    return (0x09 << 26) | (rs << 21) | (rt << 16) | (imm & 0xFFFF)


def clone_info(source: ZipInfo) -> ZipInfo:
    target = ZipInfo(source.filename, source.date_time)
    for attr in (
        "compress_type", "comment", "extra", "create_system", "create_version",
        "extract_version", "flag_bits", "volume", "internal_attr", "external_attr",
    ):
        setattr(target, attr, getattr(source, attr))
    return target


def bitmap_of(char: str) -> tuple[int, ...]:
    glyph = render_glyph(char)
    bits = tuple(1 if glyph.getpixel((x, y)) else 0 for y in range(CELL) for x in range(CELL))
    if not any(bits):
        raise SystemExit(f"{char!r} renders blank at 12x12")
    return bits


def strip_nibble(buf: bytes | bytearray, x: int, y: int) -> int:
    return (buf[y * STRIP_ROW_BYTES + x // 2] >> (0 if x % 2 == 0 else 4)) & 0xF


def set_strip_plane(buf: bytearray, x: int, y: int, plane: int, on: int) -> None:
    offset = y * STRIP_ROW_BYTES + x // 2
    shift = 0 if x % 2 == 0 else 4
    nibble = (buf[offset] >> shift) & 0xF
    nibble = nibble | (1 << plane) if on else nibble & ~(1 << plane)
    buf[offset] = (buf[offset] & ~(0xF << shift)) | (nibble << shift)


def strip_slot_bitmap(buf: bytes | bytearray, slot: int) -> tuple[int, ...]:
    column, plane = divmod(slot, PLANES)
    bit = 1 << plane
    return tuple(
        1 if strip_nibble(buf, column * CELL + x, y) & bit else 0
        for y in range(CELL) for x in range(CELL)
    )


def write_strip_slot(buf: bytearray, slot: int, bits: tuple[int, ...]) -> None:
    column, plane = divmod(slot, PLANES)
    for y in range(CELL):
        for x in range(CELL):
            set_strip_plane(buf, column * CELL + x, y, plane, bits[y * CELL + x])


def comm_plane_bitmap(font: bytes | bytearray, index: int) -> tuple[int, ...]:
    row, remainder = divmod(index, IPR)
    column, plane = divmod(remainder, PLANES)
    bit = 1 << plane
    return tuple(
        1 if get_pixel(font, column * CELL + x, row * CELL + y) & bit else 0
        for y in range(CELL) for x in range(CELL)
    )


def cell_is_occupied(font: bytes | bytearray, index: int) -> tuple[int, ...]:
    """Every pixel of the whole 12x12 cell, all four planes together.

    Non-zero anywhere means the cell is drawing something, whatever plane it uses.
    """
    row, remainder = divmod(index, IPR)
    column = remainder // PLANES
    return tuple(
        get_pixel(font, column * CELL + x, row * CELL + y)
        for y in range(CELL) for x in range(CELL)
    )


def write_comm_plane(font: bytearray, index: int, bits: tuple[int, ...]) -> None:
    row, remainder = divmod(index, IPR)
    column, plane = divmod(remainder, PLANES)
    for y in range(CELL):
        for x in range(CELL):
            px, py = column * CELL + x, row * CELL + y
            value = get_pixel(font, px, py)
            value = value | (1 << plane) if bits[y * CELL + x] else value & ~(1 << plane)
            set_pixel(font, px, py, value)


def resolve(code: bytes, lut: tuple[int, ...] | list[int]) -> int:
    """What the decoder turns a byte sequence into, by the same arithmetic it uses."""
    if len(code) == 1:
        return code[0] - 1
    lead, trail = code
    if lead in (0xE9, 0xEA):
        slot = (lead - 0xE9) * 254 + trail - 1
        if not 0 <= slot < len(lut):
            raise SystemExit(f"lookup slot {slot} is past the table")
        return lut[slot]
    if lead >= 0xDD:
        return (lead - 0xDD) * 255 + trail + 0xDB
    raise SystemExit(f"lead byte {lead:02X} does not select a glyph")


def main() -> None:
    if digest(BASE_ZIP.read_bytes()) != BASE_SHA256:
        raise SystemExit("base archive is not the v116 build")
    with ZipFile(BASE_ZIP) as archive:
        infos = archive.infolist()
        members = {info.filename: archive.read(info.filename) for info in infos}

    with PLAN_CSV.open(encoding="utf-8-sig", newline="") as handle:
        plan = list(csv.DictReader(handle))
    if not plan:
        raise SystemExit("assignment plan is empty")

    exe = bytearray(members[PSX])
    font = bytearray(members[COMM])
    base_exe, base_font = members[PSX], members[COMM]

    # ---- everything this build assumes about v116, checked ----
    t_addr, t_size = struct.unpack_from("<II", exe, HEADER_T_ADDR)
    image_end = t_addr + t_size
    if t_addr - 0x800 != RAM_TO_FILE:
        raise SystemExit(f"unexpected load address 0x{t_addr:X}")
    if struct.unpack_from("<I", exe, LOOKUP_LUI - RAM_TO_FILE)[0] != OLD_LUI_WORD:
        raise SystemExit("the lui that builds the table address is not the expected one")
    if struct.unpack_from("<I", exe, LOOKUP_ORI - RAM_TO_FILE)[0] != OLD_ORI_WORD:
        raise SystemExit("the ori that builds the table address is not the expected one")
    if (struct.unpack_from("<I", exe, MEMCPY_LEN_AT - RAM_TO_FILE)[0] & 0xFFFF) != OLD_MEMCPY_LEN:
        raise SystemExit("the reserved-block memcpy length is not 2252")
    heap_imm = struct.unpack_from("<I", exe, HEAP_BASE_AT - RAM_TO_FILE)[0] & 0xFFFF
    heap_now = HEAP_HI + (heap_imm - 0x10000 if heap_imm & 0x8000 else heap_imm) + 4
    if heap_now != OLD_HEAP_BASE or RESERVED_DST + OLD_MEMCPY_LEN != OLD_HEAP_BASE:
        raise SystemExit(f"reserved block does not end at the heap base 0x{heap_now:08X}")

    table_src = RESERVED_SRC + OLD_MEMCPY_LEN
    table_dst = RESERVED_DST + OLD_MEMCPY_LEN
    table_bytes = NEW_LOOKUP_N * 2
    if any(exe[table_src - RAM_TO_FILE:image_end - RAM_TO_FILE]):
        raise SystemExit("the executable tail after the reserved-block source is not free")
    new_heap = table_dst + table_bytes
    if new_heap >= HEAP_SEEN_USED:
        raise SystemExit("the reservation would reach heap the game uses")

    old_lut = list(struct.unpack_from(f"<{OLD_LOOKUP_N}H", exe, OLD_LOOKUP - RAM_TO_FILE))
    strip_b = bytearray(exe[GB_SRC - RAM_TO_FILE:GB_SRC - RAM_TO_FILE + STRIP_BYTES])

    # ---- place the glyphs ----
    lut = old_lut + [BLANK_INDEX] * (NEW_LOOKUP_N - OLD_LOOKUP_N)
    records: list[dict[str, object]] = []
    for row in plan:
        char, code, index = row["char"], bytes.fromhex(row["code"]), int(row["index"])
        bits = bitmap_of(char)
        if row["kind"] == "strip_b":
            slot = index - STRIP_B_BASE
            if not 0 <= slot < 52:
                raise SystemExit(f"{char}: index {index} is not inside strip B")
            if any(strip_slot_bitmap(strip_b, slot)):
                raise SystemExit(f"{char}: strip B slot {slot} is already occupied")
            write_strip_slot(strip_b, slot, bits)
            lookup_slot = int(row["lookup_slot"])
            if lookup_slot < OLD_LOOKUP_N:
                raise SystemExit(f"{char}: lookup slot {lookup_slot} is already in use")
            lut[lookup_slot] = index
        elif row["kind"] == "font_page":
            if any(comm_plane_bitmap(font, index)):
                raise SystemExit(f"{char}: COMM.IMG index {index} is already occupied")
            # An empty plane is not an empty cell.  A 4bpp pixel indexes a CLUT with
            # all four planes at once, so writing into a spare plane of a cell that
            # still holds art shifts every one of its pixels to a different colour.
            # v109 and v111 broke glyphs this way; v118 broke the START icon this way,
            # by checking only the plane it was about to write.
            if any(cell_is_occupied(font, index)):
                raise SystemExit(
                    f"{char}: COMM.IMG index {index} is in a cell that still holds art. "
                    f"A blank plane there is not free space.")
            write_comm_plane(font, index, bits)
        else:
            raise SystemExit(f"{char}: unknown storage kind {row['kind']!r}")
        records.append({"char": char, "code": code, "index": index,
                        "kind": row["kind"], "bits": bits})

    exe[GB_SRC - RAM_TO_FILE:GB_SRC - RAM_TO_FILE + STRIP_BYTES] = strip_b

    # ---- grow the image, append the table image, repoint the four words ----
    grow = 0
    while image_end + grow < table_src + table_bytes:
        grow += SECTOR
    exe += b"\x00" * grow
    struct.pack_into(f"<{NEW_LOOKUP_N}H", exe, table_src - RAM_TO_FILE, *lut)
    struct.pack_into("<I", exe, HEADER_T_SIZE, t_size + grow)
    struct.pack_into("<I", exe, LOOKUP_LUI - RAM_TO_FILE,
                     (0x0F << 26) | (T0 + 1 << 16) | (table_dst >> 16))
    struct.pack_into("<I", exe, LOOKUP_ORI - RAM_TO_FILE,
                     (0x0D << 26) | ((T0 + 1) << 21) | ((T0 + 1) << 16) | (table_dst & 0xFFFF))
    struct.pack_into("<I", exe, MEMCPY_LEN_AT - RAM_TO_FILE,
                     addiu(0, 6, OLD_MEMCPY_LEN + table_bytes))
    struct.pack_into("<I", exe, HEAP_BASE_AT - RAM_TO_FILE,
                     addiu(A0, A0, (new_heap - 4) - HEAP_HI))

    # ---- verify against the rebuilt bytes, not against intent ----
    lui = struct.unpack_from("<I", exe, LOOKUP_LUI - RAM_TO_FILE)[0]
    ori = struct.unpack_from("<I", exe, LOOKUP_ORI - RAM_TO_FILE)[0]
    if ((lui & 0xFFFF) << 16 | (ori & 0xFFFF)) != table_dst:
        raise SystemExit("the two instructions do not build the table address")
    if (lui >> 26, (lui >> 16) & 31) != (0x0F, T0 + 1) or \
       (ori >> 26, (ori >> 21) & 31, (ori >> 16) & 31) != (0x0D, T0 + 1, T0 + 1):
        raise SystemExit("the rebuilt lui/ori are not lui t1 / ori t1,t1")
    length = struct.unpack_from("<I", exe, MEMCPY_LEN_AT - RAM_TO_FILE)[0] & 0xFFFF
    if RESERVED_SRC + length != table_src + table_bytes or RESERVED_DST + length != new_heap:
        raise SystemExit("the memcpy no longer spans exactly the reserved block and the table")
    imm = struct.unpack_from("<I", exe, HEAP_BASE_AT - RAM_TO_FILE)[0] & 0xFFFF
    if HEAP_HI + (imm - 0x10000 if imm & 0x8000 else imm) + 4 != new_heap:
        raise SystemExit("the heap base does not follow the table")
    if list(struct.unpack_from(f"<{OLD_LOOKUP_N}H", exe, table_src - RAM_TO_FILE)) != old_lut:
        raise SystemExit("an inherited lookup entry changed")

    built_lut = struct.unpack_from(f"<{NEW_LOOKUP_N}H", exe, table_src - RAM_TO_FILE)
    built_strip = exe[GB_SRC - RAM_TO_FILE:GB_SRC - RAM_TO_FILE + STRIP_BYTES]
    for record in records:
        index = resolve(record["code"], built_lut)
        if index != record["index"]:
            raise SystemExit(f"{record['char']}: code {record['code'].hex().upper()} "
                             f"resolves to {index}, not {record['index']}")
        got = (strip_slot_bitmap(built_strip, index - STRIP_B_BASE)
               if record["kind"] == "strip_b" else comm_plane_bitmap(font, index))
        if got != record["bits"]:
            raise SystemExit(f"{record['char']}: glyph did not read back from index {index}")

    allowed = set(range(GB_SRC - RAM_TO_FILE, GB_SRC - RAM_TO_FILE + STRIP_BYTES))
    allowed |= set(range(table_src - RAM_TO_FILE, image_end - RAM_TO_FILE))
    for address in (LOOKUP_LUI, LOOKUP_ORI, MEMCPY_LEN_AT, HEAP_BASE_AT):
        allowed |= set(range(address - RAM_TO_FILE, address - RAM_TO_FILE + 4))
    allowed |= set(range(HEADER_T_SIZE, HEADER_T_SIZE + 4))
    stray = [i for i in range(len(base_exe)) if base_exe[i] != exe[i] and i not in allowed]
    if stray:
        raise SystemExit(f"{len(stray)} bytes changed outside the declared regions, "
                         f"first at file offset 0x{stray[0]:X}")
    font_changed = sum(1 for i in range(len(base_font)) if base_font[i] != font[i])

    members[PSX], members[COMM] = bytes(exe), bytes(font)
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with ZipFile(OUTPUT, "w") as archive:
        for info in infos:
            archive.writestr(clone_info(info), members[info.filename])

    with CHARMAP_OUT.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["char", "code_hex", "storage", "physical_index", "note"])
        for record in records:
            writer.writerow([
                record["char"], record["code"].hex().upper(), record["kind"], record["index"],
                "lookup-relative code, encode only" if record["kind"] == "strip_b"
                else "physical code",
            ])

    lines = [
        "v118 fill the empty strip B slots",
        "",
        f"base    {BASE_ZIP.name}",
        f"output  {OUTPUT.name}",
        f"        sha256 {digest(OUTPUT.read_bytes())}",
        f"PSX.EXE {len(exe)} bytes (grew {grow}); last file under the v104 layout, nothing moves",
        f"COMM.IMG {font_changed} bytes changed",
        "",
        f"syllables added   {len(records)}"
        f"  ({sum(1 for r in records if r['kind'] == 'strip_b')} strip B,"
        f" {sum(1 for r in records if r['kind'] == 'font_page')} font page)",
        "",
        "lookup table",
        f"  was     0x{OLD_LOOKUP:08X}  {OLD_LOOKUP_N} entries, in the executable image",
        f"  now     0x{table_dst:08X}  {NEW_LOOKUP_N} entries, appended to the reserved block",
        f"  source  0x{table_src:08X}..0x{table_src + table_bytes:08X}, copied by the boot memcpy",
        f"  entries {OLD_LOOKUP_N}..{OLD_LOOKUP_N + 46} are new; the rest read back as the blank"
        f" space glyph so no computable slot is undefined",
        "",
        "reserved RAM",
        f"  0x{RESERVED_DST:08X} block          {OLD_MEMCPY_LEN}",
        f"  0x{table_dst:08X} lookup table   {table_bytes}",
        f"  0x{new_heap:08X} heap starts here ({HEAP_SEEN_USED - new_heap} bytes clear of heap"
        f" the game uses)",
        "",
        "words changed",
        f"  0x{LOOKUP_LUI:08X}  {lui:08X}  lui t1,0x{table_dst >> 16:04X}",
        f"  0x{LOOKUP_ORI:08X}  {ori:08X}  ori t1,t1,0x{table_dst & 0xFFFF:04X}",
        f"  0x{MEMCPY_LEN_AT:08X}  "
        f"{struct.unpack_from('<I', exe, MEMCPY_LEN_AT - RAM_TO_FILE)[0]:08X}"
        f"  memcpy length -> {length}",
        f"  0x{HEAP_BASE_AT:08X}  "
        f"{struct.unpack_from('<I', exe, HEAP_BASE_AT - RAM_TO_FILE)[0]:08X}"
        f"  heap base -> 0x{new_heap:08X}",
        f"  header 0x{HEADER_T_SIZE:02X}    {t_size + grow:08X}  t_size, so the loader copies"
        f" the new sector",
        "",
        "verified",
        "  base archive digest matches v116",
        "  every assumption above was read out of v116 before anything was written",
        f"  {OLD_LOOKUP_N} inherited lookup entries survive unchanged at the new address",
        "  the rebuilt lui/ori really build the table address, in t1, as lui/ori",
        "  the memcpy spans exactly the reserved block plus the table, and the heap follows it",
        f"  all {len(records)} codes resolve to their own index and read their own glyph back",
        "  no byte outside strip B, the four words, the header and the new tail differs from v116",
        "",
        "NOT verified here, needs a cold boot on hardware or emulator:",
        "  that the grown sector survives from the BIOS EXE load until heap initialisation",
        "  runtime confirmation that all 48 syllables render",
        "",
        "characters added, most frequent first:",
    ]
    for record in records:
        lines.append(f"  {record['char']}  {record['code'].hex().upper():<6}"
                     f"index {record['index']:>5}  {record['kind']}")
    lines += [
        "",
        f"encoder map  {CHARMAP_OUT.relative_to(ROOT)}",
        "  The 47 strip B codes are lookup-relative.  Story builders derive a COMM.IMG cell",
        "  from a code with (lead - 0xDD) * 255 + trail + 0xDB, which is meaningless for lead",
        "  0xE9/0xEA, so these rows must never reach write_glyph_plane.  They are encode-only.",
        "",
        "rebuild with arc1_v104.xml, then run verify_iso_layout.py",
    ]
    ANALYSIS.mkdir(parents=True, exist_ok=True)
    REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines[:34]))
    print(f"\nreport -> {REPORT}")


if __name__ == "__main__":
    main()
