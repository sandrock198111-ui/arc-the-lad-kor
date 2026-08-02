"""v119: a third resident glyph strip, and 52 more syllables.

v118 used the last free slot the shipping renderer could reach.  A third strip is
the only way to add more, and it turns out to be cheap, because of how the three
values that place a glyph in VRAM are produced:

    tpage   one DR_TPAGE per text object, at 0x801A2188..0x801A2198
    U       written per glyph by the helper into packet byte 0x28
    V       per glyph, as (row * 12) & 0xFF

Only tpage is shared.  So a strip anywhere inside the page the objects already
select costs one more row test in the helper, one more V test in the classifier,
and one more LoadImage in the frame routine.  A strip outside that page would need
a tpage primitive per glyph, which is a different and much larger change.

Where it goes, measured over 99 save states (88 pre-strip, 9 from v118):

    the game draws into y 268..287 and y 300..319 inside page 15,1
    y 320..479 is free in every one of them
    strip C sits at y 380, in the middle of that gap -- 61 rows below the
    occupied block and 77 above strip A

The middle, not the edge, because nine v118 states alone showed the whole page
free and the 88 older ones proved that wrong.  The survey is evidence, not proof,
so the placement leaves room for the survey to be incomplete.

V = 124 satisfies the rule from the v106 design: a multiple of 4, and absent from
the 24 values the base rows produce (the multiples of 12 up to 252, plus 8 and 20).
It is 4 mod 12, as is strip B's 244, and the family's spacing of 12 matches the
strip height so bands cannot overlap.  x stays 961, so U is still 4 and the
helper's correction is unchanged.

Reserved RAM keeps strips A and B where they are and grows behind them.  The
classifier and the frame routine sit at the end and get longer, which moves the
lookup table v118 appended, so its lui/ori pair is rewritten too.  Nothing else
about v118's table changes.  The executable does not grow: v118's appended sector
still has room.
"""
from __future__ import annotations

import csv
import hashlib
import pickle
import struct
import subprocess
import sys
import zipfile
from collections import Counter
from pathlib import Path
from zipfile import ZipFile, ZipInfo

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))
sys.path.insert(0, str(ROOT / "06_tools" / "python_packages"))

from build_story_sf0b1_return_full import get_pixel, render_glyph  # noqa: E402

BASE_ZIP = ROOT / "03_output/ui_hud_e7_v118_strip_b_fill_patch_only.zip"
BASE_SHA = "7A772F56C8674AA09219EF3460B1EC9EB3A771B23D7F5B8EA4FB42583BDD7D3E"
OUTPUT = ROOT / "03_output/ui_hud_e7_v119_strip_c_patch_only.zip"
PLAN_CSV = ROOT / "05_docs/v119_slot_assignment.csv"
CHARMAP = ROOT / "05_docs/korean_charmap_virtual_v119.csv"
ANALYSIS = ROOT / "01_work/analysis/ui_hud_e7_v119_strip_c"
CACHE = Path(
    r"C:\Users\ADMINI~1\AppData\Local\Temp\claude\E--korean"
    r"\328ae25b-6478-4de1-a913-c780c9b01e72\scratchpad\hangul_bitmaps.pkl"
)

PSX, IMG = "PSX.EXE", "COMM.IMG"
RAM_TO_FILE = 0x8011A800
PRE_REDUCTION_COMMIT = "2239a0e"
SCRIPT_CSV = "05_docs/script_translated_full.csv"
UI_CSVS = (
    "ui_full_v42.csv", "ui_items_equipment_skills_v42_review.csv",
    "ui_skill_guide_reference_v42.csv", "ui_safe_v39.csv", "ui_system_v39.csv",
    "ui_world_name_v39.csv", "ui_battle_choice_v39.csv", "ui_consumables_v25.csv",
    "ui_v41_to_v42_restored_terms_2026-07-18.csv",
)

CELL, PLANES, IPR, COMM_ROWS = 12, 4, 84, 512 // 12
STRIP_COLS, STRIP_ROW_BYTES, STRIP_BYTES = 13, 78, 936
STRIP_SLOTS = STRIP_COLS * PLANES

ROW_A, ROW_B, ROW_C = 40, 63, 53
Y_A, Y_B, Y_C = 480, 500, 380
STRIP_X, U_OFF = 961, 4
RECT_A, RECT_B, RECT_C = 0x801A22E4, 0x801A22EC, 0x801A22F4

SRC_BASE = 0x801A86EC
HELPER_DST, HELPER_N = 0x801FE3C4, 276
GA_DST, GB_DST = 0x801FE4D8, 0x801FE880
CLS_DST = 0x801FEC28
LOOKUP_N = 508
OLD_LOOKUP_DST, OLD_LOOKUP_USED = 0x801FEC90, 456
GA_SRC, GB_SRC = 0x801A8800, 0x801A8BA8

LOADIMAGE = 0x80177E4C
HEAP_HI, HEAP_SEEN_USED = 0x80200000, 0x801FFA60
MEMCPY_LEN_AT, HEAP_BASE_AT = 0x801757CC, 0x80175810
FRAME_CALL, CLS_CALL = 0x801A208C, 0x801A2204
LOOKUP_LUI, LOOKUP_ORI = 0x801A74E4, 0x801A74E8
HEADER_T_SIZE = 0x1C

ZERO, V0, V1, A0, A1, A2, A3, T0, T8, SP, RA = 0, 2, 3, 4, 5, 6, 7, 8, 24, 29, 31
NOP, JR_RA = 0, 0x03E00008


def addiu(rt, rs, i): return (0x09 << 26) | (rs << 21) | (rt << 16) | (i & 0xFFFF)
def sltiu(rt, rs, i): return (0x0B << 26) | (rs << 21) | (rt << 16) | (i & 0xFFFF)
def ori(rt, rs, i): return (0x0D << 26) | (rs << 21) | (rt << 16) | (i & 0xFFFF)
def lui(rt, i): return (0x0F << 26) | (rt << 16) | (i & 0xFFFF)
def lbu(rt, rs, o): return (0x24 << 26) | (rs << 21) | (rt << 16) | (o & 0xFFFF)
def sb(rt, rs, o): return (0x28 << 26) | (rs << 21) | (rt << 16) | (o & 0xFFFF)
def lw(rt, rs, o): return (0x23 << 26) | (rs << 21) | (rt << 16) | (o & 0xFFFF)
def sw(rt, rs, o): return (0x2B << 26) | (rs << 21) | (rt << 16) | (o & 0xFFFF)
def beq(rs, rt, d): return (0x04 << 26) | (rs << 21) | (rt << 16) | (d & 0xFFFF)
def bne(rs, rt, d): return (0x05 << 26) | (rs << 21) | (rt << 16) | (d & 0xFFFF)
def jump(t): return 0x08000000 | ((t & 0x0FFFFFFF) >> 2)
def jal(t): return 0x0C000000 | ((t & 0x0FFFFFFF) >> 2)
def hi(a): return (a >> 16) & 0xFFFF
def lo(a): return a & 0xFFFF


def sha(b: bytes) -> str: return hashlib.sha256(b).hexdigest().upper()
def word(buf, ram): return struct.unpack_from("<I", buf, ram - RAM_TO_FILE)[0]
def put(buf, ram, v): struct.pack_into("<I", buf, ram - RAM_TO_FILE, v)


def clone(i: ZipInfo) -> ZipInfo:
    t = ZipInfo(i.filename, i.date_time)
    for a in ("compress_type", "comment", "extra", "create_system", "create_version",
              "extract_version", "flag_bits", "volume", "internal_attr", "external_attr"):
        setattr(t, a, getattr(i, a))
    return t


# ---------------------------------------------------------------- code

def build_helper() -> list[int]:
    """t0 = glyph row. Add U_OFF to the packet's U when the row is one of ours."""
    return [
        addiu(A3, T0, -ROW_A), sltiu(A3, A3, 1), bne(A3, ZERO, 7),
        addiu(A3, T0, -ROW_B),                                  # delay slot
        sltiu(A3, A3, 1), bne(A3, ZERO, 4),
        addiu(A3, T0, -ROW_C),                                  # delay slot
        sltiu(A3, A3, 1), beq(A3, ZERO, 5), NOP,
        lbu(A3, A1, 0x28), NOP, addiu(A3, A3, U_OFF), sb(A3, A1, 0x28),
        lbu(V0, A2, 0x0E), jump(0x8016B5E0), NOP,
    ]


def build_classifier() -> list[int]:
    """v0 = 1 when the packet's V belongs to any strip. t8 only: t0 carries the row."""
    return [
        lbu(V0, V1, 0x29), NOP,
        addiu(T8, V0, -(Y_A % 256)), beq(T8, ZERO, 6),
        addiu(T8, V0, -(Y_B % 256)), beq(T8, ZERO, 4),
        addiu(T8, V0, -(Y_C % 256)),                            # delay slot
        sltiu(V0, T8, 1), JR_RA, NOP,
        JR_RA, ori(V0, ZERO, 1),                                # delay slot
    ]


def build_frame(strips: list[tuple[int, int]]) -> list[int]:
    out = [addiu(SP, SP, -24), sw(RA, SP, 0x14)]
    for rect, src in strips:
        out += [lui(A0, hi(rect)), ori(A0, A0, lo(rect)), lui(A1, hi(src)),
                jal(LOADIMAGE), ori(A1, A1, lo(src))]           # ori is the delay slot
    out += [lw(RA, SP, 0x14), addiu(SP, SP, 24), JR_RA, NOP]
    return out


# ---------------------------------------------------------------- glyph storage

def strip_bitmap(strip, slot):
    column, plane = divmod(slot, PLANES)
    bit = 1 << plane
    out = []
    for y in range(CELL):
        for x in range(CELL):
            px = column * CELL + x
            byte = strip[y * STRIP_ROW_BYTES + px // 2]
            out.append(1 if (byte & 0x0F if px % 2 == 0 else byte >> 4) & bit else 0)
    return tuple(out)


def write_strip_slot(strip: bytearray, slot: int, bits):
    column, plane = divmod(slot, PLANES)
    for y in range(CELL):
        for x in range(CELL):
            px = column * CELL + x
            off, shift = y * STRIP_ROW_BYTES + px // 2, (0 if px % 2 == 0 else 4)
            nib = (strip[off] >> shift) & 0xF
            nib = nib | (1 << plane) if bits[y * CELL + x] else nib & ~(1 << plane)
            strip[off] = (strip[off] & ~(0xF << shift)) | (nib << shift)


def comm_bitmap(font, index):
    row, rem = divmod(index, IPR)
    column, plane = divmod(rem, PLANES)
    bit = 1 << plane
    return tuple(1 if get_pixel(font, column * CELL + x, row * CELL + y) & bit else 0
                 for y in range(CELL) for x in range(CELL))


def hangul_counts(text: str) -> Counter:
    c = Counter()
    for row in csv.reader(text.splitlines()):
        for cell in row:
            c.update(ch for ch in cell if "\uac00" <= ch <= "\ud7a3")
    return c


def main() -> None:
    if sha(BASE_ZIP.read_bytes()) != BASE_SHA:
        raise SystemExit("base archive is not the v118 build")
    with ZipFile(BASE_ZIP) as a:
        infos = a.infolist()
        members = {i.filename: a.read(i.filename) for i in infos}
    base_exe, font = members[PSX], members[IMG]
    exe = bytearray(base_exe)

    # ---- guards: everything this build assumes about v118, read back first ----
    old_len = word(exe, MEMCPY_LEN_AT) & 0xFFFF
    lut_src_old = SRC_BASE + (OLD_LOOKUP_DST - HELPER_DST)
    guards = {
        FRAME_CALL: jal(0x801FEC50),
        CLS_CALL: jal(CLS_DST),
        LOOKUP_LUI: lui(T0 + 1, hi(OLD_LOOKUP_DST)),
        LOOKUP_ORI: ori(T0 + 1, T0 + 1, lo(OLD_LOOKUP_DST)),
        RECT_A: (Y_A << 16) | STRIP_X,
        RECT_B: (Y_B << 16) | STRIP_X,
        RECT_C: 0, RECT_C + 4: 0,
        SRC_BASE: addiu(A3, T0, -ROW_A),          # the helper's source, still v112's
    }
    for ram, expect in guards.items():
        if word(exe, ram) != expect:
            raise SystemExit(f"guard failed at 0x{ram:08X}: "
                             f"0x{word(exe, ram):08X} != 0x{expect:08X}")
    if old_len != (OLD_LOOKUP_DST - HELPER_DST) + LOOKUP_N * 2:
        raise SystemExit(f"unexpected reserved-block length {old_len}")

    # ---- new reserved-block layout: A and B keep their addresses ----
    classifier = build_classifier()
    frame_at = CLS_DST + len(classifier) * 4
    frame = build_frame([(RECT_A, GA_DST), (RECT_B, GB_DST), (RECT_C, 0)])
    lut_at = frame_at + len(frame) * 4
    gc_dst = lut_at + LOOKUP_N * 2
    heap = gc_dst + STRIP_BYTES
    frame = build_frame([(RECT_A, GA_DST), (RECT_B, GB_DST), (RECT_C, gc_dst)])
    block_n = heap - HELPER_DST
    if heap >= HEAP_SEEN_USED:
        raise SystemExit("the reservation would reach heap the game uses")
    t_addr, t_size = struct.unpack_from("<II", exe, 0x18)
    if SRC_BASE + block_n > t_addr + t_size:
        raise SystemExit("the block's source would run past the executable image")

    # ---- pick the syllables: still missing, most frequent first ----
    lut = list(struct.unpack_from(f"<{LOOKUP_N}H", exe, lut_src_old - RAM_TO_FILE))
    strip_a = exe[GA_SRC - RAM_TO_FILE:][:STRIP_BYTES]
    strip_b = exe[GB_SRC - RAM_TO_FILE:][:STRIP_BYTES]

    def bitmap(index):
        if ROW_A * IPR <= index < ROW_A * IPR + STRIP_SLOTS:
            return strip_bitmap(strip_a, index - ROW_A * IPR)
        if ROW_B * IPR <= index < ROW_B * IPR + STRIP_SLOTS:
            return strip_bitmap(strip_b, index - ROW_B * IPR)
        return comm_bitmap(font, index) if 0 <= index < COMM_ROWS * IPR else None

    reachable = {c - 1 for c in range(0x01, 0x100)}
    for lead in range(0xDD, 0xE9):
        reachable |= {(lead - 0xDD) * 255 + t + 0xDB for t in range(0x01, 0xFF)}
    reachable |= set(lut)
    shapes: dict[tuple[int, ...], str] = pickle.loads(CACHE.read_bytes())
    supply = {shapes[b] for i in sorted(reachable)
              if (b := bitmap(i)) and any(b) and b in shapes}

    now = hangul_counts((ROOT / SCRIPT_CSV).read_text(encoding="utf-8-sig"))
    pre = hangul_counts(subprocess.run(
        ["git", "show", f"{PRE_REDUCTION_COMMIT}:{SCRIPT_CSV}"],
        cwd=ROOT, capture_output=True, check=True).stdout.decode("utf-8-sig"))
    ui = Counter()
    for name in UI_CSVS:
        p = ROOT / "05_docs" / name
        if p.exists():
            ui += hangul_counts(p.read_text(encoding="utf-8-sig"))

    free = STRIP_SLOTS
    committed = sorted((c for c in now if c not in supply),
                       key=lambda c: (-now[c], c))
    rollback = sorted((c for c in pre if c not in supply and c not in now),
                      key=lambda c: (-pre[c], c))
    chosen = (committed + rollback)[:free]
    if len(chosen) < free:
        raise SystemExit(f"only {len(chosen)} syllables need slots; {free} are free")

    # ---- draw them ----
    strip_c = bytearray(STRIP_BYTES)
    records = []
    for slot, char in enumerate(chosen):
        glyph = render_glyph(char)
        bits = tuple(1 if glyph.getpixel((x, y)) else 0
                     for y in range(CELL) for x in range(CELL))
        if not any(bits):
            raise SystemExit(f"{char!r} renders blank at 12x12")
        write_strip_slot(strip_c, slot, bits)
        index = ROW_C * IPR + slot
        lookup_slot = OLD_LOOKUP_USED + slot
        if lookup_slot >= LOOKUP_N:
            raise SystemExit("the lookup table has no free slot left")
        if lut[lookup_slot] != 0x9C - 1:
            raise SystemExit(f"lookup slot {lookup_slot} is not the blank filler")
        lut[lookup_slot] = index
        lead, trail = 0xE9 + lookup_slot // 254, lookup_slot % 254 + 1
        records.append({"char": char, "code": bytes((lead, trail)), "index": index,
                        "slot": lookup_slot, "bits": bits,
                        "now": now.get(char, 0), "pre": pre.get(char, 0)})

    # ---- write the block, then the words that point at it ----
    def emit(dst: int, values: list[int]):
        for k, v in enumerate(values):
            put(exe, SRC_BASE + (dst - HELPER_DST) + k * 4, v)

    emit(HELPER_DST, build_helper() + [NOP] * 4)
    emit(CLS_DST, classifier)
    emit(frame_at, frame)
    struct.pack_into(f"<{LOOKUP_N}H", exe, SRC_BASE + (lut_at - HELPER_DST) - RAM_TO_FILE,
                     *lut)
    at = SRC_BASE + (gc_dst - HELPER_DST) - RAM_TO_FILE
    exe[at:at + STRIP_BYTES] = strip_c

    put(exe, RECT_C, (Y_C << 16) | STRIP_X)
    put(exe, RECT_C + 4, (CELL << 16) | (STRIP_COLS * CELL // 4))
    put(exe, FRAME_CALL, jal(frame_at))
    put(exe, LOOKUP_LUI, lui(T0 + 1, hi(lut_at)))
    put(exe, LOOKUP_ORI, ori(T0 + 1, T0 + 1, lo(lut_at)))
    put(exe, MEMCPY_LEN_AT, addiu(A2, ZERO, block_n))
    put(exe, HEAP_BASE_AT, addiu(A0, A0, (heap - 4) - HEAP_HI))

    # ---- verify against the rebuilt bytes ----
    if word(exe, FRAME_CALL) != jal(frame_at) or word(exe, CLS_CALL) != jal(CLS_DST):
        raise SystemExit("a call no longer reaches its routine")
    l, o = word(exe, LOOKUP_LUI), word(exe, LOOKUP_ORI)
    if ((l & 0xFFFF) << 16 | (o & 0xFFFF)) != lut_at:
        raise SystemExit("the lui/ori pair does not build the table address")
    if (word(exe, MEMCPY_LEN_AT) & 0xFFFF) != block_n:
        raise SystemExit("the memcpy length does not span the block")
    imm = word(exe, HEAP_BASE_AT) & 0xFFFF
    if HEAP_HI + (imm - 0x10000 if imm & 0x8000 else imm) + 4 != heap:
        raise SystemExit("the heap base does not follow the block")
    built_lut = struct.unpack_from(f"<{LOOKUP_N}H", exe,
                                   SRC_BASE + (lut_at - HELPER_DST) - RAM_TO_FILE)
    if list(built_lut[:OLD_LOOKUP_USED]) != \
            list(struct.unpack_from(f"<{OLD_LOOKUP_USED}H", base_exe,
                                    lut_src_old - RAM_TO_FILE)):
        raise SystemExit("an inherited lookup entry changed")
    built_c = exe[at:at + STRIP_BYTES]
    for r in records:
        lead, trail = r["code"]
        slot = (lead - 0xE9) * 254 + trail - 1
        index = built_lut[slot]
        if index != r["index"]:
            raise SystemExit(f"{r['char']}: {r['code'].hex().upper()} resolves to {index}")
        if strip_bitmap(built_c, index - ROW_C * IPR) != r["bits"]:
            raise SystemExit(f"{r['char']}: glyph did not read back from {index}")
    if exe[GA_SRC - RAM_TO_FILE:][:STRIP_BYTES] != strip_a or \
            exe[GB_SRC - RAM_TO_FILE:][:STRIP_BYTES] != strip_b:
        raise SystemExit("strip A or B changed")
    if len(exe) != len(base_exe) or struct.unpack_from("<I", exe, HEADER_T_SIZE)[0] != t_size:
        raise SystemExit("the executable changed size")

    allowed = set(range(SRC_BASE - RAM_TO_FILE, SRC_BASE - RAM_TO_FILE + block_n))
    for a in (RECT_C, RECT_C + 4, FRAME_CALL, LOOKUP_LUI, LOOKUP_ORI,
              MEMCPY_LEN_AT, HEAP_BASE_AT):
        allowed |= set(range(a - RAM_TO_FILE, a - RAM_TO_FILE + 4))
    stray = [i for i in range(len(base_exe)) if base_exe[i] != exe[i] and i not in allowed]
    if stray:
        raise SystemExit(f"{len(stray)} bytes changed outside the declared regions, "
                         f"first at 0x{stray[0]:X}")

    members[PSX] = bytes(exe)
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with ZipFile(OUTPUT, "w") as archive:
        for i in infos:
            archive.writestr(clone(i), members[i.filename])

    with PLAN_CSV.open("w", encoding="utf-8", newline="") as h:
        w = csv.writer(h)
        w.writerow(["char", "code_hex", "lookup_slot", "physical_index",
                    "occurrences_committed", "occurrences_pre_reduction"])
        for r in records:
            w.writerow([r["char"], r["code"].hex().upper(), r["slot"], r["index"],
                        r["now"], r["pre"]])
    with CHARMAP.open("w", encoding="utf-8", newline="") as h:
        w = csv.writer(h)
        w.writerow(["char", "code_hex", "storage", "physical_index", "note"])
        for r in records:
            w.writerow([r["char"], r["code"].hex().upper(), "strip_c", r["index"],
                        "lookup-relative code, encode only"])

    still_now = [c for c in committed if c not in {r["char"] for r in records}]
    still_pre = [c for c in rollback if c not in {r["char"] for r in records}]
    lines = [
        "v119 third resident glyph strip",
        "",
        f"base    {BASE_ZIP.name}",
        f"output  {OUTPUT.name}",
        f"        sha256 {sha(OUTPUT.read_bytes())}",
        f"PSX.EXE {len(exe)} bytes, unchanged; COMM.IMG unchanged",
        "",
        f"strip C   x {STRIP_X}  y {Y_C}  V={Y_C % 256}  row {ROW_C}  "
        f"{STRIP_COLS} columns  indices {ROW_C * IPR}..{ROW_C * IPR + STRIP_SLOTS - 1}",
        f"          tpage untouched; it is inside page 15,1 like strips A and B",
        f"          y {Y_C}..{Y_C + CELL - 1} is free in all 99 surveyed save states",
        "",
        "reserved RAM",
        f"  0x{HELPER_DST:08X} helper        {HELPER_N:>5}   row tests 2 -> 3",
        f"  0x{GA_DST:08X} strip A       {STRIP_BYTES:>5}   address unchanged",
        f"  0x{GB_DST:08X} strip B       {STRIP_BYTES:>5}   address unchanged",
        f"  0x{CLS_DST:08X} classifier    {len(classifier) * 4:>5}   V tests 2 -> 3",
        f"  0x{frame_at:08X} frame routine {len(frame) * 4:>5}   LoadImage 2 -> 3",
        f"  0x{lut_at:08X} lookup table  {LOOKUP_N * 2:>5}   moved from 0x{OLD_LOOKUP_DST:08X}",
        f"  0x{gc_dst:08X} strip C       {STRIP_BYTES:>5}",
        f"  0x{heap:08X} heap starts here ({HEAP_SEEN_USED - heap} bytes clear of heap"
        f" the game uses)",
        f"  one memcpy moves {block_n} bytes, was {old_len}",
        "",
        "words changed",
        f"  0x{RECT_C:08X}  {word(exe, RECT_C):08X}  strip C rect x={STRIP_X} y={Y_C}",
        f"  0x{RECT_C + 4:08X}  {word(exe, RECT_C + 4):08X}  w={STRIP_COLS * CELL // 4} h={CELL}",
        f"  0x{FRAME_CALL:08X}  {word(exe, FRAME_CALL):08X}  frame routine -> 0x{frame_at:08X}",
        f"  0x{LOOKUP_LUI:08X}  {l:08X}  lui t1,0x{hi(lut_at):04X}",
        f"  0x{LOOKUP_ORI:08X}  {o:08X}  ori t1,t1,0x{lo(lut_at):04X}",
        f"  0x{MEMCPY_LEN_AT:08X}  {word(exe, MEMCPY_LEN_AT):08X}  memcpy -> {block_n}",
        f"  0x{HEAP_BASE_AT:08X}  {word(exe, HEAP_BASE_AT):08X}  heap -> 0x{heap:08X}",
        f"  0x{CLS_CALL:08X}  unchanged; the classifier did not move",
        "",
        f"syllables added   {len(records)}",
        f"  needed by the committed corpus     "
        f"{sum(1 for r in records if r['now'])}",
        f"  needed only if abbreviations are undone  "
        f"{sum(1 for r in records if not r['now'])}",
        "",
        "verified",
        "  base archive digest matches v118",
        "  every assumed word was read back before anything was written",
        f"  {OLD_LOOKUP_USED} inherited lookup entries survive unchanged at the new address",
        "  strips A and B are byte-identical and still at their old addresses",
        "  the lui/ori pair builds the table address; the memcpy spans the block;"
        " the heap follows it",
        f"  all {len(records)} codes resolve to their own index and read their own glyph back",
        "  no byte outside the block's source and the seven approved words differs from v118",
        "  the executable did not change size",
        "",
        "NOT verified here, needs a cold boot:",
        "  that strip C reaches VRAM and its glyphs draw",
        "  that strips A and B still draw with the classifier and frame routine rewritten",
        "",
        f"still missing after v119, committed corpus ({len(still_now)}): "
        f"{''.join(still_now)}",
        f"still missing if abbreviations are undone ({len(still_pre)}): "
        f"{''.join(still_pre)}",
        "",
        "characters added, most frequent first:",
    ]
    for r in records:
        lines.append(f"  {r['char']}  {r['code'].hex().upper()}  slot {r['slot']:>3}  "
                     f"index {r['index']:>5}  committed x{r['now']}  pre x{r['pre']}")
    lines += ["", f"plan {PLAN_CSV.relative_to(ROOT)}",
              f"encoder map {CHARMAP.relative_to(ROOT)}",
              "", "rebuild with arc1_v104.xml, then run verify_iso_layout.py"]
    ANALYSIS.mkdir(parents=True, exist_ok=True)
    (ANALYSIS / "build_report.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines[:46]))
    print(f"\nreport -> {ANALYSIS / 'build_report.txt'}")


if __name__ == "__main__":
    main()
