"""v162: move the completed-glyph cache out of the shared low-page sprite cells.

The six v161 runtime states prove two independent defects:

* the byte writer clears both nibbles twice, so the odd pixel of each pair erases
  the even pixel that was just written;
* cache cell row 8/column 1 is sampled by battle sprites and the load-screen cursor.

Keep v161's bounded text, lookup, decoder, RAM budget and 20-slot policy.  Move only
the 20 physical cache planes to five cells at the start of the previously proven
strip-A position (VRAM x=961, y=480), repair the nibble writer, and reconnect the
already resident v116 stateless high-page renderer.  No old archive is overwritten.
"""
from __future__ import annotations

import csv
import hashlib
import struct
import sys
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))

from build_ui_hud_e7_v73_dual_tpage_renderer import (  # noqa: E402
    Assembler, i_type, j, jal, r_type,
)


BASE_ZIP = ROOT / "03_output/arc1_v161_bounded_exe_text_B2EA377E.zip"
BASE_SHA = "B2EA377E1E43C1954F42A63F375B8D7B5997A6B736988C315B4C06C76A5F44E3"
V151_ZIP = ROOT / "03_output/arc1_v151_free_the_sprite_cell_A4358FEE.zip"
V151_SHA = "A4358FEE5FEA4964C9DD376B630894EB5EC133EFEEDD9E5E85BBC5FDD8CA1A46"
PLAN = ROOT / "01_work/analysis/dynamic_cache_v153_widthsafe"
OLD_CACHE_SLOTS = PLAN / "cache_slots.csv"
OUT_DIR = ROOT / "03_output"
OUT_STEM = "arc1_v162_strip_a_dynamic_cache"
ANALYSIS = ROOT / "01_work/analysis/arc1_v162_strip_a_dynamic_cache"
REPORT = ANALYSIS / "build_report.txt"
SLOTS_REPORT = ANALYSIS / "cache_slots.csv"
DISASSEMBLY = ANALYSIS / "mips_disassembly.txt"

PSX = "PSX.EXE"
RAM_TO_FILE = 0x8011A800
SOURCE_BASE, RESIDENT_BASE, COPY_N = 0x801A86EC, 0x801FE3C4, 5356
HEAP_BASE = RESIDENT_BASE + COPY_N

ROW_DICTIONARY_N = (PLAN / "row_dictionary.bin").stat().st_size
GLYPH_ROWS_N = (PLAN / "dynamic_glyph_rows.bin").stat().st_size
CACHE_N, PLANES, IPR, CELL = 20, 4, 84, 12
CACHE_INDEX_RAM = RESIDENT_BASE + ROW_DICTIONARY_N + GLYPH_ROWS_N
OWNERS = CACHE_INDEX_RAM + CACHE_N * 2
ACTIVE = (OWNERS + CACHE_N * 2 + 3) & ~3
NEXT_SLOT = ACTIVE + 4
RECT = NEXT_SLOT + 4
SHADOW = RECT + 8
SHADOW_N = CACHE_N // PLANES * CELL * (CELL // 2)
DECODER = (SHADOW + SHADOW_N + 3) & ~3
DECODER_N = 320
FRAME = (DECODER + DECODER_N + 3) & ~3
FRAME_N = 580
HELPER = FRAME + FRAME_N
HELPER_N = 44
CLASSIFIER = HELPER + HELPER_N
CLASSIFIER_N = 24

GLYPH_PACKET_HOOK = 0x8016B5D8
RENDER_HOOK = 0x8016B764
STATELESS_DRIVER = 0x801A20B0
CLASSIFIER_CALL = 0x801A2204
FRAME_X_ADD = 0x801FF288
PIXEL_LOOP = 0x801FF328
TPAGE_WORD = 0x801A2194

CACHE_ROW = 40
CACHE_X, CACHE_Y = 961, 480
CACHE_U, CACHE_V = 4, 224
CACHE_INDICES = tuple(CACHE_ROW * IPR + slot for slot in range(CACHE_N))

# MIPS registers.
ZERO, V0, V1 = 0, 2, 3
A0, A1, A2, A3 = 4, 5, 6, 7
T0, T3, T5, T6, T7, T8, T9 = 8, 11, 13, 14, 15, 24, 25
SP, RA = 29, 31
NOP = 0
JR_RA = r_type(RA, ZERO, ZERO, 0, 0x08)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def file_at(address: int) -> int:
    return address - RAM_TO_FILE


def source_at(runtime_address: int) -> int:
    """File offset of one byte copied from SOURCE_BASE to RESIDENT_BASE at boot."""
    return file_at(SOURCE_BASE + runtime_address - RESIDENT_BASE)


def word(buf: bytes | bytearray, address: int) -> int:
    return struct.unpack_from("<I", buf, file_at(address))[0]


def put_word(buf: bytearray, address: int, value: int) -> None:
    struct.pack_into("<I", buf, file_at(address), value)


def resident_word(buf: bytes | bytearray, runtime_address: int) -> int:
    return struct.unpack_from("<I", buf, source_at(runtime_address))[0]


def put_resident_word(buf: bytearray, runtime_address: int, value: int) -> None:
    struct.pack_into("<I", buf, source_at(runtime_address), value)


def clone(info: ZipInfo) -> ZipInfo:
    out = ZipInfo(info.filename, info.date_time)
    for name in (
        "compress_type", "comment", "extra", "create_system", "create_version",
        "extract_version", "flag_bits", "volume", "internal_attr", "external_attr",
    ):
        setattr(out, name, getattr(info, name))
    return out


def build_helper() -> bytes:
    """Add U=4 only to row-40 packets, then execute the displaced stock load."""
    asm = Assembler(HELPER)
    asm.emit(i_type(0x09, T0, A3, -CACHE_ROW))
    asm.emit(i_type(0x0B, A3, A3, 1))
    asm.branch(0x04, A3, ZERO, "out")
    asm.emit(NOP)
    asm.emit(i_type(0x24, A1, A3, 0x28))
    asm.emit(NOP)
    asm.emit(i_type(0x09, A3, A3, CACHE_U))
    asm.emit(i_type(0x28, A1, A3, 0x28))
    asm.label("out")
    asm.emit(i_type(0x24, A2, V0, 0x0E))
    asm.emit(j(0x8016B5E0))
    asm.emit(NOP)
    out = asm.finish()
    if len(out) != HELPER_N:
        raise SystemExit(f"helper size differs: {len(out)}")
    return out


def build_classifier() -> bytes:
    """Return v0=1 only for strip A's wrapped V value."""
    asm = Assembler(CLASSIFIER)
    asm.emit(i_type(0x24, V1, V0, 0x29))
    asm.emit(NOP)
    asm.emit(i_type(0x09, V0, T8, -CACHE_V))
    asm.emit(i_type(0x0B, T8, V0, 1))
    asm.emit(JR_RA)
    asm.emit(NOP)
    out = asm.finish()
    if len(out) != CLASSIFIER_N:
        raise SystemExit(f"classifier size differs: {len(out)}")
    return out


def old_pixel_loop() -> tuple[int, ...]:
    """The v161 sequence that erases every even pixel on the second nibble visit."""
    return (
        i_type(0x24, T7, T9, 0),
        NOP,
        r_type(T9, T8, T9, 0, 0x24),
        r_type(T3, T6, A3, 0, 0x24),
        i_type(0x04, A3, ZERO, 7),
        i_type(0x0C, T5, A3, 1),
        i_type(0x25, SP, A2, 0x14),
        NOP,
        i_type(0x04, A3, ZERO, 2),
        NOP,
        r_type(ZERO, A2, A2, 4, 0x00),
        r_type(T9, A2, T9, 0, 0x25),
        i_type(0x28, T7, T9, 0),
    )


def fixed_pixel_loop() -> tuple[int, ...]:
    """Clear the two nibbles once on even x; odd x preserves the even result."""
    return (
        i_type(0x24, T7, T9, 0),
        i_type(0x0C, T5, A3, 1),
        i_type(0x05, A3, ZERO, 2),
        r_type(T3, T6, A3, 0, 0x24),
        r_type(T9, T8, T9, 0, 0x24),
        i_type(0x04, A3, ZERO, 6),
        i_type(0x0C, T5, A3, 1),
        i_type(0x25, SP, A2, 0x14),
        i_type(0x04, A3, ZERO, 2),
        NOP,
        r_type(ZERO, A2, A2, 4, 0x00),
        r_type(T9, A2, T9, 0, 0x25),
        i_type(0x28, T7, T9, 0),
    )


def main() -> None:
    if digest(BASE_ZIP.read_bytes()) != BASE_SHA:
        raise SystemExit("base archive is not the frozen v161 build")
    if digest(V151_ZIP.read_bytes()) != V151_SHA:
        raise SystemExit("v151 renderer reference archive differs")

    with ZipFile(BASE_ZIP) as archive:
        infos = archive.infolist()
        members = {info.filename: archive.read(info.filename) for info in infos}
    base_members = dict(members)
    with ZipFile(V151_ZIP) as archive:
        v151_exe = archive.read(PSX)

    exe = bytearray(members[PSX])
    before = bytes(exe)
    if len(exe) != 587776 or struct.unpack_from("<II", exe, 0x18) != (0x8011B000, 0x8F000):
        raise SystemExit("v161 PSX.EXE layout differs")
    if HEAP_BASE != 0x801FF8B0 or CLASSIFIER + CLASSIFIER_N > HEAP_BASE:
        raise SystemExit("new resident routines cross the frozen heap boundary")

    # The old cache plan and resident layout are evidence, not assumptions.
    with OLD_CACHE_SLOTS.open(encoding="utf-8-sig", newline="") as handle:
        old_rows = list(csv.DictReader(handle))
    old_indices = tuple(int(row["physical_index"]) for row in old_rows)
    if len(old_indices) != CACHE_N:
        raise SystemExit("old cache plan no longer has 20 slots")
    old_table = struct.unpack_from(f"<{CACHE_N}H", exe, source_at(CACHE_INDEX_RAM))
    if old_table != old_indices:
        raise SystemExit("v161 resident cache-index table differs from its plan")

    # Guard every code surface reused from the accepted v116-v151 path.
    guards = (
        (GLYPH_PACKET_HOOK, 0x90C2000E, "stock glyph-packet entry"),
        (RENDER_HOOK, 0x27BDFFD0, "stock renderer entry"),
        (RENDER_HOOK + 4, 0xAFBF002C, "stock renderer second instruction"),
        (STATELESS_DRIVER, 0x27BDFFB0, "stateless high-page driver"),
        (TPAGE_WORD, 0x34E7001F, "high-page tpage 0x1F"),
        (CLASSIFIER_CALL, 0x0C07F908, "v151 classifier call before relocation"),
        (FRAME_X_ADD, i_type(0x09, T7, T7, 320), "v161 low-page cache x base"),
    )
    for address, expected, label in guards:
        got = resident_word(exe, address) if FRAME <= address < FRAME + FRAME_N else word(exe, address)
        if got != expected:
            raise SystemExit(
                f"guard failed at 0x{address:08X}: 0x{got:08X} != 0x{expected:08X} ({label})"
            )
    driver_lo, driver_hi = file_at(STATELESS_DRIVER), file_at(0x801A22A0)
    if exe[driver_lo:driver_hi] != v151_exe[driver_lo:driver_hi]:
        raise SystemExit("resident stateless renderer differs from v151")

    old_loop = tuple(resident_word(exe, PIXEL_LOOP + i * 4) for i in range(13))
    if old_loop != old_pixel_loop():
        raise SystemExit("v161 pixel loop differs from the diagnosed sequence")
    helper_blob, classifier_blob = build_helper(), build_classifier()
    append_at = source_at(HELPER)
    append_end = source_at(CLASSIFIER) + len(classifier_blob)
    if any(exe[append_at:append_end]):
        raise SystemExit("new resident helper/classifier landing area is not zero")

    # New cache locations: five cells / twenty planes in the small strip-A prefix.
    struct.pack_into(f"<{CACHE_N}H", exe, source_at(CACHE_INDEX_RAM), *CACHE_INDICES)
    exe[source_at(SHADOW):source_at(SHADOW) + SHADOW_N] = bytes(SHADOW_N)
    put_resident_word(exe, FRAME_X_ADD, i_type(0x09, T7, T7, CACHE_X))
    for i, value in enumerate(fixed_pixel_loop()):
        put_resident_word(exe, PIXEL_LOOP + i * 4, value)

    # Reconnect only the already proven high-page path needed by row 40.
    exe[source_at(HELPER):source_at(HELPER) + len(helper_blob)] = helper_blob
    exe[source_at(CLASSIFIER):source_at(CLASSIFIER) + len(classifier_blob)] = classifier_blob
    put_word(exe, GLYPH_PACKET_HOOK, j(HELPER))
    put_word(exe, RENDER_HOOK, j(STATELESS_DRIVER))
    put_word(exe, RENDER_HOOK + 4, NOP)
    put_word(exe, CLASSIFIER_CALL, jal(CLASSIFIER))

    # Readback and geometry guards.
    if struct.unpack_from(f"<{CACHE_N}H", exe, source_at(CACHE_INDEX_RAM)) != CACHE_INDICES:
        raise SystemExit("high-page cache table readback differs")
    if any(exe[source_at(SHADOW):source_at(SHADOW) + SHADOW_N]):
        raise SystemExit("dedicated cache shadow is not blank")
    if tuple(resident_word(exe, PIXEL_LOOP + i * 4) for i in range(13)) != fixed_pixel_loop():
        raise SystemExit("fixed pixel loop readback differs")
    if word(exe, GLYPH_PACKET_HOOK) != j(HELPER) or \
            word(exe, RENDER_HOOK) != j(STATELESS_DRIVER) or \
            word(exe, RENDER_HOOK + 4) != NOP or \
            word(exe, CLASSIFIER_CALL) != jal(CLASSIFIER):
        raise SystemExit("renderer hook readback differs")
    if CACHE_X // 64 != 15 or (CACHE_X % 64) * 4 != CACHE_U or \
            CACHE_Y != 256 + CACHE_V or CACHE_ROW * CELL != CACHE_Y:
        raise SystemExit("strip-A x/U/y/V/tpage geometry disagrees")
    if CACHE_X + (CACHE_N // PLANES) * 3 > 1024 or CACHE_Y + CELL > 512:
        raise SystemExit("dynamic cache leaves VRAM")

    members[PSX] = bytes(exe)
    ANALYSIS.mkdir(parents=True, exist_ok=True)
    tmp = OUT_DIR / f"{OUT_STEM}_building.zip"
    if tmp.exists():
        raise SystemExit(f"refusing to reuse temporary output: {tmp.name}")
    with ZipFile(tmp, "w", ZIP_DEFLATED) as archive:
        for info in infos:
            archive.writestr(clone(info), members[info.filename])
    with ZipFile(tmp) as archive:
        if [info.filename for info in archive.infolist()] != [info.filename for info in infos]:
            raise SystemExit("archive member order changed")
        for name, expected in members.items():
            if archive.read(name) != expected:
                raise SystemExit(f"archive readback differs: {name}")
    stamp = digest(tmp.read_bytes())
    output = OUT_DIR / f"{OUT_STEM}_{stamp[:8]}.zip"
    if output.exists():
        raise SystemExit(f"refusing to overwrite existing output: {output.name}")
    tmp.replace(output)

    changed = {i for i, (left, right) in enumerate(zip(before, exe)) if left != right}
    allowed = set()
    for address, size, resident in (
        (CACHE_INDEX_RAM, CACHE_N * 2, True),
        (SHADOW, SHADOW_N, True),
        (FRAME_X_ADD, 4, True),
        (PIXEL_LOOP, 13 * 4, True),
        (HELPER, HELPER_N, True),
        (CLASSIFIER, CLASSIFIER_N, True),
        (GLYPH_PACKET_HOOK, 4, False),
        (RENDER_HOOK, 8, False),
        (CLASSIFIER_CALL, 4, False),
    ):
        start = source_at(address) if resident else file_at(address)
        allowed.update(range(start, start + size))
    if not changed or not changed <= allowed:
        raise SystemExit("PSX.EXE changed outside the approved v162 regions")
    if any(name != PSX and members[name] != base_members[name] for name in members):
        raise SystemExit("a non-PSX member changed")

    with SLOTS_REPORT.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(("cache_slot", "physical_index", "row", "column", "plane",
                         "vram_x", "vram_y", "u", "v"))
        for slot, index in enumerate(CACHE_INDICES):
            column, plane = divmod(slot, PLANES)
            writer.writerow((slot, index, CACHE_ROW, column, plane,
                             CACHE_X + column * 3, CACHE_Y,
                             CACHE_U + column * CELL, CACHE_V))

    disassembly = [
        f"helper_runtime=0x{HELPER:08X} size={len(helper_blob)}",
        f"classifier_runtime=0x{CLASSIFIER:08X} size={len(classifier_blob)}",
        "fixed_pixel_loop_words=",
        *(f"  0x{PIXEL_LOOP+i*4:08X}  {value:08X}" for i, value in enumerate(fixed_pixel_loop())),
    ]
    DISASSEMBLY.write_text("\n".join(disassembly) + "\n", encoding="utf-8")
    lines = [
        "v162 strip-A on-demand completed-glyph cache",
        "",
        f"base={BASE_ZIP.name}",
        f"output={output.name}",
        f"sha256={stamp}",
        f"PSX.EXE_bytes={len(exe)}",
        f"changed_EXE_bytes={len(changed)}",
        "all_non_PSX_members=byte_identical_to_v161",
        "",
        "runtime evidence from HASH-36A4D7BFEE911E0C slots 1..6:",
        "  cache RAM shadow and VRAM matched 72/72 bytes in every physical cell",
        "  owners were slot0=택 and slot1=잎/랜 when visible",
        "  rendered planes omitted every even pixel because each byte was cleared twice",
        "  the same low-page physical cell coincided with battle-sprite and cursor damage",
        "",
        f"cache_slots={CACHE_N}",
        f"cache_cells={CACHE_N // PLANES}",
        f"cache_indices={CACHE_INDICES[0]}..{CACHE_INDICES[-1]}",
        f"cache_vram=x{CACHE_X}..{CACHE_X + (CACHE_N // PLANES) * 3 - 1},y{CACHE_Y}..{CACHE_Y + CELL - 1}",
        f"cache_U={CACHE_U}..{CACHE_U + (CACHE_N // PLANES) * CELL - 1}",
        f"cache_V={CACHE_V}",
        "cache_upload=on demand only; no fixed A/B/C/D strip upload",
        "",
        "reused runtime-proven path:",
        "  v116 stateless two-pass driver at 0x801A20B0",
        "  tpage 0x1F and row-40 U+4 geometry",
        "  v161 decoder, lookup, bounded text, RAM reservation and heap boundary unchanged",
        "",
        "static_verification=PENDING separate verifier",
        "runtime_verification=PENDING user cold boot",
        "rollback=v161",
    ]
    REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
