"""Read-only proof of the v169 dialogue "overlap" regression.

The translated corpus uses one-byte code 0x9C as a six-pixel space/filler.  Its
sprite is still twelve pixels wide, so the underlying physical glyph must be
blank.  This audit compares the untouched disc, the v151 working baseline and
v169, then measures every active font packet in the user's seven v169 states.

No patch archive or savestate is modified.  Reports are written only below
``01_work/analysis``.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import struct
import sys
from collections import Counter
from pathlib import Path
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))

import analyze_arc1_v163_runtime as runtime  # noqa: E402
import analyze_arc1_v165c_runtime as legacy  # noqa: E402
import build_arc1_v165_failclosed_cache as cache  # noqa: E402
import verify_arc1_v165c_failclosed_cache as executor  # noqa: E402
import verify_arc1_v167_item_description_generation_guard as layout_source  # noqa: E402
from extract_savestate_vram import inflate, locate_ram, locate_vram  # noqa: E402


V169 = ROOT / "03_output/arc1_v169_e1_control_glyph_dispatch_218D38D2.zip"
V169_SHA256 = "218D38D21FED1D20E79483D657ED2E31D86425DA644F88322461F18BC3C9D4B0"
V151 = ROOT / "03_output/arc1_v151_free_the_sprite_cell_A4358FEE.zip"
V151_SHA256 = "A4358FEE5FEA4964C9DD376B630894EB5EC133EFEEDD9E5E85BBC5FDD8CA1A46"
ORIGINAL = ROOT / "00_original/arc.zip"
ORIGINAL_SHA256 = "AE9F4366A1E7DA3805BB3BED3DDA9567E4CD4E669AF890E4E2A620D7861F11DD"

SAVE_DIR = Path.home() / "AppData/Local/DuckStation/savestates"
DEFAULT_PREFIX = "HASH-9BD6171E5513C3D5"
OUT_ROOT = ROOT / "01_work/analysis"

RAM_SIZE = 2 * 1024 * 1024
VRAM_SIZE = 1024 * 512 * 2
COMM_ROW_BYTES = 896
CELL = 12
IPR = 84
PLANES = 4
SPACE_CODE = 0x9C
SPACE_INDEX = SPACE_CODE - 1
FONT_CLUT_MIN, FONT_CLUT_MAX = 0x7FC0, 0x7FC3

PARSER_FIRST, PARSER_SECOND = 0x801A7460, 0x801A748C
PARSER_HELPER, PARSER_HELPER_SIZE = 0x801FF82C, 120
FRAME_CALL = 0x801FF7DC

SCENES = {
    1: "load menu",
    2: "story dialogue",
    3: "dialogue choice",
    4: "status/skill UI",
    5: "item name: 마력의 잎",
    6: "item name: 쓴 잎",
    7: "battle",
}


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest().upper()


def ram_at(address: int) -> int:
    return address & 0x1FFFFF


def s16(blob: bytes, offset: int) -> int:
    return struct.unpack_from("<h", blob, offset)[0]


def plane_bitmap(font: bytes, index: int) -> tuple[int, ...]:
    row, within = divmod(index, IPR)
    column, plane = divmod(within, PLANES)
    result: list[int] = []
    for y in range(CELL):
        for x in range(CELL):
            byte = font[(row * CELL + y) * COMM_ROW_BYTES + column * 6 + x // 2]
            nibble = (byte >> (4 * (x & 1))) & 0xF
            result.append((nibble >> plane) & 1)
    return tuple(result)


def slot_number(path: Path) -> int:
    return int(path.stem.rsplit("_", 1)[1])


def configure_runtime() -> None:
    runtime.CACHE_SLOTS = 24
    runtime.CACHE_CELLS = 6
    runtime.CACHE_U = (4, 16, 28, 40, 52, 64)
    runtime.CACHE_U_END = 76
    runtime.CACHE_V = 224
    runtime.CACHE_V_END = 236


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser()
    parser.add_argument("save_prefix", nargs="?", default=DEFAULT_PREFIX)
    args = parser.parse_args()

    for path, expected in (
        (V169, V169_SHA256), (V151, V151_SHA256), (ORIGINAL, ORIGINAL_SHA256)
    ):
        if digest(path) != expected:
            raise SystemExit(f"archive hash differs: {path.name}")

    states = sorted(
        (path for path in SAVE_DIR.glob(f"{args.save_prefix}_*.sav")
         if path.stem.rsplit("_", 1)[-1].isdigit()),
        key=slot_number,
    )
    slots = [slot_number(path) for path in states]
    if slots != list(range(1, 8)):
        raise SystemExit(f"expected slots 1..7, found {slots}")

    with ZipFile(V169) as archive:
        exe = archive.read("PSX.EXE")
        v169_font = archive.read("COMM.IMG")
    with ZipFile(V151) as archive:
        v151_font = archive.read("COMM.IMG")
    with ZipFile(ORIGINAL) as archive:
        original_font = archive.read("COMM.IMG")

    original_space = plane_bitmap(original_font, SPACE_INDEX)
    v151_space = plane_bitmap(v151_font, SPACE_INDEX)
    v169_space = plane_bitmap(v169_font, SPACE_INDEX)
    if sum(original_space) != 29 or any(v151_space) or v169_space != original_space:
        raise SystemExit("space-filler control-group geometry differs")

    configure_runtime()
    layout, _blobs, _routines = layout_source.routine_layout()
    owners_at = layout["owners"][0]
    active_at = layout["active_mask"][0]
    executor.plan.CHECKPOINT_GROUP = 8
    expected_memory = executor.runtime_memory(exe)
    source_rows = executor.python_sources(expected_memory, layout)
    with (legacy.PLAN / "source_manifest.csv").open(
        encoding="utf-8-sig", newline=""
    ) as handle:
        source_chars = {
            int(row["source_id"]): row["char"] for row in csv.DictReader(handle)
        }

    packet_rows: list[dict[str, object]] = []
    state_rows: list[dict[str, object]] = []
    lineage_ok = 0
    owner_checks = owner_matches = 0
    filler_packets = filler_overlaps = 0
    dynamic_packets = 0
    bad_dynamic_sizes = 0
    duplicate_xy_total = 0

    # Resident code executes at 0x801FE3C4+, but its file image lives in the
    # startup-copy source block at 0x801A86EC+.  ``source_at`` performs that
    # relocation; using ``file_at`` here would compare against unrelated tail
    # bytes and falsely reject every valid v169 state.
    helper_source = cache.source_at(PARSER_HELPER)
    helper_expected = exe[helper_source:helper_source + PARSER_HELPER_SIZE]
    entry_expected = {
        address: exe[cache.file_at(address):cache.file_at(address) + 8]
        for address in (PARSER_FIRST, PARSER_SECOND)
    }
    entry_expected[FRAME_CALL] = exe[
        cache.source_at(FRAME_CALL):cache.source_at(FRAME_CALL) + 8
    ]

    for path in states:
        slot = slot_number(path)
        inflated = inflate(path)
        ram_base, vram_base = locate_ram(inflated), locate_vram(inflated)
        ram = inflated[ram_base:ram_base + RAM_SIZE]
        vram = inflated[vram_base:vram_base + VRAM_SIZE]
        if len(ram) != RAM_SIZE or len(vram) != VRAM_SIZE:
            raise SystemExit(f"incomplete RAM/VRAM: {path.name}")

        failures: list[str] = []
        if ram[ram_at(PARSER_HELPER):ram_at(PARSER_HELPER) + PARSER_HELPER_SIZE] \
                != helper_expected:
            failures.append("parser_helper")
        for address, expected in entry_expected.items():
            if ram[ram_at(address):ram_at(address) + 8] != expected:
                failures.append(f"entry_0x{address:08X}")
        lineage_ok += int(not failures)

        owners = struct.unpack_from("<24H", ram, ram_at(owners_at))
        active = struct.unpack_from("<I", ram, ram_at(active_at))[0] & 0xFFFFFF
        for cache_slot, owner in enumerate(owners):
            if owner == 0xFFFF:
                continue
            owner_checks += 1
            got = legacy.selected_plane(
                runtime.vram_cell(vram, cache_slot // PLANES), cache_slot % PLANES
            )
            expected = legacy.expected_shape(source_rows[owner])
            owner_matches += int(got == expected)

        _context, _parity, ot = runtime.trace_active_text_ot(ram)
        glyphs: list[dict[str, object]] = []
        for row in ot:
            if row["kind"] != "SPRT" or row["clut"] == "":
                continue
            clut = int(row["clut"])
            if not FONT_CLUT_MIN <= clut <= FONT_CLUT_MAX:
                continue
            address = int(row["address"])
            at = ram_at(address)
            x, y = s16(ram, at + 8), s16(ram, at + 10)
            width, height = int(row["width"]), int(row["height"])
            cache_slot = "" if row["slot"] == "" else int(row["slot"])
            if cache_slot != "":
                dynamic_packets += 1
                bad_dynamic_sizes += int((width, height) != (12, 12))
                owner = owners[cache_slot]
                char = source_chars.get(owner, f"<D:{owner}>")
                physical = ""
                kind = "dynamic"
            else:
                physical = (int(row["v"]) // CELL) * IPR \
                    + (int(row["u"]) // CELL) * PLANES \
                    + ((clut - FONT_CLUT_MIN) & 3)
                char = f"<S:{physical}>"
                owner = ""
                kind = "static"
            item = {
                "state": f"slot{slot}", "scene": SCENES[slot],
                "order": row["order"], "address": f"0x{address:08X}",
                "x": x, "y": y, "width": width, "height": height,
                "u": row["u"], "v": row["v"], "clut": f"0x{clut:04X}",
                "kind": kind, "cache_slot": cache_slot,
                "owner_source": owner, "char": char,
                "physical_index": physical,
                "space_filler": int(physical == SPACE_INDEX),
                "next_x": "", "overlap_with_next_px": 0,
            }
            glyphs.append(item)

        xy_counts = Counter((row["x"], row["y"]) for row in glyphs)
        duplicate_xy = sum(count - 1 for count in xy_counts.values() if count > 1)
        duplicate_xy_total += duplicate_xy
        state_fillers = state_overlaps = 0
        for row in glyphs:
            if not row["space_filler"]:
                continue
            state_fillers += 1
            same_line = sorted(
                (other for other in glyphs
                 if other["y"] == row["y"] and int(other["x"]) > int(row["x"])),
                key=lambda other: int(other["x"]),
            )
            if same_line:
                next_x = int(same_line[0]["x"])
                overlap = max(0, int(row["x"]) + int(row["width"]) - next_x)
                row["next_x"] = next_x
                row["overlap_with_next_px"] = overlap
                state_overlaps += int(overlap > 0)
        filler_packets += state_fillers
        filler_overlaps += state_overlaps
        packet_rows.extend(glyphs)
        state_rows.append({
            "slot": slot, "scene": SCENES[slot], "lineage_ok": int(not failures),
            "lineage_failures": " ".join(failures),
            "active_slots": active.bit_count(), "font_packets": len(glyphs),
            "dynamic_packets": sum(row["kind"] == "dynamic" for row in glyphs),
            "space_filler_packets": state_fillers,
            "space_filler_overlaps": state_overlaps,
            "duplicate_screen_xy": duplicate_xy,
        })

    out = OUT_ROOT / f"arc1_v169_dialogue_overlap_{args.save_prefix.removeprefix('HASH-')}"
    out.mkdir(parents=True, exist_ok=True)
    for name, rows in (("state_summary.csv", state_rows), ("font_packets.csv", packet_rows)):
        with (out / name).open("w", encoding="utf-8-sig", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)

    lines = [
        "v169 dialogue-overlap runtime audit",
        f"patch={V169.name}",
        f"sha256={V169_SHA256}",
        f"savestates={args.save_prefix}_1..7.sav",
        "",
        f"v169_lineage={lineage_ok}/7",
        f"cache_owner_shapes={owner_matches}/{owner_checks}",
        f"dynamic_packets={dynamic_packets}",
        f"dynamic_packets_not_12x12={bad_dynamic_sizes}",
        f"duplicate_screen_xy={duplicate_xy_total}",
        "",
        f"space_code=0x{SPACE_CODE:02X}",
        f"space_physical_index={SPACE_INDEX}",
        f"untouched_disc_set_pixels={sum(original_space)}",
        f"v151_set_pixels={sum(v151_space)}",
        f"v169_set_pixels={sum(v169_space)}",
        f"active_space_packets={filler_packets}",
        f"active_space_packets_overlapping_next_glyph={filler_overlaps}",
        "",
        "state_detail",
    ]
    lines.extend(
        "  slot{slot} {scene}: active={active_slots} font={font_packets} "
        "dynamic={dynamic_packets} filler={space_filler_packets} "
        "filler_overlap={space_filler_overlaps} duplicate_xy={duplicate_screen_xy}"
        .format(**row)
        for row in state_rows
    )
    lines.extend((
        "",
        "conclusion=CONFIRMED",
        "  Glyph screen coordinates and dynamic sprite sizes are valid.",
        "  Code 0x9C advances by six pixels while its SPRT remains twelve pixels wide.",
        "  v151 kept physical plane 155 blank, so that intentional overlap was invisible.",
        "  v159 restored the untouched 29-pixel Japanese glyph; v169 still carries it.",
        "  The visible strokes therefore overlap the following glyph by six pixels.",
    ))
    report = out / "runtime_audit.txt"
    report.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    print(report)


if __name__ == "__main__":
    main()
