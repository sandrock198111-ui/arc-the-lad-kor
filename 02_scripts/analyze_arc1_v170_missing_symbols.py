"""Audit the remaining v170 missing-symbol and battle-UI regressions.

This is read-only.  It follows the active ordering table in the user's nine v170
savestates, records every sprite texture request, and compares the exact requested
pixels in live VRAM with v170, the working v151 control and the untouched disc.

Reports are written below ``01_work/analysis``; no archive or savestate is changed.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import pickle
import struct
import sys
from collections import Counter
from pathlib import Path
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))

import analyze_arc1_v163_runtime as runtime  # noqa: E402
import build_arc1_v165_failclosed_cache as cache  # noqa: E402
import verify_arc1_v167_item_description_generation_guard as layout_source  # noqa: E402
from audit_dynamic_cache_requirements import glyph_index  # noqa: E402
from extract_savestate_vram import inflate, locate_ram, locate_vram  # noqa: E402
from plan_bulk_insertion import CACHE as SHAPE_CACHE  # noqa: E402


V170 = ROOT / "03_output/arc1_v170_restore_blank_space_filler_F8A67A67.zip"
V170_SHA256 = "F8A67A674A8E17F18C50DB7408FB3DCFD494FD9760C665D429CC11D36D9EF81B"
V151 = ROOT / "03_output/arc1_v151_free_the_sprite_cell_A4358FEE.zip"
V151_SHA256 = "A4358FEE5FEA4964C9DD376B630894EB5EC133EFEEDD9E5E85BBC5FDD8CA1A46"
ORIGINAL = ROOT / "00_original/arc.zip"
ORIGINAL_SHA256 = "AE9F4366A1E7DA3805BB3BED3DDA9567E4CD4E669AF890E4E2A620D7861F11DD"

SAVE_DIR = Path.home() / "AppData/Local/DuckStation/savestates"
DEFAULT_PREFIX = "HASH-9BD6171E5513C3D5"
OUT_ROOT = ROOT / "01_work/analysis"

RAM_SIZE = 2 * 1024 * 1024
VRAM_SIZE = 1024 * 512 * 2
VRAM_W = 1024
COMM_ROW_BYTES = 896
COMM_TEXEL_W = COMM_ROW_BYTES * 2
COMM_TPAGE_X = 5
CELL = 12
IPR = 84
PLANES = 4
FONT_CLUT_MIN, FONT_CLUT_MAX = 0x7FC0, 0x7FCF

PARSER_FIRST, PARSER_SECOND = 0x801A7460, 0x801A748C
PARSER_HELPER, PARSER_HELPER_SIZE = 0x801FF82C, 120
FRAME_CALL = 0x801FF7DC

SCENES = {
    1: "load menu: missing L",
    2: "dialogue: missing colon",
    3: "dialogue: missing question mark",
    4: "battle dialogue",
    5: "battle help icons A",
    6: "battle help icons B",
    7: "damage overlay A",
    8: "damage overlay B",
    9: "battle configuration text",
}

# User-observed symbols whose translated codes do not use the ordinary ASCII row.
KNOWN_SYMBOL_CODES = {
    ":": bytes.fromhex("DF 80"),
    "?": bytes.fromhex("E0 47"),
    ".": bytes.fromhex("E0 60"),
    ",": bytes.fromhex("DF E2"),
}


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest().upper()


def ram_at(address: int) -> int:
    return address & 0x1FFFFF


def s16(blob: bytes, offset: int) -> int:
    return struct.unpack_from("<h", blob, offset)[0]


def slot_number(path: Path) -> int:
    return int(path.stem.rsplit("_", 1)[1])


def configure_runtime() -> None:
    runtime.CACHE_SLOTS = 24
    runtime.CACHE_CELLS = 6
    runtime.CACHE_U = (4, 16, 28, 40, 52, 64)
    runtime.CACHE_U_END = 76
    runtime.CACHE_V = 224
    runtime.CACHE_V_END = 236


def tpage_fields(value: int) -> tuple[int, int, int]:
    return value & 0xF, (value >> 4) & 1, (value >> 7) & 3


def archive_nibbles(font: bytes, tpage: int, u: int, v: int,
                    width: int, height: int) -> tuple[int, ...] | None:
    tx, ty, depth = tpage_fields(tpage)
    if depth != 0:
        return None
    result: list[int] = []
    for dy in range(height):
        py = ty * 256 + ((v + dy) & 0xFF)
        if not 0 <= py < 512:
            return None
        for dx in range(width):
            px = (tx - COMM_TPAGE_X) * 256 + ((u + dx) & 0xFF)
            if not 0 <= px < COMM_TEXEL_W:
                return None
            byte = font[py * COMM_ROW_BYTES + px // 2]
            result.append((byte >> (4 * (px & 1))) & 0xF)
    return tuple(result)


def live_nibbles(vram: bytes, tpage: int, u: int, v: int,
                 width: int, height: int) -> tuple[int, ...] | None:
    tx, ty, depth = tpage_fields(tpage)
    if depth != 0:
        return None
    result: list[int] = []
    for dy in range(height):
        py = ty * 256 + ((v + dy) & 0xFF)
        if not 0 <= py < 512:
            return None
        for dx in range(width):
            texel = (u + dx) & 0xFF
            word_x = tx * 64 + texel // 4
            if not 0 <= word_x < VRAM_W:
                return None
            word = struct.unpack_from("<H", vram, (py * VRAM_W + word_x) * 2)[0]
            result.append((word >> (4 * (texel & 3))) & 0xF)
    return tuple(result)


def selected_pixels(nibbles: tuple[int, ...] | None, clut: int) -> int | None:
    if nibbles is None or not FONT_CLUT_MIN <= clut <= FONT_CLUT_MAX:
        return None
    plane = (clut - FONT_CLUT_MIN) & 3
    return sum((value >> plane) & 1 for value in nibbles)


def selected_bitmap(nibbles: tuple[int, ...] | None, clut: int) -> tuple[int, ...] | None:
    if nibbles is None or not FONT_CLUT_MIN <= clut <= FONT_CLUT_MAX:
        return None
    plane = (clut - FONT_CLUT_MIN) & 3
    return tuple((value >> plane) & 1 for value in nibbles)


def nonzero(nibbles: tuple[int, ...] | None) -> int | None:
    return None if nibbles is None else sum(value != 0 for value in nibbles)


def bitmap_equal(a: tuple[int, ...] | None, b: tuple[int, ...] | None) -> str:
    return "" if a is None or b is None else str(int(a == b))


def physical_index(tpage: int, u: int, v: int, clut: int,
                   width: int, height: int) -> int | None:
    tx, ty, depth = tpage_fields(tpage)
    if (tx, ty, depth) != (5, 0, 0) or (width, height) != (12, 12):
        return None
    if u % CELL or v % CELL or not FONT_CLUT_MIN <= clut <= FONT_CLUT_MAX:
        return None
    return (v // CELL) * IPR + (u // CELL) * PLANES + ((clut - FONT_CLUT_MIN) & 3)


def direct_symbol_indices() -> dict[int, list[str]]:
    labels: dict[int, list[str]] = {}
    for char, token in KNOWN_SYMBOL_CODES.items():
        index = glyph_index(token, ())
        if index is None:
            raise SystemExit(f"cannot map symbol {char!r}")
        labels.setdefault(index, []).append(char)
    return labels


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser()
    parser.add_argument("save_prefix", nargs="?", default=DEFAULT_PREFIX)
    args = parser.parse_args()

    for path, expected in ((V170, V170_SHA256), (V151, V151_SHA256),
                           (ORIGINAL, ORIGINAL_SHA256)):
        if digest(path) != expected:
            raise SystemExit(f"archive hash differs: {path.name}")

    states = sorted(
        (path for path in SAVE_DIR.glob(f"{args.save_prefix}_*.sav")
         if path.stem.rsplit("_", 1)[-1].isdigit()),
        key=slot_number,
    )
    slots = [slot_number(path) for path in states]
    if slots != list(range(1, 10)):
        raise SystemExit(f"expected slots 1..9, found {slots}")

    with ZipFile(V170) as archive:
        exe = archive.read("PSX.EXE")
        v170_font = archive.read("COMM.IMG")
    with ZipFile(V151) as archive:
        v151_font = archive.read("COMM.IMG")
    with ZipFile(ORIGINAL) as archive:
        original_font = archive.read("COMM.IMG")

    configure_runtime()
    layout, _blobs, _routines = layout_source.routine_layout()
    owners_at = layout["owners"][0]
    symbol_labels = direct_symbol_indices()
    known_shapes: dict[tuple[int, ...], str] = pickle.loads(SHAPE_CACHE.read_bytes())

    helper_expected = exe[
        cache.source_at(PARSER_HELPER):cache.source_at(PARSER_HELPER) + PARSER_HELPER_SIZE
    ]
    entry_expected = {
        address: exe[cache.file_at(address):cache.file_at(address) + 8]
        for address in (PARSER_FIRST, PARSER_SECOND)
    }
    entry_expected[FRAME_CALL] = exe[
        cache.source_at(FRAME_CALL):cache.source_at(FRAME_CALL) + 8
    ]

    packet_rows: list[dict[str, object]] = []
    state_rows: list[dict[str, object]] = []
    lineage_ok = 0
    active_regressions = 0
    blank_live_font = 0

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
        _context, _parity, ot = runtime.trace_active_text_ot(ram)
        slot_packet_n = slot_regressions = slot_blank_font = 0

        for row in ot:
            if row["kind"] not in ("SPRT", "SPRT_8", "SPRT_16"):
                continue
            if row["tpage"] == "" or row["clut"] == "":
                continue
            address = int(row["address"])
            at = ram_at(address)
            x, y = s16(ram, at + 8), s16(ram, at + 10)
            tpage, u, v = int(row["tpage"]), int(row["u"]), int(row["v"])
            width, height, clut = int(row["width"]), int(row["height"]), int(row["clut"])
            live = live_nibbles(vram, tpage, u, v, width, height)
            current = archive_nibbles(v170_font, tpage, u, v, width, height)
            control = archive_nibbles(v151_font, tpage, u, v, width, height)
            untouched = archive_nibbles(original_font, tpage, u, v, width, height)
            index = physical_index(tpage, u, v, clut, width, height)
            live_selected = selected_pixels(live, clut)
            current_selected = selected_pixels(current, clut)
            control_selected = selected_pixels(control, clut)
            untouched_selected = selected_pixels(untouched, clut)
            current_bitmap = selected_bitmap(current, clut)
            control_bitmap = selected_bitmap(control, clut)
            untouched_bitmap = selected_bitmap(untouched, clut)
            lost_selected = (
                current_selected == 0 and control_selected is not None and control_selected > 0
            )
            lost_raw = (
                nonzero(current) == 0 and nonzero(control) is not None and nonzero(control) > 0
            )
            regression = bool(lost_selected or lost_raw)
            font_blank = live_selected == 0 and FONT_CLUT_MIN <= clut <= FONT_CLUT_MAX
            active_regressions += int(regression)
            blank_live_font += int(font_blank)
            slot_regressions += int(regression)
            slot_blank_font += int(font_blank)
            slot_packet_n += 1

            cache_slot = row["slot"]
            owner = ""
            if cache_slot != "":
                owner = owners[int(cache_slot)]
            labels: list[str] = []
            if index is not None:
                labels.extend(symbol_labels.get(index, ()))
                if index == 44:
                    labels.append("LOAD:L candidate")
            packet_rows.append({
                "slot": slot,
                "scene": SCENES[slot],
                "order": row["order"],
                "address": f"0x{address:08X}",
                "screen_x": x,
                "screen_y": y,
                "kind": row["kind"],
                "tpage": f"0x{tpage:04X}",
                "u": u,
                "v": v,
                "width": width,
                "height": height,
                "clut": f"0x{clut:04X}",
                "physical_index": "" if index is None else index,
                "labels": "|".join(labels),
                "cache_slot": cache_slot,
                "cache_owner": owner,
                "live_nonzero_nibbles": "" if live is None else nonzero(live),
                "v170_nonzero_nibbles": "" if current is None else nonzero(current),
                "v151_nonzero_nibbles": "" if control is None else nonzero(control),
                "original_nonzero_nibbles": "" if untouched is None else nonzero(untouched),
                "live_selected_pixels": "" if live_selected is None else live_selected,
                "v170_selected_pixels": "" if current_selected is None else current_selected,
                "v151_selected_pixels": "" if control_selected is None else control_selected,
                "original_selected_pixels": "" if untouched_selected is None else untouched_selected,
                "v170_shape": "" if current_bitmap is None else known_shapes.get(current_bitmap, ""),
                "v151_shape": "" if control_bitmap is None else known_shapes.get(control_bitmap, ""),
                "original_shape": "" if untouched_bitmap is None else known_shapes.get(untouched_bitmap, ""),
                "live_equals_v170": bitmap_equal(live, current),
                "v170_equals_v151": bitmap_equal(current, control),
                "v170_equals_original": bitmap_equal(current, untouched),
                "lost_from_v151": int(regression),
                "blank_live_font_plane": int(font_blank),
            })

        state_rows.append({
            "slot": slot,
            "scene": SCENES[slot],
            "lineage_ok": int(not failures),
            "lineage_failures": " ".join(failures),
            "sprite_packets": slot_packet_n,
            "lost_from_v151_packets": slot_regressions,
            "blank_live_font_packets": slot_blank_font,
        })

    out = OUT_ROOT / f"arc1_v170_missing_symbols_{args.save_prefix.removeprefix('HASH-')}"
    out.mkdir(parents=True, exist_ok=True)
    for name, rows in (("state_summary.csv", state_rows), ("sprite_packets.csv", packet_rows)):
        with (out / name).open("w", encoding="utf-8-sig", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)

    candidate_rows = [row for row in packet_rows if row["lost_from_v151"]]
    with (out / "active_v151_regressions.csv").open(
        "w", encoding="utf-8-sig", newline=""
    ) as handle:
        writer = csv.DictWriter(handle, fieldnames=list(packet_rows[0]))
        writer.writeheader()
        writer.writerows(candidate_rows)

    symbol_rows: list[dict[str, object]] = []
    for char, token in KNOWN_SYMBOL_CODES.items():
        index = glyph_index(token, ())
        if index is None:
            raise SystemExit(f"symbol index missing: {char}")
        row, rem = divmod(index, IPR)
        column, plane = divmod(rem, PLANES)
        u, v = column * CELL, row * CELL
        current = archive_nibbles(v170_font, 5, u, v, CELL, CELL)
        control = archive_nibbles(v151_font, 5, u, v, CELL, CELL)
        untouched = archive_nibbles(original_font, 5, u, v, CELL, CELL)
        clut = FONT_CLUT_MIN + plane
        symbol_rows.append({
            "char": char,
            "code_hex": token.hex(" ").upper(),
            "physical_index": index,
            "row": row,
            "column": column,
            "plane": plane,
            "v170_pixels": selected_pixels(current, clut),
            "v151_pixels": selected_pixels(control, clut),
            "original_pixels": selected_pixels(untouched, clut),
            "v170_shape": known_shapes.get(selected_bitmap(current, clut) or (), ""),
            "v151_shape": known_shapes.get(selected_bitmap(control, clut) or (), ""),
            "original_shape": known_shapes.get(selected_bitmap(untouched, clut) or (), ""),
            "v170_equals_v151": int(current == control),
        })
    with (out / "punctuation_inventory.csv").open(
        "w", encoding="utf-8-sig", newline=""
    ) as handle:
        writer = csv.DictWriter(handle, fieldnames=list(symbol_rows[0]))
        writer.writeheader()
        writer.writerows(symbol_rows)

    target_counter = Counter(
        (row["slot"], row["screen_x"], row["screen_y"], row["u"], row["v"], row["clut"])
        for row in candidate_rows
    )
    lines = [
        "v170 missing-symbol runtime audit",
        f"patch={V170.name}",
        f"sha256={V170_SHA256}",
        f"savestates={args.save_prefix}_1..9.sav",
        "",
        f"v170_lineage={lineage_ok}/9",
        f"sprite_packets={len(packet_rows)}",
        f"active_packets_lost_from_v151={active_regressions}",
        f"active_blank_font_packets={blank_live_font}",
        f"distinct_lost_screen_requests={len(target_counter)}",
        "",
        "state_detail",
    ]
    lines.extend(
        "  slot{slot} {scene}: sprites={sprite_packets} lost={lost_from_v151_packets} "
        "blank_font={blank_live_font_packets}".format(**row)
        for row in state_rows
    )
    lines.extend(("", "punctuation_inventory"))
    lines.extend(
        "  {char} {code_hex} index={physical_index}: v170={v170_pixels} "
        "v151={v151_pixels} original={original_pixels}".format(**row)
        for row in symbol_rows
    )
    report = out / "runtime_audit.txt"
    report.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    print(report)


if __name__ == "__main__":
    main()
