"""Read-only audit of the eight user-supplied v164 DuckStation states.

This separates three failure classes which look similar on screen:

* the v164 hook/copy did not reach live RAM;
* the cache upload in RAM differs from the five VRAM cells;
* a persistent text packet still points at a slot whose owner was replaced.

The save states, patch archive, and game image are never modified.  Reports are
written only below ``01_work/analysis/arc1_v164_runtime_states``.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import struct
import sys
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))

import analyze_arc1_v163_runtime as old  # noqa: E402
import build_arc1_v164_predrawot_cache_upload_probe as build  # noqa: E402
from extract_savestate_vram import inflate, locate_ram, locate_vram  # noqa: E402


SAVE_DIR = Path(r"C:\Users\Administrator\AppData\Local\DuckStation\savestates")
DEFAULT_SAVE_PREFIX = "HASH-5BBE776656FD02D7"

BUILD = ROOT / "03_output/arc1_v164_predrawot_cache_upload_probe_4E714493.zip"
BUILD_SHA256 = "4E71449316530FF19F44F9C98E9DE62780EBE079548A12E25E7A30F0E80ED33C"
PLAN = ROOT / "01_work/analysis/dynamic_cache_v153_widthsafe"
PSX = "PSX.EXE"
COMM = "COMM.IMG"
ORIGINAL = ROOT / "00_original/arc.zip"

RAM_SIZE = 2 * 1024 * 1024
VRAM_SIZE = 1024 * 512 * 2
EARLY_HOOK = 0x8011C4AC
LATE_HOOK = 0x8011C860
FRAME = 0x801FF1A0
FRAME_N = 580
FRAME_TAIL = 0x801FF3AC
CLASSIFIER = 0x801FF410
CLASSIFIER_N = 36
FONT_ROWS = 21
FONT_COLS = 21

V163_CALLS = (
    build.jal(FRAME),
    build.jal(build.DRAWOT),
    build.jal(build.STOCK_FRAME),
)
V164_CALLS = (
    build.jal(build.STOCK_FRAME),
    build.jal(FRAME),
    build.jal(build.DRAWOT),
)


def digest(path: Path) -> str:
    sha = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            sha.update(chunk)
    return sha.hexdigest().upper()


def slot_number(path: Path) -> int:
    return int(path.stem.rsplit("_", 1)[1])


def direct_at(address: int) -> int:
    return address - old.RAM_TO_FILE


def resident_at(address: int) -> int:
    return old.SOURCE_BASE - old.RAM_TO_FILE + address - old.RESIDENT_BASE


def expected_runtime(exe: bytes, address: int, size: int, *, resident: bool) -> bytes:
    at = resident_at(address) if resident else direct_at(address)
    return exe[at:at + size]


def axis_parts(start: int, length: int) -> list[range]:
    if length <= 0:
        return []
    if length >= 256:
        return [range(0, 256)]
    end = start + length
    if end <= 256:
        return [range(start, end)]
    return [range(start, 256), range(0, end - 256)]


def touched_cells(u: int, v: int, width: int, height: int) -> set[tuple[int, int]]:
    result: set[tuple[int, int]] = set()
    for xs in axis_parts(u, width):
        for ys in axis_parts(v, height):
            if not xs or not ys:
                continue
            for row in range(ys.start // old.CELL, (ys.stop - 1) // old.CELL + 1):
                for col in range(xs.start // old.CELL, (xs.stop - 1) // old.CELL + 1):
                    if 0 <= row < FONT_ROWS and 0 <= col < FONT_COLS:
                        result.add((row, col))
    return result


def comm_cell(data: bytes, row: int, col: int) -> bytes:
    return b"".join(
        data[(row * old.CELL + y) * 896 + col * 6:
             (row * old.CELL + y) * 896 + col * 6 + 6]
        for y in range(old.CELL)
    )


def selected_plane(cell: bytes, plane: int) -> tuple[int, ...]:
    return tuple(
        (((cell[y * 6 + x // 2] >> (4 * (x & 1))) & 0xF) >> plane) & 1
        for y in range(old.CELL)
        for x in range(old.CELL)
    )


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser(
        description="Audit one exact eight-slot v164 DuckStation save-state lineage."
    )
    parser.add_argument("save_prefix", nargs="?", default=DEFAULT_SAVE_PREFIX)
    args = parser.parse_args()
    if not args.save_prefix.startswith("HASH-") or any(
        char not in "0123456789ABCDEF" for char in args.save_prefix[5:].upper()
    ):
        raise SystemExit("save prefix must be HASH- followed by hexadecimal digits")
    save_glob = f"{args.save_prefix}_*.sav"
    suffix = args.save_prefix.removeprefix("HASH-")
    out = ROOT / "01_work/analysis" / f"arc1_v164_runtime_states_{suffix}"
    report_path = out / "runtime_audit.txt"
    state_csv = out / "state_summary.csv"
    object_csv = out / "text_objects.csv"
    ot_csv = out / "active_ot_packets.csv"
    collision_csv = out / "static_cell_collisions.csv"

    if digest(BUILD) != BUILD_SHA256:
        raise SystemExit("v164 archive hash differs from the tested diagnostic")

    states = sorted(
        (
            path for path in SAVE_DIR.glob(save_glob)
            if path.stem.rsplit("_", 1)[-1].isdigit()
            and 1 <= slot_number(path) <= 8
        ),
        key=slot_number,
    )
    if [slot_number(path) for path in states] != list(range(1, 9)):
        raise SystemExit(f"expected slots 1..8, found {[slot_number(path) for path in states]}")

    with zipfile.ZipFile(BUILD) as archive:
        exe = archive.read(PSX)
        current_comm = archive.read(COMM)
    with zipfile.ZipFile(ORIGINAL) as archive:
        original_comm = archive.read(COMM)
    if len(current_comm) != 458752 or len(original_comm) != 458752:
        raise SystemExit("COMM.IMG size differs")

    expected_ranges = (
        (EARLY_HOOK, 8, False, "early_stock_frame_hook_and_delay"),
        (LATE_HOOK, 8, False, "predrawot_cache_hook_and_delay"),
        (FRAME, FRAME_N, True, "resident_cache_wrapper"),
        (CLASSIFIER, CLASSIFIER_N, True, "text_clut_classifier"),
    )

    assignment_rows = list(csv.DictReader(
        (PLAN / "glyph_assignments.csv").open(encoding="utf-8-sig", newline="")
    ))
    source_chars = {
        int(row["source_id"]): row["char"]
        for row in assignment_rows if row.get("source_id")
    }
    dictionary_blob = (PLAN / "row_dictionary.bin").read_bytes()
    glyph_rows = (PLAN / "dynamic_glyph_rows.bin").read_bytes()
    row_dictionary = struct.unpack(f"<{len(dictionary_blob) // 2}H", dictionary_blob)
    source_count = len(glyph_rows) // old.CELL

    def expected_shape(source: int) -> tuple[int, ...]:
        rows = glyph_rows[source * old.CELL:(source + 1) * old.CELL]
        return tuple(
            1 if row_dictionary[rows[y]] & (1 << (old.CELL - 1 - x)) else 0
            for y in range(old.CELL)
            for x in range(old.CELL)
        )
    static_chars = {
        int(row["physical_index"]): row["char"]
        for row in assignment_rows
        if row.get("kind") == "static" and row.get("physical_index")
    }
    static_chars_by_cell: dict[tuple[int, int], list[str]] = {}
    for row in assignment_rows:
        if row.get("kind") != "static" or not row.get("physical_index"):
            continue
        index = int(row["physical_index"])
        glyph_row, remainder = divmod(index, 84)
        cell = (glyph_row, remainder // 4)
        static_chars_by_cell.setdefault(cell, []).append(row["char"])
    changed_cells = {
        (row, col)
        for row in range(FONT_ROWS)
        for col in range(FONT_COLS)
        if comm_cell(current_comm, row, col) != comm_cell(original_comm, row, col)
    }

    state_rows: list[dict[str, object]] = []
    object_rows: list[dict[str, object]] = []
    ot_rows: list[dict[str, object]] = []
    collision_rows: list[dict[str, object]] = []
    report = [
        "v164 eight-state runtime audit",
        f"build={BUILD.name}",
        f"build_sha256={BUILD_SHA256}",
        "savestate_pattern=" + save_glob,
        "",
    ]

    totals = {
        "matched_objects": 0,
        "stale_objects": 0,
        "stale_packets": 0,
        "dynamic_packets": 0,
        "active_ot_text_overlaps": 0,
        "active_ot_nontext_overlaps": 0,
        "static_nontext_collision_packets": 0,
        "owner_plane_mismatches": 0,
    }
    lineage_counts: dict[str, int] = {}

    for path in states:
        inflated = inflate(path)
        ram_base = locate_ram(inflated)
        vram_base = locate_vram(inflated)
        ram = inflated[ram_base:ram_base + RAM_SIZE]
        vram = inflated[vram_base:vram_base + VRAM_SIZE]
        if len(ram) != RAM_SIZE or len(vram) != VRAM_SIZE:
            raise SystemExit(f"{path.name}: incomplete RAM or VRAM")

        code_failures: list[str] = []
        for address, size, resident, label in expected_ranges:
            got = ram[old.ram_at(address):old.ram_at(address) + size]
            want = expected_runtime(exe, address, size, resident=resident)
            if got != want:
                code_failures.append(label)

        # The one changed call inside the resident frame is especially useful
        # for distinguishing a stale v163 state from a true v164 cold boot.
        live_calls = (
            old.u32(ram, old.ram_at(EARLY_HOOK)),
            old.u32(ram, old.ram_at(LATE_HOOK)),
            old.u32(ram, old.ram_at(FRAME_TAIL)),
        )
        lineage = (
            "v164" if live_calls == V164_CALLS else
            "v163" if live_calls == V163_CALLS else
            "mixed_or_unknown"
        )
        lineage_counts[lineage] = lineage_counts.get(lineage, 0) + 1
        owners = struct.unpack_from(
            f"<{old.CACHE_SLOTS}H", ram, old.ram_at(old.OWNERS)
        )
        active = old.u32(ram, old.ram_at(old.ACTIVE))
        next_slot = ram[old.ram_at(old.NEXT_SLOT)]
        lookup = struct.unpack_from("<409H", ram, old.ram_at(0x801A7520))
        shadow_matches = sum(
            ram[
                old.ram_at(old.SHADOW) + cell * old.CELL_BYTES:
                old.ram_at(old.SHADOW) + (cell + 1) * old.CELL_BYTES
            ] == old.vram_cell(vram, cell)
            for cell in range(old.CACHE_CELLS)
        )
        occupied_owners = sum(owner != 0xFFFF for owner in owners)
        owner_checks = 0
        owner_mismatches = 0
        for slot, owner in enumerate(owners):
            if owner == 0xFFFF:
                continue
            owner_checks += 1
            if owner >= source_count:
                owner_mismatches += 1
                continue
            cell, plane = divmod(slot, old.PLANES)
            if selected_plane(old.vram_cell(vram, cell), plane) != expected_shape(owner):
                owner_mismatches += 1

        objects = old.find_text_objects(ram)
        dynamic_packets = sum(len(obj["dynamic"]) for obj in objects)
        matched_objects = 0
        stale_objects = 0
        stale_packets = 0
        for obj in objects:
            match = old.match_source_entry(
                ram, obj, lookup, owners, static_chars, source_chars
            )
            stale = [] if match is None else match["stale"]
            if match is not None:
                matched_objects += 1
            if stale:
                stale_objects += 1
                stale_packets += len(stale)
            dynamic = obj["dynamic"]
            object_rows.append({
                "state": f"slot{slot_number(path)}",
                "header": f"0x{int(obj['header']):08X}",
                "base": f"0x{int(obj['base']):08X}",
                "limit": obj["limit"],
                "count": obj["count"],
                "source_pointer": f"0x{int(obj['source_pointer']):08X}",
                "dynamic_count": len(dynamic),
                "matched": int(match is not None),
                "expected_text": "" if match is None else match["expected_text"],
                "packet_text_now": "" if match is None else match["current_text"],
                "stale_count": "" if match is None else len(stale),
                "stale": "" if match is None else " ".join(
                    f"i{index}:{source_chars.get(want, '?')}({want})->"
                    f"{source_chars.get(have, '?')}({have})"
                    for index, want, have in stale
                ),
                "slots": " ".join(str(item["slot"]) for item in dynamic),
            })

        context, parity, active_ot = old.trace_active_text_ot(ram)
        selected = [row for row in active_ot if row["selected_buffer"]]
        overlaps = [row for row in selected if row["overlap"]]
        text_overlaps = [row for row in overlaps if row["text_cache"]]
        nontext_overlaps = [row for row in overlaps if not row["text_cache"]]
        static_collisions: list[dict[str, object]] = []
        for packet in selected:
            tpage = packet.get("tpage")
            if not isinstance(tpage, int) or tpage & 0x19F != 0x005:
                continue
            try:
                cells = touched_cells(
                    int(packet["u"]), int(packet["v"]),
                    int(packet["width"]), int(packet["height"]),
                )
            except (KeyError, TypeError, ValueError):
                continue
            hits = sorted(cells & changed_cells)
            if not hits:
                continue
            clut = packet.get("clut")
            looks_text = (
                packet.get("kind") in ("SPRT", "SPRT_8", "SPRT_16")
                and isinstance(clut, int)
                and old.FONT_CLUT_MIN <= clut <= old.FONT_CLUT_MAX
            )
            if looks_text:
                continue
            collision = {
                "state": f"slot{slot_number(path)}",
                "order": packet["order"],
                "address": f"0x{int(packet['address']):08X}",
                "kind": packet["kind"],
                "tpage": f"0x{tpage:04X}",
                "u": packet["u"],
                "v": packet["v"],
                "width": packet["width"],
                "height": packet["height"],
                "clut": "" if not isinstance(clut, int) else f"0x{clut:04X}",
                "cells": " ".join(f"{row},{col}" for row, col in hits),
                "static_chars": " | ".join(
                    f"{row},{col}:{''.join(static_chars_by_cell.get((row, col), []))}"
                    for row, col in hits
                ),
            }
            static_collisions.append(collision)
            collision_rows.append(collision)
        for row in active_ot:
            ot_rows.append({"state": f"slot{slot_number(path)}", **row})

        totals["matched_objects"] += matched_objects
        totals["stale_objects"] += stale_objects
        totals["stale_packets"] += stale_packets
        totals["dynamic_packets"] += dynamic_packets
        totals["active_ot_text_overlaps"] += len(text_overlaps)
        totals["active_ot_nontext_overlaps"] += len(nontext_overlaps)
        totals["static_nontext_collision_packets"] += len(static_collisions)
        totals["owner_plane_mismatches"] += owner_mismatches

        row = {
            "slot": slot_number(path),
            "savestate": path.name,
            "sha256": digest(path),
            "v164_code_ok": int(not code_failures),
            "code_failures": ",".join(code_failures),
            "lineage": lineage,
            "early_hook_word": f"0x{live_calls[0]:08X}",
            "late_hook_word": f"0x{live_calls[1]:08X}",
            "frame_tail_word": f"0x{live_calls[2]:08X}",
            "occupied_owners": occupied_owners,
            "owner_plane_checks": owner_checks,
            "owner_plane_mismatches": owner_mismatches,
            "active_mask": f"0x{active:08X}",
            "next_slot": next_slot,
            "shadow_vram_equal_cells": shadow_matches,
            "text_objects": len(objects),
            "matched_objects": matched_objects,
            "stale_objects": stale_objects,
            "stale_packets": stale_packets,
            "dynamic_packets": dynamic_packets,
            "gpu_context": f"0x{context:08X}",
            "ot_parity": parity,
            "active_ot_packets": len(selected),
            "active_ot_text_cache": len(text_overlaps),
            "active_ot_nontext_cache": len(nontext_overlaps),
            "static_nontext_collision_packets": len(static_collisions),
            "static_nontext_collision_cells": " ".join(sorted({
                cell
                for collision in static_collisions
                for cell in str(collision["cells"]).split()
            })),
        }
        state_rows.append(row)
        owner_text = " ".join(
            f"{slot}:{source_chars.get(owner, '?')}({owner})"
            for slot, owner in enumerate(owners) if owner != 0xFFFF
        )
        report.extend((
            f"slot{slot_number(path)}  {path.name}",
            f"  lineage={lineage} v164_code_ok={not code_failures} "
            f"failures={code_failures or 'none'}",
            "  call_words=" + " ".join(f"0x{value:08X}" for value in live_calls),
            f"  owners={owner_text or 'none'}",
            f"  active=0x{active:08X} next_slot={next_slot}",
            f"  RAM_shadow_equals_VRAM={shadow_matches}/{old.CACHE_CELLS}",
            f"  owner_glyph_shapes={owner_checks - owner_mismatches}/{owner_checks} "
            f"mismatches={owner_mismatches}",
            f"  text_objects={len(objects)} matched={matched_objects} "
            f"dynamic_packets={dynamic_packets}",
            f"  stale_objects={stale_objects} stale_packets={stale_packets}",
            f"  active_OT_packets={len(selected)} cache_text={len(text_overlaps)} "
            f"cache_nontext={len(nontext_overlaps)}",
            f"  static_COMM_nontext_collisions={len(static_collisions)}",
            "",
        ))

    report.extend((
        "aggregate",
        "  lineage=" + " ".join(
            f"{name}:{count}" for name, count in sorted(lineage_counts.items())
        ),
        *(f"  {key}={value}" for key, value in totals.items()),
        "",
        "Interpretation rules",
        "  code failure => stale/wrong build; do not infer cache behavior",
        "  shadow != VRAM => cache destination was overwritten or upload had not completed",
        "  nontext OT overlap => cache destination/classifier still catches game artwork",
        "  stale packet => persistent text points at a slot now owned by another glyph",
    ))

    out.mkdir(parents=True, exist_ok=True)
    report_path.write_text("\n".join(report) + "\n", encoding="utf-8")
    with state_csv.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(state_rows[0]))
        writer.writeheader()
        writer.writerows(state_rows)
    with object_csv.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(object_rows[0]))
        writer.writeheader()
        writer.writerows(object_rows)
    with ot_csv.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(ot_rows[0]))
        writer.writeheader()
        writer.writerows(ot_rows)
    with collision_csv.open("w", encoding="utf-8-sig", newline="") as handle:
        fields = (
            "state", "order", "address", "kind", "tpage", "u", "v",
            "width", "height", "clut", "cells", "static_chars",
        )
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(collision_rows)
    print("\n".join(report))


if __name__ == "__main__":
    main()
