"""Build a fail-closed safety manifest for COMM.IMG 12x12 physical cells.

The four bitplanes in one cell are inseparable for safety: game artwork samples the
combined nibble, so proving one plane is a font glyph does not authorize the cell.
This audit combines bounded original/current text producers with active ordering-
table consumers from every available save state.  Snapshot absence is recorded only
as regression evidence; it never promotes a cell to release-approved status.
"""
from __future__ import annotations

import csv
import struct
import sys
import zipfile
from collections import Counter, defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))

from analyze_arc1_v163_runtime import (  # noqa: E402
    FONT_CLUT_MAX, FONT_CLUT_MIN, RAM_SIZE, trace_active_text_ot,
)
from audit_dynamic_cache_requirements import (  # noqa: E402
    active_slots, glyph_index, read_lut, source_ranges,
)
from build_arc1_v161_bounded_exe_text import (  # noqa: E402
    pointer_records, string_span, target,
)
from extract_savestate_vram import inflate, locate_ram  # noqa: E402
from plan_bulk_insertion import (  # noqa: E402
    CELL, IPR, PLANES, SLOT_BASE, SLOT_SIZE, tokens,
)


ORIGINAL = ROOT / "00_original/arc.zip"
CURRENT = ROOT / "03_output/arc1_v163_text_clut_classifier_773E3B82.zip"
ASSIGNMENTS = ROOT / "01_work/analysis/dynamic_cache_v153_widthsafe/glyph_assignments.csv"
STATES = Path.home() / "AppData/Local/DuckStation/savestates"
OUT = ROOT / "01_work/analysis/comm_physical_cell_safety"
DETAIL = OUT / "cells.csv"
CANDIDATES = OUT / "font_only_cell_candidates.csv"
APPROVED = OUT / "font_only_cells.csv"
REPORT = OUT / "report.txt"

FONT_ROWS = 21
FONT_COLS = 21
KNOWN_RANGE_OVERLAY = {(row, col) for row in range(10, 14) for col in range(2, 6)}


def members(path: Path) -> dict[str, bytes]:
    with zipfile.ZipFile(path) as archive:
        return {name: archive.read(name) for name in archive.namelist()}


def exe_units(data: dict[str, bytes]):
    exe = data["PSX.EXE"]
    seen: set[tuple[int, int]] = set()
    for pointer, label in sorted(pointer_records().items()):
        span = string_span(exe, target(exe, pointer))
        if span in seen:
            continue
        seen.add(span)
        yield f"exe:{label}:0x{span[0]:X}", exe[span[0]:span[1]]


def body_units(data: dict[str, bytes], ranges: list[tuple[str, int, int]]):
    for name, offset, size in ranges:
        payload = data.get(name, b"")
        if offset + size <= len(payload):
            yield f"body:{name}:0x{offset:X}", payload[offset:offset + size]


def active_slot_units(data: dict[str, bytes], ranges: list[tuple[str, int, int]]):
    for name, slots in active_slots(data, ranges).items():
        payload = data[name]
        for slot in slots:
            at = SLOT_BASE + slot * SLOT_SIZE
            block = payload[at:at + SLOT_SIZE]
            end = block.find(b"\0")
            if end <= 0:
                raise ValueError(f"invalid active slot {name}:{slot}")
            yield f"slot:{name}:{slot}", block[:end]


def collect_indices(units, lut: tuple[int, ...]) -> tuple[Counter[int], dict[int, set[str]]]:
    counts: Counter[int] = Counter()
    labels: dict[int, set[str]] = defaultdict(set)
    for label, payload in units:
        for token in tokens(payload):
            index = glyph_index(token, lut)
            if index is None or not 0 <= index < FONT_ROWS * IPR:
                continue
            row, remainder = divmod(index, IPR)
            col = remainder // PLANES
            if col >= FONT_COLS:
                continue
            counts[index] += 1
            labels[index].add(label)
    return counts, labels


def is_font_tpage(value: object) -> bool:
    return isinstance(value, int) and value & 0x19F == 0x005


def axis_parts(start: int, length: int) -> list[range]:
    """Texture coordinates wrap at 256; return one or two covered ranges."""
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
            for row in range(ys.start // CELL, (ys.stop - 1) // CELL + 1):
                for col in range(xs.start // CELL, (xs.stop - 1) // CELL + 1):
                    if 0 <= row < FONT_ROWS and 0 <= col < FONT_COLS:
                        result.add((row, col))
    return result


def runtime_consumers() -> tuple[Counter[tuple[int, int]], Counter[tuple[int, int]],
                                 dict[tuple[int, int], set[str]], int, list[str]]:
    text: Counter[tuple[int, int]] = Counter()
    nontext: Counter[tuple[int, int]] = Counter()
    nontext_states: dict[tuple[int, int], set[str]] = defaultdict(set)
    read = 0
    failures: list[str] = []
    for number, path in enumerate(sorted(STATES.glob("*.sav")), 1):
        try:
            blob = inflate(path)
            ram_base = locate_ram(blob)
            ram = blob[ram_base:ram_base + RAM_SIZE]
            _context, _parity, packets = trace_active_text_ot(ram)
        except BaseException as exc:
            failures.append(f"{path.name}: {exc}")
            continue
        read += 1
        for packet in packets:
            if not is_font_tpage(packet.get("tpage")):
                continue
            try:
                u = int(packet["u"])
                v = int(packet["v"])
                width = int(packet["width"])
                height = int(packet["height"])
            except (KeyError, TypeError, ValueError):
                continue
            cells = touched_cells(u, v, width, height)
            if not cells:
                continue
            clut = packet.get("clut")
            # The runtime font CLUT table is the proven discriminator.  Glyph
            # packets are not all 12x12/aligned (punctuation and narrow UI text
            # vary), while the v162 icon counterexample used CLUT 0x0010.
            looks_text = (
                packet.get("kind") in ("SPRT", "SPRT_8", "SPRT_16")
                and isinstance(clut, int) and FONT_CLUT_MIN <= clut <= FONT_CLUT_MAX
            )
            bucket = text if looks_text else nontext
            for cell in cells:
                bucket[cell] += 1
                if not looks_text:
                    nontext_states[cell].add(path.name)
        if number % 40 == 0:
            print(f"  consumer scan {number}", flush=True)
    return text, nontext, nontext_states, read, failures


def main() -> None:
    pristine = members(ORIGINAL)
    current = members(CURRENT)
    ranges = source_ranges()
    original_lut = read_lut(pristine["PSX.EXE"])
    current_lut = read_lut(current["PSX.EXE"])

    original_units = list(body_units(pristine, ranges)) + list(exe_units(pristine))
    current_units = (
        list(body_units(current, ranges))
        + list(active_slot_units(current, ranges))
        + list(exe_units(current))
    )
    original_counts, original_labels = collect_indices(original_units, original_lut)
    current_counts, current_labels = collect_indices(current_units, current_lut)

    assigned: dict[tuple[int, int], list[str]] = defaultdict(list)
    with ASSIGNMENTS.open(encoding="utf-8-sig", newline="") as handle:
        for record in csv.DictReader(handle):
            if record.get("kind") != "static" or not record.get("physical_index"):
                continue
            index = int(record["physical_index"])
            row, remainder = divmod(index, IPR)
            col = remainder // PLANES
            if row < FONT_ROWS and col < FONT_COLS:
                assigned[(row, col)].append(record["char"])

    runtime_text, runtime_nontext, nontext_states, state_count, failures = runtime_consumers()
    rows: list[dict[str, object]] = []
    candidate_rows: list[dict[str, int]] = []
    unapproved_assigned: set[tuple[int, int]] = set()
    statuses: Counter[str] = Counter()

    for row in range(FONT_ROWS):
        for col in range(FONT_COLS):
            indices = [row * IPR + col * PLANES + plane for plane in range(PLANES)]
            original_planes = [plane for plane, index in enumerate(indices) if original_counts[index]]
            held_planes = [plane for plane, index in enumerate(indices) if current_counts[index]]
            known_overlay = (row, col) in KNOWN_RANGE_OVERLAY
            nontext_n = runtime_nontext[(row, col)]
            all_planes_text = len(original_planes) == PLANES
            no_known_consumer = not held_planes and not nontext_n and not known_overlay

            if known_overlay or nontext_n:
                status = "rejected_known_nontext"
            elif all_planes_text:
                status = "candidate_font_only_unbounded_consumers"
                candidate_rows.append({"row": row, "col": col})
            elif original_planes:
                status = "insufficient_partial_font_evidence"
            else:
                status = "unknown_no_text_evidence"
            statuses[status] += 1

            # No cell is release-approved yet: settings/auxiliary strings and all
            # scene consumers have not been exhaustively bounded.  This is the
            # agreed fail-closed distinction between candidate and ownership proof.
            approved = 0
            if assigned.get((row, col)) and not approved:
                unapproved_assigned.add((row, col))
            rows.append({
                "row": row,
                "col": col,
                "indices": " ".join(map(str, indices)),
                "original_text_planes": " ".join(map(str, original_planes)),
                "original_text_occurrences": sum(original_counts[i] for i in indices),
                "current_known_text_planes": " ".join(map(str, held_planes)),
                "current_known_text_occurrences": sum(current_counts[i] for i in indices),
                "runtime_text_reads": runtime_text[(row, col)],
                "runtime_nontext_reads": nontext_n,
                "runtime_nontext_states": " ".join(sorted(nontext_states[(row, col)])),
                "known_range_overlay": int(known_overlay),
                "v163_static_chars": "".join(assigned.get((row, col), [])),
                "status": status,
                "release_approved": approved,
                "reason_withheld": (
                    "known non-text consumer" if known_overlay or nontext_n
                    else "consumer set is not exhaustively bounded"
                ),
            })

    OUT.mkdir(parents=True, exist_ok=True)
    with DETAIL.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    with CANDIDATES.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=("row", "col"))
        writer.writeheader()
        writer.writerows(candidate_rows)
    with APPROVED.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=("row", "col"))
        writer.writeheader()

    lines = [
        "COMM.IMG physical-cell safety audit",
        f"original_bounded_text_units={len(original_units)}",
        f"current_bounded_text_units={len(current_units)}",
        f"savestates_read={state_count}",
        f"savestates_failed={len(failures)}",
        f"physical_cells={len(rows)}",
        *(f"{key}={value}" for key, value in sorted(statuses.items())),
        f"candidate_cells={len(candidate_rows)}",
        "release_approved_cells=0",
        f"v163_static_cells={len(assigned)}",
        f"v163_static_cells_not_release_approved={len(unapproved_assigned)}",
        "",
        "Decision: HOLD. Candidate means all four planes were observed as bounded",
        "original text and no sampled conflict was found. It is not ownership proof.",
        "The approved row,col file therefore contains only its header.",
        "",
        f"detail={DETAIL}",
        f"candidates={CANDIDATES}",
        f"approved={APPROVED}",
    ]
    if failures:
        lines.extend(("", "state_failures:", *failures))
    REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
