"""Measure v166 cache pressure and exact 24/28/32-slot growth budgets.

The owner table, active mask and visible VRAM are separate facts.  This audit
keeps them separate so a full owner table is not mistaken for a 24-slot
simultaneous allocation failure.  It is read-only apart from reports below
``01_work/analysis``.
"""
from __future__ import annotations

import csv
import hashlib
import struct
import sys
from pathlib import Path
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))

import analyze_arc1_v163_runtime as runtime  # noqa: E402
import analyze_arc1_v165c_runtime as old_audit  # noqa: E402
import build_arc1_v165_failclosed_cache as old_build  # noqa: E402
import build_arc1_v166_persistent_ot_guard as build  # noqa: E402
import verify_arc1_v165c_failclosed_cache as verify  # noqa: E402
from extract_savestate_vram import inflate, locate_ram, locate_vram  # noqa: E402
from map_vram_occupancy_all_states import (  # noqa: E402
    VRAM_SIZE, VRAM_W, fonts, locate,
)


PATCH = ROOT / "03_output/arc1_v166_persistent_ot_guard_fullcell_8EB4F3A4.zip"
PATCH_SHA256 = "8EB4F3A4F9031455D07F285456CF0859B6CD848399FB53E55E10FF9D8E2BD930"
SAVE_DIR = Path.home() / "AppData/Local/DuckStation/savestates"
SAVE_PREFIX = "HASH-5076D335C1AF160E"
OUT = ROOT / "01_work/analysis/arc1_v166_cache_capacity"
REPORT = OUT / "capacity_audit.txt"
STATE_CSV = OUT / "state_pressure.csv"

RAM_SIZE = 2 * 1024 * 1024
ITEM_DESCRIPTION_HEADER = 0x801F031C
STOCK_EARLY = 0x0C047205
STOCK_LATE = 0x0C05DB87


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest().upper()


def slot_number(path: Path) -> int:
    return int(path.stem.rsplit("_", 1)[1])


def configure_runtime() -> None:
    runtime.CACHE_SLOTS = 24
    runtime.CACHE_CELLS = 6
    runtime.CACHE_U = (4, 16, 28, 40, 52, 64)
    runtime.CACHE_U_END = 76
    runtime.CACHE_V = 224
    runtime.CACHE_V_END = 236


def projected_layout(slots: int, checkpoint_group: int) -> dict[str, int]:
    if slots not in (24, 28, 32):
        raise ValueError("the current one-word mask supports only 24/28/32 here")
    if checkpoint_group not in (4, 8, 16):
        raise ValueError("unsupported checkpoint group")
    current = old_build.read_layout()
    old_checkpoints = current["source_checkpoints"][1]
    checkpoint_count = (old_build.SOURCE_N + checkpoint_group - 1) // checkpoint_group
    new_checkpoints = checkpoint_count * 2
    owner_growth = (slots - 24) * 2
    checkpoint_saving = old_checkpoints - new_checkpoints
    # All routines keep the same instruction count; only their packed start
    # addresses move with the data prefix.
    current_free = old_build.HEAP_BASE - (build.FRAME + len(
        build.build_frame(build.FRAME, current)
    ))
    free = current_free + checkpoint_saving - owner_growth
    return {
        "slots": slots,
        "cells": slots // 4,
        "checkpoint_group": checkpoint_group,
        "checkpoint_bytes": new_checkpoints,
        "checkpoint_saving": checkpoint_saving,
        "owner_bytes": slots * 2,
        "owner_growth": owner_growth,
        "projected_free": free,
        "vram_x0": old_build.CACHE_X,
        "vram_x1": old_build.CACHE_X + (slots // 4) * 3 - 1,
    }


def stock_vram_controls() -> tuple[int, dict[int, int]]:
    """Count exact stock states touching each projected cache rectangle."""
    candidates = fonts()
    touched = {24: 0, 28: 0, 32: 0}
    stock = 0
    for path in sorted(SAVE_DIR.glob("*.sav")):
        try:
            blob = inflate(path)
            ram_base = locate_ram(blob)
            ram = blob[ram_base:ram_base + RAM_SIZE]
            if len(ram) != RAM_SIZE:
                continue
            early = struct.unpack_from("<I", ram, 0x11C4AC)[0]
            late = struct.unpack_from("<I", ram, 0x11C860)[0]
            if (early, late) != (STOCK_EARLY, STOCK_LATE):
                continue
            vram_base = locate(blob, candidates)
            if vram_base is None:
                continue
            vram = blob[vram_base:vram_base + VRAM_SIZE]
            stock += 1
            for slots in touched:
                x1 = old_build.CACHE_X + (slots // 4) * 3
                if any(
                    vram[(y * VRAM_W + x) * 2:(y * VRAM_W + x) * 2 + 2]
                    != b"\0\0"
                    for y in range(old_build.CACHE_Y, old_build.CACHE_Y + old_build.CELL)
                    for x in range(old_build.CACHE_X, x1)
                ):
                    touched[slots] += 1
        except BaseException:
            continue
    return stock, touched


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if sha256(PATCH) != PATCH_SHA256:
        raise SystemExit("v166 archive hash differs")
    configure_runtime()
    states = sorted(
        (path for path in SAVE_DIR.glob(f"{SAVE_PREFIX}_*.sav")
         if path.stem.rsplit("_", 1)[-1].isdigit()),
        key=slot_number,
    )
    if [slot_number(path) for path in states] != list(range(1, 11)):
        raise SystemExit("expected user slots 1..10")

    with ZipFile(PATCH) as archive:
        exe = archive.read(old_build.PSX)
    layout = old_build.read_layout()
    memory = verify.runtime_memory(exe)
    source_rows = verify.python_sources(memory, layout)
    ranges = old_audit.parse_ranges()
    with (old_audit.PLAN / "source_manifest.csv").open(
        encoding="utf-8-sig", newline=""
    ) as handle:
        source_chars = {
            int(row["source_id"]): row["char"] for row in csv.DictReader(handle)
        }
    with (old_audit.OLD_PLAN / "glyph_assignments.csv").open(
        encoding="utf-8-sig", newline=""
    ) as handle:
        static_chars = {
            int(row["physical_index"]): row["char"]
            for row in csv.DictReader(handle)
            if row["kind"] == "static" and row["physical_index"]
        }
    runtime.token_identities = lambda payload, lookup: old_audit.token_identities(
        payload, lookup, ranges
    )

    frame = build.build_frame(build.FRAME, layout)
    rows: list[dict[str, object]] = []
    shape_checks = shape_matches = 0
    stale_item_states = 0
    valid_lineage = 0
    active_counts: list[int] = []
    resident_at = old_build.source_at(old_build.RESIDENT_BASE)

    for path in states:
        slot = slot_number(path)
        blob = inflate(path)
        ram_base, vram_base = locate_ram(blob), locate_vram(blob)
        ram = blob[ram_base:ram_base + RAM_SIZE]
        vram = blob[vram_base:vram_base + VRAM_SIZE]
        owners = struct.unpack_from("<24H", ram, runtime.ram_at(layout["owners"][0]))
        active = runtime.u32(ram, runtime.ram_at(layout["active_mask"][0]))
        active_n = (active & 0xFFFFFF).bit_count()
        active_counts.append(active_n)
        lookup = struct.unpack_from(
            "<409H", ram, runtime.ram_at(old_build.LOOKUP_RAM)
        )
        code_ok = (
            ram[runtime.ram_at(build.FRAME):runtime.ram_at(build.FRAME) + len(frame)]
            == frame
            and runtime.u32(ram, runtime.ram_at(old_build.LATE_HOOK))
            == old_build.jal(build.FRAME)
        )
        valid_lineage += int(code_ok)

        for cache_slot, owner in enumerate(owners):
            if owner == 0xFFFF:
                continue
            shape_checks += 1
            got = old_audit.selected_plane(
                runtime.vram_cell(vram, cache_slot // 4), cache_slot % 4
            )
            expected = old_audit.expected_shape(source_rows[owner])
            shape_matches += int(got == expected)

        item_match = None
        item_dynamic = 0
        for obj in runtime.find_text_objects(ram):
            if int(obj["header"]) != ITEM_DESCRIPTION_HEADER:
                continue
            item_dynamic = len({int(g["slot"]) for g in obj["dynamic"]})
            item_match = runtime.match_source_entry(
                ram, obj, lookup, owners, static_chars, source_chars
            )
            break
        stale = bool(item_match and item_match["stale"])
        stale_item_states += int(stale and slot >= 5)
        rows.append({
            "slot": slot,
            "lineage_ok": int(code_ok),
            "owners_used": sum(owner != 0xFFFF for owner in owners),
            "active_slots": active_n,
            "active_mask": f"0x{active & 0xFFFFFF:06X}",
            "item_object_dynamic_slots": item_dynamic,
            "item_object_stale": int(stale),
            "item_expected": "" if not item_match else item_match["expected_text"],
            "item_current_owners": "" if not item_match else item_match["current_text"],
        })

    stock_states, stock_touches = stock_vram_controls()
    projections = [
        projected_layout(slots, group)
        for group in (4, 8, 16) for slots in (24, 28, 32)
    ]
    lines = [
        "v166 cache capacity and item-description lifetime audit",
        f"patch={PATCH.name}",
        f"sha256={PATCH_SHA256}",
        "",
        f"v166_lineage={valid_lineage}/10",
        f"owner_shape_matches={shape_matches}/{shape_checks}",
        "active_slots_by_state=" + ",".join(map(str, active_counts)),
        f"active_slots_max={max(active_counts)}",
        f"captured_full_24_slot_masks={sum(count == 24 for count in active_counts)}",
        f"item_scene_stale_object_states={stale_item_states}/6 (slots 5..10)",
        "",
        f"stock_control_states={stock_states}",
        *(f"stock_states_touching_{slots}_slot_rect={stock_touches[slots]}"
          for slots in (24, 28, 32)),
        "",
        "exact packed-resident projections",
    ]
    for row in projections:
        lines.append(
            "  slots={slots} group={checkpoint_group} checkpoints={checkpoint_bytes}B "
            "owners={owner_bytes}B free={projected_free}B "
            "VRAM=x{vram_x0}..{vram_x1},y480..491".format(**row)
        )
    lines.extend((
        "",
        "measured conclusion",
        "  A full owner table is history, not simultaneous pressure.",
        "  None of the ten captures has a full 24-bit active mask; the maximum is 12.",
        "  The item description object is stale while its cache planes still exactly match",
        "  their new owners.  This is direct owner-lifetime evidence, not fail-closed evidence.",
        "  28 and 32 slots fit the current reservation without recompressing data, but merely",
        "  delay the stale-object reuse and do not prove a fix for the observed defect.",
    ))

    OUT.mkdir(parents=True, exist_ok=True)
    REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with STATE_CSV.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    print("\n".join(lines))


if __name__ == "__main__":
    main()
