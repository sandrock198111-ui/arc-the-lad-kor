"""Read-only runtime audit for the six v162 DuckStation save states.

The first Zstandard frame in these .sav files is a 256x192 BGRA screenshot.  The
last frame is the actual emulation state and has already been decompressed to
``01_work/analysis/v162_runtime_states/slotN.state.bin``.  This script never
opens DuckStation and never modifies a save state or patch archive.

It verifies the full dynamic-glyph path that can be proven from one state:

    v162 code in RAM -> cache owner -> RAM shadow -> VRAM rectangle

It also counts live DR_TPAGE words and row-40 glyph packet candidates so a
correct upload can be separated from a wrong render-page selection.
"""
from __future__ import annotations

import csv
import hashlib
import struct
import sys
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))
from extract_savestate_vram import locate_vram  # noqa: E402

STATE_DIR = ROOT / "01_work/analysis/v162_runtime_states"
PLAN = ROOT / "01_work/analysis/dynamic_cache_v153_widthsafe"
BUILD = ROOT / "03_output/arc1_v162_strip_a_dynamic_cache_1759E571.zip"
BUILD_SHA256 = "1759E57185F8EF16D8A5421EE122FB14F158939736D2C70AC728A1D8B2EEC056"
REPORT = ROOT / "01_work/analysis/arc1_v162_runtime_states/runtime_audit.txt"
CSV_REPORT = ROOT / "01_work/analysis/arc1_v162_runtime_states/runtime_audit.csv"

PSX = "PSX.EXE"
RAM_DUMP_OFFSET = 0x1A62
RAM_SIZE = 2 * 1024 * 1024
VRAM_W = 1024
RAM_TO_FILE = 0x8011A800

SOURCE_BASE = 0x801A86EC
RESIDENT_BASE = 0x801FE3C4
ROW_DICTIONARY = RESIDENT_BASE
GLYPH_ROWS = 0x801FE4E2
CACHE_INDEX = 0x801FEE96
OWNERS = 0x801FEEBE
ACTIVE = 0x801FEEE8
NEXT_SLOT = 0x801FEEEC
RECT = 0x801FEEF0
SHADOW = 0x801FEEF8
DECODER = 0x801FF060
FRAME = 0x801FF1A0
FRAME_X_ADD = 0x801FF288
PIXEL_LOOP = 0x801FF328
HELPER = 0x801FF3E4
CLASSIFIER = 0x801FF410
FONT_CLUT_TABLE = 0x801F2FFE
FONT_CLUT_COUNT = 16

GLYPH_PACKET_HOOK = 0x8016B5D8
RENDER_HOOK = 0x8016B764
CLASSIFIER_CALL = 0x801A2204
STATELESS_DRIVER = 0x801A20B0

CACHE_SLOTS = 20
CACHE_CELLS = 5
PLANES = 4
CELL = 12
CELL_BYTES = 72
CACHE_X = 961
CACHE_Y = 480
CACHE_U = (4, 16, 28, 40, 52)
CACHE_V = 224


def digest(path: Path) -> str:
    sha = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            sha.update(chunk)
    return sha.hexdigest().upper()


def ram_offset(address: int) -> int:
    return RAM_DUMP_OFFSET + (address & 0x1FFFFF)


def file_offset(address: int) -> int:
    return address - RAM_TO_FILE


def source_offset(runtime_address: int) -> int:
    return file_offset(SOURCE_BASE + runtime_address - RESIDENT_BASE)


def word(blob: bytes, offset: int) -> int:
    return struct.unpack_from("<I", blob, offset)[0]


def runtime_word(state: bytes, address: int) -> int:
    return word(state, ram_offset(address))


def resident_source_word(exe: bytes, runtime_address: int) -> int:
    return word(exe, source_offset(runtime_address))


def cell_from_vram(vram: bytes, cell: int) -> bytes:
    x = CACHE_X + cell * 3
    return b"".join(
        vram[
            ((CACHE_Y + y) * VRAM_W + x) * 2:
            ((CACHE_Y + y) * VRAM_W + x) * 2 + 6
        ]
        for y in range(CELL)
    )


def vram_u16(vram: bytes, x: int, y: int) -> int:
    return struct.unpack_from("<H", vram, (y * VRAM_W + x) * 2)[0]


def clut_colors(vram: bytes, clut: int) -> tuple[int, ...]:
    x = (clut & 0x3F) * 16
    y = (clut >> 6) & 0x1FF
    return tuple(vram_u16(vram, x + i, y) for i in range(16))


def selected_plane(cell: bytes, plane: int) -> tuple[int, ...]:
    return tuple(
        (((cell[y * 6 + x // 2] >> (4 * (x & 1))) & 0xF) >> plane) & 1
        for y in range(CELL)
        for x in range(CELL)
    )


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if digest(BUILD) != BUILD_SHA256:
        raise SystemExit("v162 archive differs from the tested build")
    states = sorted(STATE_DIR.glob("slot*.state.bin"))
    if len(states) != 6:
        raise SystemExit(f"expected six decompressed states, found {len(states)}")

    with zipfile.ZipFile(BUILD) as archive:
        exe = archive.read(PSX)

    dictionary_blob = (PLAN / "row_dictionary.bin").read_bytes()
    glyph_blob = (PLAN / "dynamic_glyph_rows.bin").read_bytes()
    dictionary = struct.unpack(f"<{len(dictionary_blob) // 2}H", dictionary_blob)
    source_count = len(glyph_blob) // CELL
    with (PLAN / "glyph_assignments.csv").open(encoding="utf-8-sig", newline="") as handle:
        source_chars = {
            int(row["source_id"]): row["char"]
            for row in csv.DictReader(handle)
            if row["source_id"]
        }
    if set(source_chars) != set(range(source_count)):
        raise SystemExit("dynamic source ids are not contiguous")

    def expected_shape(source: int) -> tuple[int, ...]:
        rows = glyph_blob[source * CELL:(source + 1) * CELL]
        return tuple(
            1 if dictionary[rows[y]] & (1 << (CELL - 1 - x)) else 0
            for y in range(CELL)
            for x in range(CELL)
        )

    # These ranges must be exactly the code/data that v162 placed in the live RAM.
    direct_ranges = (
        (GLYPH_PACKET_HOOK, 4, "glyph_hook"),
        (RENDER_HOOK, 8, "renderer_hook"),
        (CLASSIFIER_CALL, 4, "classifier_call"),
        (STATELESS_DRIVER, 0x1F0, "stateless_driver"),
    )
    resident_ranges = (
        (CACHE_INDEX, CACHE_SLOTS * 2, "cache_index"),
        (FRAME_X_ADD, 4, "frame_x"),
        (PIXEL_LOOP, 13 * 4, "pixel_loop"),
        (HELPER, 44, "row40_helper"),
        (CLASSIFIER, 24, "v224_classifier"),
    )

    rows: list[dict[str, object]] = []
    lines = [
        "v162 runtime audit",
        f"build={BUILD.name}",
        f"build_sha256={BUILD_SHA256}",
        "",
    ]
    for path in states:
        state = path.read_bytes()
        vram_base = locate_vram(state)
        vram = state[vram_base:vram_base + VRAM_W * 512 * 2]
        if len(vram) != VRAM_W * 512 * 2:
            raise SystemExit(f"{path.name}: marker-selected VRAM is incomplete")
        live_ram = state[RAM_DUMP_OFFSET:RAM_DUMP_OFFSET + RAM_SIZE]

        code_failures = []
        for address, size, label in direct_ranges:
            got = state[ram_offset(address):ram_offset(address) + size]
            expected = exe[file_offset(address):file_offset(address) + size]
            if got != expected:
                code_failures.append(label)
        for address, size, label in resident_ranges:
            got = state[ram_offset(address):ram_offset(address) + size]
            expected = exe[source_offset(address):source_offset(address) + size]
            if got != expected:
                code_failures.append(label)

        cache_indices = struct.unpack_from(
            f"<{CACHE_SLOTS}H", state, ram_offset(CACHE_INDEX)
        )
        owners = struct.unpack_from(f"<{CACHE_SLOTS}H", state, ram_offset(OWNERS))
        active = runtime_word(state, ACTIVE)
        next_slot = state[ram_offset(NEXT_SLOT)]
        rect = struct.unpack_from("<4H", state, ram_offset(RECT))

        ram_vram_equal = 0
        cell_nonzero = 0
        owner_checks = 0
        owner_mismatches = 0
        owner_text = []
        for cell_no in range(CACHE_CELLS):
            shadow = state[
                ram_offset(SHADOW) + cell_no * CELL_BYTES:
                ram_offset(SHADOW) + (cell_no + 1) * CELL_BYTES
            ]
            cache_cell = cell_from_vram(vram, cell_no)
            ram_vram_equal += shadow == cache_cell
            cell_nonzero += any(vram)
            for plane_no in range(PLANES):
                slot = cell_no * PLANES + plane_no
                source = owners[slot]
                if source == 0xFFFF:
                    continue
                if source >= source_count:
                    owner_mismatches += 1
                    owner_text.append(f"slot{slot}=OUT:{source}")
                    continue
                mismatch = sum(
                    left != right
                    for left, right in zip(
                        selected_plane(vram, plane_no), expected_shape(source)
                    )
                )
                owner_checks += 1
                owner_mismatches += mismatch != 0
                owner_text.append(
                    f"slot{slot}={source_chars[source]}:{source}:diff{mismatch}"
                )

        tpage_word = struct.pack("<I", 0xE100001F)
        tpage_offsets = []
        at = live_ram.find(tpage_word)
        while at >= 0:
            tpage_offsets.append(0x80000000 + at)
            at = live_ram.find(tpage_word, at + 1)

        # The stock glyph builder at 0x8016B5FC..0x8016B638 selects one of
        # sixteen CLUT values from this table (style * 4 + glyph plane), then
        # stores it in the text-object metadata at +0x30.  Read the live table
        # rather than inferring the valid range from whichever styles happen
        # to be visible in the screenshots.
        font_cluts = struct.unpack_from(
            f"<{FONT_CLUT_COUNT}H", state, ram_offset(FONT_CLUT_TABLE)
        )

        # Follow the first DMA link of every aligned high-page DR_TPAGE.  This
        # distinguishes a packet that is actually submitted in the high pass
        # from an unlinked/stale packet that merely remains in RAM.
        high_links: list[tuple[int, int, int, int, int]] = []
        for at in range(0, RAM_SIZE - 12, 4):
            if word(live_ram, at + 4) != 0xE100001F:
                continue
            target24 = word(live_ram, at) & 0x00FFFFFF
            if target24 in (0, 0x00FFFFFF) or target24 >= RAM_SIZE - 20:
                continue
            if live_ram[target24 + 7] != 0x65:
                continue
            width, height = struct.unpack_from("<HH", live_ram, target24 + 16)
            u, v = live_ram[target24 + 12], live_ram[target24 + 13]
            clut = struct.unpack_from("<H", live_ram, target24 + 14)[0]
            high_links.append((0x80000000 + at, 0x80000000 + target24,
                               u, v, clut))
        high_link_groups: dict[tuple[int, int, int], int] = {}
        for _, _, u, v, clut in high_links:
            high_link_groups[(u, v, clut)] = high_link_groups.get((u, v, clut), 0) + 1
        high_link_text = " ".join(
            f"U{u}:V{v}:CLUT{clut:04X}:links{count}"
            for (u, v, clut), count in sorted(high_link_groups.items())
        )

        # A live text primitive is a 20-byte SPRT packet: DMA tag, command 0x65,
        # XY, UV+CLUT and 12x12 size.  Group cache packets by U and CLUT so all
        # four bitplanes are checked instead of inferring success from one glyph.
        packet_candidates = []
        packet_groups: dict[tuple[int, int], list[int]] = {}
        for at in range(0, RAM_SIZE - 20, 4):
            if live_ram[at + 7] != 0x65:
                continue
            width, height = struct.unpack_from("<HH", live_ram, at + 16)
            u, v = live_ram[at + 12], live_ram[at + 13]
            if (width, height, v) != (CELL, CELL, CACHE_V) or u not in CACHE_U:
                continue
            clut = struct.unpack_from("<H", live_ram, at + 14)[0]
            address = 0x80000000 + at
            packet_candidates.append(address)
            packet_groups.setdefault((u, clut), []).append(address)
        packet_group_text = []
        for (u, clut), addresses in sorted(packet_groups.items()):
            colors = clut_colors(vram, clut)
            nonzero = sum(color != 0 for color in colors)
            packet_group_text.append(
                f"U{u}:CLUT{clut:04X}:palette_nonzero{nonzero}/16:packets{len(addresses)}"
            )

        result = {
            "state": path.stem,
            "code_failures": ",".join(code_failures),
            "cache_table_ok": int(cache_indices == tuple(range(3360, 3380))),
            "active": f"0x{active:08X}",
            "next_slot": next_slot,
            "rect": "/".join(map(str, rect)),
            "occupied_owners": owner_checks,
            "owner_plane_mismatches": owner_mismatches,
            "shadow_vram_equal_cells": ram_vram_equal,
            "nonzero_cache_cells": cell_nonzero,
            "tpage_001f_words": len(tpage_offsets),
            "font_clut_table": " ".join(f"{value:04X}" for value in font_cluts),
            "high_tpage_links": high_link_text,
            "row40_packet_candidates": len(packet_candidates),
            "row40_packet_groups": " ".join(packet_group_text),
            "owners": " ".join(owner_text),
        }
        rows.append(result)
        lines.extend(
            (
                path.name,
                f"  code_failures={code_failures or 'none'}",
                f"  cache_table={cache_indices[0]}..{cache_indices[-1]} "
                f"ok={bool(result['cache_table_ok'])}",
                f"  active=0x{active:08X} next={next_slot} rect={rect}",
                f"  owners={' '.join(owner_text) or 'none'}",
                f"  owner_plane_mismatches={owner_mismatches}/{owner_checks}",
                f"  RAM_shadow_equals_VRAM={ram_vram_equal}/{CACHE_CELLS}",
                f"  nonzero_cache_cells={cell_nonzero}/{CACHE_CELLS}",
                f"  E100001F_words={len(tpage_offsets)} "
                f"addresses={','.join(f'0x{x:08X}' for x in tpage_offsets[:12]) or 'none'}",
                f"  font_CLUT_table={' '.join(f'{value:04X}' for value in font_cluts)}",
                f"  linked_high_page_packets={high_link_text or 'none'}",
                f"  row40_packet_candidates={len(packet_candidates)} "
                f"addresses={','.join(f'0x{x:08X}' for x in packet_candidates[:12]) or 'none'}",
                f"  row40_packet_groups={' '.join(packet_group_text) or 'none'}",
                "",
            )
        )

    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with CSV_REPORT.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    print("\n".join(lines))


if __name__ == "__main__":
    main()
