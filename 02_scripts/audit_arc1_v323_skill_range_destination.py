#!/usr/bin/env python3
"""Find a static COMM.IMG home for the skill-range cursor artwork.

V322's 16 px Hangul atlas overwrites the original range-cursor source on
texture page 5,0.  The cursor has nine UV-table entries whose complete source
union is U=0..96, V=128..160 (97x33 pixels).  This read-only audit searches
the other COMM.IMG-backed texture pages for an equally sized rectangle which
is blank in both the original disc and V322, then rejects every rectangle
sampled by an active textured packet in the DuckStation state corpus.

Snapshot absence is negative evidence, not proof of global ownership.  The
result is therefore a relocation candidate and must remain TEST_ONLY until a
cold-boot runtime test covers the expanded skill range.
"""

from __future__ import annotations

import csv
import hashlib
import struct
import sys
from collections import Counter
from pathlib import Path
from zipfile import ZipFile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))

from compression import zstd  # noqa: E402
from analyze_arc1_v163_runtime import RAM_SIZE, trace_active_text_ot  # noqa: E402
from extract_savestate_vram import VRAM_SIZE, VRAM_W, locate_ram, locate_vram  # noqa: E402


ORIGINAL = ROOT / "00_original/arc.zip"
V322 = ROOT / "03_output/arc1_v322_e2_skip_restore_TEST_ONLY_480924F9.zip"
STATES = Path.home() / "AppData/Local/DuckStation/savestates"
OUT = ROOT / "01_work/analysis/arc1_v323_skill_range_relocation"

COMM = "COMM.IMG"
ROW_BYTES = 896
LOGICAL_WIDTH = ROW_BYTES * 2
LOGICAL_HEIGHT = 512
COMM_FIRST_TPAGE_X = 5
COMM_LAST_TPAGE_X = 11
CURSOR_WIDTH = 97
CURSOR_HEIGHT = 33


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def inflate_state(path: Path) -> bytes:
    """Inflate the executable state frame from DUCCT or DUCCU containers."""
    raw = path.read_bytes()
    if raw[:5] == b"DUCCT":
        state_at = struct.unpack_from("<I", raw, 0xC4)[0]
        expected = None
    elif raw[:5] == b"DUCCU":
        state_at = struct.unpack_from("<I", raw, 0xD4)[0]
        expected = struct.unpack_from("<I", raw, 0xD0)[0]
    else:
        raise ValueError("not a supported DuckStation compressed state")
    if raw[state_at : state_at + 4] != b"\x28\xB5\x2F\xFD":
        raise ValueError("state zstd marker differs")
    blob = zstd.decompress(raw[state_at:])
    if expected is not None and len(blob) != expected:
        raise ValueError(f"DUCCU state length {len(blob)} != {expected}")
    return blob


def pixel(data: bytes, x: int, y: int) -> int:
    value = data[y * ROW_BYTES + x // 2]
    return (value >> (4 * (x & 1))) & 0x0F


def rectangle_blank(data: bytes, x0: int, y0: int) -> bool:
    return all(
        pixel(data, x, y) == 0
        for y in range(y0, y0 + CURSOR_HEIGHT)
        for x in range(x0, x0 + CURSOR_WIDTH)
    )


def packet_page(tpage: object) -> tuple[int, int] | None:
    if not isinstance(tpage, int):
        return None
    # Bits 0..3 select the 64-halfword X page; bit 4 selects Y=256.
    return tpage & 0x0F, (tpage >> 4) & 1


def vram_4bpp_pixel(vram: bytes, page_x: int, page_y: int, u: int, v: int) -> int:
    """Read one 4bpp texel addressed by a PS1 texture page and UV pair."""
    halfword_x = page_x * 64 + u // 4
    y = page_y * 256 + v
    value = struct.unpack_from("<H", vram, (y * VRAM_W + halfword_x) * 2)[0]
    return (value >> ((u & 3) * 4)) & 0x0F


def overlaps(
    left: int,
    top: int,
    width: int,
    height: int,
    candidate_u: int,
    candidate_v: int,
) -> bool:
    return (
        left < candidate_u + CURSOR_WIDTH
        and left + width > candidate_u
        and top < candidate_v + CURSOR_HEIGHT
        and top + height > candidate_v
    )


def main() -> None:
    with ZipFile(ORIGINAL) as archive:
        original = archive.read(COMM)
    with ZipFile(V322) as archive:
        current = archive.read(COMM)
    if len(original) != ROW_BYTES * LOGICAL_HEIGHT or len(current) != len(original):
        raise SystemExit("COMM.IMG geometry drift")

    # Keep the search grid aligned with the native 16 px atlas.  U=0/32 and
    # V=0/32 candidates are especially easy to audit and patch, but all 16 px
    # aligned positions are retained in the evidence table.
    candidates: list[dict[str, int]] = []
    for page_x in range(COMM_FIRST_TPAGE_X, COMM_LAST_TPAGE_X + 1):
        for page_y in (0, 1):
            for v in range(0, 256 - CURSOR_HEIGHT + 1, 16):
                for u in range(0, 256 - CURSOR_WIDTH + 1, 16):
                    logical_x = (page_x - COMM_FIRST_TPAGE_X) * 256 + u
                    logical_y = page_y * 256 + v
                    if rectangle_blank(original, logical_x, logical_y) and rectangle_blank(
                        current, logical_x, logical_y
                    ):
                        candidates.append(
                            {
                                "page_x": page_x,
                                "page_y": page_y,
                                "u": u,
                                "v": v,
                                "logical_x": logical_x,
                                "logical_y": logical_y,
                                "packet_overlap_count": 0,
                                "state_overlap_count": 0,
                                "runtime_nonzero_state_count": 0,
                                "runtime_nonzero_pixel_count": 0,
                            }
                        )

    packet_counts: Counter[tuple[int, int, int, int]] = Counter()
    state_hits: Counter[tuple[int, int, int, int]] = Counter()
    formats: Counter[str] = Counter()
    failures: list[str] = []
    files = sorted(STATES.glob("*.sav"))
    states_read = 0
    packets_read = 0
    for number, path in enumerate(files, 1):
        try:
            raw_magic = path.read_bytes()[:5].decode("ascii", errors="replace")
            blob = inflate_state(path)
            ram_at = locate_ram(blob)
            ram = blob[ram_at : ram_at + RAM_SIZE]
            if len(ram) != RAM_SIZE:
                raise ValueError("RAM payload is incomplete")
            _context, _parity, packets = trace_active_text_ot(ram)
        except BaseException as exc:  # keep the full corpus audit running
            failures.append(f"{path.name}: {exc}")
            continue
        formats[raw_magic] += 1
        states_read += 1
        seen_this_state: set[tuple[int, int, int, int]] = set()
        for packet in packets:
            page = packet_page(packet.get("tpage"))
            if page is None:
                continue
            try:
                u = int(packet["u"])
                v = int(packet["v"])
                width = int(packet["width"])
                height = int(packet["height"])
            except (KeyError, TypeError, ValueError):
                continue
            if width <= 0 or height <= 0:
                continue
            packets_read += 1
            for candidate in candidates:
                key = (
                    candidate["page_x"],
                    candidate["page_y"],
                    candidate["u"],
                    candidate["v"],
                )
                if page == key[:2] and overlaps(u, v, width, height, key[2], key[3]):
                    packet_counts[key] += 1
                    seen_this_state.add(key)
        for key in seen_this_state:
            state_hits[key] += 1
        if number % 50 == 0:
            print(f"consumer scan {number}/{len(files)}; usable={states_read}", flush=True)

    for candidate in candidates:
        key = (
            candidate["page_x"],
            candidate["page_y"],
            candidate["u"],
            candidate["v"],
        )
        candidate["packet_overlap_count"] = packet_counts[key]
        candidate["state_overlap_count"] = state_hits[key]

    clean = [row for row in candidates if row["packet_overlap_count"] == 0]
    if clean:
        # A packet-read census is not enough: another subsystem could overwrite
        # a blank COMM rectangle after upload.  Re-read the raw VRAM corpus and
        # count runtime writes for every packet-clean candidate.
        runtime_state_counts: Counter[tuple[int, int, int, int]] = Counter()
        runtime_pixel_counts: Counter[tuple[int, int, int, int]] = Counter()
        for number, path in enumerate(files, 1):
            try:
                blob = inflate_state(path)
                vram_at = locate_vram(blob)
                vram = blob[vram_at : vram_at + VRAM_SIZE]
                if len(vram) != VRAM_SIZE:
                    raise ValueError("VRAM payload is incomplete")
            except BaseException:
                continue
            for candidate in clean:
                key = (
                    candidate["page_x"], candidate["page_y"],
                    candidate["u"], candidate["v"],
                )
                nonzero = sum(
                    vram_4bpp_pixel(
                        vram,
                        candidate["page_x"],
                        candidate["page_y"],
                        candidate["u"] + x,
                        candidate["v"] + y,
                    )
                    != 0
                    for y in range(CURSOR_HEIGHT)
                    for x in range(CURSOR_WIDTH)
                )
                if nonzero:
                    runtime_state_counts[key] += 1
                    runtime_pixel_counts[key] += nonzero
            if number % 100 == 0:
                print(f"VRAM target scan {number}/{len(files)}", flush=True)
        for candidate in clean:
            key = (
                candidate["page_x"], candidate["page_y"],
                candidate["u"], candidate["v"],
            )
            candidate["runtime_nonzero_state_count"] = runtime_state_counts[key]
            candidate["runtime_nonzero_pixel_count"] = runtime_pixel_counts[key]

    # Stable preference: no observed reader, no observed runtime overwrite,
    # then the smallest aligned UVs.
    clean.sort(
        key=lambda row: (
            row["runtime_nonzero_state_count"],
            row["runtime_nonzero_pixel_count"],
            row["page_x"],
            row["v"],
            row["u"],
        )
    )
    selected = clean[0] if clean else None

    OUT.mkdir(parents=True, exist_ok=True)
    fields = (
        "page_x",
        "page_y",
        "u",
        "v",
        "logical_x",
        "logical_y",
        "packet_overlap_count",
        "state_overlap_count",
        "runtime_nonzero_state_count",
        "runtime_nonzero_pixel_count",
    )
    with (OUT / "destination_scan.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(sorted(candidates, key=lambda row: tuple(row[name] for name in fields[:4])))
    report = [
        "V323 skill-range static destination audit",
        f"original_comm_sha256={sha256(original)}",
        f"v322_comm_sha256={sha256(current)}",
        f"states_total={len(files)}",
        f"states_read={states_read}",
        f"states_failed={len(failures)}",
        f"state_formats={dict(sorted(formats.items()))}",
        f"textured_packets_read={packets_read}",
        f"blank_aligned_candidates={len(candidates)}",
        f"zero_observed_consumer_candidates={len(clean)}",
        f"selected_runtime_nonzero_states={selected['runtime_nonzero_state_count'] if selected else -1}",
        f"selected_runtime_nonzero_pixels={selected['runtime_nonzero_pixel_count'] if selected else -1}",
    ]
    if selected:
        report.append(
            "selected="
            f"page({selected['page_x']},{selected['page_y']}) "
            f"uv({selected['u']},{selected['v']}) "
            f"logical({selected['logical_x']},{selected['logical_y']})"
        )
    report.extend(f"failure={line}" for line in failures)
    (OUT / "destination_report.txt").write_text("\n".join(report) + "\n", encoding="utf-8")
    print("\n".join(report))


if __name__ == "__main__":
    main()
