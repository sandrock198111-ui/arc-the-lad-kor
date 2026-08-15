#!/usr/bin/env python3
"""Build v231: promote the 162 displaced high-frequency glyphs back to static.

Plan: 05_docs/dynamic_cache_resolution_plan_2026-08-15.md section 3-3.

The 162 `existing_restored_static_conflict` sources (source_manifest.csv) are
common syllables that v165c pushed into the dynamic cache because their ORIGINAL
cells are read by non-text game packets (all 50 home cells are rejected in the
509-state audit, so they cannot simply be restored in place).

This build MIGRATES them instead:

  destination   an unused slot inside a cell that (a) no non-text packet has
                ever been seen reading across all 509 states, (b) has text-read
                evidence, (c) is outside the 48-entry direct range table at
                0x801A74C0 and outside the v127 strip-D remap, and (d) whose
                plane index is not referenced by the current script.
  glyph pixels  read from the v151 build (the last build where these glyphs
                lived as static pixels; the same shapes were carried into the
                Huffman library by v165c/v190).
  script        every direct-code reference to an old index is re-encoded to
                the new index.  1-byte indices (<220) map to 1-byte indices,
                2-byte to 2-byte, so no text length or pointer changes.
                E9/EA (lookup) references are left alone: their sources stay in
                the resident Huffman library, so they keep rendering through
                the cache exactly as in v210.

Nothing else changes: no resident code bytes, no range table bytes, no lookup
table bytes, no DAT geometry.  PSX.EXE changes only inside the 0x78000..0x83000
string pool (re-encoded codes), COMM.IMG only inside the destination cells,
DATs only at re-encoded text bytes.

The cache/worldmap overlap problem is NOT addressed here; this build only
collapses the cache working set (max distinct dynamic per line: 26 -> ~7).
"""
from __future__ import annotations

import csv
import hashlib
import struct
import sys
import zipfile
from collections import Counter, defaultdict
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))
sys.path.insert(0, str(ROOT / "06_tools/python_packages"))

from plan_bulk_insertion import (  # noqa: E402
    CELL, IPR, LOOKUP_N, LOOKUP_SRC, PLANES, RAM_TO_FILE,
    SLOT_BASE, SLOT_COUNT, SLOT_SIZE, remap_slot,
)
from audit_dynamic_cache_requirements import glyph_index, source_ranges  # noqa: E402
import plan_bulk_insertion as pbi  # noqa: E402

BASE = ROOT / "03_output/arc1_v210_sd031_slots_controls.zip"
BASE_SHA = "7FB963135C753CBF509F9E722BF826856B04D456D29743A0B1D8CB5A9B34CAF9"
GLYPH_SRC = ROOT / "03_output/arc1_v151_free_the_sprite_cell_A4358FEE.zip"
GLYPH_SRC_SHA = "A4358FEE5FEA4964C9DD376B630894EB5EC133EFEEDD9E5E85BBC5FDD8CA1A46"
MANIFEST = ROOT / "01_work/analysis/arc1_v190_dynamic_owner_repair/source_manifest.csv"
CELL_AUDIT = ROOT / "01_work/analysis/font_cell_audit_full/cell_consumers.csv"
OUT_DIR = ROOT / "03_output"
ANALYSIS = ROOT / "01_work/analysis/arc1_v231_static_promotion"
ANALYSIS.mkdir(parents=True, exist_ok=True)

RANGES_RAM, RANGE_BYTES = 0x801A74C0, 96
ROW_BYTES = 896  # COMM.IMG font page: 4bpp, 1792px wide
FONT_ROWS = 21
EXE_POOL = (0x78000, 0x83000)
PSX, COMM = "PSX.EXE", "COMM.IMG"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def members_of(path: Path, expect_sha: str) -> dict[str, bytes]:
    raw = path.read_bytes()
    if sha256(raw) != expect_sha:
        raise SystemExit(f"GUARD: {path.name} sha mismatch")
    with ZipFile(path) as z:
        return {n: z.read(n) for n in z.namelist()}


def range_table_indices(exe: bytes) -> set[int]:
    raw = exe[RANGES_RAM - RAM_TO_FILE:RANGES_RAM - RAM_TO_FILE + RANGE_BYTES]
    out: set[int] = set()
    for i in range(RANGE_BYTES // 2):
        word = struct.unpack_from("<H", raw, i * 2)[0]
        start, length = word & 0x7FF, (word >> 11) + 1
        out.update(range(start, start + length))
    return out


def encode_index(index: int) -> bytes | None:
    """Canonical byte code for a physical index (the game's own arithmetic)."""
    if 0 <= index < 220:
        return bytes((index + 1,))
    rel = index - 0xDB
    lead, trail = divmod(rel, 255)
    code = bytes((0xDD + lead, trail))
    lut_unused: tuple[int, ...] = ()
    if glyph_index(code, lut_unused) != index:
        return None
    return code


def read_plane(font: bytes, index: int) -> tuple[int, ...]:
    row, rem = divmod(index, IPR)
    col, plane = divmod(rem, PLANES)
    bit = 1 << plane
    out = []
    for y in range(CELL):
        base = (row * CELL + y) * ROW_BYTES + col * (CELL // 2)
        for x in range(CELL):
            nib = font[base + x // 2]
            nib = nib & 0x0F if x % 2 == 0 else nib >> 4
            out.append(1 if nib & bit else 0)
    return tuple(out)


def write_plane(font: bytearray, index: int, bits: tuple[int, ...]) -> None:
    row, rem = divmod(index, IPR)
    col, plane = divmod(rem, PLANES)
    bit = 1 << plane
    for y in range(CELL):
        base = (row * CELL + y) * ROW_BYTES + col * (CELL // 2)
        for x in range(CELL):
            at = base + x // 2
            shift = 0 if x % 2 == 0 else 4
            nib = (font[at] >> shift) & 0x0F
            nib = (nib | bit) if bits[y * CELL + x] else (nib & ~bit & 0x0F)
            font[at] = (font[at] & (0xF0 >> shift if shift == 0 else 0x0F)) | (nib << shift)


def text_regions(members: dict[str, bytes]):
    """(file, start, end) spans walked exactly like the runtime tokenizer."""
    for name, offset, size in source_ranges():
        if name in members and offset + size <= len(members[name]):
            yield name, offset, offset + size
    from audit_dynamic_cache_requirements import active_slots
    for name, slots in active_slots(members, source_ranges()).items():
        data = members[name]
        for slot in slots:
            at = SLOT_BASE + slot * SLOT_SIZE
            block = data[at:at + SLOT_SIZE]
            end = block.index(0)
            if end:
                yield name, at, at + end
    exe = members[PSX]
    start = EXE_POOL[0]
    for cursor in range(EXE_POOL[0], EXE_POOL[1]):
        if exe[cursor]:
            continue
        if cursor > start:
            yield PSX, start, cursor
        start = cursor + 1


def walk_replace(buf: bytearray, start: int, end: int,
                 mapping: dict[int, bytes], lut: tuple[int, ...],
                 hits: Counter) -> None:
    i = start
    while i < end:
        width = 1 if buf[i] < 0xDD else 2
        if i + width > end:
            break
        tok = bytes(buf[i:i + width])
        idx = glyph_index(tok, lut)
        if idx is not None and idx in mapping:
            new = mapping[idx]
            if len(new) != width:
                raise SystemExit(f"GUARD: width change at 0x{i:X} idx {idx}")
            buf[i:i + width] = new
            hits[idx] += 1
        i += width


def main() -> None:
    base = members_of(BASE, BASE_SHA)
    v151 = members_of(GLYPH_SRC, GLYPH_SRC_SHA)
    exe = base[PSX]
    lut = struct.unpack_from(f"<{LOOKUP_N}H", exe, LOOKUP_SRC - RAM_TO_FILE)
    ranged = range_table_indices(exe)

    movers: list[tuple[str, int]] = []
    skipped_one_byte = 0
    for r in csv.DictReader(open(MANIFEST, encoding="utf-8-sig")):
        if r["kind"] == "existing_restored_static_conflict":
            old = int(r["old_physical_index"])
            if old < 220:
                # 1-byte code space: the code IS the index, every 1-byte slot
                # is referenced by the current script, and the home cells are
                # game-read.  These 39 stay dynamic; stage 2 problem.
                skipped_one_byte += 1
                continue
            movers.append((r["char"], old))
    if (len(movers), skipped_one_byte) != (123, 39):
        raise SystemExit(f"GUARD: expected 123+39 movers, got "
                         f"{len(movers)}+{skipped_one_byte}")
    for ch, old in movers:
        if old not in ranged:
            raise SystemExit(f"GUARD: {ch} old index {old} not in range table")

    # ------------------------------------------------------------------ refs
    referenced: set[int] = set()
    scratch = {n: bytearray(v) for n, v in base.items()}
    for name, s, e in text_regions(base):
        i = s
        data = base[name]
        while i < e:
            width = 1 if data[i] < 0xDD else 2
            if i + width > e:
                break
            idx = glyph_index(bytes(data[i:i + width]), lut)
            if idx is not None:
                referenced.add(idx)
            i += width

    # ---------------------------------------------------------- destinations
    audit = {}
    for r in csv.DictReader(open(CELL_AUDIT, encoding="utf-8-sig")):
        audit[(int(r["row"]), int(r["col"]))] = (
            int(r["text_reads"]), int(r["nontext_reads"]))
    def cell_ok(cell):
        t, n = audit.get(cell, (0, 1))
        return n == 0 and t > 0
    free_one, free_two = [], []
    for (row, col), _ in sorted(audit.items(),
                                key=lambda kv: -kv[1][0]):  # most text-evidence first
        if not cell_ok((row, col)):
            continue
        for plane in range(PLANES):
            idx = row * IPR + col * PLANES + plane
            if idx in referenced or idx in ranged:
                continue
            if remap_slot(exe, idx) is not None:
                continue
            if encode_index(idx) is None:
                continue
            (free_one if idx < 220 else free_two).append(idx)
    if len(free_two) < len(movers):
        raise SystemExit(f"GUARD: destinations short 2B {len(free_two)}/{len(movers)}")

    assign: dict[int, int] = {}
    for (ch, old), new in zip(movers, free_two):
        assign[old] = new
    if len(set(assign.values())) != len(assign):
        raise SystemExit("GUARD: duplicate destination")

    # ------------------------------------------------------------- glyph copy
    font = bytearray(base[COMM])
    v151_exe, v151_font = v151[PSX], v151[COMM]
    char_of = dict((old, ch) for ch, old in movers)
    for old, new in assign.items():
        bits = pbi.bitmap(v151_exe, v151_font, old)
        if bits is None or not any(bits):
            raise SystemExit(f"GUARD: v151 glyph missing for index {old} {char_of[old]}")
        before_others = [read_plane(bytes(font), (new // 4) * 4 + p)
                         for p in range(PLANES) if (new % 4) != p]
        write_plane(font, new, bits)
        if read_plane(bytes(font), new) != tuple(bits):
            raise SystemExit(f"GUARD: readback mismatch at {new}")
        after_others = [read_plane(bytes(font), (new // 4) * 4 + p)
                        for p in range(PLANES) if (new % 4) != p]
        if before_others != after_others:
            raise SystemExit(f"GUARD: sibling plane disturbed at {new}")

    # ---------------------------------------------------------- re-encode text
    mapping = {old: encode_index(new) for old, new in assign.items()}
    hits: Counter = Counter()
    for name, s, e in text_regions(base):
        walk_replace(scratch[name], s, e, mapping, lut, hits)
    scratch[COMM] = font

    # ------------------------------------------------------------ verify scan
    old_left, new_seen = Counter(), Counter()
    inv = {new: old for old, new in assign.items()}
    for name, s, e in text_regions({n: bytes(v) for n, v in scratch.items()}):
        data = scratch[name]
        i = s
        while i < e:
            width = 1 if data[i] < 0xDD else 2
            if i + width > e:
                break
            tok = bytes(data[i:i + width])
            if tok[0] not in (0xE9, 0xEA):
                idx = glyph_index(tok, lut)
                if idx in assign:
                    old_left[idx] += 1
                if idx in inv:
                    new_seen[idx] += 1
            i += width
    if old_left:
        raise SystemExit(f"GUARD: old direct refs remain {dict(old_left)}")
    if sum(new_seen.values()) != sum(hits.values()):
        raise SystemExit("GUARD: replaced count != new refs")

    # unchanged-byte guard: PSX.EXE outside pool+nothing else; COMM only cells
    diff_exe = [i for i, (a, b) in enumerate(zip(base[PSX], scratch[PSX])) if a != b]
    if diff_exe and not all(EXE_POOL[0] <= i < EXE_POOL[1] for i in diff_exe):
        raise SystemExit("GUARD: EXE changed outside string pool")
    allowed = set()
    for new in assign.values():
        row, rem = divmod(new, IPR)
        col = rem // PLANES
        for y in range(CELL):
            b0 = (row * CELL + y) * ROW_BYTES + col * (CELL // 2)
            allowed.update(range(b0, b0 + CELL // 2))
    diff_font = [i for i, (a, b) in enumerate(zip(base[COMM], bytes(font))) if a != b]
    if not all(i in allowed for i in diff_font):
        raise SystemExit("GUARD: COMM.IMG changed outside destination cells")

    # ------------------------------------------------------- effect measurement
    def unit_pressure(mem: dict[str, bytes], dead: set[int]) -> Counter:
        per = Counter()
        for name, s, e in text_regions(mem):
            data = mem[name]
            need = set()
            i = s
            while i < e:
                width = 1 if data[i] < 0xDD else 2
                if i + width > e:
                    break
                tok = bytes(data[i:i + width])
                idx = glyph_index(tok, lut)
                if idx is not None and idx in ranged and idx not in dead:
                    need.add(idx)
                elif tok[0] in (0xE9, 0xEA) and idx is not None:
                    need.add(idx)
                i += width
            per[f"{name}:{s:X}"] = len(need)
        return per
    before = unit_pressure(base, set())
    after = unit_pressure({n: bytes(v) for n, v in scratch.items()}, set(assign))
    b_max, a_max = max(before.values()), max(after.values())
    b_over = sum(1 for v in before.values() if v > 7)
    a_over = sum(1 for v in after.values() if v > 7)

    # ---------------------------------------------------------------- package
    out_members = {n: bytes(v) for n, v in scratch.items()}
    payload = b"".join(out_members[n] for n in sorted(out_members))
    tag = sha256(payload)[:8]
    out = OUT_DIR / f"arc1_v231_static_promotion_restored162_TEST_ONLY_{tag}.zip"
    with ZipFile(out, "w", ZIP_DEFLATED) as z:
        for n in sorted(out_members):
            z.writestr(n, out_members[n])
    with (ANALYSIS / "promotion_map.csv").open("w", newline="", encoding="utf-8-sig") as fh:
        w = csv.writer(fh)
        w.writerow(["char", "old_index", "new_index", "new_row", "new_col",
                    "new_plane", "old_code", "new_code", "replaced"])
        for ch, old in movers:
            new = assign[old]
            w.writerow([ch, old, new, new // IPR, (new % IPR) // 4, new % 4,
                        encode_index(old).hex().upper(),
                        mapping[old].hex().upper(), hits.get(old, 0)])
    report = [
        f"base={BASE.name} sha={BASE_SHA}",
        f"glyph_source={GLYPH_SRC.name}",
        f"movers=123 (39 one-byte deferred) replaced_total={sum(hits.values())}",
        f"movers_with_zero_direct_refs={sum(1 for _, o in movers if hits.get(o, 0) == 0)}",
        f"unit_cache_pressure_max before={b_max} after={a_max}",
        f"units_over_7 before={b_over} after={a_over}",
        f"exe_diff_bytes={len(diff_exe)} font_diff_bytes={len(diff_font)}",
        f"zip={out.name}",
        f"zip_sha256={sha256(out.read_bytes())}",
    ]
    (ANALYSIS / "build_report.txt").write_text("\n".join(report) + "\n", encoding="utf-8")
    print("\n".join(report))


if __name__ == "__main__":
    main()
