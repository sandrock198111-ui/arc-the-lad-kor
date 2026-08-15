#!/usr/bin/env python3
"""Build v232: v231 with the correct glyph source and E9/EA left untouched.

v231 failed on hardware (states HASH-46CF6CB77FE1304F): migrated glyphs drew
as the WRONG pictures (kanji, fragments).  Root cause: v231 read glyph pixels
from the v151 COMM.IMG at `old_physical_index`, but that index describes the
v163-era layout — v153/v158 had re-arranged the font between v151 and v163, so
the same index held a different glyph in v151.  The VRAM/disk comparison shows
upload worked perfectly; the pixels written were simply the wrong glyphs.

Fixes over v231 (same migration set, same destinations):

  1. Glyph source is the resident Huffman library of the CURRENT build chain
     (v190 artifacts), decoded per source_id with the proven
     plan_arc1_v171_ui_asset_recovery.decode_huffman_source /
     build_arc1_v165_failclosed_cache.rows_to_bitmap pair.  These shapes are
     exactly what the dynamic cache has been drawing on hardware since v165c.
  2. walk_replace skips E9/EA tokens.  v231 also re-encoded E9/EA occurrences
     whose lookup resolved to a migrated old index; that silently widened the
     change beyond the plan.  E9/EA occurrences keep rendering via the cache.
  3. The report records, per glyph, whether the v151 cell at old_physical_index
     matched the Huffman shape (documenting the v231 mistake).
"""
from __future__ import annotations

import csv
import struct
import sys
from collections import Counter
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))
sys.path.insert(0, str(ROOT / "06_tools/python_packages"))

from plan_bulk_insertion import (  # noqa: E402
    CELL, IPR, LOOKUP_N, LOOKUP_SRC, PLANES, RAM_TO_FILE, remap_slot,
)
from audit_dynamic_cache_requirements import glyph_index, source_ranges  # noqa: E402
import plan_bulk_insertion as pbi  # noqa: E402
import plan_arc1_v171_ui_asset_recovery as v171p  # noqa: E402
from build_arc1_v165_failclosed_cache import rows_to_bitmap  # noqa: E402
from build_arc1_v231_static_promotion_restored162 import (  # noqa: E402
    BASE, BASE_SHA, CELL_AUDIT, COMM, EXE_POOL, GLYPH_SRC, GLYPH_SRC_SHA,
    MANIFEST, PSX, encode_index, members_of, range_table_indices, read_plane,
    sha256, text_regions, write_plane,
)

ART = ROOT / "01_work/analysis/arc1_v190_dynamic_owner_repair"
OUT_DIR = ROOT / "03_output"
ANALYSIS = ROOT / "01_work/analysis/arc1_v232_static_promotion"
ANALYSIS.mkdir(parents=True, exist_ok=True)


def huffman_shapes() -> dict[int, tuple[int, ...]]:
    rows = tuple(struct.unpack(
        f"<{(ART / 'huffman_rows.bin').stat().st_size // 2}H",
        (ART / "huffman_rows.bin").read_bytes()))
    counts = (ART / "huffman_counts.bin").read_bytes()
    cps = tuple(struct.unpack(
        f"<{(ART / 'source_checkpoints.bin').stat().st_size // 2}H",
        (ART / "source_checkpoints.bin").read_bytes()))
    stream = (ART / "source_bitstream.bin").read_bytes()
    out: dict[int, tuple[int, ...]] = {}
    for r in csv.DictReader(open(MANIFEST, encoding="utf-8-sig")):
        if r["kind"] != "existing_restored_static_conflict":
            continue
        sid = int(r["source_id"])
        decoded = v171p.decode_huffman_source(sid, rows, counts, cps, stream)
        out[int(r["old_physical_index"])] = rows_to_bitmap(tuple(decoded[:CELL]))
    return out


def walk_replace_direct_only(buf: bytearray, start: int, end: int,
                             mapping: dict[int, bytes], lut: tuple[int, ...],
                             hits: Counter) -> None:
    i = start
    while i < end:
        width = 1 if buf[i] < 0xDD else 2
        if i + width > end:
            break
        if buf[i] not in (0xE9, 0xEA):  # E9/EA stay on the cache path
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
                skipped_one_byte += 1
                continue
            movers.append((r["char"], old))
    if (len(movers), skipped_one_byte) != (123, 39):
        raise SystemExit(f"GUARD: expected 123+39, got {len(movers)}+{skipped_one_byte}")
    for ch, old in movers:
        if old not in ranged:
            raise SystemExit(f"GUARD: {ch} old index {old} not in range table")

    referenced: set[int] = set()
    for name, s, e in text_regions(base):
        data = base[name]
        i = s
        while i < e:
            width = 1 if data[i] < 0xDD else 2
            if i + width > e:
                break
            idx = glyph_index(bytes(data[i:i + width]), lut)
            if idx is not None:
                referenced.add(idx)
            i += width

    audit = {}
    for r in csv.DictReader(open(CELL_AUDIT, encoding="utf-8-sig")):
        audit[(int(r["row"]), int(r["col"]))] = (
            int(r["text_reads"]), int(r["nontext_reads"]))
    free_two: list[int] = []
    for (row, col), (t, n) in sorted(audit.items(), key=lambda kv: -kv[1][0]):
        if n != 0 or t <= 0:
            continue
        for plane in range(PLANES):
            idx = row * IPR + col * PLANES + plane
            if idx < 220 or idx in referenced or idx in ranged:
                continue
            if remap_slot(exe, idx) is not None:
                continue
            if encode_index(idx) is None:
                continue
            free_two.append(idx)
    if len(free_two) < len(movers):
        raise SystemExit(f"GUARD: destinations short {len(free_two)}/{len(movers)}")
    assign = {old: new for (ch, old), new in zip(movers, free_two)}
    if len(set(assign.values())) != len(assign):
        raise SystemExit("GUARD: duplicate destination")

    shapes = huffman_shapes()
    font = bytearray(base[COMM])
    v151_mismatch = 0
    for old, new in assign.items():
        bits = shapes.get(old)
        if bits is None or not any(bits):
            raise SystemExit(f"GUARD: huffman shape missing for old index {old}")
        legacy = pbi.bitmap(v151[PSX], v151[COMM], old)
        if legacy is None or tuple(legacy) != tuple(bits):
            v151_mismatch += 1  # documents the v231 bug; informational only
        write_plane(font, new, tuple(bits))
        if read_plane(bytes(font), new) != tuple(bits):
            raise SystemExit(f"GUARD: readback mismatch at {new}")

    scratch = {n: bytearray(v) for n, v in base.items()}
    scratch[COMM] = font
    mapping = {old: encode_index(new) for old, new in assign.items()}
    hits: Counter = Counter()
    for name, s, e in text_regions(base):
        walk_replace_direct_only(scratch[name], s, e, mapping, lut, hits)

    old_left, new_seen = Counter(), Counter()
    inv = {new: old for old, new in assign.items()}
    frozen = {n: bytes(v) for n, v in scratch.items()}
    for name, s, e in text_regions(frozen):
        data = frozen[name]
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

    diff_exe = [i for i, (a, b) in enumerate(zip(base[PSX], frozen[PSX])) if a != b]
    if diff_exe and not all(EXE_POOL[0] <= i < EXE_POOL[1] for i in diff_exe):
        raise SystemExit("GUARD: EXE changed outside string pool")
    allowed = set()
    for new in assign.values():
        row, rem = divmod(new, IPR)
        col = rem // PLANES
        for y in range(CELL):
            b0 = (row * CELL + y) * 896 + col * (CELL // 2)
            allowed.update(range(b0, b0 + CELL // 2))
    diff_font = [i for i, (a, b) in enumerate(zip(base[COMM], bytes(font))) if a != b]
    if not all(i in allowed for i in diff_font):
        raise SystemExit("GUARD: COMM.IMG changed outside destination cells")

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
                if idx is not None and (
                        (tok[0] in (0xE9, 0xEA)) or (idx in ranged and idx not in dead)):
                    need.add(idx)
                i += width
            per[f"{name}:{s:X}"] = len(need)
        return per
    before = unit_pressure(base, set())
    after = unit_pressure(frozen, set(assign))

    payload = b"".join(frozen[n] for n in sorted(frozen))
    tag = sha256(payload)[:8]
    out = OUT_DIR / f"arc1_v232_static_promotion_huffman_source_TEST_ONLY_{tag}.zip"
    with ZipFile(out, "w", ZIP_DEFLATED) as z:
        for n in sorted(frozen):
            z.writestr(n, frozen[n])
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
        "glyph_source=v190 Huffman artifacts (resident library, hardware-proven)",
        f"v151_cell_would_have_been_wrong_for={v151_mismatch}/123 glyphs (v231 bug)",
        f"movers=123 (39 one-byte deferred) replaced_total={sum(hits.values())}",
        f"unit_cache_pressure_max before={max(before.values())} after={max(after.values())}",
        f"units_over_7 before={sum(1 for v in before.values() if v > 7)} "
        f"after={sum(1 for v in after.values() if v > 7)}",
        f"exe_diff_bytes={len(diff_exe)} font_diff_bytes={len(diff_font)}",
        f"zip={out.name}",
        f"zip_sha256={sha256(out.read_bytes())}",
    ]
    (ANALYSIS / "build_report.txt").write_text("\n".join(report) + "\n", encoding="utf-8")
    print("\n".join(report))


if __name__ == "__main__":
    main()
