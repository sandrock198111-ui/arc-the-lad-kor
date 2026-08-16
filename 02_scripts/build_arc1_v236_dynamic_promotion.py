"""Build v236: promote high-frequency dynamic glyphs into static font cells.

v235 finished the cache relocation -- the world map renders its place names and
glyph/scenery cross-contamination is gone.  What remains is that the flight
scene zero-fills part of the rectangle and the cache never notices, because the
hit test reads only the owners array.

Fixing that needs a 32-byte recovery hook, and 32 bytes only exist if the cache
shrinks to 12 slots, which in turn needs the per-line cache pressure down at 12.
It is 28 today.  This build takes the first step: every dynamic glyph that can
be moved into a real font cell stops competing for cache slots.

Not all of them can move.  Measured on v235:

    direct 2-byte      65   movable
    E9/EA              33   movable
    mixed               1   movable
    direct 1-byte      39   NOT movable -- a 1-byte token cannot point at a
                            2-byte destination without shifting every pointer

and of the movable ones only those whose source id is recoverable from
source_manifest.csv can be rebuilt, because the glyph bitmap has to come from
the v190 Huffman library.  v231 pulled shapes out of the v151 font by index and
52 of 123 came out wrong; index is a point-in-time thing and the manifest is the
only durable link.  Everything not in the manifest is skipped rather than
guessed at.

Replacement is 2-byte to 2-byte -- both direct codes and E9/EA cache escapes --
so pointers, body lengths and file sizes are all unchanged.  The row-40 system,
the range table, the lookup table and the resident code are untouched.
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
from audit_dynamic_cache_requirements import glyph_index  # noqa: E402
import plan_arc1_v171_ui_asset_recovery as v171p  # noqa: E402
from build_arc1_v165_failclosed_cache import rows_to_bitmap  # noqa: E402
from build_arc1_v231_static_promotion_restored162 import (  # noqa: E402
    CELL_AUDIT, COMM, EXE_POOL, MANIFEST, PSX, encode_index, members_of,
    range_table_indices, read_plane, sha256, text_regions, write_plane,
)

ART = ROOT / "01_work/analysis/arc1_v190_dynamic_owner_repair"
OUT_DIR = ROOT / "03_output"
ANALYSIS = ROOT / "01_work/analysis/arc1_v236_dynamic_promotion"
ANALYSIS.mkdir(parents=True, exist_ok=True)

BASE = OUT_DIR / "arc1_v235_cache_row36_TEST_ONLY_1654F31B.zip"
BASE_SHA = "EBFD500237DC1C2827915CF240847FBEC09F50C0998FEF983572C9DF41D4D09E"


def huffman_shapes(wanted: set[int]) -> dict[int, tuple[int, ...]]:
    """Decode the v190 Huffman library for the requested source ids."""
    rows = tuple(struct.unpack(
        f"<{(ART / 'huffman_rows.bin').stat().st_size // 2}H",
        (ART / "huffman_rows.bin").read_bytes()))
    counts = (ART / "huffman_counts.bin").read_bytes()
    cps = tuple(struct.unpack(
        f"<{(ART / 'source_checkpoints.bin').stat().st_size // 2}H",
        (ART / "source_checkpoints.bin").read_bytes()))
    stream = (ART / "source_bitstream.bin").read_bytes()
    out: dict[int, tuple[int, ...]] = {}
    for sid in sorted(wanted):
        decoded = v171p.decode_huffman_source(sid, rows, counts, cps, stream)
        out[sid] = rows_to_bitmap(tuple(decoded[:CELL]))
    return out


def scan(mem: dict[str, bytes], lut, ranged):
    """Per-line dynamic demand, reference frequency, and 1-byte-referenced set."""
    units: list[set[int]] = []
    freq: Counter = Counter()
    one_byte: set[int] = set()
    for name, s, e in text_regions(mem):
        data = mem[name]
        need: set[int] = set()
        i = s
        while i < e:
            width = 1 if data[i] < 0xDD else 2
            if i + width > e:
                break
            tok = bytes(data[i:i + width])
            idx = glyph_index(tok, lut)
            if idx is not None and (tok[0] in (0xE9, 0xEA) or idx in ranged):
                need.add(idx)
                freq[idx] += 1
                if width == 1:
                    one_byte.add(idx)
            i += width
        if need:
            units.append(need)
    return units, freq, one_byte


def walk_replace(buf: bytearray, start: int, end: int,
                 mapping: dict[int, bytes], lut, hits: Counter) -> None:
    """Rewrite both direct codes and E9/EA escapes; widths must match."""
    i = start
    while i < end:
        width = 1 if buf[i] < 0xDD else 2
        if i + width > end:
            break
        tok = bytes(buf[i:i + width])
        if tok[0] != 0xE2:
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
    exe = base[PSX]
    lut = struct.unpack_from(f"<{LOOKUP_N}H", exe, LOOKUP_SRC - RAM_TO_FILE)
    ranged = range_table_indices(exe)

    units, freq, one_byte = scan(base, lut, ranged)

    manifest: dict[int, tuple[int, str]] = {}
    for r in csv.DictReader(open(MANIFEST, encoding="utf-8-sig")):
        raw = (r.get("old_physical_index") or "").strip()
        if raw.isdigit():
            manifest[int(raw)] = (int(r["source_id"]), r["char"])

    # movable: not referenced by any 1-byte token, and the glyph source is known
    movers: list[tuple[str, int, int]] = []
    for idx, _n in freq.most_common():
        if idx in one_byte or idx not in manifest:
            continue
        sid, ch = manifest[idx]
        movers.append((ch, idx, sid))
    if not movers:
        raise SystemExit("GUARD: no movable dynamic glyphs")

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

    movers = movers[:len(free_two)]
    assign = {old: new for (_ch, old, _sid), new in zip(movers, free_two)}
    if len(set(assign.values())) != len(assign):
        raise SystemExit("GUARD: duplicate destination")
    if set(assign) & set(assign.values()):
        raise SystemExit("GUARD: destination collides with a source index")

    shapes = huffman_shapes({sid for _ch, _old, sid in movers})
    font = bytearray(base[COMM])
    for ch, old, sid in movers:
        bits = shapes.get(sid)
        if bits is None or not any(bits):
            raise SystemExit(f"GUARD: huffman shape missing/blank for '{ch}' sid {sid}")
        new = assign[old]
        write_plane(font, new, tuple(bits))
        if read_plane(bytes(font), new) != tuple(bits):
            raise SystemExit(f"GUARD: readback mismatch at {new}")

    scratch = {n: bytearray(v) for n, v in base.items()}
    scratch[COMM] = font
    mapping = {old: encode_index(new) for old, new in assign.items()}
    if any(m is None or len(m) != 2 for m in mapping.values()):
        raise SystemExit("GUARD: destination is not a 2-byte code")
    hits: Counter = Counter()
    for name, s, e in text_regions(base):
        walk_replace(scratch[name], s, e, mapping, lut, hits)
    frozen = {n: bytes(v) for n, v in scratch.items()}

    left: Counter = Counter()
    for name, s, e in text_regions(frozen):
        data = frozen[name]
        i = s
        while i < e:
            width = 1 if data[i] < 0xDD else 2
            if i + width > e:
                break
            tok = bytes(data[i:i + width])
            if tok[0] != 0xE2:
                idx = glyph_index(tok, lut)
                if idx in assign:
                    left[idx] += 1
            i += width
    if left:
        raise SystemExit(f"GUARD: old refs remain {dict(list(left.items())[:6])}")

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
    diff_font = [i for i, (a, b) in enumerate(zip(base[COMM], frozen[COMM])) if a != b]
    if not all(i in allowed for i in diff_font):
        raise SystemExit("GUARD: COMM.IMG changed outside destination cells")
    for name in frozen:
        if len(frozen[name]) != len(base[name]):
            raise SystemExit(f"GUARD: size changed for {name}")

    after_units, _f, _o = scan(frozen, lut, ranged)
    before_max = max(len(u) for u in units)
    after_max = max(len(u) for u in after_units)
    fits12 = sum(1 for u in after_units if len(u) <= 12)

    payload = b"".join(frozen[n] for n in sorted(frozen))
    tag = sha256(payload)[:8]
    out = OUT_DIR / f"arc1_v236_dynamic_promotion_TEST_ONLY_{tag}.zip"
    with ZipFile(out, "w", ZIP_DEFLATED) as z:
        for n in sorted(frozen):
            z.writestr(n, frozen[n])
    with (ANALYSIS / "promotion_map.csv").open("w", newline="", encoding="utf-8-sig") as fh:
        w = csv.writer(fh)
        w.writerow(["char", "source_id", "old_index", "new_index", "new_row",
                    "new_col", "new_plane", "old_code", "new_code", "replaced"])
        for ch, old, sid in movers:
            new = assign[old]
            w.writerow([ch, sid, old, new, new // IPR, (new % IPR) // PLANES,
                        new % PLANES, (encode_index(old) or b"").hex().upper(),
                        mapping[old].hex().upper(), hits.get(old, 0)])
    report = [
        f"base={BASE.name} sha={BASE_SHA}",
        "glyph_source=v190 Huffman artifacts (manifest source_id, never index)",
        f"movers={len(movers)} of {len(free_two)} destinations available",
        f"skipped_one_byte_referenced={len(one_byte)}",
        f"skipped_no_manifest={sum(1 for i, _ in freq.most_common() if i not in one_byte and i not in manifest)}",
        f"replaced_total={sum(hits.values())}",
        f"unit_cache_pressure_max before={before_max} after={after_max}",
        f"units_fitting_12_slots after={fits12}/{len(after_units)}",
        f"exe_diff_bytes={len(diff_exe)} font_diff_bytes={len(diff_font)}",
        "row_system=40 untouched  range_table=untouched  lookup=untouched",
        f"zip={out.name}",
        f"zip_sha256={sha256(out.read_bytes())}",
    ]
    (ANALYSIS / "build_report.txt").write_text("\n".join(report) + "\n", encoding="utf-8")
    print("\n".join(report))


if __name__ == "__main__":
    main()
