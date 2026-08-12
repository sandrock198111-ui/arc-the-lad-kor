"""Read-only audit of the ten user-supplied v163 DuckStation states.

The audit answers two separate questions which a screenshot alone cannot split:

1. Does a non-text sprite sample the five physical cache cells at
   page 15/1, U=4..63, V=224..235?
2. Do persistent text objects still reference a cache slot after that slot's
   owner has changed?

No game image, patch archive, or save state is modified.  All reports are
written below ``01_work/analysis/arc1_v163_runtime_states``.
"""
from __future__ import annotations

import csv
import hashlib
import struct
import sys
import zipfile
import zlib
from collections import defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))
from extract_savestate_vram import locate_vram  # noqa: E402

STATE_DIR = ROOT / "01_work/analysis/arc1_v163_runtime_states"
BUILD = ROOT / "03_output/arc1_v163_text_clut_classifier_773E3B82.zip"
BUILD_SHA256 = "773E3B82B58FBE9C836C96F34EA03C122847EC8BBD691AE4FDCFBA00D778FE63"
PLAN = ROOT / "01_work/analysis/dynamic_cache_v153_widthsafe"
REPORT = STATE_DIR / "runtime_audit.txt"
OBJECT_CSV = STATE_DIR / "text_objects.csv"
PACKET_CSV = STATE_DIR / "page15_packets.csv"
OT_CSV = STATE_DIR / "active_ot_packets.csv"
MONTAGE = STATE_DIR / "screenshots_montage.png"

PSX = "PSX.EXE"
RAM_DUMP_OFFSET = 0x1A62
RAM_SIZE = 2 * 1024 * 1024
VRAM_W = 1024
RAM_TO_FILE = 0x8011A800

SOURCE_BASE = 0x801A86EC
RESIDENT_BASE = 0x801FE3C4
CACHE_INDEX = 0x801FEE96
OWNERS = 0x801FEEBE
ACTIVE = 0x801FEEE8
NEXT_SLOT = 0x801FEEEC
SHADOW = 0x801FEEF8
CLASSIFIER = 0x801FF410
CLASSIFIER_N = 36
FONT_CLUT_TABLE = 0x801F2FFE

CACHE_SLOTS = 20
CACHE_CELLS = 5
PLANES = 4
CELL = 12
CELL_BYTES = 72
CACHE_X = 961
CACHE_Y = 480
CACHE_U = (4, 16, 28, 40, 52)
CACHE_V = 224
CACHE_U_END = CACHE_U[0] + CACHE_CELLS * CELL
CACHE_V_END = CACHE_V + CELL
FONT_CLUT_MIN = 0x7FC0
FONT_CLUT_MAX = 0x7FCF


def digest(path: Path) -> str:
    sha = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            sha.update(chunk)
    return sha.hexdigest().upper()


def u16(buf: bytes, at: int) -> int:
    return struct.unpack_from("<H", buf, at)[0]


def s16(buf: bytes, at: int) -> int:
    return struct.unpack_from("<h", buf, at)[0]


def u32(buf: bytes, at: int) -> int:
    return struct.unpack_from("<I", buf, at)[0]


def ram_at(address: int) -> int:
    return address & 0x1FFFFF


def source_at(runtime_address: int) -> int:
    return SOURCE_BASE - RAM_TO_FILE + runtime_address - RESIDENT_BASE


def vram_cell(vram: bytes, cell: int) -> bytes:
    x = CACHE_X + cell * 3
    return b"".join(
        vram[
            ((CACHE_Y + row) * VRAM_W + x) * 2:
            ((CACHE_Y + row) * VRAM_W + x) * 2 + 6
        ]
        for row in range(CELL)
    )


def overlaps_cache(u: int, v: int, width: int, height: int) -> bool:
    return (
        u < CACHE_U_END and u + width > CACHE_U[0]
        and v < CACHE_V_END and v + height > CACHE_V
    )


def cache_slot(u: int, clut: int) -> int | None:
    if u not in CACHE_U or not FONT_CLUT_MIN <= clut <= FONT_CLUT_MAX:
        return None
    return CACHE_U.index(u) * PLANES + ((clut - FONT_CLUT_MIN) & 3)


def png_chunk(kind: bytes, data: bytes) -> bytes:
    return (
        struct.pack(">I", len(data)) + kind + data
        + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)
    )


def write_montage(captures: list[Path]) -> None:
    """Combine ten 256x192 BGRA thumbnails into a 2x5 labelled-free contact sheet."""
    width, height = 256, 192
    columns, rows_n = 2, 5
    canvas_w, canvas_h = width * columns, height * rows_n
    images = [path.read_bytes() for path in captures]
    if any(len(blob) != width * height * 4 for blob in images):
        raise SystemExit("one or more thumbnail frames have an unexpected size")
    rows = bytearray()
    for out_y in range(canvas_h):
        rows.append(0)
        image_row, y = divmod(out_y, height)
        for image_col in range(columns):
            index = image_row * columns + image_col
            src = images[index][y * width * 4:(y + 1) * width * 4]
            for x in range(0, len(src), 4):
                blue, green, red, alpha = src[x:x + 4]
                rows.extend((red, green, blue, alpha))
    png = bytearray(b"\x89PNG\r\n\x1a\n")
    png.extend(png_chunk(b"IHDR", struct.pack(">IIBBBBB", canvas_w, canvas_h, 8, 6, 0, 0, 0)))
    png.extend(png_chunk(b"IDAT", zlib.compress(bytes(rows), 9)))
    png.extend(png_chunk(b"IEND", b""))
    MONTAGE.write_bytes(png)


def find_text_objects(ram: bytes) -> list[dict[str, object]]:
    """Find the verified [limit*52 packet array][68-byte header] structures."""
    objects: list[dict[str, object]] = []
    for header in range(0, RAM_SIZE - 68, 2):
        base_ptr = u32(ram, header)
        base = ram_at(base_ptr)
        limit = u16(ram, header + 4)
        count = u16(ram, header + 0x0A)
        if not 1 <= limit <= 128 or count > limit:
            continue
        if base + limit * 52 != header or base >= RAM_SIZE:
            continue
        if base_ptr & 0xFFE00000 not in (0x80000000, 0xA0000000):
            continue
        plausible = 0
        dynamic: list[dict[str, int]] = []
        glyphs: list[dict[str, int | str | None]] = []
        for index in range(count):
            meta = base + index * 52
            u, v = ram[meta + 0x28], ram[meta + 0x29]
            width, height = ram[meta + 0x2A], ram[meta + 0x2B] & 0x7F
            clut = u16(ram, meta + 0x30)
            if 0 < width <= 64 and 0 < height <= 64:
                plausible += 1
            slot = cache_slot(u, clut) if v == CACHE_V else None
            plane = (clut - FONT_CLUT_MIN) & 3
            physical = None if slot is not None else (v // CELL) * 84 + (u // CELL) * 4 + plane
            glyphs.append({
                "index": index,
                "meta": 0x80000000 + meta,
                "x": s16(ram, meta + 0x2C),
                "y": s16(ram, meta + 0x2E),
                "u": u,
                "v": v,
                "clut": clut,
                "slot": slot,
                "physical": physical,
            })
            if slot is not None:
                dynamic.append({
                    "index": index,
                    "meta": 0x80000000 + meta,
                    "x": s16(ram, meta + 0x2C),
                    "y": s16(ram, meta + 0x2E),
                    "u": u,
                    "v": v,
                    "clut": clut,
                    "slot": slot,
                })
        if count and plausible * 2 < count:
            continue
        objects.append({
            "header": 0x80000000 + header,
            "base": 0x80000000 + base,
            "limit": limit,
            "count": count,
            "source_pointer": u32(ram, header + 0x14),
            "dynamic": dynamic,
            "glyphs": glyphs,
            "low_tpage": u32(ram, header + 0x30),
            "high_tpage": u32(ram, header + 0x3C),
        })
    return objects


def token_identities(payload: bytes, lookup: tuple[int, ...]) -> list[tuple[str, int]]:
    identities: list[tuple[str, int]] = []
    cursor = 0
    while cursor < len(payload):
        lead = payload[cursor]
        width = 1 if lead < 0xDD else 2
        if cursor + width > len(payload):
            break
        if width == 1 and lead:
            identities.append(("static", lead - 1))
        elif width == 2:
            trail = payload[cursor + 1]
            if 0xDD <= lead <= 0xE8 and 1 <= trail <= 0xFE:
                identities.append(("static", (lead - 0xDD) * 255 + trail + 0xDB))
            elif lead in (0xE9, 0xEA) and 1 <= trail <= 0xFE:
                slot = (lead - 0xE9) * 254 + trail - 1
                if 0 <= slot < len(lookup):
                    value = lookup[slot]
                    identities.append(
                        ("dynamic", value & 0x7FFF) if value & 0x8000
                        else ("static", value)
                    )
        cursor += width
    return identities


def identity_text(identity: tuple[str, int], static_chars: dict[int, str],
                  source_chars: dict[int, str]) -> str:
    kind, value = identity
    return (source_chars if kind == "dynamic" else static_chars).get(value, f"<{kind[0]}:{value}>")


def match_source_entry(ram: bytes, obj: dict[str, object], lookup: tuple[int, ...],
                       owners: tuple[int, ...], static_chars: dict[int, str],
                       source_chars: dict[int, str]) -> dict[str, object] | None:
    """Match packet metadata to one null-delimited string in the object's table.

    Static glyph indices provide the anchor.  A dynamic identity is allowed to
    disagree with the slot's *current* owner; that disagreement is exactly the
    stale-cache condition this audit is looking for.
    """
    pointer = int(obj["source_pointer"])
    start = ram_at(pointer)
    if pointer & 0xFFE00000 not in (0x80000000, 0xA0000000) or start >= RAM_SIZE:
        return None
    metadata: list[tuple[str, int]] = []
    for glyph in obj["glyphs"]:  # type: ignore[union-attr]
        slot = glyph["slot"]
        if slot is None:
            metadata.append(("static", int(glyph["physical"])))
        else:
            metadata.append(("dynamic", owners[int(slot)]))

    best: dict[str, object] | None = None
    cursor = start
    limit = min(RAM_SIZE, start + 0x2000)
    candidate_n = 0
    while cursor < limit and candidate_n < 512:
        end = ram.find(b"\x00", cursor, limit)
        if end < 0:
            break
        payload = ram[cursor:end]
        cursor = end + 1
        if not payload:
            continue
        candidate_n += 1
        expected = token_identities(payload, lookup)
        if len(expected) != len(metadata):
            continue
        exact = 0
        structural = 0
        stale: list[tuple[int, int, int]] = []
        for index, (want, have) in enumerate(zip(expected, metadata)):
            if want == have:
                exact += 1
                structural += 1
            elif want[0] == have[0] == "dynamic":
                structural += 1
                stale.append((index, want[1], have[1]))
        score = (structural, exact, -len(stale), -abs((cursor - len(payload) - 1) - start))
        if best is None or score > best["score"]:
            best = {
                "score": score,
                "offset": 0x80000000 + cursor - len(payload) - 1,
                "expected": expected,
                "metadata": metadata,
                "stale": stale,
                "expected_text": "".join(
                    identity_text(item, static_chars, source_chars) for item in expected
                ),
                "current_text": "".join(
                    identity_text(item, static_chars, source_chars) for item in metadata
                ),
            }
    if best is None or best["score"][0] * 4 < len(metadata) * 3:
        return None
    return best


def dma_references(ram: bytes) -> dict[int, list[int]]:
    refs: dict[int, list[int]] = defaultdict(list)
    for source in range(0, RAM_SIZE - 4, 4):
        tag = u32(ram, source)
        count, target = tag >> 24, tag & 0x00FFFFFF
        valid = count == 0
        if source + 8 <= RAM_SIZE and count:
            command = ram[source + 7]
            primitive = command & 0xFC
            valid = (
                (primitive == 0x64 and count == 4)
                or (primitive in (0x74, 0x7C) and count == 3)
                or (primitive == 0x24 and count == 7)
                or (primitive == 0x2C and count == 9)
                or (primitive == 0x34 and count == 9)
                or (primitive == 0x3C and count == 12)
                or (u32(ram, source + 4) & 0xFF000000 == 0xE1000000 and count == 2)
            )
        if valid and target < RAM_SIZE and target not in (0, 0x00FFFFFF):
            refs[target].append(source)
    return refs


def trace_after_tpage(ram: bytes, tpage: int, refs: dict[int, list[int]]) -> list[dict[str, int]]:
    packets: list[dict[str, int]] = []
    current = u32(ram, tpage) & 0x00FFFFFF
    seen: set[int] = set()
    for _ in range(512):
        if current in seen or current in (0, 0x00FFFFFF) or current >= RAM_SIZE - 20:
            break
        seen.add(current)
        tag = u32(ram, current)
        command_word = u32(ram, current + 4)
        if command_word & 0xFF000000 == 0xE1000000:
            break
        command = ram[current + 7]
        if command in (0x64, 0x65, 0x66, 0x67):
            u, v = ram[current + 12], ram[current + 13]
            width, height = u16(ram, current + 16), u16(ram, current + 18)
            clut = u16(ram, current + 14)
            packets.append({
                "address": 0x80000000 + current,
                "command": command,
                "u": u,
                "v": v,
                "width": width,
                "height": height,
                "clut": clut,
                "overlap": int(overlaps_cache(u, v, width, height)),
                "text_clut": int(FONT_CLUT_MIN <= clut <= FONT_CLUT_MAX),
                "slot": cache_slot(u, clut) if v == CACHE_V else None,
                "incoming": len(refs.get(current, ())),
            })
        current = tag & 0x00FFFFFF
    return packets


def page15_textured_polygons(ram: bytes, refs: dict[int, list[int]]) -> list[dict[str, int]]:
    """Find FT3/FT4/GT3/GT4 packets whose embedded tpage is page 15/1.

    Textured polygons carry their own tpage instead of relying on DR_TPAGE.
    Battle tiles and range overlays therefore do not appear in the SPRT-only
    walk above.
    """
    layouts = {
        0x24: ((0x0C, 0x14, 0x1C), 0x16, 32, 7, "FT3"),
        0x2C: ((0x0C, 0x14, 0x1C, 0x24), 0x16, 40, 9, "FT4"),
        0x34: ((0x0C, 0x18, 0x24), 0x1A, 40, 9, "GT3"),
        0x3C: ((0x0C, 0x18, 0x24, 0x30), 0x1A, 52, 12, "GT4"),
    }
    found: list[dict[str, int]] = []
    for at in range(0, RAM_SIZE - 52, 4):
        command = ram[at + 7]
        layout = layouts.get(command & 0xFC)
        if layout is None:
            continue
        uv_offsets, tpage_offset, size, dma_words, kind = layout
        if at + size > RAM_SIZE:
            continue
        if u32(ram, at) >> 24 != dma_words:
            continue
        tpage = u16(ram, at + tpage_offset)
        # tx=15, ty=1, 4bpp.  Ignore only the two semi-transparency bits.
        if tpage & 0x19F != 0x01F:
            continue
        uv = [(ram[at + off], ram[at + off + 1]) for off in uv_offsets]
        min_u = min(point[0] for point in uv)
        max_u = max(point[0] for point in uv) + 1
        min_v = min(point[1] for point in uv)
        max_v = max(point[1] for point in uv) + 1
        overlap = (
            min_u < CACHE_U_END and max_u > CACHE_U[0]
            and min_v < CACHE_V_END and max_v > CACHE_V
        )
        found.append({
            "address": 0x80000000 + at,
            "kind": kind,
            "command": command,
            "tpage": tpage,
            "min_u": min_u,
            "max_u": max_u,
            "min_v": min_v,
            "max_v": max_v,
            "overlap": int(overlap),
            "incoming": len(refs.get(at, ())),
        })
    return found


def is_page15(tpage: int | None) -> bool:
    return tpage is not None and tpage & 0x19F == 0x01F


def trace_active_text_ot(ram: bytes) -> tuple[int, int, list[dict[str, object]]]:
    """Follow the current 512-entry ordering table from OT[0].

    The renderer's second argument selects an OT bucket; it is not the packet
    double-buffer index.  The table is reverse-linked from entry zero through
    the higher buckets, while ``context+0x870`` selects the 20-byte packet half.
    """
    context = u32(ram, ram_at(0x801F12EC))
    context_at = ram_at(context)
    if context & 0xFFE00000 not in (0x80000000, 0xA0000000) or context_at + 0x884 > RAM_SIZE:
        return context, -1, []
    parity = u16(ram, context_at + 0x870)
    rows: list[dict[str, object]] = []
    polygon_layouts = {
        0x24: ((0x0C, 0x14, 0x1C), 0x16, "FT3"),
        0x2C: ((0x0C, 0x14, 0x1C, 0x24), 0x16, "FT4"),
        0x34: ((0x0C, 0x18, 0x24), 0x1A, "GT3"),
        0x3C: ((0x0C, 0x18, 0x24, 0x30), 0x1A, "GT4"),
    }
    for buffer in (parity,):
        ot = context_at + 0x70
        current = u32(ram, ot) & 0x00FFFFFF
        current_tpage: int | None = None
        seen: set[int] = set()
        order = 0
        while current not in (0, 0x00FFFFFF) and current < RAM_SIZE - 8 and current not in seen:
            seen.add(current)
            tag = u32(ram, current)
            count = tag >> 24
            command_word = u32(ram, current + 4)
            command = ram[current + 7]
            row: dict[str, object] = {
                "buffer": buffer,
                "selected_buffer": int(buffer == parity),
                "order": order,
                "address": 0x80000000 + current,
                "dma_words": count,
                "command": command,
                "kind": "OTHER",
                "tpage": "" if current_tpage is None else current_tpage,
                "u": "",
                "v": "",
                "width": "",
                "height": "",
                "clut": "",
                "overlap": 0,
                "text_cache": 0,
                "slot": "",
            }
            if command_word & 0xFF000000 == 0xE1000000:
                current_tpage = command_word & 0xFFFF
                row.update(kind="DR_TPAGE", tpage=current_tpage)
            elif command & 0xFC in (0x64, 0x74, 0x7C):
                primitive = command & 0xFC
                expected_words = 4 if primitive == 0x64 else 3
                packet_size = 20 if primitive == 0x64 else 16
                if count != expected_words or current + packet_size > RAM_SIZE:
                    rows.append(row)
                    current = tag & 0x00FFFFFF
                    order += 1
                    if order >= 4096:
                        break
                    continue
                u, v = ram[current + 12], ram[current + 13]
                if primitive == 0x64:
                    width, height = u16(ram, current + 16), u16(ram, current + 18)
                    kind = "SPRT"
                elif primitive == 0x74:
                    width = height = 8
                    kind = "SPRT_8"
                else:
                    width = height = 16
                    kind = "SPRT_16"
                clut = u16(ram, current + 14)
                overlap = is_page15(current_tpage) and overlaps_cache(u, v, width, height)
                slot = cache_slot(u, clut) if v == CACHE_V and is_page15(current_tpage) else None
                row.update(
                    kind=kind, u=u, v=v, width=width, height=height,
                    clut=clut, overlap=int(overlap), text_cache=int(slot is not None),
                    slot="" if slot is None else slot,
                )
            else:
                layout = polygon_layouts.get(command & 0xFC)
                if layout is not None:
                    uv_offsets, tpage_offset, kind = layout
                    polygon_tpage = u16(ram, current + tpage_offset)
                    uv = [(ram[current + off], ram[current + off + 1]) for off in uv_offsets]
                    min_u, max_u = min(x for x, _ in uv), max(x for x, _ in uv) + 1
                    min_v, max_v = min(y for _, y in uv), max(y for _, y in uv) + 1
                    overlap = (
                        is_page15(polygon_tpage)
                        and min_u < CACHE_U_END and max_u > CACHE_U[0]
                        and min_v < CACHE_V_END and max_v > CACHE_V
                    )
                    row.update(
                        kind=kind, tpage=polygon_tpage, u=min_u, v=min_v,
                        width=max_u - min_u, height=max_v - min_v,
                        overlap=int(overlap),
                    )
            rows.append(row)
            current = tag & 0x00FFFFFF
            order += 1
            if order >= 4096:
                break
    return context, parity, rows


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if digest(BUILD) != BUILD_SHA256:
        raise SystemExit("v163 archive differs from the tested build")
    slot_number = lambda path: int(path.name.split(".", 1)[0][4:])
    states = sorted(STATE_DIR.glob("slot*.state.bin"), key=slot_number)
    captures = sorted(STATE_DIR.glob("slot*.capture.bin"), key=slot_number)
    if len(states) != 10 or len(captures) != 10:
        raise SystemExit(f"expected ten states/captures, found {len(states)}/{len(captures)}")
    write_montage(captures)

    with zipfile.ZipFile(BUILD) as archive:
        exe = archive.read(PSX)
    expected_classifier = exe[source_at(CLASSIFIER):source_at(CLASSIFIER) + CLASSIFIER_N]
    assignment_rows = list(csv.DictReader(
        (PLAN / "glyph_assignments.csv").open(encoding="utf-8-sig", newline="")
    ))
    source_chars = {
        int(row["source_id"]): row["char"]
        for row in assignment_rows if row.get("source_id")
    }
    static_chars = {
        int(row["physical_index"]): row["char"]
        for row in assignment_rows if row.get("kind") == "static" and row.get("physical_index")
    }

    object_rows: list[dict[str, object]] = []
    packet_rows: list[dict[str, object]] = []
    ot_rows: list[dict[str, object]] = []
    lines = [
        "v163 ten-state runtime audit",
        f"build={BUILD.name}",
        f"build_sha256={BUILD_SHA256}",
        "",
    ]
    all_nontext_overlaps = 0
    all_dynamic_refs = 0
    for state_path in states:
        state = state_path.read_bytes()
        vram_base = locate_vram(state)
        vram = state[vram_base:vram_base + VRAM_W * 512 * 2]
        if len(vram) != VRAM_W * 512 * 2:
            raise SystemExit(f"{state_path.name}: marker-selected VRAM is incomplete")
        ram = state[RAM_DUMP_OFFSET:RAM_DUMP_OFFSET + RAM_SIZE]
        if len(ram) != RAM_SIZE:
            raise SystemExit(f"{state_path.name}: RAM slice differs")
        live_classifier = ram[ram_at(CLASSIFIER):ram_at(CLASSIFIER) + CLASSIFIER_N]
        owners = struct.unpack_from(f"<{CACHE_SLOTS}H", ram, ram_at(OWNERS))
        lookup = struct.unpack_from("<409H", ram, ram_at(0x801A7520))
        active = u32(ram, ram_at(ACTIVE))
        next_slot = ram[ram_at(NEXT_SLOT)]
        shadow_matches = sum(
            ram[ram_at(SHADOW) + cell * CELL_BYTES:ram_at(SHADOW) + (cell + 1) * CELL_BYTES]
            == vram_cell(vram, cell)
            for cell in range(CACHE_CELLS)
        )
        owner_text = [
            f"{slot}:{source_chars.get(owner, '?')}({owner})"
            for slot, owner in enumerate(owners) if owner != 0xFFFF
        ]

        objects = find_text_objects(ram)
        object_tpages = {
            ram_at(int(obj["header"])) + delta
            for obj in objects for delta in (0x2C, 0x38)
        }
        object_dynamic = sum(len(obj["dynamic"]) for obj in objects)
        object_slots = sorted({
            int(item["slot"])
            for obj in objects for item in obj["dynamic"]  # type: ignore[index]
        })
        all_dynamic_refs += object_dynamic
        for obj in objects:
            dynamic = obj["dynamic"]  # type: ignore[assignment]
            source_match = match_source_entry(
                ram, obj, lookup, owners, static_chars, source_chars
            )
            object_rows.append({
                "state": state_path.stem,
                "header": f"0x{int(obj['header']):08X}",
                "base": f"0x{int(obj['base']):08X}",
                "limit": obj["limit"],
                "count": obj["count"],
                "source_pointer": f"0x{int(obj['source_pointer']):08X}",
                "dynamic_count": len(dynamic),
                "dynamic_slots": " ".join(str(item["slot"]) for item in dynamic),
                "matched_source": "" if source_match is None else f"0x{int(source_match['offset']):08X}",
                "source_match_score": "" if source_match is None else "/".join(
                    str(value) for value in source_match["score"][:3]
                ),
                "source_match": "" if source_match is None else source_match["expected_text"],
                "packet_text_now": "" if source_match is None else source_match["current_text"],
                "stale_dynamic_count": "" if source_match is None else len(source_match["stale"]),
                "stale_dynamic": "" if source_match is None else " ".join(
                    f"i{index}:{source_chars.get(want, '?')}({want})->{source_chars.get(have, '?')}({have})"
                    for index, want, have in source_match["stale"]
                ),
                "dynamic_packets": " ".join(
                    f"{item['index']}@0x{item['meta']:08X}:xy{item['x']},{item['y']}:"
                    f"U{item['u']}:C{item['clut']:04X}:S{item['slot']}"
                    for item in dynamic
                ),
            })

        refs = dma_references(ram)
        context, parity, active_ot = trace_active_text_ot(ram)
        for row in active_ot:
            ot_rows.append({"state": state_path.stem, **row})
        selected_ot = [row for row in active_ot if row["selected_buffer"]]
        selected_overlap = [row for row in selected_ot if row["overlap"]]
        selected_nontext_overlap = [
            row for row in selected_overlap if not row["text_cache"]
        ]
        tpages = [
            at for at in range(0, RAM_SIZE - 12, 4)
            if u32(ram, at + 4) == 0xE100001F
        ]
        state_nontext = 0
        state_text = 0
        state_other_overlap = 0
        for tpage in tpages:
            packets = trace_after_tpage(ram, tpage, refs)
            for packet in packets:
                if packet["slot"] is not None:
                    state_text += 1
                if packet["overlap"] and not packet["text_clut"]:
                    state_nontext += 1
                if packet["overlap"] and packet["slot"] is None:
                    state_other_overlap += 1
                packet_rows.append({
                    "kind": "SPRT",
                    "state": state_path.stem,
                    "tpage": f"0x{0x80000000 + tpage:08X}",
                    "tpage_incoming": len(refs.get(tpage, ())),
                    "tpage_is_text_object": int(tpage in object_tpages),
                    **{
                        key: ("" if value is None else value)
                        for key, value in packet.items()
                    },
                })
        polygons = page15_textured_polygons(ram, refs)
        live_polygons = [row for row in polygons if row["incoming"]]
        overlap_polygons = [row for row in polygons if row["overlap"]]
        live_overlap_polygons = [
            row for row in polygons if row["overlap"] and row["incoming"]
        ]
        for polygon in polygons:
            packet_rows.append({
                "kind": polygon["kind"],
                "state": state_path.stem,
                "tpage": f"0x{polygon['tpage']:04X}",
                "tpage_incoming": "",
                "tpage_is_text_object": 0,
                "address": f"0x{polygon['address']:08X}",
                "command": polygon["command"],
                "u": polygon["min_u"],
                "v": polygon["min_v"],
                "width": polygon["max_u"] - polygon["min_u"],
                "height": polygon["max_v"] - polygon["min_v"],
                "clut": "",
                "overlap": polygon["overlap"],
                "text_clut": 0,
                "slot": "",
                "incoming": polygon["incoming"],
            })
        all_nontext_overlaps += state_nontext
        lines.extend((
            state_path.name,
            f"  v163_classifier_live={live_classifier == expected_classifier}",
            f"  cache_owners={' '.join(owner_text) or 'none'}",
            f"  active=0x{active:08X} next_slot={next_slot}",
            f"  shadow_equals_VRAM={shadow_matches}/{CACHE_CELLS}",
            f"  text_objects={len(objects)} dynamic_packet_metadata={object_dynamic} slots={object_slots}",
            f"  page15_tpages={len(tpages)} traced_text_packets={state_text}",
            f"  cache_overlap_nontext_packets={state_nontext}",
            f"  cache_overlap_other_packets={state_other_overlap}",
            f"  page15_textured_polygons={len(polygons)} live_by_DMA_ref={len(live_polygons)}",
            f"  cache_overlap_polygons={len(overlap_polygons)} live_by_DMA_ref={len(live_overlap_polygons)}",
            f"  gpu_context=0x{context:08X} parity={parity} selected_OT_packets={len(selected_ot)}",
            f"  selected_OT_cache_overlaps={len(selected_overlap)} nontext={len(selected_nontext_overlap)}",
            "",
        ))

    with OBJECT_CSV.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(object_rows[0]))
        writer.writeheader()
        writer.writerows(object_rows)
    with PACKET_CSV.open("w", encoding="utf-8-sig", newline="") as handle:
        packet_fields = (
            "kind", "state", "tpage", "tpage_incoming", "tpage_is_text_object",
            "address", "command", "u", "v", "width", "height", "clut",
            "overlap", "text_clut", "slot", "incoming",
        )
        writer = csv.DictWriter(handle, fieldnames=packet_fields)
        writer.writeheader()
        writer.writerows(packet_rows)
    with OT_CSV.open("w", encoding="utf-8-sig", newline="") as handle:
        ot_fields = (
            "state", "buffer", "selected_buffer", "order", "address", "dma_words",
            "command", "kind", "tpage", "u", "v", "width", "height", "clut",
            "overlap", "text_cache", "slot",
        )
        writer = csv.DictWriter(handle, fieldnames=ot_fields)
        writer.writeheader()
        writer.writerows(ot_rows)
    lines.extend((
        "aggregate",
        f"  dynamic_packet_metadata={all_dynamic_refs}",
        f"  cache_overlap_nontext_packets={all_nontext_overlaps}",
        f"  montage={MONTAGE.name}",
    ))
    REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
