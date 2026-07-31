"""Build v72 by relocating active high-row UI glyphs into safe low rows.

The common UI renderer stores the glyph V coordinate with an 8-bit store.
Glyph rows 22 and above therefore wrap and render unrelated texture data.
v72 keeps every accepted v71 string, icon, and code hook intact, copies the
58 active high-row glyph planes to verified blank planes below row 21, and
updates only their E9/EA lookup-table entries.
"""

from __future__ import annotations

import csv
import hashlib
import struct
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo


ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "03_output" / "ui_hud_e7_v71_leaf_font_ring_help_patch_only.zip"
OUTPUT = ROOT / "03_output" / "ui_hud_e7_v72_low_page_glyph_relocation_patch_only.zip"
SOURCE_MAP = ROOT / "05_docs" / "ui_glyph_store_v42_map.csv"
OUTPUT_MAP = ROOT / "05_docs" / "ui_glyph_store_v72_map.csv"
REPORT = ROOT / "01_work" / "analysis" / "ui_hud_e7_v72" / "build_report.txt"

BASE_SHA256 = "C9FE5D3F3521748CDD53A43A7A47895CC1747928D2804A9502D877B4D47A250D"
PSX_MEMBER = "PSX.EXE"
COMM_MEMBER = "COMM.IMG"
PSX_LOAD_BASE = 0x8011A800
LOOKUP_ADDRESS = 0x801A7520
LOOKUP_OFFSET = LOOKUP_ADDRESS - PSX_LOAD_BASE
LOOKUP_COUNT = 409
ROW_BYTES = 0x380
GLYPH_ROWS = 12
GLYPH_COLUMNS = 21
PLANES = 4
INDICES_PER_ROW = GLYPH_COLUMNS * PLANES

# EA 66 (leaf) already uses v71's dedicated low-row E9 75 glyph. EA 9A/EA 9B
# (L/V) are unused. Several other v42 high-row entries were already moved by
# later accepted builds, so the current v71 lookup table is authoritative.
EXCLUDED_HIGH_CODES = {"EA 66", "EA 9A", "EA 9B"}

# Verified blank, unmapped bitplanes below row 21. The list intentionally
# excludes one-byte/control planes and the relocated E7 icon planes.
DESTINATION_INDICES = (
    928, 929, 930, 931,
    1012, 1013, 1014, 1015,
    1439, 1521,
    1597, 1598, 1599, 1601, 1602, 1603, 1605, 1606, 1607,
    1609, 1610, 1611, 1613, 1614, 1615, 1617, 1618, 1619,
    1621, 1622, 1623, 1625, 1626, 1627,
    1681, 1682, 1683, 1685, 1686, 1687, 1689, 1690, 1691,
    1693, 1694, 1695, 1697, 1698, 1699, 1701, 1702, 1703,
    1705, 1706, 1707, 1709, 1710, 1711,
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def clone_info(info: ZipInfo) -> ZipInfo:
    copied = ZipInfo(info.filename, info.date_time)
    copied.compress_type = ZIP_DEFLATED
    copied.comment = info.comment
    copied.extra = info.extra
    copied.internal_attr = info.internal_attr
    copied.external_attr = info.external_attr
    copied.create_system = info.create_system
    copied.flag_bits = info.flag_bits
    return copied


def read_map() -> list[dict[str, str]]:
    with SOURCE_MAP.open(encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    if len(rows) != LOOKUP_COUNT:
        raise SystemExit(f"glyph map count differs: {len(rows)}")
    return rows


def get_pixel(data: bytes | bytearray, x: int, y: int) -> int:
    value = data[y * ROW_BYTES + x // 2]
    return value & 0x0F if x % 2 == 0 else value >> 4


def set_pixel(data: bytearray, x: int, y: int, value: int) -> None:
    offset = y * ROW_BYTES + x // 2
    if x % 2 == 0:
        data[offset] = (data[offset] & 0xF0) | (value & 0x0F)
    else:
        data[offset] = (data[offset] & 0x0F) | ((value & 0x0F) << 4)


def position(index: int) -> tuple[int, int, int]:
    row, remainder = divmod(index, INDICES_PER_ROW)
    column, plane = divmod(remainder, PLANES)
    return row, column, plane


def plane_rows(data: bytes | bytearray, index: int) -> tuple[str, ...]:
    row, column, plane = position(index)
    bit = 1 << plane
    return tuple(
        "".join(
            "#" if get_pixel(data, column * 12 + x, row * 12 + y) & bit else "."
            for x in range(12)
        )
        for y in range(12)
    )


def plane_is_blank(data: bytes | bytearray, index: int) -> bool:
    return all("#" not in row for row in plane_rows(data, index))


def copy_plane(data: bytearray, source: int, destination: int) -> None:
    source_row, source_column, source_plane = position(source)
    dest_row, dest_column, dest_plane = position(destination)
    source_bit = 1 << source_plane
    dest_bit = 1 << dest_plane
    if dest_row >= 21:
        raise SystemExit(f"destination row is not renderer-safe: {dest_row}")
    if not plane_is_blank(data, destination):
        raise SystemExit(f"destination is not blank: {destination}")
    source_rows = plane_rows(data, source)
    if all("#" not in row for row in source_rows):
        raise SystemExit(f"source glyph is blank: {source}")

    for y in range(12):
        for x in range(12):
            sx = source_column * 12 + x
            sy = source_row * 12 + y
            dx = dest_column * 12 + x
            dy = dest_row * 12 + y
            old = get_pixel(data, dx, dy)
            enabled = bool(get_pixel(data, sx, sy) & source_bit)
            new = old | dest_bit if enabled else old & ~dest_bit
            if (new & ~dest_bit) != (old & ~dest_bit):
                raise SystemExit("neighboring destination bitplane changed")
            set_pixel(data, dx, dy, new)


def virtual_table_index(code_hex: str) -> int:
    lead, trail = bytes.fromhex(code_hex)
    if lead == 0xE9:
        index = trail - 1
    elif lead == 0xEA:
        index = 254 + trail - 1
    else:
        raise ValueError(f"not an E9/EA virtual code: {code_hex}")
    if not 0 <= index < LOOKUP_COUNT:
        raise ValueError(f"virtual table index out of range: {code_hex}")
    return index


def write_output_map(
    rows: list[dict[str, str]], current: dict[str, int], remap: dict[str, int]
) -> None:
    output_rows: list[dict[str, str]] = []
    for row in rows:
        item = dict(row)
        code = item["virtual_code_hex"]
        physical_index = remap.get(code, current[code])
        if physical_index != int(item["physical_index"]):
            physical_row, column, plane = position(physical_index)
            item["physical_index"] = str(physical_index)
            item["row"] = str(physical_row)
            item["column"] = str(column)
            item["plane"] = str(plane)
            item["source_x"] = str(column * 12)
            item["source_y"] = str(physical_row * 12)
            item["provenance"] = (
                "v72_low_page_relocation"
                if code in remap
                else "v71_preserved_runtime_mapping"
            )
        output_rows.append(item)

    OUTPUT_MAP.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT_MAP.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=output_rows[0].keys())
        writer.writeheader()
        writer.writerows(output_rows)


def main() -> None:
    if sha256(BASE.read_bytes()) != BASE_SHA256:
        raise SystemExit("v71 base archive hash differs")

    rows = read_map()
    with ZipFile(BASE, "r") as source:
        infos = source.infolist()
        original = {info.filename: source.read(info.filename) for info in infos}
    members = dict(original)
    psx = bytearray(members[PSX_MEMBER])
    comm = bytearray(members[COMM_MEMBER])

    if LOOKUP_OFFSET + LOOKUP_COUNT * 2 > len(psx):
        raise SystemExit("lookup table lies outside PSX.EXE")

    current_indices = {
        row["virtual_code_hex"]: struct.unpack_from(
            "<H", psx, LOOKUP_OFFSET + index * 2
        )[0]
        for index, row in enumerate(rows)
    }
    high_rows = [
        row
        for row in rows
        if current_indices[row["virtual_code_hex"]] // INDICES_PER_ROW >= 22
        and row["virtual_code_hex"] not in EXCLUDED_HIGH_CODES
    ]
    destinations = DESTINATION_INDICES[: len(high_rows)]
    if len(high_rows) != 55 or len(destinations) != len(high_rows):
        raise SystemExit(
            f"current v71 relocation count differs: {len(high_rows)}"
        )
    mapped_indices = set(current_indices.values())
    if mapped_indices.intersection(destinations):
        raise SystemExit("destination overlaps an existing virtual mapping")
    if len(set(destinations)) != len(destinations):
        raise SystemExit("duplicate destination index")

    remap: dict[str, int] = {}
    source_rows_by_code: dict[str, tuple[str, ...]] = {}
    destination_cell_masks: dict[tuple[int, int], int] = {}
    for row, destination in zip(high_rows, destinations):
        code = row["virtual_code_hex"]
        source_index = current_indices[code]
        table_index = virtual_table_index(code)
        table_offset = LOOKUP_OFFSET + table_index * 2
        current_index = struct.unpack_from("<H", psx, table_offset)[0]
        if current_index != source_index:
            raise SystemExit(f"lookup source changed while building: {code}")

        dest_row, dest_column, dest_plane = position(destination)
        cell = (dest_row, dest_column)
        destination_cell_masks[cell] = (
            destination_cell_masks.get(cell, 0) | (1 << dest_plane)
        )
        source_rows_by_code[code] = plane_rows(comm, source_index)
        copy_plane(comm, source_index, destination)
        struct.pack_into("<H", psx, table_offset, destination)
        remap[code] = destination

    members[PSX_MEMBER] = bytes(psx)
    members[COMM_MEMBER] = bytes(comm)
    changed_members = [name for name in members if members[name] != original[name]]
    if set(changed_members) != {PSX_MEMBER, COMM_MEMBER}:
        raise SystemExit(f"unexpected changed members: {changed_members}")

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with ZipFile(OUTPUT, "w") as target:
        for info in infos:
            target.writestr(clone_info(info), members[info.filename])

    with ZipFile(OUTPUT, "r") as built:
        readback = {info.filename: built.read(info.filename) for info in built.infolist()}
    if set(readback) != set(members):
        raise SystemExit("ZIP member list differs")
    for name in members:
        if readback[name] != members[name]:
            raise SystemExit(f"ZIP readback differs: {name}")

    built_psx = readback[PSX_MEMBER]
    built_comm = readback[COMM_MEMBER]
    for code, destination in remap.items():
        table_offset = LOOKUP_OFFSET + virtual_table_index(code) * 2
        if struct.unpack_from("<H", built_psx, table_offset)[0] != destination:
            raise SystemExit(f"lookup readback differs: {code}")
        if plane_rows(built_comm, destination) != source_rows_by_code[code]:
            raise SystemExit(f"glyph plane readback differs: {code}")
    for (dest_row, dest_column), changed_mask in destination_cell_masks.items():
        for y in range(12):
            for x in range(12):
                px = dest_column * 12 + x
                py = dest_row * 12 + y
                if (
                    get_pixel(built_comm, px, py) & ~changed_mask
                    != get_pixel(original[COMM_MEMBER], px, py) & ~changed_mask
                ):
                    raise SystemExit(
                        f"neighboring plane readback differs: row {dest_row}, "
                        f"column {dest_column}"
                    )

    # v71's dedicated leaf path and the target item name must remain present.
    if built_psx.count(bytes.fromhex("E9 75")) != 4:
        raise SystemExit("dedicated leaf occurrence count differs")
    if built_psx.count(bytes.fromhex("EA 7C")) != 5:
        raise SystemExit("small-bomb glyph occurrence count differs")

    write_output_map(rows, current_indices, remap)
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(
        "\n".join(
            [
                "ui_hud_e7_v72 build report",
                f"base={BASE}",
                f"base_sha256={BASE_SHA256}",
                f"output={OUTPUT}",
                f"output_sha256={sha256(OUTPUT.read_bytes())}",
                "changed_members=PSX.EXE,COMM.IMG",
                "unchanged_members=all DAT members",
                f"lookup_offset=0x{LOOKUP_OFFSET:X}",
                f"relocated_glyphs={len(remap)}",
                "source_rows=31,32,33,38,39",
                "destination_rows=11,12,17,18,19,20",
                "excluded_high_codes=EA 66 (dedicated leaf), EA 9A/EA 9B (unused L/V)",
                "icon_tables=unchanged",
                "code_hooks=unchanged",
                "static_lookup_readback=PASS",
                "static_glyph_plane_readback=PASS",
                "neighboring_bitplane_preservation=PASS",
                "runtime_verification=PENDING",
                "",
            ]
        ),
        encoding="utf-8",
    )

    print(OUTPUT)
    print(f"SHA256 {sha256(OUTPUT.read_bytes())}")
    print(f"Relocated glyphs {len(remap)}")


if __name__ == "__main__":
    main()
