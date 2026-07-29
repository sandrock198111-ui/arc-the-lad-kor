"""Build the v86 cumulative patch from the runtime-proven v85 baseline.

This build has two narrowly scoped changes:

1. Repack every currently active high-row UI glyph into blank P6 texture
   planes and route only physical row 24 through the P6 renderer.
2. Patch the three untranslated dialogue blocks identified by savestate
   slots 1-3 through the existing E2 dialogue bank.

No ISO is built. Existing archive members are preserved byte-for-byte unless
they are explicitly listed in EXPECTED_CHANGED_OR_ADDED.
"""

from __future__ import annotations

import csv
import hashlib
import struct
import sys
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))

import build_ui_hud_e7_v83_p6_sidecar_renderer as v83  # noqa: E402
import build_ui_hud_e7_v85_p6_highram_bootstrap as v85  # noqa: E402


BASE = ROOT / "03_output" / "ui_hud_e7_v85_p6_highram_bootstrap_patch_only.zip"
OUTPUT = (
    ROOT
    / "03_output"
    / "ui_hud_e7_v86_p6_glyph_repack_slots_1_to_6_patch_only.zip"
)
ANALYSIS = (
    ROOT
    / "01_work"
    / "analysis"
    / "ui_hud_e7_v86_p6_glyph_repack_slots_1_to_6"
)
REPORT = ANALYSIS / "build_report.txt"
REMAP_CSV = ANALYSIS / "p6_glyph_remap.csv"
GLYPH_MAP = ROOT / "05_docs" / "ui_glyph_store_v42_map.csv"
CHARMAP = ROOT / "05_docs" / "korean_charmap_extended.csv"
S3051_SOURCE = ROOT / "01_work" / "32" / "S3051.DAT"

BASE_SHA256 = "D7D028F83E42EA54922A853250976ADFDE06BE1A3D36DE809E05B4733AC35582"
S3051_SHA256 = "A6DC6BD40F49526C39EE20D9C1990DA45860190F31F5E938E6039AFCF7C4BB1A"

PSX_MEMBER = "PSX.EXE"
COMM_MEMBER = "COMM.IMG"
S3032_MEMBER = "31/S3032.DAT"
S3051_MEMBER = "32/S3051.DAT"
EXPECTED_CHANGED_OR_ADDED = {
    PSX_MEMBER,
    COMM_MEMBER,
    S3032_MEMBER,
    S3051_MEMBER,
}

PSX_LOAD_BASE = 0x8011A800
LOOKUP_ADDRESS = 0x801A7520
LOOKUP_OFFSET = LOOKUP_ADDRESS - PSX_LOAD_BASE
LOOKUP_COUNT = 409

ROW_BYTES = 0x380
GLYPH_SIZE = 12
GLYPH_COLUMNS = 21
PLANES = 4
INDICES_PER_ROW = GLYPH_COLUMNS * PLANES

# Physical row 24 wraps to V=32. The P6 renderer changes the texture page and
# adds 40 pixels to U, so the bitmaps live at absolute x=1576+, y=288.
P6_ROW = 24
P6_PAGE_X = 1536
P6_PAGE_Y = 256
P6_U_ORIGIN = 40
P6_DESTINATION_START = P6_ROW * INDICES_PER_ROW

SLOT_BASE = 0x45000
SLOT_SIZE = 0x80
SLOT_COUNT = 79
FILLER = 0x9C
NEWLINE = b"\xE6\x01"

DIALOGUES = (
    {
        "member": S3032_MEMBER,
        "offset": 0x47994,
        "capacity": 40,
        "expected_hex": (
            "BB803425E601432039271E1F37E601DD1027301CDE22DE0E1CDD43DE0E"
            "2FDDB0DDE11E271E732637"
        ),
        "text": "야군\n알겠습니다.\n숲으로 가는 열차 탑승을 허가하겠습니다.",
    },
    {
        "member": S3032_MEMBER,
        "offset": 0x479EE,
        "capacity": 32,
        "expected_hex": (
            "BB803425E6011F351E243F412E28E601BEDD063038872F401B211B2289C23537"
        ),
        "text": "야군\n다만, 그곳은\n우리도 애를 먹는 곳입니다.",
    },
    {
        "member": S3051_MEMBER,
        "offset": 0x48E70,
        "capacity": 23,
        "expected_hex": "2E1C3F1F3930E601DD28461F2D3549541DA1DF61DF6137",
        "text": "이곳에서\n사라졌는데...",
    },
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def clone_info(info: ZipInfo, filename: str | None = None) -> ZipInfo:
    copied = ZipInfo(filename or info.filename, info.date_time)
    copied.compress_type = ZIP_DEFLATED
    copied.comment = info.comment
    copied.extra = info.extra
    copied.internal_attr = info.internal_attr
    copied.external_attr = info.external_attr
    copied.create_system = info.create_system
    copied.flag_bits = info.flag_bits
    return copied


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def position(index: int) -> tuple[int, int, int]:
    row, remainder = divmod(index, INDICES_PER_ROW)
    column, plane = divmod(remainder, PLANES)
    return row, column, plane


def get_pixel(data: bytes | bytearray, x: int, y: int) -> int:
    value = data[y * ROW_BYTES + x // 2]
    return value & 0x0F if x % 2 == 0 else value >> 4


def set_pixel(data: bytearray, x: int, y: int, value: int) -> None:
    offset = y * ROW_BYTES + x // 2
    if x % 2 == 0:
        data[offset] = (data[offset] & 0xF0) | (value & 0x0F)
    else:
        data[offset] = (data[offset] & 0x0F) | ((value & 0x0F) << 4)


def source_plane_rows(data: bytes | bytearray, index: int) -> tuple[str, ...]:
    row, column, plane = position(index)
    bit = 1 << plane
    return tuple(
        "".join(
            "#"
            if get_pixel(data, column * GLYPH_SIZE + x, row * GLYPH_SIZE + y)
            & bit
            else "."
            for x in range(GLYPH_SIZE)
        )
        for y in range(GLYPH_SIZE)
    )


def p6_coordinates(index: int) -> tuple[int, int, int]:
    row, column, plane = position(index)
    if row != P6_ROW:
        raise ValueError(f"not a P6 row-24 index: {index}")
    x = P6_PAGE_X + P6_U_ORIGIN + column * GLYPH_SIZE
    y = P6_PAGE_Y + ((row * GLYPH_SIZE) & 0xFF)
    return x, y, plane


def p6_plane_rows(data: bytes | bytearray, index: int) -> tuple[str, ...]:
    left, top, plane = p6_coordinates(index)
    bit = 1 << plane
    return tuple(
        "".join(
            "#" if get_pixel(data, left + x, top + y) & bit else "."
            for x in range(GLYPH_SIZE)
        )
        for y in range(GLYPH_SIZE)
    )


def copy_source_plane_to_p6(
    data: bytearray, source_index: int, destination_index: int
) -> set[int]:
    source_row, source_column, source_plane = position(source_index)
    source_bit = 1 << source_plane
    left, top, destination_plane = p6_coordinates(destination_index)
    destination_bit = 1 << destination_plane
    source_rows = source_plane_rows(data, source_index)
    if all("#" not in row for row in source_rows):
        raise SystemExit(f"source glyph is blank: {source_index}")

    touched: set[int] = set()
    for y in range(GLYPH_SIZE):
        for x in range(GLYPH_SIZE):
            sx = source_column * GLYPH_SIZE + x
            sy = source_row * GLYPH_SIZE + y
            dx = left + x
            dy = top + y
            old = get_pixel(data, dx, dy)
            if old & destination_bit:
                raise SystemExit(
                    f"P6 destination plane is not blank: index={destination_index} "
                    f"x={dx} y={dy} value={old}"
                )
            enabled = bool(get_pixel(data, sx, sy) & source_bit)
            new = old | destination_bit if enabled else old & ~destination_bit
            if (new & ~destination_bit) != (old & ~destination_bit):
                raise SystemExit("neighboring P6 destination plane changed")
            set_pixel(data, dx, dy, new)
            touched.add(dy * ROW_BYTES + dx // 2)
    return touched


def disk_id(slot: int) -> int:
    if not 0 <= slot < SLOT_COUNT:
        raise ValueError(slot)
    return slot + 0x81 if slot < 40 else slot + 0x82


def encode_dialogue(text: str, mapping: dict[str, bytes]) -> bytes:
    payload = bytearray()
    for char in text:
        if char == "\n":
            payload.extend(NEWLINE)
        elif char == " ":
            payload.append(FILLER)
        else:
            try:
                payload.extend(mapping[char])
            except KeyError as exc:
                raise SystemExit(f"missing Korean glyph mapping: {char!r}") from exc
    if len(payload) > SLOT_SIZE - 1:
        raise SystemExit(f"E2 payload overflow: {len(payload)} bytes: {text}")
    return bytes(payload)


def patch_dialogues(
    members: dict[str, bytes], mapping: dict[str, bytes]
) -> list[dict[str, object]]:
    targets = {
        S3032_MEMBER: bytearray(members[S3032_MEMBER]),
        S3051_MEMBER: bytearray(members[S3051_MEMBER]),
    }
    free_slots = {
        name: [
            slot
            for slot in range(SLOT_COUNT)
            if not any(
                data[
                    SLOT_BASE + slot * SLOT_SIZE :
                    SLOT_BASE + (slot + 1) * SLOT_SIZE
                ]
            )
        ]
        for name, data in targets.items()
    }
    results: list[dict[str, object]] = []
    for item in DIALOGUES:
        name = str(item["member"])
        data = targets[name]
        offset = int(item["offset"])
        capacity = int(item["capacity"])
        expected = bytes.fromhex(str(item["expected_hex"]))
        if len(expected) != capacity:
            raise SystemExit(f"expected dialogue length differs: {name} 0x{offset:X}")
        if data[offset : offset + capacity] != expected:
            raise SystemExit(f"dialogue source differs: {name} 0x{offset:X}")
        if data[offset + capacity : offset + capacity + 2] != b"\x00\x00":
            raise SystemExit(f"dialogue boundary differs: {name} 0x{offset:X}")
        if not free_slots[name]:
            raise SystemExit(f"no empty E2 slot: {name}")

        payload = encode_dialogue(str(item["text"]), mapping)
        slot = free_slots[name].pop(0)
        slot_offset = SLOT_BASE + slot * SLOT_SIZE
        data[slot_offset : slot_offset + SLOT_SIZE] = b"\x00" * SLOT_SIZE
        data[slot_offset : slot_offset + len(payload)] = payload
        data[slot_offset + SLOT_SIZE - 1] = capacity - 2
        data[offset : offset + 2] = bytes((0xE2, disk_id(slot)))
        results.append(
            {
                "member": name,
                "offset": offset,
                "capacity": capacity,
                "slot": slot,
                "disk_id": disk_id(slot),
                "payload": payload,
                "text": item["text"],
            }
        )
    members.update({name: bytes(data) for name, data in targets.items()})
    return results


def main() -> None:
    if sha256(BASE.read_bytes()) != BASE_SHA256:
        raise SystemExit("v85 base archive hash differs")
    if sha256(S3051_SOURCE.read_bytes()) != S3051_SHA256:
        raise SystemExit("current S3051.DAT source hash differs")

    with ZipFile(BASE, "r") as archive:
        infos = archive.infolist()
        original = {info.filename: archive.read(info.filename) for info in infos}
    if len(original) != 78 or len(original) != len(infos):
        raise SystemExit("v85 archive member set differs")
    for required in (PSX_MEMBER, COMM_MEMBER, S3032_MEMBER):
        if required not in original:
            raise SystemExit(f"missing v85 member: {required}")
    if S3051_MEMBER in original:
        raise SystemExit("v85 unexpectedly already contains S3051.DAT")

    members = dict(original)
    members[S3051_MEMBER] = S3051_SOURCE.read_bytes()
    psx_before = original[PSX_MEMBER]
    comm_before = original[COMM_MEMBER]
    psx = bytearray(psx_before)
    comm = bytearray(comm_before)

    glyph_rows = read_csv(GLYPH_MAP)
    if len(glyph_rows) != LOOKUP_COUNT:
        raise SystemExit(f"glyph map count differs: {len(glyph_rows)}")
    if LOOKUP_OFFSET + LOOKUP_COUNT * 2 > len(psx):
        raise SystemExit("lookup table exceeds PSX.EXE")

    current_indices = [
        struct.unpack_from("<H", psx, LOOKUP_OFFSET + index * 2)[0]
        for index in range(LOOKUP_COUNT)
    ]
    high_table_indices = [
        index
        for index, physical_index in enumerate(current_indices)
        if physical_index // INDICES_PER_ROW >= P6_ROW
    ]
    high_rows = sorted(
        {current_indices[index] // INDICES_PER_ROW for index in high_table_indices}
    )
    if len(high_table_indices) != 57 or high_rows != [31, 32, 33, 38, 39]:
        raise SystemExit(
            f"v85 high-glyph inventory differs: count={len(high_table_indices)} "
            f"rows={high_rows}"
        )

    destinations = [
        P6_DESTINATION_START + index for index in range(len(high_table_indices))
    ]
    if destinations[-1] // INDICES_PER_ROW != P6_ROW:
        raise SystemExit("P6 destination allocation overflow")

    remap_rows: list[dict[str, object]] = []
    allowed_comm_offsets: set[int] = set()
    allowed_psx_offsets: set[int] = set()
    source_bitmaps: dict[int, tuple[str, ...]] = {}
    for table_index, destination in zip(high_table_indices, destinations):
        source_index = current_indices[table_index]
        source_bitmaps[table_index] = source_plane_rows(comm, source_index)
        allowed_comm_offsets.update(
            copy_source_plane_to_p6(comm, source_index, destination)
        )
        table_offset = LOOKUP_OFFSET + table_index * 2
        struct.pack_into("<H", psx, table_offset, destination)
        allowed_psx_offsets.update((table_offset, table_offset + 1))
        map_row = glyph_rows[table_index]
        remap_rows.append(
            {
                "char": map_row["char"],
                "virtual_code_hex": map_row["virtual_code_hex"],
                "old_physical_index": source_index,
                "old_row": source_index // INDICES_PER_ROW,
                "new_physical_index": destination,
                "new_row": P6_ROW,
                "new_column": (destination % INDICES_PER_ROW) // PLANES,
                "new_plane": destination % PLANES,
            }
        )

    # v85's helper classifies rows 24..31 as P6. All repacked glyphs now live
    # in row 24, so narrow the classifier to row 24 only.
    old_instruction = struct.pack("<I", v83.i_type(0x0B, v83.A3, v83.A3, 8))
    new_instruction = struct.pack("<I", v83.i_type(0x0B, v83.A3, v83.A3, 1))
    old_sidecar = v83.SIDECAR_ADDRESS
    v83.SIDECAR_ADDRESS = v85.HIGH_SIDECAR
    try:
        expected_helper = v83.build_glyph_helper(v85.HIGH_GLYPH_HELPER)
    finally:
        v83.SIDECAR_ADDRESS = old_sidecar
    if expected_helper.count(old_instruction) != 1:
        raise SystemExit("P6 classifier instruction count differs")
    helper_offset = v85.file_offset(v85.SOURCE_START)
    if psx[helper_offset : helper_offset + len(expected_helper)] != expected_helper:
        raise SystemExit("v85 temporary glyph helper differs")
    classifier_relative = expected_helper.index(old_instruction)
    classifier_offset = helper_offset + classifier_relative
    psx[classifier_offset : classifier_offset + 4] = new_instruction
    allowed_psx_offsets.update(range(classifier_offset, classifier_offset + 4))

    members[PSX_MEMBER] = bytes(psx)
    members[COMM_MEMBER] = bytes(comm)

    charmap_rows = read_csv(CHARMAP)
    charmap = {
        row["char"]: bytes.fromhex(row["code_hex"]) for row in charmap_rows
    }
    dialogue_results = patch_dialogues(members, charmap)

    psx_diffs = {
        index
        for index, (before, after) in enumerate(zip(psx_before, members[PSX_MEMBER]))
        if before != after
    }
    if not psx_diffs or not psx_diffs <= allowed_psx_offsets:
        raise SystemExit(
            f"unexpected PSX.EXE offsets changed: "
            f"{sorted(psx_diffs - allowed_psx_offsets)[:20]}"
        )
    comm_diffs = {
        index
        for index, (before, after) in enumerate(zip(comm_before, members[COMM_MEMBER]))
        if before != after
    }
    if not comm_diffs or not comm_diffs <= allowed_comm_offsets:
        raise SystemExit(
            f"unexpected COMM.IMG offsets changed: "
            f"{sorted(comm_diffs - allowed_comm_offsets)[:20]}"
        )

    for table_index, destination in zip(high_table_indices, destinations):
        actual = struct.unpack_from(
            "<H", members[PSX_MEMBER], LOOKUP_OFFSET + table_index * 2
        )[0]
        if actual != destination:
            raise SystemExit(f"lookup readback differs: table {table_index}")
        if p6_plane_rows(members[COMM_MEMBER], destination) != source_bitmaps[table_index]:
            raise SystemExit(f"P6 glyph readback differs: table {table_index}")
    if (
        members[PSX_MEMBER][classifier_offset : classifier_offset + 4]
        != new_instruction
    ):
        raise SystemExit("P6 row-24 classifier readback differs")

    for result in dialogue_results:
        data = members[str(result["member"])]
        offset = int(result["offset"])
        slot = int(result["slot"])
        slot_offset = SLOT_BASE + slot * SLOT_SIZE
        if data[offset : offset + 2] != bytes((0xE2, int(result["disk_id"]))):
            raise SystemExit(f"E2 command readback differs: {result['member']}")
        payload = bytes(result["payload"])
        if data[slot_offset : slot_offset + len(payload)] != payload:
            raise SystemExit(f"E2 payload readback differs: {result['member']}")
        if data[slot_offset + SLOT_SIZE - 1] != int(result["capacity"]) - 2:
            raise SystemExit(f"E2 skip readback differs: {result['member']}")

    old_changed = {
        name
        for name in original
        if members[name] != original[name]
    }
    if old_changed != {PSX_MEMBER, COMM_MEMBER, S3032_MEMBER}:
        raise SystemExit(f"unexpected changed v85 members: {sorted(old_changed)}")

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    template_info = next(info for info in infos if info.filename == S3032_MEMBER)
    with ZipFile(OUTPUT, "w", compression=ZIP_DEFLATED, compresslevel=9) as target:
        for info in infos:
            target.writestr(clone_info(info), members[info.filename])
        target.writestr(
            clone_info(template_info, S3051_MEMBER),
            members[S3051_MEMBER],
        )

    with ZipFile(OUTPUT, "r") as built:
        built_infos = built.infolist()
        readback = {info.filename: built.read(info.filename) for info in built_infos}
    if len(built_infos) != 79 or len(readback) != 79:
        raise SystemExit("output ZIP must contain 79 unique members")
    if set(readback) != set(members):
        raise SystemExit("output ZIP member set differs")
    for name, expected in members.items():
        if readback[name] != expected:
            raise SystemExit(f"output ZIP readback differs: {name}")

    ANALYSIS.mkdir(parents=True, exist_ok=True)
    with REMAP_CSV.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(remap_rows[0]))
        writer.writeheader()
        writer.writerows(remap_rows)

    report_lines = [
        "ui_hud_e7_v86 P6 glyph repack + savestate slots 1-6 report",
        f"base={BASE}",
        f"base_sha256={BASE_SHA256}",
        f"output={OUTPUT}",
        f"output_sha256={sha256(OUTPUT.read_bytes())}",
        "changed_v85_members=PSX.EXE,COMM.IMG,31/S3032.DAT",
        "added_member=32/S3051.DAT",
        "unchanged_v85_members=75",
        f"repacked_glyphs={len(remap_rows)}",
        "source_rows=31,32,33,38,39",
        "destination_row=24",
        "destination_p6_cells=15",
        "p6_classifier=rows24..31 -> row24 only",
        f"psx_changed_bytes={len(psx_diffs)}",
        f"comm_changed_bytes={len(comm_diffs)}",
        "static_lookup_readback=PASS",
        "static_p6_bitmap_readback=PASS",
        "neighboring_archive_members=PASS",
        "dialogue_E2_readback=PASS",
        "runtime_verification=PENDING",
        "",
        "dialogues:",
    ]
    for result in dialogue_results:
        report_lines.append(
            f"- {result['member']} 0x{int(result['offset']):X} "
            f"slot={result['slot']} E2={int(result['disk_id']):02X} "
            f"text={str(result['text']).replace(chr(10), ' / ')}"
        )
    report_lines.extend(
        [
            "",
            "known_slot_4_to_6_targets:",
            "- 테 (EA 7F)",
            "- 폴 (EA 8B)",
            "- 잎 (EA 66)",
            "- 탄 (EA 7C)",
            "",
        ]
    )
    REPORT.write_text("\n".join(report_lines), encoding="utf-8")

    print(OUTPUT)
    print(f"SHA256 {sha256(OUTPUT.read_bytes())}")
    print("Members 79")
    print("Changed v85 members PSX.EXE, COMM.IMG, 31/S3032.DAT")
    print("Added member 32/S3051.DAT")
    print(f"Repacked glyphs {len(remap_rows)}")
    print("Static verification PASS")


if __name__ == "__main__":
    main()
