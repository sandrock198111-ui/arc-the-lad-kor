"""Build v170 by restoring the project's proven blank 0x9C space plane.

v159 restored the whole low-page font grid from the untouched disc.  That also
restored the original Japanese glyph at physical index 155, even though every
Korean-text builder treats code 0x9C (index 155) as a six-pixel blank space and
padding byte.  The twelve-pixel sprite then visibly overlaps the next glyph.

This build changes only that one bitplane in COMM.IMG, reproducing v151's blank
plane exactly.  PSX.EXE, text, cache geometry and every other font plane remain
byte-identical to v169.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo


ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "03_output/arc1_v169_e1_control_glyph_dispatch_218D38D2.zip"
BASE_SHA256 = "218D38D21FED1D20E79483D657ED2E31D86425DA644F88322461F18BC3C9D4B0"
CONTROL = ROOT / "03_output/arc1_v151_free_the_sprite_cell_A4358FEE.zip"
CONTROL_SHA256 = "A4358FEE5FEA4964C9DD376B630894EB5EC133EFEEDD9E5E85BBC5FDD8CA1A46"
ORIGINAL = ROOT / "00_original/arc.zip"
ORIGINAL_SHA256 = "AE9F4366A1E7DA3805BB3BED3DDA9567E4CD4E669AF890E4E2A620D7861F11DD"

OUT_DIR = ROOT / "03_output"
OUT_STEM = "arc1_v170_restore_blank_space_filler"
ANALYSIS = ROOT / "01_work/analysis/arc1_v170_restore_blank_space_filler"
REPORT = ANALYSIS / "build_report.txt"
EXPECTED = ANALYSIS / "expected_writes.csv"

COMM = "COMM.IMG"
COMM_ROW_BYTES = 896
CELL = 12
IPR = 84
PLANES = 4
SPACE_CODE = 0x9C
SPACE_INDEX = SPACE_CODE - 1


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def clone(info: ZipInfo) -> ZipInfo:
    result = ZipInfo(info.filename, info.date_time)
    for attr in (
        "compress_type", "comment", "extra", "create_system", "create_version",
        "extract_version", "flag_bits", "volume", "internal_attr", "external_attr",
    ):
        setattr(result, attr, getattr(info, attr))
    return result


def plane_bitmap(font: bytes | bytearray, index: int) -> tuple[int, ...]:
    row, within = divmod(index, IPR)
    column, plane = divmod(within, PLANES)
    result: list[int] = []
    for y in range(CELL):
        for x in range(CELL):
            byte = font[(row * CELL + y) * COMM_ROW_BYTES + column * 6 + x // 2]
            nibble = (byte >> (4 * (x & 1))) & 0xF
            result.append((nibble >> plane) & 1)
    return tuple(result)


def clear_plane(font: bytearray, index: int) -> None:
    row, within = divmod(index, IPR)
    column, plane = divmod(within, PLANES)
    for y in range(CELL):
        for x in range(CELL):
            at = (row * CELL + y) * COMM_ROW_BYTES + column * 6 + x // 2
            shift = 4 * (x & 1)
            mask = 1 << (shift + plane)
            font[at] &= ~mask


def main() -> None:
    for path, expected in (
        (BASE, BASE_SHA256), (CONTROL, CONTROL_SHA256), (ORIGINAL, ORIGINAL_SHA256)
    ):
        if digest(path.read_bytes()) != expected:
            raise SystemExit(f"archive hash differs: {path.name}")

    with ZipFile(BASE) as archive:
        infos = archive.infolist()
        members = {info.filename: archive.read(info.filename) for info in infos}
    with ZipFile(CONTROL) as archive:
        control_font = archive.read(COMM)
    with ZipFile(ORIGINAL) as archive:
        original_font = archive.read(COMM)

    before = dict(members)
    font = bytearray(members[COMM])
    before_font = bytes(font)
    original_plane = plane_bitmap(original_font, SPACE_INDEX)
    control_plane = plane_bitmap(control_font, SPACE_INDEX)
    current_plane = plane_bitmap(font, SPACE_INDEX)
    if sum(original_plane) != 29:
        raise SystemExit("untouched space-index plane is not the measured 29-pixel glyph")
    if any(control_plane):
        raise SystemExit("v151 control space-index plane is not blank")
    if current_plane != original_plane:
        raise SystemExit("v169 space-index plane does not match the untouched glyph")

    clear_plane(font, SPACE_INDEX)
    if plane_bitmap(font, SPACE_INDEX) != control_plane:
        raise SystemExit("cleared space-index plane does not match v151")

    changed_offsets = [
        index for index, (left, right) in enumerate(zip(before_font, font))
        if left != right
    ]
    if not changed_offsets:
        raise SystemExit("COMM.IMG did not change")
    row, within = divmod(SPACE_INDEX, IPR)
    column, plane = divmod(within, PLANES)
    allowed_offsets = {
        (row * CELL + y) * COMM_ROW_BYTES + column * 6 + x // 2
        for y in range(CELL) for x in range(CELL)
    }
    if not set(changed_offsets) <= allowed_offsets:
        raise SystemExit("COMM.IMG diff escaped the physical index 155 cell")
    for at in changed_offsets:
        xor = before_font[at] ^ font[at]
        if xor & ~0x88 or font[at] & xor:
            raise SystemExit(f"diff at 0x{at:X} changes something besides clearing plane 3")

    members[COMM] = bytes(font)
    changed_members = [name for name in members if members[name] != before[name]]
    if changed_members != [COMM]:
        raise SystemExit(f"unexpected changed members: {changed_members}")
    if any(len(members[name]) != len(before[name]) for name in members):
        raise SystemExit("archive member length changed")

    ANALYSIS.mkdir(parents=True, exist_ok=True)
    EXPECTED.write_text(
        "member,physical_index,code,row,column,plane,set_pixels_before,set_pixels_after\n"
        f"{COMM},{SPACE_INDEX},0x{SPACE_CODE:02X},{row},{column},{plane},"
        f"{sum(current_plane)},0\n",
        encoding="utf-8-sig",
    )

    temporary = OUT_DIR / f"{OUT_STEM}_building.zip"
    if temporary.exists():
        raise SystemExit(f"refusing to reuse temporary output: {temporary.name}")
    with ZipFile(temporary, "w", ZIP_DEFLATED) as archive:
        for info in infos:
            archive.writestr(clone(info), members[info.filename])
    with ZipFile(temporary) as archive:
        if archive.namelist() != [info.filename for info in infos]:
            raise SystemExit("archive member order changed")
        for name, expected in members.items():
            if archive.read(name) != expected:
                raise SystemExit(f"archive roundtrip differs: {name}")

    stamp = digest(temporary.read_bytes())
    output = OUT_DIR / f"{OUT_STEM}_{stamp[:8]}.zip"
    if output.exists():
        raise SystemExit(f"refusing to overwrite existing output: {output.name}")
    temporary.replace(output)

    lines = [
        "v170 restore blank 0x9C space filler",
        "",
        f"base={BASE.name}",
        f"base_sha256={BASE_SHA256}",
        f"control={CONTROL.name}",
        f"control_sha256={CONTROL_SHA256}",
        f"output={output.name}",
        f"sha256={stamp}",
        f"changed_members={COMM}",
        "",
        f"space_code=0x{SPACE_CODE:02X}",
        f"physical_index={SPACE_INDEX}",
        f"cell=row{row},column{column},plane{plane}",
        f"untouched_and_v169_set_pixels={sum(current_plane)}",
        "v151_set_pixels=0",
        "v170_set_pixels=0",
        f"changed_COMM_bytes={len(changed_offsets)}",
        "",
        "PSX.EXE=byte-identical_to_v169",
        "all_DAT=byte-identical_to_v169",
        "cache_geometry=byte-identical_to_v169",
        "all_other_COMM_planes=byte-identical_to_v169",
        "archive_member_order=PASS",
        "archive_member_lengths=PASS",
        "archive_roundtrip=PASS",
        "runtime=PENDING user cold boot",
        "rollback=v169",
    ]
    REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    print(REPORT)


if __name__ == "__main__":
    main()
