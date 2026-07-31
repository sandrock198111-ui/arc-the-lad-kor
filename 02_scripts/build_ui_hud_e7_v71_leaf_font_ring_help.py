"""Build v71 from v70 with a font-matched leaf glyph and compact ring help."""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "06_tools" / "python_packages"))

from PIL import Image, ImageDraw, ImageFont  # noqa: E402


BASE = ROOT / "03_output" / "ui_hud_e7_v70_leaf_names_ring_menu_patch_only.zip"
OUTPUT = ROOT / "03_output" / "ui_hud_e7_v71_leaf_font_ring_help_patch_only.zip"
REPORT = ROOT / "01_work" / "analysis" / "ui_hud_e7_v71" / "build_report.txt"

BASE_SHA256 = "5E6D34D1B016AEAD61806B654F15E3E25E672945F43838FA3D09E16023D6EAB5"
PSX_MEMBER = "PSX.EXE"
COMM_MEMBER = "COMM.IMG"
FONT_PATH = Path(r"C:\Windows\Fonts\gulim.ttc")
ROW_BYTES = 0x380

LEAF_PHYSICAL_INDEX = 1356
LEAF_CHAR = "\uc78e"
EXPECTED_LEAF_ROWS = (
    "..####...#..",
    ".#....#..#..",
    ".#....#..#..",
    ".#....#..#..",
    "..####...#..",
    ".........#..",
    "............",
    "..########..",
    "....#..#....",
    "....#..#....",
    "..########..",
    "............",
)

HELP_OFFSET = 0x82780
HELP_SLOT_END = 0x827A0
OLD_HELP = bytes.fromhex(
    "E7 02 E0 C6 E0 40 DF E2 9C E7 05 "
    "E9 5E E9 48 9C EA 3C 9C E0 B2 E0 AC"
)
# ○공격, □링 열기
NEW_HELP = bytes.fromhex(
    "E7 02 E0 C6 E0 40 DF E2 9C E7 05 EA 3C 9C E0 B2 E0 AC"
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


def get_pixel(data: bytes | bytearray, x: int, y: int) -> int:
    value = data[y * ROW_BYTES + x // 2]
    return value & 0x0F if x % 2 == 0 else value >> 4


def set_pixel(data: bytearray, x: int, y: int, value: int) -> None:
    offset = y * ROW_BYTES + x // 2
    if x % 2 == 0:
        data[offset] = (data[offset] & 0xF0) | (value & 0x0F)
    else:
        data[offset] = (data[offset] & 0x0F) | ((value & 0x0F) << 4)


def render_leaf() -> Image.Image:
    font = ImageFont.truetype(str(FONT_PATH), size=12)
    canvas = Image.new("L", (24, 24), 0)
    draw = ImageDraw.Draw(canvas)
    bbox = draw.textbbox((0, 0), LEAF_CHAR, font=font)
    x = (24 - (bbox[2] - bbox[0])) // 2 - bbox[0]
    y = (24 - (bbox[3] - bbox[1])) // 2 - bbox[1]
    draw.text((x, y), LEAF_CHAR, fill=255, font=font)
    glyph = canvas.crop((6, 6, 18, 18)).point(
        lambda value: 255 if value >= 192 else 0, mode="1"
    )
    rows = tuple(
        "".join("#" if glyph.getpixel((x, y)) else "." for x in range(12))
        for y in range(12)
    )
    if rows != EXPECTED_LEAF_ROWS:
        raise SystemExit("Gulim leaf render differs from the verified bitmap")
    return glyph


def replace_leaf_plane(comm: bytes) -> bytes:
    data = bytearray(comm)
    row, remainder = divmod(LEAF_PHYSICAL_INDEX, 84)
    column, plane = divmod(remainder, 4)
    if (row, column, plane) != (16, 3, 0):
        raise SystemExit("dedicated leaf physical position differs")
    bit = 1 << plane
    glyph = render_leaf()
    for y in range(12):
        for x in range(12):
            source_x = column * 12 + x
            source_y = row * 12 + y
            old = get_pixel(data, source_x, source_y)
            new = old | bit if glyph.getpixel((x, y)) else old & ~bit
            if (new & ~bit) != (old & ~bit):
                raise SystemExit("leaf writer changed a neighboring bitplane")
            set_pixel(data, source_x, source_y, new)
    return bytes(data)


def main() -> None:
    if sha256(BASE.read_bytes()) != BASE_SHA256:
        raise SystemExit("v70 base archive hash differs")

    with ZipFile(BASE, "r") as source:
        infos = source.infolist()
        original = {info.filename: source.read(info.filename) for info in infos}
    members = dict(original)

    psx = bytearray(members[PSX_MEMBER])
    if psx[HELP_OFFSET : HELP_OFFSET + len(OLD_HELP)] != OLD_HELP:
        raise SystemExit("v70 battle help bytes differ")
    if psx[HELP_OFFSET + len(OLD_HELP)] != 0:
        raise SystemExit("v70 battle help terminator differs")
    slot_size = HELP_SLOT_END - HELP_OFFSET
    psx[HELP_OFFSET:HELP_SLOT_END] = NEW_HELP + bytes(slot_size - len(NEW_HELP))
    members[PSX_MEMBER] = bytes(psx)
    members[COMM_MEMBER] = replace_leaf_plane(members[COMM_MEMBER])

    changed_members = [name for name in members if members[name] != original[name]]
    if set(changed_members) != {PSX_MEMBER, COMM_MEMBER}:
        raise SystemExit(f"unexpected changed members: {changed_members}")

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with ZipFile(OUTPUT, "w") as target:
        for info in infos:
            target.writestr(clone_info(info), members[info.filename])

    with ZipFile(OUTPUT, "r") as built:
        readback = {info.filename: built.read(info.filename) for info in built.infolist()}
    if readback[PSX_MEMBER] != members[PSX_MEMBER]:
        raise SystemExit("PSX readback differs")
    if readback[COMM_MEMBER] != members[COMM_MEMBER]:
        raise SystemExit("COMM readback differs")
    for name in members:
        if name not in {PSX_MEMBER, COMM_MEMBER} and readback[name] != original[name]:
            raise SystemExit(f"unapproved member changed: {name}")

    # Verify the rendered leaf plane and the compact help payload independently.
    row, remainder = divmod(LEAF_PHYSICAL_INDEX, 84)
    column, plane = divmod(remainder, 4)
    rendered_rows = tuple(
        "".join(
            "#"
            if get_pixel(
                readback[COMM_MEMBER], column * 12 + x, row * 12 + y
            )
            & (1 << plane)
            else "."
            for x in range(12)
        )
        for y in range(12)
    )
    if rendered_rows != EXPECTED_LEAF_ROWS:
        raise SystemExit("leaf bitmap readback differs")
    built_psx = readback[PSX_MEMBER]
    if built_psx[HELP_OFFSET : HELP_OFFSET + len(NEW_HELP)] != NEW_HELP:
        raise SystemExit("ring help readback differs")
    if built_psx[HELP_OFFSET + len(NEW_HELP)] != 0:
        raise SystemExit("ring help terminator readback differs")

    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(
        "\n".join(
            [
                "ui_hud_e7_v71 build report",
                f"base={BASE}",
                f"base_sha256={BASE_SHA256}",
                f"output={OUTPUT}",
                f"output_sha256={sha256(OUTPUT.read_bytes())}",
                "changed_members=PSX.EXE,COMM.IMG",
                "unchanged_members=all DAT members",
                "leaf_virtual_code=E9 75",
                "leaf_physical_index=1356",
                "leaf_position=row16,column3,plane0",
                "leaf_renderer=Gulim 12px threshold192",
                f"help_payload_bytes={len(NEW_HELP)}",
                f"help_slot_bytes={slot_size}",
                f"help_free_bytes={slot_size - len(NEW_HELP) - 1}",
                "static_readback=PASS",
                "runtime_verification=PENDING",
                "",
            ]
        ),
        encoding="utf-8",
    )

    print(OUTPUT)
    print(f"SHA256 {sha256(OUTPUT.read_bytes())}")
    print(f"Help slot free bytes {slot_size - len(NEW_HELP) - 1}")


if __name__ == "__main__":
    main()
