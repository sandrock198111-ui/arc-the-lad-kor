#!/usr/bin/env python3
"""Build v90 from v89 with two narrowly scoped architecture repairs.

1. Remove E6 01 from the S3032 E2 secondary string. That parser renders the
   bytes as glyphs instead of treating them as line breaks.
2. Clear stale P6 sidecar state only when the same text object starts a new
   non-P6 string at glyph index zero.

No ISO is built.
"""

from __future__ import annotations

import hashlib
import struct
import sys
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))

import build_ui_hud_e7_v83_p6_sidecar_renderer as v83  # noqa: E402
import build_ui_hud_e7_v85_p6_highram_bootstrap as v85  # noqa: E402
import build_ui_hud_e7_v86_p6_repack_slots_1_to_6 as v86  # noqa: E402
import build_ui_hud_e7_v88_p6_state_persistence_slots_3_to_6 as v88  # noqa: E402


BASE = (
    ROOT
    / "03_output"
    / "ui_hud_e7_v89_story_safe_book_glyph_patch_only.zip"
)
OUTPUT = (
    ROOT
    / "03_output"
    / "ui_hud_e7_v90_e2_control_p6_lifetime_fix_patch_only.zip"
)
ANALYSIS = (
    ROOT
    / "01_work"
    / "analysis"
    / "ui_hud_e7_v90_e2_control_p6_lifetime_fix"
)
REPORT = ANALYSIS / "build_report.txt"
HELPER_WORDS = ANALYSIS / "glyph_helper_words.txt"
MARKER_WORDS = ANALYSIS / "marker_helper_words.txt"
SLOT_HEX = ANALYSIS / "s3032_slot_2_hex.txt"

BASE_SHA256 = "4A379BF0AA02D60E89C30E1BD26E9E884DF60AD0F9EF6FBB33537A9B396C9678"
BASE_PSX_SHA256 = "28C5974568666C34904682A0E1009570C46730027CB228CD655C4A4BF67BA6D3"
BASE_S3032_SHA256 = "0CD41D2A434C325737C0D2DEE753BA7134B9A872C7A34E0C21A7D558A50498D1"
BASE_COMM_SHA256 = "AFBC4A0DCD7C63C98AB352964F988607A695D182EE2B148F570A902355C260B2"

PSX_MEMBER = "PSX.EXE"
S3032_MEMBER = "31/S3032.DAT"
COMM_MEMBER = "COMM.IMG"

TARGET_SLOT = 2
TARGET_SLOT_OFFSET = v86.SLOT_BASE + TARGET_SLOT * v86.SLOT_SIZE
SECONDARY_LINE_BREAK = bytes.fromhex("E6 01")
SECONDARY_SPACE = bytes.fromhex("9C")
EXPECTED_V89_PAYLOAD = bytes.fromhex(
    "E0 DA E0 C5 E6 01 "
    "E0 49 E0 6B 9C E0 E7 E0 EA 9C E0 6B E0 BD 9C E0 04 E0 16 E0 A7 E6 01 "
    "E0 CB DF E5 E0 C2 9C E0 2D DF F6 DF A7 9C DF B7 9C "
    "E0 F1 E0 5F E0 35 E0 C1 E0 60"
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def build_lifetime_glyph_helper(address: int) -> bytes:
    """Preserve P6 state across other objects, but not object reuse."""

    asm = v83.Assembler(address)

    # v86 maps every active P6 glyph to physical row 24.
    asm.emit(v83.i_type(0x09, v83.T0, v83.A3, -0x18))
    asm.emit(v83.i_type(0x0B, v83.A3, v83.V0, 1))

    v83.load_address(asm, v83.V1, v85.HIGH_SIDECAR)
    asm.emit(v83.i_type(0x23, v83.V1, v83.A3, 0))
    asm.emit(v83.i_type(0x25, v83.A2, v83.T0, 0x0A))
    asm.branch(0x04, v83.V0, v83.ZERO, "non_p6")
    asm.emit(0)

    # A P6 glyph either continues the same string or initializes a new one.
    asm.branch(0x05, v83.A3, v83.A2, "reset")
    asm.emit(0)
    asm.branch(0x05, v83.T0, v83.ZERO, "mark")
    asm.emit(0)

    asm.label("reset")
    asm.emit(v83.i_type(0x2B, v83.V1, v83.A2, 0))
    asm.emit(v83.i_type(0x2B, v83.V1, v83.ZERO, 4))
    asm.emit(v83.i_type(0x2B, v83.V1, v83.ZERO, 8))

    asm.label("mark")
    asm.emit(v83.i_type(0x24, v83.A1, v83.A3, 0x28))
    asm.emit(0)
    asm.emit(v83.i_type(0x09, v83.A3, v83.A3, 0x28))
    asm.emit(v83.i_type(0x28, v83.A1, v83.A3, 0x28))
    asm.emit(v83.i_type(0x25, v83.A2, v83.A3, 0x0A))
    asm.emit(0)
    asm.emit(v83.i_type(0x0B, v83.A3, v83.T0, v83.BITMAP_GLYPHS))
    asm.branch(0x04, v83.T0, v83.ZERO, "done")
    asm.emit(0)

    asm.emit(v83.r_type(v83.ZERO, v83.A3, v83.T0, 5, 0x02))
    asm.emit(v83.r_type(v83.ZERO, v83.T0, v83.T0, 2, 0x00))
    asm.emit(v83.r_type(v83.V1, v83.T0, v83.V1, 0, 0x21))
    asm.emit(v83.i_type(0x0C, v83.A3, v83.A3, 0x1F))
    asm.emit(v83.i_type(0x0D, v83.ZERO, v83.T0, 1))
    asm.emit(v83.r_type(v83.A3, v83.T0, v83.T0, 0, 0x04))
    asm.emit(v83.i_type(0x23, v83.V1, v83.A3, 4))
    asm.emit(0)
    asm.emit(v83.r_type(v83.A3, v83.T0, v83.A3, 0, 0x25))
    asm.emit(v83.i_type(0x2B, v83.V1, v83.A3, 4))
    asm.branch(0x04, v83.ZERO, v83.ZERO, "done")
    asm.emit(0)

    # A different object must not erase a pending P6 item name. The same
    # object at index zero, however, is a new string and must drop stale state.
    asm.label("non_p6")
    asm.branch(0x05, v83.A3, v83.A2, "done")
    asm.emit(0)
    asm.branch(0x05, v83.T0, v83.ZERO, "done")
    asm.emit(0)
    asm.emit(v83.i_type(0x2B, v83.V1, v83.ZERO, 0))

    asm.label("done")
    asm.emit(v83.i_type(0x24, v83.A2, v83.V0, 0x0E))
    asm.emit(v83.j(v83.GLYPH_RETURN))
    asm.emit(0)
    return asm.finish()


def build_compact_marker_helper(address: int) -> bytes:
    """Build the v83 marker helper without its redundant second load nop."""

    asm = v83.Assembler(address)
    v83.load_address(asm, v83.V0, v85.HIGH_SIDECAR)
    asm.emit(v83.i_type(0x23, v83.V0, v83.V1, 0))
    asm.emit(0)
    asm.branch(0x05, v83.V1, v83.S2, "not_p6")
    asm.emit(0)
    asm.emit(v83.i_type(0x0B, v83.S0, v83.V1, v83.BITMAP_GLYPHS))
    asm.branch(0x04, v83.V1, v83.ZERO, "not_p6")
    asm.emit(0)
    asm.emit(v83.r_type(v83.ZERO, v83.S0, v83.V1, 5, 0x02))
    asm.emit(v83.r_type(v83.ZERO, v83.V1, v83.V1, 2, 0x00))
    asm.emit(v83.r_type(v83.V0, v83.V1, v83.V0, 0, 0x21))
    asm.emit(v83.i_type(0x23, v83.V0, v83.V0, 4))
    asm.emit(v83.i_type(0x0C, v83.S0, v83.V1, 0x1F))
    asm.emit(v83.r_type(v83.V1, v83.V0, v83.V0, 0, 0x06))
    asm.emit(v83.i_type(0x0C, v83.V0, v83.V0, 1))
    asm.emit(v83.r_type(v83.ZERO, v83.V0, v83.V0, 7, 0x00))
    asm.emit(v83.r_type(v83.RA, v83.ZERO, v83.ZERO, 0, 0x08))
    asm.emit(0)

    asm.label("not_p6")
    asm.emit(v83.r_type(v83.ZERO, v83.ZERO, v83.V0, 0, 0x21))
    asm.emit(v83.r_type(v83.RA, v83.ZERO, v83.ZERO, 0, 0x08))
    asm.emit(0)
    return asm.finish()


def model_sidecar(active: str | None, pointer: str, index: int) -> str | None:
    if active == pointer and index == 0:
        return None
    return active


def write_words(path: Path, address: int, payload: bytes) -> None:
    path.write_text(
        "\n".join(
            f"{address + offset:08X} "
            f"{struct.unpack_from('<I', payload, offset)[0]:08X}"
            for offset in range(0, len(payload), 4)
        )
        + "\n",
        encoding="ascii",
    )


def main() -> None:
    if sha256(BASE.read_bytes()) != BASE_SHA256:
        raise SystemExit("v89 base ZIP hash differs")

    with ZipFile(BASE, "r") as source:
        infos = source.infolist()
        members = {info.filename: source.read(info.filename) for info in infos}
    original = dict(members)

    expected_hashes = {
        PSX_MEMBER: BASE_PSX_SHA256,
        S3032_MEMBER: BASE_S3032_SHA256,
        COMM_MEMBER: BASE_COMM_SHA256,
    }
    for name, expected in expected_hashes.items():
        if sha256(members[name]) != expected:
            raise SystemExit(f"v89 {name} hash differs")

    old_helper = v88.build_p6_persistent_glyph_helper(v85.HIGH_GLYPH_HELPER)
    old_marker = (
        v85.HIGH_GLYPH_HELPER + len(old_helper) + 3
    ) & ~3
    old_sidecar = v83.SIDECAR_ADDRESS
    v83.SIDECAR_ADDRESS = v85.HIGH_SIDECAR
    try:
        old_marker_bytes = v83.build_marker_helper(old_marker)
    finally:
        v83.SIDECAR_ADDRESS = old_sidecar

    new_helper = build_lifetime_glyph_helper(v85.HIGH_GLYPH_HELPER)
    new_marker = (
        v85.HIGH_GLYPH_HELPER + len(new_helper) + 3
    ) & ~3
    new_marker_bytes = build_compact_marker_helper(new_marker)
    if len(new_helper) != 0xB0:
        raise SystemExit(f"new glyph helper size differs: 0x{len(new_helper):X}")
    if len(new_marker_bytes) != 0x58:
        raise SystemExit(f"new marker helper size differs: 0x{len(new_marker_bytes):X}")
    if new_marker + len(new_marker_bytes) != v85.HIGH_SIDECAR:
        raise SystemExit("new helpers do not end exactly at the sidecar")

    psx = bytearray(members[PSX_MEMBER])
    source_offset = v85.file_offset(v85.SOURCE_START)
    source_image = bytearray(
        psx[source_offset : source_offset + v85.COPY_SIZE]
    )
    old_marker_offset = old_marker - v85.HIGH_GLYPH_HELPER
    if source_image[: len(old_helper)] != old_helper:
        raise SystemExit("v89 glyph helper differs")
    if (
        source_image[
            old_marker_offset : old_marker_offset + len(old_marker_bytes)
        ]
        != old_marker_bytes
    ):
        raise SystemExit("v89 marker helper differs")
    if any(source_image[len(old_helper) : old_marker_offset]):
        raise SystemExit("v89 helper-to-marker padding is not empty")
    if any(
        source_image[
            old_marker_offset
            + len(old_marker_bytes) : v85.SIDECAR_OFFSET
        ]
    ):
        raise SystemExit("v89 marker-to-sidecar padding is not empty")

    current_marker_call = struct.pack("<I", v83.jal(old_marker))
    marker_call_offset = v85.file_offset(v83.PASS_MARKER_CALL)
    if psx[marker_call_offset : marker_call_offset + 4] != current_marker_call:
        raise SystemExit("v89 marker call differs")
    if psx[marker_call_offset + 4 : marker_call_offset + 8] != b"\0" * 4:
        raise SystemExit("v89 marker call delay slot differs")

    source_image[: v85.SIDECAR_OFFSET] = b"\0" * v85.SIDECAR_OFFSET
    source_image[: len(new_helper)] = new_helper
    new_marker_offset = new_marker - v85.HIGH_GLYPH_HELPER
    source_image[
        new_marker_offset : new_marker_offset + len(new_marker_bytes)
    ] = new_marker_bytes
    psx[source_offset : source_offset + v85.COPY_SIZE] = source_image
    struct.pack_into("<I", psx, marker_call_offset, v83.jal(new_marker))
    members[PSX_MEMBER] = bytes(psx)

    psx_diffs = {
        index
        for index, (before, after) in enumerate(
            zip(original[PSX_MEMBER], members[PSX_MEMBER])
        )
        if before != after
    }
    allowed_psx = set(range(source_offset, source_offset + v85.SIDECAR_OFFSET))
    allowed_psx.add(marker_call_offset)
    allowed_psx.update(range(marker_call_offset + 1, marker_call_offset + 4))
    if not psx_diffs or not psx_diffs <= allowed_psx:
        raise SystemExit("PSX.EXE changed outside helper image and marker call")
    if members[PSX_MEMBER].count(struct.pack("<I", v83.jal(old_marker))) != 0:
        raise SystemExit("old marker call remains")
    if members[PSX_MEMBER].count(struct.pack("<I", v83.jal(new_marker))) != 1:
        raise SystemExit("new marker call count differs")

    s3032 = bytearray(members[S3032_MEMBER])
    old_slot = bytes(
        s3032[
            TARGET_SLOT_OFFSET : TARGET_SLOT_OFFSET + v86.SLOT_SIZE
        ]
    )
    if old_slot[: len(EXPECTED_V89_PAYLOAD)] != EXPECTED_V89_PAYLOAD:
        raise SystemExit("v89 S3032 slot 2 payload differs")
    if any(old_slot[len(EXPECTED_V89_PAYLOAD) : -1]):
        raise SystemExit("v89 S3032 slot 2 padding differs")
    if old_slot[-1] != 0x20:
        raise SystemExit("v89 S3032 slot 2 capacity marker differs")
    if EXPECTED_V89_PAYLOAD.count(SECONDARY_LINE_BREAK) != 2:
        raise SystemExit("v89 secondary line-break count differs")

    new_payload = EXPECTED_V89_PAYLOAD.replace(
        SECONDARY_LINE_BREAK, SECONDARY_SPACE
    )
    if SECONDARY_LINE_BREAK in new_payload:
        raise SystemExit("secondary line-break remains")
    new_slot = (
        new_payload
        + b"\0" * (v86.SLOT_SIZE - len(new_payload) - 1)
        + old_slot[-1:]
    )
    s3032[
        TARGET_SLOT_OFFSET : TARGET_SLOT_OFFSET + v86.SLOT_SIZE
    ] = new_slot
    members[S3032_MEMBER] = bytes(s3032)

    s3032_diffs = {
        index
        for index, (before, after) in enumerate(
            zip(original[S3032_MEMBER], members[S3032_MEMBER])
        )
        if before != after
    }
    allowed_slot = set(
        range(TARGET_SLOT_OFFSET, TARGET_SLOT_OFFSET + v86.SLOT_SIZE)
    )
    if not s3032_diffs or not s3032_diffs <= allowed_slot:
        raise SystemExit("S3032.DAT changed outside slot 2")
    for slot in (0, 1, 3):
        start = v86.SLOT_BASE + slot * v86.SLOT_SIZE
        end = start + v86.SLOT_SIZE
        if members[S3032_MEMBER][start:end] != original[S3032_MEMBER][start:end]:
            raise SystemExit(f"preserved S3032 slot {slot} changed")

    if model_sidecar("A", "B", 0) != "A":
        raise SystemExit("unrelated-object sidecar persistence model failed")
    if model_sidecar("A", "A", 3) != "A":
        raise SystemExit("same-string sidecar persistence model failed")
    if model_sidecar("A", "A", 0) is not None:
        raise SystemExit("same-object reuse sidecar clear model failed")

    if members[COMM_MEMBER] != original[COMM_MEMBER]:
        raise SystemExit("COMM.IMG changed")
    changed_members = [
        name for name in members if members[name] != original[name]
    ]
    if changed_members != [PSX_MEMBER, S3032_MEMBER]:
        raise SystemExit(f"unexpected changed members: {changed_members}")

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with ZipFile(OUTPUT, "w", compression=ZIP_DEFLATED, compresslevel=9) as target:
        for info in infos:
            target.writestr(v88.clone_info(info), members[info.filename])

    with ZipFile(OUTPUT, "r") as built:
        readback_infos = built.infolist()
        readback = {
            info.filename: built.read(info.filename) for info in readback_infos
        }
    if [info.filename for info in readback_infos] != [
        info.filename for info in infos
    ]:
        raise SystemExit("ZIP member order changed")
    if readback != members:
        raise SystemExit("ZIP readback differs")

    ANALYSIS.mkdir(parents=True, exist_ok=True)
    write_words(HELPER_WORDS, v85.HIGH_GLYPH_HELPER, new_helper)
    write_words(MARKER_WORDS, new_marker, new_marker_bytes)
    SLOT_HEX.write_text(
        "old=" + old_slot.hex(" ").upper() + "\n"
        "new=" + new_slot.hex(" ").upper() + "\n",
        encoding="ascii",
    )
    report = [
        "ui_hud_e7_v90 E2 control and P6 lifetime repair",
        f"base={BASE}",
        f"base_zip_sha256={BASE_SHA256}",
        f"output={OUTPUT}",
        f"output_zip_sha256={sha256(OUTPUT.read_bytes())}",
        f"output_psx_sha256={sha256(members[PSX_MEMBER])}",
        f"output_s3032_sha256={sha256(members[S3032_MEMBER])}",
        f"output_comm_sha256={sha256(members[COMM_MEMBER])}",
        f"glyph_helper=0x{v85.HIGH_GLYPH_HELPER:08X}",
        f"glyph_helper_size=0x{len(new_helper):X}",
        f"marker_helper=0x{new_marker:08X}",
        f"marker_helper_size=0x{len(new_marker_bytes):X}",
        f"sidecar=0x{v85.HIGH_SIDECAR:08X}",
        "helper_marker_overlap=NO",
        "marker_sidecar_overlap=NO",
        "p6_unrelated_object_persistence=PRESERVED",
        "p6_same_string_persistence=PRESERVED",
        "p6_same_object_index_zero_clear=ENABLED",
        f"secondary_member={S3032_MEMBER}",
        f"secondary_slot={TARGET_SLOT}",
        f"secondary_slot_offset=0x{TARGET_SLOT_OFFSET:X}",
        "secondary_e6_01_before=2",
        "secondary_e6_01_after=0",
        f"secondary_payload_before={len(EXPECTED_V89_PAYLOAD)}",
        f"secondary_payload_after={len(new_payload)}",
        f"psx_changed_bytes={len(psx_diffs)}",
        f"s3032_changed_bytes={len(s3032_diffs)}",
        "comm_img_changed=NO",
        "preserved_s3032_slots=0,1,3",
        "changed_members=PSX.EXE,31/S3032.DAT",
        "iso_built=NO",
        "runtime_status=PENDING_USER_TEST",
    ]
    REPORT.write_text("\n".join(report) + "\n", encoding="ascii")

    print(f"OUTPUT={OUTPUT}")
    print(f"SHA256={sha256(OUTPUT.read_bytes())}")
    print(f"PSX_SHA256={sha256(members[PSX_MEMBER])}")
    print(f"S3032_SHA256={sha256(members[S3032_MEMBER])}")
    print(f"COMM_SHA256={sha256(members[COMM_MEMBER])}")
    print(f"GLYPH_HELPER_SIZE=0x{len(new_helper):X}")
    print(f"MARKER_HELPER=0x{new_marker:08X}")
    print(f"PSX_CHANGED_BYTES={len(psx_diffs)}")
    print(f"S3032_CHANGED_BYTES={len(s3032_diffs)}")
    print(f"REPORT={REPORT}")


if __name__ == "__main__":
    main()
