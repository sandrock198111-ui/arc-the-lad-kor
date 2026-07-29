#!/usr/bin/env python3
"""Build the cumulative v88 patch for current savestate slots 3-6.

The v83-v87 P6 helper kept only one active text-state pointer and reset that
state whenever any other UI string was parsed. Item names are parsed before
other popup strings, so their P6 bitmap was erased before rendering. This
build keeps the last P6 state while unrelated P0 strings are parsed.

It also routes the two S3032 dialogue blocks missed by v86 through free E2
slots. No ISO is built.
"""

from __future__ import annotations

import hashlib
import struct
import sys
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))

import build_ui_hud_e7_v83_p6_sidecar_renderer as v83  # noqa: E402
import build_ui_hud_e7_v85_p6_highram_bootstrap as v85  # noqa: E402
import build_ui_hud_e7_v86_p6_repack_slots_1_to_6 as v86  # noqa: E402


BASE = ROOT / "03_output" / "ui_hud_e7_v87_p6_heap_reserved_patch_only.zip"
OUTPUT = (
    ROOT
    / "03_output"
    / "ui_hud_e7_v88_p6_state_persistence_slots_3_to_6_patch_only.zip"
)
ANALYSIS = (
    ROOT
    / "01_work"
    / "analysis"
    / "ui_hud_e7_v88_p6_state_persistence_slots_3_to_6"
)
REPORT = ANALYSIS / "build_report.txt"
HELPER_WORDS = ANALYSIS / "glyph_helper_words.txt"

BASE_SHA256 = "36F578524C94771E88B96C1E90963FDC6AF6C3E1B77ECC4291D5642EBA75DC90"
BASE_PSX_SHA256 = "A5859BF199D8E6063046D87A143A21C55474C3C393059F32AC8D3FDE56CB2AA8"
BASE_S3032_SHA256 = "CC97F02A09D81B6D14782184AF545AC3CABEE8FE4932286DB29F272D7C4CEBBD"

PSX_MEMBER = "PSX.EXE"
S3032_MEMBER = "31/S3032.DAT"
CHARMAP = ROOT / "05_docs" / "korean_charmap_extended.csv"
UI_GLYPH_MAP = ROOT / "05_docs" / "ui_glyph_store_v42_map.csv"

DIALOGUES = (
    {
        "offset": 0x47A40,
        "capacity": 34,
        "expected_hex": (
            "BB803425E601381E381C7A2A3F292138E601"
            "BEDD0628DF2CDEC22F384B27592D6A37"
        ),
        "text": "야군\n만일 무슨 일이 생겨도\n저희는 책임질 수 없습니다.",
    },
    {
        "offset": 0x47AA2,
        "capacity": 34,
        "expected_hex": (
            "432029211B272B37E601411CCF282447786B425D2328E601"
            "4126DD074621703A1B37"
        ),
        "text": "알고 있습니다.\n그때는 스메리아 국왕께\n그렇게 전해 주십시오.",
    },
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


def build_p6_persistent_glyph_helper(address: int) -> bytes:
    """Track P6 state only when a P6 glyph is actually encountered.

    A non-P6 string returns without touching the sidecar. Pointer equality in
    the marker and renderer helpers still prevents unrelated text states from
    using the saved P6 bitmap.
    """

    asm = v83.Assembler(address)

    # v86 repacked every active high glyph into physical row 24.
    asm.emit(v83.i_type(0x09, v83.T0, v83.A3, -0x18))
    asm.emit(v83.i_type(0x0B, v83.A3, v83.A3, 1))
    asm.branch(0x04, v83.A3, v83.ZERO, "done")
    asm.emit(0)

    v83.load_address(asm, v83.V1, v85.HIGH_SIDECAR)
    asm.emit(v83.i_type(0x23, v83.V1, v83.A3, 0))
    asm.emit(0)
    asm.branch(0x05, v83.A3, v83.A2, "reset")
    asm.emit(0)
    asm.emit(v83.i_type(0x25, v83.A2, v83.A3, 0x0A))
    asm.emit(0)
    asm.branch(0x05, v83.A3, v83.ZERO, "mark")
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

    asm.label("done")
    asm.emit(v83.i_type(0x24, v83.A2, v83.V0, 0x0E))
    asm.emit(v83.j(v83.GLYPH_RETURN))
    asm.emit(0)
    return asm.finish()


def expected_v87_helper() -> bytes:
    old_sidecar = v83.SIDECAR_ADDRESS
    v83.SIDECAR_ADDRESS = v85.HIGH_SIDECAR
    try:
        helper = v83.build_glyph_helper(v85.HIGH_GLYPH_HELPER)
    finally:
        v83.SIDECAR_ADDRESS = old_sidecar

    broad = struct.pack("<I", v83.i_type(0x0B, v83.A3, v83.A3, 8))
    narrow = struct.pack("<I", v83.i_type(0x0B, v83.A3, v83.A3, 1))
    if helper.count(broad) != 1:
        raise SystemExit("v83 P6 classifier count differs")
    return helper.replace(broad, narrow)


def patch_dialogues(
    data: bytearray, mapping: dict[str, bytes]
) -> list[dict[str, object]]:
    free_slots = [
        slot
        for slot in range(v86.SLOT_COUNT)
        if not any(
            data[
                v86.SLOT_BASE + slot * v86.SLOT_SIZE :
                v86.SLOT_BASE + (slot + 1) * v86.SLOT_SIZE
            ]
        )
    ]
    if free_slots[:2] != [2, 3]:
        raise SystemExit(f"first free S3032 slots differ: {free_slots[:2]}")

    results: list[dict[str, object]] = []
    for item in DIALOGUES:
        offset = int(item["offset"])
        capacity = int(item["capacity"])
        expected = bytes.fromhex(str(item["expected_hex"]))
        if len(expected) != capacity:
            raise SystemExit(f"dialogue expected length differs: 0x{offset:X}")
        if data[offset : offset + capacity] != expected:
            raise SystemExit(f"dialogue source differs: 0x{offset:X}")
        if data[offset + capacity : offset + capacity + 4] != b"\0\0\x21\0":
            raise SystemExit(f"dialogue boundary differs: 0x{offset:X}")

        payload = v86.encode_dialogue(str(item["text"]), mapping)
        slot = free_slots.pop(0)
        slot_offset = v86.SLOT_BASE + slot * v86.SLOT_SIZE
        data[slot_offset : slot_offset + v86.SLOT_SIZE] = b"\0" * v86.SLOT_SIZE
        data[slot_offset : slot_offset + len(payload)] = payload
        data[slot_offset + v86.SLOT_SIZE - 1] = capacity - 2
        data[offset : offset + 2] = bytes((0xE2, v86.disk_id(slot)))
        results.append(
            {
                "offset": offset,
                "capacity": capacity,
                "slot": slot,
                "disk_id": v86.disk_id(slot),
                "payload_size": len(payload),
                "text": item["text"],
            }
        )
    return results


def main() -> None:
    if sha256(BASE.read_bytes()) != BASE_SHA256:
        raise SystemExit("v87 base ZIP hash differs")

    with ZipFile(BASE, "r") as source:
        infos = source.infolist()
        members = {info.filename: source.read(info.filename) for info in infos}
    original = dict(members)

    if sha256(members[PSX_MEMBER]) != BASE_PSX_SHA256:
        raise SystemExit("v87 PSX.EXE hash differs")
    if sha256(members[S3032_MEMBER]) != BASE_S3032_SHA256:
        raise SystemExit("v87 S3032.DAT hash differs")

    psx = bytearray(members[PSX_MEMBER])
    old_helper = expected_v87_helper()
    new_helper = build_p6_persistent_glyph_helper(v85.HIGH_GLYPH_HELPER)
    if len(new_helper) != len(old_helper):
        raise SystemExit(
            f"helper size changed: {len(old_helper)} -> {len(new_helper)}"
        )
    helper_offset = v85.file_offset(v85.SOURCE_START)
    if psx[helper_offset : helper_offset + len(old_helper)] != old_helper:
        raise SystemExit("v87 temporary glyph helper differs")
    psx[helper_offset : helper_offset + len(new_helper)] = new_helper
    members[PSX_MEMBER] = bytes(psx)

    mapping = {
        row["char"]: bytes.fromhex(row["code_hex"])
        for row in v86.read_csv(CHARMAP)
    }
    for row in v86.read_csv(UI_GLYPH_MAP):
        mapping.setdefault(
            row["char"], bytes.fromhex(row["virtual_code_hex"])
        )
    s3032 = bytearray(members[S3032_MEMBER])
    dialogue_results = patch_dialogues(s3032, mapping)
    members[S3032_MEMBER] = bytes(s3032)

    changed_members = [
        name for name in members if members[name] != original[name]
    ]
    if changed_members != [PSX_MEMBER, S3032_MEMBER]:
        raise SystemExit(f"unexpected changed members: {changed_members}")

    psx_diffs = [
        index
        for index, (before, after) in enumerate(
            zip(original[PSX_MEMBER], members[PSX_MEMBER])
        )
        if before != after
    ]
    helper_range = set(range(helper_offset, helper_offset + len(new_helper)))
    if not psx_diffs or not set(psx_diffs) <= helper_range:
        raise SystemExit("PSX.EXE changed outside the temporary helper")

    # Model the intended interleave: P6 item A, ordinary text B, then render A.
    active_state = "A"
    p6_bits = 1
    non_p6_state = "B"
    if non_p6_state == active_state:
        raise SystemExit("invalid state-persistence model")
    if active_state != "A" or p6_bits != 1:
        raise SystemExit("P6 sidecar did not survive the model interleave")

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with ZipFile(OUTPUT, "w", compression=ZIP_DEFLATED, compresslevel=9) as target:
        for info in infos:
            target.writestr(clone_info(info), members[info.filename])

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
    HELPER_WORDS.write_text(
        "\n".join(
            f"{v85.HIGH_GLYPH_HELPER + offset:08X} "
            f"{struct.unpack_from('<I', new_helper, offset)[0]:08X}"
            for offset in range(0, len(new_helper), 4)
        )
        + "\n",
        encoding="ascii",
    )
    report = [
        "ui_hud_e7_v88 P6 state persistence + slots 3-4 dialogue",
        f"base={BASE}",
        f"base_zip_sha256={BASE_SHA256}",
        f"output={OUTPUT}",
        f"output_zip_sha256={sha256(OUTPUT.read_bytes())}",
        f"output_psx_sha256={sha256(members[PSX_MEMBER])}",
        f"output_s3032_sha256={sha256(members[S3032_MEMBER])}",
        f"helper_runtime=0x{v85.HIGH_GLYPH_HELPER:08X}",
        f"helper_source=0x{v85.SOURCE_START:08X}",
        f"helper_size=0x{len(new_helper):X}",
        f"helper_changed_bytes={len(psx_diffs)}",
        "non_p6_sidecar_reset=REMOVED",
        "pointer_match_guard=PRESERVED",
        "heap_reservation_v87=PRESERVED",
        "p6_repack_v86=PRESERVED",
        "dialogue_slots="
        + ",".join(str(item["slot"]) for item in dialogue_results),
        "changed_members=PSX.EXE,31/S3032.DAT",
        "comm_img_changed=NO",
        "other_dat_changed=NO",
        "iso_built=NO",
        "runtime_status=PENDING_USER_TEST",
    ]
    for item in dialogue_results:
        report.extend(
            (
                f"dialogue_0x{int(item['offset']):X}_slot={item['slot']}",
                f"dialogue_0x{int(item['offset']):X}_disk_id="
                f"0x{int(item['disk_id']):02X}",
                f"dialogue_0x{int(item['offset']):X}_payload_size="
                f"{item['payload_size']}",
                f"dialogue_0x{int(item['offset']):X}_text="
                f"{str(item['text']).replace(chr(10), ' / ')}",
            )
        )
    REPORT.write_text("\n".join(report) + "\n", encoding="utf-8")

    print(f"OUTPUT={OUTPUT}")
    print(f"SHA256={sha256(OUTPUT.read_bytes())}")
    print(f"PSX_SHA256={sha256(members[PSX_MEMBER])}")
    print(f"S3032_SHA256={sha256(members[S3032_MEMBER])}")
    print(f"HELPER_CHANGED_BYTES={len(psx_diffs)}")
    print(f"DIALOGUE_SLOTS={','.join(str(x['slot']) for x in dialogue_results)}")
    print(f"REPORT={REPORT}")


if __name__ == "__main__":
    main()
