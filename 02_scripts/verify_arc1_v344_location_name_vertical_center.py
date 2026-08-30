#!/usr/bin/env python3
"""Independent verifier for V344's location-name Y-centering patch."""

from __future__ import annotations

import csv
import hashlib
import importlib.util
import json
import struct
import sys
from pathlib import Path
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[1]
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

BASE = ROOT / "03_output/arc1_v343_ra_safe_w16_hook_TEST_ONLY_CA08BDEB.zip"
FINAL = ROOT / "03_output/arc1_v344_location_name_vertical_center_TEST_ONLY_69B3EC07.zip"
DELTA = ROOT / "03_output/arc1_v344_location_name_vertical_center_TEST_ONLY_delta_from_v343_9C81B28C.zip"
ANALYSIS = ROOT / "01_work/analysis/arc1_v344_location_name_vertical_center"
STATE = Path(
    r"C:\Users\Administrator\.paseo\uploads\upload_0423d3cb-8f08-4e7b-8a87-3af85199368e\HASH-367FC88B8ECDBD3B_1.sav"
)

HASHES = {
    BASE: "CA08BDEB840C5BCC1D76D33D1D48F98EDAD6D764D3DFD48A70E186CBF35099D4",
    FINAL: "69B3EC07D300C28EF6C7F42588E6B392025F0392AE1207A586562B0D23001886",
    DELTA: "9C81B28C1CA59ADB9E1FE1F84E3A9C44144B9C1319415C00EC52B5BC1DC383C6",
}
PSX = "PSX.EXE"
BASE_PSX_SHA256 = "0CC93BE511AEA6074662728BE59838696BB418EFBE8C9641A669DFF629AFE8DE"
FINAL_PSX_SHA256 = "0CB561EC6B79BCF06F45D5F1D9E62DE7ABB7F545A4099127AAC2EA7D5165DF70"
STATE_SHA256 = "430000D1C22F996AB68B7D73B7F4AF2C32DA2C37ED0C575E8DFABFA17F99CCCB"

RAM_TO_FILE = 0x8011A800
LOCATION_RENDERER_RAM = 0x8016C5A4
TEXT_Y_RAM = 0x8016C5E8
TEXT_Y_FILE = TEXT_Y_RAM - RAM_TO_FILE
OLD_TEXT_Y = 0x34020006
NEW_TEXT_Y = 0x34020004
BACKGROUND_Y_FILE = 0x51DDC
BACKGROUND_H_FILE = 0x51DE4
BACKGROUND_Y_WORD = 0x34050074
BACKGROUND_H_WORD = 0x34070018
TEXT_H_FILE = 0x51DFC
TEXT_H_WORD = 0x3406000C
TEXT_X_FILE = 0x51E04
TEXT_X_WORD = 0x34070008
LOCATION_TABLE = 0x82170
LOCATION_COUNT = 55
LOCATION_3_PAYLOAD = bytes.fromhex("31 51 0F A1 DD 45 00")


class VerifyError(RuntimeError):
    pass


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def word(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def half(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def signed_half(data: bytes, offset: int) -> int:
    return struct.unpack_from("<h", data, offset)[0]


def archive(path: Path) -> tuple[list[str], dict[str, bytes]]:
    with ZipFile(path) as handle:
        names = [item.filename for item in handle.infolist() if not item.is_dir()]
        return names, {name: handle.read(name) for name in names}


def changes(before: bytes, after: bytes) -> set[int]:
    if len(before) != len(after):
        raise VerifyError("member size drift")
    return {
        offset
        for offset, (old, new) in enumerate(zip(before, after, strict=True))
        if old != new
    }


def control_target(pc: int, raw: int) -> int | None:
    opcode = raw >> 26
    if opcode in (2, 3):
        return ((pc + 4) & 0xF0000000) | ((raw & 0x03FFFFFF) << 2)
    if opcode in (1, 4, 5, 6, 7):
        immediate = raw & 0xFFFF
        if immediate & 0x8000:
            immediate -= 0x10000
        return (pc + 4 + immediate * 4) & 0xFFFFFFFF
    return None


def inbound(exe: bytes, target: int) -> list[tuple[int, str]]:
    result: list[tuple[int, str]] = []
    for offset in range(0x800, len(exe) - 3, 4):
        raw = word(exe, offset)
        if control_target(RAM_TO_FILE + offset, raw) == target:
            result.append((RAM_TO_FILE + offset, "jal" if raw >> 26 == 3 else "flow"))
    return result


def parse_runtime_state() -> dict[str, object]:
    spec = importlib.util.spec_from_file_location(
        "arc_state", ROOT / "02_scripts/analyze_arc1_v320c_savestates.py"
    )
    if spec is None or spec.loader is None:
        raise VerifyError("DUCCU parser unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    parsed = module.parse_state(STATE)
    if parsed["file_sha256"] != STATE_SHA256 or parsed["game_id"] != "V343":
        raise VerifyError("runtime state is not the pinned V343 observation")
    ram = parsed["ram"]
    header = 0x1F031C
    packet_base_address = word(ram, header)
    packet_base = packet_base_address & 0x1FFFFFFF
    count = half(ram, header + 0x0A)
    ys = [signed_half(ram, packet_base + index * 52 + 0x2E) for index in range(count)]
    heights = [ram[packet_base + index * 52 + 0x2B] & 0x7F for index in range(count)]
    if (
        packet_base_address != 0x801EFC9C
        or count != 5
        or word(ram, header + 0x14) != 0x8019BED9
        or ys != [122] * 5
        or heights != [16] * 5
        or tuple(ram[header + offset] for offset in (0x0D, 0x0E, 0x0F, 0x10)) != (14, 16, 2, 0)
    ):
        raise VerifyError("V343 location-name packet evidence drift")
    return {
        "sha256": parsed["file_sha256"],
        "game_id": parsed["game_id"],
        "text": "정령의 산",
        "packet_base": f"0x{packet_base_address:08X}",
        "count": count,
        "packet_y": ys[0],
        "packet_height": heights[0],
        "source_pointer_after_render": "0x8019BED9",
    }


def main() -> None:
    for path, expected in HASHES.items():
        if not path.is_file() or sha(path.read_bytes()) != expected:
            raise VerifyError(f"archive hash drift: {path.name}")
    base_names, base = archive(BASE)
    final_names, final = archive(FINAL)
    delta_names, delta = archive(DELTA)
    if len(base_names) != 164 or final_names != base_names:
        raise VerifyError("archive topology drift")
    if delta_names != [PSX] or delta[PSX] != final[PSX]:
        raise VerifyError("delta topology/readback drift")
    if sha(base[PSX]) != BASE_PSX_SHA256 or sha(final[PSX]) != FINAL_PSX_SHA256:
        raise VerifyError("PSX member hash drift")
    if [name for name in base_names if base[name] != final[name]] != [PSX]:
        raise VerifyError("V344 changed a non-PSX member")

    actual = changes(base[PSX], final[PSX])
    if actual != {TEXT_Y_FILE}:
        raise VerifyError(f"actual diff is not the one-byte Y immediate: {actual}")
    reconstructed = bytearray(base[PSX])
    struct.pack_into("<I", reconstructed, TEXT_Y_FILE, NEW_TEXT_Y)
    if bytes(reconstructed) != final[PSX]:
        raise VerifyError("V344 is not exactly the independent one-word patch")
    if word(base[PSX], TEXT_Y_FILE) != OLD_TEXT_Y or word(final[PSX], TEXT_Y_FILE) != NEW_TEXT_Y:
        raise VerifyError("location Y word transition drift")

    for offset, expected in (
        (BACKGROUND_Y_FILE, BACKGROUND_Y_WORD),
        (BACKGROUND_H_FILE, BACKGROUND_H_WORD),
        (TEXT_H_FILE, TEXT_H_WORD),
        (TEXT_X_FILE, TEXT_X_WORD),
    ):
        if word(base[PSX], offset) != expected or word(final[PSX], offset) != expected:
            raise VerifyError(f"neighbor geometry changed at 0x{offset:X}")
    if inbound(final[PSX], LOCATION_RENDERER_RAM) != [
        (0x801697BC, "jal"),
        (0x80169B00, "jal"),
    ]:
        raise VerifyError("location renderer caller census drift")

    pointers = [word(final[PSX], LOCATION_TABLE + index * 4) for index in range(LOCATION_COUNT)]
    nonempty = 0
    for pointer in pointers:
        at = pointer - RAM_TO_FILE
        if not 0 <= at < len(final[PSX]):
            raise VerifyError("location pointer escaped PSX.EXE")
        end = final[PSX].find(b"\0", at)
        if end < 0:
            raise VerifyError("unterminated location string")
        nonempty += end > at
    location3 = pointers[3] - RAM_TO_FILE
    if nonempty != 54 or final[PSX][location3:location3 + len(LOCATION_3_PAYLOAD)] != LOCATION_3_PAYLOAD:
        raise VerifyError("55-entry location table or 정령의 산 payload drift")

    rows = list(csv.DictReader((ANALYSIS / "expected_writes.csv").open(encoding="utf-8-sig", newline="")))
    if len(rows) != 1 or int(rows[0]["offset"], 16) != TEXT_Y_FILE:
        raise VerifyError("Expected-Write CSV row drift")
    if (rows[0]["before"], rows[0]["after"]) != (
        f"{base[PSX][TEXT_Y_FILE]:02X}",
        f"{final[PSX][TEXT_Y_FILE]:02X}",
    ):
        raise VerifyError("Expected-Write byte readback mismatch")

    runtime = parse_runtime_state()
    geometry = {
        "banner_y": 116,
        "banner_height": 24,
        "v343_text_y": 122,
        "v343_margins": [6, 2],
        "v344_expected_text_y": 120,
        "v344_expected_margins": [4, 4],
    }
    result = {
        "result": "STATIC_PASS_RUNTIME_PENDING",
        "changed_members_vs_v343": [PSX],
        "actual_changed_psx_bytes": len(actual),
        "location_table": {"entries": 55, "nonempty": nonempty},
        "location_renderer_callers": ["0x801697BC", "0x80169B00"],
        "geometry": geometry,
        "v343_runtime_evidence": runtime,
        "preserved": "all other V343 bytes; every DAT/COMM member and icon path byte exact",
        "runtime": "V344 location alignment cold boot PENDING",
    }
    (ANALYSIS / "independent_verification.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    lines = [
        "V344 independent static verification: PASS",
        f"full={FINAL.name} sha256={HASHES[FINAL]}",
        f"delta={DELTA.name} sha256={HASHES[DELTA]}",
        f"PSX.EXE sha256={FINAL_PSX_SHA256}",
        "archive=164 members; changed_vs_V343=PSX.EXE only; changed_bytes=1",
        "runtime evidence=V343 정령의 산 packets Y122/H16 in banner Y116/H24",
        "patch=inset 6->4; expected packet Y120; margins 4px/4px",
        "scope=dedicated 55-entry location renderer; two callers; other UI/icons byte exact",
        "runtime=V344 alignment PENDING; TEST_ONLY",
    ]
    (ANALYSIS / "independent_verification.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
