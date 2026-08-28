#!/usr/bin/env python3
"""Build V331: keep V330's skill shift and compact the configuration choices.

V329 runtime state 3 proves that the four right-hand configuration rows are
drawn by the loop at 0x80160810.  The first and second choice columns start at
X=166 and X=226 through the dedicated instructions at 0x8016089C and
0x801608BC.  V331 changes only those immediates to X=162/222.  It also shortens
the sole 0x825EC string from ``사용 안 함`` to the user-approved ``사용안함``.

V330's skill-name-only -4 packet wrapper is inherited byte-for-byte.
"""

from __future__ import annotations

import csv
import hashlib
import json
import struct
import sys
from pathlib import Path
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

import build_arc1_v324_static_ui_cursor_recovery as v324  # noqa: E402


BASE = ROOT / "03_output/arc1_v330_skill_name_x_minus4_TEST_ONLY_38FE2472.zip"
BASE_SHA256 = "38FE24725CA82B721A544C4F6A6B787A4028ADA00F4312A2717F746BAF809DF0"
BASE_PSX_SHA256 = "D1F4E1A90527289416BC2D7ED4D2206AC3A6ADF8FAB59A96FC4E8FB8BD31C04E"
OUTPUT_STEM = "arc1_v331_skill_config_alignment_TEST_ONLY"
DELTA_STEM = OUTPUT_STEM + "_delta_from_v330"
ANALYSIS = ROOT / "01_work/analysis/arc1_v331_skill_config_alignment"

PSX = "PSX.EXE"
RAM_TO_FILE = 0x8011A800

CONFIG_FIRST_X_RAM = 0x8016089C
CONFIG_SECOND_X_RAM = 0x801608BC
CONFIG_FIRST_X_FILE = CONFIG_FIRST_X_RAM - RAM_TO_FILE
CONFIG_SECOND_X_FILE = CONFIG_SECOND_X_RAM - RAM_TO_FILE
CONFIG_FIRST_OLD = 0x26640084  # addiu a0,s3,132; s3=34 -> X=166
CONFIG_SECOND_OLD = 0x266400C0  # addiu a0,s3,192; s3=34 -> X=226
CONFIG_FIRST_NEW = 0x26640080  # X=162
CONFIG_SECOND_NEW = 0x266400BC  # X=222

CONFIG_POINTER_FILE = 0x825EC
CONFIG_POINTER_RAM_VALUE = 0x8019C2A4
CONFIG_PAYLOAD_FILE = CONFIG_POINTER_RAM_VALUE - RAM_TO_FILE
OLD_PAYLOAD_REGION = bytes.fromhex("34 DD 1A A1 94 A1 DD CF 00")  # 사용 안 함\0
NEW_PAYLOAD_REGION = bytes.fromhex("34 DD 1A 94 DD CF 00 00 00")  # 사용안함\0 + zero tail

# Context fixes the two X instructions to the configuration-table renderer,
# not an accidental matching immediate elsewhere.
FIRST_CONTEXT_FILE = 0x80160894 - RAM_TO_FILE
FIRST_CONTEXT_OLD = (
    0x2A020004, 0x1040001A, CONFIG_FIRST_OLD, 0x001010C0,
    0x02C21021, 0x8C460014,
)
SECOND_CONTEXT_FILE = 0x801608B4 - RAM_TO_FILE
SECOND_CONTEXT_OLD = (
    0x0C05AC92, 0x02202821, CONFIG_SECOND_OLD, 0x8EA60000,
    0x3C078020, 0x24E79D44,
)

# V330 subsystem snapshots that V331 must not disturb.
SKILL_CALL_FILE = 0x80162080 - RAM_TO_FILE
SKILL_WRAPPER_FILE = 0x8019B0B0 - RAM_TO_FILE
SKILL_WRAPPER_SIZE = 92


class BuildError(RuntimeError):
    pass


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def pointer_hits(exe: bytes, value: int) -> list[int]:
    return [
        offset
        for offset in range(0, len(exe) - 3)
        if struct.unpack_from("<I", exe, offset)[0] == value
    ]


def build_once(before: dict[str, bytes]) -> dict[str, bytes]:
    members = dict(before)
    exe = bytearray(before[PSX])

    if struct.unpack_from("<6I", exe, FIRST_CONTEXT_FILE) != FIRST_CONTEXT_OLD:
        raise BuildError("configuration first-column context drift")
    if struct.unpack_from("<6I", exe, SECOND_CONTEXT_FILE) != SECOND_CONTEXT_OLD:
        raise BuildError("configuration second-column context drift")
    if struct.unpack_from("<I", exe, CONFIG_POINTER_FILE)[0] != CONFIG_POINTER_RAM_VALUE:
        raise BuildError("0x825EC configuration pointer drift")
    if pointer_hits(bytes(exe), CONFIG_POINTER_RAM_VALUE) != [CONFIG_POINTER_FILE]:
        raise BuildError("사용 안 함 payload is not owned by exactly pointer 0x825EC")
    if bytes(exe[CONFIG_PAYLOAD_FILE : CONFIG_PAYLOAD_FILE + len(OLD_PAYLOAD_REGION)]) != OLD_PAYLOAD_REGION:
        raise BuildError("사용 안 함 payload bytes drift")

    # Preserve V330's skill-only route and wrapper as independent snapshots.
    skill_call = bytes(exe[SKILL_CALL_FILE : SKILL_CALL_FILE + 8])
    skill_wrapper = bytes(exe[SKILL_WRAPPER_FILE : SKILL_WRAPPER_FILE + SKILL_WRAPPER_SIZE])

    struct.pack_into("<I", exe, CONFIG_FIRST_X_FILE, CONFIG_FIRST_NEW)
    struct.pack_into("<I", exe, CONFIG_SECOND_X_FILE, CONFIG_SECOND_NEW)
    exe[CONFIG_PAYLOAD_FILE : CONFIG_PAYLOAD_FILE + len(NEW_PAYLOAD_REGION)] = NEW_PAYLOAD_REGION

    if bytes(exe[SKILL_CALL_FILE : SKILL_CALL_FILE + 8]) != skill_call:
        raise BuildError("V330 skill call changed")
    if bytes(exe[SKILL_WRAPPER_FILE : SKILL_WRAPPER_FILE + SKILL_WRAPPER_SIZE]) != skill_wrapper:
        raise BuildError("V330 skill wrapper changed")
    members[PSX] = bytes(exe)
    return members


def main() -> None:
    if not BASE.is_file() or v324.sha256_file(BASE) != BASE_SHA256:
        raise BuildError(f"V330 base hash mismatch: {BASE}")
    infos, before = v324.read_archive(BASE)
    if len(before) != 164 or sha256_bytes(before[PSX]) != BASE_PSX_SHA256:
        raise BuildError("V330 archive/PSX premise drift")

    final = build_once(before)
    if final != build_once(before):
        raise BuildError("in-memory deterministic rebuild mismatch")
    changed_members = [name for name in before if before[name] != final[name]]
    if changed_members != [PSX]:
        raise BuildError(f"changed member set drift: {changed_members}")
    if any(len(before[name]) != len(final[name]) for name in before):
        raise BuildError("member size changed")

    actual = {
        offset
        for offset, (old, new) in enumerate(zip(before[PSX], final[PSX], strict=True))
        if old != new
    }
    envelope = (
        set(range(CONFIG_FIRST_X_FILE, CONFIG_FIRST_X_FILE + 4))
        | set(range(CONFIG_SECOND_X_FILE, CONFIG_SECOND_X_FILE + 4))
        | set(range(CONFIG_PAYLOAD_FILE, CONFIG_PAYLOAD_FILE + len(NEW_PAYLOAD_REGION)))
    )
    expected = {offset for offset in envelope if before[PSX][offset] != final[PSX][offset]}
    if actual != expected or len(actual) != 7:
        raise BuildError(f"Expected-Write mismatch: actual={len(actual)}")

    output_path, output_hash = v324.write_archive(OUTPUT_STEM, infos, final, None)
    delta_path, delta_hash = v324.write_archive(DELTA_STEM, infos, final, {PSX})
    with ZipFile(output_path) as archive:
        names = [item.filename for item in archive.infolist() if not item.is_dir()]
        expected_names = [item.filename for item in infos if not item.is_dir()]
        if names != expected_names or any(archive.read(name) != final[name] for name in final):
            raise BuildError("full ZIP round-trip/topology mismatch")
    with ZipFile(delta_path) as archive:
        if archive.namelist() != [PSX] or archive.read(PSX) != final[PSX]:
            raise BuildError("delta ZIP mismatch")

    ANALYSIS.mkdir(parents=True, exist_ok=True)
    with (ANALYSIS / "expected_writes.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(("member", "offset", "before", "after", "purpose"))
        for offset in sorted(actual):
            if CONFIG_FIRST_X_FILE <= offset < CONFIG_FIRST_X_FILE + 4:
                purpose = "config_first_choice_x_166_to_162"
            elif CONFIG_SECOND_X_FILE <= offset < CONFIG_SECOND_X_FILE + 4:
                purpose = "config_second_choice_x_226_to_222"
            else:
                purpose = "사용_안_함_to_사용안함"
            writer.writerow((PSX, f"0x{offset:X}", f"{before[PSX][offset]:02X}", f"{final[PSX][offset]:02X}", purpose))

    manifest = {
        "build": "V331 TEST_ONLY skill/config alignment",
        "base": {"path": str(BASE), "sha256": BASE_SHA256},
        "output": {"path": str(output_path), "sha256": output_hash},
        "delta": {"path": str(delta_path), "sha256": delta_hash},
        "changed_members": [PSX],
        "changed_bytes": {PSX: len(actual)},
        "skill": "inherit V330: object 0x801F1DB4 packets dx=-4",
        "configuration": {
            "renderer": "0x80160810 loop",
            "first_choice_x": "166 -> 162",
            "second_choice_x": "226 -> 222",
            "pointer": "0x825EC only",
            "text": "사용 안 함 -> 사용안함",
        },
        "scope": "configuration choice columns only; labels/window/other UI byte-identical to V330",
        "runtime": "PENDING user cold boot and configuration/skill comparison",
        "release_status": "DIAGNOSTIC; DO NOT DISTRIBUTE",
    }
    (ANALYSIS / "build_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    report = [
        "V331 TEST ONLY - skill and configuration alignment",
        f"base={BASE.name}",
        f"output={output_path.name}",
        f"sha256={output_hash}",
        f"delta={delta_path.name}",
        f"delta_sha256={delta_hash}",
        "changed_members=PSX.EXE only",
        f"changed_bytes={len(actual)} in two configuration X immediates + one owned payload",
        "skill=inherit V330 skill-name packets dx=-4",
        "configuration=choice X 166/226 -> 162/222; 사용 안 함 -> 사용안함",
        "labels/window/items/equipment/status/dialogue=unchanged from V330",
        "runtime=PENDING; TEST_ONLY",
    ]
    (ANALYSIS / "build_report.txt").write_text("\n".join(report) + "\n", encoding="utf-8")
    print("\n".join(report))


if __name__ == "__main__":
    main()
