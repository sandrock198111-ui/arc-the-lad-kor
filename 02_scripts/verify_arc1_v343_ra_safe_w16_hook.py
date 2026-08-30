#!/usr/bin/env python3
"""Independent verifier for V343's two-word RA-safe W16 hook repair."""

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

BASE = ROOT / "03_output/arc1_v342_boot_recovery_TEST_ONLY_9EAEC08A.zip"
FINAL = ROOT / "03_output/arc1_v343_ra_safe_w16_hook_TEST_ONLY_CA08BDEB.zip"
DELTA = ROOT / "03_output/arc1_v343_ra_safe_w16_hook_TEST_ONLY_delta_from_v342_49A8C6F8.zip"
ANALYSIS = ROOT / "01_work/analysis/arc1_v343_ra_safe_w16_hook"
FAILURE_STATE = Path(
    r"C:\Users\Administrator\.paseo\uploads\upload_bcfe60fe-525e-4910-8174-6a150492e360\HASH-28A054D86C3420E1_1.sav"
)

HASHES = {
    BASE: "9EAEC08A3D94120C712D72321AC28D26272EF771D53CC465542090AC78D24E1C",
    FINAL: "CA08BDEB840C5BCC1D76D33D1D48F98EDAD6D764D3DFD48A70E186CBF35099D4",
    DELTA: "49A8C6F8F9D67208267D9B78CE8A071D143D33F4E7715F987EE3FB22D2EDA192",
}
PSX = "PSX.EXE"
BASE_PSX_SHA256 = "C1A4FC63449A58939295849F033679A1EC52B6EC587A52736BF476C6CA77144D"
FINAL_PSX_SHA256 = "0CC93BE511AEA6074662728BE59838696BB418EFBE8C9641A669DFF629AFE8DE"

RAM_TO_FILE = 0x8011A800
HOOK_RAM = 0x8016B5F4
HOOK_FILE = HOOK_RAM - RAM_TO_FILE
HELPER_RAM = 0x8019D024
HELPER_FILE = HELPER_RAM - RAM_TO_FILE
HELPER_TAIL_RAM = 0x8019D040
HELPER_TAIL_FILE = HELPER_TAIL_RAM - RAM_TO_FILE
CONTINUATION_RAM = 0x8016B5FC
CONTINUATION_FILE = CONTINUATION_RAM - RAM_TO_FILE

OLD_HOOK = 0x0C067409
NEW_HOOK = 0x08067409
OLD_TAIL = 0x03E00008
NEW_TAIL = 0x0805AD7F
DELAY = 0xA4A2002E
HELPER_WORDS = (
    0x3C08801F,
    0x25080E18,
    0x14C80004,
    0x340800D6,
    0x14480002,
    0x00000000,
    0x2442FFFF,
    NEW_TAIL,
    DELAY,
)


class VerifyError(RuntimeError):
    pass


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def word(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def archive(path: Path) -> tuple[list[str], dict[str, bytes]]:
    with ZipFile(path) as handle:
        names = [item.filename for item in handle.infolist() if not item.is_dir()]
        return names, {name: handle.read(name) for name in names}


def changes(a: bytes, b: bytes) -> set[int]:
    if len(a) != len(b):
        raise VerifyError("member size drift")
    return {index for index, pair in enumerate(zip(a, b, strict=True)) if pair[0] != pair[1]}


def control_target(pc: int, raw: int) -> int | None:
    opcode = raw >> 26
    if opcode in (2, 3):
        return ((pc + 4) & 0xF0000000) | ((raw & 0x03FFFFFF) << 2)
    if opcode in (1, 4, 5, 6, 7):
        immediate = raw & 0xFFFF
        if immediate & 0x8000:
            immediate -= 0x10000
        return pc + 4 + immediate * 4
    return None


def inbound(exe: bytes, target: int) -> list[tuple[int, int]]:
    result: list[tuple[int, int]] = []
    for offset in range(0x800, len(exe) - 3, 4):
        raw = word(exe, offset)
        if control_target(RAM_TO_FILE + offset, raw) == target:
            result.append((RAM_TO_FILE + offset, raw))
    return result


def parse_v342_failure() -> dict[str, object]:
    spec = importlib.util.spec_from_file_location(
        "arc_state", ROOT / "02_scripts/analyze_arc1_v320c_savestates.py"
    )
    if spec is None or spec.loader is None:
        raise VerifyError("DUCCU parser unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    parsed = module.parse_state(FAILURE_STATE)
    if parsed["file_sha256"] != "AED47AEC0064110A415F4FD715A0479FAF4FB86EB30AFEB54A540A3A72CF2836":
        raise VerifyError("V342 failure-state hash drift")

    blob = parsed["blob"]
    cpu_tag = struct.pack("<I", 3) + b"CPU"
    cpu = blob.find(cpu_tag)
    if cpu < 0:
        raise VerifyError("CPU section missing")
    cpu += len(cpu_tag)
    ra = word(blob, cpu + 0x8C)
    current_pc = word(blob, cpu + 0xB8)
    cause = word(blob, cpu + 0xC4)
    next_pc = word(blob, cpu + 0xD4)

    gpu_tag = struct.pack("<I", 3) + b"GPU"
    gpu = blob.find(gpu_tag)
    if gpu < 0:
        raise VerifyError("GPU section missing")
    gpu += len(gpu_tag)
    gpustat = word(blob, gpu)
    vram_left, vram_top, vram_width, vram_height = struct.unpack_from("<4H", blob, gpu + 70)
    if gpustat & (1 << 23) or (vram_width, vram_height) != (320, 224):
        raise VerifyError("V342 GPU display premise drift")
    vram = parsed["vram"]
    visible_nonzero = 0
    for y in range(vram_height):
        yy = (vram_top + y) % 512
        for x in range(vram_width):
            xx = (vram_left + x) % 1024
            if vram[(yy * 1024 + xx) * 2 : (yy * 1024 + xx + 1) * 2] != b"\0\0":
                visible_nonzero += 1

    thumb = parsed["thumbnail"]
    thumb_rgb_nonzero = sum(
        thumb[pixel + channel] != 0
        for pixel in range(0, len(thumb), 4)
        for channel in range(3)
    )
    if parsed["game_id"] != "V342" or thumb_rgb_nonzero != 0:
        raise VerifyError("state is not the black V342 runtime failure")
    if ra != CONTINUATION_RAM or current_pc != 0x8016B60C or next_pc != current_pc:
        raise VerifyError("V342 lost-RA/PC evidence drift")
    if (cause >> 2) & 0x1F or cause & 0x80000000 or visible_nonzero != 0:
        raise VerifyError("V342 failure is no longer the exception-free blank-frame loop")
    return {
        "sha256": parsed["file_sha256"],
        "game_id": parsed["game_id"],
        "ra": f"0x{ra:08X}",
        "current_pc": f"0x{current_pc:08X}",
        "cause": f"0x{cause:08X}",
        "visible_vram": [vram_left, vram_top, vram_width, vram_height],
        "visible_nonzero_words": visible_nonzero,
        "thumbnail_rgb_nonzero_bytes": thumb_rgb_nonzero,
    }


def main() -> None:
    for path, expected in HASHES.items():
        if not path.is_file() or sha(path.read_bytes()) != expected:
            raise VerifyError(f"archive hash drift: {path.name}")
    base_names, base = archive(BASE)
    final_names, final = archive(FINAL)
    delta_names, delta = archive(DELTA)
    if len(base_names) != 164 or final_names != base_names:
        raise VerifyError("full archive topology drift")
    if delta_names != [PSX] or delta[PSX] != final[PSX]:
        raise VerifyError("delta topology/readback drift")
    if sha(base[PSX]) != BASE_PSX_SHA256 or sha(final[PSX]) != FINAL_PSX_SHA256:
        raise VerifyError("PSX member hash drift")
    if [name for name in base_names if base[name] != final[name]] != [PSX]:
        raise VerifyError("V343 changed a non-PSX member")

    actual = changes(base[PSX], final[PSX])
    reconstructed = bytearray(base[PSX])
    struct.pack_into("<I", reconstructed, HOOK_FILE, NEW_HOOK)
    struct.pack_into("<I", reconstructed, HELPER_TAIL_FILE, NEW_TAIL)
    if bytes(reconstructed) != final[PSX]:
        raise VerifyError("V343 is not exactly the independent two-word repair")
    if word(base[PSX], HOOK_FILE) != OLD_HOOK or word(base[PSX], HELPER_TAIL_FILE) != OLD_TAIL:
        raise VerifyError("V342 failure-word premise drift")
    if word(final[PSX], HOOK_FILE) != NEW_HOOK or word(final[PSX], HELPER_TAIL_FILE) != NEW_TAIL:
        raise VerifyError("V343 control-flow word drift")
    if word(final[PSX], HOOK_FILE + 4) != 0 or word(final[PSX], HELPER_TAIL_FILE + 4) != DELAY:
        raise VerifyError("hook/helper delay slot drift")
    if struct.unpack_from("<9I", final[PSX], HELPER_FILE) != HELPER_WORDS:
        raise VerifyError("W16 helper body drift")

    if inbound(final[PSX], HELPER_RAM) != [(HOOK_RAM, NEW_HOOK)]:
        raise VerifyError("helper entry topology is not one direct non-link jump")
    if inbound(final[PSX], HELPER_TAIL_RAM) != [
        (0x8019D02C, 0x14C80004),
        (0x8019D034, 0x14480002),
    ]:
        raise VerifyError("helper tail branch convergence drift")
    if inbound(final[PSX], CONTINUATION_RAM) != [(HELPER_TAIL_RAM, NEW_TAIL)]:
        raise VerifyError("fixed continuation topology drift")

    # No JAL/JALR or explicit write to r31 exists in the nine-word helper.
    for index, raw in enumerate(HELPER_WORDS):
        opcode = raw >> 26
        function = raw & 0x3F
        rd = (raw >> 11) & 31
        if opcode == 3 or (opcode == 0 and function == 9) or (opcode == 0 and rd == 31):
            raise VerifyError(f"helper still writes r31 at word {index}")

    rows = list(csv.DictReader((ANALYSIS / "expected_writes.csv").open(encoding="utf-8-sig", newline="")))
    declared = {int(row["offset"], 16) for row in rows}
    if declared != actual:
        raise VerifyError("Expected-Write set differs from actual PSX diff")
    for row in rows:
        at = int(row["offset"], 16)
        if (row["before"], row["after"]) != (f"{base[PSX][at]:02X}", f"{final[PSX][at]:02X}"):
            raise VerifyError("Expected-Write byte readback mismatch")

    failure = parse_v342_failure()
    result = {
        "result": "STATIC_PASS_RUNTIME_PENDING",
        "changed_members_vs_v342": [PSX],
        "actual_changed_psx_bytes": len(actual),
        "control_flow": "non-link hook -> helper -> fixed continuation; r31 untouched",
        "delay_slots": "hook NOP and packet-Y store preserved",
        "preserved": "all other V342 bytes, including every DAT and COMM member, byte exact",
        "v342_failure_evidence": failure,
        "runtime": "V343 cold boot PENDING",
    }
    (ANALYSIS / "independent_verification.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    lines = [
        "V343 independent static verification: PASS",
        f"full={FINAL.name} sha256={HASHES[FINAL]}",
        f"delta={DELTA.name} sha256={HASHES[DELTA]}",
        f"PSX.EXE sha256={FINAL_PSX_SHA256}",
        f"archive=164 members; changed_vs_V342=PSX.EXE only; changed_bytes={len(actual)}",
        "control_flow=J(non-link) helper entry; two branches converge; J fixed continuation; r31 untouched",
        "delay_slots=hook NOP and packet-Y store preserved",
        "preserved=all other V342 bytes; every DAT/COMM member byte exact",
        f"V342_failure=RA {failure['ra']}, PC {failure['current_pc']}, ExcCode0, visible VRAM all zero",
        "runtime=V343 cold boot PENDING; TEST_ONLY",
    ]
    (ANALYSIS / "independent_verification.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
