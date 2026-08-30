#!/usr/bin/env python3
"""Independent verifier for V342's narrow V341 cursor-control rollback."""

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

BASE = ROOT / "03_output/arc1_v341_runtime_ui_recovery_TEST_ONLY_FCAF5CFB.zip"
ROLLBACK = ROOT / "03_output/arc1_v340_battle_choice_ui_geometry_TEST_ONLY_3F63BFD1.zip"
FINAL = ROOT / "03_output/arc1_v342_boot_recovery_TEST_ONLY_9EAEC08A.zip"
DELTA = ROOT / "03_output/arc1_v342_boot_recovery_TEST_ONLY_delta_from_v341_9BAF1A54.zip"
ANALYSIS = ROOT / "01_work/analysis/arc1_v342_boot_recovery"
FAILURE_STATE = Path(r"C:\Users\Administrator\.paseo\uploads\upload_7ca9a425-522f-4d15-9991-fe61f8a81e9f\HASH-C7AAD85F7B2F0472_1.sav")

HASHES = {
    BASE: "FCAF5CFB8BAC230A041DC68E9B23B0F6916112D8F5406B2312DD19CE2A4E33D2",
    ROLLBACK: "3F63BFD149A100152DE8B1B3223136CC501AF5AC19E19F443D4519142F9C783E",
    FINAL: "9EAEC08A3D94120C712D72321AC28D26272EF771D53CC465542090AC78D24E1C",
    DELTA: "9BAF1A5477B71C501C8B46EE286A667B82B5E296A2E839DBF0D3FC1BE27584EB",
}
PSX = "PSX.EXE"
RANGES = (
    (0x2060, 4, "frame_DrawOT_call"),
    (0x3E14, 8, "range_initializer"),
    (0x75590, 0x34, "pre_DrawOT_cursor_gate"),
    (0x8F0D0, 36, "resident_uploader_epilogue"),
)


class VerifyError(RuntimeError):
    pass


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def archive(path: Path) -> tuple[list[str], dict[str, bytes]]:
    with ZipFile(path) as handle:
        names = [item.filename for item in handle.infolist() if not item.is_dir()]
        return names, {name: handle.read(name) for name in names}


def changes(a: bytes, b: bytes) -> set[int]:
    if len(a) != len(b):
        raise VerifyError("size drift")
    return {index for index, pair in enumerate(zip(a, b, strict=True)) if pair[0] != pair[1]}


def parse_failure_state() -> dict[str, object]:
    spec = importlib.util.spec_from_file_location(
        "arc_state", ROOT / "02_scripts/analyze_arc1_v320c_savestates.py"
    )
    if spec is None or spec.loader is None:
        raise VerifyError("DUCCU parser unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    parsed = module.parse_state(FAILURE_STATE)
    blob = parsed["blob"]
    tag = struct.pack("<I", 3) + b"CPU"
    at = blob.find(tag)
    if at < 0:
        raise VerifyError("CPU section missing")
    at += len(tag)
    current_pc = struct.unpack_from("<I", blob, at + 0xB8)[0]
    cause = struct.unpack_from("<I", blob, at + 0xC4)[0]
    next_pc = struct.unpack_from("<I", blob, at + 0xD4)[0]
    thumbnail = parsed["thumbnail"]
    thumbnail_rgb_nonzero = sum(
        thumbnail[pixel + channel] != 0
        for pixel in range(0, len(thumbnail), 4)
        for channel in range(3)
    )
    if parsed["game_id"] != "V341" or thumbnail_rgb_nonzero != 0:
        raise VerifyError("uploaded state is not the black V341 failure evidence")
    if ((cause >> 2) & 0x1F) != 0 or cause & 0x80000000:
        raise VerifyError("V341 failure unexpectedly carries a CPU exception")
    if current_pc != 0x8016B64C or next_pc != 0x8016B64C:
        raise VerifyError("V341 failure PC pair drift")
    return {
        "sha256": parsed["file_sha256"],
        "game_id": parsed["game_id"],
        "thumbnail_rgb_nonzero_bytes": thumbnail_rgb_nonzero,
        "current_pc": f"0x{current_pc:08X}",
        "next_pc": f"0x{next_pc:08X}",
        "cause": f"0x{cause:08X}",
        "exception_code": (cause >> 2) & 0x1F,
        "interpretation": "CPU is alive in normal text rendering; display/frame regression, not exception crash",
    }


def main() -> None:
    for path, expected in HASHES.items():
        if sha(path.read_bytes()) != expected:
            raise VerifyError(f"archive hash drift: {path.name}")
    base_names, base = archive(BASE)
    old_names, old = archive(ROLLBACK)
    final_names, final = archive(FINAL)
    delta_names, delta = archive(DELTA)
    if len(base_names) != 164 or base_names != old_names or final_names != base_names:
        raise VerifyError("full archive topology drift")
    if delta_names != [PSX] or delta[PSX] != final[PSX]:
        raise VerifyError("delta topology/readback drift")
    if [name for name in base_names if base[name] != final[name]] != [PSX]:
        raise VerifyError("V342 changed a non-PSX member")

    reconstructed = bytearray(base[PSX])
    allowed = set()
    for offset, size, _label in RANGES:
        reconstructed[offset:offset + size] = old[PSX][offset:offset + size]
        allowed.update(range(offset, offset + size))
    if bytes(reconstructed) != final[PSX]:
        raise VerifyError("V342 is not the independent four-range rollback")
    actual = changes(base[PSX], final[PSX])
    if len(actual) != 64 or not actual <= allowed:
        raise VerifyError(f"actual rollback diff drift: {len(actual)}")
    for offset, size, _label in RANGES:
        if final[PSX][offset:offset + size] != old[PSX][offset:offset + size]:
            raise VerifyError("cursor-control range is not V340 byte exact")

    rows = list(csv.DictReader((ANALYSIS / "expected_writes.csv").open(encoding="utf-8-sig", newline="")))
    declared = {int(row["offset"], 16) for row in rows}
    if declared != actual:
        raise VerifyError("Expected-Write set differs from actual PSX diff")
    for row in rows:
        at = int(row["offset"], 16)
        if (row["before"], row["after"]) != (f"{base[PSX][at]:02X}", f"{final[PSX][at]:02X}"):
            raise VerifyError("Expected-Write byte readback mismatch")

    # Everything outside the four rollback envelopes is necessarily V341
    # byte-exact, so its choice/help/map repairs remain present.
    if any(
        base[PSX][at] != final[PSX][at]
        for at in range(len(base[PSX]))
        if at not in allowed
    ):
        raise VerifyError("V341 non-cursor PSX repair changed")
    failure = parse_failure_state()
    result = {
        "result": "STATIC_PASS_RUNTIME_PENDING",
        "changed_members_vs_v341": [PSX],
        "actual_changed_psx_bytes": len(actual),
        "cursor_control": "four ranges V340 byte exact",
        "preserved": "all V341 non-cursor bytes and all DAT/COMM members byte exact",
        "failure_evidence": failure,
        "runtime": "V342 cold boot PENDING",
    }
    (ANALYSIS / "independent_verification.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    lines = [
        "V342 independent static verification: PASS",
        f"full={FINAL.name} sha256={HASHES[FINAL]}",
        f"delta={DELTA.name} sha256={HASHES[DELTA]}",
        "archive=164 members; changed_vs_V341=PSX.EXE only; Expected-Write exact",
        "cursor_control=frame hook, initializer, gate, epilogue all V340 byte exact",
        "preserved=V341 choice alignment, bottom-help W16 Y, Orkas label; every DAT/COMM byte exact",
        f"V341_failure=black thumbnail, ExcCode0, PC {failure['current_pc']} normal text renderer",
        "runtime=V342 cold boot PENDING; range cursor remains open",
    ]
    (ANALYSIS / "independent_verification.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
