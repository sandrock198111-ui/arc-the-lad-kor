#!/usr/bin/env python3
"""Independent static verifier for the V353 summon action-record repair."""

from __future__ import annotations

import csv
import hashlib
import json
import struct
from pathlib import Path
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "03_output/arc1_v352_punctuation_code_repair_TEST_ONLY_D4E8D2E2.zip"
BASE_SHA256 = "D4E8D2E24238123065DE0D3AF1F3FF4F7E82CCB9CB17ACEC5241AB3C2E6DDE3D"
ORIGINAL = ROOT / "00_original/arc.zip"
ORIGINAL_SHA256 = "AE9F4366A1E7DA3805BB3BED3DDA9567E4CD4E669AF890E4E2A620D7861F11DD"
V206 = ROOT / "03_output/arc1_v206_restore_zeroed_script_data.zip"
V206_SHA256 = "974AAC70D3DBFC3414AE81D71871AF010CF1DFF745CF0F836387C0DFBFA6CD5D"
V207 = ROOT / "03_output/arc1_v207_move_stub_strings.zip"
V207_SHA256 = "9C06092ED16307FECDE1F38E62B32933782AD22D5E1C199D4D0855F82595162E"
ANALYSIS = ROOT / "01_work/analysis/arc1_v353_summon_skill_action_record_repair"

PSX = "PSX.EXE"
COMM = "COMM.IMG"
RECORD_FILE = 0x78ADC
ACTION_WORD_FILE = 0x78AE4
RECORD_RAM = 0x801932DC
BEFORE_RECORD = bytes.fromhex("58 38 12 80 6C 3B 12 80 26 E0 52 A3")
AFTER_RECORD = bytes.fromhex("58 38 12 80 6C 3B 12 80 26 00 00 00")
REPAIRS = (
    (0x78AE5, 0xE0, 0x00),
    (0x78AE6, 0x52, 0x00),
    (0x78AE7, 0xA3, 0x00),
)
RECORD_REFERENCES = (0x78B48, 0x78B58)
LIVE_POINTER_FILE = 0x82A6C
LIVE_POINTER_VALUE = 0x8019AF14
STALE_POINTERS = tuple(range(0x801932E5, 0x801932EB))


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def archive(path: Path) -> tuple[list[str], dict[str, bytes]]:
    with ZipFile(path) as z:
        names = [i.filename for i in z.infolist() if not i.is_dir()]
        return names, {name: z.read(name) for name in names}


def member(path: Path, name: str) -> bytes:
    with ZipFile(path) as z:
        return z.read(name)


def assert_hash(path: Path, expected: str, label: str) -> None:
    if not path.is_file() or sha(path.read_bytes()) != expected:
        raise AssertionError(f"{label} hash drift")


def stale_pointer_hits(members: dict[str, bytes]) -> list[tuple[str, int, int]]:
    hits: list[tuple[str, int, int]] = []
    for name, data in members.items():
        for pointer in STALE_POINTERS:
            needle = struct.pack("<I", pointer)
            offset = data.find(needle)
            while offset >= 0:
                hits.append((name, offset, pointer))
                offset = data.find(needle, offset + 1)
    return hits


def main() -> None:
    assert_hash(BASE, BASE_SHA256, "V352 base")
    assert_hash(ORIGINAL, ORIGINAL_SHA256, "original")
    assert_hash(V206, V206_SHA256, "V206")
    assert_hash(V207, V207_SHA256, "V207")

    original_exe = member(ORIGINAL, PSX)
    v206_exe = member(V206, PSX)
    v207_exe = member(V207, PSX)
    if original_exe[RECORD_FILE:RECORD_FILE + 12] != AFTER_RECORD:
        raise AssertionError("original action record is not 0x26")
    if v206_exe[RECORD_FILE:RECORD_FILE + 12] != AFTER_RECORD:
        raise AssertionError("V206 action record is not 0x26")
    if v207_exe[RECORD_FILE:RECORD_FILE + 12] != bytes.fromhex(
        "58 38 12 80 6C 3B 12 80 26 E0 0A A3"
    ):
        raise AssertionError("V207 is not the pinned first corruption")

    candidates = sorted(
        p for p in (ROOT / "03_output").glob(
            "arc1_v353_summon_skill_action_record_repair_TEST_ONLY_*.zip"
        )
        if "delta" not in p.name
    )
    deltas = sorted((ROOT / "03_output").glob(
        "arc1_v353_summon_skill_action_record_repair_TEST_ONLY_delta_from_v352_*.zip"
    ))
    if len(candidates) != 1 or len(deltas) != 1:
        raise AssertionError(
            f"expected one V353 full/delta archive, found {[p.name for p in candidates]} / "
            f"{[p.name for p in deltas]}"
        )
    output, delta = candidates[0], deltas[0]
    output_sha = sha(output.read_bytes())
    delta_sha = sha(delta.read_bytes())
    if not output.stem.endswith(output_sha[:8]) or not delta.stem.endswith(delta_sha[:8]):
        raise AssertionError("archive digest suffix mismatch")

    old_names, old = archive(BASE)
    new_names, new = archive(output)
    if old_names != new_names or len(new_names) != 164:
        raise AssertionError("archive topology/order changed")
    changed = [name for name in old_names if old[name] != new[name]]
    if changed != [PSX]:
        raise AssertionError(f"changed-member drift: {changed}")
    for name in old_names:
        if len(old[name]) != len(new[name]):
            raise AssertionError(f"member size changed: {name}")

    diff = {
        i for i, (before, after) in enumerate(zip(old[PSX], new[PSX], strict=True))
        if before != after
    }
    expected_diff = {offset for offset, _before, _after in REPAIRS}
    if diff != expected_diff:
        raise AssertionError(f"Expected-Write mismatch: {sorted(diff ^ expected_diff)}")
    for offset, before, after in REPAIRS:
        if old[PSX][offset] != before or new[PSX][offset] != after:
            raise AssertionError(f"repair mismatch at PSX.EXE:0x{offset:X}")

    if old[PSX][RECORD_FILE:RECORD_FILE + 12] != BEFORE_RECORD:
        raise AssertionError("V352 before-record drift")
    if new[PSX][RECORD_FILE:RECORD_FILE + 12] != AFTER_RECORD:
        raise AssertionError("V353 record does not match original/V206")
    if new[PSX][RECORD_FILE:RECORD_FILE + 12] != original_exe[RECORD_FILE:RECORD_FILE + 12]:
        raise AssertionError("V353 action record differs from original")

    before_word = struct.unpack_from("<I", old[PSX], ACTION_WORD_FILE)[0]
    after_word = struct.unpack_from("<I", new[PSX], ACTION_WORD_FILE)[0]
    before_signed = struct.unpack_from("<h", old[PSX], ACTION_WORD_FILE)[0]
    after_signed = struct.unpack_from("<h", new[PSX], ACTION_WORD_FILE)[0]
    if (before_word, after_word) != (0xA352E026, 0x00000026):
        raise AssertionError("action-word transition drift")
    if not (before_signed < 0 and after_signed == 0x26):
        raise AssertionError("signed action-index regression guard failed")

    for offset in RECORD_REFERENCES:
        if struct.unpack_from("<I", new[PSX], offset)[0] != RECORD_RAM:
            raise AssertionError(f"record reference changed at PSX.EXE:0x{offset:X}")
    if struct.unpack_from("<I", new[PSX], LIVE_POINTER_FILE)[0] != LIVE_POINTER_VALUE:
        raise AssertionError("current relocated string pointer changed")
    hits = stale_pointer_hits(new)
    if hits:
        raise AssertionError(f"stale string pointer remains: {hits[:5]}")

    # The three repaired zeros are members of a live 32-bit field, not a free
    # string cave.  Pinning the whole record prevents another zero-run allocator
    # from treating 0x78AE5..0x78AE7 as disposable space.
    if new[PSX][ACTION_WORD_FILE:ACTION_WORD_FILE + 4] != bytes.fromhex("26 00 00 00"):
        raise AssertionError("live-zero-field guard failed")

    if new[COMM] != old[COMM]:
        raise AssertionError("COMM.IMG changed")
    dat_changes = [name for name in changed if name.upper().endswith(".DAT")]
    if dat_changes:
        raise AssertionError(f"DAT changed: {dat_changes}")
    if new[PSX][:0x800] != old[PSX][:0x800]:
        raise AssertionError("PS-X EXE header changed")
    if new[PSX][:8] != b"PS-X EXE":
        raise AssertionError("PS-X EXE magic missing")
    if struct.unpack_from("<I", new[PSX], 0x18)[0] != 0x8011B000:
        raise AssertionError("PS-X EXE load address drift")
    if struct.unpack_from("<I", new[PSX], 0x1C)[0] != 0x0008F000:
        raise AssertionError("PS-X EXE text size drift")

    delta_names, delta_members = archive(delta)
    if delta_names != [PSX] or delta_members[PSX] != new[PSX]:
        raise AssertionError("delta archive is not the exact V353 PSX.EXE")

    expected_csv = ANALYSIS / "expected_writes.csv"
    with expected_csv.open(encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    csv_triples = {
        (int(row["offset"], 16), int(row["before"], 16), int(row["after"], 16))
        for row in rows
    }
    if csv_triples != set(REPAIRS):
        raise AssertionError("expected_writes.csv disagrees with independent constants")

    manifest_path = ANALYSIS / "build_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest["output"]["sha256"] != output_sha or manifest["delta"]["sha256"] != delta_sha:
        raise AssertionError("build manifest archive hash mismatch")

    verification = {
        "version": "V353",
        "result": "PASS_STATIC_RUNTIME_PENDING",
        "output": {"file": output.name, "sha256": output_sha},
        "delta": {"file": delta.name, "sha256": delta_sha},
        "checks": {
            "archive_topology_order": "PASS 164/164",
            "changed_members": [PSX],
            "expected_write": "PASS 3 bytes at 0x78AE5..0x78AE7",
            "action_record_original_match": "PASS 12/12 bytes",
            "action_transition": "0xA352E026 -> 0x00000026",
            "signed_low16": f"{before_signed} -> {after_signed}",
            "record_references": [f"0x{x:X}" for x in RECORD_REFERENCES],
            "stale_pointer_hits": 0,
            "comm_and_dat_preservation": "PASS",
            "delta_readback": "PASS",
            "live_zero_field_guard": "PASS",
        },
        "runtime": "PENDING user cold boot; static verification cannot prove real execution",
    }
    (ANALYSIS / "independent_verification.json").write_text(
        json.dumps(verification, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(f"V353={output.name} sha256={output_sha}")
    print(f"delta={delta.name} sha256={delta_sha}")
    print("archive topology/order PASS: 164/164")
    print("Expected-Write PASS: PSX.EXE only, 3 bytes at 0x78AE5..0x78AE7")
    print("action record PASS: V352 0xA352E026 -> V353/original/V206 0x00000026")
    print(f"signed action low16 PASS: {before_signed} -> {after_signed}")
    print("record references/current pointer/stale pointer scan/live-zero-field guard PASS")
    print("COMM.IMG/all DAT/member sizes/PS-X EXE header/delta readback PASS")
    print("RESULT: PASS (static only; V353 runtime not established)")


if __name__ == "__main__":
    main()
