#!/usr/bin/env python3
"""Independent static verification for V331 skill/configuration alignment."""

from __future__ import annotations

import csv
import hashlib
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

BASE = ROOT / "03_output/arc1_v330_skill_name_x_minus4_TEST_ONLY_38FE2472.zip"
FINAL = ROOT / "03_output/arc1_v331_skill_config_alignment_TEST_ONLY_4D5F9D16.zip"
DELTA = ROOT / "03_output/arc1_v331_skill_config_alignment_TEST_ONLY_delta_from_v330_1F312682.zip"
V325_UI_MAP = ROOT / "01_work/analysis/arc1_v325_ui_reencode/ui_reencode.csv"
RUNTIME_PACKETS = ROOT / "01_work/analysis/arc1_v329_skill_states_5/packets.csv"
ANALYSIS = ROOT / "01_work/analysis/arc1_v331_skill_config_alignment"

BASE_SHA256 = "38FE24725CA82B721A544C4F6A6B787A4028ADA00F4312A2717F746BAF809DF0"
FINAL_SHA256 = "4D5F9D165B54F8EE740DE313D8524E999DFEC2763BB0E3018F767C499A2E1DD5"
DELTA_SHA256 = "1F312682F7D879AEFFBE71487DB87CA444592BB4430FF8DF8E8D237E024B08ED"
FINAL_PSX_SHA256 = "F627891E1219844CBAB269A789A9ADEF11D2CE61715632D48B0FBD7A96192E46"

PSX = "PSX.EXE"
RAM_TO_FILE = 0x8011A800
FIRST_RAM, SECOND_RAM = 0x8016089C, 0x801608BC
FIRST_FILE, SECOND_FILE = FIRST_RAM - RAM_TO_FILE, SECOND_RAM - RAM_TO_FILE
FIRST_OLD, SECOND_OLD = 0x26640084, 0x266400C0
FIRST_NEW, SECOND_NEW = 0x26640080, 0x266400BC
POINTER_FILE, POINTER_VALUE = 0x825EC, 0x8019C2A4
PAYLOAD_FILE = POINTER_VALUE - RAM_TO_FILE
OLD_REGION = bytes.fromhex("34 DD 1A A1 94 A1 DD CF 00")
NEW_REGION = bytes.fromhex("34 DD 1A 94 DD CF 00 00 00")

SKILL_CALL_FILE = 0x80162080 - RAM_TO_FILE
SKILL_WRAPPER_FILE = 0x8019B0B0 - RAM_TO_FILE
SKILL_WRAPPER_SIZE = 92


class VerifyError(RuntimeError):
    pass


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def read_zip(path: Path) -> tuple[list[str], dict[str, bytes]]:
    with ZipFile(path) as archive:
        names = [item.filename for item in archive.infolist() if not item.is_dir()]
        return names, {name: archive.read(name) for name in names}


def sign16(value: int) -> int:
    return value - 0x10000 if value & 0x8000 else value


def control_target(pc: int, word: int) -> int | None:
    op = word >> 26
    if op in (1, 4, 5, 6, 7):
        return (pc + 4 + sign16(word & 0xFFFF) * 4) & 0xFFFFFFFF
    if op in (2, 3):
        return ((pc + 4) & 0xF0000000) | ((word & 0x03FFFFFF) << 2)
    return None


def inbound_to_words(exe: bytes, targets: set[int]) -> list[tuple[int, int]]:
    hits = []
    for offset in range(0, len(exe) - 3, 4):
        word = struct.unpack_from("<I", exe, offset)[0]
        target = control_target(RAM_TO_FILE + offset, word)
        if target in targets:
            hits.append((RAM_TO_FILE + offset, target))
    return hits


def config_runtime_prediction() -> list[dict[str, object]]:
    with RUNTIME_PACKETS.open(encoding="utf-8-sig", newline="") as handle:
        rows = [
            row for row in csv.DictReader(handle)
            if row["state"] == "3" and row["header"] == "0x801F9D44"
        ]
    if len(rows) != 50:
        raise VerifyError(f"V329 configuration packet census drift: {len(rows)}")
    old_text = "".join(row["char"] for row in rows)
    if "사용 안 함확인함" not in old_text:
        raise VerifyError("V329 configuration string evidence drift")
    result = []
    # The two removed A1 tokens were 6px half-width spaces in the first
    # choice string on y=130.  Removing them changes the coordinates of the
    # following glyphs in that same render call; the second choice at x=226
    # is a separate call and therefore only receives the global -4 shift.
    removed_x = (194, 214)
    for row in rows:
        x, y = int(row["x"]), int(row["y"])
        if y == 130 and x in removed_x and row["char"] == " ":
            continue
        predicted_x = x
        if x >= 166:
            predicted_x -= 4
        if y == 130 and 166 <= x < 226:
            predicted_x -= 6 * sum(space_x < x for space_x in removed_x)
        result.append({
            "source_ordinal": int(row["ordinal"]),
            "char": row["char"],
            "y": y,
            "v329_x": x,
            "v331_predicted_x": predicted_x,
            "scope": "choice_column" if x >= 166 else "label_unchanged",
        })
    if len(result) != 48:
        raise VerifyError("V331 predicted configuration packet count is not 48")
    row130 = [(row["char"], row["v331_predicted_x"]) for row in result if row["y"] == 130]
    expected_row130 = [
        ("돌", 46), ("아", 60), ("가", 74), ("기", 88), (" ", 102),
        ("확", 108), ("인", 122),
        ("사", 162), ("용", 176), ("안", 190), ("함", 204),
        ("확", 222), ("인", 236), ("함", 250),
    ]
    if row130 != expected_row130:
        raise VerifyError(f"V331 사용안함 runtime prediction drift: {row130}")
    return result


def main() -> None:
    for path, digest in ((BASE, BASE_SHA256), (FINAL, FINAL_SHA256), (DELTA, DELTA_SHA256)):
        if sha256(path.read_bytes()) != digest:
            raise VerifyError(f"hash mismatch: {path.name}")
    base_names, base = read_zip(BASE)
    final_names, final = read_zip(FINAL)
    if base_names != final_names or len(final_names) != 164:
        raise VerifyError("archive topology mismatch")
    if [name for name in base_names if base[name] != final[name]] != [PSX]:
        raise VerifyError("changed member set is not PSX.EXE only")
    with ZipFile(DELTA) as archive:
        if archive.namelist() != [PSX] or archive.read(PSX) != final[PSX]:
            raise VerifyError("delta archive mismatch")

    exe0, exe1 = base[PSX], final[PSX]
    if sha256(exe1) != FINAL_PSX_SHA256:
        raise VerifyError("V331 PSX.EXE hash mismatch")
    if struct.unpack_from("<I", exe0, FIRST_FILE)[0] != FIRST_OLD:
        raise VerifyError("V330 first configuration X word drift")
    if struct.unpack_from("<I", exe0, SECOND_FILE)[0] != SECOND_OLD:
        raise VerifyError("V330 second configuration X word drift")
    if struct.unpack_from("<I", exe1, FIRST_FILE)[0] != FIRST_NEW:
        raise VerifyError("V331 first configuration X is not 162")
    if struct.unpack_from("<I", exe1, SECOND_FILE)[0] != SECOND_NEW:
        raise VerifyError("V331 second configuration X is not 222")
    if struct.unpack_from("<I", exe1, POINTER_FILE)[0] != POINTER_VALUE:
        raise VerifyError("configuration pointer changed")
    pointer_hits = [
        offset for offset in range(0, len(exe1) - 3)
        if struct.unpack_from("<I", exe1, offset)[0] == POINTER_VALUE
    ]
    if pointer_hits != [POINTER_FILE]:
        raise VerifyError(f"configuration payload ownership drift: {pointer_hits}")
    if exe0[PAYLOAD_FILE : PAYLOAD_FILE + 9] != OLD_REGION:
        raise VerifyError("V330 사용 안 함 payload drift")
    if exe1[PAYLOAD_FILE : PAYLOAD_FILE + 9] != NEW_REGION:
        raise VerifyError("V331 사용안함 payload mismatch")

    # Independent semantic check: the V325 readback proves the old token
    # sequence; V331 must be exactly that sequence with its two A1 spaces
    # removed, followed by a terminator and zero tail.
    with V325_UI_MAP.open(encoding="utf-8-sig", newline="") as handle:
        rows = [row for row in csv.DictReader(handle) if int(row["pointer_offset"], 0) == POINTER_FILE]
    if len(rows) != 1 or rows[0]["korean"] != "사용 안 함":
        raise VerifyError("V325 UI manifest ownership/semantic drift")
    old_payload = bytes.fromhex(rows[0]["encoded_hex"])
    if old_payload != OLD_REGION[:-1] or old_payload.replace(b"\xA1", b"") != NEW_REGION[:6]:
        raise VerifyError("사용안함 is not the exact two-space removal")

    exact = bytearray(exe0)
    struct.pack_into("<I", exact, FIRST_FILE, FIRST_NEW)
    struct.pack_into("<I", exact, SECOND_FILE, SECOND_NEW)
    exact[PAYLOAD_FILE : PAYLOAD_FILE + 9] = NEW_REGION
    if bytes(exact) != exe1:
        raise VerifyError("V331 is not the exact declared overlay")
    diff = {i for i, (a, b) in enumerate(zip(exe0, exe1, strict=True)) if a != b}
    envelope = (
        set(range(FIRST_FILE, FIRST_FILE + 4))
        | set(range(SECOND_FILE, SECOND_FILE + 4))
        | set(range(PAYLOAD_FILE, PAYLOAD_FILE + 9))
    )
    if len(diff) != 7 or not diff <= envelope:
        raise VerifyError(f"Expected-Write mismatch: {len(diff)}")
    if inbound_to_words(exe1, {FIRST_RAM, SECOND_RAM}):
        raise VerifyError("patched configuration instructions are control-flow entry targets")

    # V330's already-verified skill route/wrapper must be inherited exactly.
    if exe0[SKILL_CALL_FILE : SKILL_CALL_FILE + 8] != exe1[SKILL_CALL_FILE : SKILL_CALL_FILE + 8]:
        raise VerifyError("V330 skill call changed")
    if exe0[SKILL_WRAPPER_FILE : SKILL_WRAPPER_FILE + SKILL_WRAPPER_SIZE] != exe1[SKILL_WRAPPER_FILE : SKILL_WRAPPER_FILE + SKILL_WRAPPER_SIZE]:
        raise VerifyError("V330 skill wrapper changed")

    predictions = config_runtime_prediction()
    ANALYSIS.mkdir(parents=True, exist_ok=True)
    with (ANALYSIS / "runtime_coordinate_prediction.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(predictions[0]))
        writer.writeheader()
        writer.writerows(predictions)

    verification = {
        "result": "PASS",
        "hashes": {"base": BASE_SHA256, "final": FINAL_SHA256, "delta": DELTA_SHA256},
        "archive": {"members": 164, "changed_members": [PSX]},
        "expected_write": {"changed_bytes": 7, "declared_envelope_only": True},
        "configuration": "renderer-only columns 166/226 -> 162/222; 0x825EC sole payload 사용 안 함 -> 사용안함",
        "skill": "V330 call and 92-byte dx=-4 wrapper inherited byte-exact",
        "runtime_prediction": "configuration labels unchanged; 26 choice packets x-=4; two A1 packets removed; 50 -> 48 packets",
        "runtime": "PENDING V331 user cold boot",
    }
    (ANALYSIS / "independent_verification.json").write_text(
        json.dumps(verification, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    lines = [
        "V331 independent verification: PASS",
        f"full_sha256={FINAL_SHA256}",
        f"delta_sha256={DELTA_SHA256}",
        "archive=164 members; changed=PSX.EXE only; exact declared overlay",
        "Expected-Write=7 changed bytes in two X immediates + sole 0x825EC payload",
        "configuration=choice columns X 166/226 -> 162/222",
        "text=사용 안 함 -> 사용안함 by exact removal of two A1 spaces",
        "scope=labels/window/other UI unchanged; patched words have no control-flow inbound",
        "skill=V330 skill-only dx=-4 call and wrapper inherited byte-exact",
        "runtime=PENDING V331 cold boot; TEST_ONLY",
    ]
    (ANALYSIS / "independent_verification.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
