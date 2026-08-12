#!/usr/bin/env python3
"""Independent static verification for the v193 skill-range repair."""
from __future__ import annotations

import hashlib
import struct
import sys
from pathlib import Path
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))

import verify_arc1_v191_yagun_choice_local_fixes as runtime  # noqa: E402


BASE = ROOT / "03_output/arc1_v192_choice_speaker_rows_899DDD9A.zip"
ORIGINAL = ROOT / "00_original/arc.zip"
OUT_DIR = ROOT / "03_output"
OUT_PATTERN = "arc1_v193_restore_skill_range_levelup_dynamic_*.zip"
REPORT = ROOT / "01_work/analysis/arc1_v193_restore_skill_range_levelup_dynamic/verification.txt"

PSX, COMM = "PSX.EXE", "COMM.IMG"
ROW_BYTES = 896
PAYLOAD_AT = 0x854C8
PAYLOAD = bytes.fromhex("DF E8 E1 EA 9C CD 8E DF E3 DF E3 00")
POINTER_AT, POINTER = 0x82518, 0x8019FCC8


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def pixel(data: bytes, x: int, y: int) -> int:
    value = data[y * ROW_BYTES + x // 2]
    return (value >> (4 * (x & 1))) & 15


def main() -> None:
    candidates = sorted(OUT_DIR.glob(OUT_PATTERN))
    if len(candidates) != 1:
        raise SystemExit(f"expected exactly one v193 output, found {len(candidates)}")
    output = candidates[0]
    with ZipFile(BASE) as archive:
        base_names = archive.namelist()
        before = {name: archive.read(name) for name in base_names}
    with ZipFile(ORIGINAL) as archive:
        original_font = archive.read(COMM)
    with ZipFile(output) as archive:
        if archive.namelist() != base_names:
            raise SystemExit("member order differs")
        after = {name: archive.read(name) for name in base_names}

    changed = sorted(name for name in base_names if before[name] != after[name])
    if changed != [COMM, PSX]:
        raise SystemExit(f"changed member set differs: {changed}")
    if any(len(before[name]) != len(after[name]) for name in base_names):
        raise SystemExit("member length changed")

    exe, font = after[PSX], after[COMM]
    if exe[PAYLOAD_AT:PAYLOAD_AT + len(PAYLOAD)] != PAYLOAD:
        raise SystemExit("level-up payload differs")
    if struct.unpack_from("<I", exe, POINTER_AT)[0] != POINTER:
        raise SystemExit("level-up pointer differs")
    decoder = runtime.runtime_decoder(exe)
    at = 0
    text: list[str] = []
    while at < len(PAYLOAD) - 1:
        width = 2 if PAYLOAD[at] >= 0xDD else 1
        token = PAYLOAD[at:at + width]
        # The runtime map intentionally names Korean glyphs, not punctuation.
        # DF E3 is the long-standing verified exclamation-mark token.
        text.append("!" if token == bytes.fromhex("DF E3") else decoder(token))
        at += width
    if "".join(text) != "\ub808\ubca8 \uc0c1\uc2b9!!":
        raise SystemExit(f"runtime payload decode differs: {''.join(text)!r}")

    # The full cell must be transparent again, and the exact live sampling
    # union may retain only v181's single accepted low-bit difference.
    for y in range(132, 144):
        for x in range(36, 48):
            if pixel(font, x, y) != pixel(original_font, x, y):
                raise SystemExit(f"restored cell differs at {x},{y}")
    range_diff = [
        (x, y, pixel(original_font, x, y), pixel(font, x, y))
        for y in range(128, 161)
        for x in range(0, 65)
        if pixel(original_font, x, y) != pixel(font, x, y)
    ]
    if range_diff != [(54, 128, 9, 11)]:
        raise SystemExit(f"live range source differs unexpectedly: {range_diff[:8]}")

    psx_diffs = [i for i, pair in enumerate(zip(before[PSX], exe)) if pair[0] != pair[1]]
    if any(not PAYLOAD_AT <= i < PAYLOAD_AT + len(PAYLOAD) for i in psx_diffs):
        raise SystemExit("PSX change outside payload")
    comm_diffs = sum(a != b for a, b in zip(before[COMM], font))
    if comm_diffs != 46:
        raise SystemExit(f"COMM restored byte count is {comm_diffs}, not 46")

    lines = [
        "v193 independent verification PASS",
        f"output={output.name}",
        f"sha256={digest(output.read_bytes())}",
        f"changed_members={','.join(changed)}",
        "runtime_decode=레벨 상승!! PASS",
        "row11_col3=original-exact all four planes PASS",
        "active_skill_range_source=v182 Hangul absent PASS",
        "all_DAT_members=byte-identical PASS",
        "member_order_and_lengths=PASS",
        f"PSX_payload_changed_bytes={len(psx_diffs)}",
        f"COMM_restored_bytes={comm_diffs}",
        "emulator_run=NO",
    ]
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
