#!/usr/bin/env python3
"""Build V335: move only the common dialogue text origin 4 pixels upward.

V334 renders 16px dialogue rows from Y=36 (top window) or Y=166
(bottom window), with a 16px line pitch.  Four rows therefore begin at
36/52/68/84 or 166/182/198/214.  V335 changes the two construction sites
and the two reset-path immediates to Y=32/162.  Choice-cursor code/data, window
backgrounds, UI objects, COMM.IMG and every DAT member remain byte-identical;
the cursor's final screen coordinate remains a runtime observation gate.
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


BASE = ROOT / "03_output/arc1_v334_delay_slot_payload_relocation_TEST_ONLY_9089151E.zip"
BASE_SHA256 = "9089151E90CDC53CDC4187D6DE403E6C8654B2D302E65462A38D2A7AAE1B8CFC"
BASE_PSX_SHA256 = "EED09C4AEA7EE826B5EB1368C69200075866DCCE6C822537A4A28C4ABED69BFC"
BASE_COMM_SHA256 = "095885C3EA58F1A886BEE20033EE8313FE07476088AC27FD726F53AE44D8331B"

OUTPUT_STEM = "arc1_v335_dialogue_text_y_minus4_TEST_ONLY"
DELTA_STEM = OUTPUT_STEM + "_delta_from_v334"
ANALYSIS = ROOT / "01_work/analysis/arc1_v335_dialogue_text_y_minus4"

PSX = "PSX.EXE"
COMM = "COMM.IMG"

# Both dialogue objects are initialized once and then reconfigured through a
# top/bottom reset branch.  All four sites must agree or later dialogue pages
# would jump back to the old vertical origin.
Y_SITES = (
    (0x418F8, 0x34050024, 0x34050020, "top_object_initial_Y", 36, 32),
    (0x41918, 0x340500A6, 0x340500A2, "bottom_object_initial_Y", 166, 162),
    (0x41970, 0x34050024, 0x34050020, "top_object_reset_Y", 36, 32),
    (0x41988, 0x340500A6, 0x340500A2, "bottom_object_reset_Y", 166, 162),
)

# Structural anchors proving these immediates still feed the dialogue-state
# initializer and that subsequent E6 lines continue to use H+spacing.
DIALOGUE_INIT_CALLS = (
    (0x41900, 0x0C05AE20),
    (0x41920, 0x0C05AE20),
    (0x41990, 0x0C05AE20),
)
RESET_TOP_JUMP = (0x4196C, 0x08057063)
SETTER_WORDS = (0xA4C40006, 0x03E00008, 0xA4C50008)  # 0x8016B418
SETTER_FILE = 0x50C18
LINE_BREAK_WORDS = (
    0x02003021,
    0x86050008,
    0x9202000E,
    0x92030010,
    0x8604001E,
    0x00A22821,
    0x0C05AD06,
    0x00A32821,
)
LINE_BREAK_FILE = 0x51494

# Explicitly inherited choice-placeholder/cursor route.  V335 must not touch it.
E5_PLACEHOLDER_FILE = 0x51604
E5_PLACEHOLDER_WORD = 0x340403C0


class BuildError(RuntimeError):
    pass


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def changed_offsets(before: bytes, after: bytes) -> set[int]:
    if len(before) != len(after):
        raise BuildError("member size changed")
    return {
        offset
        for offset, (old, new) in enumerate(zip(before, after, strict=True))
        if old != new
    }


def assert_word(exe: bytes, offset: int, expected: int, label: str) -> None:
    actual = struct.unpack_from("<I", exe, offset)[0]
    if actual != expected:
        raise BuildError(
            f"{label} drift at 0x{offset:X}: 0x{actual:08X} != 0x{expected:08X}"
        )


def assert_base(members: dict[str, bytes]) -> None:
    if len(members) != 164:
        raise BuildError(f"V334 member count drift: {len(members)}")
    exe = members[PSX]
    if sha256_bytes(exe) != BASE_PSX_SHA256:
        raise BuildError("V334 PSX.EXE hash drift")
    if sha256_bytes(members[COMM]) != BASE_COMM_SHA256:
        raise BuildError("V334 COMM.IMG hash drift")
    for offset, before_word, _after_word, label, _old_y, _new_y in Y_SITES:
        assert_word(exe, offset, before_word, label)
    for offset, word in DIALOGUE_INIT_CALLS:
        assert_word(exe, offset, word, "dialogue initializer call")
    assert_word(exe, *RESET_TOP_JUMP, "top reset branch")
    if struct.unpack_from("<3I", exe, SETTER_FILE) != SETTER_WORDS:
        raise BuildError("dialogue X/Y setter drift")
    if struct.unpack_from("<8I", exe, LINE_BREAK_FILE) != LINE_BREAK_WORDS:
        raise BuildError("E6 line-break pitch path drift")
    assert_word(exe, E5_PLACEHOLDER_FILE, E5_PLACEHOLDER_WORD, "E5 choice route")


def build_once(before: dict[str, bytes]) -> tuple[dict[str, bytes], dict[str, object]]:
    assert_base(before)
    exe = bytearray(before[PSX])
    for offset, _before_word, after_word, _label, _old_y, _new_y in Y_SITES:
        struct.pack_into("<I", exe, offset, after_word)

    for offset, _before_word, after_word, label, _old_y, _new_y in Y_SITES:
        assert_word(exe, offset, after_word, label)
    if struct.unpack_from("<3I", exe, SETTER_FILE) != SETTER_WORDS:
        raise BuildError("dialogue setter changed unexpectedly")
    if struct.unpack_from("<8I", exe, LINE_BREAK_FILE) != LINE_BREAK_WORDS:
        raise BuildError("line pitch changed unexpectedly")
    assert_word(exe, E5_PLACEHOLDER_FILE, E5_PLACEHOLDER_WORD, "E5 choice route")

    final = dict(before)
    final[PSX] = bytes(exe)
    metadata = {
        "dialogue_text_origins": {
            "top_before": [36, 52, 68, 84],
            "top_after": [32, 48, 64, 80],
            "bottom_before": [166, 182, 198, 214],
            "bottom_after": [162, 178, 194, 210],
            "line_pitch": 16,
        },
        "preserved_choice_cursor": {
            "file_offset": "0x51604",
            "word": "0x340403C0",
            "policy": (
                "choice cursor code/data intentionally unchanged; final screen "
                "coordinate requires V335 runtime observation"
            ),
        },
    }
    return final, metadata


def main() -> None:
    if not BASE.is_file() or v324.sha256_file(BASE) != BASE_SHA256:
        raise BuildError(f"V334 base hash mismatch: {BASE}")
    infos, before = v324.read_archive(BASE)

    final, metadata = build_once(before)
    rebuilt, rebuilt_metadata = build_once(before)
    if final != rebuilt or metadata != rebuilt_metadata:
        raise BuildError("in-memory deterministic rebuild mismatch")

    changed_members = [name for name in before if before[name] != final[name]]
    if changed_members != [PSX]:
        raise BuildError(f"changed member set drift: {changed_members}")
    if any(len(before[name]) != len(final[name]) for name in before):
        raise BuildError("member size changed")

    actual = changed_offsets(before[PSX], final[PSX])
    expected = {offset for offset, *_rest in Y_SITES}
    if actual != expected:
        raise BuildError(
            f"Expected-Write mismatch: actual={sorted(actual)} expected={sorted(expected)}"
        )

    output_path, output_hash = v324.write_archive(OUTPUT_STEM, infos, final, None)
    delta_path, delta_hash = v324.write_archive(DELTA_STEM, infos, final, {PSX})
    with ZipFile(output_path) as archive:
        names = [item.filename for item in archive.infolist() if not item.is_dir()]
        expected_names = [item.filename for item in infos if not item.is_dir()]
        if names != expected_names or any(archive.read(name) != final[name] for name in final):
            raise BuildError("full ZIP round-trip/topology mismatch")
    with ZipFile(delta_path) as archive:
        if archive.namelist() != [PSX] or archive.read(PSX) != final[PSX]:
            raise BuildError("delta ZIP round-trip mismatch")

    ANALYSIS.mkdir(parents=True, exist_ok=True)
    with (ANALYSIS / "expected_writes.csv").open(
        "w", encoding="utf-8-sig", newline=""
    ) as handle:
        writer = csv.writer(handle)
        writer.writerow(("member", "offset", "before", "after", "purpose"))
        site_by_offset = {site[0]: site for site in Y_SITES}
        for offset in sorted(actual):
            _at, _before_word, _after_word, label, old_y, new_y = site_by_offset[offset]
            writer.writerow(
                (
                    PSX,
                    f"0x{offset:X}",
                    f"{before[PSX][offset]:02X}",
                    f"{final[PSX][offset]:02X}",
                    f"{label}:{old_y}->{new_y}",
                )
            )

    manifest = {
        "build": "V335 TEST_ONLY global dialogue text Y minus 4",
        "base": {"path": str(BASE), "sha256": BASE_SHA256},
        "output": {"path": str(output_path), "sha256": output_hash},
        "delta": {"path": str(delta_path), "sha256": delta_hash},
        "changed_members": changed_members,
        "changed_bytes": {PSX: len(actual)},
        **metadata,
        "preserved": (
            "V334 choice cursor code/data, dialogue backgrounds, COMM.IMG, all DAT, "
            "UI/item/skill paths and every non-PSX member"
        ),
        "runtime": "PENDING user cold boot",
        "release_status": "TEST ONLY; DO NOT DISTRIBUTE",
    }
    (ANALYSIS / "build_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    report = [
        "V335 TEST ONLY - global dialogue text Y minus 4",
        f"base={BASE.name}",
        f"output={output_path.name}",
        f"sha256={output_hash}",
        f"delta={delta_path.name}",
        f"delta_sha256={delta_hash}",
        "changed_members=PSX.EXE only",
        f"changed_bytes={len(actual)}",
        "top dialogue rows=36/52/68/84 -> 32/48/64/80",
        "bottom dialogue rows=166/182/198/214 -> 162/178/194/210",
        "choice cursor code+data/background/COMM.IMG/all DAT/UI=item=skill unchanged",
        "runtime=PENDING; TEST_ONLY",
    ]
    (ANALYSIS / "build_report.txt").write_text("\n".join(report) + "\n", encoding="utf-8")
    (ANALYSIS / "runtime_checklist.txt").write_text(
        "\n".join(
            (
                "V335 cold-boot checklist",
                "",
                "- Boot V335.cue from power-off/cold boot; do not load a V333 savestate.",
                "- Confirm normal top dialogue text is exactly 4px higher.",
                "- Confirm normal bottom dialogue text is exactly 4px higher.",
                "- Confirm four dialogue rows fit vertically without clipping.",
                "- Confirm choice text is 4px higher while the triangle cursor remains unchanged.",
                "- Confirm dialogue backgrounds, portraits, UI, items, skills and battle HUD match V334.",
                "- Confirm dialogue progression and choices do not freeze.",
                "",
                "Until these pass, V335 remains TEST_ONLY and bible_current.txt stays unchanged.",
            )
        )
        + "\n",
        encoding="utf-8",
    )
    print("\n".join(report))


if __name__ == "__main__":
    main()
