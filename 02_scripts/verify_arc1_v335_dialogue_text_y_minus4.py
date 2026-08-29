#!/usr/bin/env python3
"""Independent static verification for V335's dialogue-only Y shift."""

from __future__ import annotations

import csv
import hashlib
import json
import struct
from pathlib import Path
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "03_output/arc1_v334_delay_slot_payload_relocation_TEST_ONLY_9089151E.zip"
OUTPUT = ROOT / "03_output/arc1_v335_dialogue_text_y_minus4_TEST_ONLY_CF4FB2E5.zip"
DELTA = ROOT / "03_output/arc1_v335_dialogue_text_y_minus4_TEST_ONLY_delta_from_v334_02721A13.zip"
ANALYSIS = ROOT / "01_work/analysis/arc1_v335_dialogue_text_y_minus4"

BASE_SHA256 = "9089151E90CDC53CDC4187D6DE403E6C8654B2D302E65462A38D2A7AAE1B8CFC"
OUTPUT_SHA256 = "CF4FB2E518ADD6CE6B528C44D2AD4696DCD9DAF2940FE0A105F60B50C76C70D0"
DELTA_SHA256 = "02721A137139B359F84AC74BB3F0FC325A9E973EE746C6F94D6E72D36ECB4FA7"
OUTPUT_PSX_SHA256 = "B64C7F42AEAF173903CDF7A3B947B09ACE12C83A7E763F72F720240CC9AA2C54"
COMM_SHA256 = "095885C3EA58F1A886BEE20033EE8313FE07476088AC27FD726F53AE44D8331B"

PSX = "PSX.EXE"
COMM = "COMM.IMG"
RAM_TO_FILE = 0x8011A800

SITES = (
    (0x418F8, 0x8015C0F8, 0x34050024, 0x34050020, "top_initial"),
    (0x41918, 0x8015C118, 0x340500A6, 0x340500A2, "bottom_initial"),
    (0x41970, 0x8015C170, 0x34050024, 0x34050020, "top_reset"),
    (0x41988, 0x8015C188, 0x340500A6, 0x340500A2, "bottom_reset"),
)
EXPECTED_CHANGED_OFFSETS = {site[0] for site in SITES}

SETTER_FILE = 0x50C18
SETTER_WORDS = (0xA4C40006, 0x03E00008, 0xA4C50008)
CONFIG_FILE = 0x51090
CONFIG_WORDS = (
    0xA444001E,  # sh a0,+0x1E: saved line-start X
    0xA4450020,  # sh a1,+0x20: saved line-start Y
    0xA4460022,
    0xA4470024,
)
LINE_BREAK_FILE = 0x51494
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
E5_PLACEHOLDER_FILE = 0x51604
E5_PLACEHOLDER_WORD = 0x340403C0
DIRECT_GLYPH_FILE = 0x51594
DIRECT_GLYPH_WORDS = (
    0x0C05ACF0,  # decode next ordinary glyph token from state s0+0x18
    0x26040018,
    0x00402021,
    0x0C05AD46,  # common glyph builder
    0x02002821,  # a1=s0: same dialogue state
)
E5_GLYPH_WORDS = (
    0x340403C0,  # synthetic blank physical index
    0x0C05AD46,  # same common glyph builder
    0x02002821,  # a1=s0: same dialogue state as option text
)


class VerifyError(RuntimeError):
    pass


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def file_sha256(path: Path) -> str:
    return sha256(path.read_bytes())


def read_zip(path: Path) -> tuple[list[str], dict[str, bytes]]:
    with ZipFile(path) as archive:
        names = [item.filename for item in archive.infolist() if not item.is_dir()]
        return names, {name: archive.read(name) for name in names}


def disassemble_sites(exe: bytes) -> list[str]:
    try:
        from capstone import CS_ARCH_MIPS, CS_MODE_LITTLE_ENDIAN, CS_MODE_MIPS32, Cs

        engine = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 | CS_MODE_LITTLE_ENDIAN)
        lines = []
        for offset, address, _before, _after, label in SITES:
            word = exe[offset : offset + 4]
            decoded = list(engine.disasm(word, address))
            if len(decoded) != 1:
                raise VerifyError(f"cannot disassemble {label}")
            insn = decoded[0]
            lines.append(
                f"{label}: {insn.address:08X} {insn.mnemonic} {insn.op_str}".rstrip()
            )
        return lines
    except ImportError:
        return [
            f"{label}: {address:08X} word=0x{struct.unpack_from('<I', exe, offset)[0]:08X}"
            for offset, address, _before, _after, label in SITES
        ]


def main() -> None:
    for path, expected in (
        (BASE, BASE_SHA256),
        (OUTPUT, OUTPUT_SHA256),
        (DELTA, DELTA_SHA256),
    ):
        if not path.is_file() or file_sha256(path) != expected:
            raise VerifyError(f"archive hash mismatch: {path}")

    base_names, before = read_zip(BASE)
    out_names, after = read_zip(OUTPUT)
    if base_names != out_names or len(out_names) != 164:
        raise VerifyError("archive topology drift")
    changed_members = [name for name in base_names if before[name] != after[name]]
    if changed_members != [PSX]:
        raise VerifyError(f"member isolation failed: {changed_members}")
    if sha256(after[PSX]) != OUTPUT_PSX_SHA256:
        raise VerifyError("output PSX.EXE hash mismatch")
    if sha256(after[COMM]) != COMM_SHA256:
        raise VerifyError("COMM.IMG hash mismatch")
    if any(before[name] != after[name] for name in base_names if name != PSX):
        raise VerifyError("a non-PSX member changed")

    with ZipFile(DELTA) as archive:
        if archive.namelist() != [PSX] or archive.read(PSX) != after[PSX]:
            raise VerifyError("delta payload/topology mismatch")

    actual = {
        offset
        for offset, (old, new) in enumerate(zip(before[PSX], after[PSX], strict=True))
        if old != new
    }
    if actual != EXPECTED_CHANGED_OFFSETS:
        raise VerifyError(
            f"Expected-Write mismatch: actual={sorted(actual)} expected={sorted(EXPECTED_CHANGED_OFFSETS)}"
        )

    for offset, _address, before_word, after_word, label in SITES:
        if struct.unpack_from("<I", before[PSX], offset)[0] != before_word:
            raise VerifyError(f"{label} V334 premise drift")
        if struct.unpack_from("<I", after[PSX], offset)[0] != after_word:
            raise VerifyError(f"{label} V335 word mismatch")

    # The caller passes a1 to the state configuration routine, which saves it
    # as +0x20 and immediately sets active Y through 0x8016B418.  E6 later adds
    # H=16 plus spacing=0; V335 changes neither routine.
    if struct.unpack_from("<3I", after[PSX], SETTER_FILE) != SETTER_WORDS:
        raise VerifyError("dialogue coordinate setter drift")
    if struct.unpack_from("<4I", after[PSX], CONFIG_FILE) != CONFIG_WORDS:
        raise VerifyError("dialogue start-coordinate state stores drift")
    if struct.unpack_from("<8I", after[PSX], LINE_BREAK_FILE) != LINE_BREAK_WORDS:
        raise VerifyError("E6 line-pitch path drift")

    # E5 and all following ordinary option glyphs use the same s0 dialogue
    # state, so their text inherits the shifted origin.  The navigation
    # triangle is a separate runtime cursor: its code/data are byte-identical,
    # but indirect dependence on dialogue state remains a runtime gate.
    if struct.unpack_from("<5I", after[PSX], DIRECT_GLYPH_FILE) != DIRECT_GLYPH_WORDS:
        raise VerifyError("ordinary option-glyph path drift")
    if struct.unpack_from("<3I", after[PSX], E5_PLACEHOLDER_FILE) != E5_GLYPH_WORDS:
        raise VerifyError("E5 choice route changed")

    top_rows = [32 + 16 * row for row in range(4)]
    bottom_rows = [162 + 16 * row for row in range(4)]
    if top_rows != [32, 48, 64, 80] or bottom_rows != [162, 178, 194, 210]:
        raise VerifyError("four-row coordinate simulation failed")
    if top_rows[-1] + 15 != 95 or bottom_rows[-1] + 15 != 225:
        raise VerifyError("fourth-row glyph extent calculation failed")

    rows = list(csv.DictReader((ANALYSIS / "expected_writes.csv").open(encoding="utf-8-sig")))
    csv_offsets = {int(row["offset"], 16) for row in rows}
    if csv_offsets != actual or len(rows) != 4:
        raise VerifyError("expected_writes.csv mismatch")

    disassembly = disassemble_sites(after[PSX])
    result = {
        "verdict": "PASS",
        "output_sha256": OUTPUT_SHA256,
        "changed_members": changed_members,
        "changed_bytes": len(actual),
        "changed_offsets": [f"0x{offset:X}" for offset in sorted(actual)],
        "disassembly": disassembly,
        "rows": {
            "top": top_rows,
            "top_fourth_glyph_bottom": 95,
            "bottom": bottom_rows,
            "bottom_fourth_glyph_bottom": 225,
            "line_pitch": 16,
        },
        "preserved": {
            "choice_option_text": "PASS: E5 and ordinary glyphs share shifted state s0",
            "choice_triangle_cursor": (
                "code/data byte-identical; final on-screen coordinate PENDING runtime"
            ),
            "dialogue_background": "PASS: no related code/data changed",
            "COMM_IMG": "PASS",
            "all_DAT_and_other_members": "PASS",
            "UI_item_skill_paths": "PASS: exact four-byte PSX diff isolation",
        },
        "runtime": "PENDING V335 cold boot",
    }
    ANALYSIS.mkdir(parents=True, exist_ok=True)
    (ANALYSIS / "independent_verification.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    report = [
        "V335 independent verification: PASS",
        f"output_sha256={OUTPUT_SHA256}",
        "changed_members=PSX.EXE only",
        "changed_bytes=4; offsets=0x418F8/0x41918/0x41970/0x41988; Expected-Write PASS",
        "top rows=32/48/64/80; fourth glyph bottom=95 PASS",
        "bottom rows=162/178/194/210; fourth glyph bottom=225 PASS",
        "dialogue setter and E6 16px pitch path unchanged PASS",
        "choice option text shares shifted dialogue state s0 PASS",
        "choice triangle cursor code/data unchanged; final coordinate runtime PENDING",
        "background/COMM.IMG/all DAT/UI/item/skill unchanged PASS",
        *disassembly,
        "runtime=PENDING V335 user cold boot; TEST_ONLY",
    ]
    (ANALYSIS / "independent_verification.txt").write_text(
        "\n".join(report) + "\n", encoding="utf-8"
    )
    print("\n".join(report))


if __name__ == "__main__":
    main()
