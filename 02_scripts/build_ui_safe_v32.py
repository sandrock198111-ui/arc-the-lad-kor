#!/usr/bin/env python3
"""Build v0.32 with button-help, target-help, and LV glyph repairs."""

from __future__ import annotations

import csv
import hashlib
import struct
import sys
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))

import build_ui_safe_v29 as lv_base  # noqa: E402
import build_ui_safe_v31 as base  # noqa: E402
from build_ui_full_v26 import PSX_LOAD_BASE  # noqa: E402
from build_ui_safe_v27 import load_mapping  # noqa: E402


OUTPUT = ROOT / "03_output" / "ui_safe_v32_cumulative_patch_only.zip"
FONT_TARGET = "COMM.IMG"
MANIFEST = ROOT / "05_docs" / "ui_safe_v32.csv"
SKILL_REFERENCE = ROOT / "05_docs" / "ui_skill_guide_reference_v32.csv"
SYSTEM_MANIFEST = ROOT / "05_docs" / "ui_system_v32.csv"
BATTLE_MANIFEST = ROOT / "05_docs" / "ui_battle_choice_v32.csv"
ANALYSIS = ROOT / "01_work" / "analysis" / "ui_safe_v32"
REPORT = ANALYSIS / "build_report.txt"
READBACK = ANALYSIS / "readback.csv"
LOW_CODE_AUDIT = ANALYSIS / "low_6c_story_audit.csv"
PREVIEW = ANALYSIS / "lv_label_before_after.pbm"
TUTORIAL_AUDIT = ANALYSIS / "tutorial_e2_audit.csv"
SYSTEM_AUDIT = ANALYSIS / "system_text_audit.csv"
BATTLE_AUDIT = ANALYSIS / "battle_choice_audit.csv"


ICON_TOKENS = {
    "{결정버튼}": b"\xE7\x02",
    "{상태버튼}": b"\xE7\x03",
}

SYSTEM_TEXTS = tuple(
    entry for entry in base.SYSTEM_TEXTS if entry[0] != 0x8235C
) + (
    (0x8235C, 0x822AC, "{결정버튼}로 결정, {상태버튼}로 상태 확인"),
    (0x82360, 0x822C4, "다음 대상을 선택합니다"),
)

# v0.32 also reclaims the newly redirected target-help source string.
SYSTEM_POOLS = tuple(
    (start, 0x822D4) if start == 0x822AC else (start, end)
    for start, end in base.SYSTEM_POOLS
)


def write_csv(path: Path, values: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(values[0]))
        writer.writeheader()
        writer.writerows(values)


def raw_string(data: bytes | bytearray, offset: int) -> bytes:
    end = data.find(0, offset)
    if end < 0:
        raise SystemExit(f"unterminated system string at 0x{offset:X}")
    return bytes(data[offset:end])


def system_plain_text(text: str) -> str:
    for token in ICON_TOKENS:
        text = text.replace(token, "")
    return text


def system_payload(text: str, mapping: dict[str, bytes]) -> bytes:
    output = bytearray()
    position = 0
    while position < len(text):
        token = next(
            (value for value in ICON_TOKENS if text.startswith(value, position)),
            None,
        )
        if token is not None:
            output.extend(ICON_TOKENS[token])
            position += len(token)
            continue
        next_token = min(
            (index for value in ICON_TOKENS if (index := text.find(value, position)) >= 0),
            default=len(text),
        )
        output.extend(base.base.encode(text[position:next_token], mapping))
        position = next_token
    return bytes(output)


def label_bitmap() -> set[tuple[int, int]]:
    """Compact two-letter LV with a pointed, open V."""
    rows = (
        "............",
        ".##...#...#.",
        ".##...#...#.",
        ".##...#...#.",
        ".##...#...#.",
        ".##....#.#..",
        ".##....#.#..",
        ".##.....#...",
        ".####...#...",
        "............",
        "............",
        "............",
    )
    return {
        (x, y)
        for y, row in enumerate(rows)
        for x, value in enumerate(row)
        if value == "#"
    }


def patch_lv(font: bytearray) -> tuple[int, int]:
    previous_bitmap = lv_base.label_bitmap
    try:
        lv_base.label_bitmap = label_bitmap
        return lv_base.patch_label(font)
    finally:
        lv_base.label_bitmap = previous_bitmap


def patch_system_text(executable: bytearray) -> list[dict[str, object]]:
    mapping = load_mapping()
    original = (ROOT / "01_work" / "PSX.EXE").read_bytes()
    before = bytes(executable)

    for pointer_offset, _source_offset, text in base.SYSTEM_TEXTS:
        target = struct.unpack_from("<I", executable, pointer_offset)[0] - PSX_LOAD_BASE
        if not any(start <= target < end for start, end in base.SYSTEM_POOLS):
            raise SystemExit(f"v0.31 system pointer left its pool: 0x{pointer_offset:X}")
        if raw_string(executable, target) != base.base.encode(text, mapping):
            raise SystemExit(f"v0.31 system payload differs: 0x{pointer_offset:X}")

    target_pointer = struct.unpack_from("<I", executable, 0x82360)[0]
    if target_pointer != PSX_LOAD_BASE + 0x822C4:
        raise SystemExit("target-help source pointer differs")
    if executable[0x822C4:0x822D4] != original[0x822C4:0x822D4]:
        raise SystemExit("target-help source pool differs")

    payloads = {text: system_payload(text, mapping) for _, _, text in SYSTEM_TEXTS}
    for text, payload in payloads.items():
        plain = system_plain_text(text)
        if base.base.missing_chars(plain, mapping) or b"\x00" in payload:
            raise SystemExit(f"unsafe v0.32 system payload: {text!r}")

    for start, end in SYSTEM_POOLS:
        executable[start:end] = b"\x00" * (end - start)
    cursors = [start for start, _end in SYSTEM_POOLS]
    locations: dict[str, int] = {}
    for text in sorted(payloads, key=lambda value: len(payloads[value]), reverse=True):
        payload = payloads[text]
        required = len(payload) + 1
        candidates = [
            (end - cursor, index)
            for index, ((_, end), cursor) in enumerate(zip(SYSTEM_POOLS, cursors))
            if cursor + required <= end
        ]
        if not candidates:
            raise SystemExit(f"v0.32 system pool overflow: {text!r}")
        _remaining, pool_index = min(candidates)
        location = cursors[pool_index]
        executable[location:location + len(payload)] = payload
        executable[location + len(payload)] = 0
        cursors[pool_index] += required
        locations[text] = location

    audit: list[dict[str, object]] = []
    for pointer_offset, source_offset, text in SYSTEM_TEXTS:
        location = locations[text]
        struct.pack_into("<I", executable, pointer_offset, PSX_LOAD_BASE + location)
        payload = payloads[text]
        if raw_string(executable, location) != payload:
            raise SystemExit(f"v0.32 system readback differs: {text!r}")
        audit.append(
            {
                "pointer_offset": f"0x{pointer_offset:X}",
                "source_offset": f"0x{source_offset:X}",
                "new_offset": f"0x{location:X}",
                "encoded_bytes": len(payload),
                "korean": text,
                "encoded_hex": payload.hex(" ").upper(),
            }
        )

    allowed = bytearray(len(executable))
    for start, end in SYSTEM_POOLS:
        allowed[start:end] = b"\x01" * (end - start)
    for pointer_offset, _source_offset, _text in SYSTEM_TEXTS:
        allowed[pointer_offset:pointer_offset + 4] = b"\x01" * 4
    for offset, (old, new) in enumerate(zip(before, executable)):
        if old != new and not allowed[offset]:
            raise SystemExit(f"v0.32 system delta outside range: 0x{offset:X}")
    return audit


def rewrite_report(
    system_count: int,
    comm_bytes: int,
    comm_nibbles: int,
    changed: list[str],
) -> None:
    lines = REPORT.read_text(encoding="utf-8").splitlines()
    rewritten: list[str] = []
    for line in lines:
        if line.startswith("UI safe v0.31"):
            rewritten.append("UI safe v0.32 cumulative help-and-LV repair")
        elif line.startswith("output_zip_sha256="):
            rewritten.append(
                f"output_zip_sha256={hashlib.sha256(OUTPUT.read_bytes()).hexdigest().upper()}"
            )
        else:
            rewritten.append(line)
    rewritten.extend(
        [
            f"v32_system_texts={system_count}",
            "v32_button_icons=E7_02,E7_03",
            "v32_target_help=다음 대상을 선택합니다",
            "v32_lv_bitmap=compact_pointed_V",
            f"v32_comm_changed_bytes={comm_bytes}",
            f"v32_comm_changed_nibbles={comm_nibbles}",
            f"v32_delta_members={','.join(changed)}",
        ]
    )
    REPORT.write_text("\n".join(rewritten) + "\n", encoding="utf-8")


def main() -> None:
    base.OUTPUT = OUTPUT
    base.MANIFEST = MANIFEST
    base.SKILL_REFERENCE = SKILL_REFERENCE
    base.SYSTEM_MANIFEST = SYSTEM_MANIFEST
    base.BATTLE_MANIFEST = BATTLE_MANIFEST
    base.ANALYSIS = ANALYSIS
    base.REPORT = REPORT
    base.READBACK = READBACK
    base.LOW_CODE_AUDIT = LOW_CODE_AUDIT
    base.PREVIEW = PREVIEW
    base.TUTORIAL_AUDIT = TUTORIAL_AUDIT
    base.SYSTEM_AUDIT = SYSTEM_AUDIT
    base.BATTLE_AUDIT = BATTLE_AUDIT
    base.main()

    with ZipFile(OUTPUT) as archive:
        infos = archive.infolist()
        files = {info.filename: archive.read(info.filename) for info in infos}
    before_files = dict(files)

    executable = bytearray(files["PSX.EXE"])
    system_audit = patch_system_text(executable)
    files["PSX.EXE"] = bytes(executable)

    font_before = files[FONT_TARGET]
    font = bytearray(font_before)
    comm_bytes, comm_nibbles = patch_lv(font)
    files[FONT_TARGET] = bytes(font)
    lv_base.PREVIEW = PREVIEW
    lv_base.write_preview(font_before, files[FONT_TARGET])

    temporary = OUTPUT.with_suffix(".tmp.zip")
    with ZipFile(temporary, "w", ZIP_DEFLATED, compresslevel=9) as archive:
        for info in infos:
            archive.writestr(info, files[info.filename])
    temporary.replace(OUTPUT)

    with ZipFile(OUTPUT) as archive:
        if any(archive.read(name) != payload for name, payload in files.items()):
            raise SystemExit("v0.32 ZIP readback differs")

    changed = [name for name in files if files[name] != before_files[name]]
    if changed != [FONT_TARGET, "PSX.EXE"]:
        raise SystemExit(f"unexpected v0.32 delta members: {changed}")

    write_csv(SYSTEM_MANIFEST, system_audit)
    write_csv(SYSTEM_AUDIT, system_audit)
    rewrite_report(len(system_audit), comm_bytes, comm_nibbles, changed)
    print(REPORT.read_text(encoding="utf-8"), end="")


if __name__ == "__main__":
    main()
