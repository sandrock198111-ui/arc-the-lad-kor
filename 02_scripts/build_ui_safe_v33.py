#!/usr/bin/env python3
"""Build v0.33 with complete battle-help, confirmation, and LV repairs."""

from __future__ import annotations

import csv
import hashlib
import shutil
import struct
import sys
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))

import build_ui_safe_v32 as base  # noqa: E402
from build_ui_full_v26 import PSX_LOAD_BASE  # noqa: E402
from build_ui_safe_v27 import load_mapping  # noqa: E402


OUTPUT = ROOT / "03_output" / "ui_safe_v33_cumulative_patch_only.zip"
FONT_TARGET = "COMM.IMG"
MANIFEST = ROOT / "05_docs" / "ui_safe_v33.csv"
SKILL_REFERENCE = ROOT / "05_docs" / "ui_skill_guide_reference_v33.csv"
SYSTEM_MANIFEST = ROOT / "05_docs" / "ui_system_v33.csv"
BATTLE_MANIFEST = ROOT / "05_docs" / "ui_battle_choice_v33.csv"
WORLD_MANIFEST = ROOT / "05_docs" / "ui_world_name_v33.csv"
ANALYSIS = ROOT / "01_work" / "analysis" / "ui_safe_v33"
REPORT = ANALYSIS / "build_report.txt"
READBACK = ANALYSIS / "readback.csv"
LOW_CODE_AUDIT = ANALYSIS / "low_6c_story_audit.csv"
PREVIEW = ANALYSIS / "lv_label_before_after.pbm"
TUTORIAL_AUDIT = ANALYSIS / "tutorial_e2_audit.csv"
SYSTEM_AUDIT = ANALYSIS / "system_text_audit.csv"
BATTLE_AUDIT = ANALYSIS / "battle_choice_audit.csv"


HELP_TEXTS = (
    (0x82348, 0x8224C, "대상 변경"),
    (0x8234C, 0x8225C, "공격, 연결 열기"),
    (0x82350, 0x82270, "행동 끝, 상태 확인"),
    (0x82354, 0x8228C, "스킬을 선택하세요"),
    (0x82358, 0x8229C, "돌아갑니다"),
    (0x8235C, 0x822AC, "결정, 돌아가기"),
    (0x82360, 0x822C4, "다음 대상을 선택합니다"),
    (0x82364, 0x822D4, "결정하면 주변에 스킬을 사용합니다"),
    (0x82368, 0x822E8, "결정하면 보는 방향에 스킬을 사용합니다"),
    (0x8236C, 0x82304, "비어 있는 곳을 선택하세요"),
    (0x82370, 0x82318, "결정하면 스킬을 사용합니다"),
    (0x82374, 0x82328, "인물을 선택하세요"),
    (0x82378, 0x8233C, "결정하면 전투를 시작합니다"),
)
HELP_POINTERS = {pointer for pointer, _source, _text in HELP_TEXTS}

SYSTEM_TEXTS = tuple(
    entry
    for entry in base.SYSTEM_TEXTS
    if entry[0] not in HELP_POINTERS and entry[0] != 0x82AC0
) + HELP_TEXTS + (
    (0x82AC0, 0x82A88, "예    아니요"),
)

# The walkthrough's exact meaning is level +1. The accepted safe font has no
# Hangul '벨' glyph, so the already verified compact LV label is used instead
# of the old and misleading '단계' wording.
UI_FIXES = (
    (0x80F1C, 0x80C0D, "LV 1 상승"),
)

# This seven-entry world-name table is separate from the 30-entry region-name
# table covered by the 503-record UI manifest. Six names are representable by
# the accepted bank. 아리바샤 is deliberately preserved until 샤 has a verified
# glyph; substituting a different spelling would make the terminology worse.
WORLD_TABLE = (
    (0x81EE8, 0x81EB0, "スメリア", "스메리아", ""),
    (0x81EEC, 0x81EB8, "ミルマーナ", "밀마나", ""),
    (0x81EF0, 0x81EC0, "グレイシーヌ", "그레이시누", ""),
    (0x81EF4, 0x81EC8, "アララトス", "아라라토스", ""),
    (0x81EF8, 0x81ED0, "アリバーシャ", "아리바샤", "샤"),
    (0x81EFC, 0x81ED8, "カーデル", "카델", ""),
    (0x81F00, 0x81EE0, "ジークラフ島", "지크라프섬", ""),
)
WORLD_TEXTS = tuple(
    (pointer, source, korean)
    for pointer, source, _japanese, korean, missing in WORLD_TABLE
    if not missing
)
WORLD_POINTERS = {pointer for pointer, _source, _jp, _ko, _missing in WORLD_TABLE}
RELOCATED_TEXTS = SYSTEM_TEXTS + WORLD_TEXTS + UI_FIXES

# The complete Japanese battle-help string bank is now superseded. The other
# pools are inherited from v0.32 and remain inside already verified PSX data.
SYSTEM_POOLS = (
    (0x7809C, 0x780DC),
    (0x78100, 0x781B8),
    (0x781D4, 0x78220),
    (0x8224C, 0x82348),
    (0x82A88, 0x82AC0),
    (0x81F6B, 0x82170),
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


def system_payload(text: str, mapping: dict[str, bytes]) -> bytes:
    return base.base.base.encode(text, mapping)


def label_bitmap() -> set[tuple[int, int]]:
    """Thin one-cell LV that stays legible beside the following level digit."""
    rows = (
        "............",
        "............",
        ".#....#...#.",
        ".#....#...#.",
        ".#....#...#.",
        ".#....#...#.",
        ".#.....#.#..",
        ".#.....#.#..",
        ".####....#..",
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
    previous_bitmap = base.label_bitmap
    try:
        base.label_bitmap = label_bitmap
        return base.patch_lv(font)
    finally:
        base.label_bitmap = previous_bitmap


def validate_v32_system(executable: bytearray) -> None:
    mapping = load_mapping()
    original = (ROOT / "01_work" / "PSX.EXE").read_bytes()
    v32_pointers = {pointer for pointer, _source, _text in base.SYSTEM_TEXTS}

    for pointer, _source, text in base.SYSTEM_TEXTS:
        target = struct.unpack_from("<I", executable, pointer)[0] - PSX_LOAD_BASE
        if not any(start <= target < end for start, end in base.SYSTEM_POOLS):
            raise SystemExit(f"v0.32 system pointer left its pool: 0x{pointer:X}")
        if raw_string(executable, target) != base.system_payload(text, mapping):
            raise SystemExit(f"v0.32 system payload differs: 0x{pointer:X}")

    for pointer, source, _text in HELP_TEXTS:
        if pointer in v32_pointers:
            continue
        target = struct.unpack_from("<I", executable, pointer)[0] - PSX_LOAD_BASE
        if target != source:
            raise SystemExit(f"Japanese help pointer differs: 0x{pointer:X}")
        if raw_string(executable, target) != raw_string(original, source):
            raise SystemExit(f"Japanese help source differs: 0x{source:X}")

    item_pointer, _source, _text = UI_FIXES[0]
    item_target = struct.unpack_from("<I", executable, item_pointer)[0] - PSX_LOAD_BASE
    expected_item = base.base.base.encode("단계 1 상승", mapping)
    if raw_string(executable, item_target) != expected_item:
        raise SystemExit("v0.32 overflowing-fruit description differs")

    for pointer, source, _japanese, _korean, _missing in WORLD_TABLE:
        target = struct.unpack_from("<I", executable, pointer)[0] - PSX_LOAD_BASE
        if target != source:
            raise SystemExit(f"v0.32 world-name pointer differs: 0x{pointer:X}")
        if raw_string(executable, target) != raw_string(original, source):
            raise SystemExit(f"v0.32 world-name source differs: 0x{source:X}")


def patch_system_text(executable: bytearray) -> list[dict[str, object]]:
    mapping = load_mapping()
    before = bytes(executable)
    validate_v32_system(executable)

    payloads: dict[str, bytes] = {}
    for _pointer, _source, text in RELOCATED_TEXTS:
        if base.base.base.missing_chars(text, mapping):
            raise SystemExit(f"unsafe v0.33 system payload: {text!r}")
        payload = system_payload(text, mapping)
        if b"\x00" in payload:
            raise SystemExit(f"zero byte in v0.33 system payload: {text!r}")
        payloads[text] = payload

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
            remaining = sum(
                end - cursor for (_, end), cursor in zip(SYSTEM_POOLS, cursors)
            )
            raise SystemExit(
                f"v0.33 system pool overflow: {text!r}; remaining={remaining}"
            )
        _remaining, pool_index = min(candidates)
        location = cursors[pool_index]
        executable[location:location + len(payload)] = payload
        executable[location + len(payload)] = 0
        cursors[pool_index] += required
        locations[text] = location

    audit: list[dict[str, object]] = []
    for pointer, source, text in RELOCATED_TEXTS:
        location = locations[text]
        struct.pack_into("<I", executable, pointer, PSX_LOAD_BASE + location)
        payload = payloads[text]
        if raw_string(executable, location) != payload:
            raise SystemExit(f"v0.33 system readback differs: {text!r}")
        audit.append(
            {
                "pointer_offset": f"0x{pointer:X}",
                "source_offset": f"0x{source:X}",
                "new_offset": f"0x{location:X}",
                "encoded_bytes": len(payload),
                "korean": text,
                "encoded_hex": payload.hex(" ").upper(),
            }
        )

    allowed = bytearray(len(executable))
    for start, end in SYSTEM_POOLS:
        allowed[start:end] = b"\x01" * (end - start)
    for pointer, _source, _text in RELOCATED_TEXTS:
        allowed[pointer:pointer + 4] = b"\x01" * 4
    for offset, (old, new) in enumerate(zip(before, executable)):
        if old != new and not allowed[offset]:
            raise SystemExit(f"v0.33 system delta outside range: 0x{offset:X}")
    return audit


def update_ui_manifest(executable: bytes) -> None:
    mapping = load_mapping()
    payload = system_payload(UI_FIXES[0][2], mapping)
    target = struct.unpack_from("<I", executable, UI_FIXES[0][0])[0] - PSX_LOAD_BASE
    with MANIFEST.open(encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
        fields = list(rows[0])
    matched = 0
    for row in rows:
        if row["table_key"] == "consumable_description" and row["index"] == "2":
            row.update(
                {
                    "status": "guide_exact_lv_fallback",
                    "korean_target": UI_FIXES[0][2],
                    "missing_glyphs": "",
                    "encoded_bytes": str(len(payload)),
                    "encoded_hex": payload.hex(" ").upper(),
                    "string_offset": f"0x{target:X}",
                }
            )
            matched += 1
    if matched != 1:
        raise SystemExit(f"v0.33 item manifest target differs: {matched}")
    for path in (MANIFEST, READBACK):
        with path.open("w", encoding="utf-8-sig", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields)
            writer.writeheader()
            writer.writerows(rows)


def write_world_manifest(executable: bytes) -> None:
    mapping = load_mapping()
    original = (ROOT / "01_work" / "PSX.EXE").read_bytes()
    translated = {pointer for pointer, _source, _text in WORLD_TEXTS}
    rows: list[dict[str, object]] = []
    for index, (pointer, source, japanese, korean, missing) in enumerate(WORLD_TABLE):
        target = struct.unpack_from("<I", executable, pointer)[0] - PSX_LOAD_BASE
        if pointer in translated:
            payload = system_payload(korean, mapping)
            if raw_string(executable, target) != payload:
                raise SystemExit(f"v0.33 world-name readback differs: 0x{pointer:X}")
            status = "translated_existing_bank"
        else:
            payload = raw_string(original, source)
            if target != source or raw_string(executable, target) != payload:
                raise SystemExit(f"v0.33 preserved world name differs: 0x{pointer:X}")
            status = "preserved_missing_glyph"
        rows.append(
            {
                "index": index,
                "pointer_offset": f"0x{pointer:X}",
                "source_offset": f"0x{source:X}",
                "new_offset": f"0x{target:X}",
                "japanese": japanese,
                "status": status,
                "korean_target": korean,
                "missing_glyphs": missing,
                "encoded_bytes": len(payload),
                "encoded_hex": payload.hex(" ").upper(),
            }
        )
    write_csv(WORLD_MANIFEST, rows)


def rewrite_report(
    system_count: int,
    comm_bytes: int,
    comm_nibbles: int,
    changed: list[str],
) -> None:
    lines = (ROOT / "01_work" / "analysis" / "ui_safe_v32" / "build_report.txt").read_text(
        encoding="utf-8"
    ).splitlines()
    rewritten: list[str] = []
    for line in lines:
        if line.startswith("UI safe v0.32"):
            rewritten.append("UI safe v0.33 cumulative system-help repair")
        elif line.startswith("output_zip_sha256="):
            rewritten.append(
                f"output_zip_sha256={hashlib.sha256(OUTPUT.read_bytes()).hexdigest().upper()}"
            )
        else:
            rewritten.append(line)
    rewritten.extend(
        [
            f"v33_system_texts={system_count}",
            f"v33_help_texts={len(HELP_TEXTS)}",
            f"v33_ui_relocations={len(UI_FIXES)}",
            f"v33_world_names_translated={len(WORLD_TEXTS)}/7",
            "v33_world_names_preserved_missing_glyph=1",
            "v33_overflowing_fruit_effect=LV 1 상승",
            "v33_help_icons=plain_text_fallback",
            "v33_confirmation_spacing=4_spaces",
            "v33_lv_bitmap=thin_compact_LV",
            f"v33_comm_changed_bytes={comm_bytes}",
            f"v33_comm_changed_nibbles={comm_nibbles}",
            f"v33_delta_members={','.join(changed)}",
        ]
    )
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text("\n".join(rewritten) + "\n", encoding="utf-8")


def main() -> None:
    base.main()

    for source, target in (
        (base.MANIFEST, MANIFEST),
        (base.SKILL_REFERENCE, SKILL_REFERENCE),
        (base.BATTLE_MANIFEST, BATTLE_MANIFEST),
        (base.READBACK, READBACK),
        (base.LOW_CODE_AUDIT, LOW_CODE_AUDIT),
        (base.TUTORIAL_AUDIT, TUTORIAL_AUDIT),
        (base.BATTLE_AUDIT, BATTLE_AUDIT),
    ):
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)

    with ZipFile(base.OUTPUT) as archive:
        infos = archive.infolist()
        files = {info.filename: archive.read(info.filename) for info in infos}
    before_files = dict(files)

    executable = bytearray(files["PSX.EXE"])
    system_audit = patch_system_text(executable)
    files["PSX.EXE"] = bytes(executable)
    update_ui_manifest(files["PSX.EXE"])
    write_world_manifest(files["PSX.EXE"])

    font_before = files[FONT_TARGET]
    font = bytearray(font_before)
    comm_bytes, comm_nibbles = patch_lv(font)
    files[FONT_TARGET] = bytes(font)
    base.lv_base.PREVIEW = PREVIEW
    base.lv_base.write_preview(font_before, files[FONT_TARGET])

    temporary = OUTPUT.with_suffix(".tmp.zip")
    with ZipFile(temporary, "w", ZIP_DEFLATED, compresslevel=9) as archive:
        for info in infos:
            archive.writestr(info, files[info.filename])
    temporary.replace(OUTPUT)

    with ZipFile(OUTPUT) as archive:
        if any(archive.read(name) != payload for name, payload in files.items()):
            raise SystemExit("v0.33 ZIP readback differs")

    changed = [name for name in files if files[name] != before_files[name]]
    if changed != [FONT_TARGET, "PSX.EXE"]:
        raise SystemExit(f"unexpected v0.33 delta members: {changed}")

    write_csv(SYSTEM_MANIFEST, system_audit)
    write_csv(SYSTEM_AUDIT, system_audit)
    rewrite_report(len(SYSTEM_TEXTS), comm_bytes, comm_nibbles, changed)
    print(REPORT.read_text(encoding="utf-8"), end="")


if __name__ == "__main__":
    main()
