#!/usr/bin/env python3
"""Build v0.35 with the omitted non-story bank, percent, and LV repairs."""

from __future__ import annotations

import csv
import hashlib
import struct
import sys
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))

import build_ui_safe_v29 as percent_base  # noqa: E402
import build_ui_safe_v34 as base  # noqa: E402
from build_story_sf0b1_return_full import (  # noqa: E402
    ROW_BYTES,
    get_pixel,
    glyph_index,
    set_pixel,
)
from build_ui_full_v26 import PSX_LOAD_BASE, raw_string  # noqa: E402
from build_ui_safe_v27 import load_mapping  # noqa: E402


OUTPUT = ROOT / "03_output" / "ui_safe_v35_cumulative_patch_only.zip"
MANIFEST = ROOT / "05_docs" / "ui_safe_v35.csv"
SKILL_REFERENCE = ROOT / "05_docs" / "ui_skill_guide_reference_v35.csv"
SYSTEM_MANIFEST = ROOT / "05_docs" / "ui_system_v35.csv"
BATTLE_MANIFEST = ROOT / "05_docs" / "ui_battle_choice_v35.csv"
WORLD_MANIFEST = ROOT / "05_docs" / "ui_world_name_v35.csv"
REVIEW_CSV = ROOT / "05_docs" / "ui_items_equipment_skills_v35_review.csv"
NONSTORY_MANIFEST = ROOT / "05_docs" / "ui_nonstory_system_v35.csv"
ANALYSIS = ROOT / "01_work" / "analysis" / "ui_safe_v35"
REPORT = ANALYSIS / "build_report.txt"
READBACK = ANALYSIS / "readback.csv"
LOW_CODE_AUDIT = ANALYSIS / "low_6c_story_audit.csv"
PREVIEW = ANALYSIS / "lv_label_before_after.pbm"
TUTORIAL_AUDIT = ANALYSIS / "tutorial_e2_audit.csv"
SYSTEM_AUDIT = ANALYSIS / "system_text_audit.csv"
BATTLE_AUDIT = ANALYSIS / "battle_choice_audit.csv"
OMITTED_AUDIT = (
    ROOT / "01_work" / "analysis" / "ui_safe_v33" / "nonstory_psx_pointer_audit.csv"
)
TABLE_AUDIT = ROOT / "01_work" / "analysis" / "ui_tables_v24" / "psx_ui_tables.csv"
ORIGINAL_EXE = ROOT / "01_work" / "PSX.EXE"


# These are string-only banks immediately followed by their pointer tables.
OMITTED_POOLS = (
    (0x8237C, 0x823A4),
    (0x823C0, 0x823D8),
    (0x823E4, 0x82444),
    (0x82468, 0x82474),
    (0x82478, 0x82498),
    (0x824A0, 0x82518),
    (0x8255C, 0x825C8),
    (0x82618, 0x8262C),
    (0x82640, 0x8293C),
)


SYSTEM_TRANSLATIONS = {
    0x823A4: "승리!",
    0x823A8: "게임 오버",
    0x823D8: "돌 상태",
    0x823DC: "마비",
    0x823E0: "수면",
    0x82444: "데이터 저장 불러오기",
    0x82448: "데이터 저장",
    0x8244C: "데이터 불러오기",
    0x82450: "카드를 선택하세요",
    0x82454: "카드 1",
    0x82458: "카드 2",
    0x8245C: "파일을 선택하세요",
    0x82460: "메모리 카드가 없습니다",
    0x82474: "」를 손에 넣었다.",
    0x82498: "스테이지에서 얻은 경험치",
    0x8249C: "격파한 적 수",
    0x82518: "LV 상승!!",
    0x8251C: "최대 체력이",
    0x82520: "최대 마력이",
    0x82524: "공격력이",
    0x82528: "방어력이",
    0x8252C: "마력이",
    0x82530: "민첩성이",
    0x82538: "상승",
    0x8253C: "점프",
    0x82540: "던지기",
    0x82544: "받기",
    0x82548: "반격",
    0x8254C: "LV 상승",
    0x82554: "를 배웠다.",
    0x825C8: "사운드 출력",
    0x825CC: "대각선 입력",
    0x825D0: "돌아가기 확인",
    0x825D4: "도움말 보기",
    0x825D8: "촌가라의 몬스터 도감 열기",
    0x825DC: "스테레오",
    0x825E0: "모노",
    0x825E4: "일반",
    0x825E8: "사용",
    0x825EC: "사용 안 함",
    0x8262C: "대전 성적",
    0x82638: "기량",
}


ENEMY_SKILL_TRANSLATIONS = {
    0x8293C: "마비 공격",
    0x82940: "머리 던지기",
    0x82948: "해로운 공격",
    0x8294C: "분열",
    0x82950: "폭발 수리검",
    0x82968: "다이아몬드 더스트",
    0x8297C: "내려치기",
    0x82984: "감싸기",
    0x82988: "해로운 기운",
    0x8298C: "피 빨기",
    0x82990: "초음파",
    0x82994: "돌 상태",
    0x82998: "주위 공격",
    0x829A0: "강타",
    0x829A4: "꽃가루 공격",
    0x829A8: "씨 날리기",
    0x829AC: "검은 전기",
    0x829B0: "지옥의 계단",
    0x829B4: "죽음의 문",
    0x829B8: "합체",
    0x829BC: "시야 차단",
    0x829C0: "인형 난무",
    0x829C8: "전기 파동",
    0x829CC: "불꽃 파동",
    0x829D0: "황천 비행",
    0x829D4: "마법 봉인",
    0x829D8: "죽음 회복",
    0x829DC: "더스트 문양",
    0x829E0: "물기",
    0x82A6C: "불러내기",
}


REVIEW_TABLES = (
    "equipment_name",
    "equipment_description",
    "consumable_name",
    "consumable_description",
    "skill_name",
    "skill_description",
)


def csv_rows(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    if not rows:
        raise SystemExit(f"refusing to write an empty CSV: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def configure_base() -> None:
    percent_base.SINGLE_BYTE["%"] = 0x06
    for name, value in {
        "OUTPUT": OUTPUT,
        "MANIFEST": MANIFEST,
        "SKILL_REFERENCE": SKILL_REFERENCE,
        "SYSTEM_MANIFEST": SYSTEM_MANIFEST,
        "BATTLE_MANIFEST": BATTLE_MANIFEST,
        "WORLD_MANIFEST": WORLD_MANIFEST,
        "ANALYSIS": ANALYSIS,
        "REPORT": REPORT,
        "READBACK": READBACK,
        "LOW_CODE_AUDIT": LOW_CODE_AUDIT,
        "PREVIEW": PREVIEW,
        "TUTORIAL_AUDIT": TUTORIAL_AUDIT,
        "SYSTEM_AUDIT": SYSTEM_AUDIT,
        "BATTLE_AUDIT": BATTLE_AUDIT,
    }.items():
        setattr(base, name, value)


def omitted_rows() -> list[dict[str, str]]:
    rows = [
        row
        for row in csv_rows(OMITTED_AUDIT)
        if 0x82348 <= int(row["source_offset"], 0) < 0x82A88
    ]
    if len(rows) != 123:
        raise SystemExit(f"omitted pointer audit count differs: {len(rows)}")
    return rows


def verified_ui_raw_map(executable: bytes) -> dict[bytes, dict[str, str]]:
    original = ORIGINAL_EXE.read_bytes()
    manifest = {
        (row["table_key"], row["index"]): row for row in csv_rows(MANIFEST)
    }
    result: dict[bytes, dict[str, str]] = {}
    for row in csv_rows(TABLE_AUDIT):
        offset = int(row["string_offset"], 0)
        payload = raw_string(original, offset)
        current = manifest[(row["table_key"], row["index"])]
        target = int(current["string_offset"], 0)
        if raw_string(executable, target).hex(" ").upper() != current["encoded_hex"]:
            raise SystemExit(f"verified UI payload differs: {row['table_key']}[{row['index']}]")
        result.setdefault(payload, current)
    return result


def allocate_payloads(
    executable: bytearray, payloads: dict[str, bytes]
) -> dict[str, int]:
    for start, end in OMITTED_POOLS:
        executable[start:end] = b"\x00" * (end - start)
    cursors = [start for start, _end in OMITTED_POOLS]
    locations: dict[str, int] = {}
    for text in sorted(payloads, key=lambda value: len(payloads[value]), reverse=True):
        payload = payloads[text]
        required = len(payload) + 1
        candidates = [
            (end - cursor, index)
            for index, ((_, end), cursor) in enumerate(zip(OMITTED_POOLS, cursors))
            if cursor + required <= end
        ]
        if not candidates:
            remaining = sum(
                end - cursor for (_, end), cursor in zip(OMITTED_POOLS, cursors)
            )
            raise SystemExit(f"omitted pool overflow: {text!r}; remaining={remaining}")
        _remaining, index = min(candidates)
        location = cursors[index]
        executable[location : location + len(payload)] = payload
        executable[location + len(payload)] = 0
        cursors[index] += required
        locations[text] = location
    return locations


def patch_omitted_bank(executable: bytearray) -> list[dict[str, object]]:
    original = ORIGINAL_EXE.read_bytes()
    mapping = load_mapping()
    rows = omitted_rows()
    ui_raw = verified_ui_raw_map(executable)
    translations = SYSTEM_TRANSLATIONS | ENEMY_SKILL_TRANSLATIONS

    for row in rows:
        pointer = int(row["pointer_offset"], 0)
        source = int(row["source_offset"], 0)
        target = struct.unpack_from("<I", executable, pointer)[0] - PSX_LOAD_BASE
        if target != source or raw_string(executable, target) != bytes.fromhex(row["raw_hex"]):
            raise SystemExit(f"omitted baseline differs: 0x{pointer:X}")
        if raw_string(original, source) != bytes.fromhex(row["raw_hex"]):
            raise SystemExit(f"omitted original differs: 0x{source:X}")

    payloads: dict[str, bytes] = {}
    for text in set(translations.values()):
        prefix = b""
        encodable = text
        if text.startswith("」"):
            prefix, encodable = b"\x5A", text[1:]
        elif text.startswith("LV"):
            prefix, encodable = b"\x6C", text[2:]
        missing = percent_base.missing_chars(encodable, mapping)
        if missing:
            raise SystemExit(f"missing glyphs in omitted translation {text!r}: {missing}")
        payload = prefix + percent_base.encode(encodable, mapping)
        if b"\x00" in payload:
            raise SystemExit(f"zero byte in omitted translation: {text!r}")
        payloads[text] = payload
    locations = allocate_payloads(executable, payloads)

    audit: list[dict[str, object]] = []
    translated = reused = 0
    for row in rows:
        pointer = int(row["pointer_offset"], 0)
        source = int(row["source_offset"], 0)
        raw = bytes.fromhex(row["raw_hex"])
        if pointer in translations:
            korean = translations[pointer]
            target = locations[korean]
            payload = payloads[korean]
            status = "translated_new_pool"
            translated += 1
        else:
            matched = ui_raw.get(raw)
            if not matched:
                raise SystemExit(f"unmapped omitted pointer: 0x{pointer:X}")
            korean = matched["korean_target"]
            target = int(matched["string_offset"], 0)
            payload = raw_string(executable, target)
            status = "reused_verified_ui_translation"
            reused += 1
        struct.pack_into("<I", executable, pointer, PSX_LOAD_BASE + target)
        if raw_string(executable, target) != payload:
            raise SystemExit(f"omitted readback differs: 0x{pointer:X}")
        audit.append(
            {
                "pointer_offset": f"0x{pointer:X}",
                "source_offset": f"0x{source:X}",
                "new_offset": f"0x{target:X}",
                "japanese": row["japanese"],
                "korean": korean,
                "status": status,
                "encoded_bytes": len(payload),
                "encoded_hex": payload.hex(" ").upper(),
            }
        )
    if translated != 72 or reused != 51:
        raise SystemExit(f"omitted coverage differs: translated={translated}, reused={reused}")
    return audit


def label_bitmap() -> set[tuple[int, int]]:
    rows = (
        "............",
        "............",
        ".#....#...#.",
        ".#....#...#.",
        ".#....#...#.",
        ".#....#...#.",
        ".#.....#.#..",
        ".#.....#.#..",
        ".####...#...",
        "............",
        "............",
        "............",
    )
    return {(x, y) for y, row in enumerate(rows) for x, value in enumerate(row) if value == "#"}


def patch_lv(font: bytearray) -> tuple[int, int]:
    before = bytes(font)
    index = glyph_index(b"\x6C")
    row, remainder = divmod(index, 84)
    column, plane = divmod(remainder, 4)
    bit = 1 << plane
    glyph = label_bitmap()
    for y in range(12):
        for x in range(12):
            px = column * 12 + x
            py = row * 12 + y
            old = get_pixel(font, px, py)
            new = old | bit if (x, y) in glyph else old & ~bit
            if (new & ~bit) != (old & ~bit):
                raise SystemExit("LV writer changed a neighboring font plane")
            set_pixel(font, px, py, new)

    changed_bytes = changed_nibbles = 0
    for offset, (old_byte, new_byte) in enumerate(zip(before, font)):
        if old_byte == new_byte:
            continue
        changed_bytes += 1
        y, byte_x = divmod(offset, ROW_BYTES)
        for half, shift in ((0, 0), (1, 4)):
            old = (old_byte >> shift) & 0x0F
            new = (new_byte >> shift) & 0x0F
            if old == new:
                continue
            changed_nibbles += 1
            x = byte_x * 2 + half
            inside = column * 12 <= x < column * 12 + 12 and row * 12 <= y < row * 12 + 12
            if not inside or (old ^ new) & ~bit:
                raise SystemExit(f"COMM.IMG changed outside LV plane at ({x},{y})")
    return changed_bytes, changed_nibbles


def write_review_csv() -> tuple[int, int, int]:
    rows: list[dict[str, object]] = []
    percent_rows = preserved_rows = 0
    for row in csv_rows(MANIFEST):
        if row["table_key"] not in REVIEW_TABLES:
            continue
        target = row["korean_target"]
        if "%" in target:
            special_check = "percent_code_0x06"
            percent_rows += 1
        elif row["missing_glyphs"]:
            special_check = "missing_glyph_review"
        elif "preserved" in row["status"]:
            special_check = "preserved_japanese_review"
            preserved_rows += 1
        else:
            special_check = "none"
        rows.append(
            {
                "category": row["table_key"],
                "index": row["index"],
                "japanese": row["japanese"],
                "korean_display": target,
                "application_status": row["status"],
                "missing_glyphs": row["missing_glyphs"],
                "special_check": special_check,
                "encoded_bytes": row["encoded_bytes"],
                "encoded_hex": row["encoded_hex"],
                "pointer_offset": row["pointer_offset"],
                "string_offset": row["string_offset"],
            }
        )
    if len(rows) != 310:
        raise SystemExit(f"review CSV coverage differs: {len(rows)}")
    write_csv(REVIEW_CSV, rows)
    return len(rows), percent_rows, preserved_rows


def rewrite_report(
    nonstory_rows: list[dict[str, object]],
    comm_bytes: int,
    comm_nibbles: int,
    review_count: int,
    percent_count: int,
    preserved_count: int,
) -> None:
    lines = REPORT.read_text(encoding="utf-8").splitlines()
    rewritten: list[str] = []
    for line in lines:
        if line.startswith("UI safe v0.34"):
            rewritten.append("UI safe v0.35 cumulative non-story bank repair")
        elif line.startswith("output_zip_sha256="):
            rewritten.append(f"output_zip_sha256={hashlib.sha256(OUTPUT.read_bytes()).hexdigest().upper()}")
        else:
            rewritten.append(line)
    reused = sum(row["status"] == "reused_verified_ui_translation" for row in nonstory_rows)
    rewritten.extend(
        [
            f"v35_nonstory_pointer_coverage={len(nonstory_rows)}/123",
            f"v35_nonstory_new_translations={len(nonstory_rows) - reused}",
            f"v35_nonstory_reused_ui_translations={reused}",
            "v35_item_acquisition_suffix=」를 손에 넣었다.",
            "v35_percent_code=0x06",
            "v35_old_ampersand_code_for_percent_removed=true",
            f"v35_lv_bitmap_pixels={len(label_bitmap())}",
            f"v35_lv_changed_bytes={comm_bytes}",
            f"v35_lv_changed_nibbles={comm_nibbles}",
            f"v35_review_rows={review_count}",
            f"v35_review_percent_rows={percent_count}",
            f"v35_review_preserved_rows={preserved_count}",
        ]
    )
    REPORT.write_text("\n".join(rewritten) + "\n", encoding="utf-8")


def main() -> None:
    configure_base()
    base.main()

    with ZipFile(OUTPUT) as archive:
        infos = archive.infolist()
        files = {info.filename: archive.read(info.filename) for info in infos}

    executable = bytearray(files["PSX.EXE"])
    nonstory_rows = patch_omitted_bank(executable)
    files["PSX.EXE"] = bytes(executable)
    write_csv(NONSTORY_MANIFEST, nonstory_rows)

    font = bytearray(files["COMM.IMG"])
    comm_bytes, comm_nibbles = patch_lv(font)
    files["COMM.IMG"] = bytes(font)

    temporary = OUTPUT.with_suffix(".tmp.zip")
    with ZipFile(temporary, "w", ZIP_DEFLATED, compresslevel=9) as archive:
        for info in infos:
            archive.writestr(info, files[info.filename])
    temporary.replace(OUTPUT)
    with ZipFile(OUTPUT) as archive:
        if any(archive.read(name) != payload for name, payload in files.items()):
            raise SystemExit("v0.35 ZIP readback differs")

    review_count, percent_count, preserved_count = write_review_csv()
    rewrite_report(
        nonstory_rows,
        comm_bytes,
        comm_nibbles,
        review_count,
        percent_count,
        preserved_count,
    )
    print(REPORT.read_text(encoding="utf-8"), end="")


if __name__ == "__main__":
    main()
