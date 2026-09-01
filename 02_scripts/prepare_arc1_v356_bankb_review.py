#!/usr/bin/env python3
"""Prepare the 47 V354 slot-shortage rows for human Bank-B review.

This is a one-shot, hash-pinned migration.  It changes only the ``korean``
column of the canonical translation CSV and creates a review sidecar.  The
sidecar is deliberately separate from ``script_translated_full.csv`` so old
tools that consume its five-column schema keep working.

No row is approved here.  ``needs_human_review`` is a release gate, not a
suggestion that the draft is already final.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
from collections import defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CANONICAL = ROOT / "05_docs/script_translated_full.csv"
SIDECAR = ROOT / "05_docs/v356_bankb_review.csv"
EXPECTED_INPUT_SHA256 = "6232136D5540812A85C8017BF79B3387A2C60E2F2E72D64E1A6957AE2D31F777"
EXPECTED_ROWS = 2878


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest().upper()


# These are editorial drafts, not approvals.  Entries absent from this mapping
# retain the current Korean wording but still enter the 47-row review ledger.
DRAFTS: dict[tuple[str, str], str] = {
    ("31/S3014.DAT", "0x4762E"): "초핀: 강한 상대와 싸울수록 더 많은 경험을 쌓을 수 있습니다.",
    ("31/S3014.DAT", "0x477D6"): "초핀: 동료가 늘어나면 전투에서 맡은 역할에 따라 레벨 차이도 커집니다.",
    ("31/S3014.DAT", "0x4788A"): "초핀: 캐릭터들의 방어력이 비슷해지도록 맞춰 보는 건 어떨까요?",
    ("31/S3014.DAT", "0x4794A"): "낙오자라니, 누구를 말하는 게냐?",
    ("31/S3014.DAT", "0x47A78"): "초핀: 그곳에서만 얻을 수 있고 몬스터가 지키는 장신구도 있다고 들었습니다.",
    ("31/S3014.DAT", "0x47ADE"): "초핀: 실력도 시험할 겸 가끔 가 보는 건 어떨까요?",
    ("31/S3014.DAT", "0x47CD6"): "초핀: 미르마나에는 배틀 에어리어가 세 곳 있습니다. 가끔 찾아가 이야기를 들어 보세요.",
    ("31/S3014.DAT", "0x47D42"): "초핀: 찾아가면 만능약을 받을 수 있다고 합니다.",
    ("31/S3014.DAT", "0x47D92"): "참 친절하구나.",
    ("31/S3014.DAT", "0x47EE4"): "초핀: 어느 것에 관해 말씀드릴까요?",
    ("31/S3014.DAT", "0x4818E"): "초핀: 고겐 님이 동료가 된 뒤에 오르카스 언덕의 스톤 서클에 가 보셨습니까?",
    ("31/S3014.DAT", "0x481F2"): "초핀: 여기서는 어떤 아이템을 얻을 수 있습니다. 스톤 서클이니까요...",
    ("31/S3014.DAT", "0x482B6"): "초핀: 그때 커서와 버튼으로 링 안의 기술을 고른 뒤 아이콘 위치를 변경할 수 있습니다.",
    ("31/S3014.DAT", "0x48320"): "초핀: 한 번 바꾸면 저장되므로 계속 사용할 수 있습니다.",
    ("31/S3014.DAT", "0x483F8"): "초핀: 포코 님의 악기는 모두 8개라고 들었습니다. 전부 찾으면 상당히 강해질 겁니다.",
    ("31/S3014.DAT", "0x487A8"): "초핀: 전투 경험치를 두 배로 늘리는 장신구가 있다고 합니다. 이름은 「비단 띠」이며 누구나 착용할 수 있습니다.",
    ("6/S6054.DAT", "0x450AC"): "라마다 승려: 스파이는 어디에 있었지?",
    ("6/S6054.DAT", "0x4519E"): "라마다 승려: 세이브 데이터의 문양은 무엇인가?",
    ("6/S6054.DAT", "0x4529A"): "라마다 승려: 스메리아 다운타운에 있는 술 취한 사람의 이름은?",
    ("6/S6054.DAT", "0x45580"): "라마다 승려: 수도의 군 본부에는 사실 지하 50층짜리 던전이...",
    ("6/S6054.DAT", "0x45686"): "라마다 승려: 유적 던전의 최하층에 있는 것은?",
    ("6/S6054.DAT", "0x45778"): "라마다 승려: 라마다 사원의 문이 열렸을 때 안에 보이는 사람은 몇 명인가?",
    ("6/S6054.DAT", "0x45B2C"): "라마다 승려: 내 문제를 모두 맞힌 사람은 네가 두 번째다. 상으로 이걸 주마.",
    ("6/S6054.DAT", "0x45D02"): "라마다 승려: 항상 목적을 가지고 행동하도록 하거라.",
    ("6/S6054.DAT", "0x45D52"): "라마다 승려: 그건 틀렸지만, 노력은 인정해 주마.",
    ("6/S6054.DAT", "0x45DA0"): "라마다 승려: 그러니 이것을 주마.",
    ("6/S6054.DAT", "0x45E2E"): "라마다 승려: 수행이 부족한 듯하구나. 다시 도전하도록 해라.",
    ("6/S6054.DAT", "0x45F00"): "라마다 승려: 정말 잘하셨습니다. 이것을 드리겠습니다.",
    ("6/S6054.DAT", "0x460DE"): "라마다 승려: 이런, 자이언트 배트 버스터 여러분이군요.",
    ("6/S6054.DAT", "0x4623C"): "라마다 승려: 이런, 데스 플레임 버스터 여러분이군요.",
    ("6/S6054.DAT", "0x462E4"): "라마다 승려: 이런, 애시드 슬라임 버스터 여러분이군요.",
    ("6/S6054.DAT", "0x46394"): "라마다 승려: 처음 도전하시는군요. 우선 몸풀기부터 시작하지요.",
    ("6/S6054.DAT", "0x4663E"): "라마다 승려: 다섯 번째 도전이시군요. 이제 진심으로 싸워 주십시오.",
    ("6/S6054.DAT", "0x466E2"): "라마다 승려: 여섯 번째 도전이시군요.",
    ("C2/SC0B6.DAT", "0x45CD4"): "승리 10회를 달성하신 분께는 특별한 상품을 드립니다. 힘내 주십시오.",
    ("C2/SC0B6.DAT", "0x463DC"): "1000회까지 앞으로 회입니다. 포기하지 말고 힘내 주십시오.",
}


# The two rows whose editable prose omits a runtime-produced object.  The
# builder consumes this protected template; the visible Korean column stays
# readable and does not expose control bytes to the human editor.
CONTROL_TEMPLATES = {
    ("31/S3014.DAT", "0x482B6"):
        "초핀: 그때 커서와 {E7:02}버튼으로 링 안의 기술을 고른 뒤 아이콘 위치를 변경할 수 있습니다.",
    ("C2/SC0B6.DAT", "0x463DC"):
        "1000회까지 앞으로 {E8:21}회입니다. 포기하지 말고 힘내 주십시오.",
}

REPAIR_INPUT_SHA256 = "6018086ED3DCA204F9ED62FFB7CBC58C99B8BFCE87E1B64FE1CBD69E84EABA28"
REPAIR_SIDECAR_SHA256 = "C24317107848661DE6F1522F57F57AF9B6A4557602760EB104E82B45ABD64A0D"


def shortage_targets() -> set[tuple[str, str]]:
    # Frozen from the V354 editor census after the user's current reductions.
    offsets = {
        "31/S3014.DAT": (
            "0x4762E", "0x477D6", "0x4788A", "0x4794A", "0x47A78", "0x47ADE",
            "0x47CD6", "0x47D42", "0x47D92", "0x47EE4", "0x4818E", "0x481F2",
            "0x482B6", "0x48320", "0x483F8", "0x487A8",
        ),
        "6/S6054.DAT": (
            "0x450AC", "0x4519E", "0x4529A", "0x45580", "0x45686", "0x45778",
            "0x45B2C", "0x45D02", "0x45D52", "0x45DA0", "0x45E2E", "0x45F00",
            "0x460DE", "0x4623C", "0x462E4", "0x46394", "0x4663E", "0x466E2",
        ),
        "C2/SC0B6.DAT": (
            "0x45CD4", "0x463DC", "0x466A0", "0x46990", "0x46A24", "0x46D1A",
            "0x476F0", "0x47AA0", "0x47B72", "0x47BB6", "0x47C8A", "0x47F4E",
            "0x47FD6",
        ),
    }
    return {(name, offset) for name, values in offsets.items() for offset in values}


def repair_existing() -> None:
    """Repair the first pass after the codec exposed five unavailable syllables."""
    if sha(CANONICAL) != REPAIR_INPUT_SHA256 or sha(SIDECAR) != REPAIR_SIDECAR_SHA256:
        raise SystemExit("first-pass V356 review files drifted; refusing repair")
    with CANONICAL.open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        fieldnames = list(reader.fieldnames or [])
        rows = list(reader)
    with SIDECAR.open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        side_fields = list(reader.fieldnames or [])
        ledger = list(reader)
    keys = {
        ("31/S3014.DAT", "0x482B6"), ("6/S6054.DAT", "0x4519E"),
        ("6/S6054.DAT", "0x4529A"), ("6/S6054.DAT", "0x45D02"),
        ("6/S6054.DAT", "0x46394"),
    }
    count = 0
    for row in rows:
        key = (row["source file"], row["offset"])
        if key in keys:
            row["korean"] = DRAFTS[key]
            count += 1
    for row in ledger:
        key = (row["source file"], row["offset"])
        if key in keys:
            row["draft_korean"] = DRAFTS[key]
            row["protected_template"] = CONTROL_TEMPLATES.get(key, DRAFTS[key])
    if count != len(keys):
        raise SystemExit("repair target count drift")
    temp_csv = CANONICAL.with_suffix(".csv.v356.repair.tmp")
    temp_sidecar = SIDECAR.with_suffix(".csv.repair.tmp")
    with temp_csv.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    with temp_sidecar.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=side_fields)
        writer.writeheader()
        writer.writerows(ledger)
    temp_csv.replace(CANONICAL)
    temp_sidecar.replace(SIDECAR)
    print(f"repaired {count} unavailable-glyph drafts")
    print(f"canonical sha256={sha(CANONICAL)}")
    print(f"sidecar sha256={sha(SIDECAR)}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true", help="write the canonical CSV and sidecar")
    parser.add_argument("--repair-existing", action="store_true",
                        help="repair the first-pass drafts after codec validation")
    args = parser.parse_args()

    if args.repair_existing:
        repair_existing()
        return

    actual = sha(CANONICAL)
    if actual != EXPECTED_INPUT_SHA256:
        raise SystemExit(f"canonical CSV drift: {actual} != {EXPECTED_INPUT_SHA256}")
    if SIDECAR.exists():
        raise SystemExit(f"refusing to replace existing review ledger: {SIDECAR}")

    with CANONICAL.open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        fieldnames = list(reader.fieldnames or [])
        rows = list(reader)
    if len(rows) != EXPECTED_ROWS or "korean" not in fieldnames:
        raise SystemExit("canonical CSV schema/row-count drift")

    targets = shortage_targets()
    if len(targets) != 47:
        raise SystemExit("frozen Bank-B target count drift")
    by_key = {(row["source file"], row["offset"]): row for row in rows}
    missing = targets - set(by_key)
    if missing:
        raise SystemExit(f"target rows missing: {sorted(missing)}")

    ledger: list[dict[str, str]] = []
    grouped: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for key in targets:
        grouped[key[0]].append(key)
    assignment = {
        key: index
        for name, keys in grouped.items()
        for index, key in enumerate(sorted(keys, key=lambda item: int(item[1], 0)))
    }

    changed = 0
    for number, row in enumerate(rows, start=1):
        key = (row["source file"], row["offset"])
        if key not in targets:
            continue
        before = (row.get("korean") or "").strip()
        draft = DRAFTS.get(key, before)
        if not draft:
            raise SystemExit(f"empty draft: {key}")
        if draft != before:
            changed += 1
        row["korean"] = draft
        slot = assignment[key]
        ledger.append({
            "row_number": str(number),
            "source file": key[0],
            "offset": key[1],
            "japanese": row.get("japanese", ""),
            "pre_v356_korean": before,
            "draft_korean": draft,
            "protected_template": CONTROL_TEMPLATES.get(key, draft),
            "previous_constraint": "V354_SLOT_SHORTAGE",
            "bank_b_slot": str(slot),
            "bank_b_id": f"{0xD1 + slot:02X}",
            "review_status": "needs_human_review",
            "approved_korean": "",
            "review_note": "Codex draft; compare Japanese/context before approval",
        })
    if len(ledger) != 47:
        raise SystemExit(f"ledger row-count drift: {len(ledger)}")

    print(f"V356 Bank-B review preparation: 47 rows, wording changes={changed}")
    for name in sorted(grouped):
        print(f"  {name}: {len(grouped[name])}/28 Bank-B slots")
    if not args.apply:
        print("dry run only; pass --apply to write")
        return

    temp_csv = CANONICAL.with_suffix(".csv.v356.tmp")
    temp_sidecar = SIDECAR.with_suffix(".csv.tmp")
    with temp_csv.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    fields = list(ledger[0])
    with temp_sidecar.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(sorted(ledger, key=lambda row: int(row["row_number"])))
    temp_csv.replace(CANONICAL)
    temp_sidecar.replace(SIDECAR)
    print(f"canonical sha256={sha(CANONICAL)}")
    print(f"sidecar sha256={sha(SIDECAR)}")


if __name__ == "__main__":
    main()
