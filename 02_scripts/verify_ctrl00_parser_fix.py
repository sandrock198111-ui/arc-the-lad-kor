"""Verify and document the 2026-08-01 CTRL:00 parser correction.

The historical input is pinned to the task-start Git commit.  The verifier
reads the original disc but never writes to it.  With ``--write-reports`` it
writes only the two audit artifacts under ``05_docs``.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import re
import subprocess
from collections import Counter, defaultdict
from pathlib import Path

import audit_ctrl00_parser_candidates as audit
import measure_full_script_requirements as corpus


ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "05_docs"
BASELINE_REF = "291ba49"
SOURCE_PATH = "05_docs/script_original_full.csv"
TRANSLATED_PATH = "05_docs/script_translated_full.csv"
EXPECTED_BIN_SHA256 = "16c62b4485bf29b97bc6090c58490cee718647624c3f4687b0aa4cdebae97c1a"


def git_csv(ref: str, path: str) -> list[dict[str, str]]:
    data = subprocess.check_output(["git", "show", f"{ref}:{path}"], cwd=ROOT)
    return list(csv.DictReader(io.StringIO(data.decode("utf-8-sig"), newline="")))


def file_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def location(row: dict[str, str]) -> tuple[str, int]:
    field = "byte offset" if "byte offset" in row else "offset"
    return row["source file"], int(row[field], 0)


def source_metrics(rows: list[dict[str, str]]) -> dict[str, int]:
    return {
        "rows": len(rows),
        "unique": len({location(row) for row in rows}),
        "ctrl00": sum("<CTRL:00>" in row["decoded Japanese"] for row in rows),
        "controls": sum("<CTRL:" in row["decoded Japanese"] for row in rows),
        "complete": sum(
            "<G:" not in row["decoded Japanese"]
            and "<CTRL:" not in row["decoded Japanese"]
            for row in rows
        ),
    }


def translation_metrics(rows: list[dict[str, str]]) -> dict[str, int]:
    return {
        "translated": sum(bool(row["korean"]) for row in rows),
        "blank_no_g": sum(
            not row["korean"] and "<G:" not in row["japanese"] for row in rows
        ),
        "blank_plain": sum(
            not row["korean"]
            and "<G:" not in row["japanese"]
            and "<CTRL:" not in row["japanese"]
            for row in rows
        ),
        "blank_control": sum(
            not row["korean"]
            and "<G:" not in row["japanese"]
            and "<CTRL:" in row["japanese"]
            for row in rows
        ),
        "blank_ctrl00": sum(
            not row["korean"]
            and "<G:" not in row["japanese"]
            and "<CTRL:00>" in row["japanese"]
            for row in rows
        ),
    }


def raw_mismatches(
    rows: list[dict[str, str]], listing: dict[str, tuple[int, int]]
) -> int:
    cache: dict[str, bytes] = {}
    mismatches = 0
    for row in rows:
        name, begin = location(row)
        data = cache.setdefault(name, corpus.read_file(corpus.BIN, listing[name]))
        raw = bytes.fromhex(row["raw bytes as hex"])
        mismatches += data[begin : begin + len(raw)] != raw
    return mismatches


def ctrl00_evidence(
    rows: list[dict[str, str]], listing: dict[str, tuple[int, int]]
) -> dict[str, object]:
    pattern = [row for row in rows if "<CTRL:00>" in row["decoded Japanese"]]
    cache: dict[str, bytes] = {}
    contexts: list[dict[str, object]] = []
    all_per_file = Counter(row["source file"] for row in rows)
    complete_per_file = Counter(
        row["source file"]
        for row in rows
        if "<G:" not in row["decoded Japanese"]
        and "<CTRL:" not in row["decoded Japanese"]
    )
    ctrl_per_file = Counter(row["source file"] for row in pattern)
    for row in pattern:
        name, begin = location(row)
        data = cache.setdefault(name, corpus.read_file(corpus.BIN, listing[name]))
        raw = bytes.fromhex(row["raw bytes as hex"])
        context = audit.candidate_context(data, begin)
        pair_count = len(raw) // 2
        zero_high = sum(raw[p + 1] == 0 for p in range(0, len(raw) - 1, 2))
        valid, first_zero, controls = audit.runtime_token_audit(raw)
        contexts.append(
            {
                "file": name,
                "begin": begin,
                "end": begin + len(raw),
                "header": context["header_offset"],
                "known_break": corpus.LINEBREAK in raw or corpus.PAGEBREAK in raw,
                "zero_high_ratio": zero_high / pair_count if pair_count else 0.0,
                "valid": valid,
                "first_zero": first_zero,
                "controls": controls,
            }
        )

    overlap: set[tuple[str, int]] = set()
    by_file: dict[str, list[dict[str, object]]] = defaultdict(list)
    for item in contexts:
        by_file[str(item["file"])].append(item)
    for name, items in by_file.items():
        active: list[dict[str, object]] = []
        for item in sorted(items, key=lambda value: int(value["begin"])):
            begin = int(item["begin"])
            active = [other for other in active if int(other["end"]) > begin]
            if active:
                overlap.add((name, begin))
                overlap.update((name, int(other["begin"])) for other in active)
            active.append(item)

    return {
        "contexts": contexts,
        "ctrl_per_file": ctrl_per_file,
        "all_per_file": all_per_file,
        "complete_per_file": complete_per_file,
        "files": len(ctrl_per_file),
        "files_with_complete": sum(complete_per_file[name] > 0 for name in ctrl_per_file),
        "header": sum(item["header"] is not None for item in contexts),
        "no_header_break": sum(
            item["header"] is None and not item["known_break"] for item in contexts
        ),
        "mostly_16le": sum(float(item["zero_high_ratio"]) >= 0.75 for item in contexts),
        "runtime_valid": sum(bool(item["valid"]) for item in contexts),
        "overlap": len(overlap),
    }


def assert_equal(label: str, actual: object, expected: object) -> None:
    if actual != expected:
        raise SystemExit(f"{label}: expected {expected!r}, got {actual!r}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write-reports", action="store_true")
    args = parser.parse_args()

    before_source = git_csv(BASELINE_REF, SOURCE_PATH)
    before_translated = git_csv(BASELINE_REF, TRANSLATED_PATH)
    after_source = file_csv(DOCS / "script_original_full.csv")
    after_translated = file_csv(DOCS / "script_translated_full.csv")
    before_source_by_location = {location(row): row for row in before_source}
    after_source_by_location = {location(row): row for row in after_source}
    before_source_keys = set(before_source_by_location)
    after_source_keys = set(after_source_by_location)

    before = source_metrics(before_source)
    after = source_metrics(after_source)
    before_translation = translation_metrics(before_translated)
    after_translation = translation_metrics(after_translated)
    listing = corpus.iso_files(corpus.BIN)
    evidence = ctrl00_evidence(before_source, listing)

    label = "source of the translation (existing / new)"
    old_korean = {
        location(row): (row["korean"], row[label])
        for row in before_translated
        if row["korean"]
    }
    new_korean = {
        location(row): (row["korean"], row[label])
        for row in after_translated
        if row["korean"]
    }
    translated_source_changes = sum(
        before_source_by_location[key]["decoded Japanese"]
        != after_source_by_location[key]["decoded Japanese"]
        for key in old_korean
    )
    control_tokens = Counter(
        token
        for row in after_source
        for token in re.findall(r"<CTRL:[^>]+>", row["decoded Japanese"])
    )

    measured = {
        "bin_sha256": hashlib.sha256(corpus.BIN.read_bytes()).hexdigest(),
        "before": before,
        "after": after,
        "before_translation": before_translation,
        "after_translation": after_translation,
        "removed_locations": len(before_source_keys - after_source_keys),
        "added_locations": len(after_source_keys - before_source_keys),
        "shared_locations": len(before_source_keys & after_source_keys),
        "changed_shared_source": sum(
            before_source_by_location[key]["decoded Japanese"]
            != after_source_by_location[key]["decoded Japanese"]
            for key in before_source_keys & after_source_keys
        ),
        "before_raw_mismatch": raw_mismatches(before_source, listing),
        "after_raw_mismatch": raw_mismatches(after_source, listing),
        "translations_preserved": old_korean == new_korean,
        "translated_source_changes": translated_source_changes,
        "control_rows_after": sum(
            "<CTRL:" in row["decoded Japanese"] for row in after_source
        ),
        "control_tokens_after": sum(control_tokens.values()),
        "control_types_after": len(control_tokens),
    }

    expected = {
        "bin_sha256": EXPECTED_BIN_SHA256,
        "before": {"rows": 5795, "unique": 5783, "ctrl00": 3027, "controls": 3626, "complete": 1856},
        "after": {"rows": 2878, "unique": 2878, "ctrl00": 0, "controls": 713, "complete": 1852},
        "before_translation": {"translated": 2024, "blank_no_g": 3151, "blank_plain": 126, "blank_control": 3025, "blank_ctrl00": 2824},
        "after_translation": {"translated": 2024, "blank_no_g": 333, "blank_plain": 122, "blank_control": 211, "blank_ctrl00": 0},
        "removed_locations": 2905,
        "added_locations": 0,
        "shared_locations": 2878,
        "changed_shared_source": 985,
        "before_raw_mismatch": 0,
        "after_raw_mismatch": 0,
        "translations_preserved": True,
        "translated_source_changes": 528,
        "control_rows_after": 713,
        "control_tokens_after": 2057,
        "control_types_after": 41,
    }
    for name, value in expected.items():
        assert_equal(name, measured[name], value)
    assert_equal("files_with_ctrl00", evidence["files"], 179)
    assert_equal("files_with_ctrl00_and_complete", evidence["files_with_complete"], 96)
    assert_equal("rows_with_dialogue_header", evidence["header"], 6)
    assert_equal("rows_without_header_or_break", evidence["no_header_break"], 3021)
    assert_equal("mostly_16le", evidence["mostly_16le"], 2392)
    assert_equal("runtime_valid", evidence["runtime_valid"], 22)
    assert_equal("overlap", evidence["overlap"], 1750)

    false_locations = [("1/S1031.DAT", 0x4782A), ("1/S1041.DAT", 0x485CC)]
    assert_equal("false candidates removed", all(key not in after_source_keys for key in false_locations), True)
    control_sample = after_source_by_location[("21/S2041.DAT", 0x47D5A)]
    assert_equal("paired E5 sample", "<CTRL:E5:02>" in control_sample["decoded Japanese"], True)
    assert_equal("paired E6 sample", "<CTRL:E6:00>" in control_sample["decoded Japanese"], True)

    print(f"baseline_ref={BASELINE_REF}")
    print(f"bin_sha256={measured['bin_sha256']}")
    for stage in ("before", "after"):
        print(stage, measured[stage])
    print("before_translation", before_translation)
    print("after_translation", after_translation)
    print(f"translations_preserved={measured['translations_preserved']} count={len(new_korean)}")
    print(f"files_with_ctrl00={evidence['files']}")
    print(f"runtime_valid_ctrl00_rows={evidence['runtime_valid']}")
    print(f"runtime_invalid_ctrl00_rows={before['ctrl00'] - int(evidence['runtime_valid'])}")

    if not args.write_reports:
        return

    after_per_file = Counter(row["source file"] for row in after_source)
    distribution_path = DOCS / "ctrl00_file_distribution.csv"
    with distribution_path.open("w", encoding="utf-8-sig", newline="") as handle:
        fields = [
            "source file",
            "before CTRL00 rows",
            "before all rows",
            "before complete rows",
            "after all rows",
        ]
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for name, count in sorted(
            evidence["ctrl_per_file"].items(), key=lambda item: (-item[1], item[0])
        ):
            writer.writerow(
                {
                    "source file": name,
                    "before CTRL00 rows": count,
                    "before all rows": evidence["all_per_file"][name],
                    "before complete rows": evidence["complete_per_file"][name],
                    "after all rows": after_per_file[name],
                }
            )

    top = sorted(
        evidence["ctrl_per_file"].items(), key=lambda item: (-item[1], item[0])
    )[:10]
    top_table = "\n".join(
        f"| `{name}` | {count} | {evidence['all_per_file'][name]} | {after_per_file[name]} |"
        for name, count in top
    )
    report = f"""# `<CTRL:00>` 파서 감사 보고서

- 감사 기준 커밋: `{BASELINE_REF}`
- 원본 디스크 SHA-256: `{measured['bin_sha256']}`
- 에뮬레이터 실행: 없음
- 원본 디스크, `03_output`, `99_backup`, ZIP 변경: 없음

## 결론

3,027행 전체가 하나의 숨은 2바이트 문자 인코딩은 아니었다. 대다수는 광범위한
`17`/`19` 표식 검색이 16비트 수치·배치 데이터 안의 우연한 값을 문자열 시작으로
오인한 레코드였다. 동시에 실제 문자열 안의 `E1..FF` 제어코드는 **명령 1바이트와
인수 1바이트의 2바이트 토큰**인데, 기존 파서는 이를 1바이트씩 분리했다.

원본 `PSX.EXE`의 인라인 대사 처리기는 `0x8016BB48`에서 `E1` 이상을 제어 경로로
보내고, `0x8016BBFC`와 `0x8016BC08`에서 명령·인수를 읽은 뒤 `0x8016BD40`에서
폭 2를 반환한다. `0x8016BC28`은 포인터를 2바이트 전진시킨다. `0x8016BBB4`의
토큰 경계 `00`은 문자열 종료다. 따라서 확정된 폭은 다음과 같다.

- `01..DC`: 1바이트 글리프
- `DD..E0`: 2바이트 글리프
- `E1..FF`: 2바이트 제어코드(명령+인수)
- 토큰 경계의 `00`: 문자열 종료

의미까지 확인된 `E6 01`(줄바꿈), `E4 1F`(페이지 구분)만 실제 개행으로 바꿨다.
나머지는 예를 들어 `<CTRL:E6:00>`처럼 두 바이트를 그대로 보존했다.

## 실측 결과

| 항목 | 수정 전 | 수정 후 |
|---|---:|---:|
| 전체 추출 행 | {before['rows']:,} | {after['rows']:,} |
| 고유 파일·오프셋 | {before['unique']:,} | {after['unique']:,} |
| `<CTRL:00>` 포함 행 | {before['ctrl00']:,} | {after['ctrl00']:,} |
| `<G:...>`와 `<CTRL:...>`가 모두 없는 완전 해독 행 | {before['complete']:,} | {after['complete']:,} |
| 미번역이며 `<G:...>`가 없는 행 | {before_translation['blank_no_g']:,} | {after_translation['blank_no_g']:,} |
| 미번역이며 `<G:...>`·`<CTRL:...>`가 모두 없는 즉시 번역 대상 | {before_translation['blank_plain']:,} | {after_translation['blank_plain']:,} |
| 기존 한국어 번역 | {before_translation['translated']:,} | {after_translation['translated']:,} |

완전 해독 행의 절대 수가 4행 줄어든 이유는 `COMM.DAT`가 기존 대상 목록에 두 번
추가되어 동일 위치가 중복 출력됐기 때문이다. 고유한 완전 해독 위치는 손실되지
않았다. 즉시 번역 대상도 같은 중복 4행이 제거되어 126행에서 122행이 됐다.

기존 번역 2,024행은 한국어와 출처 열을 위치 기준으로 전부 동일하게 보존했다.
제어코드 폭과 앞선 글리프 지도 복구로 일본어 표시가 달라진 번역 행은 528행이지만,
그 행의 한국어 내용은 수정하지 않았다.

## `<CTRL:00>` 분포와 원본 대조

- 포함 파일: {evidence['files']}개
- 그중 정상 완전 해독 대사도 함께 있는 파일: {evidence['files_with_complete']}개
- CSV raw bytes와 원본 디스크 불일치: 수정 전 {measured['before_raw_mismatch']}행, 수정 후 {measured['after_raw_mismatch']}행
- 16비트 리틀엔디언 수치 배열 모양(상위 바이트 0 비율 75% 이상): {evidence['mostly_16le']:,}행
- 실행기의 토큰 폭으로 끝까지 유효: {evidence['runtime_valid']}행
- 토큰 경계의 독립 `00` 또는 잘린 토큰 때문에 무효: {before['ctrl00'] - int(evidence['runtime_valid']):,}행
- 다른 후보 레코드와 원본 범위가 겹침: {evidence['overlap']:,}행
- 대사 헤더가 확인된 행: {evidence['header']}행
- 대사 헤더도 확인된 줄/페이지 구분도 없는 행: {evidence['no_header_break']:,}행

상위 10개 파일은 다음과 같다. 179개 전체 분포는
`05_docs/ctrl00_file_distribution.csv`에 기록했다.

| 파일 | 수정 전 CTRL00 | 수정 전 전체 | 수정 후 전체 |
|---|---:|---:|---:|
{top_table}

대표적인 오탐 `1/S1031.DAT 0x4782A`의 원본 `22 00 1C 00 06`과
`1/S1041.DAT 0x485CC`의 반복적인 `05 00 0E 00 18 00 ...`는 제거됐다.
반대로 실제 제어열인 `21/S2041.DAT 0x47D5A`는 제거하지 않고
`<CTRL:E5:02>...<CTRL:E6:00>` 형태로 교정했다.

## 확정하지 못한 부분

- 수정 후 남은 제어코드는 {measured['control_rows_after']}행, {measured['control_tokens_after']:,}개,
  {measured['control_types_after']}종이다. `E6 01`과 `E4 1F` 외 제어쌍의 정확한 의미는 이번에
  확정하지 않았으며 삭제하거나 번역하지 않았다.
- 제거된 수치·배치 데이터 각각의 게임 내 용도는 역추적하지 않았다. 다만 대사
  실행기의 토큰 폭을 만족하지 않으므로 현재 대사 파서의 문자열은 아니다.
- `17`/`19` 검색은 여전히 기존 휴리스틱이다. 이번 수정은 오탐과 토큰 폭을 바로잡은
  것이며, 이것만으로 게임의 모든 텍스트 형식을 해독했다고 주장하지 않는다.
"""
    (DOCS / "ctrl00_parser_audit.md").write_text(report, encoding="utf-8")
    print(f"wrote={distribution_path}")
    print(f"wrote={DOCS / 'ctrl00_parser_audit.md'}")


if __name__ == "__main__":
    main()
