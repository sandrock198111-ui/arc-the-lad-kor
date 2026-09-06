"""Verify the final three name substitutions and their V359 test disc."""
from __future__ import annotations

import csv
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from zipfile import ZipFile

import build_arc1_v359_remaining_names as build
import verify_arc1_v359_slot_recovery as recovery_verify


ROOT = build.ROOT
BIN = ROOT / "03_output/V359_REVIEW_UPDATE2.bin"
CUE = ROOT / "03_output/V359_REVIEW_UPDATE2.cue"
ZIP_SHA256 = "A66F88444716E9993C0C4BBC2EC58A4965B3359D55278DC193A183A621BE4E1B"
BIN_SHA256 = "790683AAD90D3968092CE12E46C305120BA3BFC6816E7B828C83FB65348BA19E"
CANONICAL_AFTER_SHA256 = "B3F5BA97EAC7C2D20500AE8498B982F128B35D15A8151F378131F5084B99E760"


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest().upper()


def csv_rows(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def main() -> None:
    report = json.loads((build.ANALYSIS / "build_report.json").read_text(encoding="utf-8"))
    if sha(build.OUT) != ZIP_SHA256 or report["zip_sha256"] != ZIP_SHA256:
        raise RuntimeError("final ZIP hash mismatch")
    if sha(BIN) != BIN_SHA256:
        raise RuntimeError("final BIN hash mismatch")
    if BIN.name not in CUE.read_text(encoding="utf-8-sig"):
        raise RuntimeError("CUE does not reference the final BIN")

    with ZipFile(build.BASE) as archive:
        base = {name: archive.read(name) for name in archive.namelist()}
    with ZipFile(build.OUT) as archive:
        final = {name: archive.read(name) for name in archive.namelist()}
    if base.keys() != final.keys():
        raise RuntimeError("archive topology changed")
    changed = sorted(name for name in base if base[name] != final[name])
    if changed != ["5/S5025.DAT", "6/S6054.DAT"]:
        raise RuntimeError(f"unexpected changed files: {changed}")
    if base["PSX.EXE"] != final["PSX.EXE"] or base["COMM.IMG"] != final["COMM.IMG"]:
        raise RuntimeError("EXE/COMM changed")
    for name in changed:
        if base[name][0x4200:0x5000] != final[name][0x4200:0x5000]:
            raise RuntimeError(f"Bank-B changed: {name}")
    # Row 1703 is itself original live text at 0x45002, inside the address range
    # later classified as Bank-A.  Permit only that row's guarded in-place hunk;
    # do not misreport it as a newly allocated external slot.
    allowed_bank_a = set()
    for row in report["rows"]:
        if row["row"] != 1703:
            continue
        for write in row["writes"]:
            allowed_bank_a.update(range(write["at"], write["at"] + len(bytes.fromhex(write["before"]))))
    for name in changed:
        for position in range(0x45000, 0x47780):
            if base[name][position] != final[name][position] and position not in allowed_bank_a:
                raise RuntimeError(f"unapproved Bank-A-area change: {name} 0x{position:X}")

    before = csv_rows(build.ANALYSIS / "canonical_before.csv")
    after_path = ROOT / "05_docs/script_translated_full.csv"
    after = csv_rows(after_path)
    if len(before) != len(after) or len(after) != 2878:
        raise RuntimeError("canonical row count changed")
    expected_targets = build.TARGETS
    for number, (old, new) in enumerate(zip(before, after), 1):
        expected = dict(old)
        if number in expected_targets:
            expected["korean"] = expected_targets[number]
        normalize = lambda row: {key: value.replace("\r\n", "\n") for key, value in row.items()}
        if normalize(new) != normalize(expected):
            raise RuntimeError(f"unexpected canonical change at row {number}")
    if sha(after_path) != CANONICAL_AFTER_SHA256:
        raise RuntimeError("canonical output hash mismatch")

    inherited = recovery_verify.legacy_gate(build.BASE)
    final_gate = recovery_verify.legacy_gate(build.OUT)
    if inherited["fail"] != final_gate["fail"]:
        raise RuntimeError("new or changed legacy gate failure")

    disk = subprocess.run(
        [sys.executable, str(ROOT / "02_scripts/verify_iso_layout.py"), str(BIN), str(build.OUT)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=True,
    )
    result = {
        "status": "NAME/DISC CHECKS PASS; LEGACY GATE FAILS; RUNTIME PENDING",
        "release_ready": False,
        "review_total": 215,
        "review_resolved": 215,
        "review_held": 0,
        "zip_sha256": ZIP_SHA256,
        "bin_sha256": BIN_SHA256,
        "canonical_sha256": CANONICAL_AFTER_SHA256,
        "changed_files": changed,
        "changed_rows": sorted(expected_targets),
        "additional_slots": 0,
        "font_or_vram_changes": 0,
        "legacy_failures_exact": True,
        "legacy_failure_counts": {key: len(value) for key, value in final_gate["fail"].items()},
        "disk_verification": disk.stdout,
        "build": report,
    }
    (build.ANALYSIS / "final_verification.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    summary = f"""# V359 남은 이름 3행 반영 결과

최신 시험 디스크: `03_output/V359_REVIEW_UPDATE2.cue`와 같은 폴더의 BIN.

- 1481: `너, 오톤이구나!!` — 11/12바이트, 1줄.
- 1482: `내 집에 오톤이 눌러살고 있다니...` — 24/27바이트, 2줄.
- 1703: `초핀 / 초비 / 초스케 / 촌가라` — 각 2/4, 3/5, 4/6, 3/6바이트. 원본 선택지 제어코드 7개 원위치.
- 추가 E2 슬롯 0, 신규 글리프 0, EXE/COMM/VRAM 변경 0.
- 변경된 두 DAT의 다른 대사 {report['untouched_neighbor_rows']}행은 E2 확장 토큰 불변.
- 검수 목록 215건은 기술적으로 모두 반영됐지만, 이는 전체 게임의 배포 완료를 뜻하지 않는다.
- 이전부터 있던 전체 검사 실패는 마커 2건·폭 69건으로 목록까지 동일하다.
- 디스크 506개 데이터 파일의 LBA와 패치 멤버 164/164 readback 통과. 런타임 미확인.

ZIP SHA-256: `{ZIP_SHA256}`

BIN SHA-256: `{BIN_SHA256}`
"""
    (build.ANALYSIS / "최종결과.md").write_text(summary, encoding="utf-8")
    print(result["status"])
    print("review", result["review_resolved"], "/", result["review_total"])
    print("legacy", result["legacy_failure_counts"])
    print("report", build.ANALYSIS / "최종결과.md")


if __name__ == "__main__":
    main()
