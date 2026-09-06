"""Verify final recovery package, exact CSV scope, and inherited gate failures.

This reports a TEST_ONLY candidate, never runtime success or release readiness.
No game/CSV data is changed. Reports are generated under the recovery directory.
"""
from __future__ import annotations
import contextlib
import csv
import hashlib
import io
import json
import subprocess
import sys
from pathlib import Path
from zipfile import ZipFile
import check_build
import build_arc1_v359_slot_recovery as build

ROOT = build.ROOT
AN = build.AN
CUE = ROOT / '03_output/V359_REVIEW_UPDATE.cue'
BIN = CUE.with_suffix('.bin')
BIN_SHA = '353E79875603BC1FAC2B4C503B827CB80CC7DB4F18477CA4140584E95F445FBE'
ZIP_SHA = '517ABAFD7486091977DBED1F0A548E61A2D12BA933B0E78FDBC61D2B735A04A5'


def rows(path):
    with path.open(encoding='utf-8-sig', newline='') as handle:
        return list(csv.DictReader(handle))


def legacy_gate(path):
    """Collect the full failure list, not only the six examples printed by main."""
    captured = {}
    output = io.StringIO()
    saved_args, saved_profile = sys.argv, sys.getprofile()

    def profile(frame, event, arg):
        if frame.f_code is check_build.main.__code__ and event == 'return':
            for key in ('fail', 'counts'):
                captured[key] = dict(frame.f_locals[key])

    try:
        sys.argv = ['check_build.py', str(path)]
        sys.setprofile(profile)
        with contextlib.redirect_stdout(output):
            try:
                check_build.main()
                captured['exit'] = 0
            except SystemExit as exc:
                captured['exit'] = exc.code
    finally:
        sys.argv = saved_args
        sys.setprofile(saved_profile)
    assert 'fail' in captured and 'counts' in captured
    captured['console'] = output.getvalue()
    return captured


def main():
    report = json.loads((AN / 'report.json').read_text(encoding='utf-8'))
    assert build.digest(build.OUT.read_bytes()) == ZIP_SHA == report['zip_sha256']
    assert build.digest(BIN.read_bytes()) == BIN_SHA
    disk_check = subprocess.run(
        [sys.executable, str(ROOT/'02_scripts/verify_iso_layout.py'), str(BIN), str(build.OUT)],
        cwd=ROOT, capture_output=True, text=True, encoding='utf-8', errors='replace', check=True,
    )
    cue = CUE.read_text(encoding='utf-8-sig')
    assert BIN.name in cue
    with ZipFile(build.BASE) as z:
        base = {n: z.read(n) for n in z.namelist()}
    with ZipFile(build.OUT) as z:
        now = {n: z.read(n) for n in z.namelist()}
    assert base.keys() == now.keys()
    assert all(len(base[n]) == len(now[n]) for n in base)
    changed = sorted(n for n in base if base[n] != now[n])
    assert changed == ['6/S6013.DAT', '6/S6054.DAT', '7/S7032.DAT']

    before = rows(AN / 'canonical_before.csv')
    after = rows(ROOT / '05_docs/script_translated_full.csv')
    assert len(before) == len(after) == 2878
    targets = {r['row']: r for r in report['rows']}
    assert set(targets) == {1551, 1717, 1720, 1724, 1733, 1743, 2152}
    for n, (a, b) in enumerate(zip(before, after), 1):
        expected = dict(a)
        if n in targets:
            assert a['source file'] == targets[n]['file']
            assert a['offset'] == targets[n]['offset']
            assert a['korean'] == targets[n]['before']
            expected['korean'] = targets[n]['target']
        # apply_patch preserves meaning but may normalize the file's CRLF to LF.
        normalize = lambda row: {k: v.replace('\r\n', '\n') for k, v in row.items()}
        assert normalize(b) == normalize(expected), ('unexpected CSV change', n)

    previous_gate = legacy_gate(build.BASE)
    current_gate = legacy_gate(build.OUT)
    assert previous_gate['fail'] == current_gate['fail'], 'new/different gate failures'
    assert current_gate['exit'] == 1, 'reclassify inherited debt before release'
    result = dict(
        status='RECOVERY AND DISC CHECKS PASS; LEGACY GATE FAILS; RUNTIME PENDING',
        release_ready=False, zip_sha256=ZIP_SHA, bin_sha256=BIN_SHA,
        cue=str(CUE), changed_files=changed, canonical_changed_rows=sorted(targets),
        canonical_sha256=build.digest((ROOT/'05_docs/script_translated_full.csv').read_bytes()),
        before_gate=previous_gate, after_gate=current_gate,
        all_legacy_failures_exact=True, disk_verification=disk_check.stdout, recovery=report,
    )
    (AN/'final_verification.json').write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')

    notes = [
        '# V359 검수 수정 시험판', '',
        '파일: `03_output/V359_REVIEW_UPDATE.cue` (같은 폴더의 BIN과 함께 사용)',
        '이전 성공본·메모리카드·편집기 내보내기 파일은 보존했다. 빌드 번호는 V359다.', '',
        '## 반영 결과', '',
        '검수 목록 215건 중 212건 반영, 3건 보류. 별도로 슬롯 회수용 3행을 수정했다.',
        '이번 단계는 7행, 3개 DAT만 바꾸며 PSX.EXE·COMM.IMG·VRAM·UI는 기준본과 같다.', '',
        '| 행 | 파일 | 수정 내용 |', '|---|---|---|',
    ]
    for row in report['rows']:
        notes.append(f"| {row['row']} | {row['file']} | {row['target'].lstrip('|').replace('|', ' / ')} |")
    notes += [
        '', 'S6054의 기존 Bank-B 5·6·14번을 같은 파일에서 회수·재사용했다. 다른 파일의 슬롯을 빌리거나 새 영역을 사용한 것이 아니다.',
        '2152행은 원문의 ‘걸맞은’ 평가를 ‘위한’으로 조금 완화해 1바이트 연출 구간에 맞췄다.', '',
        '## 미해결 3행 — 완료로 집계하지 않음', '',
        '- 1481·1482 / 5/S5025.DAT: 원본은 オドン, 필요한 표기는 오돈. `돈` 글리프가 없어 보류했다. 현행의 ‘아버지’ 오역도 아직 남아 있다.',
        '- 1703 / 6/S6054.DAT: 인명 퀴즈의 초빈에 필요한 `빈` 글리프가 없다. 초비/초카라가 남은 현행 선택지는 이번에 바꾸지 않았다.',
        '- 고유명사를 임의로 바꾸거나 미사용이 입증되지 않은 글꼴 칸에 쓰지 않았다. 위 3행은 슬롯 회수로 해결되는 문제가 아니다.', '',
        '## 검증 및 남은 시험', '',
        '- 수정 7행의 인코딩·슬롯 종료/복귀·원본 제어코드 순서/위치 재대조 통과.',
        '- 카델 대사 27개, 로크톨 대사 23개 제어코드 보존. 이웃 대사 103행의 실제 E2 확장 토큰 불변.',
        '- CSV 2,878행 중 승인한 7개의 한국어 셀만 변경. 일본어·주소·출처·나머지 한국어는 보존.',
        '- 디스크 데이터 506파일 LBA 불변, 패치 멤버 164개 readback 일치.',
        '- 기존 전체 검사 실패 목록: 선택지 마커 2건, 폭 69건. 이전과 신규 목록 전체가 동일하며 이번에 해결한 것으로 보고하지 않는다.',
        '- 실제 실행은 미확인이다. 이전 savestate가 아닌 새 디스크 부팅 후 메모리카드 저장으로 확인한다.',
        '- 우선 시험: 라마다 퀴즈 선택/정답 판정, 카델 대사의 연출·줄바꿈, 로크톨 대사의 글자 진행과 대사 종료 후 이동.',
        '- 배포 완료판이 아닌 TEST_ONLY다. 성공 기준 bible_current.txt는 승격하지 않았다.', '',
        '## 변경 파일과 재검사', '',
        '- `02_scripts/build_arc1_v359_slot_recovery.py`: 승인 7행의 재삽입·회수·보존 검사.',
        '- `02_scripts/package_arc1_v359_review_all.py`: 기존 출력과 분리된 REVIEW_UPDATE 디스크 생성 경로.',
        '- `02_scripts/verify_arc1_v359_slot_recovery.py`: 최종 디스크·CSV·전체 검사 목록 비교 및 이 보고서 생성.',
        '- `05_docs/script_translated_full.csv`: 빌드에 들어간 한국어 7셀 동기화.',
        '- `05_docs/changelog.txt`, `05_docs/test_log.txt`, `05_docs/codex_notes.txt`: 변경·검증·확인 사실 기록.',
        '- 분석 결과는 `01_work/analysis/dialogue_review_20260905/slot_recovery/`에 보관.',
        '', '비파괴 재검사: `python 02_scripts/build_arc1_v359_slot_recovery.py` 후 `python 02_scripts/verify_arc1_v359_slot_recovery.py`.', '',
        f'BIN SHA-256: `{BIN_SHA}`', f'ZIP SHA-256: `{ZIP_SHA}`', '',
    ]
    (AN/'최종결과.md').write_text('\n'.join(notes), encoding='utf-8')
    print(result['status'])
    print('CSV', result['canonical_sha256'])
    print('Changes', sorted(targets), 'Neighbor rows', report['untouched_neighbor_rows'])
    print('Legacy failures', {k: len(v) for k, v in current_gate['fail'].items()})
    print('Report', AN/'최종결과.md')


if __name__ == '__main__':
    main()
