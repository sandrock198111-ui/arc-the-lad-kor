# 2026-07-07 자동화 상태

## 결론

수동으로 대사 블록 주소를 찍어 패치하는 방식은 중단한다. 앞으로 시나리오 확장은 자동 분석 CSV와 manifest 빌더를 기준으로 진행한다.

## 현재 자동화 파일

- `02_scripts/analyze_dialog_blocks.py`
  - 원본 DAT에서 17 00/19 00 대사 후보를 찾는다.
  - `body_start`, `payload_start`, 첫 `00 00`, 뒤 제어부를 CSV로 기록한다.
- `01_work/analysis/dialog_block_candidates.csv`
  - 현재 추출 결과: 후보 2544개, high-confidence 2046개.
- `05_docs/korean_charmap.csv`
  - 현재 검증된 한글 코드표.
- `05_docs/story_patch_manifest.csv`
  - 대규모 패치 입력 파일.
- `02_scripts/build_story_from_manifest.py`
  - manifest 기반 안전 빌더.
  - 분석 CSV에 없는 주소, 용량 초과, 00 00/제어부 훼손, 미등록 글자는 빌드 단계에서 중단한다.
  - 낮은 슬롯 글자를 쓰면 COMM.IMG에 필요한 글리프를 자동 렌더링한다.

## 현재 산출물

- `03_output/story_manifest_build_patch_only.zip`
- SHA256: `869F96C604079E9F57EEF958BC9A65F54A9EE08391250F3E51D45CD83048DA35`

## 다음 작업 원칙

1. 번역을 늘릴 때는 먼저 `story_patch_manifest.csv`에 추가한다.
2. 새 글자가 있으면 `korean_charmap.csv`에 배정하고 폰트 슬롯 전략을 정한다.
3. `analyze_dialog_blocks.py`를 다시 돌린다.
4. `build_story_from_manifest.py`로 빌드한다.
5. DuckStation 검증은 전체 수천 대사가 아니라 구간 대표 샘플과 자동 검증 실패 블록 중심으로 한다.
