# V359 커서 충돌 분리 시험판 — TEST_ONLY

실제 게임 성공 판정 전. 번호는 V359 유지. 이번 변경은 슬라임/범위 커서 충돌만 대상으로 한다.

## 입력과 결과

- 기준: `03_output/arc1_v359_review_215_TEST_ONLY.zip` SHA256 `A66F88444716E9993C0C4BBC2EC58A4965B3359D55278DC193A183A621BE4E1B`.
- 결과: `03_output/V359_CURSOR_LINES_TEST.cue`와 같은 폴더의 BIN.
- 결과 BIN SHA256 `B4C44205AFCABC5219588BC6C6C26A6C7F618AE3209ED2E277B1A0593248C511`.
- 결과 ZIP SHA256 `84844764CE39B8B378496BAAB024A967AD9FAD3EE6FE17AABC871A59E49132C2`.
- 기존 REVIEW_UPDATE2 BIN, 원본, CSV 두 개, COMM, 모든 DAT, 메모리카드 및 사용자 강제 세이브 변경 없음.

## 변경 및 검증

1. 프레임 8011C860의 커서 업로드 경유를 원래 DrawOT 호출로 복원. 전용 옛 gate 진입부도 DrawOT로 우회.
2. 전용 helper의 AddPrim 호출 8011F214만 resident 801FF488로 분기. 기존 GTE 좌표, 선택/범위 계산, 바깥 테두리 점멸 판정 유지.
3. 기존 40B FT4를 최대32B 비텍스처 polyline으로 변환. 9개 방향: 전체 사각형1, 세 변4, 두 변4. 새 텍스처 VRAM 0, 새 상주 RAM 예약0, 임시 스택16B. 커서 전용 uploader324B 및 바로 뒤 옛 RLE4B, 총328B만 재사용.
4. 801FF858..801FF8AF의 숫자 변환 UI helper와 호출부는 byte-exact 보존. 이 영역은 V338/V349에서 이미 다른 기능에 사용됐다.
5. Keystone 0.9.2 / Capstone 최종 명령 전체 재조립 바이트 왕복, R3000 load/branch delay 확인. Unicorn 2.1.4 CPU 모의실행9유형×128반복=1152회에서 ABI/복귀/좌표순서/DMA word count/종료토큰/쓰기 범위 검사 PASS. GPU 렌더 검증은 아니다.
6. EXE만 변경, 허용4범위 외 변경0. 기존 전체 legacy 검사 실패 목록(마커2/폭69)은 동일. 506 data file LBA와 디스크상의 패치164멤버 readback 일치.

원본 대비 선 출력은 1px 불투명 흰색으로, 기존 팔레트 순환·그라데이션·두께와 다르다. 원본 외형 동일성을 주장하지 않는다. 제공 상태1/8에서 커서는 마지막 drawable OT 항목으로 관측됐으나, 다른 문맥/다음 프레임 GPU draw-state와 화면 경계는 실기 확인 대상이다.

GPU 형식 참고: [PSX-SPX GPU line commands](https://psx-spx.consoledev.net/graphicsprocessingunitgpu/#gpu-render-line-commands). Polyline은 texture read 없이 선을 그리며 `0x55555555`로 종료한다. 프레임버퍼에 선을 그리는 쓰기는 있으며, 추가 텍스처 저장소를 쓰지 않는다는 의미다.

## 사용자 확인

1. 에뮬레이터에서 기존 게임을 종료하고 새 CUE로 콜드부팅한다. 자동 강제 세이브 복원은 하지 않는다.
2. 게임 내부 저장/메모리카드에서 불러온다. 이전 `.sav`에는 옛 코드와 오염 VRAM이 있으므로 그대로 재현 시험에 쓰지 않는다.
3. 슬라임 전투에서 커서를 이동하고 취소/확정한다. 슬라임 애니메이션 여러 프레임과 배경, 커서 중앙·외곽 범위를 확인한다.
4. 범위가 큰 스킬/아이템과 장비↔전투 재진입, 화면 가장자리, 층수·숫자 UI를 확인한다. PSP는 별도 미검증.
5. 문제가 있으면 기존 REVIEW_UPDATE2 CUE로 돌아갈 수 있다. 원본/기존 빌드 덮어쓰기 없음.

## 중간 실패 기록

- 초안은 역사적인 V324 tail 전체1064B를 지웠으나 추가 J/JAL 참조 검사에서 801FF858의 별도 UI helper를 발견했다. 해당 초안은 **불합격/사용 금지**이며 `REJECTED_full_tail.*`로 분석 폴더에 격리했다(CUE 확장자 DISABLED). 최종본은328B만 덮어쓰고 나머지 전부 보존한다. 초안 CPU 검사만으로 전체 안전성을 확정할 수 없었던 사례다.
- Keystone 숫자형 KSEG branch 피연산자 재조립 실패는 디코더의 분기 목적지로 라벨을 복원해 전체 재조립하여 해결. `move` alias의 OR/ADDU 차이는 소스를 canonical OR로 통일했다.
- Unicorn에서 독립 emu_start 반복 시 이전 분기 지연 상태가 남아 두 번째 호출 검사가 실패했다. 각 호출의 CPU context만 초기화하고 RAM packet은 유지하여 재검사했다. 실제 PS1 실행 성공 근거로 사용하지 않는다.

## 재현

`python -X utf8 02_scripts/build_arc1_v359_cursor_lines.py`

`python -X utf8 02_scripts/package_arc1_v359_cursor_lines.py`

기존 결과가 있으면 덮어쓰지 않고 중단한다. 상세 허용 범위와 기대 전후 바이트는 `report.json`, 디스크 검증은 `package.json`.
