# V362 한글 타이틀 — 빌드 완료 / 콜드부팅 시각 확인 대기

사용자 승인: 원본처럼 한글 부제를 중앙 칼날 뒤에 놓고 곧바로 빌드.

## 산출물

- 실행: `03_output/V362_KOREAN_TITLE_TEST.cue`와 같은 폴더의 `.bin`
- 누적 시험 아카이브: `03_output/arc1_v362_korean_title_TEST_ONLY.zip`
- 실제 인코딩 결과를 다시 해독한 그림: 이 폴더의 `title_native.png`(344×256), `title_native_3x.png`(동일 픽셀을 bilinear 3배 표시). GPU 실행 스크린샷이 아니다. PUSH START는 원래 별도 sprite라 이 텍스처에 포함하지 않는다.
- 동결한 이미지 제작 입력: `01_work/assets/v362_title/localized_source.png`. 내장 image_gen 편집 결과를 프로젝트로 복사했다. 프롬프트와 출처는 `artwork_prompt.txt`.

BIN SHA256: `0812F4E7858109A332EAABF87356CBD63897E6C5953E4E0A593453F2AEB244E5`

ZIP SHA256: `593E867DCB599C563B52C6F44A6864990B7157FA5B42B9F8C8D2337DEF6EA152`

## 확인한 저장·소비 경로

원본 COMM.IMG는 458752바이트이고 이 그림의 해석은 448×512개의 little-endian RGB555/STP word다. 타이틀은 word 좌표 `(64,0)`의 344×256 영역이다. 사용자 DC429 title-state의 VRAM `(384,0)` 344×256 영역, 원본 ZIP의 해당 데이터, V361의 해당 데이터가 **176128바이트 전체 일치**했다. 원본 COMM 전체 229376 word의 무수정 RGB 변환 왕복과 bit15 보존도 확인했다.

활성 OT의 16bit FT4는 tpage 0x106/UV0,0/256×256 및 tpage 0x10A/UV0,0/88×256으로 이 텍스처를 읽는다. 0x1A의 96×16 PUSH START FT4는 별개이며 그대로 둔다. 이 증거는 이전 빌드의 실제 소비 구조이지 V362의 콜드부팅을 실행했다는 주장은 아니다. 상세: `../title_20260906/state.json`.

## 실제 변경과 보호

- V361 계보 그대로, COMM.IMG 부제 영역의 **4719픽셀 / 8911바이트**만 변경.
- 허용 사각형: 타이틀 로컬 x90..233, y149..191. 모든 바깥과 경계 픽셀은 원본 그대로다.
- 중앙 칼날 214픽셀을 행별 보호 마스크로 원본에서 보존해 한글보다 앞에 놓는다. 전체 이미지를 생성본으로 교체하지 않았다. 영문 로고·배경·장식·저작권·TM의 부제 밖 픽셀은 원본 그대로다.
- 주황빛 구리색→아이보리의 입체 부제만 가져와 원본 크기로 재표본화했다. 과장된 도트/선명화 필터를 넣지 않았다. 사각형 주변의 배경 여백에서만 coverage를 줄여 색 경계를 연결한다.
- 5개의 완전 검정 shadow texel이 RGB555 zero(투명)로 떨어지는 것을 발견했다. 새 투명 구멍 대신 첫 중성 어두운 값 0x0421로 인코딩한다. 전체 STP bit15는 기존 그대로다.
- 1920개 공용 폰트 plane과 16개 compact 숫자/아이콘 plane 동일. EXE/DAT/번역 CSV/제어코드 및 다른 아카이브 멤버 163개 동일. 슬롯·글리프·RAM·VRAM 추가 사용 0.

## 재현과 검증

검증 환경: Windows, Python 3.14.6, Pillow 12.3.0, zlib 1.3.1.zlib-ng, 기존 mkpsxiso 2.30. ZIP은 byte-exact 재생성 검사 대상이다. BIN의 ISO 파일 기록시각은 staging 시각을 따르므로 raw 이미지의 새 빌드 간 차이는 파일 payload와 분리해 검증한다.

```powershell
python -X utf8 02_scripts/audit_arc1_title_state.py
python -X utf8 02_scripts/build_arc1_v362_korean_title.py
python -X utf8 02_scripts/verify_arc1_v362_korean_title.py
python -X utf8 02_scripts/package_arc1_v362_korean_title.py
```

빌더는 원본 ZIP, 명시적 V361 legacy 누적 아카이브, 이미지 입력, CSV SHA를 고정 검증한다. 동일 ZIP을 두 번 만들어 byte-exact를 확인한다. 새 디스크는 원본 추출용 별도 staging에서 패키징하며 이전 BIN/ISO를 입력으로 쓰지 않는다. 과거 모든 패치를 소스에서 다시 재생하는 완전한 역사적 rebuild라는 주장은 하지 않는다. 이미지 생성 모델에 같은 프롬프트를 재전송하는 것은 재현 빌드가 아니며 **보관한 동일 SHA의 이미지 자산**이 필요하다. 이 파일은 원본 배경 일부를 포함하므로 Git에 공개하지 않고 로컬에 보존했다.

패키저는 기존 BIN/CUE 덮어쓰기를 거부한다. 이미 생성한 디스크의 재검사는 다음과 같다.

```powershell
python -X utf8 02_scripts/verify_iso_layout.py 03_output/V362_KOREAN_TITLE_TEST.bin 03_output/arc1_v362_korean_title_TEST_ONLY.zip
python -X utf8 02_scripts/verify_arc1_v362_disc_delta.py
```

통과:

- 독립 native 해독 결과와 출력 PNG 일치, 쓰기 경계/칼날/모든 STP/투명 구멍/글리프 전수 검사.
- 기존 UI 본문 346조건, 커서 1152조건 CPU 회귀. 기존 마커2·폭69의 legacy 실패 목록과 건수는 **동일**하며 해결했다고 표시하지 않는다.
- 506 data LBA 보존, 164 패치 멤버 디스크 readback. PSX.EXE LBA268481은 기존 패키징 계보를 유지한 것이며 원본23과 같다고 주장하지 않는다.
- V361 대비 raw sector 268918개 중 46개 변경: 타이틀 payload 19개(LBA732..750), 새 staging의 파일 기록시각만 달라진 ISO 디렉터리 27개. 나머지 raw sector byte-exact. 507파일 이름/위치/크기 동일.
- 달라진 46 sector와 이전판의 대응46 sector 모두 Mode2/Form1 EDC·ECC P·Q 재계산 일치. 검사만 했으며 섹터를 다시 덮어쓰지 않았다.

초기 실패/수정: 첫 preview 인코딩의 zero-texel 방지 guard가 5개 shadow에서 중단했다(게임 아카이브 출력 전). opaque black 예약으로 수정 후 통과. 첫 native preview의 직사각 배경 경계는 margin coverage 후 다시 확인했고 최종본만 패키징했다.

## 남은 확인 / 다음 작업

**새 CUE로 콜드부팅**해서 타이틀·PUSH START·페이드·시작/불러오기 전환을 확인한다. 이전 강제 세이브는 옛 VRAM을 포함해 일본어 타이틀이 남을 수 있으므로 새 그림 검증에 사용하지 않는다. 실제 GPU 실행, PSP 구동, 전체 게임 무회귀를 확인했다고 주장하지 않는다. 사용자 시각 승인 전 TEST_ONLY 유지.

bible_current: 기존 사용자 확인 성공점을 유지한다. changelog/test_log/codex_notes에는 실제 변경·검증·확인 사실만 추가했다. 기록이 가리키는 이미지는 원본·추출/생성 그림이므로 Git에서 제외했다.

변경 파일: `.gitignore`; `02_scripts/audit_arc1_title_state.py`; `build_arc1_v362_korean_title.py`, `verify_arc1_v362_korean_title.py`, `verify_arc1_v362_disc_delta.py`, `package_arc1_v362_korean_title.py`; `05_docs/changelog.txt`, `test_log.txt`, `codex_notes.txt`; 타이틀 분석 JSON/MD/TXT/기존 비교 HTML. 원본/이전 빌드/사용자 세이브/메모리카드/CSV는 미수정.
