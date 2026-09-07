# V368 두 줄바꿈만 수정

사용자 승인: “커서는 건들지 말자..줄바꿈 건들만 수정하자”.
파일: `03_output/V368_LINEBREAKS_TEST.cue` (같은 폴더 BIN 필요).
커서·선택지·글꼴·타이틀·나머지 번역은 V367 그대로다.

## 범위와 실제 출력

`6/S6054.DAT`의 43E3C(36B), 4429E(38B) 본문 두 곳만 같은 길이로 재조판했다.
E6 한 개와 기존 공백의 위치를 바꾸었으며 문장 내용, 종료 NUL, 이후 이벤트·분기 주소는 보존했다.

    문제: 파렌시아 성의
    왕을 모시는 대신의 이름은?

    문제: 다른 공간에서
    적을 공격하는 아크의 기술은?

## 검사

- 두 문장 모두 실제 CPU 출력 Y32/48, 각 행 텍스트가 위 기대값과 정확히 일치한다.
- 전체107본문의 빈 중간행0, 출력 count/end 일치,4행초과0. 전체 문장의 자연스러운 어절 분할을 승인한 것은 아니다.
- 전체31선택창 좌표·상하240조건 결과가 V367과 동일.
- 두본문 밖 DAT 바이트 및 다른163 archive member byte exact. EXE/COMM/커서 시작·간격·선택 인자/E2 Bank-B/CSV 불변.
- 같은 입력 ZIP 재생성 byte exact. 상속 legacy 실패 마커2/폭69 목록 동일.
- 원본 새 staging에서 생성,506 data LBA/164 readback/507extent 동일.
- 29변경 raw sector 및 이전 대응29개의 EDC/ECC58 검사 PASS. 허용된 두본문/ISO기록시각 이외 payload 변화0.
- V366 해시확인 RAM 복사본에 누적 DAT 차분을 적용한 실제 CPU 렌더/입력산술 검증이다. 사용자의 새 상태3/4가 V367과 동일한 해당 객체/본문/렌더조건임은 v367_user4에서 확인했다.
- 실제GPU/재진입·전체정답분기는 사용자 확인 PENDING. 나머지 진행 전 문제 및 V367 임시 대체표기의 승인 상태는 바꾸지 않았다.

## 재현·식별

기존 hash-pinned 번역 archive 계보 의존을 유지하되 previous.prepare()로 V367을 재생성해 동일성을 확인한다.
원본과 기존 BIN/세이브는 수정하지 않고 새 디스크는 원본 트리에서 만든다.
역사적 전체 번역을 원본 하나만으로 재생성했다고 주장하지 않는다.

```powershell
python -X utf8 02_scripts/build_arc1_v368_linebreaks.py
python -X utf8 02_scripts/verify_arc1_v368_linebreaks.py
python -X utf8 02_scripts/package_arc1_v368_linebreaks.py
python -X utf8 02_scripts/verify_arc1_v368_disc_delta.py
```

패키징은 기존 BIN/CUE 덮어쓰기를 거부한다.
ZIP SHA256: 00A55D88117F614FD2CC30BED097AD27DD93D84A59F87C698043A93DF5431416
BIN SHA256: 5105DBA350947FFC97E0FF242B1A2C309E9F1932A22C22D29E44339F73DD76B6

bible_current 갱신 필요성을 검토하고 기존 사용자 성공점 유지.
changelog/test_log/codex_notes 갱신. 다음은 새 CUE 재부팅 후 두 문제 화면 확인.
