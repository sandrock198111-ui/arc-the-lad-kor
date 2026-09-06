# V367 라마다사 퀴즈 전체 표시 시험판

실행 파일: `03_output/V367_QUIZ_TEST.cue` (같은 폴더의 BIN 필요).
비배포 TEST_ONLY. 사용자 요청은 좌표 보고 대신 직접 볼 수 있는 빌드다.
정식 CSV/내보내기/사용자 세이브/이전 빌드/원본은 수정하지 않았다.

## 실제 적용

- 원문 누락 58본문: 질문18, 선택지17묶음(68답안), 직후 응답18, 보상·설명5.
- 모든 변경은 `6/S6054.DAT` 한 파일, 58본문+17국소 열좌표=75 Expected Writes.
- 원문 본문 경계 및 NUL/후속 이벤트 주소 보존. E6는 본문 안 조판만 재배치.
- 신규 네선택지는 E5 03의 들여쓰기만 제거하고 각 행 시작을 일치시킨다. 해당17창의 column만 -2로 바꿔 본문X46/커서X36, 행16px. count4/baseRow0/정답·분기 인자 불변.
- 기존 첫퀴즈 및 입구2창, 이미 번역된 후반11퀴즈의 선택문은 그대로다.
- 새 E2 슬롯/폰트/EXE/VRAM/RAM 예약 없음. Bank-B 전체 byte exact, 다른163멤버 byte exact.
- 몸체는 인코딩 후 원본 길이 내에 배치하고, 남는 A1 패딩은 네 선택행에 분산한다. 출력 길이는 실제 CPU로 검증했다.

## 번역 검토와 미승인 사항

원본 COMM+DAT의 글리프를 직접 그린 `original_0.png..original_5.png`를 읽고 초벌을 작성했다.
해당 그림은 로컬 재생성 증거이며 저작 자산이므로 커밋하지 않는다.
독립 `v367_quiz_review` 검토가 원문6장/58제안을 대조했다.
ブラッド는 블러드로 수정했고 単体는 단일 공격으로 수정했다.
원본 DF1C/글리프757의 雨·田·굽은 꼬리로 電을 재판독하여 오답 기술명 앵화전폭참을 확인했다.
라크의 문장은 アーク가 아닌 ラーク이며 현행 UI 명칭을 따른다.

글리프 제약 대체는 **사람 승인 대기**다. 별도 질문을 보냈으며 답변을 받았다고 기록하지 않는다.
이번 비배포 표시 시험에서만 명시적으로 선택했다. 정식 번역/배포 적격으로 승격하지 않는다.

- 0x44830: サル/イヌ/キジ/トラ → 잔나비/개/산계/호랑이. 숭·꿩 글리프가 없다.
- 0x44C1A: ヨッシャ/ヨシュア/シュワッチ/シュワルツ → 요샤/요슈아/슈와치/슈바르츠. 욧·왓·왈 글리프가 없다.
- 산계는 [한국학중앙연구원 실록위키 생치 항목](https://dh.aks.ac.kr/sillokwiki/index.php/%EC%83%9D%EC%B9%98%28%E7%94%9F%E9%9B%89%29)의 꿩 동의어를 참고했으나 익숙하지 않은 표현이라는 문제가 남는다.
- 빛나는 정령/검의 정령은 짝·칼 없는 어휘 대체다. 원문 かがやき/かたな, 정답 순서·다른 답안과의 구별을 유지한다.
- 라크의 문장 입수문은 20B→18B로 맞추려고 두 공백을 붙였다. 종료자 절단은 없다.

## 검사 결과

- 전체 관련본문107/질문29/선택창31, 선택 시작120좌표 및 상하240조건 PASS.
- 원문 동일 미변환58→0, CPU오류0, 4행초과0, 출력수/종료 불일치0, 선택 정렬 오류0.
- 출력 최대45/64. 변경58본문은 오른쪽274px 이내. 미변경0x45398은 마지막 패킷 셀끝276px로 상속 상태다.
- 실제 게임 코드 B880/B8C8/E2/event reader/choice coordinate/decoded-pad navigation을 Unicorn에서 실행했다.
- 새 업로드5/6의 V366 RAM 원본을 확인한 뒤 **메모리 복사본에만 후보의 DAT 차분을 적용**했다.
- 패드 검사는 해독된 상하 비트 주입이며 물리 입력·확정취소·정답 결과 전체 분기 검증이 아니다.
- GPU 표시, 전환·재진입, 실제 전체 퀴즈 플레이와 번역 사용자 검수는 PENDING.
- 상속 legacy 검사 실패 목록은 이전과 동일(마커2/폭69); 이번 107본문 CPU 검증과 별도다.
- 새 원본 staging에서 BIN 생성. 506 data LBA/164 patch readback/507 extent·size 동일 PASS.
- 변경30 raw sector 및 이전 대응30개 EDC/ECC=60검사 PASS, 설명되지 않은 payload 변경0.

## 식별·재현

- Original ZIP SHA256: AE9F4366A1E7DA3805BB3BED3DDA9567E4CD4E669AF890E4E2A620D7861F11DD
- V366 baseline ZIP: 2443DCCA0451372D4D7A6ACD8B593696EC52734FC467B42C2284EFD14995FEBF
- V367 ZIP: 34E00DB8BC2EF5E8929E5EC770D6CB61C02FB9DBCEE899D51411B6CDE03044B4
- V367 BIN: D00F8CE58F2ACAFEF3902AE3E3BB19DBE276467F625D75B69629E2FBD10415BB

V366 hash-pinned translation archive is a documented legacy input dependency; the new 58 entries and their structural bounds are independently compared with immutable original.
The disc packaging is from fresh original extraction, not an old BIN input. A fully original-only regeneration of the whole historical translation lineage is not claimed.

```powershell
python -X utf8 02_scripts/probe_v367_original.py
python -X utf8 02_scripts/build_arc1_v367_quiz.py
python -X utf8 02_scripts/verify_arc1_v367_quiz.py
python -X utf8 02_scripts/package_arc1_v367_quiz.py
python -X utf8 02_scripts/verify_arc1_v367_disc_delta.py
```

Packaging refuses to overwrite existing BIN/CUE. Existing outputs can be reverified without rerunning packaging.
Local generated JSON contains protected raw evidence and is not committed.

## 진행 중 잡힌 실패

초안은 여러 질문의 원본 byte 예산 초과와 완 등 미지원 글자를 검사에서 차단했다.
의미를 읽고 표현을 조정한 뒤 전량 인코딩/CPU 검사를 재실행했다.
E2에 선택 제어를 넣는 과거 실패 방식은 사용하지 않았다.

## 다음 확인

새 CUE로 재부팅 후 메모리카드에서 라마다사 진입, 문제를 연속 진행하면서 선택/취소/오답·정답 분기를 확인한다.
옛 상태저장에는 옛 script RAM이 들어 있으므로 그것만 불러와 새 빌드 여부를 판단하지 않는다.
대체 동물/인명 표기 승인 또는 글리프 공급 설계 판단이 남는다.
bible_current는 사용자 성공 확인 전이므로 기존 기준점 유지. changelog/test_log/codex_notes는 이번 결과를 기록한다.
