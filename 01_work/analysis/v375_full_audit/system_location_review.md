# V375 system/location/alias semantic review

255/255 assigned rows directly read. {'PASS_SEMANTIC': 164, 'NEEDS_SOURCE_CONFIRMATION': 4, 'ACCEPTABLE_ABBREVIATION': 19, 'CONFIRMED_DEFECT': 62, 'EMPTY_PLACEHOLDER': 1, 'HUD_BINARY': 5}

Current strings: actual V375 PSX.EXE decode in ui_inventory.json. Source pixels: original COMM sheets 01 and 28–43 inspected. Page02 loading rows also inspected as pixels. Historical nearest-glyph guesses are not source proof. Each row independently assessed; no similarity score or expected-translation bulk pass. No game/canonical files modified.

## Confirmed findings

- location_name:17: オルニス(오르니스)를 오르카스로 오독. region_name:3과 동일.

- region_name:3: オルニス(오르니스)를 오르카스로 오독.
- region_name:5: コルボ(코르보)를 니르로 오독.
- region_name:7: クイナ(쿠이나)의 イ 누락: 쿠나.
- region_name:12: ニカラス(니카라스)를 카카라스로 오독.
- region_name:13: 沼(늪)를 늘로 오자.
- region_name:20: アゼンダ(아젠다)의 ン 누락: 아제다.
- region_name:26: イシュマ(이슈마)를 라슈마로 오독.
- region_name:27: ニーデル(니델)을 카델로 오독.
- ui_pointer:81EFC: ニーデル(니델)을 카델로 오독.
- location_name:21: アゼンダ(아젠다)의 ン 누락: 아제다.
- location_name:22: アゼンダ(아젠다)의 ン 누락: 아제다.
- location_name:29: ニーデル(니델)을 카델로 오독.
- location_name:30: コロシアム(콜로세움)을 니로시암으로 오독.
- location_name:31: コロシアム(콜로세움)을 니로시암으로 오독.
- location_name:42: コルボ(코르보)를 니르로 오독.
- location_name:44: クイナ(쿠이나)의 イ 누락: 쿠나.
- location_name:46: ニカラス(니카라스)를 카카라스로 오독.
- location_name:47: 沼(늪)를 늘로 오자.
- location_name:50: イシュマ(이슈마)를 라슈마로 오독.
- location_name:51: コロシアム(콜로세움)을 니로시암으로 오독.
- ui_pointer:82348: 원문 E707/E706 대상 변경 버튼 코드가 삭제되어 현행 대상 변경만 남음. 입력 방법 정보 누락.
- ui_pointer:82354: 원문 E701로 능력 선택 안내의 방향 입력 코드 삭제.
- ui_pointer:82358: 원문 E703으로 취소한다는 안내의 취소 버튼 코드 삭제.
- ui_pointer:8236C: 원문 빈 장소를 E701로 선택 안내의 방향 입력 코드 삭제.
- ui_pointer:82948: 毒攻撃(독 공격)을 해로운 공격으로 번역하여 특정 독 상태 정보 누락.
- ui_pointer:82950: 동일 원문 기술의 이름이 main skill_name:51에서는 폭렬 수리검, 이 UI 별도 포인터에서는 폭발 수리검로 달라짐.
- ui_pointer:8295C: 동일 원문 기술의 이름이 main skill_name:25에서는 익스플로전, 이 UI 별도 포인터에서는 대폭발로 달라짐.
- ui_pointer:82960: 동일 원문 기술의 이름이 main skill_name:28에서는 윈드 슬래셔, 이 UI 별도 포인터에서는 바람 검로 달라짐.
- ui_pointer:82964: 동일 원문 기술의 이름이 main skill_name:30에서는 썬더 스톰, 이 UI 별도 포인터에서는 전기 폭풍로 달라짐.
- ui_pointer:8296C: 동일 원문 기술의 이름이 main skill_name:7에서는 디포이즌, 이 UI 별도 포인터에서는 해로운 기운 제거로 달라짐. 독 해제를 일반 유해 효과 해제로 넓힌 표현이기도 함.
- ui_pointer:82970: 동일 원문 기술의 이름이 main skill_name:10에서는 천벌, 이 UI 별도 포인터에서는 하늘의 심판로 달라짐.
- ui_pointer:82974: 동일 원문 기술의 이름이 main skill_name:11에서는 리저렉션, 이 UI 별도 포인터에서는 부활로 달라짐.
- ui_pointer:82980: 동일 원문 기술의 이름이 main skill_name:6에서는 큐어, 이 UI 별도 포인터에서는 회복로 달라짐.
- ui_pointer:82988: 毒のきり(독 안개)를 해로운 기운으로 번역하여 독/안개 정보 누락.
- ui_pointer:82998: 동일 원문 기술의 이름이 main skill_name:54에서는 사방 공격, 이 UI 별도 포인터에서는 주위 공격로 달라짐.
- ui_pointer:829B0: 동일 원문 기술의 이름이 main skill_name:53에서는 지옥으로 가는 계단, 이 UI 별도 포인터에서는 지옥의 계단로 달라짐.
- ui_pointer:829D0: 동일 원문 기술의 이름이 main skill_name:57에서는 요미의 날개, 이 UI 별도 포인터에서는 황천 비행로 달라짐.
- ui_pointer:829D8: 실제 원문 デスボール(데스 볼/죽음의 공)을 죽음 회복으로 오독. 공격명에 회복이라는 다른 의미 부여.
- ui_pointer:829DC: 실제 원문 ダストルーイン(더스트 루인)의 ruin을 rune/문양으로 오독한 더스트 문양. main skill_name:56 더스트 룬과도 불일치.
- ui_pointer:829E8: 동일 원문 기술의 이름이 main skill_name:2에서는 토탈 힐링, 이 UI 별도 포인터에서는 전체 회복로 달라짐.
- ui_pointer:829F4: 동일 원문 기술의 이름이 main skill_name:5에서는 메테오 폴, 이 UI 별도 포인터에서는 별 내리기로 달라짐.
- ui_pointer:829F8: 동일 원문 기술의 이름이 main skill_name:6에서는 큐어, 이 UI 별도 포인터에서는 회복로 달라짐.
- ui_pointer:829FC: 동일 원문 기술의 이름이 main skill_name:7에서는 디포이즌, 이 UI 별도 포인터에서는 해로운 기운 제거로 달라짐. 독 해제를 일반 유해 효과 해제로 넓힌 표현이기도 함.
- ui_pointer:82A08: 동일 원문 기술의 이름이 main skill_name:10에서는 천벌, 이 UI 별도 포인터에서는 하늘의 심판로 달라짐.
- ui_pointer:82A0C: 동일 원문 기술의 이름이 main skill_name:11에서는 리저렉션, 이 UI 별도 포인터에서는 부활로 달라짐.
- ui_pointer:82A14: 동일 원문 기술의 이름이 main skill_name:13에서는 앵화뇌폭참, 이 UI 별도 포인터에서는 토슈 비기로 달라짐.
- ui_pointer:82A18: 동일 원문 기술의 이름이 main skill_name:14에서는 주박검, 이 UI 별도 포인터에서는 봉인검로 달라짐.
- ui_pointer:82A1C: 동일 원문 기술의 이름이 main skill_name:15에서는 진공참, 이 UI 별도 포인터에서는 진공검로 달라짐.
- ui_pointer:82A20: 동일 원문 기술의 이름이 main skill_name:16에서는 호영참, 이 UI 별도 포인터에서는 그림자검로 달라짐.
- ui_pointer:82A24: 戦の小太鼓(전투의 작은 북)를 전투 큰 북으로 번역해 크기 반전. main skill_name:17 전투의 북과도 불일치.
- ui_pointer:82A28: 荒獅子太鼓는 main skill_name:18 황사자 북인데 이곳은 황사자태고. 같은 기술 악기 표기 불일치.
- ui_pointer:82A30: 동일 원문 기술의 이름이 main skill_name:20에서는 탈진 나팔, 이 UI 별도 포인터에서는 비틀비틀 나팔로 달라짐.
- ui_pointer:82A38: 동일 원문 기술의 이름이 main skill_name:22에서는 둔화 베이스, 이 UI 별도 포인터에서는 느림의 연주로 달라짐.
- ui_pointer:82A40: 동일 원문 기술의 이름이 main skill_name:24에서는 방향전환 피리, 이 UI 별도 포인터에서는 방향잡이 피리로 달라짐.
- ui_pointer:82A44: 동일 원문 기술의 이름이 main skill_name:25에서는 익스플로전, 이 UI 별도 포인터에서는 대폭발로 달라짐.
- ui_pointer:82A50: 동일 원문 기술의 이름이 main skill_name:28에서는 윈드 슬래셔, 이 UI 별도 포인터에서는 바람 검로 달라짐.
- ui_pointer:82A54: 동일 원문 기술의 이름이 main skill_name:30에서는 썬더 스톰, 이 UI 별도 포인터에서는 전기 폭풍로 달라짐.
- ui_pointer:82A58: 동일 원문 기술의 이름이 main skill_name:34에서는 선풍격축, 이 UI 별도 포인터에서는 회오리 차기로 달라짐.
- ui_pointer:82A60: 동일 원문 기술의 이름이 main skill_name:36에서는 귀신류영파, 이 UI 별도 포인터에서는 유령 파동로 달라짐.
- ui_pointer:82A7C: 동일 원문 기술의 이름이 main skill_name:48에서는 풍뢰파, 이 UI 별도 포인터에서는 바람 전기로 달라짐.
- ui_pointer:82A80: 동일 원문 기술의 이름이 main skill_name:50에서는 빙의, 이 UI 별도 포인터에서는 몸 가져오기로 달라짐.
- ui_pointer:82A84: 동일 원문 기술의 이름이 main skill_name:58에서는 의욕 없음, 이 UI 별도 포인터에서는 기운 없음로 달라짐.

## Unresolved caller/context checks

- ui_pointer:781B8: 원문 데이터 선택에 없는 불러올 추가. 로드 전용 호출인지 확인 필요.
- ui_pointer:82360: 원문 다음은 대상 선택에 L과 R 조작 추가. V360 의도는 기록되어 있으나 모든 호출 상태의 입력 대응 확인 필요.
- ui_pointer:825E8: 옵션 값 よくする(좋게/개선)를 사용으로 번역. ふつう/しない와 실제 옵션 조합 문맥 확인 필요.
- ui_pointer:82AC8: 장비 정비 질문에 전투 전 추가. 모든 호출이 전투 직전인지 확인 필요.

## Coverage limits

All 255 owned IDs appear exactly once. Five declared HUD_BINARY fragments and one original/current empty placeholder are explicitly classified, not prose passes. Remaining 249 rows receive semantic judgments including four caller-context questions. Alias defects count affected pointers, not independent root causes. Runtime behavior, hidden references, numeric/effect tables and event commands are root audit scope. No build or game modification occurred.
