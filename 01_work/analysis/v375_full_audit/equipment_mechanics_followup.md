# V375 장비·소모품 미확정 3행 후속 분석

원본 PSX.EXE와 V375의 실행 코드·속성 데이터를 직접 추적했다. 외부 공략은 사용하지 않았다. 게임 파일 수정 없음.

15개 명시 범위의 원본/V375 바이트가 모두 동일하다. 구간 주소·길이·각 SHA256과 원본 디스어셈블은 JSON에 수록했다. 이 검사는 실제 DuckStation 실행이나 화면 재현을 대신하지 않는다.

## equipment_description:48 — CONFIRMED_DEFECT

현재 문구는 쿠쿠루가 부활 마법을 받으면 만HP가 된다고 한다. 실제 장비 검사는 부활 시전자의 장비이며 그 시전자가 되살리는 대상의 HP를 만HP로 유지한다.

- 8012E394 s0=a0 actor; 8012E3B8 equipped(actor,0x31)
- 8012E438 target_id=actor+AA; 8012E43C call 80128D78 with a3=equipment result
- 80128D8C saves equipment flag; 80128DA4 skips half-HP removal when flag nonzero
- 80128DAC..28DC8 reads newly created recipient maximum HP at +14 and removes half only without equipment
- 8012E474..2E484 subsequently charges MP to same actor, separating actor from new recipient

## equipment_description:49 — CONFIRMED_DEFECT

피해 편차 증가는 사실이나 회복량 변동에도 영향을 준다. 원본의 일반적인 편차 설명을 피해만으로 좁혀 회복 효과 범위를 누락했다.

- equipment49 raw 00 01 1A 00 64 00: percentage increase 100 to stat 0x1A
- 80174D50..74DF4 reads original stat and computes original + original*100/100
- getter table 8011B844 -> 80175368 reads stat +30
- 801744E0..74544 applies base + trunc(base*(rand(2*spread)-spread)/100)
- 80173038 physical, 801731D8 magic, 80173330 item use spread
- 8017354C,80173554 sum caster/recipient spread; 80173580 applies same variation to healing

## consumable_description:2 — ACCEPTABLE_ABBREVIATION

레벨 1 상승은 실제 효과와 일치한다. 레벨 60 상한에서 변화하지 않는 예외는 원본 설명 역시 생략한다.

- consumable table row2 801A1CF0 = 05 00 00 00
- 80164ED8 dispatch type5 -> 80164F4C -> 80164F64; item index2 -> 80164FAC
- 80164FBC guards level<60; 80164FC8/64FD8 threshold function to both stats+8
- 80173DA8 threshold = current level * character coefficient
- 80173BCC checks exp >= threshold; 80173E54/73E70 subtract threshold; 80173E88/73EA0 increment level once
- Decoded arithmetic verified for 8 party IDs x levels1..59 =472 cases; no CPU harness claimed

CSV 판정 갱신 제안: description48/49를 CONFIRMED_DEFECT로, consumable_description2를 ACCEPTABLE_ABBREVIATION으로 변경한다. 이 후속 작업의 쓰기 범위는 helper/후속MD/JSON에 한정되어 이전 CSV는 직접 수정하지 않았다.

회복량 편차는 시전자뿐 아니라 회복 대상의 장비 변동폭도 더해진다. 피해만으로 좁힌 설명은 이를 전달하지 못한다. 새 문구는 의미 제안이며 정식 번역 수정·승인이 아니다.

재현: python 01_work/analysis/v375_full_audit/audit_equipment_mechanics.py

검산: 15/15 code/data spans byte-exact, attributes and dispatch assertions PASS, decoded arithmetic 472/472 PASS. 실제 게임에서의 장비 교체·부활·회복량·레벨업 UI 검증은 별도 필요.
