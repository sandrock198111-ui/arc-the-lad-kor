# V382 / v0.9.7 누적 수정

고정 V381 ZIP `9D9A2244729A765A0E98784D22A4DC8AC54F70C10E321D7462604F33774429CD`에서 누적. 업로드10개 전체경로/해시는 states.json에 고정했다. 원본·기존 빌드·업로드 상태는 변경하지 않았다.

| 제보 | 확인 및 결과 |
|---|---|
| 1 | SB071 #2395. 동료에게 하는 말이므로 모른다→몰라. 원문 かもしれない의 가능성 의미 유지. |
| 2 | SB071 #2396. E601 두 개 중 하나 제거, E503 둘 유지. 선택Y64/80→48/64. event47EC8 type6 baseRow2→1, 커서top66/82→50/66. 다른 인자와 다음 인덱스 보존. 원장은 이미 한 줄 개행이어서 수정 불필요. |
| 3 | 환상의 검(幻の剣), equipment_description47. 원문「与えるダメージの当たりはずれが大きくなります」는 주는 피해의 변동 폭 확대. 피해량 자체 증가/명중률 증가로 해석하지 않음. 기존20B 소유 영역 안에 '피해량의/변동 폭 증가'. 실제 설명 helper8016C760, header1F031C 검증. |
| 4 | 상태4는 SB022 로드 직후 검은 화면. 이후 하늘의 목소리 #2338~2360의 원본19h 대사 명령 및 별도21h type0/count1 타이머 보존 확인. 실제8015C48C→8015A420에서240/300/360/420회 후 대기 플래그 해제, 입력 불필요. 해당 파일은 변경하지 않음. 전체 연출/GPU 플레이 증명과 구별. |
| 5~10 | SF051 #2806~2812 전체7행. E4 25개가 모두 누락되어 있었음. 3D(60회)21개와1F(30회)4개 복원. #2811 중간 웃음도 포함. 8번만이 아니라 앞 #2807의捜索도 수색으로 일관되게 교정. #2809 원문은捜査지만 실종 일행의 행방을 찾는 문맥으로 수색 채택. |

대기복원은 E4를 본문에 남기고 평문만 E2 슬롯에 넣는다. 원본 순서·매개변수·실제 감소횟수·본문 종료주소를 검증했다. #2811은 같은장면 합성 적재, 상태10은 DAT RAM이 이미0으로 지워져 상태9 RAM에 #2812를 출력한 결과와 상태10에 남은 글자 패킷을 대조했다. 진행 중 캡처는 출력된 접두부의 XY/UV를 대조하며 아직 출력되지 않은 전체문장 재현으로 과장하지 않는다.

색 글리프: 직접 코드DF68/physical833. 기존V376 방식과 동일한 사용처·lookup·nontext geometry 검사 통과. 기존 Sans_8x4x4 자형으로 합성, COMM.IMG의 다른1919plane 보존. 후속 빌드는 `build_arc1_v382_reports.encoder/decoder`의 추가 매핑을 상속해야 한다. V376의 encoder만 사용하면 색을 모른다.

후보 실패도 기록: 색/짐의 미등록을 인코더가 거부; 짐이 필요 없는 최종 UI 표현을 채택. 긴 UI 후보25B가 기존20B 한도를 넘어서 포인터를 옮기지 않고 의미를 보존한 짧은 설명 선택. 글리프 후보754/762/777/804/806/823/831은 기존 사용 때문에 거부,833만 통과. UI 문자열은 resident RAM801FF6DB로 복사되는 영역이라 EXE의 일반 bias만으로 적재하면 기존 문구가 남음; 실제 resident 목적지까지 반영해 다시 검증했다.

최종 게임4멤버707B, ZIP SHA256 FA59A4730D531DEB93B66263D4E7B69DFD1170FA05FAAE469F4E15ABCA649EF7.
BIN SHA256 2179645D69313AFF8FEEFB06E38AA51CBD994B35CAE1633DF52E84D4AA8A129E.
164멤버 readback,506데이터파일 LBA 동일,38변경섹터76 EDC/ECC, 미설명payload변경0.
기존 V376~V381 CPU 회귀 통과. 실제 DuckStation 새부팅·전체장면·입력·GPU 검수는 미실행. bible_current의 사용자 확인 성공 기준은 유지한다.

재현: audit_arc1_v382_reports.py → build_arc1_v382_reports.py → package_arc1_v374_card_choice.main(build=V382, V381디스크 고정해시) → package_arc1_v382_xdelta.py. 원장 동기화는 sync_arc1_v382_canonical.py. 상세 증거는 build_report.json/package.json/xdelta.json/canonical_update.json.

2026-09-11 V382 final xdelta PASS: bundle arc1_kor_v0.9.7_rev1.zip 666650B SHA256 F95C88AE14E72B6B388BCFE6E5E29A6078D04CBB8E7E5E80198287A726D41AD5. Original Rev1 decode exactly equals V382 BIN; repeat encode byte exact. Five scripts AST and post-canonical prepare reproducibility PASS.
