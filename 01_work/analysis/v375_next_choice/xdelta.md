# v0.9.1 / V375 Rev1 xdelta

2026-09-10 사용자 V375 xdelta/해시 요청, 이전 배포명 v0.9 확인. v0.9.1 이름을 제안하고 파일에 사용했다. 내용은 V375 그대로이며 v0.9 위에 덧씌우는 패치가 아니라 Rev1 원본→V375 전체 차분이다. 외부 업로드/공개 릴리스 승격은 하지 않았다.

- 생성기: `02_scripts/package_arc1_v375_xdelta.py`.
- 묶음: `03_output/arc1_kor_v0.9.1_rev1.zip`, 666009B, SHA256 `D419479B941A77ADBB5CDAEEC489F49B23575FA9C737DD9DCE0552C446A43421`.
- xdelta: 725121B, SHA256 `5ECE5BF35755B318B51CFE75D7E0E6A7B575A51C277FD9E55BCCE38E8AA0B41C`.
- 원본Rev1 CRC32 `3235502F`, MD5 `219F45A30345D4A7370303576E312D8C`.
- 목표BIN CRC32 `6444902C`, MD5 `AAE9F3DB5BE7907E0F2A85933713D1F6`, SHA256 `E732E26BEEBEAA3B6926125837DA2A348BEB885741AB4EA5949AD7E8B031B95F`.
- 고정xdelta3 도구와 기존V375 디스크검증 해시 확인 후 생성→적용복원전체해시일치→재인코딩동일→ZIP재읽기검증 PASS.
- 구성은 xdelta/CUE/README/verification JSON뿐이다. 원본/게임BIN/폰트원본/실행파일 미포함. 출력BIN 이름은 `arc1_kor_v0.9.1.bin`으로 CUE와 일치시킨다.
- 기존출력 덮어쓰기 거부, 원본/기존BIN/메모리카드 미수정. 게임의 새 수정은 없다.
- Sans 재배포 조건 미확인, 번역/실기 잔여는 README에 명시했다. 패키징 검증을 전게임/PSP 검증으로 확대하지 않는다.

후속 선택지 대화체 복원 희망을 bible에 기록했다. 이번 패키지에서는 정보2 등을 변경하지 않았다. 다음은 남은 권리 조건/실기 검수와 추후 선택지 문맥·슬롯 검토이다.
