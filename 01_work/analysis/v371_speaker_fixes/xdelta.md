# V371 xdelta 로컬 패키징 (2026-09-08)

사용자는 배포용 xdelta 생성을 요청했다. 현행 TEST_ONLY에 알려진 화자/말투 잔여, 실기 확인 및 Sans 재배포 조건 미확인이 있어 정식 공개 배포판으로 승격하지 않았다. 로컬 차분 파일을 생성·검증했으며 외부에 업로드하지 않았다.

## 결과

- 묶음: `03_output/arc1_v371_xdelta_TEST_ONLY.zip` / 1,330,801바이트.
- SHA256: `BE5289D0C90F7763D0813056672BC819F0268EE424F79257E53B197E2E56A046`
- Rev1 패치 725,072바이트: 원본 CRC32 `3235502F`, SHA1 `67E6B53D3C7D229FBAAFB23E75DCD91520AE35A4`.
- Rev0 패치 725,748바이트: 원본 CRC32 `F9976430`, SHA1 `08439ECBC6AC70C59DAE637B4E1291DA48729413`.
- 두 원본 크기 631,820,112바이트. 원본 크기만으로 판별하지 않는다.
- 두 패치 모두 적용 결과 SHA256 `95EED042FF3A6327D815543B80B5AD0D732288A27D0CC3B71C4F310E576FF247`: 기존 V371 목표 BIN과 동일하다.
- 패치2개 + 출력 BIN용 CUE + 한국어 안내문 + verification.json만 ZIP에 포함했다. 완전한 게임 이미지/폰트 원본/xdelta 실행 파일은 포함하지 않았다. 세부 원본·패치 해시는 묶음 verification.json에 있다.

## 재현 및 검증

`python -X utf8 02_scripts/package_arc1_v371_xdelta.py --rev1 <원본-Rev1.bin> --rev0-zip <초판-원본.zip>`

기존 로컬 xdelta 3.1.0 x86_64 도구 SHA256 `6855C01CF4A1662BA421E6F95370CF9AFA2B3AB6C148473C63EFE60D634DFB9A` 사용. 실행 파일을 재배포하지 않는다. 환경 XDELTA 변수는 자식 프로세스에서 제거한다.

인코딩 `-e -9 -S none -A -D -s`, 검증 디코딩 `-d -D -R -s`. 두 리비전 모두 재인코딩 파일 byte-exact와 적용 출력 크기/SHA256/SHA1/CRC32를 목표와 대조했다. 원본은 읽기 전용, 검증 출력은 새 임시 작업 폴더이며 기존 파일 덮어쓰기는 거부한다. ZIP 재열기 후 멤버 이름과 모든 내용도 exact 확인했다.

BIN/대사/엔진은 이번 작업에서 변경하지 않았다. 번호 V371 유지. xdelta 패키징 검증이 게임 진행 또는 PSP 구동 검증을 대신하지 않는다. 공개 배포 전 Sans 권리 조건과 미검수 항목/실기 확인을 별도로 해소해야 한다.

bible_current의 사용자 확인 성공점은 유지한다. changelog에는 패키징만, test_log에는 적용 검증만, codex_notes에는 두 리비전의 동일 목표 변환 확인을 기록했다. 다음 작업 후보는 Sans 재배포 근거 확인 및 V371 실기 확인이다.
