"""Verified original Rev1-to-V377 hotfix package, without game images."""
import json,os,subprocess,tempfile
from pathlib import Path
from zipfile import ZipFile,ZipInfo,ZIP_DEFLATED
from package_arc1_v375_xdelta import hashes,TOOL,SOURCE,ROOT,TOOL_SHA
import build_arc1_v377_user_reports as build
TARGET=ROOT/'03_output/V377_USER_REPORTS.bin'
OUT=ROOT/'03_output/arc1_kor_v0.9.3_rev1'
BUNDLE=ROOT/'03_output/arc1_kor_v0.9.3_rev1.zip'

def main():
    assert not OUT.exists() and not BUNDLE.exists(),'Refusing overwrite'
    assert hashes(TOOL)['sha256']==TOOL_SHA
    src,tgt=hashes(SOURCE),hashes(TARGET)
    assert src['sha1']=='67E6B53D3C7D229FBAAFB23E75DCD91520AE35A4' and src['crc32']=='3235502F' and src['size']==631820112
    disc=json.loads((build.AN/'package.json').read_text(encoding='utf-8'))
    report=json.loads((build.AN/'build_report.json').read_text(encoding='utf-8'))
    assert tgt['sha256']==disc['bin_sha256'] and disc['unexplained_payload_changes']==0
    assert report['zip_sha256']==disc['archive_sha256']==build.digest(build.OUT.read_bytes())
    assert report['cpu']['water_temple']['return_value']==1 and len(report['dat'])==2
    work=Path(tempfile.mkdtemp(prefix='v377_xdelta_',dir=ROOT/'01_work'))
    patch=work/'arc1_kor_v0.9.3_rev1.xdelta';decoded=work/'verified.bin';repeat=work/'repeat.xdelta'
    env=os.environ.copy();env.pop('XDELTA',None)
    def run(*args):subprocess.run([str(TOOL),*map(str,args)],check=True,env=env)
    run('-e','-9','-S','none','-A','-D','-s',SOURCE,TARGET,patch)
    run('-d','-D','-R','-s',SOURCE,patch,decoded);assert hashes(decoded)==tgt
    run('-e','-9','-S','none','-A','-D','-s',SOURCE,TARGET,repeat);assert patch.read_bytes()==repeat.read_bytes()
    verification=dict(version='v0.9.3',internal_build=377,source=src,target=tgt,patch=hashes(patch),
        roundtrip_exact=True,reencode_exact=True,unexplained_payload_changes=0,
        inherited_v376_ui_fixes=102,inherited_v376_dat_fixes=70,event_rows_restored=24,
        v377_ui_edits=4,v377_dialogue_edits=2,captured_cpu_cases=6,
        runtime_verified=False,remaining=['29 quiz speech-style rows held: owned storage exhausted',
        '6 UI and 94 DAT source-confirmation rows remain',
        'DuckStation 0.1-7126 full gameplay/cold-boot verification pending',
        'Inherited Sans redistribution terms remain unverified'])
    readme=f'''아크더래드 1 한글 패치 v0.9.3 (V377 긴급 수정) — 일본판 Rev 1 전용

적용 방법
1. 일본판 Rev 1 원본 BIN에 동봉 xdelta를 적용하세요.
   기존 v0.9.1/v0.9.2/한글패치 BIN에 덧씌우지 마세요.
2. 출력 이름을 arc1_kor_v0.9.3.bin으로 지정하고 동봉 CUE를 옆에 두세요.
3. CUE로 새로 부팅한 뒤 기존 메모리카드 세이브를 불러오세요.
   에뮬레이터의 이전 상태저장은 옛 코드/RAM을 복원하므로 사용하지 마세요.

원본 Rev 1: CRC32 {src['crc32']} / MD5 {src['md5']}
패치 후 BIN: CRC32 {tgt['crc32']} / MD5 {tgt['md5']}
SHA256 {tgt['sha256']}
체크섬 오류가 나면 대상 원본이 맞는지 확인하세요.

수정 내용
- v0.9.2 제보 후속: '거의 반드시'를 '거의 확실히'로 수정.
- 목걸이 설명을 '레벨업 시 최대 체력 / 증가량 상승' 두 줄로 조정.
- 스킬 선택/빈 곳 선택 안내 앞 깨진 E7 01 기호 제거.
- 물의 정령 '자기들이'를 '본인들이'로, '후진'을 '후우진'으로 수정.
- 본인들이/후우진 글리프 및 대사·UI 고유명사 일치 검사 추가.

아래 v0.9.2 수정도 포함합니다.
- 물의 신전 진입 진행 불가를 포함한 잘못 번역된 이벤트 제어 24행 복구.
- 고겐/이가 및 다크 이름 뒤바뀜 수정. 장비 착용 데이터와 효과 연결은 원본 유지.
- 아이템·스킬·지역·도움말 등 공통 UI 확정 오류 102곳 수정.
- 튜토리얼·선택지의 잘못된 명칭, 누락된 안내 등 70곳 수정.
- 오돈 명령 포인터, 그래픽/효과음/색상 데이터, 배우 88~90 기록 원본 복구.
- 설명창과 기존 전투 커서/카드/선택지 수정 유지.

검증: 결정적 재빌드, 설명창/커서/물의 신전 이벤트 CPU 검사,
디스크 멤버 readback 및 변경 섹터 EDC/ECC, xdelta 적용 후 목표 BIN 완전 일치,
동일 xdelta 재생성 확인. DuckStation 0.1-7126 전체 플레이 검증은 아직 아닙니다.

남은 항목: 저장 공간이 부족한 퀴즈 말투 29행, 원문 확인이 더 필요한
UI 6행/DAT 94행. 전수 조사 목록은 작성했으나 모든 항목 해결 완료를 뜻하지 않습니다.
기존 기록의 Sans 글꼴 재배포 조건 미확인 상태도 남아 있습니다.
게임 BIN 및 글꼴 원본, xdelta 실행파일은 포함하지 않습니다.
'''
    files={patch.name:patch.read_bytes(),'arc1_kor_v0.9.3.cue':b'FILE "arc1_kor_v0.9.3.bin" BINARY\r\n  TRACK 01 MODE2/2352\r\n    INDEX 01 00:00:00\r\n',
        'README.txt':readme.encode('utf-8-sig'),'verification.json':json.dumps(verification,ensure_ascii=False,indent=2).encode('utf-8')}
    OUT.mkdir()
    for name,data in files.items():(OUT/name).write_bytes(data)
    with ZipFile(BUNDLE,'x') as z:
        for name,data in files.items():
            info=ZipInfo(name,(2026,9,11,0,0,0));info.compress_type=ZIP_DEFLATED;z.writestr(info,data)
    with ZipFile(BUNDLE) as z:assert set(z.namelist())==set(files) and all(z.read(n)==v for n,v in files.items())
    result=dict(bundle=str(BUNDLE),bundle_hashes=hashes(BUNDLE),**verification)
    (build.AN/'xdelta.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps(result,ensure_ascii=False,indent=2))
if __name__=='__main__':main()
