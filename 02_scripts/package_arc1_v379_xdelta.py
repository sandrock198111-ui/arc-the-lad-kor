"""Original Rev1 -> V379 cumulative patch, roundtrip and reproducibility gates."""
import json,os,subprocess,tempfile
from pathlib import Path
from zipfile import ZipFile,ZipInfo,ZIP_DEFLATED
from package_arc1_v375_xdelta import hashes,TOOL,SOURCE,ROOT,TOOL_SHA
import build_arc1_v379_spirit_reports as build
TARGET=ROOT/'03_output/V379_SPIRIT_REPORTS.bin'
OUT=ROOT/'03_output/arc1_kor_v0.9.5_rev1'
BUNDLE=Path(str(OUT)+'.zip')

def main():
    assert not OUT.exists() and not BUNDLE.exists(),'Refusing overwrite'
    assert hashes(TOOL)['sha256']==TOOL_SHA
    src,tgt=hashes(SOURCE),hashes(TARGET)
    assert src['sha1']=='67E6B53D3C7D229FBAAFB23E75DCD91520AE35A4' and src['size']==631820112
    disc=json.loads((build.AN/'package.json').read_text(encoding='utf-8'))
    report=json.loads((build.AN/'build_report.json').read_text(encoding='utf-8'))
    assert tgt['sha256']==disc['bin_sha256'] and disc['unexplained_payload_changes']==0
    assert report['zip_sha256']==disc['archive_sha256']==build.digest(build.OUT.read_bytes())
    assert report['cpu']['water_temple']['return_value']==1 and len(report['applied'])==30
    assert len(report['cpu']['spirit_captures']['captures'])==10
    work=Path(tempfile.mkdtemp(prefix='v379_xdelta_',dir=ROOT/'01_work'))
    patch=work/'arc1_kor_v0.9.5_rev1.xdelta';decoded=work/'verified.bin';repeat=work/'repeat.xdelta'
    env=os.environ.copy();env.pop('XDELTA',None)
    def run(*args):subprocess.run([str(TOOL),*map(str,args)],check=True,env=env)
    run('-e','-9','-S','none','-A','-D','-s',SOURCE,TARGET,patch)
    run('-d','-D','-R','-s',SOURCE,patch,decoded);assert hashes(decoded)==tgt
    run('-e','-9','-S','none','-A','-D','-s',SOURCE,TARGET,repeat);assert patch.read_bytes()==repeat.read_bytes()
    verification=dict(version='v0.9.5',internal_build=379,source=src,target=tgt,patch=hashes(patch),
        roundtrip_exact=True,reencode_exact=True,unexplained_payload_changes=0,
        cumulative_base=378,dialogue_corpus_edits=18,supplemental_utterances=12,
        captured_cpu_cases=10,synthetic_text_cases=30,runtime_verified=False,
        remaining=['29 quiz speech-style rows held: owned storage exhausted',
        'Prior 6 UI/94 DAT source-confirmation backlog remains separately tracked',
        'DuckStation 0.1-7126 cold-boot/input/full gameplay verification pending',
        'Inherited Sans redistribution terms remain unverified'])
    readme=f'''아크더래드 1 한글 패치 v0.9.5 (V379) — 일본판 Rev 1 전용

V378에 누적한 수정입니다. V377 상태저장은 원인 분석에만 사용했습니다.
V376~V378의 물의 신전, 아이템/UI, 후우진, 선택지·커서 수정도 포함합니다.

적용 방법
1. 일본판 Rev 1 원본 BIN에 동봉 xdelta를 적용하세요.
2. 출력 파일 이름을 arc1_kor_v0.9.5.bin으로 지정하고 동봉 CUE를 옆에 두세요.
3. CUE로 새로 부팅하고 기존 메모리카드 세이브를 불러오세요.
   이전 에뮬레이터 상태저장은 옛 코드/RAM을 복원합니다.
   기존 한글 패치 BIN에 xdelta를 덧씌우는 방식이 아닙니다.

원본 CRC32 {src['crc32']} / MD5 {src['md5']}
패치 후 CRC32 {tgt['crc32']} / MD5 {tgt['md5']}
패치 후 SHA256 {tgt['sha256']}

수정 내용
- 추출에서 누락된 짧은 대사·감탄사 12곳 번역: 젠장!, 모두 서둘러!, 끈질긴 녀석들이군! 등.
- 성 귀환 대사의 반복 표현 및 병사의 존댓말 수정.
- 왕/불꽃의 정령 네 대사의 화자 뒤 개행, 대기 구간 띄어쓰기 정리. 대기 코드 위치·값 보존.
- 아크의 '비극을 계속 낳고 있어', 고겐/불의 정령의 '만들어 내다' 문맥 정리.
- '너희에게 져 주겠다!'를 '너희를 한 번 믿어 보겠다!'로 수정.
- 은혜의 정령: 돌아가세요, 그레이시누, 에너지 세 곳, 불꽃의 정령 명칭 수정.

검증: 고정 V378 기준 재빌드 일치, 기존 물의 신전/UI/커서 CPU 회귀,
상태저장 10개 글자 출력 재현, 수정 30곳의 글리프·행수·종료주소 검사,
디스크 파일 readback/LBA/EDC/ECC, xdelta 적용 결과 및 재생성 완전 일치.
DuckStation 0.1-7126 새부팅 및 전체 플레이 확인은 아직입니다.
정령 말투는 원문의 인물별 차이를 유지합니다. 전원 같은 말투로 바꾸지 않았습니다.

남은 검토: 퀴즈 말투 29행 및 이전 UI 6행/DAT 94행 미확정 목록은 별도 관리합니다.
기존 Sans 글꼴의 재배포 조건 미확인 기록도 남아 있습니다.
게임 BIN, 글꼴 원본, xdelta 실행파일은 포함하지 않습니다.
'''
    files={patch.name:patch.read_bytes(),'arc1_kor_v0.9.5.cue':b'FILE "arc1_kor_v0.9.5.bin" BINARY\r\n  TRACK 01 MODE2/2352\r\n    INDEX 01 00:00:00\r\n',
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
