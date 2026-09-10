"""v0.9.1 (V375), Rev1-only original-to-target xdelta; no public readiness claim."""
import hashlib,json,os,subprocess,tempfile
from pathlib import Path
from zipfile import ZipFile,ZipInfo,ZIP_DEFLATED
from package_arc1_v371_xdelta import hashes as base_hashes,TOOL_SHA
ROOT=Path(__file__).resolve().parents[1]
TARGET=ROOT/'03_output/V375_NEXT_CHOICE_TEST.bin'
PIN='E732E26BEEBEAA3B6926125837DA2A348BEB885741AB4EA5949AD7E8B031B95F'
SOURCE=Path('E:/arc/원본/arc1.bin')
TOOL=ROOT/'06_tools/xdelta/xdelta3-3.1.0-x86_64.exe'
OUT=ROOT/'03_output/arc1_kor_v0.9.1_rev1'
BUNDLE=ROOT/'03_output/arc1_kor_v0.9.1_rev1.zip'
def hashes(path):
    h=base_hashes(path)
    with path.open('rb') as f:h['md5']=hashlib.file_digest(f,'md5').hexdigest().upper()
    return h

def main():
    assert not OUT.exists() and not BUNDLE.exists(),'Refusing overwrite'
    assert hashes(TOOL)['sha256']==TOOL_SHA
    src,tgt=hashes(SOURCE),hashes(TARGET)
    assert src['sha1']=='67E6B53D3C7D229FBAAFB23E75DCD91520AE35A4' and src['crc32']=='3235502F'
    assert src['size']==631820112 and tgt['sha256']==PIN
    disc=json.loads((ROOT/'01_work/analysis/v375_next_choice/package.json').read_text(encoding='utf-8'))
    assert disc['bin_sha256']==PIN and disc['unexplained_payload_changes']==0
    work=Path(tempfile.mkdtemp(prefix='v375_xdelta_',dir=ROOT/'01_work'))
    patch=work/'arc1_kor_v0.9.1_rev1.xdelta';restored=work/'verified.bin';repeat=work/'repeat.xdelta'
    env=os.environ.copy();env.pop('XDELTA',None)
    def run(*args):subprocess.run([str(TOOL),*map(str,args)],check=True,env=env)
    run('-e','-9','-S','none','-A','-D','-s',SOURCE,TARGET,patch)
    run('-d','-D','-R','-s',SOURCE,patch,restored)
    assert hashes(restored)==tgt
    run('-e','-9','-S','none','-A','-D','-s',SOURCE,TARGET,repeat)
    assert patch.read_bytes()==repeat.read_bytes()
    report=dict(version='v0.9.1',internal_build=375,source=src,target=tgt,patch=hashes(patch),
                roundtrip_exact=True,reencode_exact=True,public_release_ready=False,
                limitations=['Sans redistribution terms not verified','Remaining dialogue review and live runtime QA'])
    readme=f'''아크더래드 1 한글 패치 v0.9.1 (내부 빌드 V375) — 일본판 Rev 1 전용

일본판 Rev 1 원본 BIN에 적용하는 전체 차분입니다.
기존 v0.9/한글패치 BIN에 덧씌우지 마세요. 원본에 덮어쓰지 마세요.
xdelta 적용 도구에서 원본 BIN과 동봉한 xdelta를 선택하고,
출력 이름을 arc1_kor_v0.9.1.bin으로 지정하세요.
동봉 CUE를 출력 BIN 옆에 두고 CUE로 실행하세요.
checksum mismatch가 나면 검사를 무시하지 말고 원본 해시를 확인하세요.
구 상태저장은 옛 RAM을 복원하므로 새 부팅 후 메모리카드로 진행하세요.

원본 대상 해시값 (Rev 1)
CRC32 : {src['crc32']}
MD5 : {src['md5']}

패치 후 BIN 해시값 (v0.9.1 / V375)
CRC32 : {tgt['crc32']}
MD5 : {tgt['md5']}
SHA256 : {tgt['sha256']}

V371 이후 반영: 제보된 확인문 존댓말/대사 개행 수정,
메모리카드 1/2 라벨 복구, 제보된 전투 확인 선택지 두 건의 빈 줄 정리.
V372 어절 단위 강제 조판은 포함하지 않았습니다.
전체 선택지 대화체 복원은 향후 과제로 이번에는 적용하지 않았습니다.

주의: 패치 재적용 결과의 목표 BIN 일치와 재생성 동일성을 검증했습니다.
이는 전체 플레이/PSP 호환성 보증이 아닙니다.
기록상 Sans 글꼴 재배포 조건 및 남은 번역/실기 검수가 미확인 상태입니다.
버전명 부여가 공개 배포 준비 완료를 뜻하지 않습니다.
원본/패치된 게임 BIN, 글꼴 원본, xdelta 실행파일은 포함하지 않습니다.
'''
    files={patch.name:patch.read_bytes(),'arc1_kor_v0.9.1.cue':b'FILE "arc1_kor_v0.9.1.bin" BINARY\r\n  TRACK 01 MODE2/2352\r\n    INDEX 01 00:00:00\r\n',
           'README.txt':readme.encode('utf-8-sig'),'verification.json':json.dumps(report,ensure_ascii=False,indent=2).encode('utf-8')}
    OUT.mkdir()
    for name,data in files.items():(OUT/name).write_bytes(data)
    with ZipFile(BUNDLE,'x') as z:
        for name,data in files.items():
            info=ZipInfo(name,(2026,9,10,0,0,0));info.compress_type=ZIP_DEFLATED;z.writestr(info,data)
    with ZipFile(BUNDLE) as z:assert set(z.namelist())==set(files) and all(z.read(n)==d for n,d in files.items())
    print(json.dumps(dict(bundle=str(BUNDLE),bundle_hashes=hashes(BUNDLE),**report),ensure_ascii=False,indent=2))
if __name__=='__main__':main()
