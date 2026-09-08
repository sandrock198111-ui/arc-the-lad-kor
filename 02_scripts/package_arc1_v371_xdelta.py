"""Create local TEST_ONLY xdelta pairs; do not promote V371 to public release."""
import argparse,hashlib,json,os,shutil,subprocess,tempfile,zlib
from pathlib import Path
from zipfile import ZipFile,ZipInfo,ZIP_DEFLATED
ROOT=Path(__file__).resolve().parents[1]
TARGET=ROOT/'03_output/V371_SPEAKER_FIXES_TEST.bin'
TARGET_SHA='95EED042FF3A6327D815543B80B5AD0D732288A27D0CC3B71C4F310E576FF247'
TOOL_SHA='6855C01CF4A1662BA421E6F95370CF9AFA2B3AB6C148473C63EFE60D634DFB9A'
SOURCES={'rev1':('3235502F','67E6B53D3C7D229FBAAFB23E75DCD91520AE35A4'),
         'rev0':('F9976430','08439ECBC6AC70C59DAE637B4E1291DA48729413')}

def hashes(path):
    sha=hashlib.sha256();one=hashlib.sha1();crc=0
    with path.open('rb') as f:
        for chunk in iter(lambda:f.read(1<<20),b''):
            sha.update(chunk);one.update(chunk);crc=zlib.crc32(chunk,crc)
    return dict(size=path.stat().st_size,sha256=sha.hexdigest().upper(),sha1=one.hexdigest().upper(),crc32=f'{crc:08X}')

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--rev1',type=Path,required=True)
    p.add_argument('--rev0-zip',type=Path,required=True)
    p.add_argument('--xdelta',type=Path,default=ROOT/'06_tools/xdelta/xdelta3-3.1.0-x86_64.exe')
    args=p.parse_args()
    out=ROOT/'03_output/arc1_v371_xdelta_TEST_ONLY'
    bundle=ROOT/'03_output/arc1_v371_xdelta_TEST_ONLY.zip'
    if out.exists() or bundle.exists():raise SystemExit('Refusing overwrite of patch outputs')
    assert hashes(args.xdelta)['sha256']==TOOL_SHA
    target_info=hashes(TARGET);assert target_info['sha256']==TARGET_SHA
    verification=json.loads((ROOT/'01_work/analysis/v371_speaker_fixes/disc_delta.json').read_text(encoding='utf-8'))
    assert verification['bin_sha256']==TARGET_SHA and verification['unexplained_payload_changes']==0
    work=Path(tempfile.mkdtemp(prefix='v371_xdelta_',dir=ROOT/'01_work'))
    rev0=work/'original_rev0.bin'
    with ZipFile(args.rev0_zip) as z:
        members=[i for i in z.infolist() if i.filename.lower().endswith('.bin')]
        assert len(members)==1 and members[0].file_size==631820112
        with z.open(members[0]) as src,rev0.open('xb') as dst:shutil.copyfileobj(src,dst)
    inputs={'rev1':args.rev1.resolve(),'rev0':rev0}
    report=dict(target=target_info,tool_sha256=TOOL_SHA,public_release_ready=False,
        blockers=['Sans redistribution license not verified','Remaining speaker-format/speech review and live runtime QA'],patches={})
    env=os.environ.copy();env.pop('XDELTA',None)
    def run(*command):subprocess.run([str(args.xdelta.resolve()),*map(str,command)],check=True,env=env)
    outputs={}
    for rev,source in inputs.items():
        info=hashes(source)
        assert info['size']==631820112 and (info['crc32'],info['sha1'])==SOURCES[rev]
        name=f'arc1_kor_v371_{rev}_TEST_ONLY.xdelta';patch=work/name
        run('-e','-9','-S','none','-A','-D','-s',source,TARGET,patch)
        reconstructed=work/f'verified_{rev}.bin'
        run('-d','-D','-R','-s',source,patch,reconstructed)
        assert hashes(reconstructed)==target_info
        repeated=work/f'repeated_{rev}.xdelta'
        run('-e','-9','-S','none','-A','-D','-s',source,TARGET,repeated)
        assert repeated.read_bytes()==patch.read_bytes()
        report['patches'][rev]=dict(source=info,patch=hashes(patch),file=name,roundtrip_exact=True,reencode_exact=True)
        outputs[name]=patch.read_bytes();print(rev,len(outputs[name]),'bytes; roundtrip/re-encode PASS',flush=True)
    outputs['arc1_kor_v371_TEST_ONLY.cue']=b'FILE "arc1_kor_v371_TEST_ONLY.bin" BINARY\r\n  TRACK 01 MODE2/2352\r\n    INDEX 01 00:00:00\r\n'
    readme='''아크더래드 1 V371 xdelta — 로컬 테스트용 / 공개 배포 보류

이 묶음은 완전한 게임 이미지가 아닌 차분 패치입니다. 직접 보유한 원본 BIN이 필요합니다.
번호는 V371 그대로이며, Sans 글꼴을 사용하는 V371_SPEAKER_FIXES_TEST와 결과가 같습니다.

원본 선택 (둘 다 631,820,112바이트이므로 크기로 구분하지 마세요):
- Rev 1: CRC32 3235502F -> rev1_TEST_ONLY.xdelta
- 초판: CRC32 F9976430 -> rev0_TEST_ONLY.xdelta

적용:
1. 원본을 보관하고 xdelta UI의 Apply에서 해당 원본 BIN과 패치를 선택합니다.
2. 새 출력 파일 이름을 arc1_kor_v371_TEST_ONLY.bin 으로 지정합니다. 원본에 덮어쓰지 마세요.
3. 동봉한 arc1_kor_v371_TEST_ONLY.cue를 출력 BIN 옆에 두고 CUE를 엽니다.
4. checksum mismatch가 뜨면 원본 리비전/해시를 확인하세요. 검사 무시 옵션은 사용하지 마세요.
5. 기존 상태저장은 옛 RAM을 복원합니다. 콜드부팅 후 메모리카드에서 진행하여 확인하세요.

결과 BIN SHA256:
'''+TARGET_SHA+'''

주의:
- 양쪽 원본에서 패치를 적용한 결과 해시 및 크기가 V371과 일치함을 검증했습니다.
- 이는 패치 적용 검증이지, 전 게임 플레이나 PSP 호환성 검증이 아닙니다.
- 화자 개행 잔여 26건, 콜론 없는 후보 65건, 전체 말투 검토/실기 확인이 남아 있습니다.
- Sans 글꼴의 재배포 조건이 확인되지 않아 공개 배포판으로 승인되지 않았습니다.
- 원본 BIN, 전체 패치 BIN, 폰트 원본, xdelta 실행 파일은 포함하지 않습니다.
'''
    outputs['읽어주세요.txt']=readme.encode('utf-8-sig')
    outputs['verification.json']=json.dumps(report,ensure_ascii=False,indent=2).encode('utf-8')
    assert all(not n.lower().endswith(('.bin','.exe','.ttf','.dat','.img')) for n in outputs)
    out.mkdir()
    for name,data in outputs.items():(out/name).write_bytes(data)
    with ZipFile(bundle,'x',compression=ZIP_DEFLATED,compresslevel=9) as z:
        for name,data in outputs.items():
            entry=ZipInfo(name,date_time=(2026,9,8,0,0,0));entry.compress_type=ZIP_DEFLATED
            z.writestr(entry,data)
    with ZipFile(bundle) as z:
        assert set(z.namelist())==set(outputs)
        assert all(z.read(n)==d for n,d in outputs.items())
    print('BUNDLE',bundle,hashes(bundle),flush=True)
    print('Local verification copies retained at',work)

if __name__=='__main__':main()
