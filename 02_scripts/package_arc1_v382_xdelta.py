"""Original Rev1 -> final V382 cumulative patch, roundtrip/reproducibility gates."""
import json,os,subprocess,tempfile
from pathlib import Path
from zipfile import ZipFile,ZipInfo,ZIP_DEFLATED
from package_arc1_v375_xdelta import hashes,TOOL,SOURCE,ROOT,TOOL_SHA
import build_arc1_v382_reports as build
TARGET=ROOT/'03_output/V382_REPORTS.bin'
OUT=ROOT/'03_output/arc1_kor_v0.9.7_rev1'
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
    assert report['cpu']['water_temple']['return_value']==1 and len(report['applied'])==9
    assert len(report['cpu']['followup_v380']['captures'])==6
    assert len(report['cpu']['scene_pauses_v381']['cases'])==10
    assert len(report['cpu']['reports_v382']['waits'])==7
    assert report['cpu']['reports_v382']['voice_native_timer_proof']
    work=Path(tempfile.mkdtemp(prefix='v382_xdelta_',dir=ROOT/'01_work'))
    patch=work/'arc1_kor_v0.9.7_rev1.xdelta';decoded=work/'verified.bin';repeat=work/'repeat.xdelta'
    env=os.environ.copy();env.pop('XDELTA',None)
    def run(*args):subprocess.run([str(TOOL),*map(str,args)],check=True,env=env)
    run('-e','-9','-S','none','-A','-D','-s',SOURCE,TARGET,patch)
    run('-d','-D','-R','-s',SOURCE,patch,decoded);assert hashes(decoded)==tgt
    run('-e','-9','-S','none','-A','-D','-s',SOURCE,TARGET,repeat);assert patch.read_bytes()==repeat.read_bytes()
    verification=dict(version='v0.9.7',internal_build=382,source=src,target=tgt,patch=hashes(patch),
        roundtrip_exact=True,reencode_exact=True,unexplained_payload_changes=0,
        cumulative_base=381,dialogue_corpus_edits=9,ui_edits=1,
        captured_cpu_cases=9,original_pause_comparisons=7,runtime_verified=False,
        remaining=['29 quiz speech-style rows held: owned storage exhausted',
        'Prior 6 UI/94 DAT source-confirmation backlog remains separately tracked',
        'DuckStation 0.1-7126 cold-boot/input/full gameplay verification pending',
        'Inherited Sans redistribution terms remain unverified'])
    readme=(ROOT/'05_docs/v382_patch_readme.txt').read_text(encoding='utf-8').format(source_crc=src['crc32'],source_md5=src['md5'],target_sha=tgt['sha256'])
    files={patch.name:patch.read_bytes(),'arc1_kor_v0.9.7.cue':b'FILE "arc1_kor_v0.9.7.bin" BINARY\r\n  TRACK 01 MODE2/2352\r\n    INDEX 01 00:00:00\r\n',
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
