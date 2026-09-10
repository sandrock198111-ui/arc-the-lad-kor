"""Fresh-original V374 disc; exact delta validation against V373."""
import json,subprocess,sys
import package_test_iso as p
import build_arc1_v374_card_choice as b
from verify_arc1_v362_disc_delta import timestamp_bytes,check_form1
from verify_iso_layout import read_iso

def main(build=None,stem='V374_CARD_CHOICE_TEST',work='package_v374_card_choice',baseline='V373_TWO_REPORTS_TEST.bin',baseline_sha='0DB641C005B2218F27B9BBAFEAA7FE215BDAFA8415F45E689404B9BD3C657A89'):
    if build is None:build=b
    root=build.ROOT
    p.WORK=root/'01_work'/work;p.FILES=p.WORK/'files';p.STATE=p.WORK/'applied.json'
    binary=root/'03_output'/f'{stem}.bin';cue=binary.with_suffix('.cue')
    report=json.loads((build.AN/'build_report.json').read_text(encoding='utf-8'))
    assert build.digest(build.OUT.read_bytes())==report['zip_sha256'] and report['static_pass']
    build.verify(build.OUT.read_bytes())
    assert build.digest(build.ORIGINAL.read_bytes())==build.ORIGINAL_PIN
    if binary.exists() or cue.exists():raise SystemExit('Refusing overwrite of existing disc')
    if p.FILES.exists() and not (p.FILES/'PSX.EXE').exists():raise SystemExit('Incomplete staging requires inspection')
    p.ensure_tree();p.restore_and_apply(build.OUT)
    xml=p.WORK/f'{stem}.xml';p.write_xml(xml,binary,cue)
    subprocess.run([str(p.MKPSXISO),'-y','-q','-lba',str(p.WORK/f'{stem}_lba.txt'),str(xml)],cwd=root,check=True)
    r=subprocess.run([sys.executable,'-X','utf8',str(root/'02_scripts/verify_iso_layout.py'),str(binary),str(build.OUT)],cwd=root,check=True,capture_output=True,text=True,encoding='utf-8')
    assert binary.name in cue.read_text(encoding='utf-8-sig')
    old=root/'03_output'/baseline
    assert p.digest(old)==baseline_sha
    assert old.stat().st_size==binary.stat().st_size
    layout=read_iso(binary);assert layout==read_iso(old)
    allowed=timestamp_bytes(binary);assert allowed==timestamp_bytes(old)
    for w in report['writes']:
        lba,size=layout[w['file']]
        for offset in range(w['offset'],w['offset']+len(bytes.fromhex(w['after']))):
            allowed.setdefault(lba+offset//2048,set()).add(24+offset%2048)
    changed=[]
    with old.open('rb') as a,binary.open('rb') as handle:
        for lba in range(binary.stat().st_size//2352):
            x,y=a.read(2352),handle.read(2352)
            if x==y:continue
            check_form1(x);check_form1(y);assert x[:24]==y[:24]
            assert all(x[i]==y[i] or i in allowed.get(lba,set()) for i in range(24,2072)),lba
            changed.append(lba)
    result=dict(bin=str(binary),cue=str(cue),bin_sha256=p.digest(binary),archive_sha256=report['zip_sha256'],
        verification=r.stdout,changed_sectors=changed,edc_ecc_checks=len(changed)*2,
        unexplained_payload_changes=0,all_extents_sizes_identical=True,runtime_verified=False)
    (build.AN/'package.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
    print(r.stdout);print('BIN',result['bin_sha256']);print('SECTORS',len(changed));print('CUE',cue)
if __name__=='__main__':main()
