"""Package V365 into fresh original-disc staging; preserve prior images."""
import json,subprocess,sys
import package_test_iso as p
import build_arc1_v365_compact_choice as b
ROOT=b.ROOT;stem='V365_COMPACT_CHOICE_TEST'
p.WORK=ROOT/'01_work/package_v365_compact_choice';p.FILES=p.WORK/'files';p.STATE=p.WORK/'applied.json'
binary=ROOT/'03_output'/f'{stem}.bin';cue=binary.with_suffix('.cue')
report=json.loads((b.AN/'build_report.json').read_text(encoding='utf-8'))
v=json.loads((b.AN/'verification.json').read_text(encoding='utf-8'))
assert b.digest(b.OUT.read_bytes())==report['zip_sha256']==v['zip_sha256'] and v['static_pass']
assert b.digest(b.ORIGINAL.read_bytes())==b.ORIGINAL_PIN
if binary.exists() or cue.exists():raise SystemExit('Refusing overwrite of existing disc')
if p.FILES.exists() and not (p.FILES/'PSX.EXE').exists():raise SystemExit('Incomplete staging requires inspection')
p.ensure_tree();p.restore_and_apply(b.OUT)
xml=p.WORK/f'{stem}.xml';p.write_xml(xml,binary,cue)
subprocess.run([str(p.MKPSXISO),'-y','-q','-lba',str(p.WORK/f'{stem}_lba.txt'),str(xml)],cwd=ROOT,check=True)
r=subprocess.run([sys.executable,'-X','utf8',str(ROOT/'02_scripts/verify_iso_layout.py'),str(binary),str(b.OUT)],cwd=ROOT,check=True,capture_output=True,text=True,encoding='utf-8')
assert binary.name in cue.read_text(encoding='utf-8-sig')
package={'bin':str(binary),'cue':str(cue),'bin_sha256':p.digest(binary),'archive_sha256':report['zip_sha256'],'verification':r.stdout,'runtime_verified':False}
(b.AN/'package.json').write_text(json.dumps(package,ensure_ascii=False,indent=2),encoding='utf-8')
print(r.stdout);print('BIN',package['bin_sha256']);print('CUE',cue)
