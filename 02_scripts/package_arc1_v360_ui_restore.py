"""Package V360 in its own original-disc staging tree, preserving old builds."""
from pathlib import Path
import json, subprocess, sys
import package_test_iso as p
import build_arc1_v360_ui_restore as b

ROOT=b.ROOT
stem='V360_UI_RESTORE_TEST'
p.WORK=ROOT/'01_work/package_v360_ui_restore'
p.FILES=p.WORK/'files'
p.STATE=p.WORK/'applied.json'
binary=ROOT/'03_output'/f'{stem}.bin'
cue=binary.with_suffix('.cue')
report=json.loads((b.AN/'build_report.json').read_text(encoding='utf-8'))
assert b.cursor.digest(b.OUT.read_bytes())==report['zip_sha256']
if binary.exists() or cue.exists():raise SystemExit('Output exists; refusing overwrite')
p.ensure_tree()
p.restore_and_apply(b.OUT)
xml=p.WORK/f'{stem}.xml'
p.write_xml(xml,binary,cue)
subprocess.run([str(p.MKPSXISO),'-y','-q','-lba',str(p.WORK/f'{stem}_lba.txt'),str(xml)],cwd=ROOT,check=True)
result=subprocess.run([sys.executable,str(ROOT/'02_scripts/verify_iso_layout.py'),str(binary),str(b.OUT)],
                      cwd=ROOT,check=True,capture_output=True,text=True,encoding='utf-8',errors='replace')
assert binary.name in cue.read_text(encoding='utf-8-sig')
package={'bin':str(binary),'cue':str(cue),'bin_sha256':p.digest(binary),'cue_sha256':p.digest(cue),
         'archive_sha256':report['zip_sha256'],'verification':result.stdout,'runtime_verified':False}
(b.AN/'package.json').write_text(json.dumps(package,ensure_ascii=False,indent=2),encoding='utf-8')
print(result.stdout);print('BIN SHA256',package['bin_sha256']);print('CUE',cue)
