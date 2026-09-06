"""Read-only sector envelope and EDC/ECC verification for V367."""
from pathlib import Path
import json,hashlib
from verify_arc1_v362_disc_delta import timestamp_bytes,check_form1
from verify_iso_layout import read_iso
ROOT=Path(__file__).resolve().parents[1];AN=ROOT/'01_work/analysis/v367_quiz'
old=ROOT/'03_output/V366_FOLLOWUPS_TEST.bin';new=ROOT/'03_output/V367_QUIZ_TEST.bin'
assert old.stat().st_size==new.stat().st_size
layout=read_iso(new);assert layout==read_iso(old)
allowed=timestamp_bytes(new);assert allowed==timestamp_bytes(old)
report=json.loads((AN/'build_report.json').read_text(encoding='utf-8'))
for w in report['writes']:
    lba,size=layout[w['file']]
    for offset in range(w['offset'],w['offset']+len(bytes.fromhex(w['after']))):
        allowed.setdefault(lba+offset//2048,set()).add(24+offset%2048)
changed=[]
with old.open('rb') as a,new.open('rb') as b:
    for lba in range(new.stat().st_size//2352):
        x,y=a.read(2352),b.read(2352)
        if x==y:continue
        check_form1(x);check_form1(y);assert x[:24]==y[:24]
        assert all(x[i]==y[i] or i in allowed.get(lba,set()) for i in range(24,2072)),lba
        changed.append(lba)
result={'bin_sha256':hashlib.sha256(new.read_bytes()).hexdigest().upper(),'changed_sectors':changed,
        'edc_ecc_checks':len(changed)*2,'unexplained_payload_changes':0,'all_extents_sizes_identical':True}
(AN/'disc_delta.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
print('PASS',len(changed),'changed sectors;',len(changed)*2,'EDC/ECC checks')
