"""Restore seven proven arena VM opcodes misclassified as dialogue padding."""
import io,json
from zipfile import ZipFile
import build_arc1_v369_overflow as previous
from audit_arc1_v370_event_abort import TARGETS,main as verify_cpu
ROOT=previous.ROOT;ORIGINAL=previous.ORIGINAL;ORIGINAL_PIN=previous.ORIGINAL_PIN;digest=previous.digest
BASE=previous.OUT;PIN='58692673A78F425A206814B7C7193A69E7FAD41CD2A755E9AF5F13BB429EF69F'
OUT=ROOT/'03_output/arc1_v370_event_restore_TEST_ONLY.zip';AN=ROOT/'01_work/analysis/v370_event_abort'
def prepare():
    assert digest(BASE.read_bytes())==PIN and previous.prepare()[0]==BASE.read_bytes()
    assert digest(ORIGINAL.read_bytes())==ORIGINAL_PIN
    with ZipFile(BASE) as z:infos=z.infolist();old={i.filename:z.read(i) for i in infos};comment=z.comment
    writes=[]
    with ZipFile(ORIGINAL) as z:
        for fn,at in TARGETS.items():
            original=z.read(fn)
            assert original[at-6:at+4]==bytes.fromhex('0b001900fdff0e000000')
            assert old[fn][at-6:at+4]==bytes.fromhex('0b001900fdffa1000000')
            writes.append(dict(file=fn,offset=at,before='a1',after='0e',reason='Restore VM opcode, not dialogue'))
    final=dict(old)
    for w in writes:
        d=bytearray(old[w['file']]);d[w['offset']]=14;final[w['file']]=bytes(d)
    assert [n for n in old if old[n]!=final[n]]==list(TARGETS)
    for n in old:
        assert len(old[n])==len(final[n])
        differences=[i for i,(a,b) in enumerate(zip(old[n],final[n])) if a!=b]
        assert differences==([TARGETS[n]] if n in TARGETS else [])
    buf=io.BytesIO()
    with ZipFile(buf,'w') as z:
        z.comment=comment
        for info in infos:z.writestr(info,final[info.filename])
    report=dict(zip_sha256=digest(buf.getvalue()),baseline_sha256=PIN,writes=writes,
        changed_members=list(TARGETS),static_pass=True,runtime_verified=False,
        scope='VM dispatcher failure reproduced and seven opcodes restored. GPU/full progression pending; V369 overflow fix and Sans preserved.')
    return buf.getvalue(),report
if __name__=='__main__':
    verify_cpu();blob,report=prepare();assert prepare()[0]==blob
    if OUT.exists():assert OUT.read_bytes()==blob
    else:OUT.write_bytes(blob)
    AN.mkdir(exist_ok=True)
    for name in ('build_report.json','verification.json'):
        (AN/name).write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    print(report['zip_sha256'])
