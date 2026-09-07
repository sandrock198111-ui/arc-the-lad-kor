"""V369 Sans-derived local #1552 overflow repair. Slot2 stall remains undiagnosed."""
import io,json
from zipfile import ZipFile
from verify_arc1_v368_overflow_trial import candidate,FN,main as cpu_verify
import build_arc1_v368_linebreaks as prior
ROOT=prior.ROOT;ORIGINAL=prior.ORIGINAL;ORIGINAL_PIN=prior.ORIGINAL_PIN;digest=prior.digest
BASE=ROOT/'03_output/arc1_v368_sans_font_TEST_ONLY.zip'
PIN='B2B37F0FB06A5E63BA221A0F2BCE0E9E8B5D341932B9CDA7CDE7FFEF987E1DC6'
OUT=ROOT/'03_output/arc1_v369_overflow_TEST_ONLY.zip';AN=ROOT/'01_work/analysis/v369_overflow'
def prepare():
    assert digest(BASE.read_bytes())==PIN
    with ZipFile(BASE) as z:infos=z.infolist();old={i.filename:z.read(i) for i in infos};comment=z.comment
    d=old[FN];target=candidate(d)
    allowed=set(range(0x48361,0x4836f))|{0x4507f}
    assert len(d)==len(target)
    writes=[]
    for i,(a,b) in enumerate(zip(d,target)):
        if a!=b:
            assert i in allowed
            writes.append(dict(file=FN,offset=i,before=f'{a:02x}',after=f'{b:02x}'))
    final={**old,FN:target};buf=io.BytesIO()
    with ZipFile(buf,'w') as z:
        z.comment=comment
        for info in infos:z.writestr(info,final[info.filename])
    raw=buf.getvalue()
    with ZipFile(io.BytesIO(raw)) as z:
        assert [n for n in old if old[n]!=z.read(n)]==[FN]
        assert all(len(old[n])==len(z.read(n)) for n in old)
    return raw,dict(zip_sha256=digest(raw),baseline_sha256=PIN,writes=writes,
        changed_members=[FN],static_pass=True,runtime_verified=False,
        scope='Slot1 overflow only, Sans retained. Slot2 reported stall NOT fixed or disproved.')
if __name__=='__main__':
    cpu_verify();raw,report=prepare();assert prepare()[0]==raw
    if OUT.exists():assert OUT.read_bytes()==raw
    else:OUT.write_bytes(raw)
    AN.mkdir(exist_ok=True)
    for name in ('build_report.json','verification.json'):
        (AN/name).write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    print(report)
