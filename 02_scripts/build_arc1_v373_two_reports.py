"""Two requested V371 reports only; rejected V372 is not an ancestor."""
import csv,io,json,struct
from zipfile import ZipFile
import build_arc1_v371_speaker_fixes as previous
from audit_arc1_v371_two_reports import PATHS
from audit_arc1_9118_runtime import load
from build_arc1_v364_cursor_speaker import stream
from verify_arc1_v371_speaker_fixes import uc,m,object_at
from v354_dialogue_codec import load_v354,encode
ROOT=previous.ROOT;ORIGINAL=previous.ORIGINAL;ORIGINAL_PIN=previous.ORIGINAL_PIN
digest=previous.digest;BASE=previous.OUT
PIN='2308DAAA0F4E8AFD4B16E03DABD4402E596E1BB6CA0D404F6A3352DF4BCE6021'
OUT=ROOT/'03_output/arc1_v373_two_reports_TEST_ONLY.zip'
AN=ROOT/'01_work/analysis/v373_two_reports'
TARGETS=[(2143,'7/S7031.DAT',293048,293099),(1889,'7/S7021.DAT',298774,298801)]

def prepare():
    assert digest(BASE.read_bytes())==PIN and previous.prepare()[0]==BASE.read_bytes()
    with ZipFile(BASE) as z:infos=z.infolist();old={i.filename:z.read(i) for i in infos};comment=z.comment
    polite,missing=encode('맞습니까?',load_v354()[2],True)
    assert not missing and len(polite)==6
    writes=[dict(file='7/S7031.DAT',offset=293054,before='e601',after='a1a1',reason='Remove speaker-only row; preserve normal automatic wrapping'),
            dict(file='7/S7021.DAT',offset=298774,before='ddb11edd03a1a1a1',after=(polite+b'\xa1'*2).hex(),reason='Reported clerk confirmation in polite register; choices untouched')]
    final={n:bytearray(d) for n,d in old.items()};allowed={n:set() for n in old}
    for w in writes:
        n,a=w['file'],w['offset'];v=bytes.fromhex(w['after']);prior=bytes.fromhex(w['before'])
        assert len(v)==len(prior) and old[n][a:a+len(v)]==prior
        region=set(range(a,a+len(v)));assert not region&allowed[n];allowed[n]|=region
    for w in writes:
        n,a=w['file'],w['offset'];v=bytes.fromhex(w['after']);final[n][a:a+len(v)]=v
    final={n:bytes(d) for n,d in final.items()}
    for n in old:
        assert len(old[n])==len(final[n])
        assert all(a==b or i in allowed[n] for i,(a,b) in enumerate(zip(old[n],final[n])))
    corpus=list(csv.DictReader((ROOT/'05_docs/script_original_full.csv').open(encoding='utf-8-sig')))
    changed=[]
    for i,r in enumerate(corpus,1):
        n=r['source file']
        if n not in old:continue
        a=int(r['byte offset'],16);size=len(bytes.fromhex(r['raw bytes as hex']))
        if [t for t,_ in stream(old[n],a,size)]!=[t for t,_ in stream(final[n],a,size)]:changed.append(i)
    assert changed==[1889,2143]
    for row,n,a,e in TARGETS:
        assert old[n][e]==final[n][e]==0
        before=[t for t,_ in stream(old[n],a,e-a)];after=[t for t,_ in stream(final[n],a,e-a)]
        controls=lambda ts:[t for t in ts if t[0] in (0xe4,0xe5,0xe7)]
        assert controls(before)==controls(after)
        if row==2143:
            compact=lambda ts:[t for t in ts if t not in (b'\xa1',b'\xe6\x01')]
            assert compact(before)==compact(after)
    assert final['1/S1011.DAT']==old['1/S1011.DAT']
    buf=io.BytesIO()
    with ZipFile(buf,'w') as z:
        z.comment=comment
        for info in infos:z.writestr(info,final[info.filename])
    return buf.getvalue(),dict(zip_sha256=digest(buf.getvalue()),baseline_sha256=PIN,writes=writes,
        changed_rows=changed,changed_members=[n for n in old if old[n]!=final[n]],
        changed_bytes=sum(sum(a!=b for a,b in zip(old[n],final[n])) for n in old),
        static_pass=True,runtime_verified=False,scope='Two reported entries only; V372 rejected. Other 13 confirmation strings and omitted names not fixed.')

def render(ram,d,changed,a,e):
    # Confirmation bodies repeat verbatim; identify the surrounding event
    # context instead of assuming the text alone is unique in loaded RAM.
    signature=d[a-128:e+128]
    context=ram.find(signature);assert context>=0 and ram.find(signature,context+1)<0
    location=context+128
    copy=bytearray(ram);copy[location:location+e-a+1]=changed[a:e+1]
    vm=uc.Uc(uc.UC_ARCH_MIPS,uc.UC_MODE_MIPS32|uc.UC_MODE_LITTLE_ENDIAN)
    vm.mem_map(0,0x200000);vm.mem_write(0,bytes(copy))
    def run(pc,**regs):
        vm.reg_write(m.UC_MIPS_REG_SP,0x80040000);vm.reg_write(m.UC_MIPS_REG_RA,0x80060000)
        for k,v in regs.items():vm.reg_write(getattr(m,'UC_MIPS_REG_'+k.upper()),v)
        hit=[]
        def stop(machine,address,size,data):
            if address==0x80060000:hit.append(address);machine.emu_stop()
        hook=vm.hook_add(uc.UC_HOOK_CODE,stop)
        try:vm.emu_start(pc,0,count=400000)
        finally:vm.hook_del(hook)
        assert hit
    origin=struct.unpack_from('<4h',ram,0x1f9d44+0x1e);assert origin==(46,32,228,208)
    vm.mem_write(0x40010,struct.pack('<II',0,0x801f9d44))
    run(0x8016b880,a0=origin[0],a1=origin[1],a2=origin[2],a3=origin[3])
    run(0x8016b8c8,a0=0x80000000+location,a1=0x801f9d44)
    state,ps=object_at(bytes(vm.mem_read(0,0x200000)),0x1f9d44,{'physical_chars':{}})
    dec=load_v354()[3];display=[]
    for t,_ in stream(changed,a,e-a):
        if t==b'\xe5\x03':display.extend([' ',' '])
        elif t in dec:display.append(dec[t])
    # The captured choice object includes a final non-glyph packet after
    # consuming the NUL. Preserve and verify it, do not count it as prose.
    if a==298774:
        assert len(ps)==len(display)+1 and ps[-1]['physical_index'] is None
        assert int(state['source_pointer'],16)==0x80000000+location+e-a+1
        display.append('')
    assert len(display)==len(ps)==state['count'] and len(ps)<=64,(a,len(display),len(ps),state,display)
    rows={}
    for char,p in zip(display,ps):rows[p['y']]=rows.get(p['y'],'')+char
    return dict(state=state,rows=rows,positions=[(p['x'],p['y']) for p in ps])

def verify(blob):
    with ZipFile(BASE) as z:old={n:z.read(n) for n in z.namelist()}
    with ZipFile(io.BytesIO(blob)) as z:new={n:z.read(n) for n in z.namelist()}
    results=[]
    for path,(row,n,a,e) in zip(PATHS,TARGETS):
        ram,*_=load(path,old['PSX.EXE'])
        before=render(ram,old[n],old[n],a,e)
        captured,ps=object_at(ram,0x1f9d44,{'physical_chars':{}})
        assert before['positions']==[(p['x'],p['y']) for p in ps]
        assert before['state']['source_pointer']==captured['source_pointer']
        after=render(ram,old[n],new[n],a,e)
        assert after['state']['source_pointer']==before['state']['source_pointer']
        assert max(after['rows'])<=80
        if row==2143:
            assert after['rows'][32].startswith('로크톨:  축하합니다')
            assert sorted(before['rows'])==[32,48,64,80,96]
            assert sorted(after['rows'])==[32,48,64,80]
        else:
            assert after['rows'][32].strip()=='맞습니까?'
            assert {y:s for y,s in before['rows'].items() if y>=48}=={y:s for y,s in after['rows'].items() if y>=48}
            assert [p for p in before['positions'] if p[1]>=48]==[p for p in after['positions'] if p[1]>=48]
        results.append(dict(row=row,before=before,after=after))
    return results

if __name__=='__main__':
    blob,r=prepare();assert prepare()[0]==blob;r['cpu']=verify(blob)
    if OUT.exists():assert OUT.read_bytes()==blob
    else:OUT.write_bytes(blob)
    AN.mkdir(parents=True,exist_ok=True)
    for n in ('build_report.json','verification.json'):(AN/n).write_text(json.dumps(r,ensure_ascii=False,indent=2),encoding='utf-8')
    print(r['zip_sha256'],r['changed_bytes']);print([(v['row'],v['after']['rows']) for v in r['cpu']])
