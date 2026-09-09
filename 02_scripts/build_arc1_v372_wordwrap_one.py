"""BLOCKED experimental csv:4 layout: requested three rows fail at 180px.

The assertion intentionally prevents output until the user selects a revised
layout. No E6 inside secondary slots. Not an approved or completed V372 build.
"""
import csv,io,json,struct
from zipfile import ZipFile
import build_arc1_v371_speaker_fixes as previous
from build_arc1_v364_cursor_speaker import stream
from trial_arc1_wordwrap import SAV,SAV_PIN,load,uc,m,object_at
from v354_dialogue_codec import load_v354,tokens
ROOT=previous.ROOT;ORIGINAL=previous.ORIGINAL;ORIGINAL_PIN=previous.ORIGINAL_PIN
digest=previous.digest;BASE=previous.OUT
PIN='2308DAAA0F4E8AFD4B16E03DABD4402E596E1BB6CA0D404F6A3352DF4BCE6021'
OUT=ROOT/'03_output/arc1_v372_wordwrap_one_TEST_ONLY.zip'
AN=ROOT/'01_work/analysis/v372_wordwrap_one'
FN='1/S1011.DAT';START=0x4799e;END=0x479c8;SLOT=0x45480
LINES=['새해가 오면 팔렌시아','성에서 나를 데리러 와.','그게 우리 일족의 규율이야.']

def prepare():
    assert digest(BASE.read_bytes())==PIN and previous.prepare()[0]==BASE.read_bytes()
    with ZipFile(BASE) as z:
        infos=z.infolist();old={i.filename:z.read(i) for i in infos};comment=z.comment
    d=old[FN];before=d[SLOT:SLOT+128]
    assert before[:50].hex()=='de3d2b0ca1463aa1dd6cddb02909a1dd170e25a11e36a1812e20a18821a11541a13d2ea16bdd7a0fa1deefdea6dd01492100'
    assert before[127]==40 and not any(before[50:127])
    assert [i for i in range(len(d)-1) if d[i:i+2]==b'\xe2\x8a']==[START]
    assert d[START:END].hex()=='e28aea0cde44a1dd6cddb0e993e99aa1dd17e9a4e988e601dd61a1e907e94fe942a1e9acdd41dd41dd41'
    assert d[END]==0
    # Preserve original glyph aliases, not a fresh encode of the same text.
    head,middle,tail=before[:14],before[15:29],before[30:49]
    dec=load_v354()[3]
    assert [''.join(dec[t] for t in tokens(p)) for p in (head,middle,tail)]==LINES
    suffix=b'\xe6\x01'+middle+b'\xe6\x01'+tail
    skip=(END-START)-2-len(suffix);assert skip==3
    slot=head+b'\0'*(127-len(head))+bytes([skip])
    inline=b'\xe2\x8a'+b'\xa1'*skip+suffix
    writes=[dict(file=FN,offset=SLOT,before=before.hex(),after=slot.hex(),reason='Unique A9 head only, completion40 to3'),
            dict(file=FN,offset=START,before=d[START:END].hex(),after=inline.hex(),reason='Inline word-boundary E6 and two remaining lines')]
    allowed=set()
    for w in writes:
        a=w['offset'];v=bytes.fromhex(w['after']);prior=bytes.fromhex(w['before'])
        assert len(v)==len(prior) and d[a:a+len(v)]==prior
        region=set(range(a,a+len(v)));assert not region&allowed;allowed|=region
    new=bytearray(d)
    for w in writes:
        a=w['offset'];v=bytes.fromhex(w['after']);new[a:a+len(v)]=v
    new=bytes(new)
    assert len(new)==len(d) and new[END]==0
    assert all(a==b or i in allowed for i,(a,b) in enumerate(zip(d,new)))
    compact=lambda ts:[t for t,_ in ts if t not in (b'\xa1',b'\xe6\x01')]
    assert compact(stream(d,START,END-START))==compact(stream(new,START,END-START))
    records=list(csv.DictReader((ROOT/'05_docs/script_original_full.csv').open(encoding='utf-8-sig')))
    changed=[]
    for row,r in enumerate(records,1):
        if r['source file']!=FN:continue
        at=int(r['byte offset'],16);size=len(bytes.fromhex(r['raw bytes as hex']))
        if [t for t,_ in stream(d,at,size)]!=[t for t,_ in stream(new,at,size)]:changed.append(row)
    assert changed==[4]
    final={**old,FN:new};buf=io.BytesIO()
    with ZipFile(buf,'w') as z:
        z.comment=comment
        for info in infos:z.writestr(info,final[info.filename])
    return buf.getvalue(),dict(zip_sha256=digest(buf.getvalue()),baseline_sha256=PIN,writes=writes,
        changed_members=[FN],changed_rows=changed,changed_bytes=sum(a!=b for a,b in zip(d,new)),
        static_pass=True,runtime_verified=False,scope='Only csv:4 layout; actual scene GPU/cold boot pending')

def verify(blob):
    assert digest(SAV.read_bytes()).lower()==SAV_PIN
    with ZipFile(BASE) as z:old=z.read(FN);arena=z.read('7/S7021.DAT');exe=z.read('PSX.EXE')
    with ZipFile(io.BytesIO(blob)) as z:new=z.read(FN);assert z.read('PSX.EXE')==exe
    ram,*_=load(SAV,exe)
    bank=ram.find(arena[0x45000:0x45100]);assert bank==0x114000 and ram.find(arena[0x45000:0x45100],bank+1)<0
    dec=load_v354()[3];results=[]
    for width in (180,228):
        pair={}
        for label,d in [('before',old),('after',new)]:
            vm=uc.Uc(uc.UC_ARCH_MIPS,uc.UC_MODE_MIPS32|uc.UC_MODE_LITTLE_ENDIAN)
            vm.mem_map(0,0x200000);vm.mem_write(0,ram)
            vm.mem_write(bank+SLOT-0x45000,d[SLOT:SLOT+128])
            vm.mem_write(0x70000,d[START:END+1])
            vm.mem_write(0x40010,struct.pack('<II',0,0x801f9d44))
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
            run(0x8016b880,a0=46,a1=32,a2=width,a3=208)
            run(0x8016b8c8,a0=0x80070000,a1=0x801f9d44)
            s,ps=object_at(bytes(vm.mem_read(0,0x200000)),0x1f9d44,{'physical_chars':{}})
            ts=[t for t,_ in stream(d,START,END-START) if t!=b'\xe6\x01']
            assert len(ts)==len(ps)==s['count'] and len(ps)<=64
            assert int(s['source_pointer'],16)==0x80070000+END-START
            rows={}
            for t,p in zip(ts,ps):rows[p['y']]=rows.get(p['y'],'')+dec[t]
            pair[label]=dict(rows=rows,count=len(ps),source_pointer=s['source_pointer'])
            if label=='after':assert rows=={32+i*16:v for i,v in enumerate(LINES)},(width,rows,[(dec[t],p['x'],p['y']) for t,p in zip(ts,ps)])
        results.append(dict(width=width,**pair))
    return results

if __name__=='__main__':
    blob,r=prepare();assert prepare()[0]==blob;r['cpu']=verify(blob)
    if OUT.exists():assert OUT.read_bytes()==blob
    else:OUT.write_bytes(blob)
    AN.mkdir(parents=True,exist_ok=True)
    for n in ('build_report.json','verification.json'):(AN/n).write_text(json.dumps(r,ensure_ascii=False,indent=2),encoding='utf-8')
    print(r['zip_sha256'],r['changed_bytes']);print(r['cpu'])
