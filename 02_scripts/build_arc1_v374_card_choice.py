"""V373-derived localized card labels and reported SC021 choice blank-row fix."""
import io,json,struct
from pathlib import Path
from zipfile import ZipFile
import build_arc1_v373_two_reports as previous
from v354_dialogue_codec import load_v354,encode,tokens
from build_arc1_v364_cursor_speaker import stream
from verify_arc1_v371_speaker_fixes import uc,m,object_at
from audit_arc1_9118_runtime import load
ROOT=previous.ROOT;ORIGINAL=previous.ORIGINAL;ORIGINAL_PIN=previous.ORIGINAL_PIN
BASE=previous.OUT;PIN='B311537600B18C8D67D6E9D2C107F65121977741CE3FD82F74B517A31764330A'
OUT=ROOT/'03_output/arc1_v374_card_choice_TEST_ONLY.zip'
AN=ROOT/'01_work/analysis/v374_card_choice';digest=previous.digest
STATE=Path('C:/Users/Administrator/.paseo/uploads/upload_c5a6bf93-df6f-4597-9f10-ae8afb24e28f/HASH-477B29575D051C04_1.sav')
FN='C1/SC021.DAT';START=0x46f0e;END=0x46f2d;SLOT=0x45000+5*128

def prepare():
    assert digest(BASE.read_bytes())==PIN and previous.prepare()[0]==BASE.read_bytes()
    with ZipFile(BASE) as z:infos=z.infolist();old={i.filename:z.read(i) for i in infos};comment=z.comment
    enc=load_v354()[2];writes=[]
    for at,num in [(0x78078,1),(0x78080,2)]:
        raw,missing=encode('카드 '+str(num),enc,True)
        assert not missing and len(raw)==5
        before=bytes([0xbc,0x31,0x95,0x11+num])+bytes(4)
        writes.append(dict(file='PSX.EXE',offset=at,before=before.hex(),after=(raw+bytes(3)).hex(),reason='Translate original card label in its 8-byte slot'))
    # A14-glyph question exactly fills this captured 180px line. The renderer
    # already advances to row two, so consuming the subsequent E601 avoids
    # a second advance. The 2-byte control remains on disk, skipped by E2.
    calls=[at for at in range(0x43000,len(old[FN])-1) if old[FN][at:at+2]==b'\xe2\x86']
    assert calls==[START],calls
    assert old[FN][START+14:START+16]==b'\xe6\x01'
    writes.append(dict(file=FN,offset=SLOT+127,before='0c',after='0e',reason='Skip redundant E601 after automatic wrap at exact right edge'))
    final={n:bytearray(d) for n,d in old.items()};allowed={n:set() for n in old}
    for w in writes:
        n,a=w['file'],w['offset'];before=bytes.fromhex(w['before']);after=bytes.fromhex(w['after'])
        assert len(before)==len(after) and old[n][a:a+len(before)]==before
        span=set(range(a,a+len(after)));assert not span&allowed[n];allowed[n]|=span
        final[n][a:a+len(after)]=after
    final={n:bytes(d) for n,d in final.items()}
    for n in old:
        assert len(old[n])==len(final[n]) and all(x==y or i in allowed[n] for i,(x,y) in enumerate(zip(old[n],final[n])))
    assert final[FN][START:]==old[FN][START:] # body, NUL, event and cursor parameters untouched
    assert final['PSX.EXE'][0x78088:]==old['PSX.EXE'][0x78088:]
    buf=io.BytesIO()
    with ZipFile(buf,'w') as z:
        z.comment=comment
        for info in infos:z.writestr(info,final[info.filename])
    return buf.getvalue(),dict(zip_sha256=digest(buf.getvalue()),writes=writes,static_pass=True,
        changed_members=[n for n in old if final[n]!=old[n]],changed_bytes=sum(sum(x!=y for x,y in zip(old[n],final[n])) for n in old))

def render(ram,source,origin):
    vm=uc.Uc(uc.UC_ARCH_MIPS,uc.UC_MODE_MIPS32|uc.UC_MODE_LITTLE_ENDIAN)
    vm.mem_map(0,0x200000);vm.mem_write(0,bytes(ram))
    def run(pc,**regs):
        vm.reg_write(m.UC_MIPS_REG_SP,0x80040000);vm.reg_write(m.UC_MIPS_REG_RA,0x80060000)
        for k,v in regs.items():vm.reg_write(getattr(m,'UC_MIPS_REG_'+k.upper()),v)
        def stop(machine,address,size,data):
            if address==0x80060000:machine.emu_stop()
        hook=vm.hook_add(uc.UC_HOOK_CODE,stop)
        try:vm.emu_start(pc,0,count=400000)
        finally:vm.hook_del(hook)
        assert vm.reg_read(m.UC_MIPS_REG_PC)==0x80060000
    vm.mem_write(0x40010,struct.pack('<II',0,0x801f9d44))
    run(0x8016b880,a0=origin[0],a1=origin[1],a2=origin[2],a3=origin[3])
    run(0x8016b8c8,a0=source,a1=0x801f9d44)
    return object_at(bytes(vm.mem_read(0,0x200000)),0x1f9d44,{'physical_chars':{}})

def verify(blob):
    with ZipFile(BASE) as z:old={n:z.read(n) for n in z.namelist()}
    with ZipFile(io.BytesIO(blob)) as z:new={n:z.read(n) for n in z.namelist()}
    assert digest(STATE.read_bytes())=='0C1BC09F1E858EFD0E4C9540329B93D99F9452F37EBC08E71D346D3DF6F79BE2'
    ram,*_=load(STATE,old['PSX.EXE']);origin=struct.unpack_from('<4h',ram,0x1f9d44+0x1e)
    assert origin==(94,32,180,208)
    anchor=old[FN][0x43000:0x48000];at=ram.find(anchor);assert at>=0 and ram.find(anchor,at+1)<0
    bias=at-0x43000;source=0x80000000+bias+START
    before,bp=render(ram,source,origin);captured,cp=object_at(ram,0x1f9d44,{'physical_chars':{}})
    xy=lambda ps:[(p['x'],p['y']) for p in ps]
    assert xy(bp)==xy(cp) and before['source_pointer']==captured['source_pointer']
    copy=bytearray(ram);copy[bias+SLOT+127]=new[FN][SLOT+127]
    after,ap=render(copy,source,origin)
    assert after['source_pointer']==before['source_pointer'] and len(ap)==len(bp)==26
    assert xy(ap[:14])==xy(bp[:14])
    assert xy(ap[14:])==[(p['x'],p['y']-16) for p in bp[14:]],xy(ap)
    assert sorted(set(p['y'] for p in ap))==[32,48,64]
    # Local event baseRow already 1: no cursor program/parameters are modified.
    assert old[FN][END+3:END+17]==bytes.fromhex('2100060004000500020000000100')
    cursor=[]
    for selected in (0,1):
        vm=uc.Uc(uc.UC_ARCH_MIPS,uc.UC_MODE_MIPS32|uc.UC_MODE_LITTLE_ENDIAN)
        vm.mem_map(0,0x200000);vm.mem_write(0,ram)
        vm.reg_write(m.UC_MIPS_REG_S1,0x801f9d44);vm.reg_write(m.UC_MIPS_REG_A0,selected)
        def stop_cursor(machine,address,size,data):
            if address==0x8015a728:machine.emu_stop()
        vm.hook_add(uc.UC_HOOK_CODE,stop_cursor)
        vm.emu_start(0x8015a6e0,0,count=1000)
        assert vm.reg_read(m.UC_MIPS_REG_PC)==0x8015a728
        xy_cursor=(vm.reg_read(m.UC_MIPS_REG_A0),vm.reg_read(m.UC_MIPS_REG_A1)+2)
        assert xy_cursor==(108,50+16*selected),xy_cursor
        cursor.append(xy_cursor)
    cards=[]
    exe_ram=bytearray(ram)
    for a in (0x78078,0x78080):exe_ram[0x11a800+a:0x11a800+a+8]=new['PSX.EXE'][a:a+8]
    for i,a in enumerate((0x78078,0x78080)):
        s,ps=render(exe_ram,0x8011a800+a,(56,48+i*16,228,208))
        raw=new['PSX.EXE'][a:a+8].split(b'\0')[0]
        text=''.join(load_v354()[3][t] for t in tokens(raw))
        assert text=='카드 '+str(i+1) and len(ps)==4
        assert all(p['y']==48+i*16 for p in ps)
        cards.append(dict(text=text,xy=xy(ps),glyphs=[p['physical_index'] for p in ps],end=s['source_pointer']))
    return dict(choice_before=xy(bp),choice_after=xy(ap),cursor_top=cursor,end=after['source_pointer'],cards=cards,
                runtime_verified=False,scope='Actual renderer CPU replay; GPU and card I/O pending')

if __name__=='__main__':
    blob,r=prepare();assert prepare()[0]==blob;r['cpu']=verify(blob)
    AN.mkdir(parents=True,exist_ok=True)
    if OUT.exists():assert OUT.read_bytes()==blob
    else:OUT.write_bytes(blob)
    (AN/'build_report.json').write_text(json.dumps(r,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps(r,ensure_ascii=False,indent=2))
