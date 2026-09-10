"""Raise the next SC021 choice; preserve V374 card and previous choice fixes."""
import io,json,struct
from pathlib import Path
from zipfile import ZipFile
import build_arc1_v374_card_choice as previous
from verify_arc1_v371_speaker_fixes import uc,m,object_at
ROOT=previous.ROOT;ORIGINAL=previous.ORIGINAL;ORIGINAL_PIN=previous.ORIGINAL_PIN
BASE=previous.OUT;PIN='9A111008955CB29DCC95AC6D6D7D428D2BEE80A1BD04BEE04E2867B0498C7AF3'
OUT=ROOT/'03_output/arc1_v375_next_choice_TEST_ONLY.zip';AN=ROOT/'01_work/analysis/v375_next_choice'
digest=previous.digest;FN=previous.FN;START=0x46f74;END=0x46f91;COMP=0x4547f
STATE=Path('C:/Users/Administrator/.paseo/uploads/upload_26b70828-616f-420a-8e61-d62c2f8519ac/HASH-DE95EE0ADEFCF889_1.sav')

def prepare():
    assert digest(BASE.read_bytes())==PIN and previous.prepare()[0]==BASE.read_bytes()
    with ZipFile(BASE) as z:infos=z.infolist();old={i.filename:z.read(i) for i in infos};comment=z.comment
    d=old[FN];assert d[COMP]==10 and d[START+12:START+14]==b'\xe6\x01'
    assert [i for i in range(0x43000,len(d)-1) if d[i:i+2]==b'\xe2\x89']==[START]
    new=bytearray(d);new[COMP]=12
    assert sum(a!=b for a,b in zip(d,new))==1 and new[START:]==d[START:]
    buf=io.BytesIO()
    with ZipFile(buf,'w') as z:
        z.comment=comment
        for info in infos:z.writestr(info,bytes(new) if info.filename==FN else old[info.filename])
    return buf.getvalue(),dict(zip_sha256=digest(buf.getvalue()),static_pass=True,changed_bytes=1,
        changed_members=[FN],writes=[dict(file=FN,offset=COMP,before='0a',after='0c',reason='Skip redundant E601 after exact-width question automatic wrap')])

def verify(blob):
    with ZipFile(BASE) as z:old={n:z.read(n) for n in z.namelist()}
    with ZipFile(io.BytesIO(blob)) as z:new={n:z.read(n) for n in z.namelist()}
    assert digest(STATE.read_bytes())=='8ECAFDB7C7F9256B00F07D7E59E71D031825456F7A4ECD886DD6212BF73F404B'
    ram,*_=previous.load(STATE,old['PSX.EXE']);origin=struct.unpack_from('<4h',ram,0x1f9d44+0x1e)
    assert origin==(94,32,180,208)
    anchor=old[FN][0x43000:0x48000];at=ram.find(anchor);assert at>=0 and ram.find(anchor,at+1)<0
    bias=at-0x43000;source=0x80000000+bias+START
    before,bp=previous.render(ram,source,origin);captured,cp=object_at(ram,0x1f9d44,{'physical_chars':{}})
    xy=lambda ps:[(p['x'],p['y']) for p in ps]
    assert xy(bp)==xy(cp) and before['source_pointer']==captured['source_pointer']
    copy=bytearray(ram);copy[bias+COMP]=new[FN][COMP]
    after,ap=previous.render(copy,source,origin)
    assert after['source_pointer']==before['source_pointer'] and len(ap)==len(bp)==27
    assert xy(ap[:14])==xy(bp[:14])
    assert xy(ap[14:])==[(p['x'],p['y']-16) for p in bp[14:]],xy(ap)
    assert sorted(set(p['y'] for p in ap))==[32,48,64]
    assert old[FN][END+3:END+17]==bytes.fromhex('2100060004000500020000000100')
    cursors=[]
    for selected in (0,1):
        vm=uc.Uc(uc.UC_ARCH_MIPS,uc.UC_MODE_MIPS32|uc.UC_MODE_LITTLE_ENDIAN)
        vm.mem_map(0,0x200000);vm.mem_write(0,ram)
        vm.reg_write(m.UC_MIPS_REG_S1,0x801f9d44);vm.reg_write(m.UC_MIPS_REG_A0,selected)
        def stop(machine,address,size,data):
            if address==0x8015a728:machine.emu_stop()
        vm.hook_add(uc.UC_HOOK_CODE,stop);vm.emu_start(0x8015a6e0,0,count=1000)
        assert vm.reg_read(m.UC_MIPS_REG_PC)==0x8015a728
        cursor=(vm.reg_read(m.UC_MIPS_REG_A0),vm.reg_read(m.UC_MIPS_REG_A1)+2)
        assert cursor==(108,50+16*selected);cursors.append(cursor)
    regression=previous.verify(blob)
    return dict(before=xy(bp),after=xy(ap),cursor_top=cursors,end=after['source_pointer'],
                v374_regression=regression,runtime_verified=False)

if __name__=='__main__':
    blob,r=prepare();assert prepare()[0]==blob;r['cpu']=verify(blob)
    AN.mkdir(parents=True,exist_ok=True)
    if OUT.exists():assert OUT.read_bytes()==blob
    else:OUT.write_bytes(blob)
    (AN/'build_report.json').write_text(json.dumps(r,ensure_ascii=False,indent=2),encoding='utf-8')
    print(r['zip_sha256']);print(r['cpu']['after']);print(r['cpu']['cursor_top'])
