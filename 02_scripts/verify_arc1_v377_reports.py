"""Replay exact V376 captures and V377 text through the native CPU consumers."""
import json,struct
from pathlib import Path
from zipfile import ZipFile
import io
import build_arc1_v377_user_reports as b
from audit_arc1_9118_runtime import load
from verify_arc1_v371_speaker_fixes import uc,m,object_at
from build_arc1_v374_card_choice import render

def verify(blob):
    old=b.b.members(b.BASE)
    with ZipFile(io.BytesIO(blob)) as z:new={n:z.read(n) for n in z.namelist()}
    states=json.loads((b.AN/'states.json').read_text(encoding='utf-8'))
    paths={r['slot']:Path(r['path']) for r in states}
    for r in states:assert b.digest(Path(r['path']).read_bytes())==r['sha256']
    table,_=b.b.encoder(new['PSX.EXE']);decode=b.b.audit.make_decoder(new['PSX.EXE'])
    physical={b.b.codec._resolve_index(new['PSX.EXE'],t):c for c,t in table.items()}
    def text_rows(ps):
        result={}
        for p in ps:result[p['y']]=result.get(p['y'],'')+physical.get(p['physical_index'],'?')
        return result
    def native(ram,exe,pointer,pc,header):
        copy=bytearray(ram)
        for h in b.b.previous.hunks(old['PSX.EXE'],exe):
            a=h['at'];v=bytes.fromhex(h['after']);copy[0x11a800+a:0x11a800+a+len(v)]=v
        vm=uc.Uc(uc.UC_ARCH_MIPS,uc.UC_MODE_MIPS32|uc.UC_MODE_LITTLE_ENDIAN)
        vm.mem_map(0,0x200000);vm.mem_write(0,bytes(copy))
        vm.reg_write(m.UC_MIPS_REG_SP,0x80040000);vm.reg_write(m.UC_MIPS_REG_RA,0x80060000)
        vm.reg_write(m.UC_MIPS_REG_A0,pointer)
        vm.emu_start(pc,0x80060000,count=500000)
        assert vm.reg_read(m.UC_MIPS_REG_PC)==0x80060000
        return object_at(bytes(vm.mem_read(0,0x200000)),header,{'physical_chars':{}})
    results=[];xy=lambda ps:[(p['x'],p['y'],p['physical_index']) for p in ps]
    for slot,p,pc,header in [(1,0x80b0c,0x8016c760,0x1f031c),(3,0x80b0c,0x8016c760,0x1f031c),
                            (5,0x80ad0,0x8016c760,0x1f031c),(6,0x82354,0x8016c794,0x1f0e18)]:
        ram,*_=load(paths[slot],old['PSX.EXE'])
        captured,cp=object_at(ram,header,{'physical_chars':{}})
        ptr=struct.unpack_from('<I',old['PSX.EXE'],p)[0]
        before,bp=native(ram,old['PSX.EXE'],ptr,pc,header)
        assert xy(bp)==xy(cp),(slot,'capture mismatch',xy(bp),xy(cp))
        assert before['source_pointer']==captured['source_pointer']
        ptr=struct.unpack_from('<I',new['PSX.EXE'],p)[0]
        after,ap=native(ram,new['PSX.EXE'],ptr,pc,header)
        lines=text_rows(ap)
        assert all(p['physical_index'] is not None for p in ap)
        if slot in (1,3):assert list(lines.values())==['적이 거의 확실히','아이템을 떨어뜨림'],lines
        if slot==5:assert list(lines.values())==['레벨업 시 최대 체력','증가량 상승'],lines
        if slot==6:assert list(lines.values())==['스킬을 선택하세요'],lines
        results.append(dict(slot=slot,before=before,after=after,rows=lines,packets=ap,capture_exact=True))
    # State 7 provides a real loaded S8061 block and live renderer globals.
    ram,*_=load(paths[7],old['PSX.EXE']);fn='8/S8061.DAT'
    anchor=old[fn][0x43000:0x48000];location=ram.find(anchor)
    assert location>=0 and ram.find(anchor,location+1)<0
    bias=location-0x43000;origin=struct.unpack_from('<4h',ram,0x1f9d44+0x1e)
    copy=bytearray(ram);copy[location:location+len(anchor)]=new[fn][0x43000:0x48000]
    for n,(_,at,_,_) in b.DAT.items():
        source=0x80000000+bias+at
        before,bp=render(ram,source,origin);after,ap=render(copy,source,origin)
        if n==2275:
            captured,cp=object_at(ram,0x1f9d44,{'physical_chars':{}})
            assert xy(bp)==xy(cp),(n,'capture mismatch')
        rows=text_rows(ap);text=''.join(rows.values())
        assert all(p['physical_index'] in physical for p in ap),(n,rows)
        assert ('본인들이' if n==2275 else '후우진') in text,text
        assert after['source_pointer']==before['source_pointer']
        assert max(rows)<=origin[1]+48 and after['count']<=64,(n,rows)
        results.append(dict(row=n,rows=rows,before=before,after=after,packets=ap,capture_exact=n==2275))
    return dict(cases=results,scope='Native CPU replay of captured UI/dialogue; row 2279 uses state7 loaded-script context. GPU/cold boot pending.')

if __name__=='__main__':
    blob,_=b.prepare();r=verify(blob)
    (b.AN/'capture_cpu.json').write_text(json.dumps(r,ensure_ascii=False,indent=2),encoding='utf-8')
    for c in r['cases']:print(c.get('slot',c.get('row')),c['rows'])
