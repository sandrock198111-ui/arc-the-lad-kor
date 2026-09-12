"""Native renderer, local event reader, cursor and bounds replay for V378."""
import io,json,struct
from pathlib import Path
from zipfile import ZipFile
import build_arc1_v378_followup as b
from audit_arc1_9118_runtime import load
from build_arc1_v374_card_choice import render
from verify_arc1_v371_speaker_fixes import uc,m,object_at

def verify(blob):
    old=b.b.members(b.BASE)
    with ZipFile(io.BytesIO(blob)) as z:new={n:z.read(n) for n in z.namelist()}
    evidence=json.loads((b.AN/'states.json').read_text(encoding='utf-8'))
    paths={r['slot']:Path(r['path']) for r in evidence}
    for r in evidence:assert b.digest(Path(r['path']).read_bytes())==r['sha256']
    table,_=b.b.encoder(new['PSX.EXE']);chars={b.b.codec._resolve_index(new['PSX.EXE'],t):c for c,t in table.items()}
    from build_arc1_v336_ui_text_native_damage_repair import runtime_damage_target
    chars.update({runtime_damage_target(i):c for i,c in list(chars.items()) if i is not None and 168<=i<=170})
    chars={i:b.b.codec.ALIASES.get(c,c) for i,c in chars.items()}
    # E5 03 emits two original indentation packets using blank plane746.
    assert not any(b.b.font.read_plane(new['COMM.IMG'],746));chars[746]=' '
    rows=b.b.audit.rows(b.ROOT/'05_docs/script_original_full.csv');results=[];cursor_results=[]
    def lines(ps):
        out={}
        for p in ps:out[p['y']]=out.get(p['y'],'')+chars.get(p['physical_index'],'<?>')
        return out
    xy=lambda ps:[(p['x'],p['y'],p['physical_index']) for p in ps]
    for slot,n in [(7,2464),(8,2465),(9,2217),(10,2460)]:
        r=rows[n-1];fn=r['source file'];at=int(r['byte offset'],0);length=len(bytes.fromhex(r['raw bytes as hex']));end=at+length
        ram,*_=load(paths[slot],old['PSX.EXE']);assert ram[0xcf000+at:0xcf000+end+1]==old[fn][at:end+1]
        copy=bytearray(ram)
        for h in b.b.previous.hunks(old[fn],new[fn]):
            p=h['at'];a=bytes.fromhex(h['before']);z=bytes.fromhex(h['after'])
            assert copy[0xcf000+p:0xcf000+p+len(a)]==a,(slot,hex(p),'loaded delta mismatch')
            copy[0xcf000+p:0xcf000+p+len(z)]=z
        origin=struct.unpack_from('<4h',ram,0x1f9d62)
        before,bp=render(ram,0x800cf000+at,origin);captured,cp=object_at(ram,0x1f9d44,{'physical_chars':{}})
        assert xy(bp)==xy(cp) and before['source_pointer']==captured['source_pointer'],slot
        after,ap=render(copy,0x800cf000+at,origin);text=lines(ap)
        assert after['source_pointer']==before['source_pointer'] and after['count']<=64
        assert all(p['physical_index'] in chars for p in ap),(slot,[(p['physical_index'],p['u'],p['v'],p['clut']) for p in ap if p['physical_index'] not in chars],text)
        if slot in (7,8):
            assert sorted(text)==[32,48,64],(slot,text)
            assert text[48].strip()=='좋아' and text[64].strip()=='역시 그만둘래',text
        if slot==9:
            assert sorted(text)==[32,48,64] and text[48].startswith('「비단 허리띠」'),text
            assert text[32].strip().endswith('주는') and text[64].strip()=='착용할 수 있습니다.',text
        if slot==10:assert xy(ap)==xy(bp),'Cursor correction changed text'
        results.append(dict(slot=slot,row=n,capture_exact=True,before=lines(bp),after=text,source_end=after['source_pointer'],packets=ap))
        if slot in (7,8,10):
            vm=uc.Uc(uc.UC_ARCH_MIPS,uc.UC_MODE_MIPS32|uc.UC_MODE_LITTLE_ENDIAN);vm.mem_map(0,0x200000);vm.mem_write(0,bytes(copy))
            def run(pc,end=0x80060000,**regs):
                vm.reg_write(m.UC_MIPS_REG_SP,0x80040000);vm.reg_write(m.UC_MIPS_REG_RA,0x80060000)
                for k,v in regs.items():vm.reg_write(getattr(m,'UC_MIPS_REG_'+k.upper()),v)
                hit=[]
                def stop(machine,a,size,user):
                    if a==end:hit.append(a);machine.emu_stop()
                hook=vm.hook_add(uc.UC_HOOK_CODE,stop)
                try:vm.emu_start(pc,0,count=500000)
                finally:vm.hook_del(hook)
                assert hit==[end],(slot,hex(pc),hex(vm.reg_read(m.UC_MIPS_REG_PC)))
            event=(at+length+3)&~1;base=struct.unpack_from('<I',ram,0x1b1acc)[0]
            start_index=(0x800cf000+event+2-base)//2
            vm.mem_write(0x1fe2b4,struct.pack('<H',start_index));run(0x8015c48c)
            params=struct.unpack('<4h',vm.mem_read(0x1fe2ba,8));row=2 if slot==10 else 1
            assert params==(5,2,0,row),params
            assert struct.unpack('<H',vm.mem_read(0x1fe2b4,2))[0]==start_index+6
            tops=[]
            for selected in (0,1):
                run(0x8015a6e0,0x8015a728,s1=0x801f9d44,a0=selected)
                top=[vm.reg_read(m.UC_MIPS_REG_A0),vm.reg_read(m.UC_MIPS_REG_A1)+2]
                assert top==[108,34+16*(row+selected)] and top[1]-2 in text,(slot,top,text)
                tops.append(top)
            navigation=[]
            for selected in (0,1):
                for delta,key in [(-1,0x1000),(1,0x4000)]:
                    vm.mem_write(0x60010,struct.pack('<I',selected));vm.mem_write(0x60024,struct.pack('<I',key))
                    run(0x8015e3d8,0x8015e464,a0=selected,s0=0,s1=0x80060010,s2=0x80060020,s4=0,s5=1)
                    value=vm.reg_read(m.UC_MIPS_REG_A1);assert value==(selected+delta)%2
                    navigation.append([selected,delta,value])
            cursor_results.append(dict(slot=slot,event=event,params=params,tops=tops,navigation=navigation))
    return dict(captures=results,cursors=cursor_results,runtime_verified=False,
        scope='Four exact captured-text CPU replays; actual event type6 reader, six cursor coordinates, twelve decoded-pad bounds cases; GPU/physical input pending.')

if __name__=='__main__':
    blob,_=b.prepare();r=verify(blob);(b.AN/'capture_cpu.json').write_text(json.dumps(r,ensure_ascii=False,indent=2),encoding='utf-8')
    for c in r['captures']:print(c['slot'],c['after'])
    for c in r['cursors']:print('CURSOR',c['slot'],c['tops'])
