"""Native renderer replay on both live dialogue headers; no savestate writes."""
import io,json,struct
from pathlib import Path
from zipfile import ZipFile
import build_arc1_v379_spirit_reports as b
from audit_arc1_9118_runtime import load
from verify_arc1_v371_speaker_fixes import uc,m,object_at

def render(ram,source,origin,header):
    vm=uc.Uc(uc.UC_ARCH_MIPS,uc.UC_MODE_MIPS32|uc.UC_MODE_LITTLE_ENDIAN)
    vm.mem_map(0,0x200000);vm.mem_write(0,bytes(ram))
    def run(pc,**regs):
        vm.reg_write(m.UC_MIPS_REG_SP,0x80040000);vm.reg_write(m.UC_MIPS_REG_RA,0x80060000)
        for k,v in regs.items():vm.reg_write(getattr(m,'UC_MIPS_REG_'+k.upper()),v)
        hit=[]
        def stop(machine,a,size,user):
            if a==0x80060000:hit.append(a);machine.emu_stop()
        h=vm.hook_add(uc.UC_HOOK_CODE,stop)
        try:vm.emu_start(pc,0,count=600000)
        finally:vm.hook_del(h)
        assert hit,(hex(pc),hex(vm.reg_read(m.UC_MIPS_REG_PC)))
    vm.mem_write(0x40010,struct.pack('<II',0,0x80000000+header))
    run(0x8016b880,a0=origin[0],a1=origin[1],a2=origin[2],a3=origin[3])
    run(0x8016b8c8,a0=source,a1=0x80000000+header)
    return object_at(bytes(vm.mem_read(0,0x200000)),header,{'physical_chars':{}})

def verify(blob):
    # All new captures contain V377 memory. Apply verified V377->V379 DAT deltas.
    old=b.b.members(b.previous.BASE)
    with ZipFile(io.BytesIO(blob)) as z:new={n:z.read(n) for n in z.namelist()}
    ev=json.loads((b.AN/'states.json').read_text(encoding='utf-8'))
    paths={r['slot']:Path(r['path']) for r in ev}
    for r in ev:assert b.digest(Path(r['path']).read_bytes())==r['sha256']
    table,_=b.b.encoder(new['PSX.EXE']);chars={b.b.codec._resolve_index(new['PSX.EXE'],t):c for c,t in table.items()}
    from build_arc1_v336_ui_text_native_damage_repair import runtime_damage_target
    chars.update({runtime_damage_target(i):c for i,c in list(chars.items()) if i is not None and 168<=i<=170})
    chars={i:b.b.codec.ALIASES.get(c,c) for i,c in chars.items()};chars[746]=' '
    def lines(ps):
        out={}
        for p in ps:out[p['y']]=out.get(p['y'],'')+chars.get(p['physical_index'],'<?>')
        return out
    xy=lambda ps:[(p['x'],p['y'],p['physical_index']) for p in ps]
    rows=b.b.audit.rows(b.ROOT/'05_docs/script_original_full.csv');cases=[]
    for slot,n in [(1,505),(2,None),(3,251),(4,2767),(5,2768),(6,None),(7,2781),(8,640),(9,2784),(10,2792)]:
        if n:
            r=rows[n-1];fn=r['source file'];at=int(r['byte offset'],0);length=len(bytes.fromhex(r['raw bytes as hex']))
        else:fn,at,length=('22/S205C.DAT',0x481f8,6) if slot==2 else ('9/S9021.DAT',0x486a2,10)
        header=0x1f9d44 if slot==1 else 0x1f9d88
        ram,*_=load(paths[slot],old['PSX.EXE']);copy=bytearray(ram)
        assert ram[0xcf000+at:0xcf000+at+length+1]==old[fn][at:at+length+1],slot
        for h in b.b.previous.hunks(old[fn],new[fn]):
            p=h['at'];a=bytes.fromhex(h['before']);z=bytes.fromhex(h['after'])
            assert copy[0xcf000+p:0xcf000+p+len(a)]==a,(slot,hex(p))
            copy[0xcf000+p:0xcf000+p+len(z)]=z
        origin=struct.unpack_from('<4h',ram,header+0x1e)
        before,bp=render(ram,0x800cf000+at,origin,header);captured,cp=object_at(ram,header,{'physical_chars':{}})
        assert before['source_pointer']==captured['source_pointer'] and xy(bp)==xy(cp),(slot,before,captured,lines(bp),lines(cp))
        after,ap=render(copy,0x800cf000+at,origin,header);text=lines(ap)
        assert after['source_pointer']==before['source_pointer'],(slot,after,before)
        assert after['count']<=64 and all(p['physical_index'] in chars for p in ap),(slot,text)
        assert all(origin[0]<=p['x']<origin[0]+origin[2] for p in ap),(slot,origin,text)
        assert len(text)<=4,(slot,origin,text)
        if n in b.JOIN:assert ':' in text[min(text)] and text[min(text)].split(':',1)[1].strip(),(slot,text)
        cases.append(dict(slot=slot,row=n,file=fn,offset=at,origin=origin,capture_exact=True,before=lines(bp),after=text,source_end=after['source_pointer']))
    # All remaining edits: same native renderer, narrow captured portrait window.
    # These are synthetic DAT loads, explicitly not capture/event/GPU proofs.
    records=[];decode=b.b.audit.make_decoder(new['PSX.EXE'])
    for n in sorted((*b.TEXT,*b.JOIN,*b.REPLACE)):
        r=rows[n-1];fn=r['source file'];at=int(r['byte offset'],0);length=len(bytes.fromhex(r['raw bytes as hex']))
        target=decode(b''.join(b.b.previous.read_tokens(new[fn],at,length)))[0]
        records.append(dict(row=n,file=fn,offset=at,length=length,target=target))
    import extract_story_corpus as extraction
    pristine=b.b.members(b.ORIGINAL)
    for fn,at,target in b.EXTRA:records.append(dict(row=None,file=fn,offset=at,length=extraction.token_end(pristine[fn],at)-at,target=target))
    synthetic=[]
    ram,*_=load(paths[9],old['PSX.EXE'])
    for r in records:
        fn,at,length=r['file'],r['offset'],r['length'];copy=bytearray(ram)
        for a,z in [(0x4200,0x5000),(0x45000,0x47780),(at,at+length+2)]:
            copy[0xcf000+a:0xcf000+z]=new[fn][a:z]
        # Named spirit boxes have 228px; portrait dialogue uses 180px.
        origin=(46,162,228,208) if ':' in r['target'].split('<CTRL:')[0] else (94,162,180,208)
        for c in cases:
            if c['file']==fn and c['offset']==at:origin=tuple(c['origin'])
        after,ps=render(copy,0x800cf000+at,origin,0x1f9d88);text=lines(ps)
        assert after['source_pointer']==f'0x{0x800cf000+at+length:08X}',(r,after)
        assert all(p['physical_index'] in chars for p in ps) and len(text)<=4,(r,text)
        target=reflow(r['target']);got=''.join(''.join(text.values()).split())
        assert got==target,(r,got,target)
        synthetic.append(dict(row=r['row'],file=fn,offset=at,lines=text,source_end=after['source_pointer']))
    return dict(captures=cases,synthetic=synthetic,runtime_verified=False,scope='Ten exact native text replays (slot6 cached prior text), all edits synthetic bounds/glyph replay; GPU/input pending.')

def reflow(text):
    import re
    return ''.join(re.sub(r'<CTRL:[0-9A-F]{4}>|\|','',text).split())

if __name__=='__main__':
    blob,_=b.prepare();r=verify(blob)
    (b.AN/'capture_cpu.json').write_text(json.dumps(r,ensure_ascii=False,indent=2),encoding='utf-8')
    for c in r['captures']:print(c['slot'],c['after'])
