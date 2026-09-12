"""Captured native renderers, cursor reader, and original frame-step delays."""
import io,json,struct
from pathlib import Path
from zipfile import ZipFile
import build_arc1_v382_reports as b
from audit_arc1_9118_runtime import load
from verify_arc1_v379_spirit_reports import render,uc,m,object_at,reflow
from verify_arc1_v380_followup import timed

def verify(blob):
    old=b.b.members(b.BASE);original=b.b.members(b.ORIGINAL)
    with ZipFile(io.BytesIO(blob)) as z:new={n:z.read(n) for n in z.namelist()}
    states=json.loads((b.AN/'states.json').read_text(encoding='utf-8'));rows=b.b.audit.rows(b.ROOT/'05_docs/script_original_full.csv')
    table,_=b.encoder(new['PSX.EXE']);chars={b.b.codec._resolve_index(new['PSX.EXE'],t):c for c,t in table.items()}
    from build_arc1_v336_ui_text_native_damage_repair import runtime_damage_target
    chars.update({runtime_damage_target(i):c for i,c in list(chars.items()) if i is not None and 168<=i<=170});chars[746]=' '
    # Alternate runtime glyph planes are decoded only by exact bitmap identity.
    bitmaps={}
    for i,c in chars.items():
        if i is not None:
            key=tuple(b.b.font.read_plane(new['COMM.IMG'],i))
            if any(key):bitmaps.setdefault(key,set()).add(b.b.codec.ALIASES.get(c,c))
    for i in range(1920):
        if i not in chars:
            candidates=bitmaps.get(tuple(b.b.font.read_plane(new['COMM.IMG'],i)),set())
            if len(candidates)==1:chars[i]=next(iter(candidates))
    def lines(ps):
        out={}
        for p in ps:out[p['y']]=out.get(p['y'],'')+chars.get(p['physical_index'],'<?>')
        return out
    def machine(data):
        vm=uc.Uc(uc.UC_ARCH_MIPS,uc.UC_MODE_MIPS32|uc.UC_MODE_LITTLE_ENDIAN);vm.mem_map(0,0x200000);vm.mem_write(0,bytes(data));return vm
    def run(vm,pc,end=0x80060000,**regs):
        vm.reg_write(m.UC_MIPS_REG_SP,0x80040000);vm.reg_write(m.UC_MIPS_REG_RA,0x80060000)
        for k,v in regs.items():vm.reg_write(getattr(m,'UC_MIPS_REG_'+k.upper()),v)
        def stop(machine,address,size,user):
            if address==end:machine.emu_stop()
        hook=vm.hook_add(uc.UC_HOOK_CODE,stop)
        try:vm.emu_start(pc,0,count=600000)
        finally:vm.hook_del(hook)
        assert vm.reg_read(m.UC_MIPS_REG_PC)==end
    cases=[];waits=[];cursor=None
    xy=lambda ps:[(p['x'],p['y'],p['u'],p['v']) for p in ps]
    for slot,n in [(1,2395),(2,2396),(5,2806),(6,2807),(7,2808),(8,2809),(9,2810),(10,2812)]:
        s=states[slot-1];path=Path(s['path']);assert b.digest(path.read_bytes())==s['sha256']
        ram,*_=load(path,old['PSX.EXE']);capture_ram=ram
        if slot==10:
            # State10 retains the laughter sprites after its script RAM was cleared.
            assert not any(ram[0x1169de:0x116a03])
            ram,*_=load(Path(states[8]['path']),old['PSX.EXE'])
        r=rows[n-1];fn=r['source file'];at=int(r['byte offset'],0);length=len(bytes.fromhex(r['raw bytes as hex']))
        copy=bytearray(ram);assert ram[0xcf000+at:0xcf000+at+length]==old[fn][at:at+length]
        for h in b.b.previous.hunks(old[fn],new[fn]):
            p=h['at'];raw=bytes.fromhex(h['after']);assert copy[0xcf000+p:0xcf000+p+len(raw)]==bytes.fromhex(h['before'])
            copy[0xcf000+p:0xcf000+p+len(raw)]=raw
        header=0x1f9d44;origin=struct.unpack_from('<4h',ram,header+0x1e)
        before,bp=render(ram,0x800cf000+at,origin,header);captured,cp=object_at(capture_ram,header,{'physical_chars':{}})
        # Auto scenes may be captured mid-line. Compare the already emitted prefix.
        assert xy(bp)[:len(cp)]==xy(cp),(slot,'captured prefix mismatch')
        after,ap=render(copy,0x800cf000+at,origin,header);text=lines(ap)
        assert after['source_pointer']==before['source_pointer'] and len(text)<=4,(slot,text)
        assert all(p['physical_index'] in chars for p in ap),(slot,text)
        if n in b.TEXT:assert reflow(''.join(text.values()))==reflow(b.TEXT[n])
        if n in b.PAUSES:
            assert reflow(''.join(text.values()))==reflow(''.join(b.PAUSES[n])),(n,text)
            ref=bytearray(ram);ref[0xcf000+at:0xcf000+at+length+2]=original[fn][at:at+length+2]
            o=timed(ref,at,origin,header);a=timed(ram,at,origin,header);z=timed(copy,at,origin,header)
            assert a['events']==[]
            assert [(e['parameter'],e['ticks']) for e in o['events']]==[(e['parameter'],e['ticks']) for e in z['events']]
            assert o['end']==a['end']==z['end'];waits.append(dict(row=n,original=o,before=a,after=z))
        if slot==2:
            assert sorted(text)==[32,48,64],text
            event=(at+length+3)&~1;base=struct.unpack_from('<I',ram,0x1b1acc)[0];start=(0x800cf000+event+2-base)//2
            vm=machine(copy);vm.mem_write(0x1fe2b4,struct.pack('<H',start));run(vm,0x8015c48c)
            params=struct.unpack('<4h',vm.mem_read(0x1fe2ba,8));assert params==(5,2,0,1)
            assert struct.unpack('<H',vm.mem_read(0x1fe2b4,2))[0]==start+6
            tops=[]
            for selected in (0,1):
                run(vm,0x8015a6e0,0x8015a728,s1=0x801f9d44,a0=selected)
                top=[vm.reg_read(m.UC_MIPS_REG_A0),vm.reg_read(m.UC_MIPS_REG_A1)+2]
                assert top[1]==50+16*selected and top[1]-2 in text;tops.append(top)
            cursor=dict(params=params,tops=tops)
        cases.append(dict(slot=slot,row=n,before=lines(bp),after=text,captured_prefix_exact=True,fixture='state9 with state10 retained sprites' if slot==10 else 'own capture',end=after['source_pointer']))
    # The intervening laughter (#2811) is not captured: same scene synthetic load.
    n=2811;r=rows[n-1];at=int(r['byte offset'],0);length=len(bytes.fromhex(r['raw bytes as hex']))
    variants=[]
    for data in [original[fn],old[fn],new[fn]]:
        fixture=bytearray(ram)
        for a,z in [(0x4200,0x5000),(0x45000,0x47780),(at,at+length+2)]:fixture[0xcf000+a:0xcf000+z]=data[a:z]
        variants.append(timed(fixture,at,origin,header))
    o,a,z=variants;assert [(e['parameter'],e['ticks']) for e in o['events']]==[(e['parameter'],e['ticks']) for e in z['events']] and a['events']==[]
    waits.append(dict(row=n,original=o,before=a,after=z,synthetic=True))
    # Item description uses its genuine equipment description helper.
    s=states[2];assert b.digest(Path(s['path']).read_bytes())==s['sha256'];ram,*_=load(Path(s['path']),old['PSX.EXE']);results=[]
    for exe in [old['PSX.EXE'],new['PSX.EXE']]:
        fixture=bytearray(ram)
        for h in b.b.previous.hunks(old['PSX.EXE'],exe):
            p=h['at'];raw=bytes.fromhex(h['after']);fixture[0x11a800+p:0x11a800+p+len(raw)]=raw
        address=struct.unpack_from('<I',exe,0x80b50)[0]
        previous_raw=b.b.storage.string_at(old['PSX.EXE'],address)+b'\0'
        assert ram[address&0x1fffff:(address&0x1fffff)+len(previous_raw)]==previous_raw
        raw=b.b.storage.string_at(exe,address)+b'\0';fixture[address&0x1fffff:(address&0x1fffff)+len(raw)]=raw
        vm=machine(fixture);run(vm,0x8016c760,a0=struct.unpack_from('<I',exe,0x80b50)[0]);results.append(object_at(bytes(vm.mem_read(0,0x200000)),0x1f031c,{'physical_chars':{}}))
    cap,cp=object_at(ram,0x1f031c,{'physical_chars':{}});assert xy(results[0][1])==xy(cp)
    assert list(lines(results[1][1]).values())==b.UI.split('|'),lines(results[1][1])
    census=[]
    for n in range(2806,2813):
        r=rows[n-1];at=int(r['byte offset'],0);raw=bytes.fromhex(r['raw bytes as hex'])
        expected=[t.hex() for t in b.b.codec.tokens(raw) if t[0]==0xe4]
        actual=[t.hex() for t in b.b.previous.read_tokens(new['F/SF051.DAT'],at,len(raw)) if t[0]==0xe4]
        assert expected==actual;census.append(dict(row=n,pauses=actual))
    # Voice scene: unchanged original type0/count1 timer instructions after dialogue.
    voice=[]
    for n in range(2338,2361):
        r=rows[n-1];at=int(r['byte offset'],0);length=len(bytes.fromhex(r['raw bytes as hex']));end=(at+length+3)&~1
        assert original['B/SB022.DAT'][at-2:at]==new['B/SB022.DAT'][at-2:at]==b'\x19\0'
        if original['B/SB022.DAT'][end:end+6]==bytes.fromhex('210000000100'):
            assert original['B/SB022.DAT'][end:end+8]==new['B/SB022.DAT'][end:end+8]
            voice.append(dict(row=n,event=hex(end),delay=struct.unpack_from('<H',new['B/SB022.DAT'],end+6)[0]))
    assert len(voice)>=15
    s=states[3];assert b.digest(Path(s['path']).read_bytes())==s['sha256'];ram,*_=load(Path(s['path']),old['PSX.EXE'])
    timers=[]
    for delay in sorted({v['delay'] for v in voice}):
        v=next(v for v in voice if v['delay']==delay);event=int(v['event'],16)
        vm=machine(ram);vm.mem_write(0x1b1acc,struct.pack('<I',0x80116800));vm.mem_write(0x1fe2b4,struct.pack('<H',(event+2-0x47800)//2))
        run(vm,0x8015c48c)
        assert struct.unpack('<hh',vm.mem_read(0x1fe2b8,4))==(0,delay)
        for tick in range(delay):
            run(vm,0x8015a420)
            remaining=struct.unpack('<H',vm.mem_read(0x1fe2ba,2))[0];flags=struct.unpack('<H',vm.mem_read(0x1fe2b6,2))[0]
            assert remaining==delay-tick-1 and bool(flags&2)==(tick<delay-1)
        timers.append(dict(delay=delay,updates_until_resume=delay,requires_input=False))
    return dict(captures=cases,item=dict(before=lines(results[0][1]),after=lines(results[1][1]),capture_exact=True),cursor=cursor,waits=waits,scene_census=census,voice_scene_original_timers=voice,voice_native_timer_proof=timers,runtime_verified=False,scope='Native CPU text/cursor/frame-step checks; no whole-scene GPU/input playback.')

if __name__=='__main__':
    blob,_=b.prepare();r=verify(blob);(b.AN/'capture_cpu.json').write_text(json.dumps(r,ensure_ascii=False,indent=2),encoding='utf-8');print(json.dumps(r,ensure_ascii=False,indent=2))
