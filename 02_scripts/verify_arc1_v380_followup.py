"""Captured text and genuine frame-step E4 counter verification."""
import io,json,struct
from pathlib import Path
from zipfile import ZipFile
import build_arc1_v380_followup as b
from audit_arc1_9118_runtime import load
from verify_arc1_v379_spirit_reports import render,uc,m,object_at,reflow

def timed(ram,at,origin,header):
    vm=uc.Uc(uc.UC_ARCH_MIPS,uc.UC_MODE_MIPS32|uc.UC_MODE_LITTLE_ENDIAN);vm.mem_map(0,0x200000);vm.mem_write(0,bytes(ram))
    events=[];frame=0
    def hook(machine,pc,size,user):
        if pc==0x80060000:machine.emu_stop()
        if pc==0x8016bbe4:
            source=struct.unpack('<I',machine.mem_read(header+0x14,4))[0]
            raw=bytes(machine.mem_read(source&0x1fffff,2))
            if raw[0]==0xe4:events.append(dict(parameter=raw[1],ticks=0,start_frame=frame))
        if pc==0x8016bde0:
            assert events;events[-1]['ticks']+=1
    vm.hook_add(uc.UC_HOOK_CODE,hook)
    def run(pc,**regs):
        vm.reg_write(m.UC_MIPS_REG_SP,0x80040000);vm.reg_write(m.UC_MIPS_REG_RA,0x80060000)
        for k,v in regs.items():vm.reg_write(getattr(m,'UC_MIPS_REG_'+k.upper()),v)
        vm.emu_start(pc,0,count=400000);assert vm.reg_read(m.UC_MIPS_REG_PC)==0x80060000
    vm.mem_write(0x40010,struct.pack('<II',0,0x80000000+header))
    run(0x8016b880,a0=origin[0],a1=origin[1],a2=origin[2],a3=origin[3])
    run(0x8016bab0,a0=0x800cf000+at,a1=0x80000000+header)
    for frame in range(4000):
        run(0x8016bb10,a0=0x80000000+header)
        if vm.mem_read(header+0x1c,1)==b'\0':break
    else:raise AssertionError('Text never completed')
    for e in events:assert e['ticks']==e['parameter']-1,e
    return dict(events=events,frames=frame+1,end=hex(struct.unpack('<I',vm.mem_read(header+0x14,4))[0]))

def verify(blob):
    old=b.b.members(b.BASE);original=b.b.members(b.ORIGINAL)
    with ZipFile(io.BytesIO(blob)) as z:new={n:z.read(n) for n in z.namelist()}
    states=json.loads((b.AN/'states.json').read_text(encoding='utf-8'))
    table,_=b.b.encoder(new['PSX.EXE']);chars={b.b.codec._resolve_index(new['PSX.EXE'],t):c for c,t in table.items()}
    from build_arc1_v336_ui_text_native_damage_repair import runtime_damage_target
    chars.update({runtime_damage_target(i):c for i,c in list(chars.items()) if i is not None and 168<=i<=170})
    def lines(ps):
        out={}
        for p in ps:out[p['y']]=out.get(p['y'],'')+chars.get(p['physical_index'],'<?>')
        return out
    xy=lambda ps:[(p['x'],p['y'],p['u'],p['v'],p['clut']) for p in ps]
    results=[];waits=[]
    for s in states:
        path=Path(s['path']);assert b.digest(path.read_bytes())==s['sha256']
        ram,*_=load(path,old['PSX.EXE']);slot=s['slot'];copy=bytearray(ram)
        if slot==6:
            header=0x1f0e18;pointer=struct.unpack_from('<I',old['PSX.EXE'],0x82348)[0]
            def help_render(data):
                vm=uc.Uc(uc.UC_ARCH_MIPS,uc.UC_MODE_MIPS32|uc.UC_MODE_LITTLE_ENDIAN);vm.mem_map(0,0x200000);vm.mem_write(0,bytes(data))
                vm.reg_write(m.UC_MIPS_REG_SP,0x80040000);vm.reg_write(m.UC_MIPS_REG_RA,0x80060000);vm.reg_write(m.UC_MIPS_REG_A0,pointer)
                vm.emu_start(0x8016c794,0x80060000,count=400000);assert vm.reg_read(m.UC_MIPS_REG_PC)==0x80060000
                return object_at(bytes(vm.mem_read(0,0x200000)),header,{'physical_chars':{}})
            before,bp=help_render(ram);captured,cp=object_at(ram,header,{'physical_chars':{}});assert xy(bp)==xy(cp)
            for h in b.b.previous.hunks(old['PSX.EXE'],new['PSX.EXE']):
                p=0x11a800+h['at'];raw=bytes.fromhex(h['after']);copy[p:p+len(raw)]=raw
            after,ap=help_render(copy);text=lines(ap);assert list(text.values())==[b.UI],text
        else:
            obj=next(o for o in s['objects'] if o['hits']);r=obj['hits'][0];fn=r['file'];at=r['offset'];length=r['length'];header=obj['header']
            assert ram[0xcf000+at:0xcf000+at+length]==old[fn][at:at+length]
            for h in b.b.previous.hunks(old[fn],new[fn]):
                p=h['at'];a=bytes.fromhex(h['before']);z=bytes.fromhex(h['after'])
                assert copy[0xcf000+p:0xcf000+p+len(a)]==a,(slot,hex(p))
                copy[0xcf000+p:0xcf000+p+len(z)]=z
            origin=struct.unpack_from('<4h',ram,header+0x1e)
            before,bp=render(ram,0x800cf000+at,origin,header);captured,cp=object_at(ram,header,{'physical_chars':{}})
            assert xy(bp)==xy(cp) and before['source_pointer']==captured['source_pointer']
            after,ap=render(copy,0x800cf000+at,origin,header);text=lines(ap)
            assert after['source_pointer']==before['source_pointer'] and len(text)<=4,(slot,text)
            if r['row'] in b.PAUSES:
                ref=bytearray(ram);ref[0xcf000+at:0xcf000+at+length+2]=original[fn][at:at+length+2]
                a=timed(ram,at,origin,header);z=timed(copy,at,origin,header);o=timed(ref,at,origin,header)
                assert a['events']==[] and [(e['parameter'],e['ticks']) for e in z['events']]==[(e['parameter'],e['ticks']) for e in o['events']]
                assert a['end']==z['end']==o['end']
                waits.append(dict(row=r['row'],before=a,after=z,original=o))
        assert all(p['physical_index'] in chars for p in ap),(slot,text)
        results.append(dict(slot=slot,before=lines(bp),after=text,capture_exact=True,source_end=after['source_pointer']))
    return dict(captures=results,waits=waits,runtime_verified=False,scope='Six captured renderer replays; genuine BB10 frame-step E4 counters on original/current/fixed dialogue. GPU/input pending.')

if __name__=='__main__':
    blob,_=b.prepare();r=verify(blob);(b.AN/'capture_cpu.json').write_text(json.dumps(r,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps(r,ensure_ascii=False,indent=2))
