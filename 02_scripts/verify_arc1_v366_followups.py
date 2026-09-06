"""Run final dialogue renderer and choice coordinates on uploaded RAM copies."""
from pathlib import Path
from zipfile import ZipFile
import sys,json,struct,hashlib
from audit_arc1_9118_runtime import load
from analyze_arc1_v320c_savestates import object_at
from audit_arc1_v363_speaker_cursor import expand
from v354_dialogue_codec import load_v354
from verify_arc1_v359_slot_recovery import legacy_gate
ROOT=Path(__file__).resolve().parents[1];AN=ROOT/'01_work/analysis/v366_followups'
BASE=ROOT/'03_output/arc1_v365_compact_choice_TEST_ONLY.zip';OUT=ROOT/'03_output/arc1_v366_followups_TEST_ONLY.zip'
sys.path.insert(0,str(ROOT/'01_work/tools/cursor_verify'))
import unicorn as uc
from unicorn import mips_const as m
def main():
    with ZipFile(BASE) as z:old={n:z.read(n) for n in z.namelist()}
    with ZipFile(OUT) as z:new={n:z.read(n) for n in z.namelist()}
    fn='6/S6054.DAT';a,b=old[fn],new[fn]
    report=json.loads((AN/'build_report.json').read_text(encoding='utf-8'));allowed=set()
    expected_ranges={(0x43a28,25),(0x43a45,6),(0x43a4f,7),(0x43a94,42),(0x43afa,28),(0x43b4e,22),(0x43b70,2),(0x4980,128),(0x45e44,11)}
    assert {(w['offset'],len(bytes.fromhex(w['after']))) for w in report['writes']}==expected_ranges
    for at,size in expected_ranges:allowed.update(range(at,at+size))
    assert old.keys()==new.keys()
    for name in old:
        assert len(old[name])==len(new[name])
        if name!=fn:assert old[name]==new[name]
        else:assert all(x==y or i in allowed for i,(x,y) in enumerate(zip(a,b)))
    _,_,_,dec=load_v354();cases=[];coords=[];navigation=[]
    for n,at,length in [(1,0x43a28,46),(2,0x43a94,42),(3,0x43afa,28),(4,0x43b4e,22),(5,0x45e2e,33)]:
        paths=list(Path('C:/Users/Administrator/.paseo/uploads').glob(f'upload_*/HASH-477B29575D051C04_{n}.sav'))
        p=paths[0];ram,*_=load(p,old['PSX.EXE'])
        assert ram[0xcf000+at:0xcf000+at+length+1]==a[at:at+length+1]
        vm=uc.Uc(uc.UC_ARCH_MIPS,uc.UC_MODE_MIPS32|uc.UC_MODE_LITTLE_ENDIAN);vm.mem_map(0,0x200000);vm.mem_write(0,ram)
        for w in report['writes']:vm.mem_write(0xcf000+w['offset'],bytes.fromhex(w['after']))
        def run(pc,end=0x80060000,**regs):
            vm.reg_write(m.UC_MIPS_REG_SP,0x80040000);vm.reg_write(m.UC_MIPS_REG_RA,0x80060000)
            for key,value in regs.items():vm.reg_write(getattr(m,'UC_MIPS_REG_'+key.upper()),value)
            hit=[]
            def stop(machine,address,size,data):
                if address==end:hit.append(address);machine.emu_stop()
            hook=vm.hook_add(uc.UC_HOOK_CODE,stop);vm.emu_start(pc,0,count=500000);vm.hook_del(hook)
            assert hit==[end],(n,hex(pc),hex(vm.reg_read(m.UC_MIPS_REG_PC)))
        xywh=struct.unpack_from('<4h',ram,0x1f9d62)
        vm.mem_write(0x40010,struct.pack('<II',0,0x801f9d44))
        run(0x8016b880,a0=xywh[0],a1=xywh[1],a2=xywh[2],a3=xywh[3])
        run(0x8016b8c8,a0=0x800cf000+at,a1=0x801f9d44)
        s,ps=object_at(bytes(vm.mem_read(0,0x200000)),0x1f9d44,{'physical_chars':{}})
        ts=expand(b,at,length);expected=sum(2 if t==b'\xe5\x03' else 0 if t==b'\xe6\x01' else 1 for t in ts)
        assert s['count']==expected<=64,(n,s,expected)
        ys=sorted(set(q['y'] for q in ps));assert len(ys)<=4,(n,ys)
        text=''.join('|' if t==b'\xe6\x01' else '[indent]' if t==b'\xe5\x03' else dec[t] for t in ts)
        assert int(s['source_pointer'],16)==0x800cf000+at+length,(n,s)
        if n in (1,4):
            count=2 if n==1 else 4;row=2 if n==1 else 0;col=0 if n==1 else -2
            event=at+length+2
            assert struct.unpack_from('<7h',b,event)==(0x21,6,4,5,count,col,row)
            base=struct.unpack_from('<I',ram,0x1b1acc)[0]
            index=(0x800cf000+event+2-base)//2
            vm.mem_write(0x1fe2b4,struct.pack('<H',index));run(0x8015c48c)
            assert struct.unpack('<4h',vm.mem_read(0x1fe2ba,8))==(5,count,col,row)
            for selected in range(count):
                run(0x8015a6e0,0x8015a728,s1=0x801f9d44,a0=selected)
                x,y=vm.reg_read(m.UC_MIPS_REG_A0),vm.reg_read(m.UC_MIPS_REG_A1)+2
                assert (x,y)==(xywh[0]+14+12*col,xywh[1]+16*(row+selected)+2)
                assert y-2 in ys
                coords.append(dict(state=n,selected=selected,top=[x,y]))
            # Actual vertical navigation/bounds block; inject only the already
            # decoded pad bitfield, stop before its sound callback.
            for selected in range(count):
                for delta,key in [(-1,0x1000),(1,0x4000)]:
                    vm.mem_write(0x60010,struct.pack('<I',selected))
                    vm.mem_write(0x60024,struct.pack('<I',key))
                    run(0x8015e3d8,0x8015e464,a0=selected,s0=0,s1=0x80060010,s2=0x80060020,s4=0,s5=count-1)
                    result=vm.reg_read(m.UC_MIPS_REG_A1)
                    assert result==(selected+delta)%count,(n,selected,delta,result)
                    navigation.append([n,selected,delta,result])
        cases.append(dict(state=n,start=hex(at),count=s['count'],ys=ys,text=text,geometry=xywh))
    assert b[0x4e00:0x4e80]==a[0x4e00:0x4e80] and b[0x45204:0x4520b]==a[0x45204:0x4520b]
    before=legacy_gate(BASE);after=legacy_gate(OUT)
    for k,v in after['fail'].items():assert set(v)<=set(before['fail'].get(k,[])),k
    result=dict(zip_sha256=hashlib.sha256(OUT.read_bytes()).hexdigest().upper(),static_pass=True,
                renderer_cpu=cases,cursor_cpu=coords,navigation_bounds_cpu=navigation,inherited_gate=after,runtime_verified=False,
                limitation='Actual text renderer/event/coordinate and decoded-pad bounds CPU; physical input/GPU/branch outcome pending.')
    (AN/'verification.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
    print('PASS',json.dumps(cases,ensure_ascii=False));print('CURSORS',coords)
if __name__=='__main__':main()
