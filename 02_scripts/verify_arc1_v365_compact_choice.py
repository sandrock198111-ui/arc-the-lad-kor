"""Independent byte-envelope, E2/event CPU and cursor alignment checks."""
from pathlib import Path
from zipfile import ZipFile
import sys,struct,json,hashlib
from audit_arc1_9118_runtime import load
from audit_arc1_v363_speaker_cursor import expand
from v354_dialogue_codec import load_v354,tokens
from verify_arc1_v359_slot_recovery import legacy_gate
ROOT=Path(__file__).resolve().parents[1];AN=ROOT/'01_work/analysis/v365_compact_choice'
BASE=ROOT/'03_output/arc1_v364_cursor_speaker_TEST_ONLY.zip'
OUT=ROOT/'03_output/arc1_v365_compact_choice_TEST_ONLY.zip'
sys.path.insert(0,str(ROOT/'01_work/tools/cursor_verify'))
import unicorn as uc
from unicorn import mips_const as m
def main():
    with ZipFile(BASE) as z:old={n:z.read(n) for n in z.namelist()}
    with ZipFile(OUT) as z:new={n:z.read(n) for n in z.namelist()}
    fn='6/S6054.DAT';a,b=old[fn],new[fn]
    allowed=set(range(0x4d80,0x4e00))|{0x4395a,0x4395b,0x43996,0x43997}
    assert old.keys()==new.keys()
    for name in old:
        assert len(old[name])==len(new[name])
        if name!=fn:assert old[name]==new[name]
        else:assert all(x==y or i in allowed for i,(x,y) in enumerate(zip(a,b)))
    assert b[0x4395a:0x4395c]==b'\xe2\xe8' and b[0x43996:0x43998]==b'\x01\0'
    payload=b[0x4d80:0x4dff].split(b'\0')[0]
    _,_,_,dec=load_v354()
    assert ''.join(dec[t] for t in tokens(payload))=='승려: 수행하러 오셨습니까?'
    assert b[0x4dff]==22 and 0x4395a+2+b[0x4dff]==0x43972
    assert b[0x43972:0x43996]==a[0x43972:0x43996]
    expanded=expand(b,0x4395a,46);row=x=0;layout=[]
    for t in expanded:
        if t==b'\xe6\x01':row+=1;x=0;continue
        if t==b'\xe5\x03':x+=28;continue
        assert t[0]<0xe1,t
        width=8 if t==b'\xa1' else 14
        if x+width>=228:row+=1;x=0
        layout.append((row,x,dec[t]));x+=width
    assert sorted(set(r for r,x,c in layout))==[0,1,2]
    assert ''.join(c for r,x,c in layout if r==0)=='승려: 수행하러 오셨습니까?'
    assert [x for r,x,c in layout if r==1][0]==28
    assert [x for r,x,c in layout if r==2][0]==28
    assert len(layout)+4<=64
    with ZipFile(ROOT/'03_output/arc1_v363_dialogue_trial_TEST_ONLY.zip') as z:captured_exe=z.read('PSX.EXE');captured_dat=z.read(fn)
    cases=[]
    for slot in (7,8):
        path=next(Path('C:/Users/Administrator/.paseo/uploads').glob(f'upload_*/HASH-DC42934B1AA4449B_{slot}.sav'))
        ram,_,_,_=load(path,captured_exe)
        assert ram[0xd3200:0xd4000]==captured_dat[0x4200:0x5000]
        assert ram[0x11295a:0x112998]==captured_dat[0x4395a:0x43998]
        vm=uc.Uc(uc.UC_ARCH_MIPS,uc.UC_MODE_MIPS32|uc.UC_MODE_LITTLE_ENDIAN)
        vm.mem_map(0,0x200000);vm.mem_write(0,ram)
        for i,(before,after) in enumerate(zip(captured_exe,new['PSX.EXE'])):
            if before!=after:vm.mem_write((i+0x8011a800)&0x1fffff,bytes([after]))
        # Reproduce only the scene bytes changed in V364/V365, not live globals.
        for i,(before,after) in enumerate(zip(captured_dat,b)):
            if before!=after:vm.mem_write(0xcf000+i,bytes([after]))
        def run(pc,end=0x80060000):
            vm.reg_write(m.UC_MIPS_REG_SP,0x80040000);vm.reg_write(m.UC_MIPS_REG_RA,0x80060000)
            reached=[]
            def stop_at(machine,address,size,user):
                if address==end:reached.append(address);machine.emu_stop()
            hook=vm.hook_add(uc.UC_HOOK_CODE,stop_at)
            vm.emu_start(pc,0,count=10000)
            vm.hook_del(hook)
            assert reached==[end],reached
            assert vm.reg_read(m.UC_MIPS_REG_PC)==end,(hex(pc),hex(end),hex(vm.reg_read(m.UC_MIPS_REG_PC)))
        # Actual unchanged lookup takes disk id minus one.
        vm.reg_write(m.UC_MIPS_REG_A0,0xe7);run(0x8018fcd0)
        ptr=vm.reg_read(m.UC_MIPS_REG_V0);assert ptr==0x800d3d80
        assert bytes(vm.mem_read(ptr&0x1fffff,len(payload)))==payload
        vm.mem_write(0x1f9d58,struct.pack('<I',0x8011295c));vm.reg_write(m.UC_MIPS_REG_S0,0x801f9d44)
        run(0x8018fd28,0x8016be44)
        assert struct.unpack('<I',vm.mem_read(0x1f9d58,4))[0]==0x80112972
        # Event 0x21 reader: type6, four signed halfwords at known scene index.
        assert struct.unpack_from('<I',ram,0x1b1acc)[0]==0x80112800
        vm.mem_write(0x1fe2b4,struct.pack('<H',0xc6));run(0x8015c48c)
        assert struct.unpack('<4h',vm.mem_read(0x1fe2ba,8))==(5,2,0,1)
        assert struct.unpack('<H',vm.mem_read(0x1fe2b4,2))[0]==0xcc
        for selected in (0,1):
            vm.reg_write(m.UC_MIPS_REG_S1,0x801f9d44);vm.reg_write(m.UC_MIPS_REG_A0,selected)
            run(0x8015a6e0,0x8015a728)
            xy=[vm.reg_read(m.UC_MIPS_REG_A0),vm.reg_read(m.UC_MIPS_REG_A1)+2]
            assert xy==[60,50+16*selected],xy
            cases.append(dict(state=slot,selected=selected,cursor_top=xy,text_origin=[74,48+16*selected]))
    before=legacy_gate(BASE);after=legacy_gate(OUT)
    for k,v in after['fail'].items():assert set(v)<=set(before['fail'].get(k,[]))
    report=dict(zip_sha256=hashlib.sha256(OUT.read_bytes()).hexdigest().upper(),static_pass=True,
                cpu_cases=cases,e2_lookup_completion_and_event_reader_pass=True,
                text_rows=[1,2,3],inherited_gate=after,runtime_verified=False,
                limitation='Text wrapping model plus actual E2/event/coordinate CPU; GPU/input/scene re-entry pending.')
    (AN/'verification.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    print('PASS: only one DAT; E2 lookup/completion + event reader + four cursor CPU cases; rows 1/2/3')
if __name__=='__main__':main()
