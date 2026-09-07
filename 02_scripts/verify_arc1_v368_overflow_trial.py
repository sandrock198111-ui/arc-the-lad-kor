"""RAM-copy renderer trial: remove only #1552 padding, preserve end/event address."""
import sys,struct,json
from zipfile import ZipFile
from audit_arc1_v368_followup import ROOT,AN,states
from analyze_arc1_v320c_savestates import object_at
from audit_arc1_v363_speaker_cursor import expand
from v354_dialogue_codec import load_v354
sys.path.insert(0,str(ROOT/'01_work/tools/cursor_verify'))
import unicorn as uc
from unicorn import mips_const as m
FN='6/S6013.DAT';START=0x4834e;END=0x48389
def candidate(d):
    assert d[0x48361:0x4836b]==b'\xa1'*10
    assert d[0x4836b:0x4836f]==b'\xe6\x01\xe2\x81'
    assert d[0x4507f]==26 and d[END]==0
    assert [i for i in range(0x47000,len(d)) if d[i:i+2]==b'\xe2\x81']==[0x4836d]
    result=bytearray(d)
    result[0x48361:0x4836f]=b'\xa1\xe2\x81'+b'\xa1'*11
    result[0x4507f]=37
    return bytes(result)
def render(ram,d):
    copy=bytearray(ram)
    copy[0x11734e:0x11738a]=d[START:END+1]
    copy[0x114000:0x114080]=d[0x45000:0x45080]
    vm=uc.Uc(uc.UC_ARCH_MIPS,uc.UC_MODE_MIPS32|uc.UC_MODE_LITTLE_ENDIAN)
    vm.mem_map(0,0x200000);vm.mem_write(0,bytes(copy))
    def run(pc,**regs):
        vm.reg_write(m.UC_MIPS_REG_SP,0x80040000);vm.reg_write(m.UC_MIPS_REG_RA,0x80060000)
        for k,v in regs.items():vm.reg_write(getattr(m,'UC_MIPS_REG_'+k.upper()),v)
        hit=[]
        def stop(machine,address,size,data):
            if address==0x80060000:hit.append(address);machine.emu_stop()
        h=vm.hook_add(uc.UC_HOOK_CODE,stop)
        try:vm.emu_start(pc,0,count=300000)
        finally:vm.hook_del(h)
        assert hit,hex(vm.reg_read(m.UC_MIPS_REG_PC))
    vm.mem_write(0x40010,struct.pack('<II',0,0x801f9d44))
    run(0x8016b880,a0=94,a1=32,a2=180,a3=208)
    run(0x8016b8c8,a0=0x8011734e,a1=0x801f9d44)
    s,ps=object_at(bytes(vm.mem_read(0,0x200000)),0x1f9d44,{'physical_chars':{}})
    ts=[t for t in expand(d,START,END-START) if t!=b'\xe6\x01']
    assert len(ts)==len(ps),(len(ts),len(ps))
    dec=load_v354()[3];rows={}
    for t,q in zip(ts,ps):rows[q['y']]=rows.get(q['y'],'')+dec.get(t,'?')
    return dict(state=s,rows=rows)
def main():
    n,p,ram,vr=next(states())
    with ZipFile(ROOT/'03_output/arc1_v368_sans_font_TEST_ONLY.zip') as z:d=z.read(FN)
    assert ram[0x11734e:0x11738a]==d[START:END+1]
    assert ram[0x114000:0x114080]==d[0x45000:0x45080]
    new=candidate(d);before=render(ram,d);after=render(ram,new)
    print('BEFORE',before);print('AFTER',after)
    assert sorted(before['rows'])==[32,48,64,80,96]
    assert max(after['rows'])<=80
    assert before['state']['source_pointer']==after['state']['source_pointer']=='0x80117389'
    assert ''.join(before['rows'].values()).replace(' ','')==''.join(after['rows'].values()).replace(' ','')
    (AN/'overflow_trial.json').write_text(json.dumps(dict(before=before,after=after),ensure_ascii=False,indent=2),encoding='utf-8')
if __name__=='__main__':main()
