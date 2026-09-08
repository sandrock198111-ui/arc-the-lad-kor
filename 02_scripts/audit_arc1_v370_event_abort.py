"""Isolate malformed arena opcode using the captured RAM-copy VM dispatcher."""
import sys,struct,json
from pathlib import Path
from zipfile import ZipFile
from audit_arc1_v368_followup import states,ROOT
sys.path.insert(0,str(ROOT/'01_work/tools/cursor_verify'))
import unicorn as uc
from unicorn import mips_const as m
AN=ROOT/'01_work/analysis/v370_event_abort'
TARGETS={'7/S7021.DAT':0x4878c,'7/S7022.DAT':0x48c26,'7/S7023.DAT':0x48c56,
 '7/S7024.DAT':0x48cba,'7/S7025.DAT':0x48cca,'7/S7026.DAT':0x48f36,'7/S7028.DAT':0x47aca}
def probe(ram,raw,at,stop_first=True):
    copy=bytearray(ram);copy[0x100000:0x100000+len(raw)]=raw
    # Same script payload and VM consumer, isolated scratch relocation in RAM copy.
    struct.pack_into('<I',copy,0x1b1acc,0x80100000)
    struct.pack_into('<H',copy,0x1fe2b4,at//2)
    vm=uc.Uc(uc.UC_ARCH_MIPS,uc.UC_MODE_MIPS32|uc.UC_MODE_LITTLE_ENDIAN)
    vm.mem_map(0,0x200000);vm.mem_write(0,bytes(copy))
    vm.reg_write(m.UC_MIPS_REG_SP,0x80040000);vm.reg_write(m.UC_MIPS_REG_RA,0x80060000)
    hit=[];trace=[]
    def hook(machine,address,size,user):
        if address==0x8015ac2c:trace.append(machine.reg_read(m.UC_MIPS_REG_V0)&0xffff)
        if address==(0x8015b220 if stop_first else 0x80060000):hit.append(address);machine.emu_stop()
    vm.hook_add(uc.UC_HOOK_CODE,hook)
    vm.emu_start(0x8015ac0c,0,count=100000)
    assert hit,(hex(vm.reg_read(m.UC_MIPS_REG_PC)),trace)
    return dict(index=struct.unpack('<H',vm.mem_read(0x1fe2b4,2))[0],
        dispatch_continue=vm.reg_read(m.UC_MIPS_REG_S0),status=vm.reg_read(m.UC_MIPS_REG_S1),
        return_value=vm.reg_read(m.UC_MIPS_REG_V0),opcodes=trace)
def main():
    ram=list(states())[1][2]
    # The global scratch record was the last (auxiliary) thread, not the main thread.
    assert struct.unpack_from('<HH',ram,0x1addc4)==(0x7c7,1)
    assert struct.unpack_from('<HHHH',ram,0x1adde6)==(0xe1c,3,0,1)
    results=[]
    with ZipFile(ROOT/'03_output/arc1_v369_overflow_TEST_ONLY.zip') as z,ZipFile(ROOT/'00_original/arc.zip') as o:
        for fn,at in TARGETS.items():
            raw=z.read(fn);original=o.read(fn)
            assert original[at-6:at+4]==bytes.fromhex('0b001900fdff0e000000')
            assert raw[at-6:at+4]==bytes.fromhex('0b001900fdffa1000000')
            fixed=bytearray(raw);fixed[at]=14
            # Use complete event script, retaining script-relative branch indexes.
            base=0x46800 if fn.endswith('7028.DAT') else 0x47800
            prefix=probe(ram,raw[base:0x49800],at-base-6)
            assert prefix['opcodes']==[11] and prefix['index']==(at-base)//2
            bad=probe(ram,raw[base:0x49800],at-base)
            bad_return=probe(ram,raw[base:0x49800],at-base,stop_first=False)
            good=probe(ram,bytes(fixed[base:0x49800]),at-base)
            ref=probe(ram,original[base:0x49800],at-base)
            assert bad['opcodes']==[161] and bad['status']==0 and bad['dispatch_continue']==0
            assert bad_return['return_value']==0
            assert good==ref and good['opcodes']==[14] and good['dispatch_continue']==1
            results.append(dict(file=fn,offset=hex(at),prefix=prefix,bad=bad,bad_dispatcher_return=bad_return['return_value'],repaired=good,original=ref))
            print(results[-1])
    AN.mkdir(exist_ok=True)
    (AN/'cpu.json').write_text(json.dumps(results,indent=2),encoding='utf-8')
if __name__=='__main__':main()
