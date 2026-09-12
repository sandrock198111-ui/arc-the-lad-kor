"""Read-only V375 original skill/actor integrity and bounded CPU probes."""
from pathlib import Path
import sys, json, struct, csv, hashlib
from zipfile import ZipFile
ROOT=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/'01_work/tools/cursor_verify'))
import unicorn as uc
from unicorn import mips_const as m
OUT=Path(__file__).parent
ORIG=ZipFile(ROOT/'00_original/arc.zip').read('PSX.EXE')
CUR=ZipFile(ROOT/'03_output/arc1_v375_next_choice_TEST_ONLY.zip').read('PSX.EXE')
BIAS=0x8011A800
def word(blob,addr):return struct.unpack_from('<I',blob,addr-BIAS)[0]
def vm_for(blob):
    vm=uc.Uc(uc.UC_ARCH_MIPS,uc.UC_MODE_MIPS32|uc.UC_MODE_LITTLE_ENDIAN)
    vm.mem_map(0,0x200000);vm.mem_write(0x11b000,blob[0x800:])
    return vm
def flame_probe(blob):
    vm=vm_for(blob)
    # Start after BIOS memset. Only isolate real typed-copy instructions.
    # Fresh zero RAM supplies the already-cleared scratch buffer.
    vm.reg_write(m.UC_MIPS_REG_S0,88);vm.reg_write(m.UC_MIPS_REG_SP,0x80040000)
    vm.mem_write(0x40014,struct.pack('<I',0x80060000))
    vm.emu_start(0x801748E8,0x80060000,count=1000)
    assert vm.reg_read(m.UC_MIPS_REG_PC)==0x80060000
    source=vm.reg_read(m.UC_MIPS_REG_V0)&0x1fffff
    data=bytes(vm.mem_read(source,96));assert source==0x1A9F84
    vm.mem_write(0x11000,data);vm.mem_write(0x12000,data)
    vm.mem_write(0x100D8,struct.pack('<I',0x80011000))
    vm.mem_write(0x100DC,struct.pack('<I',0x80012000));vm.mem_write(0x1009C,b'\x58')
    vm.reg_write(m.UC_MIPS_REG_A0,0x80010000)
    vm.reg_write(m.UC_MIPS_REG_RA,0x80060000);vm.reg_write(m.UC_MIPS_REG_SP,0x80040000)
    vm.emu_start(0x80174BE0,0x80060000,count=10000)
    assert vm.reg_read(m.UC_MIPS_REG_PC)==0x80060000
    status=struct.unpack('<H',vm.mem_read(0x1104A,2))[0];hits=[]
    def hook(v,address,size,user):
        if address in (0x8012196C,0x80121A6C):
            hits.append(dict(address=hex(address),a1=v.reg_read(m.UC_MIPS_REG_A1)))
            v.emu_stop()
    vm.hook_add(uc.UC_HOOK_CODE,hook)
    vm.reg_write(m.UC_MIPS_REG_A0,0x80010000);vm.reg_write(m.UC_MIPS_REG_RA,0x80060000)
    vm.emu_start(0x801219FC,0x80060000,count=1000)
    assert len(hits)==1
    return dict(copied_status=struct.unpack_from('<H',data,74)[0],refreshed_status=status,dispatch=hits[0])
def lock_probe():
    vm=vm_for(ORIG)
    vm.mem_write(0x1000,struct.pack('<III',0x80002000,0x80003000,0))
    vm.mem_write(0x20B2,struct.pack('<H',3));vm.mem_write(0x30B2,struct.pack('<H',32))
    vm.reg_write(m.UC_MIPS_REG_A0,0x80001000)
    vm.emu_start(0x8012EBE0,0x8012EC0C,count=100)
    assert vm.reg_read(m.UC_MIPS_REG_PC)==0x8012EC0C
    values=[struct.unpack('<H',vm.mem_read(p,2))[0] for p in (0x20B2,0x30B2)]
    assert values==[0x8003,0x8020]
    return dict(initial=[3,32],final=values,scope='Real original marking loop only, two synthetic target-list entries, no helper stubs')
spans=[]
for name,start,end,count in [('actor_records',0x83A34,0x85ADC,110),('action_records',0x85ADC,0x872F4,257),('selector_pointers',0x83664,0x8381C,110),('selector_storage',0x83404,0x83664,None)]:
    diffs=[i for i in range(start,end) if ORIG[i]!=CUR[i]]
    spans.append(dict(name=name,start=hex(start),end_exclusive=hex(end),count=count,bytes=end-start,different_bytes=len(diffs),diff_offsets=[hex(i) for i in diffs]))
actors=[]
for c in range(110):
    off=0x83A34+c*76
    differences=[i for i in range(76) if ORIG[off+i]!=CUR[off+i]]
    if differences:
        actors.append(dict(actor_id=c,file_offset=hex(off),different_bytes=len(differences),relative_offsets=differences,descriptor_pointer=hex(word(ORIG,0x8018FB6C+4*c))))
slots=[]
for c in range(110):
    ptr=word(ORIG,0x8019DE64+4*c)-BIAS
    rank=list(ORIG[0x83A34+c*76+12:0x83A34+c*76+20]);assert rank==[0]*8
    vals=list(ORIG[ptr:ptr+8])
    slots.append(dict(actor_record_id=c,initial_rank=rank,raw_base_selectors=vals,non_ff_slots=[i for i,a in enumerate(vals) if a!=255],warning='Main0..7 unused slots require learned-slot/name boundaries; non-FF alone is not runtime availability'))
flame={label:flame_probe(blob) for label,blob in [('original',ORIG),('v375',CUR)]}
assert flame['original']['refreshed_status']==0
assert flame['v375']['refreshed_status']==0x8A
assert flame['v375']['dispatch']['a1']==30
result=dict(spans=spans,changed_actors=actors,base_rank_domain=slots,flame=flame,lock_on=lock_probe(),scope='Static all allocated records; bounded CPU copy-refresh-dispatch and lock-marking tests. Full gameplay not emulated.')
(OUT/'skill_integrity_followup.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
print(json.dumps(dict(spans=[{k:v for k,v in s.items() if k!='diff_offsets'} for s in spans],flame=flame,lock_on=result['lock_on']),indent=2))
