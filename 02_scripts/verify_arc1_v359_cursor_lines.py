"""CPU execution/ABI/bounds tests; not a PS1 GPU or complete game test."""
import random, struct, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'01_work/tools/cursor_verify'))
import unicorn as uc
from unicorn import mips_const as m

def verify_cpu(exe,code_size):
    import build_arc1_v359_cursor_lines as b
    import build_arc1_v324_static_ui_cursor_recovery as r
    # Independent manually traced orientation oracle, not builder.paths().
    expected_paths=[[0,1,3,2,0],[2,0,1,3],[0,1,3,2],[0,2,3,1],
                    [1,0,2,3],[1,0,2],[0,1,3],[1,3,2],[0,2,3]]
    assert b.paths()==expected_paths
    vm=uc.Uc(uc.UC_ARCH_MIPS,uc.UC_MODE_MIPS32|uc.UC_MODE_LITTLE_ENDIAN)
    vm.mem_map(0,0x200000)
    vm.mem_write(0x11a800,exe)
    vm.mem_write(r.RESIDENT_BASE&0x1fffff,exe[r.SOURCE_FILE:r.SOURCE_FILE+r.COPY_SIZE])
    packet=0x801F52BC;bucket=0x801B0000;stack=0x801EF000;stop=0x801B1000
    allowed=[(packet&0x1fffff,(packet&0x1fffff)+40),(bucket&0x1fffff,(bucket&0x1fffff)+4),
             ((stack&0x1fffff)-16,stack&0x1fffff)]
    writes=[]
    def on_write(vm,access,address,size,value,user):
        at=address&0x1fffff
        assert any(lo<=at and at+size<=hi for lo,hi in allowed),(hex(address),size)
        writes.append((at,size))
    vm.hook_add(uc.UC_HOOK_MEM_WRITE,on_write)
    saved=[m.UC_MIPS_REG_S0,m.UC_MIPS_REG_S1,m.UC_MIPS_REG_S2,m.UC_MIPS_REG_S3,m.UC_MIPS_REG_S4,
           m.UC_MIPS_REG_S5,m.UC_MIPS_REG_S6,m.UC_MIPS_REG_S7,m.UC_MIPS_REG_FP,m.UC_MIPS_REG_GP]
    rng=random.Random(9118);cases=0
    clean_cpu=vm.context_save()
    # Reuse same packet every frame; actual GTE and UV writes restore FT4 fields.
    # This catches accidental dependence on the previous polyline contents.
    for mode in range(9):
        for frame in range(128):
            # Reset emulator branch-delay internal state between independent
            # calls; retain RAM so the previous frame's packet is still present.
            vm.context_restore(clean_cpu)
            coords=[rng.getrandbits(32) for _ in range(4)]
            before=bytearray(vm.mem_read(packet&0x1fffff,40))
            for off,value in zip((8,16,24,32),coords):struct.pack_into('<I',before,off,value)
            for off in (12,20,28,36):before[off:off+2]=bytes([frame,mode])
            before[14:16]=struct.pack('<H',0x7802+frame%10)
            vm.mem_write(packet&0x1fffff,bytes(before))
            vm.mem_write(bucket&0x1fffff,struct.pack('<I',0x00ffffff))
            for reg in saved:vm.reg_write(reg,rng.getrandbits(32))
            vm.reg_write(m.UC_MIPS_REG_S1,mode*16)
            baseline={reg:vm.reg_read(reg) for reg in saved}
            vm.reg_write(m.UC_MIPS_REG_SP,stack);vm.reg_write(m.UC_MIPS_REG_RA,stop)
            vm.reg_write(m.UC_MIPS_REG_A0,bucket);vm.reg_write(m.UC_MIPS_REG_A1,packet)
            vm.emu_start(b.ENTRY,stop,count=500)
            assert vm.reg_read(m.UC_MIPS_REG_PC)==stop
            assert vm.reg_read(m.UC_MIPS_REG_SP)==stack,(mode,frame,hex(vm.reg_read(m.UC_MIPS_REG_SP)))
            assert vm.reg_read(m.UC_MIPS_REG_RA)==stop
            assert baseline=={reg:vm.reg_read(reg) for reg in saved}
            raw=vm.mem_read(packet&0x1fffff,40);p=expected_paths[mode];n=len(p)
            assert struct.unpack_from('<I',raw)[0]==((n+2)<<24)|0xffffff
            assert struct.unpack_from('<I',raw,4)[0]==0x48ffffff
            assert list(struct.unpack_from('<'+'I'*n,raw,8))==[coords[i] for i in p]
            assert struct.unpack_from('<I',raw,8+n*4)[0]==0x55555555
            assert struct.unpack('<I',vm.mem_read(bucket&0x1fffff,4))[0]==packet&0xffffff
            cases+=1
    return {'cases':cases,'modes':9,'repeat_frames_per_mode':128,'preserved_abi':True,
            'writes_confined_to_packet_ot_stack':True,'write_events':len(writes),
            'packet_max_bytes':32,'gpu_runtime_verified':False}

if __name__=='__main__':
    from zipfile import ZipFile
    import build_arc1_v359_cursor_lines as b
    payload,source,decoded,size=b.assemble()
    with ZipFile(b.OUT) as z:print(verify_cpu(z.read('PSX.EXE'),size))
