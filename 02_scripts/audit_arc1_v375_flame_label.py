"""Current unknown E0AC: actual renderer packets and selected font pixels."""
import sys, struct, json
from pathlib import Path
from zipfile import ZipFile
sys.dont_write_bytecode=True
from audit_arc1_v375_full_inventory import AN, BASE, digest
import build_arc1_v324_static_ui_cursor_recovery as resident
import build_arc1_v360_ui_restore as storage
from audit_arc1_9118_runtime import load
from analyze_arc1_v320c_savestates import object_at
from build_arc1_v319_pilgi16_integration import read_plane
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'01_work/tools/cursor_verify'))
import unicorn as uc
from unicorn import mips_const as m

def main():
    with ZipFile(BASE) as z: exe=z.read('PSX.EXE');comm=z.read('COMM.IMG')
    with ZipFile(storage.BASE) as z: baseline=z.read('PSX.EXE')
    paths=list(Path('C:/Users/Administrator/.paseo/uploads').glob('upload_*/HASH-F5D974ADD31760_2.sav'))
    assert len(paths)==1
    ram=bytearray(load(paths[0],baseline)[0])
    for i,(a,b) in enumerate(zip(baseline,exe)):
        if a!=b:ram[(i+storage.BIAS)&0x1fffff]=b
    ram[resident.RESIDENT_BASE&0x1fffff:resident.HEAP_BASE&0x1fffff]=exe[resident.SOURCE_FILE:resident.SOURCE_FILE+resident.COPY_SIZE]
    pointer=struct.unpack_from('<I',exe,0x8299c)[0]
    assert storage.string_at(exe,pointer)==bytes.fromhex('E0 AC')
    results=[]
    for width,height in [(14,16),(12,12),(6,12)]:
        vm=uc.Uc(uc.UC_ARCH_MIPS,uc.UC_MODE_MIPS32|uc.UC_MODE_LITTLE_ENDIAN)
        vm.mem_map(0,0x200000);vm.mem_write(0,bytes(ram))
        header=bytearray(32);struct.pack_into('<IH',header,0,0x80020000,128)
        header[13:17]=bytes([width,height,0,2]);vm.mem_write(0x10000,bytes(header))
        for reg,val in [(m.UC_MIPS_REG_A0,20),(m.UC_MIPS_REG_A1,20),(m.UC_MIPS_REG_A2,pointer),(m.UC_MIPS_REG_A3,0x80010000),(m.UC_MIPS_REG_SP,0x80040000),(m.UC_MIPS_REG_RA,0x80060000)]:vm.reg_write(reg,val)
        vm.emu_start(0x8016b248,0x80060000,count=10000)
        assert vm.reg_read(m.UC_MIPS_REG_PC)==0x80060000
        state,packets=object_at(bytes(vm.mem_read(0,0x200000)),0x10000,{'physical_chars':{}})
        assert len(packets)==1 and packets[0]['clut']=='0x7FC0'
        p=packets[0]
        # Width6 selects an inset of the same physical 16px cell.
        cell=(p['v']//16)*60+(p['u']//16)*4
        pixels=read_plane(comm,cell)
        assert cell==196 and sum(v.bit_count() for v in pixels)==0
        results.append(dict(width=width,height=height,state=state,packets=packets,font_cell=cell,ink_pixels=0))
    result=dict(id='extra_ui:8299C',status='CONFIRMED_DEFECT',severity='MEDIUM',
        original_label='炎',current_bytes='E0 AC',zip_sha256=digest(BASE.read_bytes()),cases=results,
        finding='Original flame label selects an empty font cell through the current native text renderer.',
        limitation='Real CPU renderer with captured initialized globals and synthetic destination object. Current COMM pixels checked; original monster-menu scene and live GPU were not replayed.')
    (AN/'flame_glyph.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps(result,ensure_ascii=False,indent=2))

if __name__=='__main__':main()
