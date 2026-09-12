import sys,json,struct,hashlib
from pathlib import Path
from zipfile import ZipFile
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/'02_scripts'))
sys.path.insert(0,str(ROOT/'01_work/tools/cursor_verify'))
import unicorn as uc
from unicorn import mips_const as m
import build_arc1_v324_static_ui_cursor_recovery as resident
import build_arc1_v360_ui_restore as b
import audit_arc1_v375_full_inventory as inv
from audit_arc1_9118_runtime import load
from analyze_arc1_v320c_savestates import object_at,read_plane,load_mappings
with ZipFile(inv.BASE) as z:exe=z.read('PSX.EXE');comm=z.read('COMM.IMG')
with ZipFile(b.BASE) as z:base=z.read('PSX.EXE')
paths=list(Path('C:/Users/Administrator/.paseo/uploads').glob('upload_*/HASH-F5D974ADD31760_1.sav'));assert len(paths)==1
ram,_,_,_=load(paths[0],base);ram=bytearray(ram)
for i,(x,y) in enumerate(zip(base,exe)):
 if x!=y:ram[(i+b.BIAS)&0x1fffff]=y
ram[resident.RESIDENT_BASE&0x1fffff:resident.HEAP_BASE&0x1fffff]=exe[resident.SOURCE_FILE:resident.SOURCE_FILE+resident.COPY_SIZE]
vm=uc.Uc(uc.UC_ARCH_MIPS,uc.UC_MODE_MIPS32|uc.UC_MODE_LITTLE_ENDIAN);vm.mem_map(0,0x200000);vm.mem_write(0,bytes(ram))
clean=vm.context_save();stop=0x80060000

def run(pc,a0=0):
 vm.context_restore(clean)
 for reg,val in [(m.UC_MIPS_REG_SP,0x80040000),(m.UC_MIPS_REG_RA,stop),(m.UC_MIPS_REG_A0,a0)]:vm.reg_write(reg,val)
 vm.mem_write(0x40010,bytes(4));vm.emu_start(pc,stop,count=500000)
 assert vm.reg_read(m.UC_MIPS_REG_PC)==stop
run(0x8016C530)
ptr=struct.unpack_from('<I',exe,0x8299c)[0]
run(0x8016C760,ptr)
state,packets=object_at(bytes(vm.mem_read(0,0x200000)),0x1f031c,load_mappings())
result={'build':str(inv.BASE),'exe_sha256':hashlib.sha256(exe).hexdigest(),'comm_sha256':hashlib.sha256(comm).hexdigest(),'capture':str(paths[0]),'pointer_offset':'0x8299C','pointer':hex(ptr),'bytes':b.string_at(exe,ptr).hex(),'constructor':'0x8016C530','renderer':'0x8016C760','state':state,'packets':packets,'gpu_verified':False}
for p in packets:
 p['pixel_rows']=[f'{r:04X}' for r in read_plane(comm,p['physical_index'])]
Path(__file__).with_name('flame_glyph.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
print(json.dumps(result,ensure_ascii=False,indent=2))
