"""Execute the actual description renderer on captured RAM, not a mock layout.

Only an in-process Unicorn RAM copy is changed. No emulator, game image or user
save state is written. Geometry/packets are CPU evidence, not GPU/cold-boot QA.
"""
from pathlib import Path
from zipfile import ZipFile
import csv, struct, sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'01_work/tools/cursor_verify'))
import unicorn as uc
from unicorn import mips_const as m
import build_arc1_v324_static_ui_cursor_recovery as resident
from audit_arc1_9118_runtime import load
from analyze_arc1_v320c_savestates import object_at

def verify_panels(exe):
    import build_arc1_v360_ui_restore as b
    with ZipFile(b.BASE) as z:base=z.read('PSX.EXE')
    catalog=list(csv.DictReader((ROOT/'05_docs/ui_full_v42.csv').open(encoding='utf-8-sig')))
    rows=[r for r in catalog if r['table_key'] in ('equipment_description','consumable_description','skill_description')]
    states={}
    for slot in (1,2):
        paths=list(Path('C:/Users/Administrator/.paseo/uploads').glob(f'upload_*/HASH-F5D974ADD31760_{slot}.sav'));assert len(paths)==1
        ram,_,_,_=load(paths[0],base);ram=bytearray(ram)
        # Apply just changed loaded EXE bytes; retain the captured live globals.
        for i,(x,y) in enumerate(zip(base,exe)):
            if x!=y:ram[(i+b.BIAS)&0x1fffff]=y
        ram[resident.RESIDENT_BASE&0x1fffff:resident.HEAP_BASE&0x1fffff]=exe[resident.SOURCE_FILE:resident.SOURCE_FILE+resident.COPY_SIZE]
        states[slot]=bytes(ram)
    results=[];abi_count=0;empty_placeholders=[];mp_cases=[]
    saved=[m.UC_MIPS_REG_S0,m.UC_MIPS_REG_S1,m.UC_MIPS_REG_S2,m.UC_MIPS_REG_S3,m.UC_MIPS_REG_S4,m.UC_MIPS_REG_S5,m.UC_MIPS_REG_S6,m.UC_MIPS_REG_S7,m.UC_MIPS_REG_FP,m.UC_MIPS_REG_GP]
    for row in rows:
        pointer=struct.unpack_from('<I',exe,int(row['pointer_offset'],0))[0]
        if not b.string_at(exe,pointer):
            # Skill 0 is a null placeholder, not an in-game description. The
            # original print routine is not defined for an empty-string call.
            assert row['table_key']=='skill_description' and row['index']=='0'
            empty_placeholders.append((row['table_key'],int(row['index'])))
            continue
        skill=row['table_key']=='skill_description';slot=2 if skill else 1
        for anchor in ([60] if skill else [10,60,110]):
            vm=uc.Uc(uc.UC_ARCH_MIPS,uc.UC_MODE_MIPS32|uc.UC_MODE_LITTLE_ENDIAN)
            vm.mem_map(0,0x200000);vm.mem_write(0,states[slot])
            group1_before_constructor=bytes(vm.mem_read(0x1f0798,0xaf4))
            clean=vm.context_save();sp=0x80040000;stop=0x80060000
            def run(pc,end=stop,a0=0,a1=0,a2=0,a3=0,abi=True,s2=None):
                nonlocal abi_count
                vm.context_restore(clean)
                for i,reg in enumerate(saved):vm.reg_write(reg,0x12340000+i)
                if s2 is not None:vm.reg_write(m.UC_MIPS_REG_S2,s2)
                vm.reg_write(m.UC_MIPS_REG_SP,sp);vm.reg_write(m.UC_MIPS_REG_RA,stop)
                for reg,val in zip([m.UC_MIPS_REG_A0,m.UC_MIPS_REG_A1,m.UC_MIPS_REG_A2,m.UC_MIPS_REG_A3],[a0,a1,a2,a3]):vm.reg_write(reg,val)
                vm.mem_write((sp&0x1fffff)+16,bytes(4))
                vm.emu_start(pc,end,count=500000)
                assert vm.reg_read(m.UC_MIPS_REG_PC)==end,('did not return',row['index'],hex(vm.reg_read(m.UC_MIPS_REG_PC)))
                assert vm.reg_read(m.UC_MIPS_REG_SP)==sp
                if abi:
                    assert all(vm.reg_read(reg)==0x12340000+i for i,reg in enumerate(saved)),('callee-saved drift',row)
                    assert vm.reg_read(m.UC_MIPS_REG_RA)==stop
                    abi_count+=1
            if skill:run(0x80161A64,0x80161A7C,abi=False)
            else:run(0x8016C530)
            assert bytes(vm.mem_read(0x1f0798,0xaf4))==group1_before_constructor,'constructor touched other help group'
            xywh=struct.unpack('<4i',vm.mem_read(0x1f0780,16))
            assert xywh==((60,103,200,46) if skill else (60,110,200,46)),xywh
            # Inventory relocation has independent guarded anchor immediates.
            # Set the captured panel x for each legal menu position and exercise
            # the shared renderer, which must read that position dynamically.
            vm.mem_write(0x1f0780,struct.pack('<i',anchor))
            protected=bytes(vm.mem_read(0x1f0798,0xaf4))
            ptr=struct.unpack_from('<I',exe,int(row['pointer_offset'],0))[0]
            run(0x8016C760,a0=ptr)
            ram=bytes(vm.mem_read(0,0x200000));state,packets=object_at(ram,0x1f031c,{'physical_chars':{}})
            ys=sorted(set(p['y'] for p in packets));top=109 if skill else 116
            assert state['line_extra']==2 and state['E']==16 and state['D']==14,state
            expected_packets=sum(t!=b.codec.LINEBREAK for t in b.codec.tokens(b.string_at(exe,ptr)))
            assert state['count']==expected_packets<=32 and len(ys)<=(1 if skill else 2),(row,state,ys,expected_packets)
            assert ys and all(y in (top,top+18) for y in ys),(row,ys)
            # A 16px sprite extends 2px past its 14px advance. Keep at least
            # 6px to the outer 200px panel edge, including this real overhang.
            assert all(anchor+8<=p['x'] and p['x']+p['w']<=anchor+194 and top<=p['y'] and p['y']+p['h']<=top+34 for p in packets),(row,anchor,packets)
            assert bytes(vm.mem_read(0x1f0798,0xaf4))==protected,'other help group changed'
            assert ram[resident.RESIDENT_BASE&0x1fffff:resident.HEAP_BASE&0x1fffff]==states[slot][resident.RESIDENT_BASE&0x1fffff:resident.HEAP_BASE&0x1fffff],'resident code/data overwritten'
            if skill and row['index']=='1':
                # Prefix setup and label emission are self-contained. The next
                # block calls BIOS sprintf, outside this CPU harness's mapped
                # RAM; numeric formatting/blue orb remain runtime checklist.
                run(0x801620B0,0x8016212C,abi=False,s2=0)
                mpstate,mppackets=object_at(bytes(vm.mem_read(0,0x200000)),0x1f9d44,{'physical_chars':{}})
                assert mppackets and all(64<=p['x'] and p['x']+p['w']<=256 and 133<=p['y'] and p['y']+p['h']<=145 for p in mppackets),(mpstate,mppackets)
                mp_cases.append({'coverage':'MP prefix setup/label only; BIOS formatting and orb not executed','state':mpstate,'packets':mppackets})
            results.append({'table':row['table_key'],'index':int(row['index']),'anchor':anchor,'rows_y':ys,'packets':len(packets),'max_right':max(p['x']+p['w'] for p in packets),'max_bottom':max(p['y']+p['h'] for p in packets)})
    assert len(results)==96*3+58
    return {'cases':len(results),'description_rows':154,'empty_placeholders_not_rendered':empty_placeholders,'item_anchors':[10,60,110],'abi_calls':abi_count,
      'packets_fit':True,'other_help_group_preserved':True,'resident_code_preserved':True,'gpu_runtime_verified':False,'mp_cases':mp_cases,'cases_detail':results}

if __name__=='__main__':
    import build_arc1_v360_ui_restore as b
    _,_,current,_=b.prepare()
    result=verify_panels(current['PSX.EXE']);print({k:v for k,v in result.items() if k!='cases_detail'})
