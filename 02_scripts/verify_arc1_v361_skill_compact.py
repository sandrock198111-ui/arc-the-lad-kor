"""CPU/packet bounds verification; no GPU, BIOS sprintf or cold-boot claim."""
from pathlib import Path
from zipfile import ZipFile
import json, struct
import build_arc1_v361_skill_compact as b
from verify_arc1_v360_ui_restore import verify_panels, uc, m
from verify_arc1_v359_cursor_lines import verify_cpu
from verify_arc1_v359_slot_recovery import legacy_gate
from audit_arc1_9118_runtime import load
from analyze_arc1_v320c_savestates import object_at
from analyze_arc1_v163_runtime import trace_active_text_ot

def captured_geometry(exe):
    with ZipFile(b.BASE) as z:base=z.read('PSX.EXE')
    results=[];projection=None
    for slot in (1,2,3,4):
        paths=list(Path('C:/Users/Administrator/.paseo/uploads').glob(f'upload_*/HASH-AA53DAA1260A4ED6_{slot}.sav'))
        assert len(paths)==1
        captured,_,_,_=load(paths[0],base)
        for parity in (0,1):
            vm=uc.Uc(uc.UC_ARCH_MIPS,uc.UC_MODE_MIPS32|uc.UC_MODE_LITTLE_ENDIAN)
            vm.mem_map(0,0x200000);vm.mem_write(0,captured)
            for address,_,after,_,_ in b.PATCHES:vm.mem_write(address&0x1fffff,struct.pack('<I',after))
            clean=vm.context_save()
            def run(pc,end=0x80060000,a0=0):
                vm.context_restore(clean)
                vm.reg_write(m.UC_MIPS_REG_SP,0x80050000);vm.reg_write(m.UC_MIPS_REG_RA,0x80060000)
                vm.reg_write(m.UC_MIPS_REG_A0,a0)
                vm.emu_start(pc,end,count=500000)
                assert vm.reg_read(m.UC_MIPS_REG_PC)==end,hex(vm.reg_read(m.UC_MIPS_REG_PC))
                assert vm.reg_read(m.UC_MIPS_REG_SP)==0x80050000
            protected=bytes(vm.mem_read(0x1f0798,0xaf4))
            if slot==3:
                run(0x80161A64,0x80161A7C)
                run(0x801620B0,0x8016212C)
                # Prefix setup executes the changed y immediate. The numeric
                # formatter is not emulated. Replay the orb call with the x
                # observed from the stored orb location before +14, and the
                # cursor y produced by the actual changed prefix setup.
                mp_y=struct.unpack('<h',vm.mem_read(0x1f9d4c,2))[0];assert mp_y==127
                old_orb_x,old_orb_y=struct.unpack_from('<hh',captured,0x1f30d2)
                vm.mem_write(0x1f9d4a,struct.pack('<h',old_orb_x-14))
                run(0x801621E0,0x80162200)
                orb_xy=struct.unpack('<hh',vm.mem_read(0x1f30d2,4))
                assert orb_xy==(old_orb_x,126),orb_xy
            else:orb_xy=None
            assert bytes(vm.mem_read(0x1f0798,0xaf4))==protected
            xywh=struct.unpack('<4i',vm.mem_read(0x1f0780,16))
            assert xywh==((60,103,200,42) if slot==3 else struct.unpack_from('<4i',captured,0x1f0780))
            ctx=struct.unpack('<I',vm.mem_read(0x1f12ec,4))[0]&0x1fffff
            vm.mem_write(ctx+0x870,struct.pack('<H',parity))
            before=bytes(vm.mem_read(0,0x200000))
            run(0x8016A4F0,a0=0x801F0360)
            after=bytes(vm.mem_read(0,0x200000))
            changed=[i for i,(x,y) in enumerate(zip(before,after)) if x!=y]
            assert all(0x1f0360<=i<0x1f0780 for i in changed),'geometry wrote outside panel packets'
            packet_base=0x1f0360+parity*480
            ys=[struct.unpack_from('<h',after,packet_base+40*n+k)[0] for n in range(12) for k in (10,18,26,34)]
            assert (min(ys),max(ys))==(xywh[1],xywh[1]+xywh[3]),(slot,parity,ys)
            results.append({'slot':slot,'parity':parity,'xywh':xywh,'ft4_y_extent':[min(ys),max(ys)],'orb_xy':orb_xy,'other_help_group_preserved':True})
        if slot==3:
            _,mp=object_at(captured,0x1f9d44,{'physical_chars':{}})
            _,desc=object_at(captured,0x1f031c,{'physical_chars':{}})
            assert mp and all(p['y']==133 for p in mp)
            # Coordinate projection of captured *actual* number/prefix sprites,
            # not a claim that BIOS number formatting was executed here.
            rects=[[p['x'],p['y']-6,p['w'],p['h']] for p in mp]
            desc_bottom=max(p['y']+p['h'] for p in desc)
            assert desc_bottom==125
            assert all(60<=x and x+w<=260 and y>=desc_bottom and y+h<=143 for x,y,w,h in rects)
            _,_,active=trace_active_text_ot(captured)
            orbs=[p for p in active if p.get('kind')=='SPRT' and p.get('tpage')==21 and p.get('u')==112 and p.get('v')==64]
            assert len(orbs)==1 and orbs[0]['width']==orbs[0]['height']==16
            oldxy=struct.unpack_from('<hh',captured,(orbs[0]['address']&0x1fffff)+8)
            assert oldxy==(154,130)
            assert 126>=desc_bottom and 126+16<=143
            projection={'coverage':'Observed active sprites projected with CPU-verified offsets; no BIOS formatter/GPU execution',
                        'mp_rectangles':rects,'description_sprite_bottom':desc_bottom,'orb_rectangle':[154,126,16,16],
                        'panel_bottom':145,'minimum_bottom_margin':2}
    return {'cases':results,'captured_sprite_projection':projection}

def main():
    payload,build,exe=b.prepare();assert b.OUT.read_bytes()==payload
    panels=verify_panels(exe,skill_height=42,mp_y=127)
    geometry=captured_geometry(exe)
    cursor=verify_cpu(exe,156)
    old,new=legacy_gate(b.BASE),legacy_gate(b.OUT)
    assert old['fail']==new['fail'] and old['counts']==new['counts']
    with ZipFile(b.BASE) as z:old_members={n:z.read(n) for n in z.namelist()}
    with ZipFile(b.OUT) as z:new_members={n:z.read(n) for n in z.namelist()}
    assert old_members.keys()==new_members.keys()
    assert [n for n in old_members if old_members[n]!=new_members[n]]==['PSX.EXE']
    assert all(len(old_members[n])==len(new_members[n]) for n in old_members)
    result={'zip_sha256':build['zip_sha256'],'panels':panels,'geometry':geometry,'cursor':cursor,
            'legacy_failures_identical':True,'inherited_failures':new['fail'],'counts':new['counts'],
            'non_exe_members_identical':163,'runtime_verified':False,
            'remaining':'Cold boot + memory-card load, open/close and switch skills; BIOS numeric formatting, GPU appearance/clear transitions not executed by this harness'}
    (b.AN/'verification.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
    print('PASS',panels['cases'],'description cases;',len(geometry['cases']),'background parity cases; inherited failures unchanged')
    print('CPU/packet checks only; cold-boot visual approval still required.')

if __name__=='__main__':main()
