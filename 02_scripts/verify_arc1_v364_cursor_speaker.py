"""Independent expected-write and captured-RAM cursor coordinate tests."""
from pathlib import Path
from zipfile import ZipFile
import sys,json,hashlib,struct,csv
from audit_arc1_9118_runtime import load
from audit_arc1_v363_speaker_cursor import expand
from verify_arc1_v359_slot_recovery import legacy_gate
ROOT=Path(__file__).resolve().parents[1];AN=ROOT/'01_work/analysis/v364_cursor_speaker'
BASE=ROOT/'03_output/arc1_v363_dialogue_trial_TEST_ONLY.zip'
OUT=ROOT/'03_output/arc1_v364_cursor_speaker_TEST_ONLY.zip'
sys.path.insert(0,str(ROOT/'01_work/tools/cursor_verify'))
import unicorn as uc
from unicorn import mips_const as m

def main():
    with ZipFile(BASE) as z:old={n:z.read(n) for n in z.namelist()}
    with ZipFile(OUT) as z:new={n:z.read(n) for n in z.namelist()}
    report=json.loads((AN/'build_report.json').read_text(encoding='utf-8'))
    assert old.keys()==new.keys() and old['COMM.IMG']==new['COMM.IMG']
    specs={0x3fee0:(0x000418c0,0x00041900),0x3fee4:(0x00641823,0),0x3fee8:(0x00031840,0),
           0x3ff08:(0x000510c0,0x00051100),0x3ff0c:(0x00451023,0),
           0x3ff1c:(0x00021040,0x2484000e),0x3ff2c:(0x24a5ffff,0x24a50002)}
    allowed={k:set() for k in old}
    for at,(a,b) in specs.items():
        assert struct.unpack_from('<I',old['PSX.EXE'],at)[0]==a
        assert struct.unpack_from('<I',new['PSX.EXE'],at)[0]==b
        allowed['PSX.EXE'].update(range(at,at+4))
    for w in report['writes']:
        if w['file']=='PSX.EXE':continue
        assert bytes.fromhex(w['before'])==b'\xe6\x01' and bytes.fromhex(w['after'])==b'\xa1\xa1'
        at=w['offset'];fn=w['file'];assert old[fn][at:at+2]==b'\xe6\x01' and new[fn][at:at+2]==b'\xa1\xa1'
        allowed[fn].update((at,at+1))
    for fn in old:
        assert len(old[fn])==len(new[fn])
        assert all(a==b or i in allowed[fn] for i,(a,b) in enumerate(zip(old[fn],new[fn])))
    originals=list(csv.DictReader((ROOT/'05_docs/script_original_full.csv').open(encoding='utf-8-sig')))
    changed_text=0
    for r in originals:
        fn=r['source file']
        if not allowed.get(fn):continue
        at=int(r['byte offset'],16);length=len(bytes.fromhex(r['raw bytes as hex']))
        a=expand(old[fn],at,length);b=expand(new[fn],at,length)
        if a==b:continue
        assert [t for t in a if t not in (b'\xe6\x01',b'\xa1')]==[t for t in b if t not in (b'\xe6\x01',b'\xa1')]
        assert sum(t!=b'\xe6\x01' for t in b)<=64
        changed_text+=1
    cases=[]
    for slot in (7,8):
        path=next(Path('C:/Users/Administrator/.paseo/uploads').glob(f'upload_*/HASH-DC42934B1AA4449B_{slot}.sav'))
        captured,_,_,_=load(path,old['PSX.EXE'])
        vm=uc.Uc(uc.UC_ARCH_MIPS,uc.UC_MODE_MIPS32|uc.UC_MODE_LITTLE_ENDIAN);vm.mem_map(0,0x200000);vm.mem_write(0,captured)
        for at,(_,b) in specs.items():vm.mem_write((at+0x8011a800)&0x1fffff,struct.pack('<I',b))
        for origin_y in (32,162):
            for row in range(4):
                for selected in range(4):
                    for col in range(3):
                        vm.mem_write(0x1fe2be,struct.pack('<hh',col,row));vm.mem_write(0x1f9d62,struct.pack('<hh',46,origin_y))
                        vm.reg_write(m.UC_MIPS_REG_S1,0x801f9d44);vm.reg_write(m.UC_MIPS_REG_A0,selected)
                        vm.emu_start(0x8015a6e0,0x8015a728,count=100)
                        xy=(vm.reg_read(m.UC_MIPS_REG_A0),vm.reg_read(m.UC_MIPS_REG_A1)+2)
                        assert xy==(46+12*col+14,origin_y+16*(row+selected)+2)
                        cases.append(xy)
    before=legacy_gate(BASE);after=legacy_gate(OUT)
    # Existing failures must not grow; row changes can legitimately remove warnings.
    for key,entries in after['fail'].items():assert key in before['fail'] and set(entries)<=set(before['fail'][key]),key
    result={'zip_sha256':hashlib.sha256(OUT.read_bytes()).hexdigest().upper(),'static_pass':True,
            'cpu_coordinate_cases':len(cases),'captured_prompt_expected_cursor':[[60,66],[60,82]],
            'changed_existing_dialogues':changed_text,'joined_total':len(report['applied'])+1,'deferred':report['deferred'],
            'inherited_gate':after,'runtime_verified':False,
            'remaining':'GPU/interactive choice navigation and new text wrapping player review. 29 deferred speaker candidates; canonical CSV unchanged.'}
    (AN/'verification.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
    print('PASS',len(cases),'CPU coordinate cases;',changed_text,'existing text joins; cursor start (60,66), second (60,82)')
if __name__=='__main__':main()
