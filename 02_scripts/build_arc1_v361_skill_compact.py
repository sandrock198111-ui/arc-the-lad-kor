"""V361: three guarded skill-only immediates; no text/font/VRAM changes.

The pinned V360 archive is an explicit legacy build dependency. Packaging
applies this archive to an original-disc staging tree, not a prior BIN.
"""
from pathlib import Path
from zipfile import ZipFile
import hashlib, io, json, struct, sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'01_work/tools/cursor_verify'))
import capstone
from keystone import Ks, KS_ARCH_MIPS, KS_MODE_MIPS32, KS_MODE_LITTLE_ENDIAN

BASE=ROOT/'03_output/arc1_v360_ui_restore_TEST_ONLY.zip'
PIN='9235BCB75903A00477E69BC47713D200E8BAE4C37AFDDDA83EF1878D07441731'
OUT=ROOT/'03_output/arc1_v361_skill_compact_TEST_ONLY.zip'
AN=ROOT/'01_work/analysis/v361_skill_compact'
BIAS=0x8011A800
PATCHES=[
    (0x80161A78,0x3407002E,0x3407002A,'ori $a3, $zero, 42','skill height 46 -> 42'),
    (0x801620D0,0x34050085,0x3405007F,'ori $a1, $zero, 127','MP baseline 133 -> 127'),
    (0x801621FC,0x24C6FFFD,0x24C6FFFF,'addiu $a2, $a2, -1','orb offset -3 -> -1'),
]
CSV_PINS={
    'script_translated_full.csv':'90DB5C0E984C6EED14BD747736F023053DC87E7A09D0BFDE2681003EB40F6E51',
    'dialogue_all.csv':'CEBB7E2C575F3669873693B2C6BC03AA239DAF801474DC3A326F31A58383EEC5',
}

def digest(data):return hashlib.sha256(data).hexdigest().upper()

def prepare():
    assert digest(BASE.read_bytes())==PIN
    assert digest((ROOT/'00_original/arc.zip').read_bytes())=='AE9F4366A1E7DA3805BB3BED3DDA9567E4CD4E669AF890E4E2A620D7861F11DD'
    for name,want in CSV_PINS.items():assert digest((ROOT/'05_docs'/name).read_bytes())==want,name
    with ZipFile(BASE) as z:
        infos=z.infolist();old={i.filename:z.read(i) for i in infos};comment=z.comment
    assert len(old)==164
    exe=bytearray(old['PSX.EXE']);writes=[]
    ks=Ks(KS_ARCH_MIPS,KS_MODE_MIPS32|KS_MODE_LITTLE_ENDIAN)
    md=capstone.Cs(capstone.CS_ARCH_MIPS,capstone.CS_MODE_MIPS32|capstone.CS_MODE_LITTLE_ENDIAN)
    for address,before,after,asm,reason in PATCHES:
        offset=address-BIAS
        assert struct.unpack_from('<I',exe,offset)[0]==before,(hex(address),'unexpected baseline')
        encoded=bytes(ks.asm(asm,addr=address)[0]);assert encoded==struct.pack('<I',after)
        ins=list(md.disasm(encoded,address));assert len(ins)==1 and ins[0].size==4
        decoded=ins[0].mnemonic+' '+ins[0].op_str
        assert bytes(ks.asm(decoded,addr=address)[0])==encoded
        exe[offset:offset+4]=encoded
        writes.append({'address':hex(address),'offset':offset,'before':struct.pack('<I',before).hex(),
                       'after':encoded.hex(),'disassembly':decoded,'reason':reason})
    changed=[i for i,(a,b) in enumerate(zip(old['PSX.EXE'],exe)) if a!=b]
    assert changed==sorted(a-BIAS for a,_,_,_,_ in PATCHES)
    current=dict(old);current['PSX.EXE']=bytes(exe)
    stream=io.BytesIO()
    with ZipFile(stream,'w') as z:
        z.comment=comment
        for info in infos:z.writestr(info,current[info.filename])
    payload=stream.getvalue()
    report={'baseline_zip_sha256':PIN,'zip_sha256':digest(payload),'exe_sha256':digest(exe),
            'changed_members':['PSX.EXE'],'changed_bytes':len(changed),'writes':writes,
            'unchanged_members':163,'csv_sha256':CSV_PINS,'runtime_verified':False,
            'geometry':{'skill':[60,103,200,42],'description_y':109,'mp_y':127,'orb_y':126},
            'build_dependency':'Pinned V360 legacy archive; original-disc packaging; not full historical source replay'}
    return payload,report,current['PSX.EXE']

def main():
    payload,report,_=prepare()
    assert prepare()[0]==payload,'non-deterministic output'
    if OUT.exists():assert OUT.read_bytes()==payload,'refusing to overwrite different output'
    else:OUT.write_bytes(payload)
    AN.mkdir(parents=True,exist_ok=True)
    (AN/'build_report.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps(report,indent=2))

if __name__=='__main__':main()
