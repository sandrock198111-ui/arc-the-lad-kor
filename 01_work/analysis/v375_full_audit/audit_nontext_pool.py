"""Read-only original/V375 EXE pool byte census and structural corruption evidence."""
from pathlib import Path
from zipfile import ZipFile
import csv
import hashlib
import json
import re
import struct
import capstone

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
BIAS=0x8011A800

def sha(b): return hashlib.sha256(b).hexdigest().upper()
def word(b,p): return struct.unpack_from('<I',b,p)[0]

def main():
    original=ZipFile(ROOT/'00_original/arc.zip').read('PSX.EXE')
    current=ZipFile(ROOT/'03_output/arc1_v375_next_choice_TEST_ONLY.zip').read('PSX.EXE')
    inventory=json.loads((HERE/'ui_inventory.json').read_text(encoding='utf-8'))
    masks={}
    for r in inventory:
        p=int(r['pointer_offset'],0)
        for i in range(p,p+4): masks[i]='CATALOG_POINTER'
        for field,h in [('original_pointer','original_hex'),('current_pointer','current_hex')]:
            p=int(r[field],0)-BIAS
            end=(p+len(bytes.fromhex(r[h]))+1+3)//4*4
            for i in range(p,end): masks.setdefault(i,'CATALOG_OR_CURRENT_TEXT_AND_ALIGNMENT')
    # Do not treat this approximate mask as proof that every covered byte is text.
    initial=set(masks)
    for p in range(0x78000,0x83000,4):
        if word(original,p)-BIAS in initial:
            for i in range(p,p+4):masks.setdefault(i,'POINTER_TO_CATALOG_FOOTPRINT_CANDIDATE')
    defects=[
        dict(id='nontext:79210',start=0x79210,end=0x79214,status='CONFIRMED_DEFECT',
             finding='Action-handler table pointer 801A80E0 -> 801AE7E0; only byte79211 changed. Original destination is an 8-byte handler record whose first word is function8012F2F8. Current destination is outside the loaded EXE payload.',
             evidence='Outer table8018FB6C actor85 ->801A7D88 ->801A80F8; initializer8012176C..217A4 reads descriptor+4 ->80193974 into actor+C0; command0x27 ->80193A10/file79210. 80121934..21960 dereferences selected handler record into actor+D4;8012198C executes it. Original handler8012F2F8 is replaced with whatever word is in BSS801AE7E0. Actor85 is Odon according to the sibling actor/skill census; actual game trigger pending.'),
        dict(id='nontext:7C1C0',start=0x7C1C0,end=0x7C1C2,status='CONFIRMED_DEFECT',
             finding='Sprite descriptor texture/page field changed 01E0 ->9CE1. It is not a text glyph.',
             evidence='8014C840 passes descriptor801969B8 to80132204; 8013225C reads descriptor+8; low6bits changes0x20->0x21; 80132268 shifts2 and stores object+2C. 80132328 also reads this field for texture setup. Exact on-screen effect remains untested.'),
        dict(id='nontext:7E0D0',start=0x7E0D0,end=0x7E0D2,status='CONFIRMED_DEFECT',
             finding='Sound/voice ID480 becomes signed -25375 and is rejected by the range guard, suppressing that sound entry.',
             evidence='8015572C maps char index3, action state0x42 to table80198888+2*(3*10+6)=801988D0. 8015579C loads signed halfword; 801557C0 calls801298D0; 80129880 sltiu ID<0x232 rejects0xFFFF9CE1. No out-of-bounds sound lookup occurs because guard returns0.'),
        dict(id='nontext:7E7FC',start=0x7E7FC,end=0x7E7FE,status='CONFIRMED_DEFECT',
             finding='Color-animation first RGB key changes (224,48,48) to(225,210,48), corrupting the red transition color.',
             evidence='8015BEBC uses pointer bank801990B0, index7 ->pointer801990CC/file7E8CC ->80198FFC/file7E7FC; 80152C40 stores keyframe pointer object+58; 80152D24 uses stride8; +4 duration60,+6 flags3; 80152E18 interpolates RGB; 80152E34/38/3C and80152F14/18/1C consume RGB. Actual story trigger of bank index7 not traced.'),
    ]
    for d in defects:
        d['original_hex']=original[d['start']:d['end']].hex(' ')
        d['current_hex']=current[d['start']:d['end']].hex(' ')
        d['changed_offsets']=[hex(p) for p in range(d['start'],d['end']) if original[p]!=current[p]]
    suspect={i:d['id'] for d in defects for i in range(d['start'],d['end'])}
    rows=[]
    for p in range(0x78000,0x83000):
        if original[p]==current[p]:continue
        label=suspect.get(p,masks.get(p,'OUTSIDE_CATALOG_REVIEW_REQUIRED'))
        if 0x80210<=p<0x80222:label='INTENTIONAL_ICON_UV_TABLE'
        rows.append(dict(offset=f'0x{p:X}',original=f'{original[p]:02X}',current=f'{current[p]:02X}',classification=label))
    with (HERE/'nontext_pool_byte_census.csv').open('w',encoding='utf-8-sig',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
    md=capstone.Cs(capstone.CS_ARCH_MIPS,capstone.CS_MODE_MIPS32|capstone.CS_MODE_LITTLE_ENDIAN)
    code_ranges=[(0x8012176C,0x801217A8),(0x80121934,0x801219A4),(0x8014C838,0x8014C894),(0x80132204,0x8013236C),(0x8015572C,0x801557D4),
                 (0x80129880,0x80129904),(0x8015BE98,0x8015BEE8),(0x80152C40,0x80152F44)]
    code=[]
    for s,e in code_ranges:
        a,b=original[s-BIAS:e-BIAS],current[s-BIAS:e-BIAS]
        code.append(dict(start=hex(s),end_exclusive=hex(e),byte_exact=a==b,
                         original_sha256=sha(a),current_sha256=sha(b),
                         original_disassembly=[f'{i.address:08X} {i.mnemonic} {i.op_str}' for i in md.disasm(a,s)]))
    attrs=[]
    for group,start,stride,count in [('equipment',0x87568,6,64),('consumable',0x874E8,4,32)]:
        for index in range(count):
            s=start+index*stride;a,b=original[s:s+stride],current[s:s+stride]
            attrs.append(dict(group=group,index=index,offset=hex(s),original_hex=a.hex(' '),current_hex=b.hex(' '),byte_exact=a==b))
    assert len(attrs)==96 and all(r['byte_exact'] for r in attrs)
    lineage=[]
    chosen={151,159,161,168,177,178,220,229,231,240,269,320,321,325,336,346,375}
    for f in ROOT.joinpath('03_output').glob('arc1_v*.zip'):
        m=re.match(r'arc1_v(\d+)',f.name)
        if not m or int(m.group(1)) not in chosen or 'delta' in f.name:continue
        try:
            with ZipFile(f) as z:b=z.read('PSX.EXE')
        except (KeyError,ValueError):continue
        lineage.append(dict(build=int(m.group(1)),filename=f.name,exe_sha256=sha(b),
                            values={d['id']:b[d['start']:d['end']].hex(' ') for d in defects}))
    result=dict(scope='Every differing byte in original EXE file78000..82FFF, original/current catalog footprint masks; masks are triage, not proof of text semantics.',
                original_exe_sha256=sha(original),current_exe_sha256=sha(current),
                changed_byte_count=len(rows),structural_changed_bytes=sum(len(d['changed_offsets']) for d in defects),
                defects=defects,code_evidence=code,attributes=attrs,lineage=sorted(lineage,key=lambda r:(r['build'],r['filename'])),
                exclusions=['80210..80221 is intentional icon UV table; see build_ui_safe_v38/v39 and build_arc1_v177_restore_circle_icon.py.',
                            'Catalog/current-text masks include rounded alignment bytes and are only triage; all other residuals are explicit in CSV.',
                            'Extra short UI, native HUD, reused text pools and injected helper code are reviewed separately by parent; their changed bytes are not assumed corrupt.'])
    (HERE/'nontext_pool_followup.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
    lines=['# V375 nontext pool gap census','',result['scope'],'',f'Changed bytes: {len(rows)}. Four confirmed structural-change groups / 7 altered bytes, all with proven nontext consumers. All 96 equipment/consumable attribute records are byte-exact.','']
    for d in defects:
        lines += ['## '+d['id']+' / '+d['status'],'',d['finding'],'',d['evidence'],'']
    lines += ['## Cause and lineage','',
              'Color change first appears in V178 relative to its direct V177 base. V178 scans glyph-looking pointer targets and accepts the color keyframe as text. The three other changes are intact in V229 and damaged by available V231. V231 text_regions treats every NUL-separated nonempty run of EXE78000..83000 as text, including pointers and numeric data. Full values and EXE hashes per available build are in JSON. V159 had a different earlier color rewrite that V161 removed; do not confuse that repaired occurrence with V178 reintroduction.','',
              'The icon table at80210..80221 is deliberately changed; exclude its five differing U bytes from the corruption count. The four structural groups contain 1+2+2+2=7 differing bytes. No ROM or canonical data changed.','',
              '## Scope limits','',
              'This is a complete byte-difference census for the declared 0xB000-byte pool, not a claim that every unknown original data type has been proven safe. CSV retains every changed byte and every unresolved residual explicitly. Attribute integrity covers all64+32 entries, not every downstream effect or name-consumer mapping in the game. Existing 192-row semantic review and mechanic followup handle translation discrepancies independently.','',
              'Next: parent should prove actual event reachability and perform CPU/game regression tests, then approve concrete byte restoration together with broad text-region exclusion. Reproduce with python 01_work/analysis/v375_full_audit/audit_nontext_pool.py.']
    (HERE/'nontext_pool_followup.md').write_text('\n'.join(lines)+'\n',encoding='utf-8')
    print(json.dumps(dict(changed_bytes=len(rows),structural_changed_bytes=result['structural_changed_bytes'],attributes_exact=len(attrs),code_byte_exact=[r['byte_exact'] for r in code])))

if __name__=='__main__':main()
