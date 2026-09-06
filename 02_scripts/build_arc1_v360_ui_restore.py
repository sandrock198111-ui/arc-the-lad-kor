"""Guarded V360 UI candidate. No new VRAM/resident allocation or font changes.

Input is the user's confirmed V359 cursor checkpoint, not an arbitrary latest
archive. The unused suffix of its retired cursor RLE is deliberately reused;
the following live numeric UI helper is an immutable boundary. CSVs are not
written by this builder. Runtime approval is separate from these tests.
"""
from pathlib import Path
from zipfile import ZipFile, ZIP_DEFLATED
import csv, json, struct
import build_arc1_v359_cursor_lines as cursor
import build_arc1_v324_static_ui_cursor_recovery as resident
import v354_dialogue_codec as codec
import review_editor as editor_module
import build_arc1_v357_user_reviewed_dialogue_bankb as dialogue
import build_arc1_v359_review_all as previous
from v360_ui_targets import TARGETS, LR_TEXT, DIALOGUE_TARGETS

ROOT=cursor.ROOT
BASE=cursor.OUT
PIN='84844764CE39B8B378496BAAB024A967AD9FAD3EE6FE17AABC871A59E49132C2'
OUT=ROOT/'03_output/arc1_v360_ui_restore_TEST_ONLY.zip'
AN=ROOT/'01_work/analysis/v360_panels'
BIAS=cursor.BIAS
HELPER=0x801FF5D0
END=0x801FF858
HEADER=0x801F031C

# Explicit instruction identity, not a global constant search/replacement.
IMMEDIATES=[
 (0x8016C53C,0x34040050,60,'item_default_x'),
 (0x8016C544,0x340600A0,200,'item_width'),
 (0x8016C54C,0x34070026,46,'item_height'),
 (0x80161A68,0x34040050,60,'skill_x'),
 (0x80161A70,0x340600A0,200,'skill_width'),
 (0x80161A78,0x34070034,46,'skill_height'),
 (0x8016C774,0x34050090,184,'description_width'),
 (0x8016C778,0x3406001C,34,'description_height'),
 (0x801620CC,0x34040056,66,'skill_mp_x'),
 (0x801620D0,0x34050089,133,'skill_mp_y'),
 (0x801640BC,0x24840014,0,'equipment_anchor_offset'),
 (0x80164B70,0x34040082,110,'consumable_right_x'),
 (0x80164B74,0x3404001E,10,'consumable_left_x'),
]

def file_offset(address):
    return resident.resident_source_offset(address) if resident.RESIDENT_BASE<=address<resident.HEAP_BASE else address-BIAS

def string_at(exe,address):
    p=file_offset(address);out=bytearray()
    for _ in range(256):
        if exe[p]==0:return bytes(out)
        n=1 if exe[p]<0xDD else 2
        out.extend(exe[p:p+n]);p+=n
    raise ValueError('unterminated UI string')

def layout(raw,width=184):
    x=0;rows=[0];glyphs=0
    for token in codec.tokens(raw):
        if token==codec.LINEBREAK:rows.append(0);x=0;continue
        assert token[0] not in (0xE2,0xE4,0xE5,0xE7,0xE8),token.hex()
        advance=6 if token==codec.SPACE_CODE else 14
        if x+advance>=width:rows.append(0);x=0
        x+=advance;rows[-1]=x
        if token!=codec.SPACE_CODE:glyphs+=1
    return {'rows':len(rows),'advance_widths':rows,'glyphs':glyphs}

def helper_code():
    asm=f'''.set noreorder
        lui $at, 0x801f
        ori $t0, $zero, 2
        sb $t0, 0x032c($at)
        addiu $sp, $sp, -32
        sw $ra, 24($sp)
        j 0x8016c768
        nop
    '''
    ks=cursor.Ks(cursor.KS_ARCH_MIPS,cursor.KS_MODE_MIPS32|cursor.KS_MODE_LITTLE_ENDIAN)
    code=bytes(ks.asm(asm,addr=HELPER)[0]);assert len(code)==28
    md=cursor.capstone.Cs(cursor.capstone.CS_ARCH_MIPS,cursor.capstone.CS_MODE_MIPS32|cursor.capstone.CS_MODE_LITTLE_ENDIAN)
    ins=list(md.disasm(code,HELPER));assert len(ins)==7
    assert bytes(ks.asm('.set noreorder\n'+'\n'.join(i.mnemonic+' '+i.op_str for i in ins),addr=HELPER)[0])==code
    return code,asm

def prepare():
    assert cursor.digest(BASE.read_bytes())==PIN
    assert cursor.digest(cursor.ORIGINAL.read_bytes())==cursor.ORIGINAL_SHA
    with ZipFile(BASE) as z:infos=z.infolist();old={i.filename:z.read(i) for i in infos}
    current=dict(old);before=old['PSX.EXE'];exe=bytearray(before)
    old_codec,_,table,reverse=codec.load_v354()
    catalog=list(csv.DictReader((ROOT/'05_docs/ui_full_v42.csv').open(encoding='utf-8-sig')))
    bykey={(r['table_key'],int(r['index'])):r for r in catalog}
    assert set(TARGETS)<=bykey.keys()
    writes=[];covered=set()

    def put(name,at,want):
        span=set(range(at,at+len(want)));assert not span&covered;covered.update(span)
        assert 0<=at<=len(exe)-len(want)
        writes.append({'name':name,'offset':at,'size':len(want),'before':before[at:at+len(want)].hex(),'after':want.hex()})
        exe[at:at+len(want)]=want

    def encode(text):
        raw,missing=codec.encode(text,table,True);assert not missing,(text,missing)
        for t in codec.tokens(raw):
            if t!=codec.LINEBREAK:assert codec._resolve_index(before,t)==codec._resolve_index(old_codec,t),(text,t.hex())
        assert all(t[0]!=0 for t in codec.tokens(raw))
        return raw

    assert cursor.word(before,resident.COPY_LENGTH_WORD_RAM-BIAS)==resident.EXPECTED_COPY_LENGTH_WORD
    assert cursor.word(before,resident.HEAP_BOUNDARY_WORD_RAM-BIAS)==resident.EXPECTED_HEAP_BOUNDARY_WORD
    assert before[0x2060:0x2064]==cursor.jal(cursor.DRAWOT)
    assert before[0x75590:0x75598]==cursor.jump(cursor.DRAWOT)+bytes(4)
    assert before[0x3E14:0x3E1C]==ZipFile(cursor.ORIGINAL).read('PSX.EXE')[0x3E14:0x3E1C]
    for address,expected,value,name in IMMEDIATES:
        at=address-BIAS;assert cursor.word(before,at)==expected,(name,hex(cursor.word(before,at)))
        put(name,at,struct.pack('<I',(expected&0xFFFF0000)|value))
    entry=0x8016C760-BIAS
    assert before[entry:entry+8]==bytes.fromhex('e0ffbd271800bfaf')
    put('description_line_extra_entry',entry,cursor.jump(HELPER)+bytes(4))
    code,asm=helper_code();payload=bytearray(code);restorations=[]

    def allocate(text):
        raw=encode(text);addr=HELPER+len(payload);payload.extend(raw+b'\0')
        assert HELPER+len(payload)<=END,('resident capacity',len(payload),END-HELPER)
        return addr,raw

    for key,text in TARGETS.items():
        r=bykey[key];ptr=int(r['pointer_offset'],0);oldptr=cursor.word(before,ptr)
        addr,raw=allocate(text);metrics=layout(raw)
        assert metrics['rows']<=2 and metrics['glyphs']<=32,(key,metrics)
        assert all(x+2<=184 for x in metrics['advance_widths']),(key,metrics)
        put(f'{key[0]}_{key[1]}',ptr,struct.pack('<I',addr))
        restorations.append({'table':key[0],'index':key[1],'source_extracted':r['japanese'],
          'before':' '.join(''.join(reverse.get(t,'<'+t.hex()+'>') for t in codec.tokens(string_at(before,oldptr))).split()),
          'target':text,'pointer_cell':ptr,'old_pointer':oldptr,'new_pointer':addr,'encoded_bytes':len(raw),**metrics})
    addr,raw=allocate(LR_TEXT)
    assert cursor.word(before,0x82360)==0x8019B702
    assert layout(raw,304)['rows']==1
    put('target_help_lr_pointer',0x82360,struct.pack('<I',addr))
    put('retired_cursor_rle_reuse',file_offset(HELPER),bytes(payload))
    assert before[file_offset(END):file_offset(END)+88]==exe[file_offset(END):file_offset(END)+88]
    assert before[file_offset(cursor.ENTRY):file_offset(HELPER)]==exe[file_offset(cursor.ENTRY):file_offset(HELPER)]
    assert len(exe)==len(before)
    assert all(i in covered for i,(x,y) in enumerate(zip(before,exe)) if x!=y)
    current['PSX.EXE']=bytes(exe)
    preserved=0
    for r in catalog:
        key=(r['table_key'],int(r['index']));ptr=int(r['pointer_offset'],0)
        if key not in TARGETS:
            assert before[ptr:ptr+4]==exe[ptr:ptr+4]
            p=cursor.word(before,ptr);assert string_at(before,p)==string_at(exe,p)
            preserved+=1
        if r['table_key']=='skill_description':
            metrics=layout(string_at(exe,cursor.word(exe,ptr)))
            assert metrics['rows']==1 and metrics['glyphs']<=32,(key,metrics)

    ed=editor_module.Editor.__new__(editor_module.Editor);ed.load()
    dialogue_records=[]
    for n,target in DIALOGUE_TARGETS.items():
        line=ed.lines[n-1];o=int(line.offset,0);blob=current[line.file]
        plan=previous.Planner(line.file,blob,ed.originals[line.file],ed.table)
        if n==1634:
            spans,controls=dialogue.structure(line.raw)
            assert spans==[(0,4),(6,26)] and controls==[(4,b'\xe6\x01')]
            parts=['이것 봐!','「방향전환 피리」를 얻었어!']
            for (lo,hi),part in zip(spans,parts):plan.place(o+lo,hi-lo,part,f'row {n}')
            assert plan.data[o+4:o+6]==blob[o+4:o+6]==b'\xe6\x01'
        else:
            # V358 already moved this whole row into one owned E2 slot.
            # Preserve its current caller, skip and flow; do not reinterpret the
            # original inline E6 inside the now-skipped caller area.
            assert blob[o:o+2]==bytes.fromhex('e281')
            plan.place(o,len(line.raw),target,f'row {n}')
            assert plan.data[o:o+len(line.raw)]==blob[o:o+len(line.raw)]
        result=bytes(plan.data)
        oldtokens=previous.read_tokens(blob,o,len(line.raw));ts=previous.read_tokens(result,o,len(line.raw))
        assert [t for t in oldtokens if t[0] in dialogue.STRUCTURAL_LEADS]==[t for t in ts if t[0] in dialogue.STRUCTURAL_LEADS]
        visible=''.join(reverse[t] for t in ts if t[0] not in dialogue.STRUCTURAL_LEADS)
        assert previous.compact(visible)==previous.compact(target),(n,visible,target)
        assert dialogue.wrapped_rows(encode(target))<=4
        for neighbor in ed.lines:
            if neighbor.file==line.file and neighbor.n!=n:
                a=int(neighbor.offset,0);size=len(neighbor.raw)
                assert previous.read_tokens(blob,a,size)==previous.read_tokens(result,a,size),neighbor.n
        current[line.file]=result
        dialogue_records.append({'row':n,'file':line.file,'target':target,'readback':visible,
          'active_control_count':sum(t[0] in dialogue.STRUCTURAL_LEADS for t in ts),'writes':previous.hunks(blob,result)})
    changed=[n for n in old if old[n]!=current[n]]
    assert set(changed)=={'PSX.EXE','6/S6021.DAT','F/SF0F1.DAT'}
    assert all(len(old[n])==len(current[n]) for n in old)
    report={'status':'STATIC CANDIDATE / RUNTIME PENDING / TEST_ONLY','base_sha256':PIN,
      'changed_members':changed,'new_vram_bytes':0,'new_reserved_ram_bytes':0,'new_glyphs':0,
      'resident_reused_bytes':len(payload),'resident_capacity':END-HELPER,'protected_numeric_helper':hex(END),
      'ui_items_reviewed':96,'ui_descriptions_changed':len(TARGETS),'other_catalog_entries_preserved':preserved,
      'panel_dimensions':[200,46],'description_dimensions':[184,34],'description_row_pitch':18,
      'lr_text':LR_TEXT,'ui_rows':restorations,'dialogue_rows':dialogue_records,'writes':writes,
      'held':['Equipment description 49: source does not explicitly identify damage; existing wording retained, effect needs gameplay confirmation.'],
      'helper_assembly':asm,'risks':['Requires cold boot; old save states contain old executable and resident payload.',
         'CPU/static checks do not replace real GPU clipping, inventory navigation and skill MP checks.',
         'Original gradient cursor appearance remains intentionally replaced by white lines.']}
    return infos,old,current,report

def main():
    infos,old,current,report=prepare()
    from verify_arc1_v359_cursor_lines import verify_cpu
    report['cursor_cpu']=verify_cpu(current['PSX.EXE'],156)
    from verify_arc1_v360_ui_restore import verify_panels
    report['panel_cpu']=verify_panels(current['PSX.EXE'])
    if OUT.exists():
        with ZipFile(OUT) as z:assert all(z.read(n)==current[n] for n in current),'existing output differs'
    else:
        with ZipFile(OUT,'w',compression=ZIP_DEFLATED,compresslevel=9) as z:
            for info in infos:z.writestr(info,current[info.filename],compress_type=ZIP_DEFLATED,compresslevel=9)
    with ZipFile(OUT) as z:assert z.namelist()==list(old) and all(z.read(n)==current[n] for n in current)
    from verify_arc1_v359_slot_recovery import legacy_gate
    a,b=legacy_gate(BASE),legacy_gate(OUT)
    assert a['fail']==b['fail'],'new legacy checker failure'
    report.update(zip_sha256=cursor.digest(OUT.read_bytes()),legacy_fail=b['fail'],legacy_counts_before=a['counts'],legacy_counts_after=b['counts'])
    AN.mkdir(parents=True,exist_ok=True)
    (AN/'build_report.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    print(OUT);print(report['zip_sha256']);print('UI rows',len(TARGETS),'resident bytes',report['resident_reused_bytes'])
    print({k:v for k,v in report['panel_cpu'].items() if k not in ('cases_detail','mp_cases')})

if __name__=='__main__':main()
