"""V376 corrective build from pristine members plus the pinned V375 delta.

Only audited source rows, pointer-owned text and two proven unused font aliases
are writable. All changes are planned in memory before any output is emitted.
"""
import csv,io,json,struct,sys,re
from pathlib import Path
from zipfile import ZipFile,ZIP_DEFLATED
from collections import Counter,defaultdict
sys.dont_write_bytecode=True
import audit_arc1_v375_full_inventory as audit
import v354_dialogue_codec as codec
import build_arc1_v320_hanme_static_recovery as font
import build_arc1_v359_thin_font_preview as sans
import build_arc1_v359_review_all as previous
import build_arc1_v360_ui_restore as storage
from v376_ui_targets import TARGETS,ALIASES,PRESERVE_RELOCATE

ROOT=audit.ROOT;ORIGINAL=audit.ORIGINAL;BASE=audit.BASE
ORIGINAL_PIN='AE9F4366A1E7DA3805BB3BED3DDA9567E4CD4E669AF890E4E2A620D7861F11DD'
PIN='AD9ED2B9E898F05C2EC5C78ABBA4253CE052B7B4836DEE31D84108AD4256CFBB'
OUT=ROOT/'03_output/arc1_v376_hotfix_TEST_ONLY.zip'
AN=ROOT/'01_work/analysis/v376_hotfix'
digest=audit.digest;BIAS=audit.BIAS
NEW_GLYPHS={'돈':765,'딜':816}
FONT_ZIP=Path('C:/Users/Administrator/.paseo/uploads/upload_1a60438a-45e6-4b32-b9dc-d1cdec784af5/8x4x4-fonts-all.zip')
RESTORED_ACTORS=(0x85454,0x85538)

def members(path):
    with ZipFile(path) as z:return {n:z.read(n) for n in z.namelist() if not n.endswith('/')}

def encoder(exe):
    _,_,table,_=codec.load_v354();table=dict(table)
    for ch,physical in NEW_GLYPHS.items():table[ch]=font.encode_index(physical)
    def encode(text):
        result=bytearray();p=0
        for match in re.finditer(r'\{E7:([0-9A-F]{2})\}',text):
            raw,missing=codec.encode(text[p:match.start()],table,True);assert not missing,(text,missing)
            result.extend(raw);result.extend(bytes([0xE7,int(match[1],16)]));p=match.end()
        raw,missing=codec.encode(text[p:],table,True);assert not missing,(text,missing)
        result.extend(raw);assert all(t[0]!=0 for t in codec.tokens(result))
        return bytes(result)
    return table,encode

def font_patch(old,all_files):
    exe,comm=old['PSX.EXE'],old['COMM.IMG'];uses=Counter()
    def add(raw):
        for t in codec.tokens(raw):
            if t[0] in (0xE2,0xE4,0xE5,0xE6,0xE7,0xE8):continue
            physical=codec._resolve_index(exe,t)
            if physical is not None:uses[physical]+=1
    ui=audit.rows(audit.AN/'ui_inventory.csv')
    for row in ui:add(bytes.fromhex(row['current_hex']))
    dat=audit.rows(audit.AN/'dat_ui_candidates.csv')
    for row in dat:add(bytes.fromhex(row['current_expanded_hex']))
    source=audit.rows(ROOT/'05_docs/script_original_full.csv')
    for row in source:
        add(b''.join(previous.read_tokens(all_files[row['source file']],int(row['byte offset'],0),len(bytes.fromhex(row['raw bytes as hex'])))))
    lookup={font.lookup_get(exe,i) for i in range(font.LOOKUP_SLOTS)}
    cell_rows=audit.rows(ROOT/'01_work/analysis/font_cell_audit_full/cell_consumers.csv')
    cell_audit={(int(r['row']),int(r['col'])):int(r['nontext_reads']) for r in cell_rows}
    assert digest(FONT_ZIP.read_bytes())==sans.FONT_ARCHIVE_SHA256
    with ZipFile(FONT_ZIP) as z:ttf=z.read('Sans_8x4x4.ttf')
    assert digest(ttf)=='A630598E7ACAB70DC6C6AC4D46DE59CEF25EF61A2FEEC439E8B25C7DDBA05726'
    pieces=sans.render_pieces(ttf);result=bytearray(comm);report=[]
    for ch,index in NEW_GLYPHS.items():
        assert uses[index]==0 and index not in lookup and font.safe_geometry(index,cell_audit),(ch,index)
        rows=sans.v320c.compose(pieces,ch,official=True);assert any(rows)
        font.put_plane(result,index,rows)
        report.append(dict(char=ch,physical=index,code=font.encode_index(index).hex(),
            previous_uses=uses[index],nontext_safe=True,lookup_references=0,
            old_rows=list(font.read_plane(comm,index)),new_rows=list(rows)))
    for i in range(1920):
        if i not in NEW_GLYPHS.values():assert font.read_plane(result,i)==font.read_plane(comm,i),i
    return bytes(result),report

def immediate_refs(exe):
    """Conservative veto of text-storage reuse, never proof by absence alone."""
    out=set()
    for p in range(0x800,0x78000,4):
        w=struct.unpack_from('<I',exe,p)[0];op=w>>26;rs=(w>>21)&31
        if op not in (9,13,32,33,35,36,37,40,41,43):continue
        low=w&0xffff
        if op!=13 and low&0x8000:low-=0x10000
        for q in range(p-4,max(0x7fc,p-64),-4):
            v=struct.unpack_from('<I',exe,q)[0]
            if v>>26==15 and (v>>16)&31==rs:
                out.add(((v&0xffff)<<16)+low);break
    return out

def ui_patch(before):
    catalog={r['id']:r for r in audit.rows(audit.AN/'ui_inventory.csv')}
    pointers={int(r['pointer_offset'],0) for r in catalog.values()}
    pointers.update([0x780DC,0x780E0,0x780E4,0x780FC,0x78244,0x82470,0x82534,0x82550,0x82558,0x825F0,0x825F4,0x825F8,0x82630,0x82634,0x8299C,0x82A68,0x82938,*range(0x82AE8,0x82B00,4)])
    pointers.update(PRESERVE_RELOCATE)
    ptr_addr=lambda p:struct.unpack_from('<I',before,p)[0]
    raw={p:storage.string_at(before,ptr_addr(p)) for p in pointers}
    table,encode=encoder(before)
    targets={}
    for key,text in TARGETS.items():
        p=int(key.split(':')[1],16) if key.startswith('extra_ui:') else int(catalog[key]['pointer_offset'],0)
        targets[p]=(key,text,encode(text))
    for p,skill in ALIASES.items():
        key=f'skill_name:{skill}';text=TARGETS.get(key,catalog[key]['current_korean'])
        targets[p]=(f'ui_pointer:{p:05X}',text,encode(text))
    for p,text in PRESERVE_RELOCATE.items():targets[p]=(f'preserve:{p:05X}',text,encode(text))
    assert len(targets)==104
    # Every affected or preserved pointer is a previously proven text consumer.
    refs=defaultdict(list)
    for p in range(0,len(before)-3,4):refs[ptr_addr(p)].append(p)
    immediates=immediate_refs(before)
    byraw=defaultdict(list)
    for p,r in raw.items():
        address=ptr_addr(p);at=storage.file_offset(address)
        if not(RESTORED_ACTORS[0]<=at<RESTORED_ACTORS[1]):byraw[r].append(address)
    desired={r for _,_,r in targets.values()}
    placed={r:min(byraw[r]) for r in desired if r in byraw}
    locked=set(placed.values())
    free=[];excluded=[]
    for p in targets:
        address=ptr_addr(p);r=raw[p];end=address+len(r)+1;at=storage.file_offset(address)
        if address in locked or RESTORED_ACTORS[0]<=at<RESTORED_ACTORS[1]:continue
        if len(r)==0:continue
        external=[(a,ps) for a,ps in refs.items() if address<=a<end and any(q not in targets for q in ps)]
        direct=[a for a in immediates if address<=a<end]
        if external or direct:
            excluded.append(dict(pointer=hex(p),address=hex(address),external=external,direct=list(map(hex,direct))))
            continue
        free.append((address,end))
    # Merge only overlapping/adjacent explicitly owned bytes, never NUL gaps.
    merged=[]
    for start,end in sorted(set(free)):
        if merged and start<=merged[-1][1]:merged[-1]=(merged[-1][0],max(end,merged[-1][1]))
        else:merged.append((start,end))
    free=merged;new=bytearray(before);allocations=[]
    for r in sorted(desired-set(placed),key=lambda x:(-len(x),x)):
        size=len(r)+1;options=[(e-s-size,i,s,e) for i,(s,e) in enumerate(free) if e-s>=size]
        if not options:raise ValueError(('UI text storage exhausted',size,sum(e-s for s,e in free),r.hex(),excluded))
        _,i,start,end=min(options);placed[r]=start;free[i]=(start+size,end)
        at=storage.file_offset(start);new[at:at+size]=r+b'\0'
        allocations.append(dict(address=hex(start),file_offset=at,length=size,payload=r.hex()))
    records=[]
    for p,(key,text,r) in targets.items():
        struct.pack_into('<I',new,p,placed[r]);assert storage.string_at(new,placed[r])==r
        if 'description:' in key:
            metrics=storage.layout(r)
            assert metrics['rows']<=(1 if key.startswith('skill') else 2), (key,text,metrics)
        records.append(dict(id=key,pointer=hex(p),before_pointer=hex(ptr_addr(p)),after_pointer=hex(placed[r]),
            before_hex=raw[p].hex(),after_hex=r.hex(),target=text))
    for p,r in raw.items():
        if p not in targets:
            assert before[p:p+4]==new[p:p+4]
            assert storage.string_at(new,ptr_addr(p))==r,hex(p)
    return bytes(new),records,dict(allocations=allocations,remaining_owned_bytes=sum(e-s for s,e in free),excluded=excluded)

def prepare():
    assert digest(ORIGINAL.read_bytes())==ORIGINAL_PIN and digest(BASE.read_bytes())==PIN
    pristine=members(ORIGINAL);old=members(BASE)
    # Materialize from immutable originals; inherited byte delta is explicitly
    # derived from the hash-pinned successful baseline, not a modified work tree.
    new={}
    for name,want in old.items():
        source=pristine[name]
        if len(source)!=len(want):new[name]=want;continue
        copy=bytearray(source)
        for h in previous.hunks(source,want):
            at=h['at'];a=bytes.fromhex(h['before']);b=bytes.fromhex(h['after'])
            assert copy[at:at+len(a)]==a;copy[at:at+len(a)]=b
        assert copy==want;new[name]=bytes(copy)
    new['PSX.EXE'],ui,allocation=ui_patch(old['PSX.EXE'])
    new['COMM.IMG'],glyphs=font_patch(old,{**pristine,**old})
    event=json.loads((audit.AN/'event_integrity.json').read_text(encoding='utf-8'))
    repairs=[]
    for proof in event['proofs']:
        name=proof['file'];at=int(proof['source_offset'],0)
        expected=bytes.fromhex(proof['current_source_hex']);source=bytes.fromhex(proof['original_source_hex'])
        assert len(source)==len(expected)==3
        assert old[name][at:at+3]==expected and pristine[name][at:at+3]==source
        copy=bytearray(new[name]);copy[at:at+3]=source;new[name]=bytes(copy)
        repairs.append(dict(file=name,offset=at,before=expected.hex(),after=source.hex()))
    exe=bytearray(new['PSX.EXE'])
    for at,size in [(0x79210,4),(0x7C1C0,2),(0x7E0D0,2),(0x7E7FC,3),(RESTORED_ACTORS[0],RESTORED_ACTORS[1]-RESTORED_ACTORS[0])]:
        exe[at:at+size]=pristine['PSX.EXE'][at:at+size]
    new['PSX.EXE']=bytes(exe)
    from v376_dat_targets import apply as apply_dat
    dat=apply_dat(old,new,pristine,encoder(exe)[0],audit)
    covered=[(r['file'],r['offset'],r['offset']+r['length']) for r in dat['applied']]
    covered.extend((r['file'],r['offset'],r['offset']+3) for r in repairs)
    preserved=0
    all_old={**pristine,**old};all_new={**pristine,**new}
    for row in audit.rows(ROOT/'05_docs/script_original_full.csv'):
        name=row['source file'];at=int(row['byte offset'],0);room=len(bytes.fromhex(row['raw bytes as hex']))
        if any(name==n and at<end and start<at+room for n,start,end in covered):continue
        assert previous.read_tokens(all_old[name],at,room)==previous.read_tokens(all_new[name],at,room),(name,hex(at),'unrelated dialogue changed')
        preserved+=1
    unknown_dat={r['id'] for r in audit.rows(audit.AN/'dat_ui_review.csv') if r['status']=='NEEDS_SOURCE_CONFIRMATION'}
    for row in audit.rows(audit.AN/'dat_ui_candidates.csv'):
        name=row['file'];at=int(row['offset']);end=int(row['end'])
        if any(name==n and at<z and a<end for n,a,z in covered):continue
        if row['expansion_error'] or row['id'] in unknown_dat:
            assert all_old[name][at:end]==all_new[name][at:end],row['id']
            continue
        assert previous.read_tokens(all_old[name],at,end-at)==previous.read_tokens(all_new[name],at,end-at),(row['id'],'unrelated DAT UI changed')
        preserved+=1
    dat['unchanged_body_checks']=preserved
    # Restoring original actor records must not destroy the relocated UI text.
    for r in ui:assert storage.string_at(exe,int(r['after_pointer'],0))==bytes.fromhex(r['after_hex'])
    writes=[]
    for name,data in new.items():
        assert len(data)==len(old[name])
        for h in previous.hunks(old[name],data):writes.append(dict(file=name,offset=h['at'],before=h['before'],after=h['after']))
    with ZipFile(BASE) as z:infos=z.infolist();comment=z.comment
    stream=io.BytesIO()
    with ZipFile(stream,'w',compression=ZIP_DEFLATED,compresslevel=9) as z:
        z.comment=comment
        for info in infos:z.writestr(info,new[info.filename])
    blob=stream.getvalue()
    report=dict(zip_sha256=digest(blob),base_sha256=PIN,static_pass=True,writes=writes,
        changed_members=sorted({w['file'] for w in writes}),changed_bytes=sum(len(bytes.fromhex(w['after'])) for w in writes),
        ui=ui,allocation=allocation,glyphs=glyphs,event_repairs=repairs,dat=dat,runtime_verified=False)
    return blob,report

def verify(blob):
    with ZipFile(io.BytesIO(blob)) as z:new={n:z.read(n) for n in z.namelist()}
    from verify_arc1_v360_ui_restore import verify_panels
    panels=verify_panels(new['PSX.EXE'],skill_height=42,mp_y=127)
    from verify_arc1_v359_cursor_lines import verify_cpu
    cursor=verify_cpu(new['PSX.EXE'],156)
    from build_arc1_v375_next_choice import verify as verify_choices
    choices=verify_choices(blob)
    import audit_arc1_v370_event_abort as event_cpu
    ram=bytearray(list(event_cpu.states())[1][2]);old=members(BASE)
    for h in previous.hunks(old['PSX.EXE'],new['PSX.EXE']):
        at=h['at'];raw=bytes.fromhex(h['after']);ram[0x11A800+at:0x11A800+at+len(raw)]=raw
    raw=new['8/S8041.DAT'][0x47800:0x49800]
    water=event_cpu.probe(ram,raw,0x110,stop_first=False)
    source=members(ORIGINAL)['8/S8041.DAT'][0x47800:0x49800]
    assert water==event_cpu.probe(ram,source,0x110,stop_first=False)
    assert water['return_value']==1 and water['opcodes']==[11,11,20,33],water
    # Reuse only the previously audited pure CPU functions, without running its
    # historical V375 report-writing module body.
    import ast
    path=audit.AN/'skill_integrity_followup.py';tree=ast.parse(path.read_text(encoding='utf-8'))
    functions=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in ('vm_for','flame_probe')]
    scope=dict(uc=event_cpu.uc,m=event_cpu.m,struct=struct)
    exec(compile(ast.Module(body=functions,type_ignores=[]),str(path),'exec'),scope)
    flame=scope['flame_probe'](new['PSX.EXE'])
    assert flame==scope['flame_probe'](members(ORIGINAL)['PSX.EXE']) and flame['refreshed_status']==0
    return dict(panels=panels,cursor=cursor,previous_choices=choices,water_temple=water,flame_actor=flame)

def main():
    AN.mkdir(parents=True,exist_ok=True)
    blob,report=prepare();assert prepare()[0]==blob
    report['cpu']=verify(blob)
    if OUT.exists():assert OUT.read_bytes()==blob,'Refusing overwrite'
    else:OUT.write_bytes(blob)
    (AN/'build_report.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps({k:v for k,v in report.items() if k not in ('writes','ui','allocation','glyphs','cpu','event_repairs','dat')},indent=2))

if __name__=='__main__':main()
