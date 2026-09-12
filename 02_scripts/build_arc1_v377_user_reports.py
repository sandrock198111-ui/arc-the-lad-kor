"""V376-based fixes for the eight supplied 69D03814 states."""
import io,json,struct
from zipfile import ZipFile
import build_arc1_v376_hotfix as b
ROOT=b.ROOT;ORIGINAL=b.ORIGINAL;ORIGINAL_PIN=b.ORIGINAL_PIN
BASE=b.OUT;PIN='B2197E829FA33C0766EE13BB3BA5C98E05CBEBACD495296E81C105BA16113A46'
OUT=ROOT/'03_output/arc1_v377_user_reports_TEST_ONLY.zip'
AN=ROOT/'01_work/analysis/v377_user_reports';digest=b.digest
UI={0x80B0C:'적이 거의 확실히|아이템을 떨어뜨림',
    0x80AD0:'레벨업 시 최대 체력|증가량 상승',
    0x82354:'스킬을 선택하세요',0x8236C:'비어 있는 곳을 선택하세요'}
DAT={2275:('8/S8061.DAT',0x47CD6,'자기들이','본인들이'),
     2279:('8/S8061.DAT',0x47EBE,'후진','후우진')}

def prepare():
    assert digest(BASE.read_bytes())==PIN and b.prepare()[0]==BASE.read_bytes()
    old=b.members(BASE);new=dict(old);exe=old['PSX.EXE'];table,encode=b.encoder(exe)
    # Preserve the entire baseline, including the original-structure repairs.
    pointer=lambda p:struct.unpack_from('<I',exe,p)[0]
    catalog=b.audit.rows(b.audit.AN/'ui_inventory.csv')
    strings={int(r['pointer_offset'],0):b.storage.string_at(exe,pointer(int(r['pointer_offset'],0))) for r in catalog}
    spans=[]
    for p in UI:
        a=pointer(p);raw=strings[p]
        outside=[q for q in range(0,len(exe)-3,4) if a<=pointer(q)<a+len(raw)+1 and q not in UI]
        assert not outside,(hex(p),list(map(hex,outside)))
        assert not any(a<=v<a+len(raw)+1 for v in b.immediate_refs(exe)),hex(p)
        spans.append((a,a+len(raw)+1))
    free=[]
    for a,z in sorted(spans):
        if free and a<=free[-1][1]:free[-1]=(free[-1][0],max(z,free[-1][1]))
        else:free.append((a,z))
    result=bytearray(exe);ui=[]
    for p,text in sorted(UI.items(),key=lambda x:-len(encode(x[1]))):
        raw=encode(text);size=len(raw)+1
        choices=[(z-a-size,i,a,z) for i,(a,z) in enumerate(free) if z-a>=size]
        assert choices,(text,size,free)
        _,i,a,z=min(choices);free[i]=(a+size,z)
        off=b.storage.file_offset(a);result[off:off+size]=raw+b'\0';struct.pack_into('<I',result,p,a)
        ui.append(dict(pointer=p,before=strings[p].hex(),target=text,after=raw.hex(),address=a))
    for p,raw in strings.items():
        if p not in UI:assert b.storage.string_at(result,pointer(p))==raw,hex(p)
    new['PSX.EXE']=bytes(result)
    decode=b.audit.make_decoder(exe);rows=b.audit.rows(ROOT/'05_docs/script_original_full.csv')
    planner=b.previous.Planner('8/S8061.DAT',old['8/S8061.DAT'],b.members(ORIGINAL)['8/S8061.DAT'],table)
    dat=[]
    for n,(name,at,a,z) in DAT.items():
        row=rows[n-1];assert row['source file']==name and int(row['byte offset'],0)==at
        room=len(bytes.fromhex(row['raw bytes as hex']));raw=b''.join(b.previous.read_tokens(old[name],at,room))
        text,unknown=decode(raw);assert not unknown and text.count(a)==1
        target=text.replace(a,z);planner.place(at,room,target,str(n))
        dat.append(dict(row=n,file=name,offset=at,length=room,before=text,target=target))
    new['8/S8061.DAT']=bytes(planner.data)
    for r in dat:
        raw=b''.join(b.previous.read_tokens(new[r['file']],r['offset'],r['length']))
        assert decode(raw)[0].strip()==r['target']
    canonical=b.audit.rows(ROOT/'05_docs/script_translated_full.csv')
    assert len(canonical)==2878
    for r in dat:assert canonical[r['row']-1]['korean']==r['target'],('Canonical drift',r['row'])
    assert all('후진' not in r['korean'] for r in canonical),'Canonical proper-name regression'
    checked=0;names=[]
    pristine=b.members(ORIGINAL);full_old={**pristine,**old};full_new={**pristine,**new}
    for n,r in enumerate(rows,1):
        name=r['source file'];at=int(r['byte offset'],0);room=len(bytes.fromhex(r['raw bytes as hex']))
        a=b.previous.read_tokens(full_old[name],at,room);z=b.previous.read_tokens(full_new[name],at,room)
        if n not in DAT:assert a==z,n;checked+=1
        text=decode(b''.join(z))[0];assert '후진' not in text,(n,text)
        if '후우진' in text:names.append(dict(row=n,text=text))
    for r in catalog:
        p=int(r['pointer_offset'],0);text=decode(b.storage.string_at(result,struct.unpack_from('<I',result,p)[0]))[0]
        assert '후진' not in text,r['id']
        if '후우진' in text:names.append(dict(id=r['id'],text=text))
    glyphs=[]
    for ch in '본인들이후우진':
        token=table[ch];idx=b.codec._resolve_index(result,token)
        assert idx is not None and any(b.font.read_plane(new['COMM.IMG'],idx)),(ch,idx)
        glyphs.append(dict(char=ch,token=token.hex(),physical=idx))
    writes=[]
    for name,data in new.items():
        for h in b.previous.hunks(old[name],data):writes.append(dict(file=name,offset=h['at'],before=h['before'],after=h['after']))
    with ZipFile(BASE) as z:infos=z.infolist();comment=z.comment
    buf=io.BytesIO()
    with ZipFile(buf,'w') as z:
        z.comment=comment
        for info in infos:z.writestr(info,new[info.filename])
    blob=buf.getvalue()
    return blob,dict(zip_sha256=digest(blob),base_sha256=PIN,static_pass=True,ui=ui,dat=dat,glyphs=glyphs,
        names=names,unchanged_dialogue_rows=checked,writes=writes,changed_members=sorted({w['file'] for w in writes}),
        changed_bytes=sum(len(bytes.fromhex(w['after'])) for w in writes),runtime_verified=False)

def verify(blob):
    # V376 structural, water-temple, actor, panel and cursor/choice regressions.
    result=b.verify(blob)
    from verify_arc1_v377_reports import verify as captures
    result['user_captures']=captures(blob)
    return result

def main():
    AN.mkdir(parents=True,exist_ok=True);blob,r=prepare();assert prepare()[0]==blob
    r['cpu']=verify(blob)
    if OUT.exists():assert OUT.read_bytes()==blob
    else:OUT.write_bytes(blob)
    (AN/'build_report.json').write_text(json.dumps(r,ensure_ascii=False,indent=2),encoding='utf-8')
    print(r['zip_sha256'],r['changed_bytes'],r['changed_members'])
if __name__=='__main__':main()
