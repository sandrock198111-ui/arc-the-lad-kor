"""Cumulative V377 fixes, using V376 captures only as symptom evidence."""
import io,json,struct
from zipfile import ZipFile
import build_arc1_v377_user_reports as previous
import build_arc1_v376_hotfix as b
from v376_dat_targets import parts
ROOT=b.ROOT;ORIGINAL=b.ORIGINAL;ORIGINAL_PIN=b.ORIGINAL_PIN
BASE=previous.OUT;PIN='16FE8214E4E96EA80B12445A8819A0460B881A1F52B6E9DDFCE268CA59CCA6EC'
OUT=ROOT/'03_output/arc1_v378_followup_TEST_ONLY.zip';AN=ROOT/'01_work/analysis/v378_followup';digest=b.digest
TUTORIAL_ROWS=(437,833,1423,1633,1868,2217)
TUTORIAL='초핀:   경험치를 두 배로 주는|「비단 허리띠」는 누구나|착용할 수 있습니다.'
CHOICES={2464:'난 언제든 좋아.|<CTRL:E503>좋아|<CTRL:E503>역시 그만둘래',
         2465:'나한테 맡겨!|<CTRL:E503>좋아|<CTRL:E503>역시 그만둘래'}
CURSOR_ROW=2460

def prepare():
    assert digest(BASE.read_bytes())==PIN and previous.prepare()[0]==BASE.read_bytes()
    old=b.members(BASE);new=dict(old);pristine=b.members(ORIGINAL)
    table,encode=b.encoder(old['PSX.EXE']);decode=b.audit.make_decoder(old['PSX.EXE'])
    rows=b.audit.rows(ROOT/'05_docs/script_original_full.csv');plans={};applied=[]
    for n in (*TUTORIAL_ROWS,*CHOICES):
        row=rows[n-1];name=row['source file'];at=int(row['byte offset'],0);room=len(bytes.fromhex(row['raw bytes as hex']))
        data=old[name];before=decode(b''.join(b.previous.read_tokens(data,at,room)))[0]
        if n in TUTORIAL_ROWS:
            assert before.startswith('초핀:') and '「비단 허리띠」' in before
            assert all(t[0] not in (0xe2,0xe4,0xe5,0xe7,0xe8) for t in b.codec.tokens(data[at:at+room]))
            raw=encode(TUTORIAL);assert len(raw)<=room,(n,len(raw),room)
            copy=bytearray(new[name]);copy[at:at+room]=raw+b'\xa1'*(room-len(raw));new[name]=bytes(copy);target=TUTORIAL
        else:
            if name not in plans:plans[name]=b.previous.Planner(name,data,pristine[name],table)
            plan=plans[name];target=CHOICES[n];texts,controls=parts(target);oldtexts,oldcontrols=parts(before)
            assert controls==oldcontrols
            p=start=at;spans=[];actual=[]
            while p<at+room:
                w=1 if data[p]<0xdd else 2;t=data[p:p+w]
                if t[0]==0xe2:
                    loc=b.previous.slot_pos(b.previous.b.slot_of_disk(t[1]));p+=2+data[loc+127];continue
                if t[0] in b.previous.b.STRUCTURAL_LEADS:
                    spans.append((start,p-start));actual.append(t);start=p+w
                p+=w
            spans.append((start,at+room-start));assert actual==controls and len(spans)==len(texts)
            for (pos,length),a,z in zip(spans,oldtexts,texts):
                if a.strip()!=z.strip():plan.place(pos,length,z.strip(),str(n))
        applied.append(dict(row=n,file=name,offset=at,length=room,before=before,target=target,
                            original_japanese=row['decoded Japanese']))
    for name,plan in plans.items():new[name]=bytes(plan.data)
    # Only the proven per-dialogue type6 baseRow operand moves the cursor.
    row=rows[CURSOR_ROW-1];name=row['source file'];at=int(row['byte offset'],0);room=len(bytes.fromhex(row['raw bytes as hex']))
    end=at+room;event=(end+3)&~1;expected=bytes.fromhex('2100060004000500020000000100')
    assert old[name][event:event+14]==expected
    copy=bytearray(new[name]);copy[event+12:event+14]=b'\x02\0';new[name]=bytes(copy)
    cursor=dict(row=CURSOR_ROW,file=name,source_offset=at,length=room,event=event,offset=event+12,before=1,after=2)
    full_old={**pristine,**old};full_new={**pristine,**new};changed_rows=[]
    for n,row in enumerate(rows,1):
        name=row['source file'];at=int(row['byte offset'],0);room=len(bytes.fromhex(row['raw bytes as hex']))
        a=b.previous.read_tokens(full_old[name],at,room);z=b.previous.read_tokens(full_new[name],at,room)
        if a!=z:changed_rows.append(n)
    assert changed_rows==sorted((*TUTORIAL_ROWS,*CHOICES)),changed_rows
    for r in applied:
        got=decode(b''.join(b.previous.read_tokens(new[r['file']],r['offset'],r['length'])))[0]
        assert ''.join(got.split())==''.join(r['target'].split()),(r['row'],got)
    canonical=b.audit.rows(ROOT/'05_docs/script_translated_full.csv')
    for r in applied:assert canonical[r['row']-1]['korean']==r['target'].replace('<CTRL:E503>',''),r['row']
    assert new['PSX.EXE']==old['PSX.EXE'] and new['COMM.IMG']==old['COMM.IMG']
    writes=[]
    for name,data in new.items():
        for h in b.previous.hunks(old[name],data):writes.append(dict(file=name,offset=h['at'],before=h['before'],after=h['after']))
    with ZipFile(BASE) as z:infos=z.infolist();comment=z.comment
    buf=io.BytesIO()
    with ZipFile(buf,'w') as z:
        z.comment=comment
        for info in infos:z.writestr(info,new[info.filename])
    blob=buf.getvalue()
    return blob,dict(zip_sha256=digest(blob),base_sha256=PIN,static_pass=True,applied=applied,cursor=cursor,
        writes=writes,changed_bytes=sum(len(bytes.fromhex(w['after'])) for w in writes),
        changed_members=sorted({w['file'] for w in writes}),unchanged_dialogue_rows=len(rows)-len(changed_rows),runtime_verified=False)

def verify(blob):
    result=previous.verify(blob)
    from verify_arc1_v378_followup import verify as captures
    result['followup_captures']=captures(blob)
    return result

def main():
    AN.mkdir(exist_ok=True);blob,r=prepare();assert prepare()[0]==blob;r['cpu']=verify(blob)
    if OUT.exists():assert OUT.read_bytes()==blob
    else:OUT.write_bytes(blob)
    (AN/'build_report.json').write_text(json.dumps(r,ensure_ascii=False,indent=2),encoding='utf-8')
    print(r['zip_sha256'],r['changed_bytes'],r['changed_members'])
if __name__=='__main__':main()
