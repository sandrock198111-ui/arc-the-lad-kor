"""V379 cumulative dialogue pauses and button help corrections."""
import io,json,struct
from zipfile import ZipFile
import build_arc1_v379_spirit_reports as previous
b=previous.b;ROOT=b.ROOT;ORIGINAL=b.ORIGINAL;ORIGINAL_PIN=b.ORIGINAL_PIN;digest=b.digest
BASE=previous.OUT;PIN='B1B3BC98BB886B666759D8806F26650BE73D4D39C4C8C74B93611D02CC06921F'
OUT=ROOT/'03_output/arc1_v380_followup_TEST_ONLY.zip';AN=ROOT/'01_work/analysis/v380_followup'
TEXT={635:'전하, 정신 차리십시오.',2323:'아나운서: 범인은 토우빌 마을 출신 아크 에다 리코르누를 우두머리로 한 일당 7명으로,'}
PAUSES={644:['스메리아 왕: 형에게','.','..',' 사과',' 한마디라도',' 하고',' 싶','었','다','.','.','..'],
        648:['서두르지 못하겠느냐!',' 이런 곳에서 죽는 건 싫다고!',''],
        649:['안 돼!',' 아래 계단이 무너져 버렸어!','']}
UI='L R 대상변경'

def prepare():
    assert digest(BASE.read_bytes())==PIN and previous.prepare()[0]==BASE.read_bytes()
    old=b.members(BASE);new=dict(old);original=b.members(ORIGINAL);table,encode=b.encoder(old['PSX.EXE'])
    decode=b.audit.make_decoder(old['PSX.EXE']);rows=b.audit.rows(ROOT/'05_docs/script_original_full.csv');plans={};applied=[]
    for n in sorted((*TEXT,*PAUSES)):
        r=rows[n-1];fn=r['source file'];at=int(r['byte offset'],0);room=len(bytes.fromhex(r['raw bytes as hex']))
        if fn not in plans:plans[fn]=b.previous.Planner(fn,old[fn],original[fn],table)
        p=plans[fn];before=decode(b''.join(b.previous.read_tokens(old[fn],at,room)))[0]
        if n in TEXT:
            target=TEXT[n];assert not previous.parts(before)[1];p.place(at,room,target,str(n));controls=[]
        else:
            controls=[t for _,t in previous.boundaries(original[fn],at,room)[1] if t[0]==0xe4]
            chunks=PAUSES[n];assert len(chunks)==len(controls)+1
            output=bytearray();target='';last_text=max(i for i,t in enumerate(chunks) if t);last_allocation=None
            for i,text in enumerate(chunks):
                raw=encode(text)
                if len(raw)<=2 and i!=last_text:output+=raw
                else:
                    a=p.allocate(raw,0,str(n)+':'+str(i))
                    if i==last_text:last_allocation=(len(output),a)
                    output+=bytes((0xe2,a.disk_id))
                target+=text
                if i<len(controls):output+=controls[i];target+=f'<CTRL:{controls[i].hex().upper()}>'
            assert len(output)<=room,(n,len(output),room)
            padding=room-len(output);pos,a=last_allocation
            assert len(a.users)==1
            p.data[p._slot_offset(a.bank,a.slot)+127]=padding
            output[pos+2:pos+2]=b'\xa1'*padding
            p.data[at:at+room]=output
        applied.append(dict(row=n,file=fn,offset=at,length=room,before=before,target=target,original_japanese=r['decoded Japanese'],pauses=[t.hex() for t in controls]))
    for fn,p in plans.items():new[fn]=bytes(p.data)
    exe=bytearray(old['PSX.EXE']);ptr=struct.unpack_from('<I',exe,0x82348)[0];at=ptr-0x8011a800
    end=exe.index(0,at);assert exe[at:at+4]==bytes.fromhex('e707e706')
    raw=encode(UI);assert len(raw)<=end-at,(len(raw),end-at)
    exe[at:end+1]=(raw+b'\0').ljust(end-at+1,b'\0');new['PSX.EXE']=bytes(exe)
    ui=dict(pointer_offset=0x82348,offset=at,before=old['PSX.EXE'][at:end+1].hex(),target=UI,length=end-at)
    for r in applied:
        fn,at,room=r['file'],r['offset'],r['length'];tokens=b.previous.read_tokens(new[fn],at,room)
        assert ''.join(decode(b''.join(tokens))[0].split())==''.join(r['target'].split())
        assert [t.hex() for t in tokens if t[0]==0xe4]==r['pauses']
        assert new[fn][at+room:at+room+2]==old[fn][at+room:at+room+2]
    changed=[]
    for n,r in enumerate(rows,1):
        fn=r['source file'];at=int(r['byte offset'],0);sz=len(bytes.fromhex(r['raw bytes as hex']))
        if b.previous.read_tokens(old.get(fn,original[fn]),at,sz)!=b.previous.read_tokens(new.get(fn,original[fn]),at,sz):changed.append(n)
    assert changed==sorted((*TEXT,*PAUSES)),changed
    writes=[dict(file=fn,offset=h['at'],before=h['before'],after=h['after']) for fn,d in new.items() if d!=old[fn] for h in b.previous.hunks(old[fn],d)]
    with ZipFile(BASE) as z:infos=z.infolist();comment=z.comment
    buf=io.BytesIO()
    with ZipFile(buf,'w') as z:
        z.comment=comment
        for info in infos:z.writestr(info,new[info.filename])
    blob=buf.getvalue()
    return blob,dict(zip_sha256=digest(blob),base_sha256=PIN,static_pass=True,applied=applied,ui=ui,writes=writes,
        changed_bytes=sum(len(bytes.fromhex(w['after'])) for w in writes),changed_members=sorted({w['file'] for w in writes}),runtime_verified=False)

def verify(blob):
    r=previous.verify(blob)
    from verify_arc1_v380_followup import verify as cases
    r['followup_v380']=cases(blob)
    return r

def main():
    blob,r=prepare();assert prepare()[0]==blob;r['cpu']=verify(blob)
    if OUT.exists():assert OUT.read_bytes()==blob
    else:OUT.write_bytes(blob)
    (AN/'build_report.json').write_text(json.dumps(r,ensure_ascii=False,indent=2),encoding='utf-8')
    print(r['zip_sha256'],r['changed_bytes'])
if __name__=='__main__':main()
