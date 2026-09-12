"""V380 cumulative completion of the reported scene pause restoration."""
import io,json,struct
from zipfile import ZipFile
import build_arc1_v380_followup as previous
b=previous.b;ROOT=b.ROOT;ORIGINAL=b.ORIGINAL;ORIGINAL_PIN=b.ORIGINAL_PIN;digest=b.digest
BASE=previous.OUT;PIN='13B3EBAF57DA63D06FED2F53C791BED304D3484F68D537356536B0241E0959E8'
OUT=ROOT/'03_output/arc1_v381_scene_pauses_TEST_ONLY.zip';AN=ROOT/'01_work/analysis/v381_scene_pauses'
TEXT={}
PAUSES={
631:['스메리아 왕: 대신에게...',' 안델에게 당했다...',''],
632:['스메리아 왕: 그놈은',' 로마리아가 보내온 자였다...',''],
633:['스메리아 왕: 이 나라에',' 몬스터를',' 불러들여',' 나라를 혼란에 빠뜨린 것도,',''],
634:['스메리아 왕: 로마리아의',' 세계 지배를 위해서였다...',''],
636:['스메리아 왕: 그놈들은',' 성궤를 노리고 있다.',' 성궤의 힘을',' 넘겨주어서는 안 된다.'],
638:['스메리아 왕: 아크,',' 너에게',' 마지막으로 해 두어야 할',' 말이 있다.'],
639:['스메리아 왕: 네 아버지',' 요슈아를',' 미르마나로 보내 둔 것은',''],
642:['스메리아 왕: 인망',' 두터운',' 형님만',' 없으면 하는 생각에...',' 그런 짓을...'],
643:['스메리아 왕: 허나',' 세상을 근심하던 형님이야말로',' 왕에',' 어울렸다...'],
650:['초핀: 옥상에 비행선이 기다리고 있습니다.',' 자, 어서 위로!',''],
}

def prepare():
    assert digest(BASE.read_bytes())==PIN and previous.prepare()[0]==BASE.read_bytes()
    old=b.members(BASE);new=dict(old);original=b.members(ORIGINAL);table,encode=b.encoder(old['PSX.EXE'])
    decode=b.audit.make_decoder(old['PSX.EXE']);rows=b.audit.rows(ROOT/'05_docs/script_original_full.csv');plans={};applied=[]
    for n in sorted((*TEXT,*PAUSES)):
        r=rows[n-1];fn=r['source file'];at=int(r['byte offset'],0);room=len(bytes.fromhex(r['raw bytes as hex']))
        if fn not in plans:plans[fn]=b.previous.Planner(fn,old[fn],original[fn],table)
        p=plans[fn];before=decode(b''.join(b.previous.read_tokens(old[fn],at,room)))[0]
        if n in TEXT:
            target=TEXT[n];assert not previous.previous.parts(before)[1];p.place(at,room,target,str(n));controls=[]
        else:
            controls=[t for _,t in previous.previous.boundaries(original[fn],at,room)[1] if t[0]==0xe4]
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
    ui=None
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
    from verify_arc1_v381_scene_pauses import verify as cases
    r['scene_pauses_v381']=cases(blob)
    return r

def main():
    blob,r=prepare();assert prepare()[0]==blob;r['cpu']=verify(blob)
    if OUT.exists():assert OUT.read_bytes()==blob
    else:OUT.write_bytes(blob)
    (AN/'build_report.json').write_text(json.dumps(r,ensure_ascii=False,indent=2),encoding='utf-8')
    print(r['zip_sha256'],r['changed_bytes'])
if __name__=='__main__':main()
