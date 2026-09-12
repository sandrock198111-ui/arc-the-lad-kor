"""V381 cumulative ten-capture corrections, with original scene delays."""
import io,json,struct
from zipfile import ZipFile
import build_arc1_v381_scene_pauses as previous
b=previous.b;ROOT=b.ROOT;ORIGINAL=b.ORIGINAL;ORIGINAL_PIN=b.ORIGINAL_PIN;digest=b.digest
BASE=previous.OUT;PIN='9D9A2244729A765A0E98784D22A4DC8AC54F70C10E321D7462604F33774429CD'
OUT=ROOT/'03_output/arc1_v382_reports_TEST_ONLY.zip';AN=ROOT/'01_work/analysis/v382_reports'
TEXT={2395:'앞으로 나아가면 이제 돌아올 수 없게 될지도 몰라.'}
PAUSES={
2806:['토벌병: 보고드립니다.','',''],
2807:['토벌병: 아크와 그 일당은 계속 수색하고 있으나 행방을 알 수 없습니다.','',''],
2808:['토벌병: 아무래도 지형이 크게 바뀌어 버려서...','',''],
2809:['안델: 알겠다.',' 수색을 중단하도록 지시를 내려라.','',''],
2810:['안델:','.','.','.',' 뭐 좋다.',' 어차피 이 나라에 이제 그놈들이 있을 곳 따위는 없으니 말이다.','','',''],
2811:['안델: 후후후후.','',''],
2812:['안델: 와하하하하하하하!!','','','','','',''],
}
UI='피해량의|변동 폭 증가'
GLYPHS={'색':833}

def encoder(exe):
    table,encode=b.encoder(exe)
    for ch,index in GLYPHS.items():table[ch]=b.font.encode_index(index)
    return table,encode

def decoder(exe):
    prior=b.audit.make_decoder(exe)
    def decode(raw):
        out=[];unknown=[];mapping={b.font.encode_index(i):ch for ch,i in GLYPHS.items()}
        for token in b.codec.tokens(raw):
            if token in mapping:out.append(mapping[token])
            else:
                text,u=prior(token);out.append(text)
                if u:unknown.append(u)
        return ''.join(out),','.join(unknown)
    return decode

def prepare():
    assert digest(BASE.read_bytes())==PIN
    old=b.members(BASE);new=dict(old);original=b.members(ORIGINAL);table,encode=encoder(old['PSX.EXE'])
    decode=decoder(old['PSX.EXE']);rows=b.audit.rows(ROOT/'05_docs/script_original_full.csv');plans={};applied=[]
    saved=b.NEW_GLYPHS
    try:
        b.NEW_GLYPHS=GLYPHS
        new['COMM.IMG'],glyphs=b.font_patch(old,{**original,**old})
    finally:b.NEW_GLYPHS=saved
    for n in sorted((*TEXT,*PAUSES)):
        r=rows[n-1];fn=r['source file'];at=int(r['byte offset'],0);room=len(bytes.fromhex(r['raw bytes as hex']))
        if fn not in plans:plans[fn]=b.previous.Planner(fn,old[fn],original[fn],table)
        p=plans[fn];before=decode(b''.join(b.previous.read_tokens(old[fn],at,room)))[0]
        controls=[]
        if n in TEXT:target=TEXT[n];p.place(at,room,target,str(n))
        else:
            controls=[t for _,t in previous.previous.previous.boundaries(original[fn],at,room)[1] if t[0]==0xe4]
            chunks=PAUSES[n];assert len(chunks)==len(controls)+1,(n,len(chunks),len(controls))
            output=bytearray();target='';last_text=max(i for i,t in enumerate(chunks) if t)
            for i,text in enumerate(chunks):
                raw=encode(text)
                if len(raw)<=2 and i!=last_text:output+=raw
                else:
                    a=p.allocate(raw,0,str(n)+':'+str(i))
                    if i==last_text:last_allocation=(len(output),a)
                    output+=bytes((0xe2,a.disk_id))
                target+=text
                if i<len(controls):output+=controls[i];target+=f'<CTRL:{controls[i].hex().upper()}>'
            assert len(output)<=room
            padding=room-len(output);pos,a=last_allocation;assert len(a.users)==1
            p.data[p._slot_offset(a.bank,a.slot)+127]=padding
            output[pos+2:pos+2]=b'\xa1'*padding;p.data[at:at+room]=output
        applied.append(dict(row=n,file=fn,offset=at,length=room,before=before,target=target,original_japanese=r['decoded Japanese'],pauses=[t.hex() for t in controls]))
    for fn,p in plans.items():new[fn]=bytes(p.data)
    # Preserve both E503 indentation codes; remove only the extra empty line.
    fn='B/SB071.DAT';r=rows[2395];at=int(r['byte offset'],0);room=len(bytes.fromhex(r['raw bytes as hex']))
    data=bytearray(new[fn]);raw=bytes(data[at:at+room]);assert raw.count(b'\xe6\x01\xe6\x01')==1
    pos=raw.index(b'\xe6\x01\xe6\x01');fixed=raw[:pos]+raw[pos+2:]+b'\xa1\xa1';data[at:at+room]=fixed
    event=(at+room+3)&~1;assert data[event:event+14]==bytes.fromhex('2100060004000500020000000200')
    data[event+12]=1;new[fn]=bytes(data)
    applied.append(dict(row=2396,file=fn,offset=at,length=room,before=decode(raw)[0],target=decode(fixed)[0],pauses=[],original_japanese=r['decoded Japanese']))
    cursor=dict(event=event,offset=event+12,before=2,after=1)
    exe=bytearray(old['PSX.EXE']);p=0x80B50;address=struct.unpack_from('<I',exe,p)[0];at=b.storage.file_offset(address);end=exe.index(0,at);raw=encode(UI)
    assert len(raw)<=end-at,(UI,len(raw),end-at)
    refs=[i for i in range(0,len(exe)-3,4) if address<=struct.unpack_from('<I',exe,i)[0]<=address+end-at]
    assert refs==[p],refs
    exe[at:end+1]=(raw+b'\0').ljust(end-at+1,b'\0');new['PSX.EXE']=bytes(exe)
    ui=dict(pointer=p,address=address,offset=at,length=end-at,before=decode(old['PSX.EXE'][at:end])[0],target=UI)
    expected=sorted((*TEXT,*PAUSES,2396));changed=[]
    for n,r in enumerate(rows,1):
        fn=r['source file'];at=int(r['byte offset'],0);sz=len(bytes.fromhex(r['raw bytes as hex']))
        if b.previous.read_tokens(old.get(fn,original[fn]),at,sz)!=b.previous.read_tokens(new.get(fn,original[fn]),at,sz):changed.append(n)
    assert changed==expected,changed
    for r in applied:
        fn,at,room=r['file'],r['offset'],r['length'];tokens=b.previous.read_tokens(new[fn],at,room)
        assert ''.join(decode(b''.join(tokens))[0].split())==''.join(r['target'].split()),r
        assert [t.hex() for t in tokens if t[0]==0xe4]==r['pauses']
        assert new[fn][at+room:at+room+2]==old[fn][at+room:at+room+2]
    assert new['B/SB022.DAT']==old['B/SB022.DAT']
    writes=[dict(file=fn,offset=h['at'],before=h['before'],after=h['after']) for fn,d in new.items() if d!=old[fn] for h in b.previous.hunks(old[fn],d)]
    with ZipFile(BASE) as z:infos=z.infolist();comment=z.comment
    buf=io.BytesIO()
    with ZipFile(buf,'w') as z:
        z.comment=comment
        for info in infos:z.writestr(info,new[info.filename])
    blob=buf.getvalue()
    return blob,dict(zip_sha256=digest(blob),base_sha256=PIN,static_pass=True,applied=applied,ui=ui,cursor=cursor,glyphs=glyphs,writes=writes,changed_bytes=sum(len(bytes.fromhex(w['after'])) for w in writes),changed_members=sorted({w['file'] for w in writes}),runtime_verified=False)

def verify(blob):
    from verify_arc1_v382_reports import verify as cases
    r=previous.verify(blob);r['reports_v382']=cases(blob);return r

def main():
    blob,r=prepare();assert prepare()[0]==blob;r['cpu']=verify(blob)
    if OUT.exists():assert OUT.read_bytes()==blob
    else:OUT.write_bytes(blob)
    (AN/'build_report.json').write_text(json.dumps(r,ensure_ascii=False,indent=2),encoding='utf-8')
    print(r['zip_sha256'],r['changed_bytes'])
if __name__=='__main__':main()
