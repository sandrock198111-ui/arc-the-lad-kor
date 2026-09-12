"""V378 cumulative dialogue corrections; V377 states are evidence only."""
import io,json,re
from zipfile import ZipFile
import build_arc1_v378_followup as previous
from v376_dat_targets import parts
b=previous.b
ROOT=b.ROOT;ORIGINAL=b.ORIGINAL;ORIGINAL_PIN=b.ORIGINAL_PIN;digest=b.digest
BASE=previous.OUT;PIN='C23A2F7E10F044F6C6E897CECE8F6D3DCFDC64D1BA2C54EE303E6DFA969112D7'
OUT=ROOT/'03_output/arc1_v379_spirit_reports_TEST_ONLY.zip'
AN=ROOT/'01_work/analysis/v379_spirit_reports'
TEXT={
 505:'우리는 지금부터 팔렌시아 성으로 돌아가지만, 이제 여기에 다시 오지 못할지도 몰라.',
 251:'병사 1: 아크 님이신가요? 왕의 임무는 끝내셨습니까?',
 2780:'불의 정령: 스스로는 아무것도 만들어 내지 않으면서 우리가 만든 생명을 가지고 놀며 세계의 지배자인 양 구는구나.',
 2781:'...분명 인간들의 욕망은 많은 비극을 계속 낳고 있어.',
 2783:'불의 정령이여. 인간은 아무것도 만들어 내지 못한다고 했지만,',
 2784:'단 하나 만들어 낼 수 있는 것이 있다.',
 2785:'바로 인간이다.',
 2792:'불의 정령: 너희를 한 번 믿어 보겠다!',
}
JOIN={
 640:'스메리아 왕: 대신 <CTRL:E41F>안델의 말에 <CTRL:E41F>넘어간 <CTRL:E41F>바로 나였다.',
 2767:'불꽃의 정령: 그래, 이 연구소는 <CTRL:E415>새로운 <CTRL:E40B>에너지를 연구하고 <CTRL:E415>있다<CTRL:E43D>. 바로 생명력 에너지다.',
 2768:'불꽃의 정령: 불꽃의 정령인 <CTRL:E415>나를 붙잡아 <CTRL:E40B>에너지를 <CTRL:E415>빼앗아 왔다.',
 2770:'불꽃의 정령: 에너지는 <CTRL:E415>서로 나누며 <CTRL:E415>키워 가는 것이지 <CTRL:E41F>억지로 <CTRL:E415>빼앗는 게 아니다.',
}
REPLACE={1035:('돌아가거라','돌아가세요'),1051:('그레이시느','그레이시누'),
         1065:('에릴베','에너지'),1066:('에릴베','에너지'),1067:('에릴베','에너지'),
         1069:('불의 정령','불꽃의 정령')}
# Explicit supplemental corpus: original opcode17/argument0 short utterances.
# Do not globally reinterpret byte-pattern candidates as events.
EXTRA=[
 ('22/S2056.DAT',0x47bf0,'네.'),
 ('22/S205C.DAT',0x481f8,'젠장!<CTRL:E479>'),
 ('22/S205C.DAT',0x482e8,'모두 서둘러!<CTRL:E479>'),
 ('23/S2061.DAT',0x485dc,'!'),
 ('32/S3061.DAT',0x48412,'잠깐만 기다려 줘.|아직 물어볼 게|많이 남았는데...<CTRL:E45B>'),
 ('7/S7026.DAT',0x48a2c,'?'),
 ('8/S8031.DAT',0x4861e,'어쩌다 이런 일이...<CTRL:E43D><CTRL:E43D>.'),
 ('9/S9021.DAT',0x486a2,'끈질긴 녀석들이군!'),
 ('B/SB041.DAT',0x47a72,'쿠쿠루!'),
 ('B/SB041.DAT',0x47bf6,'쿠쿠루우우우우우우!'),
 ('B/SB071.DAT',0x48100,'그럼 일단 돌아가자.'),
 ('B/SB072.DAT',0x47ed4,'...'),
]

def boundaries(data,at,room):
    p=start=at;spans=[];controls=[]
    while p<at+room:
        w=1 if data[p]<0xdd else 2;t=data[p:p+w]
        if t[0]==0xe2:
            loc=b.previous.slot_pos(b.previous.b.slot_of_disk(t[1]));p+=2+data[loc+127];continue
        if t[0] in b.previous.b.STRUCTURAL_LEADS:
            spans.append((start,p-start));controls.append((p,t));start=p+w
        p+=w
    assert p==at+room
    spans.append((start,p-start))
    return spans,controls

def prepare():
    assert digest(BASE.read_bytes())==PIN and previous.prepare()[0]==BASE.read_bytes()
    old=b.members(BASE);new=dict(old);pristine=b.members(ORIGINAL)
    table,encode=b.encoder(old['PSX.EXE']);decode=b.audit.make_decoder(old['PSX.EXE'])
    rows=b.audit.rows(ROOT/'05_docs/script_original_full.csv');plans={};applied=[]
    def plan(fn):
        if fn not in plans:plans[fn]=b.previous.Planner(fn,old[fn],pristine[fn],table)
        return plans[fn]
    for n in sorted((*TEXT,*JOIN,*REPLACE)):
        r=rows[n-1];fn=r['source file'];at=int(r['byte offset'],0);room=len(bytes.fromhex(r['raw bytes as hex']))
        before=decode(b''.join(b.previous.read_tokens(old[fn],at,room)))[0]
        p=plan(fn)
        if n in JOIN:
            spans,controls=boundaries(old[fn],at,room)
            pos,t=controls[0];assert t==b'\xe6\x01' and before.split('|')[0].endswith(':')
            target=JOIN[n];texts,wanted=parts(target)
            pauses=[(pos,t) for pos,t in controls if t[0]!=0xe6]
            assert [t for _,t in pauses]==wanted
            start=at
            for text,(stop,_) in zip(texts,pauses+[(at+room,b'')]):
                length=stop-start;raw=encode(text)
                if len(raw)==length:p.data[start:stop]=raw
                else:
                    assert length>=2
                    allocation=p.allocate(raw,length-2,str(n)+':pause')
                    p.data[start:stop]=bytes((0xe2,allocation.disk_id))+b'\xa1'*(length-2)
                start=stop+2
        else:
            if n in REPLACE:
                a,z=REPLACE[n];assert a in before;target=before.replace(a,z)
            else:target=TEXT[n]
            texts,ctrl=parts(target);spans,controls=boundaries(old[fn],at,room)
            assert ctrl==[t for _,t in controls]
            for (pos,length),text in zip(spans,texts):
                if length:p.place(pos,length,text.strip(),str(n))
                else:assert not text.strip()
        applied.append(dict(row=n,file=fn,offset=at,length=room,before=before,target=target,original_japanese=r['decoded Japanese']))
    import extract_story_corpus as extraction
    g,a,near,_=b.audit.ui.build_glyph_map()
    for fn,at,target in EXTRA:
        original=pristine[fn];assert original[at-4:at]==old[fn][at-4:at]==b'\x17\0\0\0'
        end=extraction.token_end(original,at);assert end and end>at
        room=end-at;assert old[fn][at:end+2]==original[at:end+2]
        texts,ctrl=parts(target);spans,controls=boundaries(original,at,room)
        assert ctrl==[t for _,t in controls] and len(texts)==len(spans)
        p=plan(fn)
        for (pos,length),text in zip(spans,texts):
            if length:p.place(pos,length,text,'supplement:'+hex(at))
            else:assert not text
        applied.append(dict(row=None,file=fn,offset=at,length=room,before=decode(original[at:end])[0],target=target,
            original_japanese=extraction.decode_body(original[at:end],g,a,near)[0],original_hex=original[at:end].hex()))
    for fn,p in plans.items():new[fn]=bytes(p.data)
    for r in applied:
        fn,at,room=r['file'],r['offset'],r['length']
        got=decode(b''.join(b.previous.read_tokens(new[fn],at,room)))[0]
        assert ''.join(got.split())==''.join(r['target'].split()),(r,got)
        assert new[fn][at+room:at+room+2]==old[fn][at+room:at+room+2]
        oc=boundaries(old[fn],at,room)[1];nc=boundaries(new[fn],at,room)[1]
        assert nc==([(pos,t) for pos,t in oc if t[0]!=0xe6] if r['row'] in JOIN else oc),(r['row'],oc,nc)
    changed=[]
    for n,r in enumerate(rows,1):
        fn=r['source file'];at=int(r['byte offset'],0);room=len(bytes.fromhex(r['raw bytes as hex']))
        if b.previous.read_tokens(old.get(fn,pristine[fn]),at,room)!=b.previous.read_tokens(new.get(fn,pristine[fn]),at,room):changed.append(n)
    assert changed==sorted((*TEXT,*JOIN,*REPLACE)),changed
    assert new['PSX.EXE']==old['PSX.EXE'] and new['COMM.IMG']==old['COMM.IMG']
    writes=[dict(file=fn,offset=h['at'],before=h['before'],after=h['after']) for fn,d in new.items() if d!=old[fn] for h in b.previous.hunks(old[fn],d)]
    with ZipFile(BASE) as z:infos=z.infolist();comment=z.comment
    buf=io.BytesIO()
    with ZipFile(buf,'w') as z:
        z.comment=comment
        for info in infos:z.writestr(info,new[info.filename])
    blob=buf.getvalue()
    return blob,dict(zip_sha256=digest(blob),base_sha256=PIN,static_pass=True,applied=applied,writes=writes,
        changed_bytes=sum(len(bytes.fromhex(w['after'])) for w in writes),changed_members=sorted({w['file'] for w in writes}),
        unchanged_dialogue_rows=len(rows)-len(changed),runtime_verified=False)

def verify(blob):
    result=previous.verify(blob)
    from verify_arc1_v379_spirit_reports import verify as captures
    result['spirit_captures']=captures(blob)
    return result

def main():
    blob,r=prepare();assert prepare()[0]==blob;r['cpu']=verify(blob)
    if OUT.exists():assert OUT.read_bytes()==blob
    else:OUT.write_bytes(blob)
    (AN/'build_report.json').write_text(json.dumps(r,ensure_ascii=False,indent=2),encoding='utf-8')
    print(r['zip_sha256'],r['changed_bytes'],r['changed_members'])
if __name__=='__main__':main()
