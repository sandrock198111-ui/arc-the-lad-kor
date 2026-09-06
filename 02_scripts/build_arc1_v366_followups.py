"""V366 TEST_ONLY: five reported Ramada states, no executable/font change."""
from pathlib import Path
from zipfile import ZipFile
import io,json,hashlib
from v354_dialogue_codec import load_v354,encode,tokens
ROOT=Path(__file__).resolve().parents[1]
BASE=ROOT/'03_output/arc1_v365_compact_choice_TEST_ONLY.zip'
PIN='28EEE68677DB124D91550CF89B2EF437B1CE728686011CA79B419FA1DAB27764'
ORIGINAL=ROOT/'00_original/arc.zip'
ORIGINAL_PIN='AE9F4366A1E7DA3805BB3BED3DDA9567E4CD4E669AF890E4E2A620D7861F11DD'
OUT=ROOT/'03_output/arc1_v366_followups_TEST_ONLY.zip'
AN=ROOT/'01_work/analysis/v366_followups';FN='6/S6054.DAT'
TEXTS={0x43a28:'승려: 그럼 장난삼아|오셨습니까?',
       0x43a94:'승려: 다음 문제를 다 맞히시면|좋은 걸 알려 드리겠습니다.',
       0x43afa:'문제: 지금 일행은 모두 몇 명입니까?'}
def digest(b):return hashlib.sha256(b).hexdigest().upper()
def prepare():
    assert digest(BASE.read_bytes())==PIN and digest(ORIGINAL.read_bytes())==ORIGINAL_PIN
    with ZipFile(BASE) as z:infos=z.infolist();old={i.filename:z.read(i) for i in infos};comment=z.comment
    with ZipFile(ORIGINAL) as z:pristine=z.read(FN)
    d=old[FN];_,_,encoder,decoder=load_v354();writes=[]
    def enc(s):
        b,missing=encode(s,encoder,True);assert not missing,(s,missing);return b
    def add(at,before,after,reason):
        assert len(before)==len(after) and d[at:at+len(before)]==before
        assert all(at+len(after)<=w['offset'] or at>=w['offset']+len(bytes.fromhex(w['after'])) for w in writes)
        writes.append(dict(file=FN,offset=at,before=before.hex(),after=after.hex(),reason=reason))
    def inplace(at,size,s):
        payload=enc(s);assert len(payload)<=size,(s,len(payload),size)
        add(at,d[at:at+size],payload+b'\xa1'*(size-len(payload)),s)
    for at,length in [(0x43a28,46),(0x43a94,42),(0x43afa,28),(0x43b4e,22)]:
        assert d[at:at+length+1]==pristine[at:at+length+1] and d[at+length]==0
    # Keep the two option E5/E6 anchors and both event boundaries in place.
    br=[i for i in range(46) if d[0x43a28+i:0x43a2a+i]==b'\xe6\x01']
    assert br==[5,25,35],br
    inplace(0x43a28,25,TEXTS[0x43a28])
    inplace(0x43a28+29,6,'맞습니다.')
    inplace(0x43a28+39,7,'아닙니다.')
    inplace(0x43a94,42,TEXTS[0x43a94])
    inplace(0x43afa,28,TEXTS[0x43afa])
    # E2 payload uses the plain glyph path, so E5/E6 MUST stay inline.
    # One A1 indent + digit + two-byte 명 fits each original four-byte run.
    choices=b'\xe6\x01'.join(b'\xa1'+enc(f'{n}명') for n in range(5,9))
    assert len(choices)==22
    add(0x43b4e,d[0x43b4e:0x43b64],choices,'four inline choices, original E6/NUL addresses retained; indent8px')
    assert d[0x43b66:0x43b74]==bytes.fromhex('21 00 06 00 04 00 05 00 04 00 00 00 00 00')
    add(0x43b70,b'\0\0',b'\xfe\xff','signed local column -2 gives cursor x=origin-10, before text origin+8')
    # Tone change within the existing owned slot and fixed inline tail.
    s=d[0x4980:0x4a00]
    assert s[127]==11
    assert ''.join(decoder[t] for t in tokens(s.split(b'\0')[0]))=='수행이 부족한 듯하구나. 다시'
    p=enc('수행이 부족한 것 같습니다.')
    add(0x4980,s,p+b'\0'*(127-len(p))+s[127:],'polite refusal; existing metadata unchanged')
    inplace(0x45e44,11,'다시 찾아오십시오.')
    new=bytearray(d);allowed=set()
    for w in writes:
        at=w['offset'];p=bytes.fromhex(w['after']);new[at:at+len(p)]=p;allowed.update(range(at,at+len(p)))
    assert len(new)==len(d) and all(a==b or i in allowed for i,(a,b) in enumerate(zip(d,new)))
    final={**old,FN:bytes(new)};buf=io.BytesIO()
    with ZipFile(buf,'w') as z:
        z.comment=comment
        for info in infos:z.writestr(info,final[info.filename])
    report=dict(zip_sha256=digest(buf.getvalue()),baseline_sha256=PIN,writes=writes,changed_members=[FN],
                runtime_verified=False,policy='TEST_ONLY; five reported states; local four-choice indent/column only; other low-address candidates pending; canonical CSV unchanged')
    return buf.getvalue(),report
if __name__=='__main__':
    blob,report=prepare();assert prepare()[0]==blob
    if OUT.exists():assert OUT.read_bytes()==blob
    else:OUT.write_bytes(blob)
    AN.mkdir(parents=True,exist_ok=True)
    (AN/'build_report.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    print(report['zip_sha256'])
