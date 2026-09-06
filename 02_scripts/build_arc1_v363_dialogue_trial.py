"""Bounded V363 player-review trial. No EXE, font, or cursor-code changes.

Pinned legacy archive is a dependency, not a prior disc image. Package into
fresh original-disc staging. New low-address translation is TEST_ONLY input.
"""
from pathlib import Path
from zipfile import ZipFile
import hashlib,io,json
from v354_dialogue_codec import load_v354,encode,tokens

ROOT=Path(__file__).resolve().parents[1]
BASE=ROOT/'03_output/arc1_v362_korean_title_TEST_ONLY.zip'
PIN='593E867DCB599C563B52C6F44A6864990B7157FA5B42B9F8C8D2337DEF6EA152'
OUT=ROOT/'03_output/arc1_v363_dialogue_trial_TEST_ONLY.zip'
AN=ROOT/'01_work/analysis/v363_dialogue_trial'
ORIGINAL=ROOT/'00_original/arc.zip'
ORIGINAL_PIN='AE9F4366A1E7DA3805BB3BED3DDA9567E4CD4E669AF890E4E2A620D7861F11DD'
def digest(b):return hashlib.sha256(b).hexdigest().upper()

def prepare():
    assert digest(BASE.read_bytes())==PIN
    assert digest(ORIGINAL.read_bytes())==ORIGINAL_PIN
    with ZipFile(BASE) as z:
        infos=z.infolist();before={i.filename:z.read(i) for i in infos};comment=z.comment
    _,_,encoder,decoder=load_v354();writes=[]
    def enc(s):
        b,missing=encode(s,encoder,True)
        assert not missing,(s,missing)
        return b
    def add(fn,at,old,new,reason):
        assert len(old)==len(new)
        assert before[fn][at:at+len(old)]==old,(fn,hex(at))
        assert all(fn!=w['file'] or at+len(new)<=w['offset'] or at>=w['offset']+len(w['after']) for w in writes)
        writes.append({'file':fn,'offset':at,'before':old,'after':new,'reason':reason})
    def slot(fn,n,oldtext,newtext):
        at=0x45000+n*128;s=before[fn][at:at+128];p=s.split(b'\0')[0]
        decoded=''.join(decoder.get(t,'<'+t.hex()+'>') for t in tokens(p))
        assert decoded==oldtext,(fn,n,decoded)
        new=enc(newtext);assert len(new)<=126
        final=new+b'\0'+s[len(new)+1:]
        assert len(final)==128 and final[127]==s[127]
        add(fn,at,s,final,'existing owned E2 payload; completion preserved')
    slot('6/S6041.DAT',8,
         '대지의 정령: 라마다의 기술은 대지와 대기의 힘을 기로 내보내는 기술이다. 대지에 감사하는 마음이 있어야 쓸 수 있지.',
         '대지의 정령: 라마다의 기술은 대지와 대기의 힘을 기로 내보내는 기술이다. 대지에 감사하는 마음이 있어야 쓸수있지.')
    slot('6/S6053.DAT',6,'이가 사범님. 저희가 스승님께 배운','이가 사범님.|저희가 사범님께 배운')
    slot('6/S6053.DAT',0,'제자: 스승님은 저희에게 자신의 잘못을 바로잡는 것을 두려워하지 않는 용기를 가르쳐 주셨습니다.',
         '제자: 사범님은 저희에게 자신의 잘못을 바로잡는 것을 두려워하지 않는 용기를 가르쳐 주셨습니다.')
    slot('6/S6053.DAT',4,'제자: 스승님이 돌아오실 때까지 이 절은 우리가 지키겠습니다.',
         '제자: 사범님이 돌아오실 때까지 이 절은 우리가 지키겠습니다.')
    # Four in-place spans. Preserve every E5/E6 offset and event/choice topology.
    fn='6/S6054.DAT';start=0x4395a
    with ZipFile(ORIGINAL) as z:original=z.read(fn)
    source=original[start:0x43988]
    assert source==before[fn][start:0x43988] and source[-1]==0
    spans=[(0,5,'승려:'),(7,17,'수행하러 오셨습니까?'),(28,6,'맞습니다.'),(38,7,'아닙니다.')]
    for relative,size,text in spans:
        new=enc(text);assert len(new)<=size,(text,len(new),size)
        # A1 is the existing engine's visible blank glyph, not a terminator.
        add(fn,start+relative,source[relative:relative+size],new+b'\xa1'*(size-len(new)),text)
    final=dict(before)
    for w in writes:
        b=bytearray(final[w['file']]);at=w['offset'];b[at:at+len(w['after'])]=w['after'];final[w['file']]=bytes(b)
    for fn,old in before.items():
        assert len(old)==len(final[fn])
        allowed={i for w in writes if w['file']==fn for i in range(w['offset'],w['offset']+len(w['after']))}
        assert all(a==b or i in allowed for i,(a,b) in enumerate(zip(old,final[fn])))
    assert final['PSX.EXE']==before['PSX.EXE'] and final['COMM.IMG']==before['COMM.IMG']
    stream=io.BytesIO()
    with ZipFile(stream,'w') as z:
        z.comment=comment
        for info in infos:z.writestr(info,final[info.filename])
    report={'zip_sha256':digest(stream.getvalue()),'baseline_sha256':PIN,'runtime_verified':False,
            'status':'TEST_ONLY; low-address translation pending player review; cursor movement pending',
            'writes':[{**w,'before':w['before'].hex(),'after':w['after'].hex()} for w in writes],
            'changed_members':[fn for fn in before if before[fn]!=final[fn]],
            'changed_bytes':sum(a!=b for fn in before for a,b in zip(before[fn],final[fn])),
            'canonical_policy':'Trial-specific input here; canonical/export CSV unchanged until review'}
    return stream.getvalue(),report

if __name__=='__main__':
    data,report=prepare();assert prepare()[0]==data
    if OUT.exists():assert OUT.read_bytes()==data
    else:OUT.write_bytes(data)
    AN.mkdir(parents=True,exist_ok=True)
    (AN/'build_report.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    print(report['zip_sha256'],report['changed_members'],report['changed_bytes'])
