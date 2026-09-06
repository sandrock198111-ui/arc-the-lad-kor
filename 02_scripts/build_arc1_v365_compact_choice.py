"""V365 TEST_ONLY: one-space priest prompt and per-event choice row 2 -> 1.

Uses the already scene-owned Bank-B slot 23; no EXE or font edits.
"""
from pathlib import Path
from zipfile import ZipFile
import io,json,hashlib
from v354_dialogue_codec import load_v354,encode,tokens
ROOT=Path(__file__).resolve().parents[1]
BASE=ROOT/'03_output/arc1_v364_cursor_speaker_TEST_ONLY.zip'
PIN='A4C43D7BE52CDEE4182ADF7580604BC86A7D4D883C7D6D85CD6E0DD60C31C122'
ORIGINAL=ROOT/'00_original/arc.zip'
ORIGINAL_PIN='AE9F4366A1E7DA3805BB3BED3DDA9567E4CD4E669AF890E4E2A620D7861F11DD'
OUT=ROOT/'03_output/arc1_v365_compact_choice_TEST_ONLY.zip'
AN=ROOT/'01_work/analysis/v365_compact_choice'
FN='6/S6054.DAT'
PROMPT='승려: 수행하러 오셨습니까?'
def digest(b):return hashlib.sha256(b).hexdigest().upper()
def prepare():
    assert digest(BASE.read_bytes())==PIN and digest(ORIGINAL.read_bytes())==ORIGINAL_PIN
    with ZipFile(BASE) as z:
        infos=z.infolist();old={i.filename:z.read(i) for i in infos};comment=z.comment
    with ZipFile(ORIGINAL) as z:pristine=z.read(FN)
    d=old[FN];slot=0x4200+23*128
    assert not any(pristine[0x4200:0x5000])
    assert not any(d[slot:slot+128])
    # Original binary occurrences outside the script are not E2 callers.
    occurrences=[i for i in range(len(d)-1) if d[i:i+2]==b'\xe2\xe8']
    assert occurrences==[0x17b21,0x24687]
    assert all(d[i-12:i+18]==pristine[i-12:i+18] for i in occurrences)
    _,_,enc,dec=load_v354();payload,missing=encode(PROMPT,enc,keep_breaks=True)
    assert not missing,missing
    assert ''.join(dec[t] for t in tokens(payload))==PROMPT and len(payload)<=126
    # Source entry boundary and all E5/E6 choice bytes remain at their addresses.
    expected=bytes.fromhex('69 3c dd 02 a1 a1 a1 50 dd 31 19 20 a1 46 dd d5 2d 07 3b d1 a1 a1 a1 a1')
    assert d[0x4395a:0x43972]==expected
    assert d[0x4398a:0x43998]==bytes.fromhex('21 00 06 00 04 00 05 00 02 00 00 00 02 00')
    body=payload+b'\0'*(127-len(payload))+bytes([22])
    specs=[(slot,bytes(128),body,'owned Bank-B 23, one-space prompt, completion resumes original E6'),
           (0x4395a,expected[:2],b'\xe2\xe8','E2 caller consumes original prompt span without rendering filler'),
           (0x43996,b'\x02\x00',b'\x01\x00','event 21/type6 arg4 baseRow 2 -> 1; count/index/column unchanged')]
    allowed=set();writes=[]
    for at,before,after,why in specs:
        assert len(before)==len(after) and d[at:at+len(before)]==before
        span=set(range(at,at+len(after)));assert not span&allowed;allowed|=span
        writes.append(dict(file=FN,offset=at,before=before.hex(),after=after.hex(),reason=why))
    out=bytearray(d)
    for at,before,after,why in specs:out[at:at+len(after)]=after
    assert len(out)==len(d) and all(a==b or i in allowed for i,(a,b) in enumerate(zip(d,out)))
    final={**old,FN:bytes(out)};buf=io.BytesIO()
    with ZipFile(buf,'w') as z:
        z.comment=comment
        for info in infos:z.writestr(info,final[info.filename])
    report=dict(zip_sha256=digest(buf.getvalue()),baseline_sha256=PIN,writes=writes,
                changed_members=[FN],prompt=PROMPT,choice_rows=[2,3],runtime_verified=False,
                policy='TEST_ONLY; this prompt only; other V364 speaker spacing not changed; CSV preserved')
    return buf.getvalue(),report
if __name__=='__main__':
    blob,report=prepare();assert prepare()[0]==blob
    if OUT.exists():assert OUT.read_bytes()==blob
    else:OUT.write_bytes(blob)
    AN.mkdir(parents=True,exist_ok=True)
    (AN/'build_report.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    print(report['zip_sha256'])
