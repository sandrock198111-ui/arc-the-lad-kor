"""V368: user-approved two line breaks only; all cursor data/code immutable."""
import io,json
from zipfile import ZipFile
import build_arc1_v367_quiz as previous
from v354_dialogue_codec import load_v354,encode,tokens
ROOT=previous.ROOT;ORIGINAL=previous.ORIGINAL;ORIGINAL_PIN=previous.ORIGINAL_PIN
digest=previous.digest;FN=previous.FN
BASE=previous.OUT;PIN='34E00DB8BC2EF5E8929E5EC770D6CB61C02FB9DBCEE899D51411B6CDE03044B4'
OUT=ROOT/'03_output/arc1_v368_linebreaks_TEST_ONLY.zip'
AN=ROOT/'01_work/analysis/v368_linebreaks'
TARGETS={
 0x43e3c:(36,'문제: 파렌시아 성의|왕을 모시는 대신의 이름은?'),
 0x4429e:(38,'문제: 다른 공간에서|적을 공격하는 아크의 기술은?'),
}
def prepare():
 assert digest(BASE.read_bytes())==PIN
 assert previous.prepare()[0]==BASE.read_bytes()
 assert digest(ORIGINAL.read_bytes())==ORIGINAL_PIN
 with ZipFile(BASE) as z:infos=z.infolist();old={i.filename:z.read(i) for i in infos};comment=z.comment
 d=old[FN];new=bytearray(d);enc,dec=load_v354()[2:];writes=[]
 for at,(size,text) in TARGETS.items():
  before=d[at:at+size];after,missing=encode(text,enc,True)
  assert not missing and len(after)<=size and d[at+size]==0
  after+=b'\xa1'*(size-len(after))
  oldtext=''.join('|' if t==b'\xe6\x01' else dec[t] for t in tokens(before))
  assert oldtext.replace('|',' ').strip()==text.replace('|',' ').strip()
  assert list(tokens(before)).count(b'\xe6\x01')==list(tokens(after)).count(b'\xe6\x01')==1
  writes.append(dict(file=FN,offset=at,before=before.hex(),after=after.hex(),reason=text))
 for w in writes:
  at=w['offset'];after=bytes.fromhex(w['after']);new[at:at+len(after)]=after
 allowed={i for at,(size,_) in TARGETS.items() for i in range(at,at+size)}
 assert len(d)==len(new) and all(a==b or i in allowed for i,(a,b) in enumerate(zip(d,new)))
 final={**old,FN:bytes(new)};buf=io.BytesIO()
 with ZipFile(buf,'w') as z:
  z.comment=comment
  for info in infos:z.writestr(info,final[info.filename])
 report=dict(zip_sha256=digest(buf.getvalue()),baseline_sha256=PIN,writes=writes,
  changed_members=[FN],policy='TEST_ONLY; two line-break relocations; wording/EXE/COMM/all choices and cursor fields unchanged')
 return buf.getvalue(),report
if __name__=='__main__':
 blob,r=prepare();assert prepare()[0]==blob
 if OUT.exists():assert OUT.read_bytes()==blob
 else:OUT.write_bytes(blob)
 AN.mkdir(parents=True,exist_ok=True)
 (AN/'build_report.json').write_text(json.dumps(r,ensure_ascii=False,indent=2),encoding='utf-8')
 print(r['zip_sha256'])
