"""V367 nonrelease quiz layout build. Immutable baseline; all 58 bodies atomic."""
from pathlib import Path
from zipfile import ZipFile
import io,json,hashlib,struct
from v354_dialogue_codec import load_v354,encode,tokens
from extract_story_corpus import token_end
from v367_quiz_targets import TEXTS,CHOICES
ROOT=Path(__file__).resolve().parents[1]
BASE=ROOT/'03_output/arc1_v366_followups_TEST_ONLY.zip'
PIN='2443DCCA0451372D4D7A6ACD8B593696EC52734FC467B42C2284EFD14995FEBF'
ORIGINAL=ROOT/'00_original/arc.zip'
ORIGINAL_PIN='AE9F4366A1E7DA3805BB3BED3DDA9567E4CD4E669AF890E4E2A620D7861F11DD'
OUT=ROOT/'03_output/arc1_v367_quiz_TEST_ONLY.zip'
AN=ROOT/'01_work/analysis/v367_quiz';FN='6/S6054.DAT'
def digest(b):return hashlib.sha256(b).hexdigest().upper()
def prepare():
 assert digest(BASE.read_bytes())==PIN and digest(ORIGINAL.read_bytes())==ORIGINAL_PIN
 with ZipFile(BASE) as z:infos=z.infolist();old={i.filename:z.read(i) for i in infos};comment=z.comment
 with ZipFile(ORIGINAL) as z:o=z.read(FN)
 d=old[FN];_,_,encoder,_=load_v354();writes=[];entries=[];missing_bodies=set();previous=0
 for marker in range(0x43958,0x45e50,2):
  if marker<previous or o[marker:marker+2]!=b'\x19\0':continue
  at=marker+2;end=token_end(o,at)
  assert o[marker-6:marker]==bytes.fromhex('29 00 00 00 7f 00')
  assert end and 0<end-at<256
  previous=end+1
  if o[at:end+1]==d[at:end+1]:missing_bodies.add(at)
 assert missing_bodies==set(TEXTS)|set(CHOICES) and len(missing_bodies)==58
 def enc(s):
  b,missing=encode(s,encoder,True);assert not missing,(s,missing);return b
 def add(at,after,reason):
  before=d[at:at+len(after)]
  assert len(before)==len(after)
  assert all(at+len(after)<=w['offset'] or at>=w['offset']+len(bytes.fromhex(w['after'])) for w in writes)
  writes.append(dict(file=FN,offset=at,before=before.hex(),after=after.hex(),reason=reason))
 for at in sorted(missing_bodies):
  end=token_end(o,at);size=end-at
  if at in TEXTS:
   body=enc(TEXTS[at]);assert len(body)<=size,(hex(at),len(body),size)
   body+=b'\xa1'*(size-len(body))
   label=TEXTS[at];option_starts=None
  else:
   ss=CHOICES[at];assert len(ss)==4 and len(set(ss))==4
   assert list(tokens(o[at:end])).count(b'\xe5\x03')==4
   parts=[enc(s) for s in ss];slack=size-6-sum(map(len,parts))
   assert slack>=0,(hex(at),slack)
   # Same left edge for all answers. Spread visible safe padding across rows;
   # never add an early NUL or move the following event/answer-index table.
   for i in range(slack):parts[i%4]+=b'\xa1'
   option_starts=[];packet=0
   for p in parts:option_starts.append(packet);packet+=len(list(tokens(p)))
   body=b'\xe6\x01'.join(parts);assert len(body)==size
   event=(end+3)&~1
   assert struct.unpack_from('<7h',d,event)==(0x21,6,4,5,4,0,0)
   add(event+10,struct.pack('<h',-2),'local column -2: text x46, cursor x36; count/baseRow/branches preserved')
   label=' | '.join(ss)
  assert len(body)==size and b'\0' not in body
  add(at,body,label)
  entries.append(dict(offset=at,end=end,text=label,option_packet_starts=option_starts))
 new=bytearray(d);allowed=set()
 for w in writes:
  at=w['offset'];p=bytes.fromhex(w['after']);new[at:at+len(p)]=p;allowed.update(range(at,at+len(p)))
 assert len(new)==len(d) and all(a==b or i in allowed for i,(a,b) in enumerate(zip(d,new)))
 assert new[0x4200:0x5000]==d[0x4200:0x5000] # Bank-B, including all metadata
 for e in entries:assert new[e['end']]==o[e['end']]==0
 final={**old,FN:bytes(new)};buf=io.BytesIO()
 with ZipFile(buf,'w') as z:
  z.comment=comment
  for info in infos:z.writestr(info,final[info.filename])
 report=dict(zip_sha256=digest(buf.getvalue()),baseline_sha256=PIN,writes=writes,
  changed_members=[FN],entries=entries,missing_bodies_repaired=len(entries),
  policy='TEST_ONLY nonrelease; all 58 missing quiz bodies; translation human review pending; no font/code/E2 slot changes; canonical CSV unchanged')
 return buf.getvalue(),report
if __name__=='__main__':
 blob,report=prepare();assert prepare()[0]==blob
 if OUT.exists():assert OUT.read_bytes()==blob,'Existing output differs; inspect before replacing'
 else:OUT.write_bytes(blob)
 AN.mkdir(exist_ok=True)
 (AN/'build_report.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
 print(report['zip_sha256'])
