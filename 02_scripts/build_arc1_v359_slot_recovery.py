"""Approved three donors, two quizzes, and two control-preserving speeches."""
import json,html,hashlib,shutil
from zipfile import ZipFile,ZIP_DEFLATED
from pathlib import Path
import review_editor as e
import build_arc1_v357_user_reviewed_dialogue_bankb as b
import build_arc1_v359_review_all as previous
ROOT=previous.ROOT
BASE=ROOT/'03_output/arc1_v359_review_all_final_TEST_ONLY.zip'
OUT=ROOT/'03_output/arc1_v359_slot_recovery2_TEST_ONLY.zip'
AN=ROOT/'01_work/analysis/dialogue_review_20260905/slot_recovery'
PIN='0C8482782890EB5A83C6D9A40A788177602E70A1D15C26AF49B7A4D9DA5A7D06'
DONORS={1717:(5,'아크더래드 제작진은?'),1720:(6,'수도의 군 본부에는 사실 지하 50층 던전이...'),1743:(14,'틀렸지만, 노력은 인정하마.')}
TARGETS={1724:'|저거|그거|어느 거|비밀',1733:'|노랑|사정상 갈빛|실은 빨강|누구?'}
def digest(d):return hashlib.sha256(d).hexdigest().upper()
def main():
 AN.mkdir(parents=True,exist_ok=True)
 if not (AN/'canonical_before.csv').exists():shutil.copy2(ROOT/'05_docs/script_translated_full.csv',AN/'canonical_before.csv')
 assert digest((AN/'canonical_before.csv').read_bytes())=='26EC84DC29CC75E8D088314607C33DA85F8F3F39E8503F4516AB2C3721F0FFFF'
 e.TRANSLATED=AN/'canonical_before.csv'
 ed=e.Editor.__new__(e.Editor);ed.load()
 assert digest(BASE.read_bytes())==PIN
 with ZipFile(BASE) as z:infos=z.infolist();old={i.filename:z.read(i) for i in infos}
 current=dict(old);records=[]
 name='6/S6054.DAT';data=bytearray(current[name])
 for n,(slot,text) in DONORS.items():
  line=ed.lines[n-1];assert line.file==name
  at=int(line.offset,0)+7;pair=bytes((0xE2,0xD1+slot));loc=0x4200+128*slot
  assert bytes(data).count(pair)==1 and data[at:at+2]==pair
  room=2+data[loc+127];payload=b.encoded(text,ed.table)
  assert len(payload)<=room
  before=bytes(data)
  data[at:at+room]=payload.ljust(room,b'\xA1')
  assert pair not in data
  # Only now is the known translation-owned 128-byte slot reclaimed.
  data[loc:loc+128]=bytes(128)
  records.append(dict(row=n,file=name,before=line.korean,target='라마다 승려: '+text,
                      reclaimed_slot=slot,writes=previous.hunks(before,bytes(data))))
 current[name]=bytes(data)
 for n,text in TARGETS.items():
  line=ed.lines[n-1];at=int(line.offset,0);before=current[name]
  planner=previous.Planner(name,before,ed.originals[name],ed.table)
  spans,controls=b.structure(line.raw);spans=[s for s in spans if s[1]>s[0]]
  parts=[x for x in text.split('|') if x];assert len(parts)==len(spans)
  for (lo,hi),part in zip(spans,parts):
   assert b.wrapped_rows(b.encoded(part,ed.table))==1
   planner.place(at+lo,hi-lo,part,f'row {n}')
  after=bytes(planner.data)
  for p,t in controls:assert after[at+p:at+p+2]==t
  current[name]=after
  records.append(dict(row=n,file=name,before=line.korean,target=text,writes=previous.hunks(before,after)))
 # Original 1-byte delay slots can encode these exact one-byte Korean tokens.
 n=2152;line=ed.lines[n-1];name=line.file;at=int(line.offset,0);before=current[name]
 spans,controls=b.structure(line.raw)
 parts=['로크톨:','그야말로','이','피비린내 나는','무투 대회의']
 tail=list('승자를위한것이아니겠습니까?')
 assert all(len(b.encoded(c,ed.table))==1 for c in tail)
 for lo,hi in spans[5:]:
  parts.append(tail.pop(0) if hi>lo and tail else '')
 assert not tail and len(parts)==len(spans)
 planner=previous.Planner(name,before,ed.originals[name],ed.table)
 for p,t in controls:planner.data[at+p:at+p+2]=t
 for (lo,hi),text in zip(spans,parts):
  if hi>lo:planner.place(at+lo,hi-lo,text,'row 2152')
 after=bytes(planner.data)
 for p,t in controls:assert after[at+p:at+p+2]==t
 current[name]=after
 records.append(dict(row=n,file=name,before=line.korean,target='로크톨: 그야말로 이 피비린내 나는 무투 대회의 승자를 위한 것이 아니겠습니까?',writes=previous.hunks(before,after)))
 # Preserve every original dramatic pause in the elemental-stone recital.
 n=1551;line=ed.lines[n-1];name=line.file;at=int(line.offset,0);before=current[name]
 spans,controls=b.structure(line.raw)
 parts=['대지의 돌:','','','.','.','.','서방','의','','','카델','','땅에','','','','','봉인된','','바람의','','','','','','힘','','.']
 assert len(parts)==len(spans)
 planner=previous.Planner(name,before,ed.originals[name],ed.table)
 for p,t in controls:planner.data[at+p:at+p+2]=t
 for (lo,hi),text in zip(spans,parts):
  if hi>lo:planner.place(at+lo,hi-lo,text,'row 1551')
  else:assert not text
 after=bytes(planner.data);current[name]=after
 records.append(dict(row=n,file=name,before=line.korean,target='대지의 돌: ...서방의 카델 땅에 봉인된 바람의 힘.',writes=previous.hunks(before,after)))
 reverse={v:k for k,v in ed.table.items()}
 for rec in records:
  line=ed.lines[rec['row']-1];at=int(line.offset,0)
  ts=previous.read_tokens(current[line.file],at,len(line.raw))
  assert previous.compact(''.join(reverse[t] for t in ts if t[0] not in b.STRUCTURAL_LEADS))==previous.compact(rec['target'])
  assert [t for t in ts if t[0] in b.STRUCTURAL_LEADS]==[t for _,t in b.structure(line.raw)[1]]
  for p,t in b.structure(line.raw)[1]:assert current[line.file][at+p:at+p+2]==t
  rec['readback']='PASS'
  rec['offset']=line.offset
  rec['control_count']=len(b.structure(line.raw)[1])
  if not line.is_choice:
   x=0;row=1;vis=1
   for t in ts:
    if t[0]==0xE6:x=0;row+=1
    elif t[0] in b.STRUCTURAL_LEADS:continue
    else:
     if x+b.advance(t)>=228:row+=1;x=0
     x+=b.advance(t)
     if t!=e.SPACE_CODE:vis=max(vis,row)
   assert vis<=max(4,line.rows),(rec['row'],vis)
   rec['visible_rows']=vis
 assert {n for n in old if current[n]!=old[n]}=={'6/S6054.DAT','7/S7032.DAT','6/S6013.DAT'}
 assert all(len(current[n])==len(old[n]) for n in old)
 replay={n:bytearray(v) for n,v in old.items()}
 for rec in records:
  for w in rec['writes']:
   a=bytes.fromhex(w['before']);v=bytes.fromhex(w['after']);p=w['at']
   assert replay[rec['file']][p:p+len(a)]==a
   replay[rec['file']][p:p+len(a)]=v
 assert all(bytes(replay[n])==current[n] for n in old)
 # Recheck every other previously accepted dialogue after the donor reallocation.
 oldreport=json.loads((previous.OUT/'build_report.json').read_text(encoding='utf-8'))
 newids={r['row'] for r in records}
 for rec in oldreport['rows']:
  if rec['status']!='BUILT' or rec['row'] in newids:continue
  line=ed.lines[rec['row']-1];at=int(line.offset,0)
  assert previous.read_tokens(old[line.file],at,len(line.raw))==previous.read_tokens(current[line.file],at,len(line.raw))
 untouched_count=0
 for line in ed.lines:
  if line.file not in {'6/S6054.DAT','7/S7032.DAT','6/S6013.DAT'} or line.n in newids:continue
  at=int(line.offset,0)
  assert previous.read_tokens(old[line.file],at,len(line.raw))==previous.read_tokens(current[line.file],at,len(line.raw)),(line.n,'neighbor changed')
  untouched_count+=1
 if OUT.exists():
  with ZipFile(OUT) as z:assert all(z.read(n)==current[n] for n in current)
 else:
  with ZipFile(OUT,'w',compression=ZIP_DEFLATED,compresslevel=9) as z:
   for i in infos:z.writestr(i,current[i.filename],compress_type=ZIP_DEFLATED,compresslevel=9)
 report=dict(status='RECOVERY CHECKS PASS / RUNTIME PENDING / TEST_ONLY',zip=str(OUT),
             zip_sha256=digest(OUT.read_bytes()),base_sha256=PIN,
             untouched_neighbor_rows=untouched_count,rows=records,
             review_total=215,review_applied=212,review_held=3,
             unresolved=[{'rows':[1481,1482],'file':'5/S5025.DAT','required_name':'오돈','missing_glyph':'돈','reason':'확인된 고유명사; 임의 개명 금지. 기존 아버지 오역 미해결.'},
                         {'rows':[1703],'file':'6/S6054.DAT','required_name':'초빈','missing_glyph':'빈','reason':'인명 구별 선택지. 원문과 다른 초비/초카라는 이번에 변경하지 않음.'}])
 (AN/'report.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
 print(report['status'],report['zip_sha256'])
if __name__=='__main__':main()
