"""Candidate-only actual renderer/event/input audit; never writes game files."""
import json,io
from zipfile import ZipFile
import build_arc1_v367_quiz as b
import audit_arc1_quiz_complete as audit
from extract_story_corpus import token_end
from verify_arc1_v359_slot_recovery import legacy_gate
def main():
 blob,report=b.prepare()
 assert b.OUT.read_bytes()==blob,'Build the exact candidate archive before final verification'
 with ZipFile(b.BASE) as z:old={n:z.read(n) for n in z.namelist()}
 with ZipFile(io.BytesIO(blob)) as z:new={n:z.read(n) for n in z.namelist()}
 with ZipFile(b.ORIGINAL) as z:o=z.read(b.FN)
 assert old.keys()==new.keys()
 allowed=set()
 for e in report['entries']:
  at=e['offset'];end=token_end(o,at)
  assert end==e['end'] and o[at:end+1]==old[b.FN][at:end+1]
  allowed.update(range(at,end))
  if e['option_packet_starts'] is not None:allowed.update(range(((end+3)&~1)+10,((end+3)&~1)+12))
 for name in old:
  assert len(old[name])==len(new[name])
  if name!=b.FN:assert old[name]==new[name]
  else:assert all(x==y or i in allowed for i,(x,y) in enumerate(zip(old[name],new[name])))
 assert b.prepare()[0]==blob
 audit.main(blob,b.AN)
 a=json.loads((b.AN/'audit.json').read_text(encoding='utf-8'))
 c=a['counts']
 assert c['entries']==107 and c['questions']==29 and c['choice_windows']==31
 assert c['original_identical']==c['cpu_errors']==c['misaligned_windows']==c['over_four_rows']==0,c
 assert c['navigation_cases']==240
 for e in a['entries']:
  r=e['renderer']
  assert r['count']<=64 and r['packet_count_matches'] and r['source_end_matches'],e
  assert r['max_right']<=290 and r['max_bottom']<=96,e
  if int(e['offset'],16) in {x['offset'] for x in report['entries']}:assert r['max_right']<=274,e
 before=legacy_gate(b.BASE);after=legacy_gate(b.OUT)
 assert before['fail']==after['fail'],'Inherited failure set changed'
 result=dict(zip_sha256=report['zip_sha256'],static_pass=True,counts=c,
  inherited_failure_counts={k:len(v) for k,v in after['fail'].items()},
  runtime_verified=False,limitation='Actual renderer/event/coordinate/decoded-pad CPU on captured RAM copy. GPU/physical input/branch outcome and human translation review pending.')
 (b.AN/'verification.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
 print('V367 ALL QUIZ CPU PASS',c)
if __name__=='__main__':main()
