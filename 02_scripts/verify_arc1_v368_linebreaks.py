"""Verify two exact display rows and preservation of all choice/cursor outputs."""
import json,io
from zipfile import ZipFile
import build_arc1_v368_linebreaks as b
import audit_arc1_quiz_complete as audit
from verify_arc1_v359_slot_recovery import legacy_gate
def main():
 blob,report=b.prepare();assert blob==b.OUT.read_bytes()
 with ZipFile(b.BASE) as z:old={n:z.read(n) for n in z.namelist()}
 with ZipFile(io.BytesIO(blob)) as z:new={n:z.read(n) for n in z.namelist()}
 assert old.keys()==new.keys()
 allowed={i for at,(size,_) in b.TARGETS.items() for i in range(at,at+size)}
 for fn in old:
  assert len(old[fn])==len(new[fn])
  if fn!=b.FN:assert old[fn]==new[fn],fn
  else:assert all(x==y or i in allowed for i,(x,y) in enumerate(zip(old[fn],new[fn])))
 audit.main(blob,b.AN)
 a=json.loads((b.AN/'audit.json').read_text(encoding='utf-8'))
 baseline=json.loads((b.ROOT/'01_work/analysis/v367_quiz/audit.json').read_text(encoding='utf-8'))
 c=a['counts'];assert c['entries']==107 and c['choice_windows']==31 and c['navigation_cases']==240
 assert c['cpu_errors']==c['over_four_rows']==c['misaligned_windows']==c['original_identical']==0,c
 checked=[]
 for e,prior in zip(a['entries'],baseline['entries']):
  assert e['offset']==prior['offset']
  r=e['renderer'];assert r['packet_count_matches'] and r['source_end_matches'] and r['count']<=64
  assert not r['interior_empty_rows'],e['offset']
  at=int(e['offset'],16)
  if at in b.TARGETS:
   expected=b.TARGETS[at][1].split('|')
   actual=[s.rstrip() for _,s in sorted(r['row_text'].items(),key=lambda kv:int(kv[0]))]
   assert r['ys']==[32,48] and actual==expected,(e['offset'],r,expected)
   checked.append(dict(offset=e['offset'],rows=actual))
  else:
   for key,value in prior['renderer'].items():assert r[key]==value,(e['offset'],key)
  if 'choice' in e:assert e['choice']==prior['choice'],e['offset']
 before=legacy_gate(b.BASE);after=legacy_gate(b.OUT);assert before['fail']==after['fail']
 result=dict(zip_sha256=report['zip_sha256'],static_pass=True,checked=checked,counts=c,
  cursor_windows_unchanged=31,runtime_verified=False,
  limitation='Actual CPU renderer/coordinates/decoded-pad bounds; final GPU/user playback pending.')
 (b.AN/'verification.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
 print('PASS',checked,'31 cursor windows unchanged')
if __name__=='__main__':main()
