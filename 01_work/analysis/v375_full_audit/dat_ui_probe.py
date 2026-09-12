"""Original-bounded DAT UI inventory; no canonical/game writes."""
import sys,csv,json
from pathlib import Path
from zipfile import ZipFile
from collections import Counter
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/'02_scripts'))
import audit_arc1_v375_full_inventory as inv
from audit_arc1_v363_speaker_cursor import expand
from extract_story_corpus import token_end
AN=Path(__file__).resolve().parent
def rows(n):return list(csv.DictReader((ROOT/n).open(encoding='utf-8-sig')))
original={n:ZipFile(inv.ORIGINAL).read(n) for n in ZipFile(inv.ORIGINAL).namelist() if n.endswith('.DAT')}
current={n:ZipFile(inv.BASE).read(n) for n in ZipFile(inv.BASE).namelist() if n.endswith('.DAT')}
exe=ZipFile(inv.BASE).read('PSX.EXE');decode=inv.make_decoder(exe)
entries={}
for r in rows('01_work/analysis/story_corpus/story_corpus.csv'):
 n=r['file'].replace('\\','/');at=int(r['payload_start'],0);end=int(r['end_exclusive'],0)
 entries[(n,at)]=dict(file=n,offset=at,end=end,original_japanese=r['decoded_jp'],confidence=r['confidence'],sources=['story_corpus'])
for i,r in enumerate(rows('05_docs/script_original_full.csv'),1):
 n=r['source file'];at=int(r['byte offset'],0);end=at+len(bytes.fromhex(r['raw bytes as hex']))
 if (n,at) not in entries:entries[(n,at)]=dict(file=n,offset=at,end=end,confidence='canonical',sources=[])
 entries[(n,at)].update(original_japanese=r['decoded Japanese'],canonical_row=i)
 entries[(n,at)]['sources'].append('script_original_full')
quiz=json.loads((ROOT/'01_work/analysis/v368_linebreaks/audit.json').read_text(encoding='utf-8'))['entries']
for q in quiz:
 n='6/S6054.DAT';at=int(q['offset'],0);end=int(q['end'],0)
 assert token_end(original[n],at)==end
 assert original[n][at-8:at]==bytes.fromhex('290000007f001900')
 if (n,at) not in entries:entries[(n,at)]=dict(file=n,offset=at,end=end,confidence='quiz_bounded',sources=[],original_japanese=q['japanese_map_preview'])
 entries[(n,at)]['sources'].append('quiz107')
for filename in ['05_docs/story_all_choices_v21_translation.csv','05_docs/ui_battle_choice_v39.csv']:
 for r in rows(filename):
  n=r['file'];at=int(r['offset'],0)
  if (n,at) in entries:entries[(n,at)]['sources'].append(filename.split('/')[-1])
  else:raise RuntimeError(('uncatalogued legacy choice',n,at))
result=[]
for (n,at),e in sorted(entries.items()):
 raw=original[n][at:e['end']];ts=list(inv.codec.tokens(raw))
 choice=sum(t[0]==0xe5 for t in ts)
 if not(choice or 'quiz107' in e['sources']):continue
 d=current.get(n,original[n])
 try:expanded=expand(d,at,len(raw));current_raw=b''.join(expanded);ko,unknown=decode(current_raw);error=''
 except Exception as exc:current_raw=b'';ko='';unknown='';error=str(exc)
 result.append(dict(id=f'{n}:{at:X}',**e,original_choice_count=choice,current_choice_count=sum(t[0]==0xe5 for t in inv.codec.tokens(current_raw)),current_korean=ko,current_unknown=unknown,expansion_error=error,original_hex=raw.hex(),current_expanded_hex=current_raw.hex(),scope='choice_or_quiz',status='UNREVIEWED',finding=''))
TUTORIAL_FILES=['1/S1023.DAT','21/S2041.DAT','21/S2042.DAT','21/S2045.DAT','31/S3012.DAT','31/S3013.DAT','31/S3014.DAT','5/S5013.DAT','6/S6014.DAT','7/S7012.DAT','8/S8013.DAT']
known={r['id'] for r in result}
for (n,at),e in sorted(entries.items()):
 if n not in TUTORIAL_FILES or e['confidence']!='high' or f'{n}:{at:X}' in known:continue
 raw=original[n][at:e['end']];d=current.get(n,original[n]);expanded=b''.join(expand(d,at,len(raw)));ko,unknown=decode(expanded)
 result.append(dict(id=f'{n}:{at:X}',**e,original_choice_count=0,current_choice_count=sum(t[0]==0xe5 for t in inv.codec.tokens(expanded)),current_korean=ko,current_unknown=unknown,expansion_error='',original_hex=raw.hex(),current_expanded_hex=expanded.hex(),scope='tutorial_file_nonchoice',status='UNREVIEWED',finding=''))
if __name__=='__main__':
 with (AN/'dat_ui_candidates.csv').open('w',encoding='utf-8-sig',newline='') as f:
  w=csv.DictWriter(f,fieldnames=sorted(set().union(*(r.keys() for r in result))));w.writeheader();w.writerows(result)
 print('COUNTS',len(result),Counter(r['confidence'] for r in result),Counter(r['file'] for r in result))
 for i,r in enumerate(result):print(i,r['id'],r['original_choice_count'],r['confidence'],r['original_japanese'].replace('\n','|'),'=>',r['current_korean'])
