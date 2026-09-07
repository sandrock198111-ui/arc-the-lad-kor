"""Read-only capture audit of four V367 user states."""
from pathlib import Path
from zipfile import ZipFile
from array import array
import hashlib,json,struct
from PIL import Image
from extract_duckstation_savestate import decompress
from audit_arc1_9118_runtime import load
from analyze_arc1_v320c_savestates import object_at
from analyze_arc1_v163_runtime import trace_active_text_ot
from build_arc1_v320_hanme_static_recovery import read_plane
from audit_arc1_v363_speaker_cursor import expand
from v354_dialogue_codec import load_v354
ROOT=Path(__file__).resolve().parents[1]
AN=ROOT/'01_work/analysis/v367_user4';AN.mkdir(exist_ok=True)
FOLDERS=['2cad065c-807d-43a6-bef2-7a632c74b4ac','e5dfc7a3-d310-47e0-a020-3c61505c999a','31b4220a-abe4-41a7-919d-4e4893de632f','d61184f7-9540-4cc1-a16c-95ca43f8d763']
with ZipFile(ROOT/'03_output/arc1_v367_quiz_TEST_ONLY.zip') as z:exe=z.read('PSX.EXE');dat=z.read('6/S6054.DAT')
catalog=json.loads((ROOT/'01_work/analysis/v367_quiz/audit.json').read_text(encoding='utf-8'))['entries']
results=[]
decoder=load_v354()[3]
for n,folder in enumerate(FOLDERS,1):
 p=Path('C:/Users/Administrator/.paseo/uploads')/('upload_'+folder)/f'HASH-477B29575D051C04_{n}.sav'
 raw=p.read_bytes();ram,vram,rb,vb=load(p,exe)
 Image.frombytes('RGBA',(256,192),decompress(p,'first'),'raw','BGRA').convert('RGB').save(AN/f'thumb{n}.png')
 words=array('H',vram)
 rgb=bytes(c for w in words for c in ((w&31)*255//31,((w>>5)&31)*255//31,((w>>10)&31)*255//31))
 im=Image.frombytes('RGB',(1024,512),rgb)
 for y in (0,240,256):im.crop((0,y,320,y+240)).save(AN/f'frame{n}_{y}.png')
 state,packets=object_at(ram,0x1f9d44,{'physical_chars':{}})
 ptr=int(state['source_pointer'],16);off=(ptr&0x1fffff)-0xcf000
 matches=[e for e in catalog if int(e['offset'],16)<=off<=int(e['end'],16)]
 result=dict(slot=n,sha256=hashlib.sha256(raw).hexdigest(),title=raw[8:128].split(b'\0')[0].decode(),
  state=state,packets=packets,source=hex(off),matches=matches,
  quiz_ram_matches=ram[0x11295a:0x114e50]==dat[0x4395a:0x45e50],
  choice_fields=struct.unpack_from('<4h',ram,0x1fe2ba))
 results.append(result)
 _,_,active=trace_active_text_ot(ram)
 result['triangles']=[dict(address=hex(q['address']),xy=[struct.unpack_from('<hh',ram,(q['address']&0x1fffff)+k) for k in (8,12,16)]) for q in active if q['command']&0xfc==0x20 and q['address'] in (0x801f2fd4,0x801f2fe8)]
 result['cursor_global']=struct.unpack_from('<hh',ram,0x1f2fc4)
 result['row_ys']=sorted(set(q['y'] for q in packets))
 if matches:
  e=matches[0];ts=[t for t in expand(dat,int(e['offset'],16),e['bytes']) if t!=b'\xe6\x01']
  assert len(ts)==len(packets)
  rows={}
  for t,q in zip(ts,packets):rows[q['y']]=rows.get(q['y'],'')+decoder[t]
  result['visible_rows']=rows
  print('ROWS',rows)
 if n<=2:
  resident=b''.join(vram[y*2048+640:y*2048+640+896] for y in range(512))
  result['ink']=[]
  for q in [packets[0],packets[1],packets[7],packets[8]]:
   rows=read_plane(resident,q['physical_index']);ys=[i for i,r in enumerate(rows) if r]
   result['ink'].append(dict(index=q['physical_index'],packet_y=q['y'],ink_top=q['y']+min(ys),ink_bottom=q['y']+max(ys)))
  print('INK',result['ink'])
 print('CURSOR',result['triangles'],result['cursor_global'],result['row_ys'])
 print(n,result['title'],result['quiz_ram_matches'],hex(off),state,[(e['offset'],e['current_decode']) for e in matches])
(AN/'states.json').write_text(json.dumps(results,ensure_ascii=False,indent=2),encoding='utf-8')
