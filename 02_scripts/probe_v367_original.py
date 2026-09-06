"""Render only the bounded missing quiz originals for manual reading."""
from pathlib import Path
from zipfile import ZipFile
import json
from PIL import Image,ImageDraw
from extract_story_corpus import bitmap_key_from_comm
from v354_dialogue_codec import tokens
ROOT=Path(__file__).resolve().parents[1]
AN=ROOT/'01_work/analysis/v367_quiz';AN.mkdir(exist_ok=True)
entries=json.loads((ROOT/'01_work/analysis/quiz_v366_audit/audit.json').read_text(encoding='utf-8'))['entries']
with ZipFile(ROOT/'00_original/arc.zip') as z:comm=z.read('COMM.IMG');data=z.read('6/S6054.DAT')
selected=[e for e in entries if e['original_identical']]
for page in range(0,len(selected),10):
 im=Image.new('RGB',(720,10*112),'white');draw=ImageDraw.Draw(im)
 for row,e in enumerate(selected[page:page+10]):
  x=5;y=row*112+15;draw.text((5,row*112),e['offset'],fill='red')
  for t in tokens(data[int(e['offset'],16):int(e['end'],16)]):
   if t==b'\xe6\x01':x=5;y+=24;continue
   if t==b'\xe5\x03':x+=24;continue
   if x>680:x=5;y+=24
   idx=t[0]-1 if len(t)==1 else (t[0]-0xdd)*255+t[1]+0xdb
   bits=bitmap_key_from_comm(comm,idx);g=Image.new('RGB',(12,12),'white')
   for gy in range(12):
    for gx in range(12):
     if int.from_bytes(bits[gy*2:gy*2+2],'little')>>gx&1:g.putpixel((gx,gy),(0,0,0))
   im.paste(g.resize((24,24),Image.Resampling.NEAREST),(x,y));x+=24
 im.save(AN/f'original_{page//10}.png')
print([(e['offset'],e['bytes'],e['japanese_map_preview']) for e in selected])
im=Image.new('RGB',(240,192),'white')
bits=bitmap_key_from_comm(comm,757)
g=Image.new('RGB',(12,12),'white')
for gy in range(12):
 for gx in range(12):
  if int.from_bytes(bits[gy*2:gy*2+2],'little')>>gx&1:g.putpixel((gx,gy),(0,0,0))
im.paste(g.resize((192,192),Image.Resampling.NEAREST),(0,0));im.save(AN/'original_glyph757.png')
