from zipfile import ZipFile
from pathlib import Path
from PIL import Image
from extract_story_corpus import bitmap_key_from_comm
from v354_dialogue_codec import load_v354,encode,tokens
_,_,enc,dec=load_v354()
for text in ['승려: 그럼 장난삼아|오셨습니까?','승려: 다음 문제를 다 맞히시면|좋은 걸 알려 드리겠습니다.','문제: 지금 일행은 모두 몇 명입니까?','문제: 지금 일행은 모두 몇 명인가요?','다시 찾아오십시오.','타이틀로고']:
 b,missing=encode(text,enc,True);print(repr(text),len(b),missing,b.hex(' '))
with ZipFile('00_original/arc.zip') as z:comm=z.read('COMM.IMG')
im=Image.new('RGB',(240,60),'white')
for j,index in enumerate([0x15,0x16,0x17,0x18]):
 bits=bitmap_key_from_comm(comm,index);g=Image.new('RGB',(12,12),'white')
 for y in range(12):
  for x in range(12):
   if int.from_bytes(bits[y*2:y*2+2],'little')>>x&1:g.putpixel((x,y),(0,0,0))
 im.paste(g.resize((48,48),Image.Resampling.NEAREST),(j*60,0))
p=Path('01_work/analysis/v366_followups');p.mkdir(exist_ok=True)
im.save(p/'original_choice_digits.png')
