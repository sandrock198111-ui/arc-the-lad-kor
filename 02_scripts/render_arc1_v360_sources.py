"""Render source text from original game glyphs; no guessed OCR corrections."""
from pathlib import Path
from zipfile import ZipFile
from PIL import Image, ImageDraw
import csv,struct
from extract_story_corpus import bitmap_key_from_comm
from v360_ui_targets import TARGETS
ROOT=Path(__file__).resolve().parents[1]
AN=ROOT/'01_work/analysis/v360_panels'
z=ZipFile(ROOT/'00_original/arc.zip');exe=z.read('PSX.EXE');comm=z.read('COMM.IMG')
rows={(r['table_key'],int(r['index'])):r for r in csv.DictReader((ROOT/'05_docs/ui_full_v42.csv').open(encoding='utf-8-sig'))}
keys=list(TARGETS)
for page in range((len(keys)+7)//8):
    im=Image.new('RGB',(1100,8*110),'white');draw=ImageDraw.Draw(im)
    for line,key in enumerate(keys[page*8:page*8+8]):
        r=rows[key];ptr=int(r['pointer_offset'],0);pos=struct.unpack_from('<I',exe,ptr)[0]-0x8011a800
        draw.text((8,line*110+2),f'{key} original 0x{pos:X}',fill='black')
        x=8;y=line*110+20
        while exe[pos]:
            b=exe[pos];pos+=1
            if b>=0xdd:index=(b-0xdd)*255+exe[pos]+0xdb;pos+=1
            else:index=b-1
            if x+24>1100:x=8;y+=27
            bits=bitmap_key_from_comm(comm,index);g=Image.new('RGB',(12,12),'white')
            for gy in range(12):
                v=int.from_bytes(bits[gy*2:gy*2+2],'little')
                for gx in range(12):
                    if v>>gx&1:g.putpixel((gx,gy),(0,0,0))
            im.paste(g.resize((24,24),Image.Resampling.NEAREST),(x,y));x+=25
    im.save(AN/f'original_ui_{page+1}.png')

for num in (1634,2873):
    r=list(csv.DictReader((ROOT/'05_docs/script_translated_full.csv').open(encoding='utf-8-sig')))[num-1]
    print(num,{k:v for k,v in r.items() if k!='raw bytes as hex'})
    source=list(csv.DictReader((ROOT/'05_docs/script_original_full.csv').open(encoding='utf-8-sig')))[num-1]
    raw=bytes.fromhex(source['raw bytes as hex']);offset=int(source['byte offset'],16)
    assert z.read(source['source file'])[offset:offset+len(raw)]==raw
    im=Image.new('RGB',(1100,350),'white');x=8;y=8;pos=0
    while pos<len(raw):
        lead=raw[pos];pos+=1
        if lead in (0xe4,0xe6):pos+=1;x=8;y+=42;continue
        if lead>=0xdd:index=(lead-0xdd)*255+raw[pos]+0xdb;pos+=1
        else:index=lead-1
        if x+36>1100:x=8;y+=42
        bits=bitmap_key_from_comm(comm,index);g=Image.new('RGB',(12,12),'white')
        for gy in range(12):
            v=int.from_bytes(bits[gy*2:gy*2+2],'little')
            for gx in range(12):
                if v>>gx&1:g.putpixel((gx,gy),(0,0,0))
        im.paste(g.resize((36,36),Image.Resampling.NEAREST),(x,y));x+=37
    im.crop((0,0,1100,y+42)).save(AN/f'original_row_{num}.png')
