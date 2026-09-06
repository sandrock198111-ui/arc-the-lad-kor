import csv, sys, zipfile
from pathlib import Path
from PIL import Image, ImageDraw
ROOT=Path('E:/korean')
sys.path.insert(0,str(ROOT/'02_scripts'))
from extract_story_corpus import bitmap_key_from_comm
rows=list(csv.DictReader((ROOT/'05_docs/script_original_full.csv').open(encoding='utf-8-sig',newline='')))
out=Path(__file__).parent
z=zipfile.ZipFile(ROOT/'00_original/arc.zip')
comm=z.read('COMM.IMG')
for num in [208,347,601,743,1089,1104,1481,1482,1640,1650,2242,2255,2261,2263,2300,2767,2789]:
    r=rows[num-1]; raw=bytes.fromhex(r['raw bytes as hex']); off=int(r['byte offset'],16)
    assert z.read(r['source file'])[off:off+len(raw)]==raw
    indices=[]; pos=0
    while pos<len(raw):
        b=raw[pos]
        if b in [0xE4,0xE6]: indices.append(None); pos+=2
        elif 0xDD<=b<=0xE0: indices.append((b-0xDD)*255+raw[pos+1]+0xDB); pos+=2
        elif 1<=b<0xDD: indices.append(b-1); pos+=1
        else: pos+=1
    im=Image.new('RGB',(1100,750),'white'); draw=ImageDraw.Draw(im); x=8;y=20
    draw.text((8,0),f'row {num} / original DAT bytes verified',fill='black')
    for index in indices:
        if index is None or x+50>1100: x=8;y+=65
        if index is None: continue
        key=bitmap_key_from_comm(comm,index); g=Image.new('RGB',(12,12),'white')
        for gy in range(12):
            v=int.from_bytes(key[gy*2:gy*2+2],'little')
            for gx in range(12):
                if v>>gx&1:g.putpixel((gx,gy),(0,0,0))
        im.paste(g.resize((48,48),Image.Resampling.NEAREST),(x,y)); draw.text((x,y+48),str(index),fill='black');x+=50
    im.crop((0,0,1100,y+65)).save(out/f'row_{num}.png')
    print(num,r['source file'],r['byte offset'],indices)
