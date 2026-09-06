"""Read-only diagnosis of six user-uploaded DC429 states; no game edits."""
from pathlib import Path
from zipfile import ZipFile
from array import array
import hashlib,json,csv
from PIL import Image
from extract_duckstation_savestate import decompress
from audit_arc1_9118_runtime import load
import analyze_arc1_v320c_savestates as a

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'01_work/analysis/dc429_followup'
UPLOADS=Path('C:/Users/Administrator/.paseo/uploads')
FOLDERS=['ac41803f-7f66-413b-976b-8003cc350f8b','cfb1a0cb-373b-4016-9050-d9ec2491ad5a',
         'f3a3ecae-5c20-4574-a85a-c3001b12433e','2f7e6a04-6645-4c1b-8628-1ce605fe1de4',
         'e8b8fa4a-2983-452b-88d5-876974b2ee39','505cf548-af4c-4c19-b3ba-ac1d71207dc2']

def main():
    OUT.mkdir(parents=True,exist_ok=True)
    with ZipFile(ROOT/'03_output/arc1_v362_korean_title_TEST_ONLY.zip') as z:exe=z.read('PSX.EXE')
    mapping=a.load_mappings();report=[]
    for n,folder in enumerate(FOLDERS,1):
        path=UPLOADS/('upload_'+folder)/f'HASH-DC42934B1AA4449B_{n}.sav'
        raw=path.read_bytes();ram,vram,rb,vb=load(path,exe)
        thumb=decompress(path,'first')
        assert len(thumb)==256*192*4
        Image.frombytes('RGBA',(256,192),thumb,'raw','BGRA').convert('RGB').save(OUT/f'thumb{n}.png')
        words=array('H',vram)
        rgb=bytes(c for w in words for c in ((w&31)*255//31,((w>>5)&31)*255//31,((w>>10)&31)*255//31))
        im=Image.frombytes('RGB',(1024,512),rgb)
        for y in (0,240,256):im.crop((0,y,320,y+240)).save(OUT/f'frame{n}_{y}.png')
        objects=a.find_text_objects(ram,mapping)
        for header in (0x1f9d44,0x1f9d88):
            state,packets=a.object_at(ram,header,mapping)
            objects.append({'state':state,'packets':packets})
        entry={'slot':n,'sha256':hashlib.sha256(raw).hexdigest(),'title':raw[8:128].split(b'\0')[0].decode('ascii'),
               'ram_offset':rb,'vram_offset':vb,'objects':objects}
        report.append(entry)
        print(n,entry['sha256'],entry['title'])
        for ob in objects:
            if ob['packets']:print(ob['state'],a.packet_text(ob['packets']))
    (OUT/'states.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    from extract_story_corpus import bitmap_key_from_comm
    from v354_dialogue_codec import tokens
    with ZipFile(ROOT/'00_original/arc.zip') as z:
        original=z.read('6/S6054.DAT');comm=z.read('COMM.IMG')
    with ZipFile(ROOT/'03_output/arc1_v362_korean_title_TEST_ONLY.zip') as z:
        current=z.read('6/S6054.DAT')
    start=0x4395a;end=original.index(0,start)
    assert original[start:end+1]==current[start:end+1]
    canvas=Image.new('RGB',(900,180),'white');x=y=6
    for t in tokens(original[start:end]):
        if t==b'\xe6\x01':x=6;y+=40;continue
        if t[0]>=0xe0:x+=72;continue
        index=t[0]-1 if len(t)==1 else (t[0]-0xdd)*255+t[1]+0xdb
        bits=bitmap_key_from_comm(comm,index);g=Image.new('RGB',(12,12),'white')
        for gy in range(12):
            for gx in range(12):
                if int.from_bytes(bits[gy*2:gy*2+2],'little')>>gx&1:g.putpixel((gx,gy),(0,0,0))
        canvas.paste(g.resize((36,36),Image.Resampling.NEAREST),(x,y));x+=36
    canvas.save(OUT/'slot6_original_glyph_evidence.png')
    rows=list(csv.DictReader((ROOT/'05_docs/script_translated_full.csv').open(encoding='utf-8-sig')))
    terms=[{'row':i+1,**r} for i,r in enumerate(rows) if '스승' in r['korean'] or '사범' in r['korean']]
    (OUT/'term_occurrences.json').write_text(json.dumps(terms,ensure_ascii=False,indent=2),encoding='utf-8')
    # Count actual E2-expanded streams, not CSV prose or skipped source tails.
    # Special controls remain unclassified: this is not a complete layout gate.
    from check_build import slot_ref
    originals=list(csv.DictReader((ROOT/'05_docs/script_original_full.csv').open(encoding='utf-8-sig')))
    scan=[]
    with ZipFile(ROOT/'03_output/arc1_v362_korean_title_TEST_ONLY.zip') as z, ZipFile(ROOT/'00_original/arc.zip') as pristine:
        for number,r in enumerate(originals,1):
            data=(z if r['source file'] in z.namelist() else pristine).read(r['source file']);offset=int(r['byte offset'],16)
            raw=bytes.fromhex(r['raw bytes as hex']);body=data[offset:offset+len(raw)]
            expanded=[];at=0;issues=[]
            while at<len(body):
                lead=body[at]
                if not lead:break
                width=1 if lead<0xdd else 2;t=body[at:at+width]
                if lead==0xe2 and len(t)==2:
                    ref=slot_ref(data,t[1])
                    if ref:
                        stored=ref[2];stop=stored.find(b'\0')
                        if stop<0:issues.append('unterminated_slot');break
                        expanded.extend(tokens(stored[:stop]));at+=2+stored[127];continue
                expanded.append(t);at+=width
            special=[t.hex() for t in expanded if t[0]>=0xe1 and t[0] not in (0xe9,0xea) and t!=b'\xe6\x01']
            count=sum(t!=b'\xe6\x01' for t in expanded)
            scan.append({'row':number,'file':r['source file'],'offset':hex(offset),
                         'simple_stream':not special and not issues,'token_count':count,
                         'over64_candidate':not special and not issues and count>64,
                         'special_controls':special,'issues':issues})
    (OUT/'capacity_scan.json').write_text(json.dumps(scan,ensure_ascii=False,indent=2),encoding='utf-8')
    print('capacity rows',len(scan),'simple',sum(r['simple_stream'] for r in scan),
          'over64 candidates',sum(r['over64_candidate'] for r in scan))

if __name__=='__main__':main()
