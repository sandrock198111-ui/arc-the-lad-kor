"""Read-only RAM/VRAM evidence extraction; no build or state edits."""
from pathlib import Path
from zipfile import ZipFile
import json
from array import array
from PIL import Image
from extract_duckstation_savestate import decompress
import analyze_arc1_v320c_savestates as a
ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'01_work/analysis/issues_9118_20260906'
BUILD=ROOT/'03_output/arc1_v359_review_215_TEST_ONLY.zip'

def load(p, exe):
    raw=p.read_bytes()
    assert raw[:5]==b'DUCCV'
    blob=decompress(p)
    rb=a.section_end(blob,'Bus')+64
    anchors=[0x800,0x1000,0x2000,0x44950,0x80dea,0x80f02]
    for off in anchors:
        sig=exe[off:off+48]
        assert blob.find(sig)==rb+0x11a800+off,(p.name,off)
    vb=a.locate_vram(blob)
    return blob[rb:rb+a.RAM_SIZE],blob[vb:vb+a.VRAM_SIZE],rb,vb

def run():
    exe=ZipFile(BUILD).read('PSX.EXE')
    report=[]
    for p in sorted(Path('C:/Users/Administrator/.paseo/uploads').glob('upload_*/HASH-9118D5AA9448C036_*.sav')):
        n=int(p.stem.rsplit('_',1)[1]);ram,vram,rb,vb=load(p,exe)
        objects=a.find_text_objects(ram,{'physical_chars':{}})
        for h in [0x1f9d44,0x1f9d88]:
            try:
                state,packets=a.object_at(ram,h,{'physical_chars':{}})
                objects.append({'state':state,'packets':packets})
            except (ValueError,IndexError): pass
        words=array('H',vram)
        rgb=bytes(channel for w in words for channel in ((w&31)*255//31,((w>>5)&31)*255//31,((w>>10)&31)*255//31))
        im=Image.frombytes('RGB',(1024,512),rgb)
        im.save(OUT/f'vram{n}.png')
        for y in [0,256]: im.crop((0,y,320,y+240)).save(OUT/f'frame{n}_{y}.png')
        entry={'slot':n,'ram_base':hex(rb),'vram_base':hex(vb),'objects':objects}
        report.append(entry)
        print('SLOT',n,'objects',len(objects))
        for ob in objects:
            s=ob['state'];ps=ob['packets']
            if ps: print(s,'rows',sorted(set((q['y'],q['h']) for q in ps)))
    (OUT/'runtime.json').write_text(json.dumps(report,indent=2),encoding='utf-8')

if __name__=='__main__':run()
