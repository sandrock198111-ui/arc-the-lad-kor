"""Read-only state and EXE evidence for item/skill panels; inputs never edited."""
from pathlib import Path
from zipfile import ZipFile
import json, hashlib, struct
from array import array
from PIL import Image
import capstone
import build_arc1_v324_static_ui_cursor_recovery as resident
from audit_arc1_9118_runtime import load
from extract_duckstation_savestate import decompress
import analyze_arc1_v320c_savestates as objects

ROOT=Path(__file__).resolve().parents[1]
AN=ROOT/'01_work/analysis/v360_panels'
BASE=ROOT/'03_output/arc1_v359_cursor_lines_TEST_ONLY.zip'

def run():
    AN.mkdir(parents=True,exist_ok=True)
    exe=ZipFile(BASE).read('PSX.EXE');report=[]
    for p in sorted(Path('C:/Users/Administrator/.paseo/uploads').glob('upload_*/HASH-F5D974ADD31760_*.sav')):
        n=int(p.stem.rsplit('_',1)[1])
        thumb=decompress(p,'first');assert len(thumb)==256*192*4
        Image.frombytes('RGBA',(256,192),thumb,'raw','BGRA').convert('RGB').save(AN/f'slot{n}.png')
        ram,vram,rb,vb=load(p,exe)
        assert ram[resident.HELPER_RAM&0x1fffff:(resident.HELPER_RAM&0x1fffff)+156]==exe[resident.HELPER_SOURCE_FILE:resident.HELPER_SOURCE_FILE+156]
        ob=objects.find_text_objects(ram,{'physical_chars':{}})
        entry={'slot':n,'path':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),
               'title':p.read_bytes()[8:128].split(b'\0')[0].decode('ascii'),'ram_base':rb,'vram_base':vb,
               'panel_xywh':struct.unpack_from('<4i',ram,0x1f0780),'objects':ob}
        report.append(entry)
        rgb=bytes(c for w in array('H',vram) for c in ((w&31)*255//31,((w>>5)&31)*255//31,((w>>10)&31)*255//31))
        im=Image.frombytes('RGB',(1024,512),rgb)
        for y in (0,256):im.crop((0,y,320,y+240)).save(AN/f'frame{n}_{y}.png')
        print('slot',n,entry['title'],entry['panel_xywh'])
        for obj in ob:
            if obj['packets']:print(obj['state'],'rows',sorted(set((q['y'],q['h']) for q in obj['packets'])))
    (AN/'states.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf8')
    md=capstone.Cs(capstone.CS_ARCH_MIPS,capstone.CS_MODE_MIPS32|capstone.CS_MODE_LITTLE_ENDIAN)
    code=[]
    for a,b in [(0x8016c4c0,0x8016c810),(0x801619a0,0x80161bb0)]:
        code.extend(f'{i.address:08X} {i.mnemonic} {i.op_str}' for i in md.disasm(exe[a-0x8011a800:b-0x8011a800],a))
    (AN/'panel_code.txt').write_text('\n'.join(code),encoding='utf8')

if __name__=='__main__':run()
