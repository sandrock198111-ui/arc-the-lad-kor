"""Read-only evidence for user V368 overflow/loop captures; no state edits."""
from pathlib import Path
from zipfile import ZipFile
import json,struct,hashlib
from PIL import Image
from extract_duckstation_savestate import decompress
from audit_arc1_9118_runtime import load
from analyze_arc1_v320c_savestates import object_at
from analyze_arc1_v320c_savestates import section_end
from build_arc1_v359_thin_font_preview import load_targets
from build_arc1_v320_hanme_static_recovery import read_plane
ROOT=Path(__file__).resolve().parents[1]
AN=ROOT/'01_work/analysis/v368_followup';AN.mkdir(exist_ok=True)
FOLDERS=['722b5e3d-666d-4150-ad84-e3a5a05d0d74','0aab59e5-6068-421e-b886-5bfa43d9365e']
def states():
    with ZipFile(ROOT/'03_output/arc1_v368_linebreaks_TEST_ONLY.zip') as z:exe=z.read('PSX.EXE')
    for n,folder in enumerate(FOLDERS,1):
        p=Path('C:/Users/Administrator/.paseo/uploads')/('upload_'+folder)/f'HASH-477B29575D051C04_{n}.sav'
        ram,vram,rb,vb=load(p,exe)
        yield n,p,ram,vram
def main():
    results=[]
    for n,p,ram,vram in states():
        Image.frombytes('RGBA',(256,192),decompress(p,'first'),'raw','BGRA').convert('RGB').save(AN/f'thumb{n}.png')
        entry=dict(slot=n,sha256=hashlib.sha256(p.read_bytes()).hexdigest(),objects=[],
            script_index=hex(struct.unpack_from('<I',ram,0x1fe2b4)[0]),
            script_base=hex(struct.unpack_from('<I',ram,0x1b1acc)[0]))
        fn=['6/S6013.DAT','7/S7021.DAT'][n-1]
        with ZipFile(ROOT/'03_output/arc1_v368_sans_font_TEST_ONLY.zip') as z:
            data=z.read(fn);comm=z.read('COMM.IMG')
        resident=b''.join(vram[y*2048+640:y*2048+1536] for y in range(512))
        entry['sans_planes_matching']=sum(read_plane(resident,i)==read_plane(comm,i) for i in load_targets()[2])
        entry['script_file']=fn
        entry['script_region_47800_49800_matches']=ram[0x116800:0x118800]==data[0x47800:0x49800]
        entry['script_index_low16']=hex(struct.unpack_from('<H',ram,0x1fe2b4)[0])
        blob=decompress(p);cpu=section_end(blob,'CPU')
        entry['cpu_fields']={hex(at):hex(struct.unpack_from('<I',blob,cpu+at)[0]) for at in (0x8c,0xb8,0xc0,0xc4,0xd4)}
        for at in (0x1f9d44,0x1f9d88):
            s,packets=object_at(ram,at,{'physical_chars':{}})
            entry['objects'].append(dict(state=s,packets=packets))
            print(n,s,'Y',sorted(set(q['y'] for q in packets)))
        results.append(entry)
        print('EVENT',entry['script_index'],entry['script_base'])
    (AN/'states.json').write_text(json.dumps(results,ensure_ascii=False,indent=2),encoding='utf-8')
if __name__=='__main__':main()
