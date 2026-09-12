"""Enumerate V375 UI from original pointer IDs; write analysis only.

No game file, canonical translation or build input is modified. Historical
translations are context, never a substitute for decoding the current bytes.
"""
from pathlib import Path
from zipfile import ZipFile
import csv, hashlib, json, struct, sys
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'02_scripts'))
import audit_psx_ui_tables as ui
import v354_dialogue_codec as codec
import build_arc1_v360_ui_restore as storage
from extract_story_corpus import bitmap_key_from_comm
from PIL import Image, ImageDraw
AN = ROOT/'01_work/analysis/v375_full_audit'
BASE = ROOT/'03_output/arc1_v375_next_choice_TEST_ONLY.zip'
ORIGINAL = ROOT/'00_original/arc.zip'
BIAS = 0x8011A800

def digest(data): return hashlib.sha256(data).hexdigest().upper()
def rows(path):
    with path.open(encoding='utf-8-sig', newline='') as f: return list(csv.DictReader(f))
def write_csv(path, data):
    if not data: return
    with path.open('w',encoding='utf-8-sig',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(data[0]));w.writeheader();w.writerows(data)

def make_decoder(exe):
    _,_,_,reverse=codec.load_v354()
    # Resolve alternate codes through the same current physical index. Keep
    # ambiguity visible instead of selecting a character by expected wording.
    physical={}
    for token,char in reverse.items():
        if token[0] in (0xe2,0xe4,0xe5,0xe6,0xe7,0xe8): continue
        try: index=codec._resolve_index(exe,token)
        except Exception: continue
        physical.setdefault(index,set()).add(char)
    def decode(raw):
        out=[];unknown=[]
        for token in codec.tokens(raw):
            if token==b'\xe6\x01': out.append('|');continue
            if token[0] in (0xe2,0xe4,0xe5,0xe6,0xe7,0xe8):
                out.append('<CTRL:'+token.hex().upper()+'>');continue
            if token in reverse:out.append(reverse[token]);continue
            try: chars=physical.get(codec._resolve_index(exe,token),set())
            except Exception:chars=set()
            if len(chars)==1:out.append(next(iter(chars)))
            else:
                out.append('<CODE:'+token.hex().upper()+'>');unknown.append(token.hex().upper())
        return ''.join(out),','.join(sorted(set(unknown)))
    return decode

def raw_at(exe, offset):
    result=bytearray();p=offset
    while 0<=p<len(exe) and len(result)<512:
        lead=exe[p]
        if lead==0:return bytes(result)
        n=1 if lead<0xdd else 2
        result.extend(exe[p:p+n]);p+=n
    raise ValueError(f'No terminator at {offset:X}')

def main():
    AN.mkdir(parents=True,exist_ok=True)
    with ZipFile(ORIGINAL) as z: original={n:z.read(n) for n in z.namelist() if not n.endswith('/')}
    with ZipFile(BASE) as z: patch={n:z.read(n) for n in z.namelist()}
    exe=patch['PSX.EXE'];orig=original['PSX.EXE'];decode=make_decoder(exe)
    glyphs,_,nearest,_=ui.build_glyph_map()
    entries={}
    for spec in ui.TABLES:
        for i in range(spec.count):
            entries[spec.pointer_offset+4*i]=dict(id=f'{spec.key}:{i}',group=spec.key,index=i,historical_korean='')
    for filename in ['ui_full_v42.csv','ui_system_v39.csv','ui_nonstory_system_v39.csv','ui_world_name_v39.csv']:
        for r in rows(ROOT/'05_docs'/filename):
            ptr=int(r['pointer_offset'],0)
            if ptr not in entries:entries[ptr]=dict(id=f'ui_pointer:{ptr:05X}',group=filename.removesuffix('.csv'),index='',historical_korean='')
            entries[ptr]['historical_korean']=r.get('korean',r.get('korean_target',''))
    # Original memory-card slot selector uses these literal pointers, outside
    # the legacy 671-pointer catalog; V374 changed their actual labels.
    for i in range(2):
        ptr=0x78088+4*i
        entries.setdefault(ptr,dict(id=f'card_label:{i+1}',group='card_label',index=i+1,historical_korean=''))
    inventory=[];original_raws=[]
    for ptr,entry in sorted(entries.items()):
        original_pointer=struct.unpack_from('<I',orig,ptr)[0]
        current_pointer=struct.unpack_from('<I',exe,ptr)[0]
        raw=raw_at(orig,original_pointer-BIAS)
        try:jp,_=ui.decode_string(orig,original_pointer-BIAS,glyphs,nearest)
        except Exception as error:jp=f'<DECODE_ERROR:{error}>'
        current=storage.string_at(exe,current_pointer)
        ko,unknown=decode(current)
        hud=ptr in (0x823ac,0x823b0,0x823b4,0x823b8,0x823bc)
        inventory.append(dict(**entry,pointer_offset=f'0x{ptr:X}',original_pointer=f'0x{original_pointer:X}',current_pointer=f'0x{current_pointer:X}',japanese=jp,current_korean=ko,unknown_codes=unknown,original_hex=raw.hex(' ').upper(),current_hex=current.hex(' ').upper(),storage_class='HUD_BINARY' if hud else 'text',empty_original=not raw,empty_current=not current,review_status='PENDING'))
        original_raws.append(raw)
    write_csv(AN/'ui_inventory.csv',inventory)
    (AN/'ui_inventory.json').write_text(json.dumps(inventory,ensure_ascii=False,indent=2),encoding='utf-8')
    # All source labels are independently rendered with original Japanese
    # glyph pixels, so an approximate historical transcription can be checked.
    for page in range((len(inventory)+15)//16):
        im=Image.new('RGB',(1500,16*96),'white');draw=ImageDraw.Draw(im)
        for slot,r in enumerate(inventory[page*16:page*16+16]):
            draw.text((5,slot*96+2),f'{page*16+slot+1}: {r["id"]} @{r["pointer_offset"]}',fill='black')
            x=5;y=slot*96+20
            for tok in codec.tokens(original_raws[page*16+slot]):
                if tok[0]>=0xe1:
                    draw.text((x,y),'['+tok.hex()+']',fill='red');x+=90;continue
                index=tok[0]-1 if len(tok)==1 else (tok[0]-0xdd)*255+tok[1]+0xdb
                if x+24>=1500:x=5;y+=26
                bits=bitmap_key_from_comm(original['COMM.IMG'],index)
                g=Image.new('RGB',(12,12),'white')
                for gy in range(12):
                    word=int.from_bytes(bits[gy*2:gy*2+2],'little')
                    for gx in range(12):
                        if word>>gx&1:g.putpixel((gx,gy),(0,0,0))
                im.paste(g.resize((24,24),Image.Resampling.NEAREST),(x,y));x+=25
        im.save(AN/f'original_ui_{page+1:02d}.png')
    from collections import Counter
    meta=dict(original_sha256=digest(ORIGINAL.read_bytes()),build_sha256=digest(BASE.read_bytes()),original_exe_sha256=digest(orig),build_exe_sha256=digest(exe),inventory_count=len(inventory),groups=dict(Counter(r['group'] for r in inventory)),unknown_code_rows=sum(bool(r['unknown_codes']) for r in inventory),enumeration_scope='671 historical pointer records + 2 memory-card label records; additional reference/inline census remains required',complete=False)
    (AN/'inventory_meta.json').write_text(json.dumps(meta,ensure_ascii=False,indent=2),encoding='utf-8');print(json.dumps(meta,ensure_ascii=False))

if __name__=='__main__':main()
