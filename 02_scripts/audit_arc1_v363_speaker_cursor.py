"""Read-only current-DAT speaker break census and captured cursor comparison."""
from pathlib import Path
from zipfile import ZipFile
import csv,json,struct,hashlib,sys
from check_build import slot_ref
from v354_dialogue_codec import tokens,load_v354
from audit_arc1_9118_runtime import load
from analyze_arc1_v163_runtime import trace_active_text_ot
from analyze_arc1_v320c_savestates import object_at
ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'01_work/analysis/dc429_789'
BASE=ROOT/'03_output/arc1_v363_dialogue_trial_TEST_ONLY.zip'

def expand(data,start,length):
    end=start+length;result=[];at=start
    while at<end:
        lead=data[at]
        if not lead:break
        size=1 if lead<0xdd else 2;t=data[at:at+size]
        if lead==0xe2 and (ref:=slot_ref(data,t[1])):
            s=ref[2];stop=s.find(b'\0');assert 0<=stop<127
            result.extend(tokens(s[:stop]));at+=2+s[127];continue
        result.append(t);at+=size
    return result

def main():
    OUT.mkdir(exist_ok=True);_,_,_,dec=load_v354()
    def decode(ts):return ''.join('\n' if t==b'\xe6\x01' else dec.get(t,'<'+t.hex()+'>') for t in ts)
    originals=list(csv.DictReader((ROOT/'05_docs/script_original_full.csv').open(encoding='utf-8-sig')))
    corpus=list(csv.DictReader((ROOT/'05_docs/script_translated_full.csv').open(encoding='utf-8-sig')))
    with ZipFile(BASE) as z,ZipFile(ROOT/'00_original/arc.zip') as o:
        files={n:z.read(n) for n in z.namelist()};exe=files['PSX.EXE'];candidates=[];challenges=[]
        for number,r in enumerate(originals,1):
            fn=r['source file'];data=files.get(fn)
            if data is None:data=o.read(fn)
            at=int(r['byte offset'],16);ts=expand(data,at,len(bytes.fromhex(r['raw bytes as hex'])))
            text=decode(ts);first=text.split('\n')[0].rstrip()
            entry={'row':number,'file':fn,'offset':hex(at),'current':text,'canonical':corpus[number-1]['korean']}
            if '\n' in text and first.endswith(':') and len(first)<=25:candidates.append(entry)
            if fn=='6/S6054.DAT' and ('挑戦' in r['decoded Japanese'] or '도전' in text):challenges.append(entry)
        low=decode(expand(files['6/S6054.DAT'],0x4395a,46))
        states=[]
        for n in (7,8,9):
            paths=list(Path('C:/Users/Administrator/.paseo/uploads').glob(f'upload_*/HASH-DC42934B1AA4449B_{n}.sav'));assert len(paths)==1
            path=paths[0];ram,_,_,_=load(path,exe)
            _,_,active=trace_active_text_ot(ram)
            tri=[]
            for p in active:
                if p['command']&0xfc==0x20 and p['address'] in (0x801f2fd4,0x801f2fe8):
                    at=p['address']&0x1fffff
                    tri.append({'address':hex(p['address']),'xy':[struct.unpack_from('<hh',ram,at+k) for k in (8,12,16)]})
            state,packets=object_at(ram,0x1f9d44,{'physical_chars':{}})
            states.append({'slot':n,'sha256':hashlib.sha256(path.read_bytes()).hexdigest(),
                           'triangle':tri,'text_row_y':sorted(set(p['y'] for p in packets)),
                           'cursor_global_xy':struct.unpack_from('<hh',ram,0x1f2fc4),
                           'choice_fields':struct.unpack_from('<4h',ram,0x1fe2ba),
                           'dialogue_origin':struct.unpack_from('<hh',ram,0x1f9d44+0x1e),
                           'source_pointer':state['source_pointer']})
    report={'build':str(BASE),'scanned_rows':len(originals),'speaker_break_candidates':candidates,
            'challenge_family':challenges,'low_address_choice':low,'states':states,
            'limits':'Colon-at-first-explicit-break candidate census; not all speaker semantics or non-CSV text. No game changes.'}
    (OUT/'audit.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    print('rows',len(originals),'speaker break candidates',len(candidates),'challenge family',len(challenges))
    for e in challenges:print(e['row'],e['offset'],repr(e['current']))
    for s in states:print(s)
if __name__=='__main__':main()
