"""Read-only capture matching for the two reports after V372 rejection."""
import csv,json,hashlib
from pathlib import Path
from zipfile import ZipFile
from audit_arc1_9118_runtime import load
from analyze_arc1_v320c_savestates import object_at
from audit_arc1_v363_speaker_cursor import expand
from v354_dialogue_codec import load_v354
ROOT=Path(__file__).resolve().parents[1]
AN=ROOT/'01_work/analysis/v371_two_reports'
PATHS=[Path('C:/Users/Administrator/.paseo/uploads/upload_d93df414-db5a-47c3-964e-d54a8c15d441/HASH-477B29575D051C04_1.sav'),Path('C:/Users/Administrator/.paseo/uploads/upload_ef8308d1-2e25-4db8-85b8-f6d2b055140f/HASH-477B29575D051C04_2.sav')]
def main():
    base=ROOT/'03_output/arc1_v371_speaker_fixes_TEST_ONLY.zip'
    assert hashlib.sha256(base.read_bytes()).hexdigest().upper()=='2308DAAA0F4E8AFD4B16E03DABD4402E596E1BB6CA0D404F6A3352DF4BCE6021'
    with ZipFile(base) as z:files={n:z.read(n) for n in z.namelist()}
    corpus=list(csv.DictReader((ROOT/'05_docs/script_original_full.csv').open(encoding='utf-8-sig')))
    dec=load_v354()[3];reports=[]
    for p in PATHS:
        ram,*_=load(p,files['PSX.EXE'])
        result=dict(name=p.name,sha256=hashlib.sha256(p.read_bytes()).hexdigest(),title=p.read_bytes()[8:128].split(b'\0')[0].decode(),objects=[])
        for h in (0x1f9d44,0x1f9d88):
            s,ps=object_at(ram,h,{'physical_chars':{}})
            if not ps:continue
            ptr=int(s['source_pointer'],16)&0x1fffff;sig=ram[ptr-48:ptr+8];matches=[]
            for n,d in files.items():
                at=d.find(sig) if n.endswith('.DAT') else -1
                if at<0:continue
                end=at+48
                for i,r in enumerate(corpus,1):
                    a=int(r['byte offset'],16);size=len(bytes.fromhex(r['raw bytes as hex']))
                    if r['source file']==n and a<=end<=a+size+1 and (end<=a+size or d[a+size]==0):
                        ts=expand(d,a,size)
                        matches.append(dict(row=i,file=n,offset=a,end=a+size,japanese=r['decoded Japanese'],current=''.join('|' if t==b'\xe6\x01' else dec.get(t,'<'+t.hex()+'>') for t in ts),raw=d[a:a+size].hex()))
            result['objects'].append(dict(state=s,ys=sorted(set(q['y'] for q in ps)),matches=matches))
        reports.append(result)
    AN.mkdir(parents=True,exist_ok=True)
    (AN/'captures.json').write_text(json.dumps(reports,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps(reports,ensure_ascii=False,indent=2))
if __name__=='__main__':main()
