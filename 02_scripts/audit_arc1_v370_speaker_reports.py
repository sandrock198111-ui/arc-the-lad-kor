"""Read-only current-build capture matching and speaker-format candidate census."""
import csv,json,hashlib,re
from collections import defaultdict
from pathlib import Path
from zipfile import ZipFile
from PIL import Image
from audit_arc1_9118_runtime import load
from extract_duckstation_savestate import decompress
from analyze_arc1_v320c_savestates import object_at
from audit_arc1_v363_speaker_cursor import expand
from v354_dialogue_codec import load_v354
ROOT=Path(__file__).resolve().parents[1];AN=ROOT/'01_work/analysis/v370_speaker_reports'
FOLDERS={2:'467db601-b436-4664-b2a0-65fbdb69857d',3:'4fc19ad8-13f2-475c-8741-bb4270605d89',4:'fedb4b16-0d60-4cc5-bb6f-79351bee4d60',5:'5ccc6553-eac1-46e8-b855-8a3fc9e43ec3'}
def main():
    AN.mkdir(exist_ok=True)
    with ZipFile(ROOT/'03_output/arc1_v370_event_restore_TEST_ONLY.zip') as z:files={n:z.read(n) for n in z.namelist()}
    with ZipFile(ROOT/'00_original/arc.zip') as z:original={n:z.read(n) for n in z.namelist() if n.endswith('.DAT')}
    dec=load_v354()[3]
    def decode(ts):return ''.join('|' if t==b'\xe6\x01' else dec.get(t,'<'+t.hex()+'>') for t in ts)
    corpus=list(csv.DictReader((ROOT/'05_docs/script_original_full.csv').open(encoding='utf-8-sig')))
    entries=[]
    for n,r in enumerate(corpus,1):
        fn=r['source file'];at=int(r['byte offset'],16);length=len(bytes.fromhex(r['raw bytes as hex']))
        d=files.get(fn,original.get(fn));ts=expand(d,at,length)
        text=decode(ts)
        entries.append(dict(row=n,file=fn,offset=at,end=at+length,current=text,japanese=r['decoded Japanese']))
    reports=[]
    for n,folder in FOLDERS.items():
        p=Path('C:/Users/Administrator/.paseo/uploads')/('upload_'+folder)/f'HASH-477B29575D051C04_{n}.sav'
        ram,vr,*_=load(p,files['PSX.EXE'])
        Image.frombytes('RGBA',(256,192),decompress(p,'first'),'raw','BGRA').convert('RGB').save(AN/f'thumb{n}.png')
        result=dict(slot=n,sha256=hashlib.sha256(p.read_bytes()).hexdigest(),title=p.read_bytes()[8:128].split(b'\0')[0].decode(),objects=[])
        for header in (0x1f9d44,0x1f9d88):
            s,ps=object_at(ram,header,{'physical_chars':{}})
            if not ps:continue
            ptr=int(s['source_pointer'],16)&0x1fffff;sig=ram[ptr-48:ptr+8]
            matches=[]
            for fn,d in files.items():
                if not fn.endswith('.DAT'):continue
                at=d.find(sig)
                if at>=0:
                    end=at+48
                    matches.extend(e for e in entries if e['file']==fn and e['offset']<=end<=e['end'])
            result['objects'].append(dict(state=s,row_ys=sorted(set(q['y'] for q in ps)),matches=matches))
        reports.append(result);print(json.dumps(result,ensure_ascii=False))
    colon_breaks=[e for e in entries if re.match(r'^[^|:]{1,24}: *\|',e['current'])]
    historical=json.loads((ROOT/'01_work/analysis/v364_cursor_speaker/build_report.json').read_text(encoding='utf-8'))
    old_deferred={e['row'] for e in historical['deferred']}
    assert {e['row'] for e in colon_breaks}==old_deferred
    speakers=defaultdict(set)
    for e in entries:
        jp=e['japanese'].split('\n')[0].strip();kr=e['current'].split(':')[0].strip()
        if '\n' in e['japanese'] and len(jp)<=12 and ':' in e['current'] and len(kr)<20 and '|' not in kr:
            speakers[jp].add(kr)
    missing=[e for e in entries if '\n' in e['japanese'] and
        e['japanese'].split('\n')[0].strip() in speakers and ':' not in e['current']]
    # These are candidates, not inferred speakers or automatic rewrite authority.
    result=dict(corpus_rows=len(entries),states=reports,colon_break_candidates=colon_breaks,
        all_colon_breaks_are_v364_deferred=True,missing_colon_candidates=missing,
        limits='CSV corpus only plus matched captures. Missing speaker names and speech-level semantics require original/context review; no edits.')
    (AN/'report.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
    (AN/'corpus.json').write_text(json.dumps(entries,ensure_ascii=False,indent=2),encoding='utf-8')
    lines=['# V370 speaker formatting candidates','',
        'Read-only scan of 2878 extracted CSV records, not 2878 proven dialogue entries. Known false extractions remain in this historical input. No whole-game coverage claim.',
        '',f'Existing colon + break: {len(colon_breaks)}; identical to all V364 deferred rows.',
        f'Original-speaker association but no current colon: {len(missing)} candidates; context confirmation required.',
        '', '## Known deferred colon breaks','']
    for group in (colon_breaks,missing):
        for e in group:
            lines.extend([f"### #{e['row']} {e['file']} @ {e['offset']:X}",'',
                e['current'].replace('|',' / ').rstrip(),''])
        if group is colon_breaks:lines.extend(['## Missing-colon candidates (not auto-approved)',''])
    (AN/'candidates.md').write_text('\n'.join(lines).rstrip()+'\n',encoding='utf-8')
    print('CORPUS',len(entries),'COLON_BREAK',len(colon_breaks),'MISSING_COLON_CANDIDATES',len(missing))
if __name__=='__main__':main()
