"""Read-only speech-register review inputs and capture/source matching."""
import csv,json,hashlib
from pathlib import Path
from zipfile import ZipFile
from audit_arc1_9118_runtime import load
from analyze_arc1_v320c_savestates import object_at
from audit_arc1_v363_speaker_cursor import expand
from v354_dialogue_codec import load_v354,encode
ROOT=Path(__file__).resolve().parents[1];AN=ROOT/'01_work/analysis/v371_register'
SAV=Path('C:/Users/Administrator/.paseo/uploads/upload_038b258b-3f0a-4668-a502-7c25c1144d43/HASH-477B29575D051C04_2.sav')

def main():
    AN.mkdir(exist_ok=True)
    baseline=ROOT/'03_output/arc1_v371_speaker_fixes_TEST_ONLY.zip'
    assert hashlib.sha256(baseline.read_bytes()).hexdigest().upper()=='2308DAAA0F4E8AFD4B16E03DABD4402E596E1BB6CA0D404F6A3352DF4BCE6021'
    with ZipFile(baseline) as z:files={n:z.read(n) for n in z.namelist()}
    with ZipFile(ROOT/'00_original/arc.zip') as z:original={n:z.read(n) for n in z.namelist() if n.endswith('.DAT')}
    dec=load_v354()[3]
    decode=lambda ts:''.join('|' if t==b'\xe6\x01' else dec.get(t,'<'+t.hex()+'>') for t in ts)
    records=list(csv.DictReader((ROOT/'05_docs/script_original_full.csv').open(encoding='utf-8-sig')))
    corpus=[]
    for i,r in enumerate(records,1):
        n=r['source file'];at=int(r['byte offset'],16);raw=bytes.fromhex(r['raw bytes as hex'])
        d=files.get(n,original.get(n));text=decode(expand(d,at,len(raw)))
        corpus.append(dict(row=i,file=n,offset=at,end=at+len(raw),japanese=r['decoded Japanese'],current=text,original_raw=raw.hex()))
    groups={'early':[e for e in corpus if e['file'].split('/')[0] in ('1','21','22','31','32','4')],
            'arena':[e for e in corpus if e['file'].startswith('7/')],
            'other':[e for e in corpus if e['file'].split('/')[0] not in ('1','21','22','31','32','4','7')]}
    assert sum(map(len,groups.values()))==len(corpus)
    for name,entries in groups.items():
        (AN/(name+'.json')).write_text(json.dumps(entries,ensure_ascii=False,indent=2),encoding='utf-8')
    ram,*_=load(SAV,files['PSX.EXE']);matches=[]
    for h in (0x1f9d44,0x1f9d88):
        s,ps=object_at(ram,h,{'physical_chars':{}})
        if not ps:continue
        ptr=int(s['source_pointer'],16)&0x1fffff;sig=ram[ptr-48:ptr+8]
        for n,d in files.items():
            if not n.endswith('.DAT'):continue
            at=d.find(sig)
            if at>=0:
                end=at+48
                entries=[e for e in corpus if e['file']==n and e['offset']<=end<=e['end']+1
                         and (end<=e['end'] or d[e['end']]==0)]
                matches.append(dict(file=n,dat_pointer=end,state=s,entries=entries))
    report=dict(title=SAV.read_bytes()[8:128].split(b'\0')[0].decode(),sha256=hashlib.sha256(SAV.read_bytes()).hexdigest(),matches=matches,
                groups={k:len(v) for k,v in groups.items()},exact_matna=[e for e in corpus if '맞나?' in e['current']],
                limits='Historical CSV records include false extractions and omit some low-address bodies. Linguistic review separate from enumeration.')
    # Current '?' uses DD03 alias, not the encoder's preferred D1.
    needle=bytes.fromhex('ddb11edd03');hits=[]
    for n,d in files.items():
        if not n.endswith('.DAT'):continue
        start=0
        while (at:=d.find(needle,start))>=0:
            hits.append(dict(file=n,offset=at));start=at+len(needle)
    assert {(e['file'],e['offset']) for e in report['exact_matna']}=={(e['file'],e['offset']) for e in hits}
    assert all(files[e['file']][e['offset']+8:e['offset']+10]==b'\xe6\x01' for e in hits)
    report['raw_matna_census']=hits
    value,missing=encode('맞습니까?',load_v354()[2],True)
    report['minimal_polite_candidate']=dict(text='맞습니까?',encoded_bytes=len(value),missing=missing,
        current_prompt_bytes=8,statically_fits_all_14=len(value)<=8,
        limit='Does not restore omitted names; no insertion or renderer test performed.')
    (AN/'capture.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    # Reuse the independently catalogued 107 low-address quiz boundaries,
    # but always decode current ZIP bytes, never old report translations.
    catalog=json.loads((ROOT/'01_work/analysis/v368_linebreaks/audit.json').read_text(encoding='utf-8'))
    from extract_story_corpus import token_end
    low=[];n='6/S6054.DAT'
    for e in catalog['entries']:
        at=int(e['offset'],16);end=int(e['end'],16)
        assert token_end(original[n],at)==end
        assert original[n][at-8:at]==bytes.fromhex('290000007f001900')
        low.append(dict(file=n,offset=at,end=end,csv_present=e['csv_present'],
                        japanese=e['japanese_map_preview'],current=decode(expand(files[n],at,end-at))))
    assert len(low)==107 and sum(not e['csv_present'] for e in low)==63
    (AN/'quiz107.json').write_text(json.dumps(low,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps(report,ensure_ascii=False,indent=2))

if __name__=='__main__':main()
