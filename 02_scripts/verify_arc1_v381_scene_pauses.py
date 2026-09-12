"""Original/current/fixed E4 timing for every additional reported-scene row."""
import io,json,struct
from pathlib import Path
from zipfile import ZipFile
import build_arc1_v381_scene_pauses as b
from audit_arc1_9118_runtime import load
from verify_arc1_v379_spirit_reports import render,reflow
from verify_arc1_v380_followup import timed

def verify(blob):
    old=b.b.members(b.BASE);original=b.b.members(b.ORIGINAL)
    with ZipFile(io.BytesIO(blob)) as z:new={n:z.read(n) for n in z.namelist()}
    states=json.loads((b.previous.AN/'states.json').read_text(encoding='utf-8'));s=next(s for s in states if s['slot']==2)
    assert b.digest(Path(s['path']).read_bytes())==s['sha256'];ram,*_=load(Path(s['path']),old['PSX.EXE'])
    rows=b.b.audit.rows(b.ROOT/'05_docs/script_original_full.csv');fn='22/S205C.DAT';header=0x1f9d88;origin=struct.unpack_from('<4h',ram,header+0x1e)
    table,_=b.b.encoder(new['PSX.EXE']);chars={b.b.codec._resolve_index(new['PSX.EXE'],t):c for c,t in table.items()};results=[]
    from build_arc1_v336_ui_text_native_damage_repair import runtime_damage_target
    chars.update({runtime_damage_target(i):c for i,c in list(chars.items()) if i is not None and 168<=i<=170})
    for n,chunks in b.PAUSES.items():
        r=rows[n-1];at=int(r['byte offset'],0);length=len(bytes.fromhex(r['raw bytes as hex']))
        variants=[];outputs=[]
        for data in [original[fn],old[fn],new[fn]]:
            copy=bytearray(ram)
            for a,z in [(0x4200,0x5000),(0x45000,0x47780),(at,at+length+2)]:copy[0xcf000+a:0xcf000+z]=data[a:z]
            variants.append(timed(copy,at,origin,header))
            if data is new[fn]:
                after,ps=render(copy,0x800cf000+at,origin,header);lines={}
                for p in ps:
                    assert p['physical_index'] in chars
                    lines[p['y']]=lines.get(p['y'],'')+chars[p['physical_index']]
                assert len(lines)<=4 and reflow(''.join(lines.values()))==reflow(''.join(chunks)),(n,lines)
                outputs=lines
        o,a,z=variants
        assert a['events']==[] and [(e['parameter'],e['ticks']) for e in o['events']]==[(e['parameter'],e['ticks']) for e in z['events']]
        assert o['end']==a['end']==z['end']
        results.append(dict(row=n,original=o,before=a,after=z,lines=outputs))
    census=[]
    for n,r in enumerate(rows,1):
        if r['source file']!=fn:continue
        at=int(r['byte offset'],0);raw=bytes.fromhex(r['raw bytes as hex'])
        expected=[t.hex() for t in b.b.codec.tokens(raw) if t[0]==0xe4]
        actual=[t.hex() for t in b.b.previous.read_tokens(new[fn],at,len(raw)) if t[0]==0xe4]
        assert expected==actual,(n,expected,actual)
        if expected:census.append(dict(row=n,pauses=expected))
    return dict(cases=results,scene_census=census,runtime_verified=False,scope='Ten synthetic scene dialogue loads into captured native renderer; all scene E4 sequences checked; actual frame-step counter comparisons, GPU/input pending.')

if __name__=='__main__':
    blob,_=b.prepare();print(json.dumps(verify(blob),ensure_ascii=False,indent=2))
