"""Pin and identify the ten 5DC715 user captures, read-only."""
import json,struct
from pathlib import Path
import build_arc1_v381_scene_pauses as base
from audit_arc1_9118_runtime import load
from analyze_arc1_v320c_savestates import object_at,find_text_objects
b=base.b
AN=b.ROOT/'01_work/analysis/v382_reports'

def main():
    AN.mkdir(parents=True,exist_ok=True)
    files=b.members(base.OUT); original=b.members(b.ORIGINAL);exe=files['PSX.EXE']
    table,_=b.encoder(exe); chars={b.codec._resolve_index(exe,t):c for c,t in table.items()}
    from build_arc1_v336_ui_text_native_damage_repair import runtime_damage_target
    chars.update({runtime_damage_target(i):c for i,c in list(chars.items()) if i is not None and 168<=i<=170});chars[746]=' '
    rows=b.audit.rows(b.ROOT/'05_docs/script_original_full.csv');decode=b.audit.make_decoder(exe)
    paths=sorted(Path('C:/Users/Administrator/.paseo/uploads').glob('upload_*/HASH-5DC715247256FEDC_*.sav'),key=lambda p:int(p.stem.rsplit('_',1)[1]))
    assert len(paths)==10
    results=[]
    for path in paths:
        ram,vram,*_=load(path,exe);obs=[]
        for header in [0x1f9d44,0x1f9d88,0x1f0e18]:
            state,ps=object_at(ram,header,{'physical_chars':{}});end=int(state['source_pointer'],16)-0x800cf000;hits=[]
            for n,r in enumerate(rows,1):
                at=int(r['byte offset'],0);length=len(bytes.fromhex(r['raw bytes as hex']));fn=r['source file']
                if at<=end<=at+length and ram[0xcf000+at:0xcf000+at+length]==files.get(fn,original[fn])[at:at+length]:
                    hits.append(dict(row=n,file=fn,offset=at,length=length,jp=r['decoded Japanese'],ko=decode(b''.join(b.previous.read_tokens(files.get(fn,original[fn]),at,length)))[0]))
            lines={}
            for p in ps:lines[p['y']]=lines.get(p['y'],'')+chars.get(p['physical_index'],'<?>')
            obs.append(dict(header=header,state=state,hits=hits,lines=lines,packets=ps))
        slot=int(path.stem.rsplit('_',1)[1]);results.append(dict(slot=slot,path=str(path),sha256=b.digest(path.read_bytes()),objects=obs))
        print('SLOT',slot)
        for ob in obs:print(hex(ob['header']),ob['state']['source_pointer'],ob['lines'],ob['hits'])
    (AN/'states.json').write_text(json.dumps(results,ensure_ascii=False,indent=2),encoding='utf-8')
if __name__=='__main__':main()
