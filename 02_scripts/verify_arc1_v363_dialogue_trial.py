"""Independent DAT bounds/control checks; not interactive cursor validation."""
from pathlib import Path
from zipfile import ZipFile
import hashlib,json
from v354_dialogue_codec import load_v354,tokens
from verify_arc1_v359_slot_recovery import legacy_gate
ROOT=Path(__file__).resolve().parents[1]
AN=ROOT/'01_work/analysis/v363_dialogue_trial'
BASE=ROOT/'03_output/arc1_v362_korean_title_TEST_ONLY.zip'
OUT=ROOT/'03_output/arc1_v363_dialogue_trial_TEST_ONLY.zip'

def main():
    with ZipFile(BASE) as z:old={n:z.read(n) for n in z.namelist()}
    with ZipFile(OUT) as z:new={n:z.read(n) for n in z.namelist()}
    assert old.keys()==new.keys()
    expected={'6/S6041.DAT':[(0x45400,128)],'6/S6053.DAT':[(0x45000,128),(0x45200,128),(0x45300,128)],
              '6/S6054.DAT':[(0x4395a,5),(0x43961,17),(0x43976,6),(0x43980,7)]}
    assert {n for n in old if old[n]!=new[n]}==set(expected)
    for n in old:
        assert len(old[n])==len(new[n])
        for i,(a,b) in enumerate(zip(old[n],new[n])):
            assert a==b or any(start<=i<start+size for start,size in expected.get(n,[])),(n,hex(i))
    _,_,_,decoder=load_v354();texts=[]
    for n,ranges in expected.items():
        for start,size in ranges:
            payload=new[n][start:start+size]
            if size==128:
                assert payload[127]==old[n][start+127]
                end=payload.index(0);assert end<=126;payload=payload[:end]
            ts=list(tokens(payload));assert all(t in decoder or t==b'\xe6\x01' for t in ts)
            texts.append({'file':n,'offset':hex(start),'tokens':len(ts),'text':''.join('| ' if t==b'\xe6\x01' else decoder[t] for t in ts)})
    assert len(list(tokens(new['6/S6041.DAT'][0x45400:0x4547f].split(b'\0')[0])))==64
    assert sum(t==b'\xe6\x01' for t in tokens(new['6/S6053.DAT'][0x45300:0x4537f].split(b'\0')[0]))==1
    for at in (0x4395f,0x43972,0x4397c):assert new['6/S6054.DAT'][at:at+2]==b'\xe6\x01'
    for at in (0x43974,0x4397e):assert new['6/S6054.DAT'][at:at+2]==b'\xe5\x03'
    assert new['6/S6054.DAT'][0x43987]==0
    before=legacy_gate(BASE);after=legacy_gate(OUT)
    assert before['fail']==after['fail'] and before['counts']==after['counts']
    result={'zip_sha256':hashlib.sha256(OUT.read_bytes()).hexdigest().upper(),'static_pass':True,
            'exe_comm_identical':True,'unchanged_members':161,'slot_metadata_preserved':True,
            'choice_markers_offsets_preserved':True,'texts':texts,'inherited_gate':after,
            'runtime_verified':False,'remaining':'Player cold boot/dialogue re-entry; both choice cursor positions and movement. Other seven capacity candidates and global wrap audit not fixed.'}
    (AN/'verification.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
    print('PASS: 3 DAT-only changes; controls, capacities, font mapping; legacy results unchanged')
if __name__=='__main__':main()
