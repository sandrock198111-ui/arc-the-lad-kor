"""Approved local spacing/Ye repair and read-only original UI control audit."""
from pathlib import Path
from zipfile import ZipFile, ZIP_DEFLATED
from collections import Counter
import csv, hashlib, json, struct, sys
import build_arc1_v320_hanme_static_recovery as font
from v354_dialogue_codec import load_v354, tokens, _resolve_index

sys.stdout.reconfigure(encoding='utf-8')
ROOT=Path(__file__).resolve().parents[1]
BASE=ROOT/'03_output/arc1_v359_thin_prep_icons_TEST_ONLY.zip'
OUT=ROOT/'03_output/arc1_v359_thin_spacing_ye_TEST_ONLY.zip'
REPORT=ROOT/'01_work/analysis/arc1_v359_spacing_ye'
def sha(b): return hashlib.sha256(b).hexdigest().upper()
def read(z):
    with ZipFile(z) as a: return a.infolist(),{i.filename:a.read(i) for i in a.infolist()}
def string(exe,ptr):
    at=struct.unpack_from('<I',exe,ptr)[0]-0x8011A800
    assert 0<=at<len(exe)
    end=exe.index(0,at)
    assert end-at<4096
    return bytes(exe[at:end])

def main():
    assert sha(BASE.read_bytes())=='281D3CA41C0D32E7FD6E5E04FDBF0EF0B6F349189D6C342B57744CCA04EDF408'
    infos,old=read(BASE); new=dict(old)
    exe=bytearray(old['PSX.EXE'])
    before=bytes.fromhex('E7 02 DD 10 DD 0A E7 05 DE 54 A1 DD 89 24 00 00 00')
    after=bytes.fromhex('E7 02 DD 10 DD 0A A1 A1 E7 05 DE 54 A1 DD 89 24 00')
    assert exe[0x80950:0x80961]==before
    assert struct.unpack_from('<I',exe,0x82350)[0]==0x8019B161
    exe[0x80950:0x80961]=after
    new['PSX.EXE']=bytes(exe)
    comm=bytearray(old['COMM.IMG']); rows=list(font.read_plane(comm,150))
    expected=('................','....####.##.##..','...#....#.#..#..','...#...####..#..','...#....#.#..#..','...#...####..#..','....####..#..#..','..........#..#..','..........#..#..','..........#..#..','..........#..#..','..........#..#..','..........#..#..','.............#..','................','................')
    assert rows==[sum(0x8000>>x for x,c in enumerate(r) if c=='#') for r in expected]
    # Only the finished Ye plane: shorten ㅇ right edge and ㅖ arms, leaving
    # column8 blank between components. No shared component or advance edit.
    for y in range(2,6): rows[y]=(rows[y]&~(0x8000>>8))|(0x8000>>7)
    for y in (3,5): rows[y]&=~(0x8000>>8)
    font.put_plane(comm,150,tuple(rows)); new['COMM.IMG']=bytes(comm)
    assert [i for i in range(1920) if font.read_plane(old['COMM.IMG'],i)!=font.read_plane(comm,i)]==[150]
    assert all(i in range(0x80950,0x80961) for i,(a,b) in enumerate(zip(old['PSX.EXE'],exe)) if a!=b)
    assert all(len(new[n])==len(old[n]) for n in old)
    if OUT.exists(): assert read(OUT)[1]==new,'refuse differing output'
    else:
        with ZipFile(OUT,'w',compression=ZIP_DEFLATED,compresslevel=9) as z:
            for i in infos:z.writestr(i,new[i.filename],compress_type=ZIP_DEFLATED,compresslevel=9)
    REPORT.mkdir(parents=True,exist_ok=True)
    _,_,enc,dec=load_v354()
    # Decode direct aliases of current UI glyphs through physical identity.
    identities={_resolve_index(exe,c):ch for ch,c in enc.items()}
    def decode(raw):
        return ''.join(dec.get(t,identities.get(_resolve_index(exe,t),'<'+t.hex(' ').upper()+'>')) for t in tokens(raw))
    with ZipFile(ROOT/'00_original/arc.zip') as z: original=z.read('PSX.EXE')
    records={}
    for name in ('ui_full_v42.csv','ui_system_v39.csv','ui_nonstory_system_v39.csv','ui_world_name_v39.csv'):
        with (ROOT/'05_docs'/name).open(encoding='utf-8-sig',newline='') as f:
            for row in csv.DictReader(f):records[int(row['pointer_offset'],16)]=row
    audit=[]
    for p,row in sorted(records.items()):
        if p in (0x823AC,0x823B0,0x823B4,0x823B8,0x823BC):continue
        a,b=string(original,p),string(exe,p)
        ac=Counter(t for t in tokens(a) if len(t)==2 and 0xE2<=t[0]<=0xE8)
        bc=Counter(t for t in tokens(b) if len(t)==2 and 0xE2<=t[0]<=0xE8)
        missing=list((ac-bc).elements())
        audit.append(dict(pointer=hex(p),japanese=row.get('japanese',''),current=decode(b),original_hex=a.hex(' '),current_hex=b.hex(' '),missing_controls=';'.join(t.hex(' ') for t in missing),empty_after=bool(a) and not bool(b)))
    with (REPORT/'ui_control_audit.csv').open('w',encoding='utf-8-sig',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(audit[0]));w.writeheader();w.writerows(audit)
    report=dict(output_sha256=sha(OUT.read_bytes()),changed_bytes={n:sum(a!=b for a,b in zip(old[n],new[n])) for n in old if old[n]!=new[n]},changed_planes=[150],ui_pointer_census=len(records),audited=len(audit),binary_excluded=5,empty_after=sum(r['empty_after'] for r in audit),control_difference_candidates=sum(bool(r['missing_controls']) for r in audit),status='STATIC PASS / RUNTIME PENDING; UI audit not whole-game completeness')
    (REPORT/'report.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(report,indent=2))
    for r in audit:
        if r['missing_controls']:print(r['pointer'],r['missing_controls'],r['current'])
if __name__=='__main__':main()
