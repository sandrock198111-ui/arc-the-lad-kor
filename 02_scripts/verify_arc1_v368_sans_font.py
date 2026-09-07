"""Independent archive, source raster, packed nibble and protected-byte checks."""
import argparse,json,hashlib
from pathlib import Path
from zipfile import ZipFile
import verify_arc1_v359_thin_font_preview as prior

ROOT=Path(__file__).resolve().parents[1]
AN=ROOT/'01_work/analysis/v368_sans_font'
def sha(raw):return hashlib.sha256(raw).hexdigest().upper()
def plane(raw,index):
    cell,bit=divmod(index,4);left=(cell%15)*16;top=(cell//15)*16
    return tuple(sum(0x8000>>x for x in range(16)
        if raw[(top+y)*896+(left+x)//2]&(1<<(bit+4*((left+x)%2)))) for y in range(16))

def main():
    p=argparse.ArgumentParser();p.add_argument('font_archive',type=Path);args=p.parse_args()
    base=ROOT/'03_output/arc1_v368_linebreaks_TEST_ONLY.zip'
    target=ROOT/'03_output/arc1_v368_sans_font_TEST_ONLY.zip'
    assert sha(base.read_bytes())=='00A55D88117F614FD2CC30BED097AD27DD93D84A59F87C698043A93DF5431416'
    assert sha(args.font_archive.read_bytes())==prior.FONT_SHA
    with ZipFile(base) as a,ZipFile(target) as b:
        assert a.namelist()==b.namelist() and len(a.namelist())==164
        old={n:a.read(n) for n in a.namelist()};new={n:b.read(n) for n in b.namelist()}
    assert [n for n in old if old[n]!=new[n]]==['COMM.IMG']
    assert all(len(old[n])==len(new[n]) for n in old)
    with ZipFile(args.font_archive) as z:ttf=z.read('Sans_8x4x4.ttf')
    assert sha(ttf)=='A630598E7ACAB70DC6C6AC4D46DE59CEF25EF61A2FEEC439E8B25C7DDBA05726'
    pieces=prior.raster(ttf);targets=prior.expected_targets();owners={}
    before=old['COMM.IMG'];after=new['COMM.IMG']
    for index in range(1920):
        got=plane(after,index)
        if index in targets:
            ch=targets[index];expected=prior.official.compose(pieces,ch,official=True)
            assert got==expected and any(got),(index,ch)
            assert owners.setdefault(got,ch)==ch,('duplicate',ch)
        else:assert got==plane(before,index),index
    # Check every changed bit, not only decoded cells: native title/margins stay exact.
    for off,(a,b) in enumerate(zip(before,after,strict=True)):
        y,byte_x=divmod(off,896)
        for bit in range(8):
            if not (a^b)&(1<<bit):continue
            x=byte_x*2+bit//4
            assert x<240 and y<512,(off,bit)
            index=((y//16)*15+x//16)*4+bit%4
            assert index in targets,(off,index)
    report=json.loads((AN/'build_report.json').read_text(encoding='utf-8'))
    assert report['zip_sha256']==sha(target.read_bytes())
    expected={(i,a,b) for i,(a,b) in enumerate(zip(before,after)) if a!=b}
    actual={(w['offset'],int(w['before'],16),int(w['after'],16)) for w in report['writes']}
    assert expected==actual and len(actual)==len(report['writes'])
    result=dict(zip_sha256=sha(target.read_bytes()),static_pass=True,planes_checked=1920,
        replaced_planes=len(targets),unique_hangul=len(owners),mapped_collisions=0,
        nonfont_members_preserved=163,all_other_comm_bits_preserved=True,runtime_verified=False)
    (AN/'verification.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(result,indent=2))

if __name__=='__main__':main()
