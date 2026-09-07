"""Separate V368 Sans comparison. Frozen baseline, same slots/metrics, no release promotion."""
import argparse
import json
from io import BytesIO
from pathlib import Path
from zipfile import ZipFile, ZIP_DEFLATED
import build_arc1_v359_thin_font_preview as f
import build_arc1_v368_linebreaks as baseline

ROOT=f.ROOT
BASE=baseline.OUT
BASE_PIN='00A55D88117F614FD2CC30BED097AD27DD93D84A59F87C698043A93DF5431416'
COMM_PIN='BD831E19FB86B7EDFF6DEF07C2D241B09251243AA4B4DDC2A74A83A5D8092B82'
SANS_PIN='A630598E7ACAB70DC6C6AC4D46DE59CEF25EF61A2FEEC439E8B25C7DDBA05726'
PIECES_PIN='2D5F23E2A66ACF6DE92CC475ED1D1A524554EC26B695E4CD1B63913468CCCBFF'
OUT=ROOT/'03_output/arc1_v368_sans_font_TEST_ONLY.zip'
AN=ROOT/'01_work/analysis/v368_sans_font'
ORIGINAL=baseline.ORIGINAL
ORIGINAL_PIN=baseline.ORIGINAL_PIN
digest=f.sha

def prepare(font_archive):
    for path,pin in ((BASE,BASE_PIN),(f.ATLAS,f.ATLAS_SHA256),
                     (f.ASSIGNMENTS,f.ASSIGNMENTS_SHA256),(font_archive,f.FONT_ARCHIVE_SHA256)):
        assert digest(path)==pin, str(path)
    assert baseline.prepare()[0]==BASE.read_bytes(), 'V368 reproduction drift'
    with ZipFile(font_archive) as z:
        sans=z.read('Sans_8x4x4.ttf');thin=z.read(f.THIN_MEMBER)
        hanme=z.read(f.HANME_MEMBER)
    assert digest(sans)==SANS_PIN and digest(thin)==f.THIN_TTF_SHA256
    assert digest(hanme)==f.HANME_TTF_SHA256
    pieces=f.render_pieces(sans);oldpieces=f.render_pieces(thin)
    assert digest(f.pieces_blob(pieces))==PIECES_PIN
    assert digest(f.pieces_blob(oldpieces))==f.THIN_PIECES_SHA256
    assert digest(f.pieces_blob(f.render_pieces(hanme)))==f.HANME_PIECES_SHA256
    _,_,targets=f.load_targets()
    infos,names,old=f.read_archive(BASE)
    assert digest(old['COMM.IMG'])==COMM_PIN
    planned={};owners={}
    for index,(_,ch) in sorted(targets.items()):
        expected=list(f.thin_rows(oldpieces,ch))
        if index==150:
            assert ch=='예'
            for y in range(2,6):expected[y]=(expected[y]&~(0x8000>>8))|(0x8000>>7)
            for y in (3,5):expected[y]&=~(0x8000>>8)
        assert f.v320.read_plane(old['COMM.IMG'],index)==tuple(expected), (index,ch)
        rows=f.v320c.compose(pieces,ch,official=True)
        assert any(rows), ('empty',ch)
        assert owners.setdefault(rows,ch)==ch, ('collision',ch,owners[rows])
        planned[index]=rows
    # Plan all plane writes against immutable baseline before modifying a copy.
    comm=bytearray(old['COMM.IMG'])
    for index,rows in planned.items():f.v320.put_plane(comm,index,rows)
    for index in range(1920):
        expected=planned.get(index,f.v320.read_plane(old['COMM.IMG'],index))
        assert f.v320.read_plane(comm,index)==expected,index
    # Exact nibble-bit ownership mask also protects unused margins and title.
    mask=bytearray(len(comm))
    for index in planned:
        cell,plane=divmod(index,4);cx,cy=cell%15*16,cell//15*16
        for y in range(cy,cy+16):
            for x in range(cx,cx+16):mask[y*896+x//2]|=1<<(plane+4*(x%2))
    writes=[]
    for offset,(a,b) in enumerate(zip(old['COMM.IMG'],comm,strict=True)):
        assert ((a^b)&~mask[offset])==0,offset
        if a!=b:writes.append(dict(file='COMM.IMG',offset=offset,before=f'{a:02x}',after=f'{b:02x}'))
    new=dict(old);new['COMM.IMG']=bytes(comm)
    assert [n for n in names if new[n]!=old[n]]==['COMM.IMG']
    assert all(len(old[n])==len(new[n]) for n in names)
    stream=BytesIO()
    with ZipFile(stream,'w',compression=ZIP_DEFLATED,compresslevel=9) as z:
        for info in infos:z.writestr(f.clone_info(info),new[info.filename],compress_type=ZIP_DEFLATED,compresslevel=9)
    raw=stream.getvalue()
    return raw,dict(zip_sha256=digest(raw),baseline_sha256=BASE_PIN,font_sha256=SANS_PIN,
        pieces_sha256=PIECES_PIN,changed_members=['COMM.IMG'],writes=writes,
        targets=len(planned),unique_hangul=len(owners),mapped_collisions=0,
        comm_sha256=digest(comm),static_pass=True,runtime_verified=False,
        policy='V368 frozen; font-only local TEST_ONLY; no new slots, code, text, metrics or title changes')

def main():
    p=argparse.ArgumentParser();p.add_argument('font_archive',type=Path);args=p.parse_args()
    raw,report=prepare(args.font_archive)
    assert prepare(args.font_archive)[0]==raw,'Non-deterministic build'
    if OUT.exists():assert OUT.read_bytes()==raw,'Refusing different existing output'
    else:OUT.write_bytes(raw)
    AN.mkdir(parents=True,exist_ok=True)
    (AN/'build_report.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({k:v for k,v in report.items() if k!='writes'},ensure_ascii=False,indent=2))
    print('Changed COMM bytes',len(report['writes']))

if __name__=='__main__':main()
