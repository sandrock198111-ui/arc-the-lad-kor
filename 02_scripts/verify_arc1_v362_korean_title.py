"""Independent diff/texture/font audit of the exact V362 candidate archive.

Does not import the V362 writer. Cold boot/GPU appearance is a separate gate.
"""
from pathlib import Path
from zipfile import ZipFile
import hashlib, json, struct
from PIL import Image
from audit_arc1_title_state import SOURCE
from audit_arc1_9118_runtime import load
from analyze_arc1_v163_runtime import trace_active_text_ot
from verify_arc1_v359_slot_recovery import legacy_gate
from verify_arc1_v360_ui_restore import verify_panels
from verify_arc1_v359_cursor_lines import verify_cpu
from build_arc1_v320_hanme_static_recovery import read_plane
from build_arc1_v326_compact_ui_recovery import read_strip_plane

ROOT=Path(__file__).resolve().parents[1]
BASE=ROOT/'03_output/arc1_v361_skill_compact_TEST_ONLY.zip'
NEW=ROOT/'03_output/arc1_v362_korean_title_TEST_ONLY.zip'
AN=ROOT/'01_work/analysis/v362_korean_title'


def sha(p):
    return hashlib.sha256(p).hexdigest().upper()


def preserve_blade(x,y):
    if 149<=y<165:return 158<=x<165
    if 165<=y<174:return 159<=x<164
    if 174<=y<182:return 159<=x<163
    if 182<=y<187:return 160<=x<163
    if 187<=y<192:return 160<=x<162
    return False


def main():
    assert sha(BASE.read_bytes())=='B0AA760222B6F9AE3CB063FC49531DB5E9A735BD4EDDA56759F5CAD7CE2426C8'
    with ZipFile(BASE) as z:
        old_names=z.namelist();old={n:z.read(n) for n in old_names}
    with ZipFile(NEW) as z:
        names=z.namelist();new={n:z.read(n) for n in names}
    assert names==old_names and len(names)==len(set(names))==164
    assert [n for n in names if old[n]!=new[n]]==['COMM.IMG']
    assert all(len(old[n])==len(new[n]) for n in names)
    before,after=old['COMM.IMG'],new['COMM.IMG']
    changed=[];protected=0;zero_added=0
    for at in range(0,len(before),2):
        a,b=struct.unpack_from('<H',before,at)[0],struct.unpack_from('<H',after,at)[0]
        y,global_x=divmod(at//2,448);x=global_x-64
        allowed=90<x<233 and 149<y<191 and not preserve_blade(x,y)
        if a!=b:
            assert allowed,('out of bounds',at,x,y)
            changed.append(at)
        elif preserve_blade(x,y):
            protected+=1
        assert a&0x8000==b&0x8000
        zero_added+=a!=0 and b==0
    assert zero_added==0 and len(changed)==4719
    assert protected==214
    # Entire low font atlas (not just the Hangul subset) and compact strip.
    for i in range(1920):assert read_plane(before,i)==read_plane(after,i),i
    for i in range(16):assert read_strip_plane(before,i)==read_strip_plane(after,i),i
    assert sha(new['PSX.EXE'])=='5C46A42D9BD521E7830A1D3EC4B53A7E16B746252B08B53C38FF645211C38365'
    # Independent native texture decode, then compare the packer's preview.
    rgb=bytearray()
    for y in range(256):
        for x in range(344):
            w=int.from_bytes(after[2*(y*448+64+x):2*(y*448+65+x)],'little')
            rgb.extend((int(w&31)*255//31,int((w>>5)&31)*255//31,int((w>>10)&31)*255//31))
    assert Image.open(AN/'title_native.png').convert('RGB').tobytes()==bytes(rgb)
    ram,vram,_,_=load(SOURCE,new['PSX.EXE'])
    with ZipFile(ROOT/'00_original/arc.zip') as z:original=z.read('COMM.IMG')
    for y in range(256):
        assert original[(y*448+64)*2:(y*448+408)*2]==before[(y*448+64)*2:(y*448+408)*2]
        assert before[(y*448+64)*2:(y*448+408)*2]==vram[(y*1024+384)*2:(y*1024+728)*2]
    _,_,ot=trace_active_text_ot(ram)
    consumers=[p for p in ot if p.get('kind')=='FT4' and p.get('dma_words')==9]
    assert sorted((p['tpage'],p['width'],p['height']) for p in consumers)==[(26,96,16),(262,256,256),(266,88,256)]
    panel=verify_panels(new['PSX.EXE'],skill_height=42,mp_y=127)
    cursor=verify_cpu(new['PSX.EXE'],156)
    previous,current=legacy_gate(BASE),legacy_gate(NEW)
    assert previous['fail']==current['fail'] and previous['counts']==current['counts']
    report={'archive_sha256':sha(NEW.read_bytes()),'changed_members':['COMM.IMG'],
            'changed_pixels':len(changed),'changed_bytes':sum(a!=b for a,b in zip(before,after)),
            'protected_blade_pixels':protected,'font_planes_unchanged':1920,'compact_planes_unchanged':16,
            'outside_subtitle_unchanged':True,'all_stp_bits_unchanged':True,'added_transparent_texels':zero_added,
            'native_preview_independent_decode_match':True,'captured_original_title_upload_bytes':344*256*2,
            'title_texture_consumers':2,'start_sprite_unchanged':True,
            'panels':panel,'cursor':cursor,'legacy_failures_identical':True,
            'inherited_failures':current['fail'],'counts':current['counts'],
            'runtime_verified':False,'remaining':'Cold boot new CUE; title/start/fade and new/load-game transitions. Old savestate retains original VRAM.'}
    (AN/'verification.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    print('PASS: 4719 title pixels only; sword, 1920 font planes, 16 compact planes, other 163 archive members unchanged.')
    print('CPU regression:',panel['cases'],'panel cases; cursor:',cursor)
    print('Legacy failure set unchanged; cold-boot GPU appearance PENDING.')


if __name__=='__main__':main()
