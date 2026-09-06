"""Read-only title-state extraction, not image editing or a game patch."""
from pathlib import Path
from zipfile import ZipFile
from array import array
import hashlib, json, struct
from PIL import Image
from extract_duckstation_savestate import decompress
from audit_arc1_9118_runtime import load
from analyze_arc1_v163_runtime import trace_active_text_ot

ROOT=Path(__file__).resolve().parents[1]
SOURCE=Path('C:/Users/Administrator/.paseo/uploads/upload_ec216dc5-6ef2-400e-9220-911b8968b0ba/HASH-DC42934B1AA4449B_1.sav')
OUT=ROOT/'01_work/analysis/title_20260906'

def main():
    OUT.mkdir(parents=True,exist_ok=True)
    with ZipFile(ROOT/'03_output/arc1_v361_skill_compact_TEST_ONLY.zip') as z:
        exe=z.read('PSX.EXE');baseline_comm=z.read('COMM.IMG')
    with ZipFile(ROOT/'00_original/arc.zip') as z:comm=z.read('COMM.IMG')
    native_rgb=bytes(c for w in array('H',comm) for c in ((w&31)*255//31,((w>>5)&31)*255//31,((w>>10)&31)*255//31))
    Image.frombytes('RGB',(448,512),native_rgb).save(OUT/'comm_16bit_original.png')
    texture=b''.join(native_rgb[(y*448+64)*3:(y*448+408)*3] for y in range(256))
    Image.frombytes('RGB',(344,256),texture).save(OUT/'title_texture_original.png')
    patch=b''.join(texture[(y*344+90)*3:(y*344+234)*3] for y in range(144,192))
    Image.frombytes('RGB',(144,48),patch).save(OUT/'subtitle_region_original.png')
    ram,vram,rb,vb=load(SOURCE,exe)
    native=b''.join(comm[(y*448+64)*2:(y*448+408)*2] for y in range(256))
    baseline=b''.join(baseline_comm[(y*448+64)*2:(y*448+408)*2] for y in range(256))
    uploaded=b''.join(vram[(y*1024+384)*2:(y*1024+728)*2] for y in range(256))
    assert native==baseline==uploaded,'Full native title/VRAM upload mismatch'
    # Lossless no-edit round trip: all original COMM texels, including bit15.
    for word in array('H',comm):
        rgb5=(word&31,(word>>5)&31,(word>>10)&31)
        rgb8=tuple(c*255//31 for c in rgb5)
        restored=tuple((c*31+127)//255 for c in rgb8)
        assert restored==rgb5
        assert (restored[0]|restored[1]<<5|restored[2]<<10|(word&0x8000))==word
    ctx,parity,ot=trace_active_text_ot(ram)
    title_packets=[]
    for p in ot:
        if p.get('kind')!='FT4' or p.get('dma_words')!=9:
            continue
        q={k:p[k] for k in ('address','command','tpage','u','v','width','height')}
        q['xy']=[struct.unpack_from('<hh',ram,(p['address']&0x1fffff)+off) for off in (8,16,24,32)]
        title_packets.append(q)
    assert sorted((p['tpage'],p['width'],p['height']) for p in title_packets)==[(26,96,16),(262,256,256),(266,88,256)]
    thumb=decompress(SOURCE,'first');assert len(thumb)==256*192*4
    Image.frombytes('RGBA',(256,192),thumb,'raw','BGRA').convert('RGB').save(OUT/'title_thumbnail.png')
    rgb=bytes(c for w in array('H',vram) for c in ((w&31)*255//31,((w>>5)&31)*255//31,((w>>10)&31)*255//31))
    im=Image.frombytes('RGB',(1024,512),rgb);im.save(OUT/'title_vram.png')
    # Decode the first framebuffer directly; not a designed/retouched image.
    frame=b''.join(rgb[y*1024*3:(y*1024+320)*3] for y in range(240))
    Image.frombytes('RGB',(320,240),frame).save(OUT/'title_frame_320x240.png')
    report={'state_sha256':hashlib.sha256(SOURCE.read_bytes()).hexdigest(),'title':SOURCE.read_bytes()[8:128].split(b'\0')[0].decode('ascii'),
            'ram_offset':rb,'vram_offset':vb,'exe_anchors':6,'asset_location_confirmed':True,'game_modified':False,
            'native_asset':'COMM.IMG','comm_stride_bytes':896,'comm_title_rectangle':[64,0,344,256],
            'vram_title_rectangle':[384,0,344,256],'full_title_equal_bytes':len(native),
            'original_title_sha256':hashlib.sha256(native).hexdigest(),
            'original_comm_word_roundtrip':len(comm)//2,'original_high_bits_preserved':True,
            'active_context':hex(ctx),'parity':parity,'active_ot_rows':len(ot),'ft4_packets':title_packets,
            'evidence_scope':'Captured V361 original title upload/consumer; not execution of V362 artwork'}
    (OUT/'state.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(report)

if __name__=='__main__':main()
