"""Read-only cost of restoring cursor art to its original COMM rectangle."""
import json
from zipfile import ZipFile
from audit_arc1_9118_runtime import ROOT,OUT,BUILD
import v354_dialogue_codec as codec
import build_arc1_v320_hanme_static_recovery as font

def run():
    z=ZipFile(BUILD);exe=z.read('PSX.EXE');current=z.read('COMM.IMG')
    original=ZipFile(ROOT/'00_original/arc.zip').read('COMM.IMG')
    hypothetical=bytearray(current) # In memory only. Never saved as a game asset.
    for y in range(128,161):hypothetical[y*896:y*896+50]=original[y*896:y*896+50]
    planes=[i for i in range(960) if font.read_plane(current,i)!=font.read_plane(hypothetical,i)]
    _,_,encoder,decoder=codec.load_v354()
    chars=sorted({ch for code,ch in decoder.items() if codec._resolve_index(exe,code) in planes and ch!=' '})
    selected=sorted(ch for ch,code in encoder.items() if codec._resolve_index(exe,code) in planes)
    result={'scope':'hypothetical original cursor rectangle restoration only; no patch',
            'changed_planes':planes,'changed_plane_count':len(planes),'decoder_characters':chars,
            'decoder_character_count':len(chars),'selected_encoder_characters':selected,
            'selected_encoder_count':len(selected),
            'packet_budget':{'existing_ft4_bytes':40,'flat_closed_5_vertex_polyline_with_dma_tag':32,
                             'note':'format budget only; no implementation or visual equivalence proof'}}
    (OUT/'cursor_options_cost.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
    print('Changed planes:',len(planes),'decoder chars:',len(chars),'selected encoder entries:',len(selected))

if __name__=='__main__':run()
