"""Diagnose reported causes from immutable archives and user states, no fixes."""
from pathlib import Path
from zipfile import ZipFile
import hashlib, json, struct
import capstone
from audit_arc1_9118_runtime import load, ROOT, OUT, BUILD
import analyze_arc1_v163_runtime as ot
import build_arc1_v341_runtime_ui_recovery as gate

def run():
    e=ZipFile(BUILD).read('PSX.EXE')
    pristine=ZipFile(ROOT/'00_original/arc.zip')
    original=pristine.read('PSX.EXE');comm=pristine.read('COMM.IMG')
    source=b''.join(comm[y*896:y*896+50] for y in range(128,161))
    assert hashlib.sha256(source).hexdigest()=='b0005b318220fc61c11c3290837a7df245646254ffa5cebe7ea9a11932c7f421'
    result={'source_sha256':hashlib.sha256(source).hexdigest(),'source_bytes':len(source),'states':[]}
    for n in [1,3,4,6,8]:
        p=next(Path('C:/Users/Administrator/.paseo/uploads').glob(f'upload_*/HASH-9118D5AA9448C036_{n}.sav'))
        ram,vram,rb,vb=load(p,e)
        dest=b''.join(vram[(y*1024+960)*2:(y*1024+985)*2] for y in range(447,480))
        context,parity,rows=ot.trace_active_text_ot(ram)
        # Independently verify the traced chain terminates at the sentinel, not a cycle/truncation.
        cur=struct.unpack_from('<I',ram,(context&0x1fffff)+0x70)[0]&0xffffff
        seen=set()
        while cur not in (0,0xffffff):
            assert cur not in seen and cur<len(ram)-8
            seen.add(cur);cur=struct.unpack_from('<I',ram,cur)[0]&0xffffff
        assert len(seen)==len(rows)
        readers=[]
        for row in rows:
            if row['kind']!='FT4':continue
            at=row['address']&0x1fffff
            xy=[struct.unpack_from('<hh',ram,at+k) for k in (8,16,24,32)]
            if xy != [(224,87),(255,87),(224,118),(255,118)]:continue
            uv=[tuple(ram[at+k:at+k+2]) for k in (12,20,28,36)]
            page=struct.unpack_from('<H',ram,at+22)[0]
            clut=struct.unpack_from('<H',ram,at+14)[0]
            assert (page>>7)&3==0
            x0=(page&15)*64+min(u for u,v in uv)//4
            x1=(page&15)*64+max(u for u,v in uv)//4+1
            y0=((page>>4)&1)*256+min(v for u,v in uv)
            y1=((page>>4)&1)*256+max(v for u,v in uv)+1
            readers.append({'packet':hex(row['address']),'order':row['order'],'xy':xy,'uv':uv,
                            'clut':hex(clut),'tpage':hex(page),'physical_halfwords':[x0,y0,x1,y1],
                            'overlap_cursor': x0<985 and x1>960 and y0<480 and y1>447})
        entry={'slot':n,'ram_base':hex(rb),'vram_base':hex(vb),'ot_context':hex(context),'parity':parity,
               'ot_packets':len(rows),'ot_terminated':True,'cursor_pixels_exact':dest==source,
               'cursor_owner':hex(struct.unpack_from('<I',ram,0x1ee058)[0]),
               'cursor_active_flag':struct.unpack_from('<H',ram,0x1ee024)[0],
               'panel_xywh':struct.unpack_from('<4i',ram,0x1f0780),'slime_position_readers':readers}
        if n in (1,8):
            assert dest==source and len(readers)==2
            assert all(q['overlap_cursor']==(n==8) for q in readers)
        result['states'].append(entry)
    # Original geometry retained; actual glyph packet metrics are independently in runtime.json.
    for addr,word in [(0x8016c54c,0x34070026),(0x8016c778,0x3406001c)]:
        off=addr-0x8011a800
        assert struct.unpack_from('<I',e,off)[0]==word==struct.unpack_from('<I',original,off)[0]
    result['item_geometry']={'background_height':38,'text_room_height':28,'original_constants_retained':True,
                             'packet_rows_y':[116,132],'packet_height':16,'background_y':110,
                             'background_end_exclusive':148,'text_end_exclusive':148}
    ptr=struct.unpack_from('<I',e,0x82360)[0]-0x8011a800
    result['lr']={'pointer_file':'0x82360','text_file':hex(ptr),'payload_hex':e[ptr:e.index(0,ptr)].hex(),
                  'prior_lr_fix':'4/S4033.DAT:0x48102, separate dialogue consumer'}
    (OUT/'causes.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    md=capstone.Cs(capstone.CS_ARCH_MIPS,capstone.CS_MODE_MIPS32+capstone.CS_MODE_LITTLE_ENDIAN)
    lines=[]
    for lo,hi in [(0x8016c530,0x8016c558),(0x8016c760,0x8016c794),(0x80161a64,0x80161a7c),
                  (gate.CURSOR_GATE_RAM,gate.CURSOR_GATE_RAM+gate.CURSOR_GATE_SIZE)]:
        lines.extend(f'{i.address:08X} {i.mnemonic} {i.op_str}' for i in md.disasm(e[lo-0x8011a800:hi-0x8011a800],lo))
    (OUT/'cause_code.txt').write_text('\n'.join(lines)+'\n',encoding='utf-8')
    print(json.dumps(result,indent=2))

if __name__=='__main__':run()
