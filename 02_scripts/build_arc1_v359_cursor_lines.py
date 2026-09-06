"""Isolated TEST_ONLY textureless range cursor; no CSV/font/VRAM allocation.

Dependencies: keystone-engine 0.9.2, capstone, unicorn 2.1.4 (verification).
Existing V324 resident cursor-only tail is reused, NOT a new RAM cave.
R3000A little-endian MIPS-I integer instructions only; no relocated instructions.
"""
from pathlib import Path
from zipfile import ZipFile, ZIP_DEFLATED
import hashlib, json, struct, sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'01_work/tools/cursor_verify'))
from keystone import Ks, KS_ARCH_MIPS, KS_MODE_MIPS32, KS_MODE_LITTLE_ENDIAN
import capstone
import build_arc1_v324_static_ui_cursor_recovery as resident
from build_arc1_v323_skill_range_relocation import BASE_UV

BASE = ROOT/'03_output/arc1_v359_review_215_TEST_ONLY.zip'
BASE_SHA = 'A66F88444716E9993C0C4BBC2EC58A4965B3359D55278DC193A183A621BE4E1B'
OUT = ROOT/'03_output/arc1_v359_cursor_lines_TEST_ONLY.zip'
AN = ROOT/'01_work/analysis/v359_cursor_lines'
ORIGINAL = ROOT/'00_original/arc.zip'
ORIGINAL_SHA = 'AE9F4366A1E7DA3805BB3BED3DDA9567E4CD4E669AF890E4E2A620D7861F11DD'
ENTRY = resident.HELPER_RAM
TABLE = ENTRY+256
ADDPRIM = 0x80178F84
DRAWOT = 0x80176E1C
BIAS = 0x8011A800

def digest(b): return hashlib.sha256(b).hexdigest().upper()
def word(b, off): return struct.unpack_from('<I', b, off)[0]
def jal(addr): return struct.pack('<I', 0x0c000000|((addr>>2)&0x3ffffff))
def jump(addr): return struct.pack('<I', 0x08000000|((addr>>2)&0x3ffffff))

def paths():
    """Map original UV edge orientation, not nine identical squares."""
    result=[]
    for mode,uv in enumerate(BASE_UV):
        corners=list(zip(uv[::2],uv[1::2]))
        tile=0 if mode==0 else (1 if mode<=4 else 2)
        edges=[]
        for a,b in [(0,1),(1,3),(3,2),(2,0)]:
            u=(corners[a][0]+corners[b][0])//2
            v=(corners[a][1]+corners[b][1])//2
            visible=(tile==0 or v==128 or u==(tile+1)*32 or (tile==1 and u==32))
            if visible: edges.append((a,b))
        assert len(edges)==(4 if mode==0 else 3 if mode<=4 else 2)
        degree={p:sum(p in e for e in edges) for p in range(4)}
        start=0 if mode==0 else min(p for p,d in degree.items() if d==1)
        seq=[start];remaining=edges[:]
        while remaining:
            edge=next(e for e in remaining if seq[-1] in e)
            seq.append(edge[1] if edge[0]==seq[-1] else edge[0]);remaining.remove(edge)
        result.append(seq)
    return result

def assemble():
    # a0=OT bucket, a1=40-byte FT4, s1=original UV type * 16.
    # Snapshot all four projected coordinates before replacing interleaved FT4.
    # Each load has an independent instruction/nop before consumption (R3000).
    # Opaque flat white is deliberate: no dependency on prior blend/tpage state.
    source=f'''.set noreorder
        addiu $sp, $sp, -16
        lw $t0, 8($a1)
        lw $t1, 16($a1)
        lw $t2, 24($a1)
        lw $t3, 32($a1)
        sw $t0, 0($sp)
        sw $t1, 4($sp)
        sw $t2, 8($sp)
        sw $t3, 12($sp)
        srl $t0, $s1, 4
        sltiu $t1, $t0, 9
        bne $t1, $zero, valid
        nop
        or $t0, $zero, $zero
    valid:
        sll $t0, $t0, 3
        lui $t1, {TABLE>>16}
        ori $t1, $t1, {TABLE&65535}
        addu $t0, $t0, $t1
        lbu $t2, 0($t0)
        addiu $t0, $t0, 1
        addiu $t1, $t2, 2
        sb $t1, 3($a1)
        lui $t1, 0x48ff
        ori $t1, $t1, 0xffff
        sw $t1, 4($a1)
        addiu $t3, $a1, 8
    vertex:
        lbu $t1, 0($t0)
        addiu $t0, $t0, 1
        addu $t1, $sp, $t1
        lw $t1, 0($t1)
        addiu $t2, $t2, -1
        sw $t1, 0($t3)
        bne $t2, $zero, vertex
        addiu $t3, $t3, 4
        lui $t1, 0x5555
        ori $t1, $t1, 0x5555
        sw $t1, 0($t3)
        j {ADDPRIM}
        addiu $sp, $sp, 16
    '''
    ks=Ks(KS_ARCH_MIPS, KS_MODE_MIPS32|KS_MODE_LITTLE_ENDIAN)
    code=bytes(ks.asm(source, addr=ENTRY)[0])
    assert len(code)<=256 and len(code)%4==0
    md=capstone.Cs(capstone.CS_ARCH_MIPS,capstone.CS_MODE_MIPS32|capstone.CS_MODE_LITTLE_ENDIAN)
    decoded=list(md.disasm(code,ENTRY))
    assert sum(i.size for i in decoded)==len(code)
    # Keystone MIPS PC-relative numeric absolute operands are unsupported at
    # KSEG addresses. Reconstruct labels from decoded targets; do not encode
    # branches ourselves or skip their round-trip.
    lines=['.set noreorder']
    for i in decoded:
        operand=i.op_str
        if i.mnemonic.startswith('b'):
            parts=operand.rsplit(', ',1);target=int(parts[-1],0)
            assert ENTRY<=target<ENTRY+len(code) and (target-ENTRY)%4==0
            operand=(parts[0]+', ' if len(parts)==2 else '')+f'pc_{target:x}'
        lines += [f'pc_{i.address:x}:',i.mnemonic+' '+operand]
    rebuilt=bytes(ks.asm('\n'.join(lines),addr=ENTRY)[0])
    assert rebuilt==code,('full instruction round-trip mismatch',rebuilt.hex(),code.hex())
    table=b''.join(bytes([len(p)]+[v*4 for v in p]).ljust(8,b'\0') for p in paths())
    payload=code.ljust(256,b'\0')+table
    assert len(payload)<=resident.RECLAIM_SIZE
    return payload,source,decoded,len(code)

def build():
    assert digest(BASE.read_bytes())==BASE_SHA
    assert digest(ORIGINAL.read_bytes())==ORIGINAL_SHA
    csv_hashes={p.name:digest(p.read_bytes()) for p in [ROOT/'05_docs/script_translated_full.csv',ROOT/'05_docs/dialogue_all.csv']}
    with ZipFile(BASE) as z: members={n:z.read(n) for n in z.namelist()}
    with ZipFile(ORIGINAL) as z: original=z.read('PSX.EXE')
    old=members['PSX.EXE'];new=bytearray(old)
    payload,asm,decoded,code_size=assemble()
    # Pinned baseline plus exact original call-site guards before any patch.
    assert old[0x2060:0x2064]==jal(0x8018FD90)
    assert original[0x2060:0x2064]==jal(DRAWOT)
    assert old[0x2064:0x2068]==original[0x2064:0x2068]==bytes.fromhex('70000426')
    hook=0x8011F214-BIAS
    assert old[hook:hook+8]==original[hook:hook+8]==jal(ADDPRIM)+bytes.fromhex('68088424')
    assert old[0x3e14:0x3e1c]==original[0x3e14:0x3e1c] # initializer no uploader
    assert word(old,resident.COPY_LENGTH_WORD_RAM-BIAS)==resident.EXPECTED_COPY_LENGTH_WORD
    assert word(old,resident.HEAP_BOUNDARY_WORD_RAM-BIAS)==resident.EXPECTED_HEAP_BOUNDARY_WORD
    # Old dedicated gate also becomes a safe DrawOT tail-call, never converter.
    changes=[('stop_predraw_upload',0x2060,jal(DRAWOT)),
             ('disable_old_gate',0x75590,jump(DRAWOT)+b'\0'*4),
             ('range_packet_hook',hook,jal(ENTRY)),
             ('resident_cursor_prefix',resident.HELPER_SOURCE_FILE,payload)]
    manifest=[];covered=set()
    for name,off,data in changes:
        span=set(range(off,off+len(data)));assert not covered&span;covered|=span
        manifest.append({'name':name,'file_offset':hex(off),'size':len(data),'before_hex':old[off:off+len(data)].hex(),'after_hex':data.hex()})
        new[off:off+len(data)]=data
    assert len(old)==len(new)
    assert all(i in covered for i,(a,b) in enumerate(zip(old,new)) if a!=b)
    # Selection logic, GTE setup, UV/timing code, font, descriptors and text untouched.
    assert old[0x8011ED24-BIAS:hook]==new[0x8011ED24-BIAS:hook]
    # Later builds reused F858..F8AF for UI code with two live JAL callers.
    # Never clear the historical V324 whole tail. Only uploader prefix + the
    # first four obsolete RLE bytes are replaced; all bytes after stay exact.
    assert old[resident.HELPER_SOURCE_FILE+len(payload):]==new[resident.HELPER_SOURCE_FILE+len(payload):]
    ui_off=resident.resident_source_offset(0x801FF858)
    assert old[ui_off:ui_off+88]==new[ui_off:ui_off+88]
    members['PSX.EXE']=bytes(new)
    from verify_arc1_v359_cursor_lines import verify_cpu
    verification=verify_cpu(bytes(new),code_size)
    AN.mkdir(parents=True,exist_ok=True)
    (AN/'cursor.s').write_text(asm,encoding='utf-8')
    (AN/'cursor_disassembly.txt').write_text('\n'.join(f'{i.address:08X}: {bytes(i.bytes).hex()} {i.mnemonic} {i.op_str}' for i in decoded)+'\n',encoding='utf-8')
    if OUT.exists(): raise FileExistsError('Do not overwrite existing test archive')
    with ZipFile(OUT,'w',compression=ZIP_DEFLATED,compresslevel=9) as z:
        for name,data in members.items():z.writestr(name,data)
    with ZipFile(OUT) as z:
        assert z.namelist()==list(members)
        assert all(z.read(n)==data for n,data in members.items())
    with ZipFile(BASE) as z: assert [n for n in members if z.read(n)!=members[n]]==['PSX.EXE']
    from verify_arc1_v359_slot_recovery import legacy_gate
    before,after=legacy_gate(BASE),legacy_gate(OUT)
    assert before['fail']==after['fail'] and before['counts']==after['counts']
    assert csv_hashes=={name:digest((ROOT/'05_docs'/name).read_bytes()) for name in csv_hashes}
    report={'status':'TEST_ONLY; cold-boot runtime NOT VERIFIED','base_sha256':BASE_SHA,'zip_sha256':digest(OUT.read_bytes()),
            'changed_members':['PSX.EXE'],'csv_sha256':csv_hashes,'new_texture_vram_bytes':0,'new_reserved_ram_bytes':0,
            'resident_reused_bytes':len(payload),'code_bytes':code_size,'paths':paths(),'changes':manifest,
            'cpu_verification':verification,'legacy_gate_unchanged':True,'legacy_fail':after['fail'],
            'risks':['Opaque 1px white outline replaces animated gradient texture; outer blink retained.',
                     'Captured cursor is last drawable OT entry; other contexts and next-frame draw-state need runtime testing.',
                     'Line endpoint rasterization differs from FT4 edge exclusion.',
                     'Old savestates retain old code and corrupted VRAM; cold boot required.']}
    (AN/'report.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    print(OUT);print(report['zip_sha256']);print(verification)

if __name__=='__main__':build()
