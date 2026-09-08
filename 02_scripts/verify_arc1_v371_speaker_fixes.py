"""Actual text-renderer CPU replay on read-only copies of four supplied states."""
import io,sys,struct,csv
from pathlib import Path
from zipfile import ZipFile
from audit_arc1_9118_runtime import load
from audit_arc1_v370_speaker_reports import FOLDERS
from analyze_arc1_v320c_savestates import object_at
from build_arc1_v364_cursor_speaker import stream
from v354_dialogue_codec import load_v354
import build_arc1_v371_speaker_fixes as b
sys.path.insert(0,str(b.ROOT/'01_work/tools/cursor_verify'))
import unicorn as uc
from unicorn import mips_const as m

def render(ram,old,new,start,end):
    copy=bytearray(ram)
    # Only verified matching loaded ranges; no saved-state file is changed.
    banks=[(0x4200,0x5000)] if start==0x45d02 else [(0x45000,0x45300)]
    for a,z in [(start,end+1)]+banks:
        location=ram.find(old[a:z]);assert location>=0,(hex(a),hex(z))
        assert ram.find(old[a:z],location+1)<0,('ambiguous loaded block',hex(a))
        copy[location:location+z-a]=new[a:z]
        if a==start:source=0x80000000+location;expected_end=source+end-start
    vm=uc.Uc(uc.UC_ARCH_MIPS,uc.UC_MODE_MIPS32|uc.UC_MODE_LITTLE_ENDIAN)
    vm.mem_map(0,0x200000);vm.mem_write(0,bytes(copy))
    def run(pc,**regs):
        vm.reg_write(m.UC_MIPS_REG_SP,0x80040000);vm.reg_write(m.UC_MIPS_REG_RA,0x80060000)
        for k,v in regs.items():vm.reg_write(getattr(m,'UC_MIPS_REG_'+k.upper()),v)
        hit=[]
        def stop(machine,address,size,data):
            if address==0x80060000:hit.append(address);machine.emu_stop()
        h=vm.hook_add(uc.UC_HOOK_CODE,stop)
        try:vm.emu_start(pc,0,count=400000)
        finally:vm.hook_del(h)
        assert hit,hex(vm.reg_read(m.UC_MIPS_REG_PC))
    origin=struct.unpack_from('<4h',ram,0x1f9d44+0x1e)
    assert origin==(46,32,228,208),origin
    vm.mem_write(0x40010,struct.pack('<II',0,0x801f9d44))
    run(0x8016b880,a0=origin[0],a1=origin[1],a2=origin[2],a3=origin[3])
    run(0x8016b8c8,a0=source,a1=0x801f9d44)
    state,packets=object_at(bytes(vm.mem_read(0,0x200000)),0x1f9d44,{'physical_chars':{}})
    dec=load_v354()[3]
    ts=[t for t,_ in stream(new,start,end-start) if t in dec]
    assert len(ts)==len(packets),(len(ts),len(packets),state)
    rows={}
    for t,p in zip(ts,packets):rows[p['y']]=rows.get(p['y'],'')+dec[t]
    assert int(state['source_pointer'],16)==expected_end,(state,hex(expected_end))
    return dict(state=state,rows=rows,positions=[(p['x'],p['y']) for p in packets])

def verify(blob):
    results=[]
    with ZipFile(b.BASE) as z:old={n:z.read(n) for n in z.namelist()}
    with ZipFile(io.BytesIO(blob)) as z:new={n:z.read(n) for n in z.namelist()}
    assert set(old)==set(new)
    assert {n for n in old if old[n]!=new[n]}=={'7/S7032.DAT','6/S6054.DAT'}
    records=list(csv.DictReader((b.ROOT/'05_docs/script_original_full.csv').open(encoding='utf-8-sig')))
    changed=[]
    for row,r in enumerate(records,1):
        fn=r['source file']
        if fn not in old:continue
        a=int(r['byte offset'],16);length=len(bytes.fromhex(r['raw bytes as hex']))
        before=[t for t,_ in stream(old[fn],a,length)]
        after=[t for t,_ in stream(new[fn],a,length)]
        if before!=after:changed.append(row)
    assert changed==[1742,2148,2151,2152],changed
    expected={2148:['로크톨:  이 무투 대회의 상품은','저 바람의 오브입니다.'],
              2151:['로크톨:  왕가가 멸망한 뒤에도','권력자와 부호 사이에서','선망과 두려움의 대상으로','전해 내려온 물건입니다.'],
              2152:['로크톨:  그야말로','이 피비린내 나는 무투 대회의 ','승자를 위한','것이 아니겠습니까? '],
              1742:['라마다 승려: 항상 목적을','가지고 행동하십시오.']}
    for n,(row,fn,start,end) in zip((2,3,4,5),b.TARGETS):
        path=Path('C:/Users/Administrator/.paseo/uploads')/('upload_'+FOLDERS[n])/f'HASH-477B29575D051C04_{n}.sav'
        ram,*_=load(path,old['PSX.EXE'])
        before=render(ram,old[fn],old[fn],start,end)
        captured,ps=object_at(ram,0x1f9d44,{'physical_chars':{}})
        assert before['state']['count']==captured['count']
        assert sorted(before['rows'])==sorted(set(p['y'] for p in ps))
        assert before['positions']==[(p['x'],p['y']) for p in ps]
        after=render(ram,old[fn],new[fn],start,end)
        assert max(after['rows'])<=80 and after['state']['count']<=64
        assert after['rows']=={32+i*16:text for i,text in enumerate(expected[row])}
        if row!=1742:
            assert after['rows'][32].startswith('로크톨:  ')
            assert len(after['rows'][32].strip())>len('로크톨:')
            assert ''.join(before['rows'].values()).replace(' ','')==''.join(after['rows'].values()).replace(' ','')
        else:assert after['rows']=={32:'라마다 승려: 항상 목적을',48:'가지고 행동하십시오.'},after
        results.append(dict(slot=n,row=row,before=before,after=after))
        print('CPU',row,after['rows'])
    return results
