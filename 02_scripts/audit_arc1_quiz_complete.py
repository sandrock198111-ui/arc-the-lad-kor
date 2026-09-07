"""Read-only V366 Ramada quiz catalog and actual CPU layout audit.

Enumerates the bounded event-text interval, not the old CSV start threshold.
Writes only analysis JSON/Markdown. No translation or game changes.
"""
from pathlib import Path
from zipfile import ZipFile
import csv,struct,json,hashlib,sys,io
from extract_story_corpus import token_end
from v354_dialogue_codec import tokens,load_v354
from audit_arc1_v363_speaker_cursor import expand
from audit_arc1_9118_runtime import load
from analyze_arc1_v320c_savestates import object_at
ROOT=Path(__file__).resolve().parents[1];AN=ROOT/'01_work/analysis/quiz_v366_audit'
BASE=ROOT/'03_output/arc1_v366_followups_TEST_ONLY.zip'
PIN='2443DCCA0451372D4D7A6ACD8B593696EC52734FC467B42C2284EFD14995FEBF'
sys.path.insert(0,str(ROOT/'01_work/tools/cursor_verify'))
import unicorn as uc
from unicorn import mips_const as m
def main(candidate_bytes=None, output_dir=None):
    global AN
    if output_dir is not None:AN=Path(output_dir)
    assert hashlib.sha256(BASE.read_bytes()).hexdigest().upper()==PIN
    with ZipFile(BASE) as z:d=z.read('6/S6054.DAT');exe=z.read('PSX.EXE')
    with ZipFile(ROOT/'00_original/arc.zip') as z:o=z.read('6/S6054.DAT')
    jp={int(r['index']):r['selected'] for r in csv.DictReader((ROOT/'01_work/analysis/story_corpus/japanese_glyph_map.csv').open(encoding='utf-8-sig'))}
    jp.update({16+i:str(i) for i in range(10)});jp[36]='：'
    _,_,_,dec=load_v354()
    def japanese(ts):
        return ''.join(('|' if t==b'\xe6\x01' else '[선택]' if t==b'\xe5\x03' else '<'+t.hex()+'>') if t[0]>=0xe1 else (jp.get(t[0]-1 if len(t)==1 else (t[0]-0xdd)*255+t[1]+0xdb) or '□') for t in ts)
    def korean(ts):
        return ''.join('|' if t==b'\xe6\x01' else '[선택]' if t==b'\xe5\x03' else dec.get(t,'<'+t.hex()+'>') for t in ts)
    csvkeys={int(r['byte offset'],16) for r in csv.DictReader((ROOT/'05_docs/script_original_full.csv').open(encoding='utf-8-sig')) if r['source file']=='6/S6054.DAT'}
    uploads=[('65623c59-dfb1-431f-86ac-437ed91b23a9',5),('9ce9f534-5d44-45d9-8f9d-cab1affc577b',6)]
    states=[]
    for folder,n in uploads:
        p=Path(f'C:/Users/Administrator/.paseo/uploads/upload_{folder}/HASH-477B29575D051C04_{n}.sav')
        ram,*_=load(p,exe)
        assert ram[0x11295a:0x114e50]==d[0x4395a:0x45e50]
        assert ram[0xd3200:0xd4000]==d[0x4200:0x5000]
        ptr=struct.unpack_from('<I',ram,0x1f9d58)[0]
        states.append(dict(slot=n,sha256=hashlib.sha256(p.read_bytes()).hexdigest(),title=p.read_bytes()[8:128].split(b'\0')[0].decode(),source_file_offset=hex((ptr&0x1fffff)-0xcf000)))
    captured=ram;entries=[];previous_end=0
    if candidate_bytes is not None:
        with ZipFile(io.BytesIO(candidate_bytes)) as z:
            target=z.read('6/S6054.DAT')
            assert z.read('PSX.EXE')==exe and len(target)==len(d)
        patched=bytearray(captured)
        for i,(a,b) in enumerate(zip(d,target)):
            if a!=b:
                assert 0x4395a<=i<0x45e50,(hex(i),'outside captured quiz text')
                patched[0xcf000+i]=b
        captured=bytes(patched);d=target
    for marker in range(0x43958,0x45e50,2):
        if marker<previous_end or o[marker:marker+2]!=b'\x19\0':continue
        at=marker+2;end=token_end(o,at)
        assert end is not None and 0<end-at<256,(hex(at),end)
        ts=list(tokens(o[at:end]));assert all(t[0]<0xe1 or t in (b'\xe6\x01',b'\xe5\x03') for t in ts),(hex(at),ts)
        assert o[marker-6:marker]==bytes.fromhex('29 00 00 00 7f 00'),hex(at)
        previous_end=end+1
        finalts=expand(d,at,end-at)
        entry=dict(offset=hex(at),end=hex(end),bytes=end-at,csv_present=at in csvkeys,
                   original_identical=d[at:end+1]==o[at:end+1],japanese_map_preview=japanese(ts),
                   current_decode=korean(finalts),choice_count=sum(t==b'\xe5\x03' for t in ts))
        vm=uc.Uc(uc.UC_ARCH_MIPS,uc.UC_MODE_MIPS32|uc.UC_MODE_LITTLE_ENDIAN);vm.mem_map(0,0x200000);vm.mem_write(0,captured)
        def run(pc,endpc=0x80060000,**regs):
            vm.reg_write(m.UC_MIPS_REG_SP,0x80040000);vm.reg_write(m.UC_MIPS_REG_RA,0x80060000)
            for k,v in regs.items():vm.reg_write(getattr(m,'UC_MIPS_REG_'+k.upper()),v)
            hit=[]
            def stop(machine,address,size,data):
                if address==endpc:hit.append(address);machine.emu_stop()
            hook=vm.hook_add(uc.UC_HOOK_CODE,stop)
            try:vm.emu_start(pc,0,count=200000)
            finally:vm.hook_del(hook)
            assert hit==[endpc],hex(vm.reg_read(m.UC_MIPS_REG_PC))
        vm.mem_write(0x40010,struct.pack('<II',0,0x801f9d44))
        try:
            run(0x8016b880,a0=46,a1=32,a2=228,a3=208)
            run(0x8016b8c8,a0=0x800cf000+at,a1=0x801f9d44)
            s,ps=object_at(bytes(vm.mem_read(0,0x200000)),0x1f9d44,{'physical_chars':{}})
            ys=sorted(set(p['y'] for p in ps));expected=sum(2 if t==b'\xe5\x03' else 0 if t==b'\xe6\x01' else 1 for t in finalts)
            entry['renderer']=dict(count=s['count'],expected_tokens=expected,ys=ys,
                source_end_matches=int(s['source_pointer'],16)==0x800cf000+end,
                max_right=max((p['x']+p['w'] for p in ps),default=0),
                max_bottom=max((p['y']+p['h'] for p in ps),default=0),
                over_four_rows=len(ys)>4,packet_count_matches=s['count']==expected)
            display=[]
            for t in finalts:
                if t==b'\xe6\x01':continue
                if t==b'\xe5\x03':display.extend([' ',' '])
                else:display.append(dec.get(t,'<'+t.hex()+'>'))
            if len(display)==len(ps):
                row_text={}
                for char,p in zip(display,ps):row_text[p['y']]=row_text.get(p['y'],'')+char
                entry['renderer']['row_text']=row_text
                entry['renderer']['interior_empty_rows']=any(b-a>16 for a,b in zip(ys,ys[1:]))
            if entry['choice_count']:
                # String termination occupies a zero halfword after rounding
                # an odd-byte body up; do not stop at the padding zero word.
                event=(end+3)&~1
                header=struct.unpack_from('<7h',d,event)
                assert header[:4]==(0x21,6,4,5),(hex(at),header)
                _,_,_,index,count,col,row=header
                assert count==entry['choice_count']
                base=struct.unpack_from('<I',captured,0x1b1acc)[0]
                vm.mem_write(0x1fe2b4,struct.pack('<H',(0x800cf000+event+2-base)//2));run(0x8015c48c)
                assert struct.unpack('<4h',vm.mem_read(0x1fe2ba,8))==(index,count,col,row)
                # Map emitted option text packets from actual expanded tokens.
                starts=[];pi=0
                for t in finalts:
                    if t==b'\xe5\x03':starts.append(pi+2);pi+=2
                    elif t!=b'\xe6\x01':pi+=1
                if at==0x43b4e:starts=[1,4,7,10]
                elif entry['choice_count']==4 and not starts:
                    # Inline four-option layout without E5 indentation.
                    starts=[0];pi=0
                    for t in finalts:
                        if t==b'\xe6\x01':starts.append(pi)
                        else:pi+=1
                    assert len(starts)==4
                positions=[]
                for selected in range(count):
                    run(0x8015a6e0,0x8015a728,s1=0x801f9d44,a0=selected)
                    x,y=vm.reg_read(m.UC_MIPS_REG_A0),vm.reg_read(m.UC_MIPS_REG_A1)+2
                    p=ps[starts[selected]] if len(starts)>selected and starts[selected]<len(ps) else None
                    positions.append(dict(index=selected,cursor=[x,y],text=[p['x'],p['y']] if p else None,
                        aligned=bool(p and p['y']+2==y and 0<=p['x']-(x+7)<=20)))
                nav=[]
                for selected in range(count):
                    for delta,key in [(-1,0x1000),(1,0x4000)]:
                        vm.mem_write(0x60010,struct.pack('<I',selected));vm.mem_write(0x60024,struct.pack('<I',key))
                        run(0x8015e3d8,0x8015e464,a0=selected,s0=0,s1=0x80060010,s2=0x80060020,s4=0,s5=count-1)
                        result=vm.reg_read(m.UC_MIPS_REG_A1);assert result==(selected+delta)%count
                        nav.append(result)
                entry['choice']=dict(event=hex(event),fields=list(header[3:]),positions=positions,
                    all_aligned=all(p['aligned'] for p in positions),navigation_cases=len(nav))
        except Exception as ex:entry['cpu_error']=repr(ex)
        entries.append(entry)
    questions=[]
    for i,e in enumerate(entries):
        if e['choice_count']==4:
            question=entries[i-1];follow=entries[i+1]
            questions.append(dict(number=len(questions)+1,question=question['offset'],choices=e['offset'],followup=follow['offset'],
                question_original=question['original_identical'],choices_original=e['original_identical'],
                followup_original=follow['original_identical'],question_preview=question['japanese_map_preview'],
                choice_aligned=e.get('choice',{}).get('all_aligned'),rows=e.get('renderer',{}).get('ys'),error=e.get('cpu_error')))
    extra_four=[]
    for marker in range(0x42000,len(o)-8,2):
        if o[marker-6:marker+2]!=bytes.fromhex('29 00 00 00 7f 00 19 00'):continue
        end=token_end(o,marker+2)
        if end and end-marker<256 and list(tokens(o[marker+2:end])).count(b'\xe5\x03')==4 and not 0x43958<=marker<0x45e50:extra_four.append(hex(marker+2))
    counts=dict(entries=len(entries),questions=len(questions),four_choice_items=4*len(questions),
        outside_old_csv=sum(not e['csv_present'] for e in entries),original_identical=sum(e['original_identical'] for e in entries),
        question_original=sum(q['question_original'] for q in questions),choices_original=sum(q['choices_original'] for q in questions),
        followup_original=sum(q['followup_original'] for q in questions),cpu_errors=sum('cpu_error' in e for e in entries),
        over_four_rows=sum(e.get('renderer',{}).get('over_four_rows',False) for e in entries),
        choice_windows=sum('choice' in e for e in entries),misaligned_windows=sum(not e['choice']['all_aligned'] for e in entries if 'choice' in e),
        navigation_cases=sum(e['choice']['navigation_cases'] for e in entries if 'choice' in e),
        additional_same_header_four_choice_bodies=extra_four)
    result=dict(baseline_sha256=PIN,states=states,scope='S6054 event text 4395A..45E4F; 29-header + token boundaries + same consumer CPU. Full gameplay branch reachability not proven.',
                counts=counts,questions=questions,entries=entries)
    if candidate_bytes is not None:result['candidate_sha256']=hashlib.sha256(candidate_bytes).hexdigest().upper()
    AN.mkdir(parents=True,exist_ok=True);(AN/'audit.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
    lines=['# 라마다사 퀴즈 '+('후보 전체 CPU 검사' if candidate_bytes is not None else 'V366 전수 목록 조사'),'',str(counts),'',
        '실제 CPU 출력 검사이며 전체 플레이 검증은 아니다. 일본어 미리보기 표는 기존 글리프 매핑의 빈칸/오독을 포함하므로 번역 원문 확정으로 사용하지 않는다.',
        '', '|번호|질문 주소|선택지 주소|질문 원문잔존|선택 원문잔존|후속 원문잔존|선택 커서 정렬|', '|---:|---|---|---|---|---|---|']
    for q in questions:lines.append(f"|{q['number']}|{q['question']}|{q['choices']}|{q['question_original']}|{q['choices_original']}|{q['followup_original']}|{q['choice_aligned']}|")
    lines+=['','## 전체 대사 주소와 배치','', '|주소|기존표 포함|원문동일|출력 행 Y|출력수|CPU 오류|','|---|---|---|---|---|---|']
    for e in entries:lines.append(f"|{e['offset']}|{e['csv_present']}|{e['original_identical']}|{e.get('renderer',{}).get('ys')}|{e.get('renderer',{}).get('count')}|{e.get('cpu_error','')}|")
    lines+=['','## 선택문·커서 실제 CPU 좌표','',
        '각 항목은 `선택문 [X,Y] → 커서 상단 [X,Y]` 순서. 상하 이동은 원본과 동일하게 끝에서 순환한다.',
        '', '|선택창 주소|선택 인자(index,count,column,baseRow)|항목별 좌표|', '|---|---|---|']
    for e in entries:
        if 'choice' in e:
            c=e['choice'];positions=' / '.join(f"{p['text']} → {p['cursor']}" for p in c['positions'])
            lines.append(f"|{e['offset']}|{c['fields']}|{positions}|")
    (AN/'catalog.md').write_text('\n'.join(lines)+'\n',encoding='utf-8')
    print(json.dumps(counts));print('STATES',states)
    print('PROBLEMS',[(e['offset'],e.get('cpu_error'),e.get('renderer'),e.get('choice')) for e in entries if 'cpu_error' in e or e.get('renderer',{}).get('over_four_rows') or ('choice'in e and not e['choice']['all_aligned'])])
if __name__=='__main__':main()
