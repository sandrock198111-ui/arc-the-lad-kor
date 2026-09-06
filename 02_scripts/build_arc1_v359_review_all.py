"""Compose approved review edits into a guarded TEST_ONLY disc-member set.

The fixed baseline is materialized from pristine members and its exact delta;
all later edits are guarded hunks. No source CSV or existing game is overwritten.
"""
import csv, hashlib, html, json, shutil, sys
from pathlib import Path
from zipfile import ZipFile, ZIP_DEFLATED
import review_editor as e
import build_arc1_v357_user_reviewed_dialogue_bankb as b
import qualify_dialogue_review_20260905 as q

ROOT=q.ROOT
OUT=ROOT/'01_work/analysis/dialogue_review_20260905/build_all'
ZIP=ROOT/'03_output/arc1_v359_review_all_final_TEST_ONLY.zip'
TEMPLATES={
 67:['말을 걸거나','물건을 찾을 때는','가까이 다가가 ','버튼을 누르면 돼.'],
 463:['뭐, 무슨 무례한 짓을!','이분이 누군지 아느냐.','',''],
 574:['국왕:','찬탈이라니.','','이런 아이가 그런 짓을...'],
 640:['스메리아 왕:','대신','안델의 말에','','넘어간','바로 나였다.'],
 1131:['두목님...','','아우들...'],
 1313:['장사라니, 이 자식아!','','','','혼 좀 나고 싶냐!',''],
 2151:['로크톨:','왕가가 멸망한 뒤에도','권력자와','부호 사이에서','선망과','두려움의 대상으로','전해','내려온','물건입니다.',''],
 2152:['로크톨:','그야말로','이','피비린내 나는','무투 대회의 승자에게','어','울','리','는','물','','건','이','아','니','겠','습','니','까','','','','?',''],
 2695:['굉장한 아이템을 손에 넣었다!',''],
 2696:['촌가라의 굉장한 아이템을 빼앗았다!',''],
 2698:['굉장한 아이템을 빼앗았다!',''],
 2711:['후후후후','.','.','.','','','아니,','','아무도 없잖아!?','',''],
 2740:['아아,','','대체 이 오브와 정령은','무슨 관계가 있는 걸까?'],
 2734:['자, 다 같이 출까요?',''],
 2767:['불꽃의 정령:','그래, 이 연구소는','새로운','','에너지를 연구하고','있다','.','바로 생명력 에너지다.'],
 2768:['불꽃의 정령:','불꽃의 정령인','나를 붙잡아','','에너지를','계속 빼앗아 왔다.'],
 2770:['불꽃의 정령:','에너지는','서로 나누며','','키워 가는 것이지','','억지로','빼앗는 게 아니다.'],
}
for n,count in [(2483,20),(2486,40),(2489,80),(2492,120),(2495,160),(2498,200)]:
    TEMPLATES[n]=[f'{count}회까지 앞으로 ','회입니다.','힘내 주십시오.']

# Root-reviewed simple context resolutions; uncertain corrupted source stays held.
RESOLVED={1048,1176,1177,1179,1203,1313,1409,1521,1552,1619,1658,1715,1854,2203,2352,2460,2594,2751}
RESOLVED.update({208,347,601,743,1089,1104,1640,1650,2242,2255,2261,2263,2300,2767,2768,2770,2777,2789})
SOURCE_CONFIRMED={
208:'이야, 술이 확 깨는구먼.',
347:'그래. 먼 옛날의 여행 때부터 운명으로 이어진 영혼이지.',
601:'네. 아버지의 편지로 옛일을 적은 고대의 기록이 있다는 것을 알게 되었습니다.',
743:'승무원: 요수도 증식하면 HP가 절반으로 줄지만, 처치했을 때 얻는 경험치는 그대로입니다.',
1089:'병사1: 좋다! 인간이 얼마나 약한지 알려 주마.',
1104:'나한테는 신경 쓰지 않는 게 좋아.',
1640:'떨어진 상대에게 피해를 줄 수 있다고 하네.',
1650:'우리조차 올라간 적 없는 라마다산에 들어가려 하다니.',
2242:'매트 버틀러: 물의 신전 열쇠는 손에 넣었나?',
2255:'카사토르: 이용할 수 있는 것은 철저히 이용하고, 살 가치도 없는 쓰레기들을 없애는 게 뭐가 나쁘지?',
2261:'카사토르: 좋아, 신전 열쇠가 필요했을 뿐이다.',
2263:'카사토르: 쓰레기들을 죽이는 데 그 이상의 이유 따위는 없다.',
2300:'데스: 엘리베이터 줄을 끊어 한꺼번에 끝장내 주마.',
2767:'불꽃의 정령: 그래, 이 연구소는 새로운 에너지를 연구하고 있다. 바로 생명력 에너지다.',
2768:'불꽃의 정령: 불꽃의 정령인 나를 붙잡아 에너지를 계속 빼앗아 왔다.',
2770:'불꽃의 정령: 에너지는 서로 나누며 키워 가는 것이지 상대에게서 억지로 빼앗는 것이 아니다.',
2777:'불의 정령: 생물이 가진 생명을 에너지로 바꾸는 일을 생각하기 시작했다.',
2789:'나는 그쪽에 기대를 걸어 보고 싶구먼.',
}

def sha(data):return hashlib.sha256(data).hexdigest().upper()
def compact(s):return ''.join(s.replace('|',' ').split())
def hunks(old,new):
    assert len(old)==len(new)
    start=None;out=[]
    for pos in range(len(old)+1):
        changed=pos<len(old) and old[pos]!=new[pos]
        if changed and start is None:start=pos
        if not changed and start is not None:
            out.append({'at':start,'before':old[start:pos].hex(),'after':new[start:pos].hex()});start=None
    return out

def materialize():
    assert sha(q.BASE.read_bytes())==q.PIN
    assert sha(b.PRISTINE.read_bytes())==b.PRISTINE_SHA256
    with ZipFile(q.BASE) as z:infos=z.infolist();expected={i.filename:z.read(i) for i in infos}
    with ZipFile(b.PRISTINE) as z:pristine={n:z.read(n) for n in expected}
    result={};spec={}
    for name,want in expected.items():
        old=pristine[name]
        # Baseline executable enlargement is already a verified shipping boundary.
        if len(old)!=len(want):
            spec[name]={'original_sha256':sha(old),'replacement':want.hex()}
            result[name]=bytes.fromhex(spec[name]['replacement'])
        else:
            changes=hunks(old,want);data=bytearray(old)
            for w in changes:
                a=bytes.fromhex(w['before']);v=bytes.fromhex(w['after'])
                assert data[w['at']:w['at']+len(a)]==a
                data[w['at']:w['at']+len(a)]=v
            result[name]=bytes(data);spec[name]={'original_sha256':sha(old),'hunks':changes}
        assert result[name]==want
    return infos,pristine,result,spec

def slot_pos(ref):
    bank,slot=ref
    return (b.SLOT_BASE if bank=='A' else b.BANK_B_OFFSET)+128*slot

class Planner(b.FilePlanner):
    def __init__(self,name,current,pristine,table):
        super().__init__(name,current,pristine,[],table)
        # Same previously validated Bank-B range; only pristine/current-zero
        # individual slots with no possible bytewise caller are eligible.
        if not any(pristine[0x4200:0x5000]) and len(pristine)>=0x5000:
            self.free_b=[s for s in range(28) if not any(current[0x4200+128*s:0x4280+128*s])
                         and bytes((0xE2,0xD1+s)) not in current]
    def place(self,at,room,text,user):
        data=b.encoded(text,self.table)
        if len(data)<=room:return super().place(at,room,text,user)
        live=self.before[at:at+room]
        if len(live)>=2 and live[0]==0xE2:
            ref=b.slot_of_disk(live[1])
            if ref and self.before.count(live[:2])==1:
                loc=slot_pos(ref)
                if self.before[loc+127]==room-2 and len(data)<=126:
                    old=self.before[loc:loc+127].split(b'\0')[0]
                    if not b.structure(old)[1]:
                        self.data[loc:loc+127]=(data+b'\0').ljust(127,b'\0')
                        return
        # Reuse an already populated translation slot only with exact payload AND
        # return skip equality. No shared payload is ever overwritten here.
        for bank,count in [('A',79),('B',28)]:
            for s in range(count):
                if bank=='A' and s not in self.safe_slots:continue
                loc=slot_pos((bank,s));block=bytes(self.data[loc:loc+128])
                if len(block)!=128 or len(data)>126 or block[-1]!=room-2:continue
                if block[:127].split(b'\0')[0]==data and room>=2:
                    disk=b.disk_id_a(s) if bank=='A' else 0xD1+s
                    pool=self.free_a if bank=='A' else self.free_b
                    if s in pool:pool.remove(s)
                    self.data[at:at+room]=bytes((0xE2,disk))+bytes([b.FILL])*(room-2)
                    return
        return super().place(at,room,text,user)

def read_tokens(blob,offset,room,depth=0):
    assert depth<2
    out=[];p=0
    while p<room:
        lead=blob[offset+p];sz=1 if lead<0xDD else 2
        token=blob[offset+p:offset+p+sz]
        if lead==0xE2:
            assert depth==0
            ref=b.slot_of_disk(token[1]);assert ref is not None
            at=slot_pos(ref);payload=blob[at:at+127];assert 0 in payload
            end=payload.index(0);out+=read_tokens(blob,at,end,depth+1);sz=2+blob[at+127]
        else:out.append(token)
        p+=sz
    assert p==room
    return out

def main():
    OUT.mkdir(parents=True,exist_ok=True)
    snap=OUT/'canonical_before.csv'
    if not snap.exists():shutil.copy2(q.SOURCE,snap)
    e.TRANSLATED=snap
    ed=e.Editor.__new__(e.Editor);ed.load()
    review=json.loads((q.OUT.parent/'combined_review.json').read_text(encoding='utf-8'))['issues']
    oldplan=json.loads((q.OUT/'application_plan.json').read_text(encoding='utf-8'))
    alternatives=json.loads((q.OUT.parent/'glyph_reword.json').read_text(encoding='utf-8'))['rows']
    alt={x['row']:x['text'] for x in alternatives if x['text']}
    alt.update(SOURCE_CONFIRMED)
    alt[1721]='|있다|없다|만들려 했다|가려 했다'
    alt[1748]='환수의 어금니를 얻었다.'
    # Root-reviewed acquisition wording: preserve item names and acquisition
    # meaning while avoiding needless new slots for a whitespace-only repair.
    for item in review:
        if item['row_number'] in {2505,2516,2522,2527,2531,2538,2542,2544,2549,2554,2570,2577,2578,2580,2582,2584,2585,2586}:
            alt[item['row_number']]=item['suggestion'].replace('손에 넣었다','얻었다')
    infos,pristine,base,spec=materialize();current=dict(base);records=[]
    OUT.joinpath('baseline_composition.json').write_text(json.dumps(spec),encoding='utf-8')
    oldmap={r['row']:r for r in oldplan['rows']}
    for issue in review:
        n=issue['row_number'];line=ed.lines[n-1];oldrec=oldmap[n]
        target=alt.get(n,issue['suggestion'])
        if oldrec['status']=='QUALIFIED_CANONICAL_ONLY':target=oldrec['proposed']
        rec=dict(row=n,file=line.file,offset=line.offset,before=line.korean,target=target,status='HELD',reason='',writes=[])
        precise_holds={1481:'원본은 オドン으로 확인됨. 오돈의 돈 글리프가 없으며 고유명사를 다른 뜻으로 대체하지 않음.',
                       1482:'원본은 オドン으로 확인됨. 오돈의 돈 글리프가 없어 인명 두 행을 함께 보류.',
                       1703:'인명 구별 퀴즈: 초빈의 빈 글리프가 없어 정답/오답 구별을 보존한 대체 불가.',
                       1551:'카델 용어 통일안이나 27개 연출/줄바꿈 제어 위치의 템플릿 미검증. 현행 카데르 유지.'}
        if n in precise_holds:
            rec['reason']=precise_holds[n];records.append(rec);continue
        if n==1733:target='|노랑|사정상 갈빛|실은 빨강|누구?';rec['target']=target
        if n in TEMPLATES:
            target=' '.join(x.strip() for x in TEMPLATES[n] if x.strip());rec['target']=target
        if issue.get('context_uncertain') and n not in RESOLVED and n not in TEMPLATES and oldrec['status']!='QUALIFIED_CANONICAL_ONLY':
            rec['reason']='원문/고유명사 확인 필요: '+issue['reason'];records.append(rec);continue
        if target.startswith('원문') or target.startswith('원본'):
            rec['reason']='추출 원문 재확인 전 기존 번역 유지';records.append(rec);continue
        before=current[line.file];o=int(line.offset,0)
        try:
            b.encoded(target,ed.table)
            planner=Planner(line.file,before,pristine[line.file],ed.table)
            source_special=[t for _,t in b.structure(line.raw)[1] if t[0] not in (0xE5,0xE6)]
            if n in TEMPLATES:
                spans,controls=b.structure(line.raw);parts=TEMPLATES[n]
                assert len(parts)==len(spans)
                for p,t in controls:planner.data[o+p:o+p+len(t)]=t
                # Template's prose is authoritative; E7 placeholder remains an icon.
                target=' '.join(x.strip() for x in parts if x.strip())
                rec['target']=target
                pairs=list(zip(spans,parts))
            else:
                if source_special:raise b.BuildError('원본 특수 제어코드의 위치별 한국어 템플릿 추가 필요')
                spans,controls=q.live_structure(before,o,len(line.raw))
                content=[s for s in spans if s[1]>s[0]]
                if line.is_choice:
                    parts=[x.strip() for x in target.split('|') if x.strip()]
                    if len(content)==len(parts)+1 and not target.startswith('|'):
                        head=b.split_words(parts[0],2,[content[0][1]-content[0][0],content[1][1]-content[1][0]],ed.table)
                        parts=head+parts[1:]
                    if len(parts)!=len(content):raise b.BuildError('선택지 영역 대응 불일치')
                    if any(b.wrapped_rows(b.encoded(x,ed.table))>1 for x in parts):raise b.BuildError('선택지 한 줄 폭 초과')
                else:parts=b.split_words(target.replace('|',' '),len(content),[hi-lo for lo,hi in content],ed.table)
                pairs=list(zip(content,parts))
            for (lo,hi),part in pairs:
                if hi==lo:
                    if part:raise b.BuildError('0바이트 구간에 문자 배치 불가')
                else:planner.place(o+lo,hi-lo,part,f'row {n}')
            after=bytes(planner.data)
            ts=read_tokens(after,o,len(line.raw))
            activecontrols=[t for t in ts if t[0] in b.STRUCTURAL_LEADS]
            assert activecontrols==[t for _,t in controls]
            # Decode via exact forward-code inverse; new text may use old aliases
            # only in unchanged controls, never as generated Korean bytes.
            reverse={v:k for k,v in ed.table.items()}
            visible=''.join(reverse[t] for t in ts if t[0] not in b.STRUCTURAL_LEADS)
            assert compact(visible)==compact(target),(n,visible,target)
            rows,x,visible_rows=1,0,1
            for t in ts:
                if t[0]==0xE6:rows+=1;x=0
                elif t[0]==0xE5: x=0
                elif t[0] in (0xE4,):continue
                else:
                    w=56 if t[0]==0xE8 else 24 if t[0]==0xE7 else b.advance(t)
                    if x+w>=228:rows+=1;x=0
                    x+=w
                    if t!=e.SPACE_CODE:visible_rows=max(visible_rows,rows)
            if not line.is_choice and visible_rows>max(4,line.rows):raise b.BuildError(f'줄 수 초과: {visible_rows}')
            assert len(after)==len(before)
            rec.update(status='BUILT',writes=hunks(before,after),visible_rows=visible_rows,
                       control_sequence=[t.hex() for t in activecontrols],readback='PASS')
            current[line.file]=after
        except (b.BuildError,AssertionError,KeyError) as ex:
            rec['reason']=str(ex) or '보호/재해독 검증 실패'
        records.append(rec)
    # Recreate final output only by pristine baseline composition and exact hunks.
    replay={n:bytearray(v) for n,v in base.items()}
    for r in records:
        if r['status']!='BUILT':continue
        for w in r['writes']:
            old,new=bytes.fromhex(w['before']),bytes.fromhex(w['after']);at=w['at']
            assert replay[r['file']][at:at+len(old)]==old
            replay[r['file']][at:at+len(old)]=new
    assert all(bytes(replay[n])==current[n] for n in base)
    # Recheck all earlier placements against the FINAL file, not just against
    # the intermediate file immediately after each row was changed.
    reverse={v:k for k,v in ed.table.items()}
    for rec in records:
        if rec['status']!='BUILT':continue
        line=ed.lines[rec['row']-1]
        ts=read_tokens(current[line.file],int(line.offset,0),len(line.raw))
        assert [t.hex() for t in ts if t[0] in b.STRUCTURAL_LEADS]==rec['control_sequence']
        assert compact(''.join(reverse[t] for t in ts if t[0] not in b.STRUCTURAL_LEADS))==compact(rec['target'])
        rec['final_readback']='PASS'
    assert current['PSX.EXE']==base['PSX.EXE'] and current['COMM.IMG']==base['COMM.IMG']
    for line in ed.lines:
        if line.nontext_protected and line.file in current:
            o=int(line.offset,0);assert current[line.file][o:o+len(line.raw)]==base[line.file][o:o+len(line.raw)]
    # Existing outputs must be identical; never overwrite an unverified game.
    if '--write' not in sys.argv:pass
    elif ZIP.exists():
        with ZipFile(ZIP) as z:assert all(z.read(n)==v for n,v in current.items()),'output exists with different content'
    else:
        with ZipFile(ZIP,'w',compression=ZIP_DEFLATED,compresslevel=9) as z:
            for info in infos:z.writestr(info,current[info.filename],compress_type=ZIP_DEFLATED,compresslevel=9)
    report=dict(status='STATIC PASS / RUNTIME PENDING / TEST_ONLY',zip=str(ZIP),sha256=sha(ZIP.read_bytes()) if '--write' in sys.argv else None,
                built=sum(r['status']=='BUILT' for r in records),held=sum(r['status']=='HELD' for r in records),rows=records)
    (OUT/'build_report.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    for title,status in [('빌드적용내역','BUILT'),('미적용과이유','HELD')]:
        page=['<meta charset="utf-8"><style>body{font:16px/1.7 sans-serif;max-width:1050px;margin:30px auto}article{border:1px solid #bbb;padding:15px;margin:15px 0}</style>',f'<h1>{title}</h1>']
        for r in records:
            if r['status']==status:page.append(f"<article><h3>#{r['row']} {r['file']}</h3><p>{html.escape(r['target'])}</p><p>{html.escape(r['reason'])}</p></article>")
        (OUT/f'{title}.html').write_text('\n'.join(page),encoding='utf-8')
    print(json.dumps({k:v for k,v in report.items() if k!='rows'},ensure_ascii=False))

if __name__=='__main__':main()
