"""Confirmed DAT UI corrections; control tokens keep their physical boundaries."""
import re
import build_arc1_v359_review_all as prev

REPLACE={
 '키토우올':'히트 월','비단 띠':'비단 허리띠','그레이시느':'그레이시누',
 '카델':'니델','파렌시아':'팔렌시아','오르카스':'오르니스',
 '넘치는 과실':'넘치는 열매','약화의 구슬':'약화 구슬','부활의 약':'부활약',
 '생명의 나무 열매':'생명의 열매','마법의 카트':'마법 카드',
 '슬리플리스 카트':'수면 방지 카드','디르의 어금니':'딜의 이빨',
}
QUIZ={
 '라마다승려:  정답!':'라마다 승려: 정답입니다!',
 '라마다 승려:  스파이는 어디에 있었지?':'라마다 승려: 스파이는 어디에 있었습니까?',
 '라마다 승려:  세이브 데이터의 문양은 무엇인가?':'라마다 승려: 세이브 데이터의 문양은 무엇입니까?',
 '라마다 승려:  스메리아 다운타운에 있는 술 취한 사람의 이름은?':'라마다 승려: 스메리아 다운타운의 술 취한 사람은 누구입니까?',
 '라마다승려:  아크더래드 속편은?':'라마다 승려: 아크더래드의 속편은 무엇입니까?',
 '라마다승려:  정답!정말이냐?':'라마다 승려: 정답입니다! 정말이지요?',
 '라마다 승려:  아크더래드 제작진은?':'라마다 승려: 아크더래드 제작진은 누구입니까?',
 '라마다 승려:  수도의 군 본부에는 사실 지하 50층 던전이...':'라마다 승려: 수도의 군 본부에는 사실 지하 50층 던전이 있습니다...',
 '라마다 승려:  유적 던전의 최하층에 있는 것은?':'라마다 승려: 유적 던전의 최하층에는 무엇이 있습니까?',
 '라마다 승려:  라마다사의 문이 열렸을 때 안에 보이는 사람은 몇 명인가?':'라마다 승려: 라마다사의 문이 열렸을 때 안에 보이는 사람은 몇 명입니까?',
 '라마다 승려:  스톤서클에서 촌가라가 찾은 아이템은?':'라마다 승려: 스톤서클에서 촌가라가 찾은 아이템은 무엇입니까?',
 '라마다 승려:  초코의 머리빛은 무엇인가?':'라마다 승려: 초코의 머리 색은 무엇입니까?',
 '라마다승려:  정답!!':'라마다 승려: 정답입니다!',
 '라마다승려:  문제를 모두 맞힌 건 네가 처음이다. 상으로 이걸 주마.':'라마다 승려: 문제를 모두 맞힌 분은 당신이 처음입니다. 상으로 이것을 드리겠습니다.',
 '라마다 승려:  내 문제를 모두 맞힌 사람은 네가 두 번째다. 상으로 이걸 주마.':'라마다 승려: 제 문제를 모두 맞힌 분은 당신이 두 번째입니다. 상으로 이것을 드리겠습니다.',
 '이미 가지고 있지 않느냐? 놀리지 마라.':'이미 가지고 계시지 않습니까? 놀리지 마십시오.',
 '세계에는 정령의 돌 말고 모두 모으면 효과가 나타나는 돌이 또 있다고 들었다.':'세계에는 정령의 돌 말고 모두 모으면 효과가 나타나는 돌이 또 있다고 들었습니다.',
 '그 돌은 모험가들을 위험에서 구해 줄 위대한 힘이 될것이다.':'그 돌은 모험가들을 위험에서 구해 줄 위대한 힘이 될 것입니다.',
 '라마다 승려:  틀렸지만, 노력은 인정하마.':'라마다 승려: 틀렸지만 노력은 인정합니다.',
 '라마다 승려:  그러니 이것을 주마.':'라마다 승려: 그러니 이것을 드리겠습니다.',
}
MARKER=re.compile(r'\||<CTRL:([0-9A-F]{4})>')
def parts(text):
    spans=[];controls=[];start=0
    for m in MARKER.finditer(text):
        spans.append(text[start:m.start()]);controls.append(bytes.fromhex(m[1]) if m[1] else b'\xe6\x01');start=m.end()
    spans.append(text[start:]);return spans,controls

def target(row,c):
    old=row['current_korean'];s=old
    if old.strip() in QUIZ:return QUIZ[old.strip()]
    for a,b in REPLACE.items():s=s.replace(a,b)
    if row['id']=='31/S3024.DAT:47F68':s='공격:'+s[s.index('|'):]
    if row['id']=='31/S3024.DAT:47FD2':s='방어:'+s[s.index('|'):];s=s.replace('갑옷','술 취한 사람')
    if row['id']=='31/S3024.DAT:48052':s='어떻게 할까?'+s[s.index('|'):];s=s.replace('강공격','최강 공격')
    if old.startswith(('맞나?','맞습니까?')):
        raw=bytes.fromhex(c['original_hex']);assert raw[0]==0xe2 and 1<=raw[1]<=8
        name=['아크','쿠쿠루','토슈','포코','고겐','이가','켈베크','촌가라'][raw[1]-1]
        s=name+' 님 맞습니까?'+s[s.index('|'):]
    if old.startswith('처음부터?'):s='참가 신청을 다시 할까요?'+s[s.index('|'):]
    if row['id']=='21/S2045.DAT:47F94':
        s='초핀: 아이템, 장신구, 특수 능력을 커서로 선택하고 L이나 R 버튼을 누르면 효과를 볼 수 있습니다.'
    assert s!=old,('No correction',row['id'],old)
    return s

def apply(old,new,pristine,table,audit):
    catalog={r['id']:r for r in audit.rows(audit.AN/'dat_ui_candidates.csv')}
    defects=[r for r in audit.rows(audit.AN/'dat_ui_review.csv') if r['status']=='CONFIRMED_DEFECT']
    assert len(defects)==99
    planners={};records=[];held=[]
    for row in defects:
        if row['current_korean'].strip() in QUIZ:
            held.append(dict(id=row['id'],reason='Quiz speech-style rewrite exceeds available owned storage; preserve current text in urgent hotfix.'))
            continue
        c=catalog[row['id']];name=c['file'];at=int(c['offset']);end=int(c['end']);before=new[name]
        if name not in planners:planners[name]=prev.Planner(name,before,pristine[name],table)
        plan=planners[name];data=plan.before
        expanded=b''.join(prev.read_tokens(data,at,end-at));assert expanded==bytes.fromhex(c['current_expanded_hex'])
        oldparts,oldctrl=parts(row['current_korean']);wanted=target(row,c);texts,ctrl=parts(wanted)
        assert oldctrl==ctrl and len(texts)==len(oldparts)
        # E2 slots in this audited set contain prose only. Their completion byte
        # supplies the original span width; active E5/E6 coordinates never move.
        p=start=at;spans=[];actual=[]
        while p<end:
            width=1 if data[p]<0xdd else 2;t=data[p:p+width]
            if t[0]==0xe2:
                ref=prev.b.slot_of_disk(t[1]);assert ref
                loc=prev.slot_pos(ref);payload=data[loc:loc+127].split(b'\0')[0]
                assert not prev.b.structure(payload)[1]
                p+=2+data[loc+127];continue
            if t[0] in prev.b.STRUCTURAL_LEADS:
                spans.append((start,p-start));actual.append(t);start=p+width
            p+=width
        spans.append((start,end-start));assert actual==ctrl and len(spans)==len(texts),(row['id'],actual,ctrl)
        expected=[]
        for i,((pos,room),a,b) in enumerate(zip(spans,oldparts,texts)):
            expected.extend(prev.read_tokens(data,pos,room) if a==b else prev.b.tokens(prev.b.encoded(b.strip(),table)))
            if i<len(ctrl):expected.append(ctrl[i])
            if a==b:continue
            assert room>0,(row['id'],pos,b)
            plan.place(pos,room,b.strip(),row['id'])
        records.append(dict(id=row['id'],file=name,offset=at,length=end-at,before=row['current_korean'],target=wanted,expected_hex=b''.join(expected).hex()))
    for name,plan in planners.items():new[name]=bytes(plan.data)
    for rec in records:
        got=b''.join(prev.read_tokens(new[rec['file']],rec['offset'],rec['length']))
        expected=prev.b.tokens(bytes.fromhex(rec['expected_hex']))
        # Padding is rendering whitespace, not content; all other tokens exact.
        assert [t for t in prev.b.tokens(got) if t!=b'\xa1']==[t for t in expected if t!=b'\xa1'],rec['id']
    return dict(applied=records,held=held)
