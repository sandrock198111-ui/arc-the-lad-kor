"""Qualify review proposals against current bytes; emit guarded reinsertion plan.

Does not modify canonical CSV or game archives. A caller applies the generated
canonical patch separately. Current-byte simulation is NOT a release build.
"""
import collections
import copy
import csv
import hashlib
import html
import json
import shutil
from pathlib import Path
from zipfile import ZipFile

import review_editor as ecode
import build_arc1_v357_user_reviewed_dialogue_bankb as b

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / '01_work/analysis/dialogue_review_20260905/application'
SOURCE = ROOT / '05_docs/script_translated_full.csv'
BASE = ROOT / '03_output/arc1_v359_ui_bundle_TEST_ONLY.zip'
PIN = '7536D17369B8591DFC8D84D78A5C783A4268099006D8203EB274EE82C88FD4F2'


def digest(raw):
    return hashlib.sha256(raw).hexdigest().upper()


def live_structure(blob, offset, room):
    """Skip dead call-site bytes using the existing E2 return metadata."""
    pos, start = 0, 0
    spans, controls = [], []
    while pos < room:
        lead = blob[offset+pos]
        size = 1 if lead < 0xDD else 2
        if pos+size > room:
            raise b.BuildError('현행 토큰 경계 초과')
        token = blob[offset+pos:offset+pos+size]
        if lead == 0xE2:
            ref=b.slot_of_disk(token[1])
            if ref is None:raise b.BuildError('미지원 E2 참조')
            bank,slot=ref
            loc=(b.SLOT_BASE if bank=='A' else b.BANK_B_OFFSET)+128*slot
            skip=blob[loc+127]
            payload=blob[loc:loc+127].split(b'\0')[0]
            if b.structure(payload)[1]:
                raise b.BuildError('E2 슬롯 내부 제어코드: 보호 템플릿 검증 필요')
            size=2+skip
            if pos+size>room:raise b.BuildError('E2 복귀 위치가 보호 영역을 넘음')
        elif lead in b.STRUCTURAL_LEADS:
            spans.append((start,pos)); controls.append((pos,token));start=pos+size
        pos+=size
    spans.append((start,room))
    return spans,controls


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    snapshot = OUT / 'canonical_before.csv'
    if not snapshot.exists():
        shutil.copy2(SOURCE, snapshot)
    assert SOURCE.read_bytes() == snapshot.read_bytes(), 'canonical changed; do not silently rebase'
    assert digest(BASE.read_bytes()) == PIN
    ed = ecode.Editor.__new__(ecode.Editor)
    ed.load()
    with ZipFile(BASE) as z:
        original = {n: z.read(n) for n in z.namelist()}
    current = dict(original)
    review = json.loads((OUT.parent / 'combined_review.json').read_text(encoding='utf-8'))
    result = []
    for issue in review['issues']:
        n = issue['row_number']
        line = ed.lines[n - 1]
        target = issue['suggestion']
        rec = dict(row=n, file=line.file, offset=line.offset, before=line.korean,
                   proposed=target, japanese=line.japanese, reasons=[], writes=[])
        if n == 1101:
            target = '몬스터가 성의 병사로까지 위장해 있다니...'
            rec['proposed'] = target
        if target == line.korean:
            rec['status'] = 'ALREADY_APPLIED'
            result.append(rec)
            continue
        if issue.get('context_uncertain') or issue.get('feasibility') == 'SOURCE_VERIFICATION_REQUIRED':
            rec['reasons'].append('원문 추출/문맥/명칭 해석이 미확정: ' + issue.get('reason', ''))
        if line.korean != issue['latest_current']:
            rec['reasons'].append('검수 후 사용자 입력 변경: 자동 덮어쓰기 금지')
        try:
            payload = b.encoded(target, ed.table)
        except b.BuildError as ex:
            rec['reasons'].append(str(ex))
            payload = b''
        if payload and not line.is_choice and b.wrapped_rows(payload) > max(4, line.rows):
            rec['reasons'].append('허용 줄 수 초과')
        if any(t[0] in (0xE4, 0xE7, 0xE8) for _, t in b.structure(line.raw)[1]):
            rec['reasons'].append('연출/버튼/변수 제어코드: 수정문에 맞춘 보호 템플릿 재검증 필요')
        if rec['reasons']:
            rec['status'] = 'HELD'
            result.append(rec)
            continue
        before = current[line.file]
        offset = int(line.offset, 0)
        body = before[offset:offset + len(line.raw)]
        try:
            spans, controls = live_structure(before,offset,len(line.raw))
        except b.BuildError as ex:
            rec['status']='HELD';rec['reasons'].append(str(ex));result.append(rec);continue
        if any(t[0] not in (0xE5, 0xE6) for _, t in controls):
            rec['reasons'].append('현행 본문 특수 제어코드 보존 검증 필요')
        content = [(lo, hi) for lo, hi in spans if hi > lo]
        planner = b.FilePlanner(line.file, before, ed.originals[line.file], [], ed.table)
        try:
            if rec['reasons']:
                raise b.BuildError(rec['reasons'].pop())
            if line.is_choice:
                parts = [x.strip() for x in target.split('|') if x.strip()]
                if len(parts) != len(content):
                    raise b.BuildError('선택지 항목/현재 문자열 영역 대응 검증 필요')
                if any(b.wrapped_rows(b.encoded(x, ed.table)) > 1 for x in parts):
                    raise b.BuildError('선택지 한 줄 폭 초과')
            else:
                parts = b.split_words(target.replace('|',' '), len(content), [hi-lo for lo, hi in content], ed.table)
                if sum(b.wrapped_rows(b.encoded(x, ed.table)) for x in parts) > max(4, line.rows):
                    raise b.BuildError('현재 강제 줄바꿈 보존 시 허용 줄 수 초과')
            for (lo, hi), part in zip(content, parts):
                at, room = offset + lo, hi - lo
                data = b.encoded(part, ed.table)
                live = before[at:at+room]
                # Reuse only an exclusively referenced existing slot with the
                # exact same return skip. Other cases use the established planner.
                ref = b.slot_of_disk(live[1]) if len(live) >= 2 and live[0] == 0xE2 else None
                if len(data) > room and ref and before.count(live[:2]) == 1:
                    bank, slot = ref
                    slot_at = (b.SLOT_BASE if bank == 'A' else b.BANK_B_OFFSET) + slot * 128
                    if before[slot_at+127] != room-2 or len(data) > 126:
                        raise b.BuildError('기존 슬롯 복귀 길이/126바이트 한도 불일치')
                    if any(t[0] in b.STRUCTURAL_LEADS for t in ecode.tokens(before[slot_at:slot_at+126].split(b'\0')[0]) if len(t)==2):
                        raise b.BuildError('기존 슬롯 내부 제어코드 보존 검증 필요')
                    planner.data[slot_at:slot_at+127] = (data+b'\0').ljust(127,b'\0')
                    rec['writes'].append(dict(at=slot_at, before=before[slot_at:slot_at+127].hex(), after=bytes(planner.data[slot_at:slot_at+127]).hex()))
                else:
                    planner.place(at, room, part, f'row {n}')
            after = bytes(planner.data)
            assert len(after) == len(before)
            for pos, token in controls:
                assert after[offset+pos:offset+pos+len(token)] == token
            # Exact byte hunks, covering allocations as well as original spans.
            rec['writes'] = []
            start = None
            for k in range(len(before)+1):
                changed = k < len(before) and before[k] != after[k]
                if changed and start is None:
                    start = k
                if not changed and start is not None:
                    rec['writes'].append(dict(at=start,before=before[start:k].hex(),after=after[start:k].hex()))
                    start = None
            rec['new_allocations'] = [dict(bank=a.bank,slot=a.slot) for a in planner.allocations]
            rec['status'] = 'QUALIFIED_CANONICAL_ONLY'
            current[line.file] = after
        except (b.BuildError, AssertionError) as ex:
            rec['writes'] = []
            rec['status'] = 'HELD'
            rec['reasons'].append(str(ex) or '보호 바이트 검증 실패')
        result.append(rec)
    # Replay every exact expected-before hunk independently of placement logic.
    replay = {k:bytearray(v) for k,v in original.items()}
    for rec in result:
        if rec['status'] != 'QUALIFIED_CANONICAL_ONLY':
            continue
        for w in rec['writes']:
            old,new=bytes.fromhex(w['before']),bytes.fromhex(w['after'])
            assert len(old)==len(new)
            assert replay[rec['file']][w['at']:w['at']+len(old)] == old
            replay[rec['file']][w['at']:w['at']+len(old)] = new
    assert all(bytes(replay[k])==current[k] for k in current)
    assert current['PSX.EXE']==original['PSX.EXE'] and current['COMM.IMG']==original['COMM.IMG']
    reverse={v:k for k,v in ed.table.items()}
    def readback(blob,start,room):
        text=[];pos=0
        while pos<room:
            lead=blob[start+pos]
            size=1 if lead<0xDD else 2
            token=blob[start+pos:start+pos+size]
            if lead==0xE2:
                bank,slot=b.slot_of_disk(token[1])
                at=(b.SLOT_BASE if bank=='A' else b.BANK_B_OFFSET)+128*slot
                data=blob[at:at+127].split(b'\0')[0]
                text.append(''.join(reverse[t] for t in ecode.tokens(data)))
                size=2+blob[at+127]
            elif lead in b.STRUCTURAL_LEADS:
                text.append(' ')
            else:text.append(reverse[token])
            pos+=size
        assert pos==room
        return ''.join(text)
    norm=lambda s:''.join(s.replace('|',' ').split())
    for rec in result:
        if rec['status']=='QUALIFIED_CANONICAL_ONLY':
            line=ed.lines[rec['row']-1]
            actual=readback(current[line.file],int(line.offset,0),len(line.raw))
            assert norm(actual)==norm(rec['proposed']),(rec['row'],actual,rec['proposed'])
            rec['readback']='PASS'
    report = dict(base_sha256=PIN,canonical_before_sha256=digest(snapshot.read_bytes()),
                  status='CANONICAL_APPLICATION_PLAN / NO GAME BUILD / RUNTIME PENDING',
                  counts=dict(collections.Counter(x['status'] for x in result)),rows=result)
    (OUT/'application_plan.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    header='<meta charset="utf-8"><style>body{font:16px/1.6 sans-serif;max-width:1050px;margin:30px auto}article{border:1px solid #bbb;padding:16px;margin:16px 0}p{white-space:pre-wrap}</style>'
    for name,status in [('적용내역','QUALIFIED_CANONICAL_ONLY'),('보류목록','HELD')]:
        chunks=[header,f'<h1>{name}</h1><p>정식 번역표 적용 대상 / 게임 빌드·실행 검증은 별도. 보류는 불가능 확정이 아닌 추가 검증 필요를 포함합니다.</p>']
        for r in result:
            if r['status']!=status:continue
            esc=html.escape
            chunks.append(f"<article><h3>#{r['row']} {esc(r['file'])}</h3><p>현재: {esc(r['before'])}</p><p>제안: {esc(r['proposed'])}</p><p>이유: {esc(' / '.join(r['reasons']) or '현행 영역·누적 배치·보호 바이트 정적 검사 통과')}</p></article>")
        (OUT/f'{name}.html').write_text('\n'.join(chunks),encoding='utf-8')
    print(json.dumps(report['counts'],ensure_ascii=False))


if __name__=='__main__':main()
