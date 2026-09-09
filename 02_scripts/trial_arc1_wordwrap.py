"""V371 offline word-boundary layout trial. Never writes game/build inputs.

Runs the existing MIPS text consumer on isolated RAM copies, with expanded
plain text at a synthetic address. This proves layout, NOT reinsertion or
the window type / event reachability of an arbitrary corpus entry.
"""
import csv
import hashlib
import html
import json
import re
import struct
import sys
from collections import Counter
from pathlib import Path
from zipfile import ZipFile

from audit_arc1_9118_runtime import load
from audit_arc1_v363_speaker_cursor import expand
from analyze_arc1_v320c_savestates import object_at
from v354_dialogue_codec import load_v354, tokens
from extract_story_corpus import token_end

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / '01_work/analysis/v371_wordwrap_trial'
BASE = ROOT / '03_output/arc1_v371_speaker_fixes_TEST_ONLY.zip'
PIN = '2308DAAA0F4E8AFD4B16E03DABD4402E596E1BB6CA0D404F6A3352DF4BCE6021'
SAV = Path('C:/Users/Administrator/.paseo/uploads/upload_038b258b-3f0a-4668-a502-7c25c1144d43/HASH-477B29575D051C04_2.sav')
SAV_PIN = 'eda104706fcb415abe64d8915a63b99068df0d22be5c9c17e9f93f11b0b9f438'
BR, SPACE = b'\xe6\x01', b'\xa1'
# Non-prose / severe decoding failures identified during the prior independent
# V371 register review. Keep these OUT of automatic layout proposals.
NONPROSE_RANGES = [(272,277),(300,305),(320,325),(327,332),(354,359),
    (438,443),(498,503),(646,647),(700,705),(707,712),(727,732),(749,754),
    (1783,1788),(1800,1805),(1302,1307),(1319,1324),(1339,1344),
    (1515,1520),(1523,1528),(1537,1542),(1558,1563),(2156,2161),
    (2168,2173),(2186,2191),(2314,2316),(2362,2384),(2601,2604),
    (2616,2619),(2635,2642)]
NONPROSE = {i for a,b in NONPROSE_RANGES for i in range(a,b+1)} | {
    2218,2250,2361,2385,2398,2399,2412,2413,2763,2794,2799}
sys.path.insert(0, str(ROOT / '01_work/tools/cursor_verify'))
import unicorn as uc
from unicorn import mips_const as m


class Renderer:
    def __init__(self, ram, dec):
        self.ram, self.dec, self.cache = ram, dec, {}

    def render(self, ts, width):
        raw = b''.join(ts)
        key = (raw, width)
        if key in self.cache:
            return self.cache[key]
        assert len(raw) < 1024
        assert all(t == BR or t in self.dec for t in ts)
        vm = uc.Uc(uc.UC_ARCH_MIPS, uc.UC_MODE_MIPS32 | uc.UC_MODE_LITTLE_ENDIAN)
        vm.mem_map(0, 0x200000)
        vm.mem_write(0, self.ram)
        # Deliberate analysis-only injection, never a proposed game address.
        vm.mem_write(0x70000, raw + b'\0')
        vm.mem_write(0x40010, struct.pack('<II', 0, 0x801f9d44))
        def run(pc, **regs):
            vm.reg_write(m.UC_MIPS_REG_SP, 0x80040000)
            vm.reg_write(m.UC_MIPS_REG_RA, 0x80060000)
            for k, v in regs.items():
                vm.reg_write(getattr(m, 'UC_MIPS_REG_' + k.upper()), v)
            hit = []
            def stop(machine, address, size, data):
                if address == 0x80060000:
                    hit.append(address)
                    machine.emu_stop()
            hook = vm.hook_add(uc.UC_HOOK_CODE, stop)
            try:
                vm.emu_start(pc, 0, count=400000)
            finally:
                vm.hook_del(hook)
            assert hit, 'CPU did not return'
        run(0x8016b880, a0=46, a1=32, a2=width, a3=208)
        run(0x8016b8c8, a0=0x80070000, a1=0x801f9d44)
        state, packets = object_at(bytes(vm.mem_read(0, 0x200000)), 0x1f9d44, {'physical_chars': {}})
        indices = [i for i, t in enumerate(ts) if t != BR]
        assert len(indices) == len(packets) == state['count'], 'packet mismatch / limit'
        assert int(state['source_pointer'], 16) == 0x80070000 + len(raw), 'end mismatch'
        rows, positions = {}, {}
        for i, p in zip(indices, packets):
            rows[p['y']] = rows.get(p['y'], '') + self.dec[ts[i]]
            positions[i] = (p['x'], p['y'])
        ys = sorted(rows)
        result = dict(rows=[rows[y] for y in ys], ys=ys, positions=positions,
                      row_extent=(max(ys)-32)//16+1 if ys else 0,
                      blank_row=any(b-a > 16 for a,b in zip(ys,ys[1:])),
                      count=len(packets))
        self.cache[key] = result
        return result


def splits(ts, rendered, dec):
    """Only directly adjacent alphanumeric glyphs separated by automatic wrap.

    Existing E6 remains a protected boundary: do not guess whether it means
    an inter-word space or an intentional split inside a word.
    """
    out = []
    for i in range(1, len(ts)):
        if i not in rendered['positions'] or i-1 not in rendered['positions']:
            continue
        a, b = dec[ts[i-1]], dec[ts[i]]
        if a.isalnum() and b.isalnum() and rendered['positions'][i-1][1] != rendered['positions'][i][1]:
            out.append(i)
    return out


def proposal(ts, width, renderer):
    original = tuple(ts)
    current = list(ts)
    before = renderer.render(current, width)
    hits = splits(current, before, renderer.dec)
    if not hits:
        return dict(status='no_auto_split', before=before, after=before, changes=[])
    changed = []
    for _ in range(64):
        after = renderer.render(current, width)
        remaining = splits(current, after, renderer.dec)
        if not remaining:
            status = 'layout_candidate' if after['row_extent'] <= 4 and not after['blank_row'] else 'row_limit_or_blank'
            assert len(original) == len(current)
            assert all(a == b or a == SPACE and b == BR for a,b in zip(original,current))
            return dict(status=status, before=before, after=after, changes=changed,
                        proposed_hex=b''.join(current).hex(), byte_growth=len(changed))
        split = remaining[0]
        start = split-1
        while start >= 0 and current[start] not in (SPACE, BR):
            start -= 1
        if start < 0 or current[start] != SPACE:
            return dict(status='no_safe_space_before_word', before=before, after=after, changes=changed)
        # A space already wrapped onto the next line is not useful; detect
        # such cases through the subsequent CPU output rather than guessing.
        current[start] = BR
        changed.append(start)
    raise AssertionError('proposal did not converge')


def main():
    blob = BASE.read_bytes()
    assert hashlib.sha256(blob).hexdigest().upper() == PIN
    assert hashlib.sha256(SAV.read_bytes()).hexdigest() == SAV_PIN
    with ZipFile(BASE) as z:
        files = {n:z.read(n) for n in z.namelist()}
    with ZipFile(ROOT/'00_original/arc.zip') as z:
        original = {n:z.read(n) for n in z.namelist() if n.endswith('.DAT')}
    dec = load_v354()[3]
    ram, *_ = load(SAV, files['PSX.EXE'])
    renderer = Renderer(ram, dec)
    # Positive regression on the previously reported V367 split, using the
    # same consumer but a synthetic inline source. No old game bytes edited.
    with ZipFile(ROOT/'03_output/arc1_v367_quiz_TEST_ONLY.zip') as z:
        legacy = z.read('6/S6054.DAT')
    old_ts = expand(legacy,0x4429e,38)
    positive = proposal(old_ts,228,renderer)
    assert splits(old_ts,positive['before'],dec)
    assert positive['status'] == 'layout_candidate'
    assert not splits(list(tokens(bytes.fromhex(positive['proposed_hex']))),positive['after'],dec)
    records = []
    with (ROOT/'05_docs/script_original_full.csv').open(encoding='utf-8-sig') as f:
        for number, r in enumerate(csv.DictReader(f), 1):
            at = int(r['byte offset'],16)
            raw = bytes.fromhex(r['raw bytes as hex'])
            records.append(dict(id=f'csv:{number}',file=r['source file'],offset=at,end=at+len(raw),original_raw=raw))
    catalog = json.loads((ROOT/'01_work/analysis/v368_linebreaks/audit.json').read_text(encoding='utf-8'))
    known = set()
    for e in catalog['entries']:
        at,end = int(e['offset'],16),int(e['end'],16)
        assert token_end(original['6/S6054.DAT'],at) == end
        assert original['6/S6054.DAT'][at-8:at] == bytes.fromhex('290000007f001900')
        known.add(('6/S6054.DAT',at))
        if not e['csv_present']:
            records.append(dict(id=f'quiz:{at:x}',file='6/S6054.DAT',offset=at,end=end,
                                original_raw=original['6/S6054.DAT'][at:end]))
    assert len(records) == 2941
    results = []
    for index,r in enumerate(records):
        fn,at,end = r['file'],r['offset'],r['end']
        data = files.get(fn,original.get(fn))
        raw = data[at:end]
        ts = expand(data,at,end-at)
        item = {k:v for k,v in r.items() if k != 'original_raw'}
        item['known_quiz_window'] = (fn,at) in known
        item['has_expansion'] = any(t[0]==0xe2 for t in tokens(raw))
        item['current'] = ''.join('| ' if t==BR else dec.get(t,'<'+t.hex()+'>') for t in ts)
        origts = list(tokens(r['original_raw']))
        reasons = []
        if r['id'].startswith('csv:') and int(r['id'][4:]) in NONPROSE: reasons.append('prior_review_nonprose')
        if any(t[0]==0xe5 for t in origts) or any(t[0]==0xe5 for t in ts): reasons.append('choice')
        if any(t[0]==0xe2 for t in origts): reasons.append('original_dynamic_variable')
        if any(t!=BR and t not in dec for t in ts): reasons.append('control_or_undecodable')
        if not re.search('[가-힣]',item['current']): reasons.append('no_hangul')
        if sum(t!=BR for t in ts)>64: reasons.append('packet_budget_over_64')
        if not data[end:end+1]==b'\0': reasons.append('unconfirmed_end')
        if reasons:
            item['excluded'] = reasons
        else:
            item['scenarios'] = {}
            for width in (228,180):
                try:
                    p = proposal(ts,width,renderer)
                    # Physical capacity only directly estimable for inline data.
                    # Expanded slots need a separate mapping/completion plan.
                    p['insertion'] = 'expansion_mapping_required' if item['has_expansion'] else (
                        'extra_bytes_required' if p.get('byte_growth',0) else 'unchanged')
                    if p['status']=='layout_candidate' and not item['has_expansion']:
                        proposed=list(tokens(bytes.fromhex(p['proposed_hex'])))
                        growth=p['byte_growth']
                        trailing=0
                        for t in reversed(proposed):
                            if t!=SPACE:break
                            trailing+=1
                        p['trailing_space_bytes']=trailing
                        if trailing>=growth:
                            fitted=proposed[:-growth] if growth else proposed
                            fitted_result=renderer.render(fitted,width)
                            assert not splits(fitted,fitted_result,dec)
                            assert fitted_result['row_extent']<=4 and not fitted_result['blank_row']
                            assert len(b''.join(fitted))==len(raw)
                            assert [t for t in fitted if t not in (SPACE,BR)]==[t for t in ts if t not in (SPACE,BR)]
                            p['insertion']='inline_same_length_candidate'
                            p['fitted_hex']=b''.join(fitted).hex()
                            p['fitted_rows']=fitted_result['rows']
                    item['scenarios'][str(width)] = p
                except Exception as ex:
                    item['scenarios'][str(width)] = dict(status='cpu_error',error=repr(ex))
        results.append(item)
        if index % 250 == 0:
            print('reviewed',index,'/',len(records),flush=True)
    counts = dict(records=len(results),excluded=sum('excluded' in r for r in results),
                  reasons=dict(Counter(x for r in results for x in r.get('excluded',[]))))
    for width in ('228','180'):
        counts[width] = dict(Counter(r['scenarios'][width]['status'] for r in results if 'scenarios' in r))
        counts[width+'_candidate_storage'] = dict(Counter(r['scenarios'][width]['insertion'] for r in results if r.get('scenarios',{}).get(width,{}).get('status')=='layout_candidate'))
    counts['known_quiz_228'] = dict(Counter(r['scenarios']['228']['status'] for r in results if r['known_quiz_window'] and 'scenarios' in r))
    # Regression: known current quiz lines retain their already-correct layout.
    checks = []
    for at in (0x43e3c,0x4429e):
        r = next(r for r in results if r['file']=='6/S6054.DAT' and r['offset']==at)
        assert r['scenarios']['228']['status']=='no_auto_split',r
        checks.append(r['id'])
    assert BASE.read_bytes()==blob
    report = dict(baseline_sha256=PIN,sav_sha256=SAV_PIN,counts=counts,regressions=checks,positive_regression=positive,entries=results,
                  limits='Offline expanded plain-text CPU layout scenarios; not original caller/window proof, not insertion, not GPU. Existing hard breaks preserved. Exclusions are NOT passes.')
    OUT.mkdir(parents=True,exist_ok=True)
    (OUT/'trial.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    cards=[]
    for r in results:
        for width,p in r.get('scenarios',{}).items():
            if p['status']=='no_auto_split':continue
            before='\n'.join(p.get('before',{}).get('rows',[]))
            after='\n'.join(p.get('after',{}).get('rows',[]))
            cards.append('<article><h3>'+html.escape(f"{r['id']} {r['file']} / {width}px / {p['status']}")+'</h3><p>'+html.escape(p.get('insertion',''))+'</p><div><pre>'+html.escape(before)+'</pre><pre>'+html.escape(after)+'</pre></div></article>')
    page='<!doctype html><meta charset="utf-8"><title>V371 어절 조판 시험</title><style>body{font-family:system-ui;max-width:1100px;margin:32px auto;background:#eee}article{background:white;padding:16px;margin:16px 0}article div{display:flex;gap:32px}pre{white-space:pre-wrap;flex:1;font-size:17px}h3{font-size:16px}</style><h1>V371 어절 조판 시험 — 미적용</h1><p>왼쪽 현재 / 오른쪽 후보. 실제 게임 픽셀 미리보기가 아닌 행별 문자열 비교입니다. 228/180px는 서로 다른 시험 조건이며, 모든 대사의 실제 창 폭이 확정된 것은 아닙니다. 기존 강제 개행 유지, 선택지·변수·특수 제어는 제외. 저장 공간과 최종 삽입 검증 전입니다.</p><pre>'+html.escape(json.dumps(counts,ensure_ascii=False,indent=2))+'</pre>'+''.join(cards)
    (OUT/'preview.html').write_text(page,encoding='utf-8')
    print(json.dumps(counts,ensure_ascii=False),flush=True)


if __name__ == '__main__':
    main()
