"""Read-only proposal report. Never writes canonical/editor/build inputs."""
import csv
import html
import json
from pathlib import Path

import review_editor as codec

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / '01_work/analysis/dialogue_review_20260905'


def main():
    reviews = [json.loads((OUT / f'review_{part}.json').read_text(encoding='utf-8'))
               for part in 'abc']
    editor = codec.Editor.__new__(codec.Editor)
    editor.load()
    issues = []
    for review in reviews:
        for item in review['issues']:
            item = dict(item)
            line = editor.lines[int(item['row_number']) - 1]
            assert line.file == item['file'] and int(line.offset, 0) == int(item['offset'], 0)
            item['latest_current'] = line.korean
            proposed = item.get('suggestion') or line.korean
            measure = editor.measure(line, proposed)
            plan = editor.slot_plan_for_file(line.file, {line.n: proposed})
            item['editor_estimate'] = measure
            item['file_balance_single_change'] = plan['balance']
            item['feasibility'] = ('CONSTRAINT_FAIL' if measure['missing'] or measure['over_rows'] or measure['over_slot'] or plan['balance'] < 0
                                   else 'ESTIMATE_PASS_BUILD_UNVERIFIED')
            if line.is_choice:
                item['feasibility'] = 'CHOICE_TEMPLATE_CHECK_REQUIRED'
            item['status'] = 'APPLIED_TERM_ONLY' if proposed == line.korean and item['category'] in ('approved_term', '사찰표기', 'terminology') else 'UNAPPROVED'
            if '원본' in proposed or '원문' in proposed or item['row_number'] == 2789:
                item['feasibility'] = 'SOURCE_VERIFICATION_REQUIRED'
            if item['row_number'] == 2789:
                item['root_review'] = '現抽出の負けてみたいは現行「져 보고 싶구먼」と一致。賭けてみたいの原本確認なしに期待へ変更しない。'
            issues.append(item)
    issues.sort(key=lambda x: int(x['row_number']))
    result = {'inventory_rows': len(editor.lines),
              'protected_nontext_rows': sum(x.nontext_protected for x in editor.lines),
              'reviewed_ranges': [r.get('reviewed_row_ranges', r.get('row_range')) for r in reviews],
              'limitations': ['Estimates use the existing V354-origin editor planner with Bank-B; not latest-build reinsertion verification.',
                             'Single-change estimates are NOT a cumulative slot allocation guarantee.',
                             'Restoration category does not establish historical forced-shortening cause.',
                             'No proposals applied to canonical/editor/build; approved temple term only is separate.'],
              'issues': issues}
    (OUT / 'combined_review.json').write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    esc = lambda x: html.escape(str(x))
    blocks = []
    for item in issues:
        restoration = 'restor' in item['category'].lower() or '축약' in item['category']
        tags = 'restoration' if restoration else 'review'
        m = item['editor_estimate']
        blocks.append(f'''<article class="{tags}"><h3>#{item['row_number']} · {esc(item['file'])} · {esc(item['category'])} · {esc(item['status'])}</h3>
<p><b>원문</b><br>{esc(item.get('japanese', ''))}</p><p><b>현재</b><br>{esc(item['latest_current'])}</p>
<p><b>미승인 제안</b><br>{esc(item.get('suggestion', ''))}</p><p>{esc(item.get('reason',''))}</p>
<p class="budget">{esc(item['feasibility'])} · {m['bytes']}B · {m['need_rows']}/{m['window']}줄 · 누락 글자 {esc(m['missing'])} · 이 한 건 변경 시 파일 여유 추정 {item['file_balance_single_change']}</p>
<details><summary>근거·불확실성</summary><pre>{esc(json.dumps(item,ensure_ascii=False,indent=2))}</pre></details></article>''')
    page = '''<!doctype html><meta charset="utf-8"><title>전체 대사 검수</title><style>
body{font:16px/1.6 sans-serif;max-width:1080px;margin:30px auto;background:#f4f5f7;color:#202630}article{background:white;border-left:6px solid #e2b13a;padding:16px 24px;margin:18px 0}.restoration{border-color:#348aca}p,pre{white-space:pre-wrap;overflow-wrap:anywhere}.budget{color:#6a4b10}button{padding:10px;margin:4px}h3{margin-top:0}</style>
<h1>전체 대사 검수 — 제안 전용</h1><p>2,878행 중 비대사 199행 제외, 대사 2,679행 일독. 노랑: 검토 후보 / 파랑: 축약 복원 검토. 번역을 자동 적용하지 않습니다.</p>
<p>길이·글리프·슬롯은 기존 편집기 기준의 개별 변경 추정입니다. 최신 빌드의 제어코드·선택지·동시 할당·게임 실행 검증 전에는 “안전하게 복원 가능”으로 확정하지 않습니다.</p>
<button onclick="document.querySelectorAll('article').forEach(x=>x.hidden=false)">전체</button>
<button onclick="document.querySelectorAll('article').forEach(x=>x.hidden=!x.classList.contains('restoration'))">축약 복원 후보만</button>'''
    (OUT / '전체대사_검수.html').write_text(page + '\n'.join(blocks), encoding='utf-8')
    (OUT / '축약복원_후보.html').write_text(page + '\n'.join(b for b in blocks if 'class="restoration"' in b), encoding='utf-8')
    print(json.dumps({'issues': len(issues), 'restoration': sum('restor' in x['category'].lower() or '축약' in x['category'] for x in issues)}, ensure_ascii=False))


if __name__ == '__main__':
    main()
