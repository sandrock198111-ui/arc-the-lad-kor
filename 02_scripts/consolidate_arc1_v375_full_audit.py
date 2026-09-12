"""Consolidate row-level evidence; unknowns never count as passes."""
import json, sys
from collections import Counter
sys.dont_write_bytecode=True
from audit_arc1_v375_full_inventory import AN, rows, write_csv

def main():
    inventory={r['id']:r for r in rows(AN/'ui_inventory.csv')}
    reviews={}
    for filename in ('equipment_review.csv','skills_characters_review.csv','system_location_review.csv'):
        for row in rows(AN/filename):
            assert row['id'] not in reviews,row['id']
            reviews[row['id']]={**row,'review_source':filename}
    assert set(reviews)==set(inventory) and len(reviews)==673
    for row in rows(AN/'extra_system_review.csv'):
        reviews[row['id']]={**row,'review_source':'extra_system_review.csv'}
    flame=json.loads((AN/'flame_glyph.json').read_text(encoding='utf-8'))
    assert flame['status']=='CONFIRMED_DEFECT'
    reviews[flame['id']].update(status=flame['status'],severity=flame['severity'],
        finding=flame['finding'],evidence='flame_glyph.json: real 8016B248 CPU renderer; CLUT7FC0 / font cell196 / zero ink; three width scenarios.',
        next_action='Restore a valid flame label; verify the actual monster-menu scene.',review_source='flame_glyph.json (supersedes extra_system_review.csv)')
    for row in rows(AN/'ascii_format_census.csv'):
        if row['classification']!='UI_NUMERIC_FORMAT' or row['already_in_711_ui_inventory']=='True':continue
        assert row['original_current_equal']=='True'
        rid=f"ascii_format:{int(row['offset'],0):05X}"
        assert rid not in reviews
        reviews[rid]=dict(id=rid,status='PASS_SEMANTIC',severity='NONE',
            finding='Additional ASCII numeric format '+repr(row['ascii'])+' is byte-exact in original/current.',
            evidence='ascii_format_census.csv; direct_print_calls.csv; numeric formatter wrappers/native ASCII consumers.',
            next_action='No text correction needed; actual numeric rendering and bounds are separate.',review_source='ascii_format_census.csv')
    combined=[]
    for key,review in reviews.items():
        source=inventory.get(key,{})
        combined.append(dict(id=key,status=review['status'],severity=review['severity'].upper(),
            original_japanese=source.get('japanese','See evidence / original source pixels'),
            current_korean=source.get('current_korean','See evidence'),
            pointer_offset=source.get('pointer_offset',''),finding=review['finding'],
            evidence=review['evidence'],next_action=review['next_action'],review_source=review['review_source']))
    assert len(combined)==723
    assert not any(r['status'] in ('PENDING','UNREVIEWED','') for r in combined)
    write_csv(AN/'ui_review_all.csv',combined)
    dat=rows(AN/'dat_ui_review.csv')
    assert len(dat)==868 and len({r['id'] for r in dat})==868
    assert not any(r['status'] in ('PENDING','UNREVIEWED','') for r in dat)
    findings=[]
    for category,data in [('EXE_UI',combined),('DAT_UI',dat)]:
        for r in data:
            if r['status'] in ('CONFIRMED_DEFECT','NEEDS_SOURCE_CONFIRMATION'):
                findings.append(dict(category=category,id=r['id'],status=r['status'],
                    severity=r['severity'].upper(),finding=r['finding'],evidence=r['evidence']))
    write_csv(AN/'findings_and_unknowns.csv',findings)
    event=json.loads((AN/'event_integrity.json').read_text(encoding='utf-8'))
    meta=dict(baseline_zip_sha256=event['zip_sha256'],
        exe_ui_rows=len(combined),exe_ui_status=dict(Counter(r['status'] for r in combined)),
        dat_ui_bodies=len(dat),dat_ui_status=dict(Counter(r['status'] for r in dat)),
        source_script_rows=event['source_rows'],confirmed_opcode_changes=event['confirmed_opcode_changes'],
        affected_dat_files=event['files'],also_changed_preceding_operands=event['also_changed_preceding_operand'],
        count_unit='Affected rows/bodies. Repeated defects are NOT distinct root causes.',
        complete_game_population_proven=False,all_scene_runtime_verified=False,game_bytes_modified=False)
    (AN/'summary.json').write_text(json.dumps(meta,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps(meta,ensure_ascii=False,indent=2))

if __name__=='__main__':main()
