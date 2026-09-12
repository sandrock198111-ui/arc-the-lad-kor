"""Reproducible census of the reported missing argument0 family, all 162 DATs."""
import json,re
import build_arc1_v379_spirit_reports as b
import extract_story_corpus as e

def main():
    original=b.b.members(b.ORIGINAL);old=b.b.members(b.BASE);new=b.b.members(b.OUT)
    rows=b.b.audit.rows(b.ROOT/'05_docs/script_original_full.csv')
    known={(r['source file'],int(r['byte offset'],0)) for r in rows}
    expected={(fn,at) for fn,at,_ in b.EXTRA};found=[];excluded=[]
    for fn,d in old.items():
        if not fn.endswith('.DAT'):continue
        source=original[fn]
        for m in re.finditer(b'\x17\0\0\0',source[0x45000:]):
            at=0x45000+m.end();end=e.token_end(source,at)
            if not end or end<=at or (fn,at) in known or end-at>150:continue
            raw=source[at:end]
            if d[at:end]!=raw:continue
            item=dict(file=fn,offset=at,length=end-at)
            if (fn,at) in expected:
                assert new[fn][at:end]!=raw
                found.append(item)
            else:
                assert (fn=='9/S9031.DAT' and at==0x499cc and raw==b'\xff\xff') or (
                    fn in [f'D/SD01{i}.DAT' for i in range(1,6)] and at==0x49a2d and raw==b'\x01'),(item,raw.hex())
                assert new[fn][at:end]==raw
                excluded.append(item)
    assert {(r['file'],r['offset']) for r in found}==expected and len(excluded)==6
    result=dict(dat_files=sum(fn.endswith('.DAT') for fn in old),fixed=found,nontext_candidates_preserved=excluded,
        scope='Argument0 family only; not proof that every other opcode/text family has no omission.')
    (b.AN/'short_dialogue_census.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
    print(result['dat_files'],len(found),len(excluded))
if __name__=='__main__':main()
