"""Whole-EXE ASCII format candidates and direct print callsites, read-only."""
import re,struct,json,sys
from zipfile import ZipFile
from collections import Counter
sys.dont_write_bytecode=True
from audit_arc1_v375_full_inventory import AN, ORIGINAL, BASE, BIAS, rows, write_csv

def main():
    with ZipFile(ORIGINAL) as z:original=z.read('PSX.EXE')
    with ZipFile(BASE) as z:current=z.read('PSX.EXE')
    known={int(r['id'].split(':')[1],16) for r in rows(AN/'extra_system_review.csv') if r['id'].startswith('ascii_format:')}
    formats=[]
    for match in re.finditer(rb'[\x09\x0A\x0D\x20-\x7e]{2,}\x00',original):
        raw=match.group()[:-1];p=match.start()
        if not re.search(rb'%(?:[-+0 #]*\d*(?:\.\d+)?)?[diouxXscfeEgG%]',raw):continue
        region='SDK_OR_CONSOLE_CANDIDATE'
        if p in (0xDB4,0xE04) or 0x8D6A8<=p<=0x8DB10:region='UI_NUMERIC_FORMAT'
        if p in (0x31AE,0x34F6,0x27CDA):region='CODE_BYTE_FALSE_POSITIVE'
        formats.append(dict(offset=hex(p),ascii=raw.decode('ascii'),original_current_equal=raw==current[p:p+len(raw)],
            classification=region,already_in_711_ui_inventory=p in known,
            status='BYTES_PRESERVED_NOT_RUNTIME_FORMATTING_APPROVAL'))
    assert all(r['original_current_equal'] for r in formats)
    targets={0x8016B248:'native_xy',0x8016B288:'native_append',0x8016B2E4:'ascii_xy',
             0x8016B324:'ascii_append',0x8016C760:'description',0x801759B8:'sprintf',
             0x8015642C:'numeric_ui_wrapper',0x80165B08:'bounded_number_wrapper',0x80165BC8:'bounded_pair_wrapper'}
    calls=[]
    for p in range(0x800,0x78000,4):
        word=struct.unpack_from('<I',original,p)[0]
        if word>>26!=3:continue
        target=0x80000000|((word&0x3ffffff)<<2)
        if target in targets:
            calls.append(dict(callsite=hex(p+BIAS),target=hex(target),kind=targets[target],
                              same_call_word=original[p:p+4]==current[p:p+4],
                              scope='Direct JAL occurrence; indirect calls and argument dataflow require separate analysis'))
    write_csv(AN/'ascii_format_census.csv',formats)
    write_csv(AN/'direct_print_calls.csv',calls)
    summary=dict(format_candidates=len(formats),format_regions=dict(Counter(r['classification'] for r in formats)),
        additional_ui_numeric_formats=sum(r['classification']=='UI_NUMERIC_FORMAT' and not r['already_in_711_ui_inventory'] for r in formats),
        all_candidate_bytes_preserved=True,direct_calls=len(calls),call_kinds=dict(Counter(r['kind'] for r in calls)),
        limits='ASCII regex is a candidate census, not whole-game text completeness. Console candidates and code false positives not merged into semantic UI711. Direct call-word changes can be intentional hooks, not automatically defects.')
    (AN/'format_census.json').write_text(json.dumps(summary,indent=2),encoding='utf-8')
    print(json.dumps(summary,indent=2))

if __name__=='__main__':main()
