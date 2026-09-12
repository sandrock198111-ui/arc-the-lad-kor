"""Independent original-EXE alias census against the full V375 UI inventory."""
from audit_arc1_v375_full_inventory import *

def main():
    catalog=rows(AN/'ui_inventory.csv');known={int(r['pointer_offset'],0) for r in catalog}
    with ZipFile(ORIGINAL) as z:orig=z.read('PSX.EXE')
    with ZipFile(BASE) as z:exe=z.read('PSX.EXE')
    decode=make_decoder(exe);spans={}
    for r in catalog:
        if r['storage_class']=='HUD_BINARY':continue
        start=int(r['original_pointer'],0)-BIAS;raw=bytes.fromhex(r['original_hex'])
        p=0
        for tok in codec.tokens(raw):
            spans.setdefault(start+p,[]).append((r['id'],p));p+=len(tok)
        if not raw:spans.setdefault(start,[]).append((r['id'],0))
    found=[]
    for ptr in range(0,len(orig)-3,4):
        value=struct.unpack_from('<I',orig,ptr)[0];offset=value-BIAS
        if offset not in spans:continue
        current=struct.unpack_from('<I',exe,ptr)[0]
        try:ko,unknown=decode(storage.string_at(exe,current));error=''
        except Exception as e:ko='';unknown='';error=str(e)
        found.append(dict(pointer=f'0x{ptr:X}',original_target=f'0x{offset:X}',known=ptr in known,
            original_links=json.dumps(spans[offset],ensure_ascii=False),current_pointer=f'0x{current:X}',
            current_text=ko,unknown=unknown,error=error,status='CATALOGED' if ptr in known else 'NEEDS_CONSUMER_REVIEW'))
    write_csv(AN/'all_original_ui_references.csv',found)
    extra=[r for r in found if not r['known']];write_csv(AN/'extra_ui_references.csv',extra)
    result=dict(original_aligned_words=(len(orig)-3+3)//4,ui_boundary_refs=len(found),cataloged=sum(r['known'] for r in found),extra_candidates=len(extra),scope='Every aligned original EXE word targeting a known UI token boundary; inline literals and previously unknown strings require separate audit')
    (AN/'reference_meta.json').write_text(json.dumps(result,indent=2),encoding='utf-8');print(result)
    for r in extra: print(r)

if __name__=='__main__':main()
