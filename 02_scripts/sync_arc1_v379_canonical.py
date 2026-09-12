"""Synchronize only V379 Korean cells; preserve every source/metadata cell."""
import csv,io,json,re
import build_arc1_v379_spirit_reports as b
# Exact V378 corpus pin, separate from immutable historical build inputs.
PIN='B1DE855B19AB89A3A895D0718EF3474CA68B055E91820CE49F2159ABB946A203'

def main():
    path=b.ROOT/'05_docs/script_translated_full.csv';raw=path.read_bytes()
    report=json.loads((b.AN/'build_report.json').read_text(encoding='utf-8'))
    record=b.AN/'canonical_update.json'
    if record.exists():
        assert b.digest(raw)==json.loads(record.read_text(encoding='utf-8'))['after_sha256'];return
    assert b.digest(raw)==PIN
    backup=b.ROOT/'99_backup/v379_script_translated_full.csv';backup.parent.mkdir(exist_ok=True)
    if backup.exists():assert backup.read_bytes()==raw
    else:backup.write_bytes(raw)
    reader=csv.DictReader(io.StringIO(raw.decode('utf-8-sig'),newline=''));fields=reader.fieldnames
    old=list(reader);new=[dict(r) for r in old];changes=[]
    for r in report['applied']:
        n=r['row']
        if n is None:continue
        target=' '.join(re.sub(r'<CTRL:[0-9A-F]{4}>|\|',' ',r['target']).split())
        # Pauses between Korean particles/punctuation must not create spaces.
        target=target.replace('있다 .','있다.')
        if old[n-1]['korean']!=target:
            changes.append(dict(row=n,before=old[n-1]['korean'],after=target));new[n-1]['korean']=target
    for i,(a,z) in enumerate(zip(old,new),1):
        assert all(a[k]==z[k] for k in fields if k!='korean')
        if a!=z:assert i in {r['row'] for r in changes}
    out=io.StringIO(newline='');writer=csv.DictWriter(out,fieldnames=fields);writer.writeheader();writer.writerows(new)
    data=out.getvalue().encode('utf-8-sig' if raw.startswith(b'\xef\xbb\xbf') else 'utf-8')
    path.write_bytes(data)
    result=dict(before_sha256=PIN,after_sha256=b.digest(data),changed_korean_cells=changes,other_cells_unchanged=True,backup=str(backup))
    record.write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
    supplemental=[r for r in report['applied'] if r['row'] is None]
    (b.ROOT/'05_docs/script_supplement_v379.json').write_text(json.dumps(supplemental,ensure_ascii=False,indent=2),encoding='utf-8')
    print(len(changes),result['after_sha256'])
if __name__=='__main__':main()
