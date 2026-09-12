"""Record the three changed Korean cells; existing choice manuscript is correct."""
import csv,io,json
import build_arc1_v382_reports as b
PIN='81FB640865A0CCCC4131449DB6AD3E6F43660F15E699DBD0756E658F4F7D4590'

def main():
    path=b.ROOT/'05_docs/script_translated_full.csv';raw=path.read_bytes();record=b.AN/'canonical_update.json'
    if record.exists():
        assert b.digest(raw)==json.loads(record.read_text(encoding='utf-8'))['after_sha256'];return
    assert b.digest(raw)==PIN
    backup=b.ROOT/'99_backup/v382_script_translated_full.csv'
    if backup.exists():assert backup.read_bytes()==raw
    else:backup.write_bytes(raw)
    reader=csv.DictReader(io.StringIO(raw.decode('utf-8-sig'),newline=''));fields=reader.fieldnames;old=list(reader);new=[dict(r) for r in old]
    targets={2395:b.TEXT[2395],2807:''.join(b.PAUSES[2807]),2809:''.join(b.PAUSES[2809])}
    assert old[2395]['korean']=='괜찮을까?|물론|그만'
    changes=[]
    for n,target in targets.items():
        assert old[n-1]['korean']!=target
        changes.append(dict(row=n,before=old[n-1]['korean'],after=target));new[n-1]['korean']=target
    for n,(a,z) in enumerate(zip(old,new),1):
        assert all(a[k]==z[k] for k in fields if k!='korean')
        if n not in targets:assert a==z
    out=io.StringIO(newline='');w=csv.DictWriter(out,fieldnames=fields);w.writeheader();w.writerows(new)
    data=out.getvalue().encode('utf-8-sig' if raw.startswith(b'\xef\xbb\xbf') else 'utf-8');path.write_bytes(data)
    record.write_text(json.dumps(dict(before_sha256=PIN,after_sha256=b.digest(data),changes=changes,other_cells_unchanged=True,backup=str(backup)),ensure_ascii=False,indent=2),encoding='utf-8')
    print(len(changes),b.digest(data))
if __name__=='__main__':main()
