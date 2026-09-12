"""Read-only source-row / actual event-consumer audit, not a gameplay test."""
import csv, json, sys, struct
from pathlib import Path
from zipfile import ZipFile
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'02_scripts'))
import audit_arc1_v370_event_abort as cpu
from audit_arc1_v375_full_inventory import AN, ORIGINAL, BASE, digest, write_csv

def main():
    with ZipFile(ORIGINAL) as z: original = {n:z.read(n) for n in z.namelist()}
    with ZipFile(BASE) as z: patch = {n:z.read(n) for n in z.namelist()}
    current = {**original, **patch}  # Patch archive omits unchanged original members.
    with (ROOT/'05_docs/script_original_full.csv').open(encoding='utf-8-sig',newline='') as f:
        rows = list(csv.DictReader(f))
    ram = list(cpu.states())[1][2]
    begin,end = 0x8015AC0C,0x8015D900
    bias=0x8011A800
    assert current['PSX.EXE'][begin-bias:end-bias] == ram[begin&0x1fffff:end&0x1fffff]
    code_deltas = [hex(i+bias) for i in range(begin-bias,end-bias)
                   if original['PSX.EXE'][i] != current['PSX.EXE'][i]]
    assert code_deltas == ['0x8015c0f8','0x8015c118','0x8015c170','0x8015c188']
    ledger=[]; proofs=[]
    for number,row in enumerate(rows,1):
        name=row['source file']; at=int(row['byte offset'],0)
        raw=bytes.fromhex(row['raw bytes as hex']); old=original[name]; new=current[name]
        assert old[at:at+len(raw)]==raw, (number,name,hex(at))
        changed=raw!=new[at:at+len(raw)]
        # These are CANDIDATE predicates, not a semantic classifier or full VM parser.
        suspect=raw[0]>=0xEB or len(raw)==3 or (len(raw)<8 and b'\x0b\0' in old[max(0,at-10):at])
        record=dict(row=number,file=name,offset=hex(at),length=len(raw),changed=changed,
                    original_hex=raw.hex(' '),current_hex=new[at:at+len(raw)].hex(' '),
                    status='OUTSIDE_TARGETED_OPCODE_PREDICATE')
        if suspect:
            record['status']='CANDIDATE_UNCHANGED' if not changed else 'CANDIDATE_CHANGED'
        if suspect and changed:
            target=at+2; base=at//0x800*0x800
            old_script=old[base:base+0x8000];new_script=new[base:base+0x8000]
            prefixes=[]
            for start in range(at-16,at+2,2):
                opcode=int.from_bytes(old[start:start+2],'little')
                if opcode not in (3,7,11,16,17,23,25):continue
                try:
                    p=cpu.probe(ram,old_script,start-base)
                    q=cpu.probe(ram,new_script,start-base)
                except Exception:continue
                if p['index']==(target-base)//2 and p['dispatch_continue']==1:
                    prefixes.append(dict(start=hex(start),opcode=opcode,original=p,current=q))
            if not prefixes:
                record['status']='CANDIDATE_NO_OPCODE_BOUNDARY_PROOF'
                ledger.append(record)
                continue
            opcode_old=int.from_bytes(old[target:target+2],'little')
            opcode_new=int.from_bytes(new[target:target+2],'little')
            assert opcode_old != opcode_new
            proof=dict(file=name,row=number,offset=hex(target),source_offset=hex(at),
                       original_opcode=opcode_old,current_opcode=opcode_new,prefixes=prefixes,
                       original_source_hex=raw.hex(' '),current_source_hex=new[at:at+len(raw)].hex(' '),
                       preceding_operand_changed=old[at:at+2]!=new[at:at+2],
                       original_file_sha256=digest(old),current_file_sha256=digest(new))
            for label,payload in [('original',old_script),('current',new_script)]:
                try: proof[label+'_single_dispatch']=cpu.probe(ram,payload,target-base)
                except Exception as error:proof[label+'_single_dispatch']={'unresolved':str(error)}
            repaired=bytearray(new_script)
            repaired[target-base:target-base+2]=old[target:target+2]
            try:proof['memory_only_restored_dispatch']=cpu.probe(ram,bytes(repaired),target-base)
            except Exception as error:proof['memory_only_restored_dispatch']={'unresolved':str(error)}
            proofs.append(proof)
            record['status']='CONFIRMED_OPCODE_CHANGED'
        ledger.append(record)
    water='8/S8041.DAT'; base=0x47800; at=0x47924
    repaired=bytearray(current[water]); repaired[at]=original[water][at]
    water_proof={label:cpu.probe(ram,data[base:0x49800],0x110,False)
                 for label,data in [('original',original[water]),('current',current[water]),('memory_only_restored',bytes(repaired))]}
    assert water_proof['original']==water_proof['memory_only_restored']
    assert water_proof['original']['opcodes']==[11,11,20,33]
    assert water_proof['current']['opcodes']==[11,11,39,0,652]
    assert water_proof['original']['return_value']==1 and water_proof['current']['return_value']==0
    write_csv(AN/'event_source_rows.csv',ledger)
    result=dict(source_rows=len(rows),changed_rows=sum(r['changed'] for r in ledger),
                confirmed_opcode_changes=len(proofs),files=len({p['file'] for p in proofs}),
                also_changed_preceding_operand=sum(p['preceding_operand_changed'] for p in proofs),
                zip_sha256=digest(BASE.read_bytes()),fixture_current_vm_bytes_equal=True,
                original_current_vm_deltas=code_deltas,
                vm_delta_meaning='Four UI box Y coordinates only; opcode handlers/readers unchanged.',
                water_from_preceding_commands=water_proof,proofs=proofs,
                limitation='Isolated captured-RAM CPU tests. Scene entry/reachability and reporter screen not reproduced. All 2878 source rows enumerated; candidate predicate is NOT an exhaustive bytecode grammar. Other rows are NOT marked PASS.')
    (AN/'event_integrity.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps({k:v for k,v in result.items() if k!='proofs'},ensure_ascii=False,indent=2))

if __name__=='__main__':main()
