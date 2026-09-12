"""Reproduce all 154 nonempty item/skill description CPU layout cases."""
import json, sys
from zipfile import ZipFile
sys.dont_write_bytecode=True
from audit_arc1_v375_full_inventory import AN, BASE, digest
from verify_arc1_v360_ui_restore import verify_panels

if __name__=='__main__':
    with ZipFile(BASE) as z: exe=z.read('PSX.EXE')
    result=verify_panels(exe,skill_height=42,mp_y=127)
    result['build_sha256']=digest(BASE.read_bytes())
    result['exe_sha256']=digest(exe)
    (AN/'description_cpu.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    print(json.dumps({k:v for k,v in result.items() if k not in ('cases_detail','mp_cases')},indent=2))
