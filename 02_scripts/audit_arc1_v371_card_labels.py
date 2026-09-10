"""Read-only card-selection call-path reproduction; no card I/O or GPU claim."""
import hashlib, json, struct
from pathlib import Path
from zipfile import ZipFile
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'01_work/tools/cursor_verify'))
import unicorn as uc
from unicorn import mips_const as m
from v354_dialogue_codec import load_v354, tokens

ROOT = Path(__file__).resolve().parents[1]

def main():
    with ZipFile(ROOT/'00_original/arc.zip') as z:
        original = z.read('PSX.EXE')
    with ZipFile(ROOT/'03_output/arc1_v371_speaker_fixes_TEST_ONLY.zip') as z:
        current = z.read('PSX.EXE')
    dec = load_v354()[3]
    results = {}
    for name, exe in [('original', original), ('v371', current)]:
        vm = uc.Uc(uc.UC_ARCH_MIPS, uc.UC_MODE_MIPS32 | uc.UC_MODE_LITTLE_ENDIAN)
        vm.mem_map(0, 0x200000)
        load, size = struct.unpack_from('<II', exe, 0x18)
        vm.mem_write(load & 0x1fffff, exe[0x800:0x800+size])
        vm.reg_write(m.UC_MIPS_REG_SP, 0x80040000)
        vm.reg_write(m.UC_MIPS_REG_RA, 0x80060000)
        calls = []
        def hook(machine, address, length, data):
            if address == 0x80060000:
                machine.emu_stop()
            elif address == 0x8016b248:
                args = [machine.reg_read(getattr(m, 'UC_MIPS_REG_A'+str(i))) for i in range(4)]
                raw = bytes(machine.mem_read(args[2] & 0x1fffff, 8)).split(b'\0')[0]
                calls.append(dict(x=args[0], y=args[1], source=hex(args[2]), raw=raw.hex(),
                                  current_codec=''.join(dec.get(t, '<'+t.hex()+'>') for t in tokens(raw))))
                # Observe renderer arguments, not rendering: skip this callee.
                machine.reg_write(m.UC_MIPS_REG_PC, machine.reg_read(m.UC_MIPS_REG_RA))
        vm.hook_add(uc.UC_HOOK_CODE, hook)
        vm.emu_start(0x8012d660, 0, count=10000)
        assert vm.reg_read(m.UC_MIPS_REG_PC) == 0x80060000
        assert [(c['x'],c['y'],c['raw']) for c in calls] == [(56,48,'bc319512'),(56,64,'bc319513')]
        results[name] = dict(exe_sha256=hashlib.sha256(exe).hexdigest(), calls=calls,
                             cursor_max=struct.unpack('<I',vm.mem_read(0x1a87c0,4))[0])
    assert current[0x78078:0x78090] == original[0x78078:0x78090]
    assert current[0x12e60:0x12f34] == original[0x12e60:0x12f34]
    results['scope'] = 'CPU card-label caller reproduced; draw callee intercepted. No card-detection, GPU or load/save reproduction.'
    print(json.dumps(results, ensure_ascii=False, indent=2))

if __name__ == '__main__':
    main()
