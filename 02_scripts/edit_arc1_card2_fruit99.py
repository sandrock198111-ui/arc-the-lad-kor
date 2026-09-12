"""Create a separate QA card; preserve the live DuckStation card."""
import hashlib, json, struct
from pathlib import Path
import build_arc1_v379_spirit_reports as build
from verify_arc1_v371_speaker_fixes import uc, m

ROOT = Path(__file__).resolve().parents[1]
SOURCE = Path('C:/Users/Administrator/AppData/Local/DuckStation/memcards/shared_card_2.mcd')
OUT = ROOT / '03_output/V379_CARD2_FRUIT99.mcd'
REPORT = ROOT / '01_work/analysis/v379_card2_fruit99'

def sha(data):
    return hashlib.sha256(data).hexdigest().upper()

def main():
    original = SOURCE.read_bytes()
    assert len(original) == 131072 and original[:2] == b'MC'
    for slot in (1, 2, 3):
        directory = original[slot*128:(slot+1)*128]
        assert directory[0] == 0x51
        assert directory[10:30].split(b'\0')[0] == f'BISCPS-10008ARC1-{slot:03}'.encode()
        block = original[slot*8192:(slot+1)*8192]
        assert block[:2] == b'SC'
        assert sum(block[0x100:0xA79]) & 255 == block[0xA79]
    assert all(original[n*128] != 0x51 for n in range(4,16))
    changed = bytearray(original)
    quantity = 0x6000 + 0x112
    checksum = 0x6000 + 0xA79
    assert original[quantity] == 5
    changed[quantity] = 99
    changed[checksum] = sum(changed[0x6100:checksum]) & 255
    differences = [i for i,(a,b) in enumerate(zip(original,changed)) if a != b]
    assert differences == [quantity,checksum]
    exe = build.b.members(build.OUT)['PSX.EXE']
    vm = uc.Uc(uc.UC_ARCH_MIPS, uc.UC_MODE_MIPS32 | uc.UC_MODE_LITTLE_ENDIAN)
    vm.mem_map(0,0x200000)
    vm.mem_write(0x11B000,exe[0x800:])
    # Native checksum writer over the exact serialized gameplay payload.
    vm.mem_write(0x1C30EC,bytes(changed[0x6100:0x6A7A]))
    vm.reg_write(m.UC_MIPS_REG_A0,0x801C30EC)
    vm.reg_write(m.UC_MIPS_REG_A1,0x979)
    vm.reg_write(m.UC_MIPS_REG_RA,0x80060000)
    vm.emu_start(0x8012B5F0,0x80060000,count=100000)
    assert bytes(vm.mem_read(0x1C30EC,0x97A)) == bytes(changed[0x6100:0x6A7A])
    # Native load-copy section, stopping before stack restoration.
    vm.emu_start(0x8012B0EC,0x8012B1B8,count=100000)
    assert bytes(vm.mem_read(0x119800,0x979)) == bytes(changed[0x6100:0x6A79])
    # Inventory icon availability consumer: base 80118000 + item index + 1810.
    vm.reg_write(m.UC_MIPS_REG_S1,2)
    vm.emu_start(0x8016475C,0x80164770,count=20)
    assert vm.reg_read(m.UC_MIPS_REG_V0) == 99
    assert SOURCE.read_bytes() == original, 'Live source changed during verification'
    backup = ROOT / '99_backup' / ('shared_card_2_before_fruit99_' + sha(original)[:16] + '.mcd')
    backup.parent.mkdir(parents=True,exist_ok=True)
    if backup.exists():
        assert backup.read_bytes() == original
    else:
        backup.write_bytes(original)
    OUT.write_bytes(changed)
    assert OUT.read_bytes() == changed and SOURCE.read_bytes() == original
    REPORT.mkdir(parents=True,exist_ok=True)
    result = dict(source=str(SOURCE), source_sha256=sha(original), backup=str(backup),
                  output=str(OUT), output_sha256=sha(changed), slot=3,
                  item='넘치는 열매', item_index=2, before=5, after=99,
                  changed_offsets=[hex(i) for i in differences],
                  checks=['three original checksums', 'only quantity and checksum changed',
                          'native V379 checksum writer', 'native load-copy',
                          'native inventory consumer reads 99', 'source and slots 1/2 preserved'],
                  limitation='Actual DuckStation gameplay not run; load this card via in-game Load, not savestate.')
    (REPORT/'report.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(result,ensure_ascii=False,indent=2))

if __name__ == '__main__':
    main()
