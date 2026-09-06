"""Restore prebattle help icons using only the two already-owned string spans.

V359 Thin is the pinned cumulative patch input, not an original game image.
The original disc remains untouched; package_test_iso overlays the cumulative
patch on the original tree. Runtime approval is deliberately not implied.
"""
from pathlib import Path
from zipfile import ZipFile, ZIP_DEFLATED
import hashlib
import json
import struct
import sys

sys.stdout.reconfigure(encoding='utf-8', errors='replace')

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / '03_output/arc1_v359_thin_font_all_TEST_ONLY_D38CAB43.zip'
OUTPUT = ROOT / '03_output/arc1_v359_thin_prep_icons_TEST_ONLY.zip'
REPORT = ROOT / '01_work/analysis/arc1_v359_prep_icons/report.json'
BASE_HASH = 'D38CAB437797F649819E4D777C0C6344C67351D5EB5BFFAB812F22C4F71B821A'
BIAS = 0x8011A800
OLD_FIRST = bytes.fromhex('35 6D 0D A1 DD 53 DF 9A 19 8C 2C 00')
OLD_SECOND = bytes.fromhex('DD 47 31 19 3A A1 4F DD 39 36 A1 29 DD 64 DD 1D 07 01 00')
# Retain the exact approved first-row Korean encoding. The second row uses
# existing codes for " 전투 시작", with START expressing the missing action.
FIRST = bytes.fromhex('E7 03 E7 05 A1') + OLD_FIRST
SECOND = bytes.fromhex('E7 08 A1 4F DD 39 A1 29 DD 64 00')


def sha(data):
    return hashlib.sha256(data).hexdigest().upper()


def make():
    assert sha(BASE.read_bytes()) == BASE_HASH, 'baseline drift'
    with ZipFile(BASE) as z:
        infos = z.infolist()
        members = {i.filename: z.read(i) for i in infos}
    old = members['PSX.EXE']
    assert old[0x80224:0x80230] == OLD_FIRST
    assert old[0x80D8E:0x80DA1] == OLD_SECOND
    # Scan bytewise, including unaligned references and internal string targets.
    refs = [(i, struct.unpack_from('<I', old, i)[0])
            for i in range(len(old)-3)
            if any(BIAS+lo <= struct.unpack_from('<I',old,i)[0] < BIAS+hi
                   for lo,hi in ((0x80224,0x80230),(0x80D8E,0x80DA1)))]
    assert refs == [(0x82374,BIAS+0x80224),(0x82378,BIAS+0x80D8E)], refs
    # Dedicated panel loads these two table entries; no code edits are needed.
    assert old[0x4C30C:0x4C314] == bytes.fromhex('1A 80 04 3C 74 CB 84 8C')
    assert old[0x4C338:0x4C340] == bytes.fromhex('1A 80 04 3C 78 CB 84 8C')
    assert len(FIRST) <= len(OLD_SECOND) and len(SECOND) <= len(OLD_FIRST)
    writes = (
        (0x80224, SECOND.ljust(len(OLD_FIRST), b'\0')),
        (0x80D8E, FIRST.ljust(len(OLD_SECOND), b'\0')),
        (0x82374, struct.pack('<I',BIAS+0x80D8E)),
        (0x82378, struct.pack('<I',BIAS+0x80224)),
    )
    new = bytearray(old)
    for at, raw in writes:
        new[at:at+len(raw)] = raw
    allowed = {i for at,raw in writes for i in range(at,at+len(raw))}
    changed = {i for i,(a,b) in enumerate(zip(old,new)) if a != b}
    assert changed <= allowed and len(new) == len(old)
    members['PSX.EXE'] = bytes(new)
    if OUTPUT.exists():
        with ZipFile(OUTPUT) as z:
            assert z.namelist() == list(members)
            assert all(z.read(n) == raw for n,raw in members.items()), 'refuse different output'
    else:
        with ZipFile(OUTPUT,'w',compression=ZIP_DEFLATED,compresslevel=9) as z:
            for info in infos:
                z.writestr(info,members[info.filename],compress_type=ZIP_DEFLATED,compresslevel=9)
    report = dict(status='STATIC CANDIDATE / RUNTIME PENDING', base_sha256=BASE_HASH,
                  output_sha256=sha(OUTPUT.read_bytes()), exe_sha256=sha(bytes(new)),
                  changed_member='PSX.EXE', changed_bytes=len(changed),
                  ranges=[dict(offset=hex(at),size=len(raw)) for at,raw in writes],
                  new_glyphs=0,new_vram=0,code_changes=0,
                  rows=['□ ✕ 인물을 선택하세요','START 전투 시작'])
    REPORT.parent.mkdir(parents=True,exist_ok=True)
    REPORT.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(report,ensure_ascii=False,indent=2))


if __name__ == '__main__':
    make()
