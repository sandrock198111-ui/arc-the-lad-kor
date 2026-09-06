"""Independent packed-plane and exact UI byte verification."""
from pathlib import Path
from zipfile import ZipFile
import struct
ROOT=Path(__file__).resolve().parents[1]
def archive(name):
    with ZipFile(ROOT/'03_output'/name) as z:return {n:z.read(n) for n in z.namelist()}
a=archive('arc1_v359_thin_prep_icons_TEST_ONLY.zip')
b=archive('arc1_v359_thin_spacing_ye_TEST_ONLY.zip')
assert list(a)==list(b) and len(b)==164
assert {n for n in a if a[n]!=b[n]}=={'PSX.EXE','COMM.IMG'}
assert all(len(a[n])==len(b[n]) for n in a)
exe=b['PSX.EXE']
assert exe[0x80950:0x80961]==bytes.fromhex('E7 02 DD 10 DD 0A A1 A1 E7 05 DE 54 A1 DD 89 24 00')
assert exe[:0x80950]==a['PSX.EXE'][:0x80950] and exe[0x80961:]==a['PSX.EXE'][0x80961:]
assert struct.unpack_from('<I',exe,0x8234C)[0]==0x8019B150
assert struct.unpack_from('<I',exe,0x82350)[0]==0x8019B161
# Direct raw packed-bit oracle for plane150: 4 planes/cell, 15 columns,
# row stride896, cell16x16. Assert explicit old/new bit coordinates only.
def bit_at(x,y):
    cell=150//4; col=cell%15; row=cell//15
    return (row*16+y)*896+col*8+x//2,1<<((150%4)+(4 if x%2 else 0))
expected=bytearray(a['COMM.IMG'])
for y in range(2,6):
    at,mask=bit_at(8,y);expected[at]&=255^mask
    at,mask=bit_at(7,y);expected[at]|=mask
assert bytes(expected)==b['COMM.IMG'], 'unexplained font bit change'
for y in range(2,6):
    at,mask=bit_at(8,y);assert not b['COMM.IMG'][at]&mask
print('PASS: exact byte/bit oracle; 162 members unchanged; one glyph only; all pointers/code unchanged; spacing NUL boundary preserved')
print('RUNTIME PENDING: Ye readability and battle-help visual spacing')
