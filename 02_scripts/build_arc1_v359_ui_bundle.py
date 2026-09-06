"""Approved two help gaps + overhead name width, preserving prior V359 fixes."""
from pathlib import Path
from zipfile import ZipFile,ZIP_DEFLATED
import struct,hashlib,json
ROOT=Path(__file__).resolve().parents[1]
BASE=ROOT/'03_output/arc1_v359_thin_spacing_ye_TEST_ONLY.zip'
OUT=ROOT/'03_output/arc1_v359_ui_bundle_TEST_ONLY.zip'
BIAS=0x8011A800
def digest(b):return hashlib.sha256(b).hexdigest().upper()
def run():
 assert digest(BASE.read_bytes())=='76A031522C046E54673A56EBAE304D53411F0A4C161A30D4E0750A8661D0C993'
 with ZipFile(BASE) as z:infos=z.infolist();members={i.filename:z.read(i) for i in infos}
 old=members['PSX.EXE'];exe=bytearray(old)
 expected=bytes.fromhex('DD 2F 70 45 1E 00 00 00 00 00 00 00 E7 02 DD 10 DD 0A A1 A1 E7 05 DE 54 A1 DD 89 24 00 E7 03 DD 31 DD 32 A1 DD A3 E7 08 8B DD D2 A1 DE 2B 35 00 DE 2B 35 DD CF 00')
 assert old[0x80944:0x8097A]==expected
 assert old[0x820D5:0x820E2]==bytes.fromhex('E7 02 DD 47 31 A1 E7 03 72 09 0C 24 00')
 refs={0x81EEC:0x80944,0x8234C:0x80950,0x82350:0x80961,0x8235C:0x820D5,0x825F0:0x80974}
 found={i:struct.unpack_from('<I',old,i)[0]-BIAS for i in range(len(old)-3) if any(lo<=struct.unpack_from('<I',old,i)[0]-BIAS<hi for lo,hi in ((0x80944,0x8097A),(0x820D5,0x820E2)))}
 assert found==refs,found
 # Both regions are currently owned terminated strings, not inferred caves.
 attack=old[0x80950:0x80961]
 end=old[0x80961:0x8096A]+b'\xA1\xA1'+old[0x8096A:0x80974]
 decide=old[0x820D5:0x820DB]+b'\xA1'+old[0x820DB:0x820E2]
 assert [len(x) for x in (attack,end,decide)]==[17,21,14]
 exe[0x80944:0x8097A]=(attack+end+decide).ljust(54,b'\0')
 exe[0x820D5:0x820E2]=(old[0x80944:0x8094A]+old[0x80974:0x8097A]).ljust(13,b'\0')
 newrefs={0x81EEC:0x820D5,0x8234C:0x80944,0x82350:0x80955,0x8235C:0x8096A,0x825F0:0x820DB}
 for p,v in newrefs.items():struct.pack_into('<I',exe,p,BIAS+v)
 patches={0x44960:(0x00028040,0x000280C0),0x44964:(0x02028021,0x02028023),0x4497C:(0x00108080,0x00108040),0x44980:(0x26100010,0x26100012)}
 for p,(before,after) in patches.items():
  assert struct.unpack_from('<I',old,p)[0]==before
  struct.pack_into('<I',exe,p,after)
 allowed=set(range(0x80944,0x8097A))|set(range(0x820D5,0x820E2))|{i for p in [*refs,*patches] for i in range(p,p+4)}
 assert len(exe)==len(old) and all(i in allowed for i,(a,b) in enumerate(zip(old,exe)) if a!=b)
 members['PSX.EXE']=bytes(exe)
 if OUT.exists():
  with ZipFile(OUT) as z:assert {n:z.read(n) for n in z.namelist()}==members
 else:
  with ZipFile(OUT,'w',compression=ZIP_DEFLATED,compresslevel=9) as z:
   for i in infos:z.writestr(i,members[i.filename],compress_type=ZIP_DEFLATED,compresslevel=9)
 print(json.dumps(dict(zip_sha256=digest(OUT.read_bytes()),exe_sha256=digest(bytes(exe)),changed_bytes=sum(a!=b for a,b in zip(old,exe)),status='STATIC CANDIDATE / RUNTIME PENDING'),indent=2))
if __name__=='__main__':run()
