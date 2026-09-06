"""Independent final archive, UI payload and bounded MIPS arithmetic checks."""
from pathlib import Path
from zipfile import ZipFile
import struct
from capstone import Cs,CS_ARCH_MIPS,CS_MODE_MIPS32,CS_MODE_LITTLE_ENDIAN
ROOT=Path(__file__).resolve().parents[1]
def load(name):
 with ZipFile(ROOT/'03_output'/name) as z:return {n:z.read(n) for n in z.namelist()}
a=load('arc1_v359_thin_spacing_ye_TEST_ONLY.zip');b=load('arc1_v359_ui_bundle_TEST_ONLY.zip')
assert list(a)==list(b) and len(a)==164
assert [n for n in a if a[n]!=b[n]]==['PSX.EXE']
assert all(len(a[n])==len(b[n]) for n in a)
old=a['PSX.EXE'];exe=b['PSX.EXE'];bias=0x8011A800
def string(buf,p):
 t=struct.unpack_from('<I',buf,p)[0]-bias
 assert 0<=t<len(buf)
 return buf[t:buf.index(0,t)]
payloads={0x8234C:'E7 02 DD 10 DD 0A A1 A1 E7 05 DE 54 A1 DD 89 24',0x82350:'E7 03 DD 31 DD 32 A1 DD A3 A1 A1 E7 08 8B DD D2 A1 DE 2B 35',0x8235C:'E7 02 DD 47 31 A1 A1 E7 03 72 09 0C 24'}
for p,h in payloads.items():assert string(exe,p)==bytes.fromhex(h)
for p in (0x81EEC,0x825F0,0x82374,0x82378):assert string(exe,p)==string(old,p)
words={0x44960:0x000280C0,0x44964:0x02028023,0x4497C:0x00108040,0x44980:0x26100012}
allowed=set(range(0x80944,0x8097A))|set(range(0x820D5,0x820E2))|{i for p in [0x81EEC,0x8234C,0x82350,0x8235C,0x825F0,*words] for i in range(p,p+4)}
assert all(i in allowed for i,(x,y) in enumerate(zip(old,exe)) if x!=y)
m=Cs(CS_ARCH_MIPS,CS_MODE_MIPS32|CS_MODE_LITTLE_ENDIAN)
for p,w in words.items():
 assert struct.unpack_from('<I',exe,p)[0]==w
 ins=list(m.disasm(exe[p:p+4],p+bias));assert len(ins)==1
 print(hex(p),ins[0].mnemonic,ins[0].op_str)
# Independent interpreter for the complete four-instruction arithmetic block.
for n in range(257):
 regs=[0]*32;regs[2]=n
 for p in words:
  w=struct.unpack_from('<I',exe,p)[0];op=w>>26;rs=(w>>21)&31;rt=(w>>16)&31;rd=(w>>11)&31
  if op==0 and w&63==0:regs[rd]=regs[rt]<<((w>>6)&31)
  elif op==0 and w&63==35:regs[rd]=regs[rs]-regs[rt]
  elif op==9:regs[rt]=regs[rs]+(w&65535)
  else:raise AssertionError(hex(w))
 assert regs[16]==14*n+18
# Reject direct branch/jump entry to arithmetic interiors, except sequential
# execution of the unmodified containing routine. No new branch/delay slot.
for o in range(0x800,0x78000,4):
 w=struct.unpack_from('<I',exe,o)[0];op=w>>26;pc=o+bias;t=None
 if op in (2,3):t=((pc+4)&0xF0000000)|((w&0x3ffffff)<<2)
 elif op in (1,4,5,6,7):t=pc+4+struct.unpack('<h',struct.pack('<H',w&65535))[0]*4
 assert t not in {bias+p for p in words},hex(pc)
lengths=[]
for index in range(108):
 raw=string(exe,0x81B4C+index*4);at=0;n=0
 while at<len(raw):
  width=1 if raw[at]<0xDD else 2
  assert at+width<=len(raw)
  assert not 0xE2<=raw[at]<=0xE8
  at+=width;n+=1
 lengths.append(n)
assert max(lengths)*14+18<=320
assert exe[0x828C8:0x82908]==old[0x828C8:0x82908]
print('PASS: all prior fonts/DAT and prep fixes preserved; two gaps; relocated text exact; arithmetic 257/257; registered names108/max length',max(lengths))
print('Runtime screen-edge placement and visual QA PENDING; no new edge clamp claimed')
