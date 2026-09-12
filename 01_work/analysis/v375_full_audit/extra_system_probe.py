"""Read-only extra UI fragment/ref investigation; emits analysis only."""
import sys,json,struct,csv
from pathlib import Path
from zipfile import ZipFile
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/'02_scripts'))
import audit_arc1_v375_full_inventory as inv
from capstone import Cs,CS_ARCH_MIPS,CS_MODE_MIPS32,CS_MODE_LITTLE_ENDIAN
AN=Path(__file__).resolve().parent
ORIG=ZipFile(inv.ORIGINAL).read('PSX.EXE')
CUR=ZipFile(inv.BASE).read('PSX.EXE')
decode=inv.make_decoder(CUR)
glyphs,_,nearest,_=inv.ui.build_glyph_map()
PTRS=[0x780DC,0x780E0,0x780E4,0x780FC,0x78244,0x82470,0x82534,0x82550,0x82558,0x825F0,0x825F4,0x825F8,0x82630,0x82634,0x8299C,0x82A68,0x82938,*range(0x82AE8,0x82B00,4)]
md=Cs(CS_ARCH_MIPS,CS_MODE_MIPS32|CS_MODE_LITTLE_ENDIAN)
def instructions(start,end):
 return list(md.disasm(ORIG[start:end],inv.BIAS+start))
def context(addr,n=8):
 return '\n'.join(f'{i.address:08X} {i.mnemonic} {i.op_str}' for i in instructions(addr-inv.BIAS-n*4,addr-inv.BIAS+(n+1)*4))
# Reconstruct static LUI/low-half references from machine words, bounding the
# candidate to a nearby preceding LUI. These are candidate xrefs, not CFG proof.
refs={}
for p in range(0x800,0x77F00,4):
 w=struct.unpack_from('<I',ORIG,p)[0];op=w>>26;rs=(w>>21)&31
 if op not in (9,13,32,33,35,36,37,40,41,43):continue
 low=w&65535
 if op!=13 and low&32768:low-=65536
 for q in range(p-4,max(0x7FC,p-64),-4):
  v=struct.unpack_from('<I',ORIG,q)[0]
  if v>>26==15 and (v>>16)&31==rs:
   addr=((v&65535)<<16)+low
   refs.setdefault(addr,[]).append(p+inv.BIAS);break
rows=[]
for p in PTRS:
 oa,ca=struct.unpack_from('<I',ORIG,p)[0],struct.unpack_from('<I',CUR,p)[0]
 raw=inv.raw_at(ORIG,oa-inv.BIAS)
 cr=inv.storage.string_at(CUR,ca)
 jp,_=inv.ui.decode_string(ORIG,oa-inv.BIAS,glyphs,nearest)
 ko,u=decode(cr)
 r=dict(id=f'extra_ui:{p:05X}',pointer_offset=f'0x{p:X}',original_pointer=f'0x{oa:X}',current_pointer=f'0x{ca:X}',japanese_guess=jp,current_decode=ko,original_hex=raw.hex(' '),current_hex=cr.hex(' '),original_ascii=raw.decode('ascii',errors='backslashreplace'),current_ascii=cr.decode('ascii',errors='backslashreplace'),candidate_pointer_xrefs=[hex(z) for z in refs.get(inv.BIAS+p,[])])
 rows.append(r)
print(json.dumps(rows,ensure_ascii=False,indent=2))
if len(sys.argv)>1 and sys.argv[1]=='contexts':
 for p in [*PTRS,0x781B8,0x82360,0x825E8,0x82AC8]:
  print('\nPTR',hex(p))
  for addr in refs.get(inv.BIAS+p,[]):print(context(addr,10))
if len(sys.argv)>1 and sys.argv[1]=='review':
 from collections import Counter
 verdicts={
  0x780DC:('HUD_BINARY','NONE','1 → DFEA: native digit fragment, indexed 3-entry selector. Unknown prose decode is not glyph failure.'),
  0x780E0:('HUD_BINARY','NONE','2 → DFEB: native digit fragment, same selector bank.'),
  0x780E4:('HUD_BINARY','NONE','3 → DFEC: native digit fragment, same selector bank.'),
  0x780FC:('HUD_BINARY','NONE','Original pixels L → DFF4: native HUD letter, not Japanese word.'),
  0x78244:('HUD_BINARY','NONE','Original pixel is colon : (raw25 is NOT ASCII % here). Current DFF7 native HUD punctuation.'),
  0x82470:('PASS_SEMANTIC','NONE','Original opening corner quote 「 matches current 「; item acquisition message component.'),
  0x82534:('ACCEPTABLE_ABBREVIATION','LOW','Japanese subject particle が becomes space in stat-number-increase message, e.g. 공격력 N 상승. Meaning preserved.'),
  0x82550:('PASS_SEMANTIC','NONE','Original opening corner quote 「 matches current 「; learned-skill message component.'),
  0x82558:('ACCEPTABLE_ABBREVIATION','LOW','Original 」の becomes 」 plus space; possessive particle omitted in named-skill level-up component, meaning retained.'),
  0x825F0:('PASS_SEMANTIC','NONE','する → 확인함 is the affirmative cancel-confirmation option, not a generic verb. Table consumer proves row pairing.'),
  0x825F4:('PASS_SEMANTIC','NONE','あり → 보기 is help-window ON option; paired with なし.'),
  0x825F8:('PASS_SEMANTIC','NONE','なし → 안 보기 is help-window OFF option; paired with あり.'),
  0x82630:('CONFIRMED_DEFECT','MEDIUM','Original 勝 (wins) becomes 위 (rank/up). Original win counter renderer loads at80156898 and draws at801568A0.'),
  0x82634:('CONFIRMED_DEFECT','HIGH','Original pixel 負 (losses) becomes 로 분<CODE:E0ED>, corrupt text. Original loss-counter draw8015691C. Known-buried exception did not mean repaired.'),
  0x8299C:('NEEDS_SOURCE_CONFIRMATION','HIGH','Original pixel 炎 is proven. Current only E0AC has no known Korean mapping; exact current glyph/CPU render still required before deciding corruption versus intentionally preserved symbol. Pointer is skill-alias bank index25.'),
  0x82A68:('CONFIRMED_DEFECT','MEDIUM','Original ????? unknown-entry label becomes empty. Explicit unknown branches draw this pointer at8015652C and80156AE0; not an original empty placeholder.'),
  0x82938:('EMPTY_PLACEHOLDER','NONE','Original/current empty bank index0; indexed aliases consumed at80156F90,801632E0,80171CA0.'),
 }
 for ptr in range(0x82AE8,0x82B00,4):
  verdicts[ptr]=('CONFIRMED_DEFECT','LOW','Native CJK state-editor label is unchanged bytes but Korean glyph mapping changes its visible meaning. Six-entry bank drawn80157E8C. Ordinary-player reachability NOT proven; keep debug/state editor scope separate.')
 out=[]
 for r in rows:
  p=int(r['pointer_offset'],16);s,sev,n=verdicts[p]
  ev='original COMM pixels independently rendered in-memory; bytes='+r['original_hex']+'; current='+r['current_decode']+' bytes='+r['current_hex']+'; candidate refs='+','.join(r['candidate_pointer_xrefs'])
  if p in [0x780DC,0x780E0,0x780E4]:ev+='; indexed bank load8012D2B4 -> draw8012D2C0'
  if p in [0x825F0,0x825F4,0x825F8]:ev+='; configuration loop80160894..801608CC: base825C8+(row*8)+0x14 and +0x18; row2 cancel confirm / row3 help'
  if p==0x8299C:ev+='; alias bank82938 +25*4, bank indexed native consumer80156F78..80156F90'
  out.append(dict(id=r['id'],status=s,severity=sev,finding=n,evidence=ev,next_action='Validate current glyph pixels and actual reachability; approve corrections only after review' if s in ['CONFIRMED_DEFECT','NEEDS_SOURCE_CONFIRMATION','HUD_BINARY'] else 'No semantic correction needed; runtime validation remains separate',storage_class='DEBUG_STATE_UI' if p>=0x82AE8 else 'HUD_BINARY' if s=='HUD_BINARY' else 'TEXT_FRAGMENT'))
 # Individually inspected numeric formats with verified formatting/text consumer
 # evidence. These must not be decoded through the Japanese/Korean native table.
 formats={0x801A7EA8:(0x8012D418,'B2E4 at8012D43C'),0x801A7EAC:(0x8012D480,'B2E4 at8012D4A4'),0x801A7EB0:(0x8012D508,'B2E4 at8012D528'),0x801A8288:(0x80157EBC,'B2E4 at80157F2C'),0x801A8290:(0x80157EEC,'B2E4 at80157F2C'),0x801A8298:(0x80157F10,'B2E4 at80157F2C'),0x801A82B8:(0x80160450,'stat message numeric component80160440 onward'),0x801A82C0:(0x80162150,'B324 at80162160'),0x801A82C4:(0x801621C0,'B324 at801621D0'),0x801A82CC:(0x80164074,'B324 at80164088'),0x801A82D4:(0x80164B48,'B324 at80164B5C'),0x801A82FC:(0x80169768,'native floor composite80169774..80169798'),0x801A8300:(0x8016B1E8,'dynamic format builder8016B1BC then numeric draw'),0x801A8308:(0x8016B200,'dynamic signed format builder8016B1BC then numeric draw'),0x801A8310:(0x8016BD0C,'native number converter8016BD20; text substitution helper')}
 for address,(ref,sink) in formats.items():
  p=address-inv.BIAS;old=ORIG[p:ORIG.index(b'\0',p)];new=CUR[p:CUR.index(b'\0',p)]
  assert old==new,(hex(address),old,new)
  out.append(dict(id=f'ascii_format:{p:05X}',status='PASS_SEMANTIC',severity='NONE',finding='ASCII numeric format '+repr(old.decode('ascii'))+' unchanged; not native game text.',evidence=f'Original/current bytes {old.hex()}; static ref {ref:08X} calls sprintf801759B8; {sink}',next_action='Formatting bytes preserved; no prose translation required',storage_class='ASCII_FORMAT'))
 updates=[('ui_pointer:781B8','NEEDS_SOURCE_CONFIRMATION','Direct original caller8012C7CC passes to8012D734 after selector drawing8012D220; load-only menu reachability still not fully traced.'),('ui_pointer:82360','NEEDS_SOURCE_CONFIRMATION','Indexed help bank: additional L/R instruction still needs all-input-state proof. No direct static pointer xref found.'),('ui_pointer:825E8','ACCEPTABLE_ABBREVIATION','Resolved option context: original configuration row1 pairs825E4 normal /825E8 improve; current 일반/사용 expresses normal versus enhanced input. Table loop801608A8/801608C0 proves pairing.'),('ui_pointer:82AC8','NEEDS_SOURCE_CONFIRMATION','Direct original consumer801666F4 stages equipment prompt and registers callback8016674C; all callers being pre-battle not yet proven.')]
 for rid,s,n in updates:out.append(dict(id=rid,status=s,severity='LOW' if s=='ACCEPTABLE_ABBREVIATION' else 'MEDIUM',finding=n,evidence='Original MIPS disassembly; extra_system_probe.py contexts and configuration80160810..80160928',next_action='Root must merge this update with original 255-row review; unresolved caller traces remain',storage_class='PREVIOUS_REVIEW_UPDATE'))
 with (AN/'extra_system_review.csv').open('w',encoding='utf-8-sig',newline='') as f:
  w=csv.DictWriter(f,fieldnames=list(out[0]));w.writeheader();w.writerows(out)
 counts=Counter(r['status'] for r in out)
 text=['# V375 extra system fragments and direct numeric formats','',f'{len(out)} rows: 23 additional pointer records + 15 ASCII format literals + 4 previous-review updates. {dict(counts)}','', 'The 6 state-editor labels are proven text consumers but are NOT proven normally player reachable. Native HUD codes are explicitly excluded from prose-decoder failure counts. Source pixels were rendered from original COMM in memory and directly viewed; raw ASCII-looking source25 is colon in the native encoding.', '', '## Findings','']
 text += ['- '+r['id']+' ['+r['status']+']: '+r['finding'] for r in out]
 text += ['', '## Scope boundary', '', 'Nearby LUI/low-half reference scan: original EXE code offsets0x800..0x77EFF, maximum64-byte preceding LUI search. This identifies candidates rather than proving dataflow across control flow. Direct native/ascii text calls with immediate a2 were inspected; only runtime scratch buffers were additional direct a2 literals. Format a1 references in title/UI code bands8012C000..8012DFFF and80155000..80171FFF produced the 15 reviewed literals, whose consumers were independently inspected. Indirect and distant register constructions, other wrappers, overlays/DAT, debug reachability and entire-program text population remain outside a completeness guarantee. No claim that these 38 additions exhaust all UI strings. No game/canonical bytes changed.', '', 'Helper extra_system_probe.py review regenerates only this CSV/MD. contexts prints candidate native consumers. Existing system_location_review.csv/.md were not altered; merge the four updates explicitly.']
 (AN/'extra_system_review.md').write_text('\n'.join(text)+'\n',encoding='utf-8')
 print('REVIEW',dict(counts))
