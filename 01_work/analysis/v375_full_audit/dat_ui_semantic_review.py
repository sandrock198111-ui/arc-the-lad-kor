"""Apply recorded manual semantic judgments to the read-only DAT UI census.

Judgments were made by reading all454 choice/quiz rows and all183 exact
JP/current-pair tutorial groups (414 rows). No score or expected text comparison
is used to determine a semantic pass. Original/canonical files are untouched.
"""
import dat_ui_probe as probe
import csv,json,re
from collections import Counter
from pathlib import Path
r=probe.result
assert len(r)==868
D='CONFIRMED_DEFECT';A='ACCEPTABLE_ABBREVIATION';N='NEEDS_SOURCE_CONFIRMATION';P='PASS_SEMANTIC'
judgments={}
def assign(ids,status,finding,severity='MEDIUM'):
 for i in ids:judgments[i]=(status,severity,finding)
# All first454 records were read in complete printed batches0..27,28..119,
# 120..224,225..329,330..403,404..453. The medium families were separately
# viewed with original pixels and retained unresolved, not discarded as noise.
for i in range(454):judgments[i]=(P,'NONE','Directly compared original/current meaning; no material choice direction, count, target or action change identified. Runtime branch/geometry approval is separate.')
assign([i for i in range(454) if r[i]['confidence']=='medium'],N,'Original E502 family is already nonsensical under original COMM glyphs; alternate consumer/codebook or obsolete data must be resolved before calling it valid prose or safe nontext. No inferred translation proposed.')
assign([382],N,'Embedded NUL/control/opcode-looking source candidate B/SB072:487A6; ordinary prose decoding is not valid evidence. Root VM/canonical false-extraction audit must establish its consumer.','HIGH')
compressed=[1,2,9,14,15,28,29,30,31,32,33,34,35,36,38,40,45,64,65,70,71,72,73,74,75,76,77,78,80,82,83,84,85,90,92,93,102,107,108,109,110,111,112,113,114,115,117,119,132,137,138,139,140,141,142,143,144,146,148,155,158,168,171,180,188,197,209,224,227,230,233,236,239,242,244,247,254,260,265,266,267,268,269,270,272,274,282,283,287,291,300,309,311,319,321,329,331,339,341,349,350,354,358,360,361,370,375,376,378,380,381,427,428,431,434,435,436,438,440,441,452,453]
compressed += list(range(275,282))+list(range(293,300))+list(range(302,309))+list(range(312,319))+list(range(322,329))+list(range(332,339))+list(range(342,349))
assign(compressed,A,'Menu/dialogue/option shortened or paraphrased but reviewed action or distinction remains. Dialogue-style restoration requested by user should remain on editorial follow-up; this is not approval to retain all phrasing.','LOW')
assign([37,39,79,81,116,118,145,147,271,273,377,379],D,'Original glyphs say ヒートウォール (Heat Wall), but current menu says 키토우올. Main skill_name29 is 히트 월. Original heat spell name was misread and its tutorial menu no longer matches the selectable skill.')
assign([40,82,119,148,274,380],D,'Same equipment きぬのおび is 비단 띠 here versus equipment_name4 비단 허리띠. Cross-UI item name inconsistency; do not alter its mechanics.')
assign([86],D,'Original 攻撃: heading removed to spaces; names remain but attack-side role label disappears. Tutorial/debug reachability must be established separately.')
assign([87],D,'Original 防御: heading removed; original よっぱらい (drunkard) option becomes 갑옷 (armor). Source glyphs directly checked. Other enemy names are abbreviated, but this option changes identity.','HIGH')
assign([88],D,'Original どうする？ question removed and 最強攻撃 becomes 강공격. Strongest-versus-normal/weak distinction is weakened; this appears test/tutorial selection, reachability not yet proven.')
assign([89],D,'Current 그레이시느 differs from resident region/world/location 그레이시누 for identical グレイシーヌ. Cross-UI location name inconsistency.')
assign([91,215],D,'Original source pixels say ニーデル (Nidel), not historical guess カーデル. Current 카델 propagates the same confirmed resident place-name misread.')
assign([161,177],D,'Original パレンシア uses current 파렌시아 in quiz versus resident 팔렌시아. Same named location rendered inconsistently.')
assign([212],N,'Quiz チョビン is rendered 초비, whereas original final ン is present. Need established NPC name glossary/other actual dialogue comparison before prescribing 초빈; choices remain distinct.')
assign([284,285,286,288,289,290,292,351,352,353,355,356,357,359],D,'Original selected-character E2 name + さんですね confirmation loses the name entirely (맞나?/맞습니까?). Current confirmation no longer repeats whom the player selected. Most rows also flatten polite NPC speech. V373 only fixed one question register, not this missing identity.')
assign([301,310,320,330,340],D,'Original asks whether to redo entry/registration (エントリーをやりなおしますか), but current 처음부터? omits what restarts. Material action-scope information missing; following round-reset confirmation is separate.')
assign([446],D,'Quiz/menu item labels differ from resident inventory: 넘치는 과실 vs 넘치는 열매; 약화의 구슬 vs 약화 구슬; 부활의 약 vs 부활약. Numerical/effect identities not altered in this row.')
assign([447],D,'Quiz/menu 생명의 나무 열매 differs from resident consumable_name21 생명의 열매 for the same original item.')
assign([448,449],D,'Current 마법의 카트 / 슬리플리스 카트 misread original カード and differ from resident 마법 카드 / 수면 방지 카드. Original BC3195 suffix is byte-exact with memory-card label; earlier ガード visual suspicion was disproved.')
assign([450],D,'Original ディールの牙 item becomes 디르의 어금니 here versus resident equipment_name26 데일의 이빨. Both refer to same original item; reconcile with original glyph/source approval.')
# Quiz response register is inconsistent across the same monk and duplicate
# reward messages. Record affected rows, rather than claiming wrong answers.
register=[213,214,216,217,219,220,222,223,225,226,228,229,231,232,234,235,237,238,240,241,243,244,245,246,248,249,250,252,253]
assign(register,D,'Same Ramada monk switches from earlier 승려: ...입니다/하십시오 to 라마다승려/...다/주마/인정하마 forms within the quiz/reward sequence; character label and speech-register consistency defect. Correct-answer facts are not changed by this finding.','LOW')
# Tutorial body pass was performed by exact original/current pair, preserving
# every member ID. 183 groups were read in complete batches0..59,60..119,120..182.
groups={}
for i,e in enumerate(r[454:],454):groups.setdefault((e['original_japanese'],e['current_korean']),[]).append(i)
assert len(groups)==183
for gi,((jp,ko),ids) in enumerate(groups.items()):
 assign(ids,P,f'Exact JP/current tutorial pair group{gi} directly read; mechanics, numbers, direction, negation and conditions preserved. Each listed duplicate has the identical reviewed text pair.','NONE')
 # Only manually identified exceptions below override these read judgments.
 if gi in [64]:assign(ids,D,'Instruction omits source condition カーソルで選んでいる時 (while selected with cursor), so L/R help activation context is missing. Other duplicate at31/S3014 preserves this condition.','LOW')
 if gi==102:assign(ids,D,'Source オルニスの丘 is misread as 오르카스 언덕, same defect as resident region_name3/location_name17. Original name byte sequence crosschecked to glyph-verified resident source.')
 if gi in [111,164]:assign(ids,D,'ヒートウォール is mistranslated 키토우올 in the big-bomb detonation tutorial; selectable skill_name29 says 히트 월, so the actionable spell hint does not match the skill menu.')
 if gi in [26,116,169]:assign(ids,D,'Repeated item name differs from resident inventory: 생명의 나무 열매 vs 생명의 열매, or 비단 띠 vs 비단 허리띠. Same original item, consistency correction required.')
 if gi in [8,43,56,104,105,120,126,130,161]:assign(ids,A,'Input instructions retain button/action semantics (LR simultaneously or confirm icon/word). English-derived terminology / button icon wording varies; harmonize editorially without changing controls.','LOW')
 if gi in [115,167,175]:assign(ids,A,'Romancing Stone location list retains all named destinations/holders across adjoining bodies; country qualifier Sumeria abbreviated. Each stone location still represented.','LOW')
assert set(judgments)==set(range(868))
# Crosscheck the exact Ornis byte sequence instead of trusting historical kana.
ui=json.loads((probe.AN/'ui_inventory.json').read_text(encoding='utf-8'))
ornis=bytes.fromhex(next(e['original_hex'] for e in ui if e['id']=='region_name:3'))
for i in groups[list(groups)[102]]:assert ornis in bytes.fromhex(r[i]['original_hex']),r[i]['id']
out=[]
for i,e in enumerate(r):
 status,severity,finding=judgments[i]
 out.append(dict(id=e['id'],status=status,severity=severity,finding=finding,evidence='Actual V375 decoded via E2 BankA/BankB; original/current bytes in dat_ui_candidates.csv; index='+str(i)+'; original catalog sources='+str(e['sources']),next_action='Original glyph/caller/VM confirmation required' if status==N else 'Review proposal and consistent terminology before any canonical/game modification' if status==D else 'Runtime selection/effect/geometry validation separate',scope=e['scope'],original_choice_count=e['original_choice_count'],current_choice_count=e['current_choice_count'],original_japanese=e['original_japanese'],current_korean=e['current_korean']))
with (probe.AN/'dat_ui_review.csv').open('w',encoding='utf-8-sig',newline='') as f:
 w=csv.DictWriter(f,fieldnames=list(out[0]));w.writeheader();w.writerows(out)
totals=Counter(e['status'] for e in out)
choice=[e for e in r if e['original_choice_count']]
text=['# V375 DAT UI semantic census and review','',f'868/868 catalogued candidate bodies read:454 choice/quiz candidates +414 nonchoice bodies from11 tutorial-containing files. Status totals {dict(totals)}.',f'Original choice-containing candidates {len(choice)}; sum E5 markers {sum(e["original_choice_count"] for e in choice)}; distinct original choice byte bodies {len(set(e["original_hex"] for e in choice))}. These are candidate counts, not proven semantic selectable-option counts.','', '## Population and source', '', 'Union sources: story_corpus5701 boundaries; script_original_full2878; choice-translation265; battle-choice63; separately verified quiz107 (63 outside original full CSV). Every legacy choice/battle entry had a union match. E2 expansion uses current check_build.slot_ref, including BankB D1..EC at0x4200. Current text is decoded from V375 data and physical code aliases, never copied from translation proposals.', '', 'Tutorial scope includes all high-confidence bounded bodies in '+', '.join(probe.TUTORIAL_FILES)+'. This deliberately includes adjacent narrative, not just keyword-selected instructional sentences. 414 rows form183 exact original/current text-pair groups; every group and its IDs was read. Missing catalog boundaries and other tutorial-bearing files remain an external census gap.', '', 'Source glyphs directly inspected for four repeated medium E502 families; Heat Wall menu; attack/defense test menus; Nidel hint;33 ambiguous quiz/name/option rows. Historical source guesses were retained as evidence history, not overwritten. Original glyphs and card-label byte equivalence prove カード/ヒートウォール/ニーデル and quiz identities where noted.', '', '## Confirmed findings','']
text+=['- '+e['id']+': '+e['finding'] for e in out if e['status']==D]
text+=['','## Unresolved and limits','','93 medium candidates remain unresolved (92 repeated E502-family bodies + B/SB072:487A6 opcode-like candidate), plus quiz Chobin-name convention. Original E502 family pixels themselves are gibberish with original COMM, so a different original consumer/codebook or inactive content must be investigated; they are not silently passed or removed. Selection marker counts may legitimately differ after V365 UI rewrite; semantic review does not interpret that alone as broken selection.','', 'The whole-game DAT UI universe is NOT proven complete by these legacy catalogs. Scanning arbitrary E5 bytes can hit binary/data; original VM consumer tracing is required for omitted bodies and suspect candidates. Entire tutorial effect/runtime/branch execution, all choices being reachable, current physical glyph8299C, and debugger labels are separate work. No game/canonical source changes made.']
(probe.AN/'dat_ui_review.md').write_text('\n'.join(text)+'\n',encoding='utf-8')
print(dict(totals));print('choices',len(choice),'markers',sum(e['original_choice_count'] for e in choice),'unique',len(set(e['original_hex'] for e in choice)))
