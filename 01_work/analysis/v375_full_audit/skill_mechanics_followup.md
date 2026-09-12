# V375 skill and actor mechanics: final bounded findings

Primary source: original PSX.EXE in 00_original/arc.zip. Reproduce with `python 01_work/analysis/v375_full_audit/skill_integrity_followup.py`. No game or canonical edits.

## Allocation bounds and byte comparisons

Actor records: RAM8019E234/file83A34..85ADC exclusive,110 records*76=8360B. Consumer801748C4..80174938 indexes*76 and copies76B; next separately consumed table starts801A02DC. V375 differs61B: actor88 twelve,89 thirty-three,90 sixteen.

Action data: RAM801A02DC/file85ADC..872F4 exclusive=6168B, all byte-exact. This span contains257 physical24B records, NOT257 usable skills. Start/stride consumed801749A4; endpoint is next distinct growth table801A1AF4 consumed801740B8..C4. One-byte selectors cannot address index256; its usable reachability is not claimed. Other action consumers may use wider indices; that question remains outside this pass.

Selector pointer table RAM8019DE64/file83664..8381C contains110 pointers/440B, all byte-exact. Selector storage83404..83664 is608B, all byte-exact. Consumer80174B8C uses pointer[rank*8+slot], FF unavailable. Actor IDs>=150 remap by-50 in selector and stat consumers. Classifier8015DE20 identifies main0..7, enemies11..77, chests78..79, summons80..87, flame88, enemies>=150. Dark150..157 map records100..107. Do not enumerate108 display names*8*3 as valid skills.

## Actual rank domain and119 main combinations

All110 original source records have rank bytes+0C..13 zero. Companion integrity JSON enumerates all110 baseline selector rows, with raw non-FF slots explicitly separated from runtime availability. Rank-learning80174134..40 exits for non-main classes. Main learning pointers at801A1BE8 and loop801742B4..80174344 establish advancement.

Name-base consumer80162040..68 plus learning rows/action blocks gives main slot counts[5,7,4,8,7,6,0,8]. First37 skills have ranks0..2; Chongara8 have base rank:119 static combinations,119 selectors and119 complete action records equal. Starting threshold0 does not mean absent (Poco/event skills). Chongara slot7 is Choko although its learning pointer is sentinel. Unused main slots can overlap adjacent raw action data; non-FF alone is not a learned skill.

Earlier provisional suggestion that actor82 might not be Mofri because an online guide says MP8 is withdrawn. Original classifier/descriptor mapping supports Mofri82, whose original action194 MP is6. Guide disagreement does not override binary evidence. All actual scene/save actor instances and nonbaseline rank mutations remain unenumerated.

## Mind-eye semantic defect resolved

Iga5 slot0 actions167/173/179 have MP2/4/6. Record+16h=3 becomes radius2 in80170028..68. Shape1 diamond loop801701C4 tests Manhattan distance at80170224 and marks every qualifying map cell8000 at80170270.

Initializer8012176C uses table8018FB6C[actor] -> pointer -> descriptor; descriptor+4 becomes actor+C0. Dispatcher80121934 indexes that command table by actor+A8. Iga table80193224[26h] -> sequence801A8040 -> callback8012EBA8. Callback calls80123270, whose80128004 collector gathers every eligible actor on marked8000 cells. Loop8012EBE4..8012EC04 sets actor+B2 bit8000 for EVERY returned target.

Original CPU marking-loop test with two synthetic list entries changes0003/0020 to8003/8020, without helper mocks. Current description32's one-enemy restriction is CONFIRMED_DEFECT. Main226 semantic ledger updated:180 PASS,8 acceptable abbreviation,18 empty,17 confirmed defects,3 unresolved wording judgments.

## Heat Wall: spawn proven and separate actor88 regression

Gogen4 slot4 -> command2Ah/table80192D38 -> callback8012DCDC. Count check801286F4(88) limits flames; continuation8012DD68 calls80121438 to spawn actor88 at selected tile. Thus flame creation is proven. Whether Korean barrier wording conveys its rendered/collision behavior is still a separate semantic judgment.

V375 actor88 source file85454 has12 changed tail bytes. Status halfword+4A/file8549E changed0000 to008A by Korean text bytes. Actual typed-copy path801748C4 loads it. Actual full stat refresh80174BE0 preserves it. Descriptor88 init801237D8 only sets actor+C4/C8/CC and does not restore stats. Command0 is801219FC, which reads that status.

Bounded CPU test executes real copy beginning801748E8, then full80174BE0 refresh, then801219FC status dispatch. Original0000 -> normal80121A6C; V375008A ->8012196C with command30 (first set status bit1). This is confirmed behavior divergence, not merely a loaded unused field. Exact visible gameplay consequences are not claimed.

The CPU copy probe explicitly starts after the BIOS memset helper with fresh zero scratch RAM. Initial BIOS-dependent attempts did not return correctly and were discarded; final runs assert return PCs. No BIOS stub pretends successful execution.

Actor89/90 changed33/16 bytes and contain nonzero original typed data. Their outer descriptor pointers areNULL, so ordinary spawning has no valid descriptor. No scene/save instantiation was proven: classify ownership/integrity gaps, not confirmed playable bugs.

## Floor creation: terrain write proven, wording open

Mofri82 slot0 -> table80193494[26h] -> sequence801A8088 -> callback8012EF0C. Continuation8012EF7C converts selected world coordinates and calls8011E158(x,y,03FFh). This bounds-checks and writes one map-cell halfword. Reader8016E314 interprets its low12 bits through the map terrain lookup.

This proves one terrain-cell alteration, not a bridge actor. Source says floor. Whether bridge is a valid functional paraphrase requires relevant map tile03FF visual/passability evidence or gameplay. Thus name47/description47 remain explicit unresolved wording judgments with description29. No original source row is unread.

## Odon pointer cross-investigation

Outer table8018FB6C entry85 ->801A7D88 ->descriptor801A80F8 ->Odon command table80193974. Damaged file79210 is command27h/slot1, original selectorCF, callback8012F2F8. Equipment investigator owns current BSS-pointer regression proof. This is Odon's transformed-monster special, not Iga or event dispatch.

## Limits

Table equality does not prove callback/code integrity; Odon demonstrates why. This work covers allocated table comparisons, baseline slot/rank domains, specific callback paths, and bounded CPU copy/refresh/mark/dispatch. It does not prove every actual actor instance, whole-game emulator completion, full visual behavior, all saved ranks, or absence of other code damage. The257 count is physical allocated records only; report6168B integrity and119 main combinations separately.
