# V375 skills and character names: final 226-row semantic review

Baseline ZIP SHA256 AD9ED2B9E898F05C2EC5C78ABBA4253CE052B7B4836DEE31D84108AD4256CFBB.
All59 skill names,59 descriptions and108 character names were read individually and compared with original Japanese glyph pages14..28. Historical nearest-glyph OCR was not treated as source authority. See CSV for every row, including unchanged and empty records.

{'EMPTY_PLACEHOLDER': 18, 'PASS_SEMANTIC': 180, 'ACCEPTABLE_ABBREVIATION': 8, 'CONFIRMED_DEFECT': 17, 'NEEDS_SOURCE_CONFIRMATION': 3}

## Confirmed text defects

- skill_name:43 [LOW]: Original Odon rendered Oton: voiced DO misread as TO; same discrepancy in character85/description43
- skill_name:56 [LOW]: Original Dust Ruin rendered Dust Rune; distinct ruin/rune name lost
- skill_description:20 [LOW]: Original fires many bombs AT ONCE; current says consecutive fire, changing simultaneous to sequential animation
- skill_description:24 [MEDIUM]: Original EVERYONE FACES SAME DIRECTION AS POCO; current invents Poni and says toward Poni direction, losing same-facing relation
- skill_description:32 [MEDIUM]: Original locks every eligible enemy in a radius-2 target area; current one-enemy restriction is false. Original target collector and marking loop both iterate all matching actors.
- skill_description:33 [MEDIUM]: Original explicitly shoots light at enemies locked by MIND-EYE TECHNIQUE; current omits named prerequisite skill
- skill_description:37 [MEDIUM]: Original removes enemies A CERTAIN AMOUNT WEAKER THAN SELF; current weak enemies omits relative-strength condition
- skill_description:43 [LOW]: Original summons Odon; current Oton repeats voiced DO misread from name43/character85
- character_name:4 [HIGH]: Original Gogen ID4 currently Iga: identities exchanged
- character_name:5 [HIGH]: Original Iga ID5 currently Gogen: identities exchanged
- character_name:15 [MEDIUM]: Original NINJA rendered Ganja: species name misread
- character_name:35 [MEDIUM]: Original SUPER SHINOBI rendered SUPER ZOMBIE: different monster identity
- character_name:62 [MEDIUM]: Original STUN GOLEM rendered STONE GOLEM: modifier changed
- character_name:72 [MEDIUM]: Original KO ABIS rendered NI ABIS: KO misread as NI
- character_name:85 [LOW]: Original ODON rendered OTON: voiced DO misread; also name43/description43
- character_name:104 [HIGH]: Original DARK GOGEN rendered DARK IGA: ID4/5 swap propagated to dark counterpart104
- character_name:105 [HIGH]: Original DARK IGA rendered DARK GOGEN: ID4/5 swap propagated to dark counterpart105

## Three remaining semantic judgments

Original code now confirms that Heat Wall creates flame actor88 and Floor Creation writes terrain tile03FF. This narrows the open issue to whether Korean barrier/bridge descriptions accurately convey the visual/functional result; no source row is unread.
- skill_name:47: Original floor creation translated bridge creation; narrower construction meaning needs original gameplay evidence
- skill_description:29: Original creates a mass of flame; current says flame BARRIER. Shape/obstruction claim needs original effect evidence
- skill_description:47: Original creates FLOOR in inaccessible places; current bridge claims narrower structure. Confirm original placement effect

## Verification limits

skill_description32 was resolved by original code: target-area diamond, collection of every matching actor, and an actual two-target CPU marking loop. Names29 and47 remain translation-judgment questions because this pass did not execute the full flame/terrain visual behavior.
Additional binary integrity results are in skill_integrity_followup.json/.py and skill_mechanics_followup.md. In particular, a distinct flame-actor status corruption is confirmed by bounded CPU copy/refresh/status-dispatch and must not be confused with the wording judgment for description29.
PASS_SEMANTIC is not runtime, renderer or emulator approval. No MP claims occur in these118 skill strings. Main-character skill matrix119 is only one subset; the expanded allocation checks cover257 action records and110 actor records with explicit runtime-domain limits. Game and canonical translations remain untouched. Only audit artifacts changed.
