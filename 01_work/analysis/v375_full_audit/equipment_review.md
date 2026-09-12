# V375 equipment and consumable semantic census

All64 equipment names,64 equipment descriptions,32 consumable names and32 consumable descriptions were individually read against actual V375 decoded text and original COMM pixel sheets02..14. Every one of192 IDs occurs exactly once. Japanese nearest-glyph guesses were not accepted as proven source readings.

Baseline ZIP SHA256 AD9ED2B9E898F05C2EC5C78ABBA4253CE052B7B4836DEE31D84108AD4256CFBB.

{'PASS_SEMANTIC': 81, 'ACCEPTABLE_ABBREVIATION': 99, 'CONFIRMED_DEFECT': 12}

These are independent semantic judgments, not runtime release approval or user approval of new translations. PASS and acceptable abbreviation are kept separate. Source question-mark placeholders are preserved, not falsely counted as untranslated text.

## Confirmed differences

- equipment_name:14: Source Violet Racer (ree-saa) has unvoiced SA, but current Korean says Laser (reijeo).
- equipment_name:26: Source Diiru fang is transliterated as Deil; the source vowel sequence is different.
- equipment_name:42: Source jigoku no SCOPE is rendered as hell's SNOOP, a glyph misreading.
- equipment_name:48: Source Reira hair ornament is rendered as Rira, changing the proper name.
- equipment_name:55: Source Sun HAT (boushi) becomes Sun MIRROR, changing the object type.
- equipment_name:57: Source Kuravisu book becomes Klaus book, changing the proper name.
- equipment_name:61: Source Furei crest becomes Pony crest, changing the proper name.
- equipment_description:30: Source says enemies ALMOST ALWAYS drop an item when defeated; current says RARE ITEM acquisition, changing probability into rarity.
- equipment_description:48: Caster/recipient reversed: current says Kukuru RECEIVES resurrection with full HP; original code tests the CASTER'S equipment, giving her resurrected target full HP.
- equipment_description:49: Damage variation is real but incomplete: equipment doubles variability also used in healing, including the recipient's contribution. Source general variation wording was narrowed to damage.
- consumable_name:8: Source is poisonous medicine (dokuyaku), current says poisonous HERB; source distinguishes it from medicinal herb.
- consumable_name:16: Source attack BOTTLE (bin) becomes attack JAR, conflating the vessel with summoning tsubo.

## Resolved mechanic questions

All three prior source/mechanic questions are resolved in equipment_mechanics_followup.json: equipment description48 caster/recipient reversal,49 healing variation omission, and consumable description2 one-level increase. Original/V375 code/data15 ranges are byte-exact; level arithmetic472 cases passed. This was disassembly and arithmetic, not a DuckStation playthrough.

Descriptions16/26/41/42 correctly name Gogen/Iga from original source; changing their owners to match swapped character labels would introduce new errors. Equipment names5/6 really end in CARD: rawBC3195 is identical to original memory-card labels and not GUARD.

## Output integrity

The initial CSV findings were damaged by Windows native stdin encoding. This replacement is serialized from UTF-8 apply_patch source with English individual judgments and original JSON-derived Korean current text. No semantic record remains question-mark corruption. The known five-question-mark source placeholders are intentional and excluded from that check. No game or canonical translation bytes were edited.

Reproduce: python 01_work/analysis/v375_full_audit/write_equipment_review.py

Next: review the12 correction proposals, follow all same-name references, then build/test the approved changes. Structural nontext corruption is tracked independently in nontext_pool_followup.
