"""Serialize individually read semantic judgments; never infer PASS by similarity."""
from pathlib import Path
import csv
import json
from collections import Counter

HERE=Path(__file__).resolve().parent
BLOCKS={
'equipment_name':'''P|Flame protection: meaning preserved.
P|Ice protection: meaning preserved.
P|Anti-Hemoji: name and prevention concept preserved.
P|Healing charm: meaning preserved.
P|Silk belt: meaning preserved.
P|Magic card: meaning preserved. Final BC3195 matches native memory-card label exactly; source is CARD, not GUARD.
A|Sleepless card: functional translation as sleep-prevention card is acceptable. BC3195 is CARD, not GUARD.
P|Power arm: transliteration preserved.
P|Kaiser glove: transliteration preserved.
A|Phantom gauntlet: glove is a close functional rendering of kote.
P|Sunglasses: meaning preserved.
A|Scroll of how to hit: accuracy-scroll abbreviation preserves meaning.
A|Hurling scroll: throwing-scroll abbreviation supported by its explicit enhanced-throw description.
P|God's fist: meaning preserved.
D|Source Violet Racer (ree-saa) has unvoiced SA, but current Korean says Laser (reijeo).
P|Necklace: meaning preserved.
P|Juzu: correctly translated as prayer beads.
P|Elder's headband: meaning preserved.
P|Gale bandana: meaning preserved.
P|Hyper boots: transliteration preserved.
P|Makeshift shoes: meaning preserved.
A|Bracelet: suffix1 added to distinguish the two same-name source items with different effects.
A|Bracelet: suffix2 added to distinguish the two same-name source items with different effects.
P|Technique bracelet: meaning preserved.
P|Goddess's prayer: meaning preserved.
P|Power wrist: transliteration preserved.
D|Source Diiru fang is transliterated as Deil; the source vowel sequence is different.
P|Phantom beast fang: meaning preserved.
P|Sea-breeze melody: meaning preserved.
P|Seashell: meaning preserved.
P|Unicorn horn: meaning preserved.
P|Tragic spectacles: meaning preserved.
P|Mirror: meaning preserved.
P|Ancient ring: meaning preserved.
P|Phantom ring: meaning preserved.
P|Magic ring: meaning preserved.
P|Toy ring: meaning preserved.
P|Poison-ward ring: meaning preserved.
P|Phantom shield: meaning preserved.
P|Warrior's protection: meaning preserved.
P|Elder's shield: meaning preserved.
P|Powerful staff: meaning preserved.
D|Source jigoku no SCOPE is rendered as hell's SNOOP, a glyph misreading.
P|King's statue: meaning preserved.
P|Hawk statue: meaning preserved.
P|Imitation statue: meaning preserved.
P|Dagger: meaning preserved.
P|Phantom sword: meaning preserved.
D|Source Reira hair ornament is rendered as Rira, changing the proper name.
P|Turbulent jewel: the imagery is preserved.
P|Armor stone: transliteration preserved.
P|Romancing stone: transliteration preserved.
P|Romancing stone: source genuinely repeats the same name.
P|Romancing stone: source genuinely repeats the same name.
P|Romancing stone: source genuinely repeats the same name.
D|Source Sun HAT (boushi) becomes Sun MIRROR, changing the object type.
P|Pressed-flower book: meaning preserved.
D|Source Kuravisu book becomes Klaus book, changing the proper name.
P|Music collection: meaning preserved.
P|Lark crest: transliteration preserved.
P|Yukari crest: source sound retained; whether Yukari is a personal name is not assumed.
D|Source Furei crest becomes Pony crest, changing the proper name.
P|Hero's proof: meaning preserved.
P|Five question marks in both source and current; not an empty/untranslated slot.''',
'equipment_description':'''A|Resistance to flame attacks retained.
A|Resistance to water attacks retained.
A|Prevents Hemoji status retained.
A|Increases own HP recovery amount retained.
A|Doubles battle experience retained.
A|Magic power +10% retained.
A|Prevents sleep retained.
A|Chongara defense +30% retained.
A|Throw becomes level1 retained.
A|Attack +50% retained.
A|Prevents darkness retained.
A|Attacks become very accurate retained.
A|Throw changes to strong hurl retained.
A|Attacks stronger against specific enemies retained as additional damage.
A|Attacks always hit retained.
A|Increased maximum HP growth on level-up retained.
A|Gogen magic +30% retained; separate character-display swap does not invalidate this source owner.
A|Improved hit chance retained.
A|Agility +10% retained.
A|Agility +30% retained.
A|Jump becomes level1 retained.
A|Higher counterattack chance retained.
A|Catch becomes level1 retained.
A|Catch changes to throw-back retained.
A|Special ability MP consumption halved retained.
A|Attack +30% retained.
A|Iga counterattack damage increases retained.
A|Effect unknown in original too; not an omitted translation.
A|Kukuru heals surrounding characters each action retained.
A|Enemies become more likely to drop items retained.
D|Source says enemies ALMOST ALWAYS drop an item when defeated; current says RARE ITEM acquisition, changing probability into rarity.
A|Effect unknown in original too.
A|Prevents petrification retained.
A|Effect unknown with Arc owner retained.
A|Magic +50% retained.
A|Magic +30% retained.
A|Poco turn-around flute expands to whole map retained.
A|Prevents poison retained.
A|Defense +50% retained.
A|Defense +30% retained.
A|Improved guarding chance retained.
A|Gogen attack +70% is exactly the source owner/effect. Do not swap with description42.
A|Iga mind-eye technique range expansion is exactly the source owner/effect. Do not swap with description41.
A|Chongara receives summoned character experience retained.
A|Prevents silence retained.
A|Improved evasion retained.
A|Attack +10% retained.
A|Source explicitly says inflicted damage variation increases; current retains that statement.
D|Caster/recipient reversed: current says Kukuru RECEIVES resurrection with full HP; original code tests the CASTER'S equipment, giving her resurrected target full HP.
D|Damage variation is real but incomplete: equipment doubles variability also used in healing, including the recipient's contribution. Source general variation wording was narrowed to damage.
A|Defense +10% retained.
A|Effect unknown in original too.
A|Effect unknown in original too; repeated source entry.
A|Effect unknown in original too; repeated source entry.
A|Effect unknown in original too; repeated source entry.
A|HP recovery every action retained.
A|Tosh very high hit chance retained.
A|Prevents all status ailments retained.
A|Poco magic +30% retained.
A|Prevents paralysis retained.
A|Tosh cherry-blossom thunder strike gains paralysis retained.
A|Attacks stronger against specific enemies retained as additional damage.
A|Arc recovers MP every action retained.
P|Five question marks in both source and current; not an empty/untranslated slot.''',
'consumable_name':'''P|Sticky substance: meaning retained.
P|Motivation jelly: meaning retained.
P|Overflowing fruit: meaning retained.
P|Recovery fruit: meaning retained.
A|Numbing apple: paralysis apple preserves its function.
P|Stone: meaning retained.
P|Reko grass: name retained.
P|Medicinal herb: meaning retained.
D|Source is poisonous medicine (dokuyaku), current says poisonous HERB; source distinguishes it from medicinal herb.
P|Ruu medicine: name retained.
P|Agility medicine: meaning retained.
P|Small bomb: size retained.
P|Large bomb: size retained.
P|Universal medicine: meaning retained.
P|Holy water: meaning retained.
P|Resurrection medicine: meaning retained.
D|Source attack BOTTLE (bin) becomes attack JAR, conflating the vessel with summoning tsubo.
P|Sleep orb: meaning retained.
P|Weakening orb: meaning retained.
P|Power fruit: meaning retained.
P|Paro fruit: name retained.
P|Life-tree fruit: life fruit is faithful.
P|Magic leaf: meaning retained.
P|Magic spring: meaning retained.
A|Blinding grass: eye-obscuring grass preserves function.
P|Bitter leaf: meaning retained.
A|Stone-dissolving needle: petrification-removal needle preserves function.
A|Piercing needle: silence-removal needle deliberately uses its matching description effect as the name.
P|Summoning jar: meaning retained.
P|Five question marks retained from source.
P|Five question marks retained from source.
P|Five question marks retained from source.''',
'consumable_description':'''A|Temporary agility reduction retained.
A|Reverts Hemoji status retained.
A|Level1 increase confirmed by original code: sets next-level EXP threshold, then one level-up subtracts it to zero; level60 cap unchanged.
A|HP recovery60 retained, verified numeral in original pixels.
A|Paralysis prevents movement retained.
A|Thrown impact causes damage retained.
A|Defense increase retained; source does not say temporary.
A|HP recovery20 retained.
A|Spreads poison retained.
A|Removes paralysis retained.
A|Temporary agility increase retained.
A|Explosion retained as explosion damage.
A|Explosion expanded to large explosion using this same item's large-bomb name; no numerical claim added.
A|Recovers MOST status ailments retained, not incorrectly changed to all.
A|Removes poison retained.
A|Revives incapacitated character retained.
A|Temporary attack increase retained.
A|Induces sleep retained.
A|Temporary attack AND defense reduction retained.
A|Attack increase retained; source does not say temporary.
A|Agility increase retained; source does not say temporary.
A|Maximum HP +2 retained.
A|Magic increase retained.
A|Maximum MP +2 retained.
A|Spreading it causes blindness retained; source does not explicitly identify recipient here.
A|Temporary defense increase retained.
A|Reverts petrification retained.
A|Sealed magic becomes usable again retained.
A|Chongara uses this to summon monsters retained.
P|Five question marks retained from source.
P|Five question marks retained from source.
P|Five question marks retained from source.'''
}

def main():
    inventory=json.loads((HERE/'ui_inventory.json').read_text(encoding='utf-8'))
    inv={r['id']:(n,r) for n,r in enumerate(inventory)}
    mechanics={r['id']:r for r in json.loads((HERE/'equipment_mechanics_followup.json').read_text(encoding='utf-8'))['conclusions']}
    statuses={'P':'PASS_SEMANTIC','A':'ACCEPTABLE_ABBREVIATION','D':'CONFIRMED_DEFECT'}
    rows=[]
    for group,block in BLOCKS.items():
        lines=block.splitlines()
        assert len(lines)==(64 if group.startswith('equipment') else 32),(group,len(lines))
        for index,line in enumerate(lines):
            key,finding=line.split('|',1)
            rid=f'{group}:{index}';n,r=inv[rid]
            severity='none'
            if key=='D':severity='low'
            if rid in ['equipment_name:55','equipment_description:30','equipment_description:49']:severity='medium'
            if rid=='equipment_description:48':severity='high'
            evidence=f'Original COMM glyph sheet original_ui_{n//16+1:02}.png row{n+1}; pointer{r["pointer_offset"]}; original raw={r["original_hex"]}; actual current={r["current_korean"]}'
            if rid in mechanics:evidence+='; equipment_mechanics_followup.json: '+'; '.join(mechanics[rid]['evidence'])
            rows.append(dict(id=rid,status=statuses[key],severity=severity,finding=finding,evidence=evidence,
                             next_action='Review source-faithful correction proposal; user approval before canonical edits.' if key=='D' else 'No semantic change indicated; runtime/display validation remains separate.'))
    assert len(rows)==192 and len({r['id'] for r in rows})==192
    assert all('?' not in r['finding'] for r in rows)
    with (HERE/'equipment_review.csv').open('w',encoding='utf-8-sig',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
    counts=Counter(r['status'] for r in rows)
    lines=['# V375 equipment and consumable semantic census','',
           'All64 equipment names,64 equipment descriptions,32 consumable names and32 consumable descriptions were individually read against actual V375 decoded text and original COMM pixel sheets02..14. Every one of192 IDs occurs exactly once. Japanese nearest-glyph guesses were not accepted as proven source readings.','',
           'Baseline ZIP SHA256 AD9ED2B9E898F05C2EC5C78ABBA4253CE052B7B4836DEE31D84108AD4256CFBB.','',
           str(dict(counts)),'',
           'These are independent semantic judgments, not runtime release approval or user approval of new translations. PASS and acceptable abbreviation are kept separate. Source question-mark placeholders are preserved, not falsely counted as untranslated text.','',
           '## Confirmed differences','']
    lines += ['- '+r['id']+': '+r['finding'] for r in rows if r['status']=='CONFIRMED_DEFECT']
    lines += ['', '## Resolved mechanic questions','',
              'All three prior source/mechanic questions are resolved in equipment_mechanics_followup.json: equipment description48 caster/recipient reversal,49 healing variation omission, and consumable description2 one-level increase. Original/V375 code/data15 ranges are byte-exact; level arithmetic472 cases passed. This was disassembly and arithmetic, not a DuckStation playthrough.','',
              'Descriptions16/26/41/42 correctly name Gogen/Iga from original source; changing their owners to match swapped character labels would introduce new errors. Equipment names5/6 really end in CARD: rawBC3195 is identical to original memory-card labels and not GUARD.','',
              '## Output integrity','',
              'The initial CSV findings were damaged by Windows native stdin encoding. This replacement is serialized from UTF-8 apply_patch source with English individual judgments and original JSON-derived Korean current text. No semantic record remains question-mark corruption. The known five-question-mark source placeholders are intentional and excluded from that check. No game or canonical translation bytes were edited.','',
              'Reproduce: python 01_work/analysis/v375_full_audit/write_equipment_review.py','',
              'Next: review the12 correction proposals, follow all same-name references, then build/test the approved changes. Structural nontext corruption is tracked independently in nontext_pool_followup.']
    (HERE/'equipment_review.md').write_text('\n'.join(lines)+'\n',encoding='utf-8')
    print(json.dumps(dict(counts)))

if __name__=='__main__':main()
