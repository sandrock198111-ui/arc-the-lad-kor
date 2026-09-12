# V375 nontext pool gap census

Every differing byte in original EXE file78000..82FFF, original/current catalog footprint masks; masks are triage, not proof of text semantics.

Changed bytes: 9054. Four confirmed structural-change groups / 7 altered bytes, all with proven nontext consumers. All 96 equipment/consumable attribute records are byte-exact.

## nontext:79210 / CONFIRMED_DEFECT

Action-handler table pointer 801A80E0 -> 801AE7E0; only byte79211 changed. Original destination is an 8-byte handler record whose first word is function8012F2F8. Current destination is outside the loaded EXE payload.

Outer table8018FB6C actor85 ->801A7D88 ->801A80F8; initializer8012176C..217A4 reads descriptor+4 ->80193974 into actor+C0; command0x27 ->80193A10/file79210. 80121934..21960 dereferences selected handler record into actor+D4;8012198C executes it. Original handler8012F2F8 is replaced with whatever word is in BSS801AE7E0. Actor85 is Odon according to the sibling actor/skill census; actual game trigger pending.

## nontext:7C1C0 / CONFIRMED_DEFECT

Sprite descriptor texture/page field changed 01E0 ->9CE1. It is not a text glyph.

8014C840 passes descriptor801969B8 to80132204; 8013225C reads descriptor+8; low6bits changes0x20->0x21; 80132268 shifts2 and stores object+2C. 80132328 also reads this field for texture setup. Exact on-screen effect remains untested.

## nontext:7E0D0 / CONFIRMED_DEFECT

Sound/voice ID480 becomes signed -25375 and is rejected by the range guard, suppressing that sound entry.

8015572C maps char index3, action state0x42 to table80198888+2*(3*10+6)=801988D0. 8015579C loads signed halfword; 801557C0 calls801298D0; 80129880 sltiu ID<0x232 rejects0xFFFF9CE1. No out-of-bounds sound lookup occurs because guard returns0.

## nontext:7E7FC / CONFIRMED_DEFECT

Color-animation first RGB key changes (224,48,48) to(225,210,48), corrupting the red transition color.

8015BEBC uses pointer bank801990B0, index7 ->pointer801990CC/file7E8CC ->80198FFC/file7E7FC; 80152C40 stores keyframe pointer object+58; 80152D24 uses stride8; +4 duration60,+6 flags3; 80152E18 interpolates RGB; 80152E34/38/3C and80152F14/18/1C consume RGB. Actual story trigger of bank index7 not traced.

## Cause and lineage

Color change first appears in V178 relative to its direct V177 base. V178 scans glyph-looking pointer targets and accepts the color keyframe as text. The three other changes are intact in V229 and damaged by available V231. V231 text_regions treats every NUL-separated nonempty run of EXE78000..83000 as text, including pointers and numeric data. Full values and EXE hashes per available build are in JSON. V159 had a different earlier color rewrite that V161 removed; do not confuse that repaired occurrence with V178 reintroduction.

The icon table at80210..80221 is deliberately changed; exclude its five differing U bytes from the corruption count. The four structural groups contain 1+2+2+2=7 differing bytes. No ROM or canonical data changed.

## Scope limits

This is a complete byte-difference census for the declared 0xB000-byte pool, not a claim that every unknown original data type has been proven safe. CSV retains every changed byte and every unresolved residual explicitly. Attribute integrity covers all64+32 entries, not every downstream effect or name-consumer mapping in the game. Existing 192-row semantic review and mechanic followup handle translation discrepancies independently.

Next: parent should prove actual event reachability and perform CPU/game regression tests, then approve concrete byte restoration together with broad text-region exclusion. Reproduce with python 01_work/analysis/v375_full_audit/audit_nontext_pool.py.
