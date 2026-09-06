# V365 refusal follow-up — diagnosis only

User state HASH-477B29575D051C04_1.sav SHA256
928b7ed8a26389f858bb34e47b48e974284f654b1c5a0598d160b284bcaea6c0.
Header identifies V365_COMPACT_CHOICE_TEST; EXE anchor checks pass.

Active dialogue object 801F9D44: count39/limit64, D14/E16, final y96,
source pointer80112A56. Scene load base800CF000 maps this to S6054:43A56.
The actual inline body is 6/S6054.DAT:43A28..43A55 (46 bytes), ending00
at43A56. Its entire body/terminator is byte-identical to the original arc.zip.
The captured source tail matches V365 and the entire scene Bank-B matches V365.
Thus this is an unconverted original text stream consumed with the replaced
font, not evidence of a newly corrupted V365 payload or a stale older state.
Choice fields are (5,2,0,2); rendered object occupies five rows32/48/64/80/96.
It is not the previously corrected first prompt at4395A.

Existing script_original_full.csv has no row for43A28. The established extraction
start45000 excludes this reached text. A bounded even-address 19 00 candidate
scan of43000..44FFF finds many additional E6-bearing original-identical bodies,
including43A94,43AFA,43B4E and subsequent questions/choices. This scan is only
a candidate search: NUL/control boundaries and event reachability must be
validated before counting these as confirmed dialogue or changing them.

No game build, source CSV, state, original or binary was changed in this
diagnosis. Next scope: classify the below45000 event strings and choice branches
in this scene, extend the extraction/coverage manifest with proven consumers,
then propose an insertion/layout plan with glyph and storage budgets. Do not
claim corpus-wide completion from the existing2878-row corpus.

## Additional states 2 through 5

States2/3/4 reach original-identical, unconverted S6054 bodies43A94..43ABE,
43AFA..43B16,43B4E..43B64 respectively. These are further reached examples of
the same below45000 extraction omission, not just static candidates.

State5 source80114E4F maps to end45E4F of known corpus row1746/start45E2E.
Actual expanded Korean is `라마다 승려:  수행이 부족한 듯하구나. 다시|도전하도록 해라. `.
The canonical translation also contains this informal wording. Original text is
`修行が足りないようだ。出直してくるがよい。`, itself in a commanding rather than
polite register. Adjacent rows1743/1744 also say `인정하마/주마`; row1747 says
`잘하셨습니다/드리겠습니다` and its Japanese is polite. A same-speaker label
alone does not prove all these rows are the same individual/scene role.
This is a register-consistency review issue, distinct from the broken raw Japanese
streams in states1..4. No prose change or glyph/slot qualification was performed.
