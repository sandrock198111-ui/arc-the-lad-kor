# ASCII glyph-rule audit and repair

## Verified range

- Original COMM.IMG LBA 667 was read from the original disc only.
- Valid range: **indices 0..25**. Index 0 is a blank space; 1..25 are `!` through `9`.
- Rejected range: **indices 26..94**. Each is a visible Japanese/non-ASCII glyph, not the matching ASCII code.
- `script_original_full.csv` did not exist before `2109797`; each correction is instead proved against its retained raw bytes.
- Existing Korean authority: `32389d29da6b7870ffe449fb3e44811f0f4947f4`.

## Measured result

- Source rows returned to unresolved markers: 277
- Invalid ASCII substitutions returned to `<G:n>`: 562
- Actually encountered rejected indices: [89, 90]
- Fully glyph-decoded source strings (no `<G:`): 5,175/5,795
- Strings with neither unresolved glyph nor unresolved control marker: 1,856/5,795
- Remaining unresolved glyph indices: 107
- Remaining unresolved glyph occurrences: 1,425
- Korean cells cleared because these 277 source rows are untrustworthy: 76
- Non-empty Korean cells after this source-integrity repair: 1,959

No Korean wording was created, changed, or judged. No disc image, output archive, backup, ZIP, or emulator was touched.
