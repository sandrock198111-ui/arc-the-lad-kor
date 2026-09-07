# V368 Sans font comparison — TEST_ONLY

2026-09-07. User requested the current version remain frozen and a separate Sans test.
No release-number increment or baseline promotion. Current Thin V368 files are untouched.

## Inputs and scope

- Frozen `arc1_v368_linebreaks_TEST_ONLY.zip`: `00A55D88117F614FD2CC30BED097AD27DD93D84A59F87C698043A93DF5431416`.
- Original `00_original/arc.zip`: `AE9F4366A1E7DA3805BB3BED3DDA9567E4CD4E669AF890E4E2A620D7861F11DD`.
- User-supplied `8x4x4-fonts-all.zip`: `31084434DC45D383B21A8A3BE10A47869BB31E92D7C2C5AEEF91BD439D956A78`.
- `Sans_8x4x4.ttf`: `A630598E7ACAB70DC6C6AC4D46DE59CEF25EF61A2FEEC439E8B25C7DDBA05726`.
- 360 component raster SHA: `2D5F23E2A66ACF6DE92CC475ED1D1A524554EC26B695E4CD1B63913468CCCBFF`. Existing 16px/threshold96/official-beol composition, unchanged cell and advance.
- Same 723 runtime Hangul planes / 690 unique syllables; same V336/V337 aliases. No glyph-slot additions, remapping, dynamic cache, new VRAM or executable edits.
- The frozen Thin ownership is verified for all targets, including its local 에-family and 예 repairs. Sans is composed from its own stock pieces, not passed through Thin-specific corrections.
- Only COMM.IMG changes, 17149 bytes. Every changed bit belongs to an authorized Hangul plane. Other 163 members, title, digits, icons, native damage bank, non-target planes and margins are identical.

## Reproduce

Run with the external archive path (do not commit the font or original assets):

```powershell
python -X utf8 02_scripts/build_arc1_v368_sans_font.py <8x4x4-fonts-all.zip>
python -X utf8 02_scripts/verify_arc1_v368_sans_font.py <8x4x4-fonts-all.zip>
python -X utf8 02_scripts/package_arc1_v368_sans_font.py
python -X utf8 02_scripts/verify_arc1_v368_sans_disc_delta.py
```

The font build verifies the V368 reproduction through its existing builder before applying a planned bit-plane delta to an in-memory copy. Historical frozen patch archives and mapping CSVs remain explicit dependencies; this is not a claim that the entire translation can be rebuilt solely from the original and current CSV. The disc packager extracts a fresh original tree in `01_work/package_v368_sans_font`; no prior BIN is used as build input. Packager refuses existing disc outputs.

## Results

- ZIP `03_output/arc1_v368_sans_font_TEST_ONLY.zip`: `B2B37F0FB06A5E63BA221A0F2BCE0E9E8B5D341932B9CDA7CDE7FFEF987E1DC6`.
- BIN `03_output/V368_SANS_FONT_TEST.bin`: `1B6129A322E000C11CD5239F4BE3FFCB5FF288CEBBB97DB17E63E8E95BEE093F`.
- CUE `03_output/V368_SANS_FONT_TEST.cue`.
- Same-input ZIP reconstruction byte-exact. Independent verifier checks all 1920 planes, raster identity, zero empty target glyphs, zero identical-bitmap collisions among 690 syllables, exact changed-byte plan, and every non-target COMM bit.
- Disc: all 506 data LBAs preserved, 164 patched members read back exact, 507 extents/sizes equal to V368. 132 changed raw sectors permitted only by font bytes and ISO record timestamps; 264 old/new EDC/ECC checks pass; no unexplained payload changes.
- Frozen Thin BIN rehashed unchanged: `5105DBA350947FFC97E0FF242B1A2C309E9F1932A22C22D29E44339F73DD76B6`.

## Limits and next check

This is a local comparison build, not a release. No new GPU/cold-boot execution or whole-game readability claim. Zero exact bitmap duplicates does not prove all similar glyphs visually distinguishable. The historical Sans 12px issue does not establish failure of this 16px raster.

Cold boot this CUE and compare dialogue, choice text and item/battle UI. Old emulator savestates contain old font VRAM; use reset plus memory-card loading to inspect the new font. Do not overwrite user savestates or cards. All V368 unresolved translation approvals and prior testing limits remain inherited.

The supplied archive has no embedded license/readme entry; no font source, binary or patch archive is committed or publicly redistributed. Redistribution requires separate license verification. Current `bible_current.txt` success baseline is deliberately not promoted; changelog/test_log/codex_notes record only this comparison and verified facts.
