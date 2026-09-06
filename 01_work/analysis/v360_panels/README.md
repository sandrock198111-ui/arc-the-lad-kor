# V360 UI restoration — TEST_ONLY

2026-09-06. Static/CPU/disc checks passed. **Cold-boot GPU/gameplay pending.**
Latest user-confirmed symptom fix remains V359_CURSOR_LINES_TEST.

## Output and scope

- `03_output/V360_UI_RESTORE_TEST.cue` + `.bin`
- `03_output/arc1_v360_ui_restore_TEST_ONLY.zip`
- ZIP SHA256: `9235BCB75903A00477E69BC47713D200E8BAE4C37AFDDDA83EF1878D07441731`
- BIN SHA256: `258203E47E57D04DD2ECE5285BC547B3D9CB3AA893519A8AE11C9BF513F680C7`
- Old builds, original archive, user states and `dialogue_all.csv` were not overwritten.

Item and skill panels both use 200×46 px. Shared description area is 184×34,
16px sprites with 18px row pitch. A sprite extends 2px beyond its 14px advance;
the tested outer horizontal margin remains at least 6px. Item text Y=116/134,
skill text Y=109, skill MP label Y=133. Equipment/consumable inventory positions
are adjusted so the widened panel remains inside 320px at all three anchors.

All 96 item/equipment descriptions were compared with the original source
table. Twenty-three descriptions restore omitted conditions, recipients,
effect strength or HP/MP distinctions. Original COMM glyph rendering resolved
extraction errors for these targets; an independent translation review was
followed by root inspection of original glyph sheets. The authoritative delta
is `02_scripts/v360_ui_targets.py`; historical `ui_full_v42.csv` is unchanged.
The other 73 item descriptions retain their actual V359 bytes. Equipment
description 49's original wording does not explicitly identify damage; its
existing wording is retained, not asserted to be newly validated.

The actual UI pointer at EXE file 0x82360 now selects
`L과 R로 다음 대상을 선택합니다.` The earlier DAT help fixes alone did not change
this consumer. No L/R icon textures or missing slash glyph are introduced.

Dialogue 2873: original rendered glyphs read `山に登るのは別の用じゃ。`, not the
extracted `帰る`. Translation now says `산에 오르는 건 다른 볼일이 있어서다.`
Its owned E2 slot 0 and skip/caller are preserved. V358 had already externalized
the whole row and reflowed its original E6; this build does not remove another
active control. Dialogue 1634 becomes `이것 봐! 「방향전환 피리」를 얻었어!`, retaining
the E6 between its two source spans. Existing Bank-A slot 2 is reused and a
previously unreferenced, planner-qualified Bank-A slot 3 is assigned to the
second span; E2 84 raw callers are 0 before / 1 after, with return skip 18.
Only these two Korean cells are synchronized to the canonical CSV; the user
export and Japanese source columns stay unchanged. CSV backup is in
`99_backup/v360_ui_restore_20260906/` (local only).

## Storage and regression limits

No new VRAM, resident RAM reservation or glyph. The confirmed cursor build
disabled the RLE uploader and its old frame gate. Reuse starts after its current
328-byte cursor implementation, at RAM 0x801FF5D0. Of the retired RLE suffix's
648 bytes, 590 hold a 28-byte description-only line-spacing helper and new UI
strings; 58 bytes remain unchanged. The live numeric helper at 0x801FF858..
0x801FF8AF and the old cursor implementation remain byte-exact. Boot copy size
0x14EC and heap boundary 0x801FF8B0 are unchanged. This is not a claim that a
new zero-filled region is free. All non-target old strings are retained.

The spacing entry hook is restricted to the shared item/skill description
function 0x8016C760. It sets only that object's line_extra, reproduces both
displaced instructions and resumes at 0x8016C768. Other help group memory is
unchanged in both constructor and renderer tests.

## Verification and reproduction

1. `python -X utf8 02_scripts/audit_arc1_v360_panels.py`
2. `python -X utf8 02_scripts/render_arc1_v360_sources.py`
3. `python -X utf8 02_scripts/build_arc1_v360_ui_restore.py`
4. `python -X utf8 02_scripts/verify_arc1_v360_ui_restore.py`
5. `python -X utf8 02_scripts/package_arc1_v360_ui_restore.py`

Requires the hash-pinned original and V359 baseline, historical codec inputs,
the two supplied F5D974ADD31760 states, and local Capstone/Keystone/Unicorn.
Binary/font artifacts are intentionally not in Git. Package step refuses an
existing output. Builder reruns require byte-identical existing archive members.

- Instruction identity guards, helper disassembly/assembly round-trip, exact
  write coverage, archive member sizes/topology, and non-target strings pass.
- 346 actual renderer CPU conditions: 96 items at three positions and 58 skill
  descriptions; one empty skill-0 placeholder is excluded from printing.
  All expected packets emitted, <=32 per description, within panel margins.
- 634 callee-saved/stack checks. Other help group and resident payload unchanged.
- MP prefix/label executes at (66,133). The BIOS formatting call and blue orb
  are not executed by this RAM-only harness; their live appearance remains QA.
- Inherited cursor test passes 1,152 conditions (9 modes ×128 frames).
- Canonical delta is exactly rows 1634/2873. Other dialogue in the two touched
  DAT files preserves expanded tokens. No active control changes.
- Two archive builds agree byte-for-byte. Disc data LBAs 506/506 unchanged,
  164/164 patched members read back exactly; EXE remains 587,776 bytes at LBA268481.
- Legacy checker still reports the identical 2 marker and 69 choice-width
  failures. This is not a full release pass and not zero-risk certification.

## Required user test

Cold boot the new CUE, then load a memory-card save (not an old quick-state).
Check item descriptions in both inventory columns and in battle, repeated
switching between one/two-line items, skill MP digits/orb and name banner,
L/R selection/help, reward dialogue, and mountain continuation. Recheck slime,
large attack ranges, screen-edge cursors and menu reentry. No numerical
regression probability is justified by the available coverage.

## Failed checks during development

- Initial packet oracle demanded 8px right margin without the 2px sprite
  overhang; existing equipment #30 revealed the actual 6px minimum. The test
  now checks real sprite bounds against that explicit outer margin.
- Calling the text renderer on the null skill-0 placeholder emits a packet;
  it is not a real description and is excluded explicitly, not silently counted.
- Extending the MP CPU block through BIOS sprintf caused an unmapped fetch.
  No BIOS stub or assumed numeric result was substituted; coverage ends before
  formatting. These failures did not generate or overwrite a game image.
