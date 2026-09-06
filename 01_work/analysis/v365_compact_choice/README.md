# V365 compact priest choice — TEST_ONLY

User approved removing excess speaker spacing and raising the choices together.
Scope: only `6/S6054.DAT:0x4395A`, not all V364 speaker joins.

## Cause and correction

V364 replaced the first E6 01 with two visible A1 spaces. Together with the
existing speaker space this produced three spaces after the colon. The prompt's
remaining A1 filler crossed the 228px wrap boundary before the explicit newline.
The separate choice event still specified baseRow 2. This was a patch artifact,
not evidence of intentional layout for a later visit.

- Prompt is exactly `승려: 수행하러 오셨습니까?` with one space after the colon.
- Scene-owned Bank-B slot 23 at 0x4D80 holds the prompt, terminated before metadata.
  Caller E2 E8 at 0x4395A uses completion 22, resuming at original E6 0x43972.
- Original E5 indentation, choice strings, NUL and following event addresses stay
  byte-exact. At 0x43996 only baseRow changes 2 to 1.
- No EXE, font, title, shared triangle, other DAT, CSV or uploaded state changes.

Slot ownership: the original complete Bank-B 0x4200..0x4FFF is zero and its
scene-owned allocation/loader was established by V355/V356. Current slot23 is
zero. Raw E2 E8 occurrences at 0x17B21/0x24687 are unchanged original non-script
binary data, not new callers; no such pair occurs in the current script region.
This is reuse of the established Bank-B pool, not a generic zero-run allocation.

## Tests

- Pinned V364 ZIP A4C43D7BE52CDEE4182ADF7580604BC86A7D4D883C7D6D85CD6E0DD60C31C122.
  Original arc.zip AE9F4366A1E7DA3805BB3BED3DDA9567E4CD4E669AF890E4E2A620D7861F11DD.
- Expected-write preflight and whole-archive byte envelope; identical second
  in-memory ZIP generation; missing glyphs rejected; inherited failures do not grow.
- State7/8 scene Bank-B and prompt bytes match pinned V363 input.
  In-process RAM-only tests apply final changed bytes and execute actual E2
  lookup/completion, event reader 8015C48C and coordinate producer.
- Reader 8015D7D0 reads signed halfwords from table 80112800. Index C6 feeds
  event type6/count4, producing fields (5,2,0,1), final index CC. Selection index,
  count2, column0 and downstream event boundary are preserved.
- E2 resolves 800D3D80 and completion resumes 80112972. Four coordinate cases
  return cursor top (60,50)/(60,66); text model origins (74,48)/(74,64).
- Text layout model: three occupied rows, no blank row, output count under64.
  This is not full GPU/text-loop or interactive navigation verification.
- Fresh original staging: all506 data LBAs and164 patched member readbacks PASS;
  all507 extents/sizes unchanged. 29 changed raw sectors, 58 old/new EDC/ECC checks,
  no unexplained payload changes beyond the three DAT writes and ISO timestamps.

Harness fixes: encoder returns (bytes, missing), not bytes alone; initial call
failed before output and was corrected. Unicorn end-address stop at a cached
branch boundary left PC at the preceding instruction; an explicit code hook now
verifies actual arrival at each stop address. No game code was changed for tests.

## Outputs and reproduction

- ZIP `03_output/arc1_v365_compact_choice_TEST_ONLY.zip` SHA256
  28EEE68677DB124D91550CF89B2EF437B1CE728686011CA79B419FA1DAB27764.
- BIN `03_output/V365_COMPACT_CHOICE_TEST.bin` SHA256
  9BBD07FA34F6B644E4A685A0DA70ADD2F20B5B125B5DB43777423A4B8270987D.
- CUE `03_output/V365_COMPACT_CHOICE_TEST.cue`.

Run with `python -X utf8 02_scripts/` plus, in order:

1. `build_arc1_v365_compact_choice.py`
2. `verify_arc1_v365_compact_choice.py`
3. `package_arc1_v365_compact_choice.py` (refuses overwriting an existing disc)
4. `verify_arc1_v365_disc_delta.py`

Remaining: cold boot and enter/re-enter this priest conversation; select both
answers, test top/bottom movement, cancellation/confirmation and clearing. Loading
an old mid-dialogue save retains old DAT/globals and is not new build verification.
Other V364 speaker-spacing cases remain outside this focused change. Bible current
success baseline was reviewed and retained pending user runtime confirmation.
