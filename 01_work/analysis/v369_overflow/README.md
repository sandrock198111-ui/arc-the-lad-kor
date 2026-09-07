# V369: reported slot1 overflow fixed; slot2 stall still open

2026-09-07. User requested cause and repair of two uploaded states. Only slot1 has a demonstrated cause and repair. This is NOT a claim that slot2 is fixed.

## Evidence

`audit_arc1_v368_followup.py` reads uploaded folders `722b5e3d-666d-4150-ad84-e3a5a05d0d74` (slot1) and `0aab59e5-6068-421e-b886-5bfa43d9365e` (slot2), preserving input states. Local evidence is `01_work/analysis/v368_followup/states.json`, thumbnails and `overflow_trial.json`; these state-derived assets are not committed. Both states identify V368_SANS_FONT_TEST and match all 723 Sans Hangul planes. Whole COMM VRAM is not byte-identical because other runtime consumers can update its regions; it is not a font identity test.

Slot1 is #1552, `6/S6013.DAT:4834E..48388`, source termination `80117389`. Portrait window origin (94,32), width180, glyph advance14/row16, limit64. Captured count59 and actual rows32/48/64/80/96 are reproduced by the existing renderer in Unicorn from a RAM copy. The first phrase already wraps into two lines, then ten padding spaces and an explicit E601 separate it from the three-line E2 tail. This creates five lines even below the 64-packet limit.

An initial theory that the ten spaces alone caused the overflow was rejected: removing those while retaining E6 still produced five lines. Final fix removes the forced break too, joining with one space. No words are shortened or replaced.

## Changes

- Preserve all bytes except a 14-byte local span `48361..4836E` and Bank-A0 completion byte `4507F`.
- Move the sole E281 caller from4836D to48362, replace displayed padding/E6 with one space, increase completion26→37. Both old and new return to the same NUL at48389; following events are exact.
- There is one raw E281 caller in this DAT's script tail, and the CSV corpus identifies that same #1552 caller. No new slot or shared caller change.
- Actual final diff: seven bytes in one DAT. Other163 members, Sans COMM, EXE, cursor code, UI and title are exact V368 Sans. Old V368 Thin and Sans outputs remain untouched. Canonical CSV wording is unchanged.

## Verification and reproducibility

```powershell
python -X utf8 02_scripts/audit_arc1_v368_followup.py
python -X utf8 02_scripts/verify_arc1_v368_overflow_trial.py
python -X utf8 02_scripts/build_arc1_v369_overflow.py
python -X utf8 02_scripts/package_arc1_v369_overflow.py
python -X utf8 02_scripts/verify_arc1_v369_disc_delta.py
```

CPU intervention changes only the local caller and its actual captured Bank-A RAM at114000, then invokes B880/B8C8 in a copy. It proves renderer termination, output rows and pointer semantics, not physical input, GPU or whole-event execution. First trial incorrectly assumed Bank-A atCF000; the premise assertion failed before any game output. Searching the pinned payload confirmed114000, also consistent with the captured source payload pointer. No savestate was patched.

Before:59 packets/5 rows; after:50 packets/4 rows Y32,48,64,80; exact source termination80117389; same nonspace wording. Automatic wrapping can still split a word and start the fourth row with a space; natural whole-game typesetting is not claimed.

Builder checks immutable baseline, exact expected bytes, allowable writes, member sizes and repeatable archive bytes. Disc built from fresh original staging, not an old BIN. Existing historical archive dependencies remain; no original-only whole-translation rebuild claim. 506data LBAs,164member readbacks,507extents/sizes pass. 29raw sectors changed only in permitted font-independent DAT bytes/ISO timestamps;58old/new EDC/ECC checks pass.

- Base ZIP SHA `B2B37F0FB06A5E63BA221A0F2BCE0E9E8B5D341932B9CDA7CDE7FFEF987E1DC6`.
- Output ZIP `arc1_v369_overflow_TEST_ONLY.zip`, SHA `58692673A78F425A206814B7C7193A69E7FAD41CD2A755E9AF5F13BB429EF69F`.
- CUE `03_output/V369_OVERFLOW_TEST.cue`.
- BIN SHA `7D33BF57E5B10D6353D05721D9FA23FEBD1262C97FEA6A50903DCD37032A855D`.

## Slot2 open investigation

Thumbnail shows a black screen with a location banner, no active dialogue packets. Loaded script is7/S7021.DAT; region47800..49800 matches the build. Global script index has low16=0E1C, corresponding to49438 with base80116800; surrounding event bytes match original. Established CPU-state parser reports PC80178710, cause30000400 (exception code0), also found in the progressing slot1 sample. This is not evidence that the game cannot be stuck elsewhere or that the banner is correct. Single snapshot cannot distinguish a persistent wait from normal transition or recurring events.

User was asked whether the black screen persists or the transition/dialogue repeats, and what action preceded it. No reply available at handoff. Need that reproduction, preferably a second state after10–20seconds, before changing transition code. Do not alter working event logic based on the word 'loop'.

Main success bible is not promoted. Changelog records only applied slot1 changes; test log includes failed hypotheses and scope; codex notes record confirmed facts. Next: user checks slot1 by cold boot/memory-card path; obtain slot2 continuation evidence and diagnose separately. TEST_ONLY/non-release.
