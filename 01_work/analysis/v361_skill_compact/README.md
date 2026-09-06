# V361 skill panel compact candidate

2026-09-06. User approved **only the pictured skill panel** after the V360
four-state diagnosis. TEST_ONLY: cold-boot/GPU approval remains pending.

## Applied scope

Three guarded instruction immediates in PSX.EXE, three changed bytes total:

| Address | V360 | V361 | Purpose |
|---|---|---|---|
| 80161A78 | height46 | height42 | Skill background only |
| 801620D0 | y133 | y127 | Level/MP row |
| 801621FC | y-3 | y-1 | Orb relative to MP row, final y126 |

Panel stays x60/y103/w200. Description y109 is unchanged. All other163 archive
members, both CSVs, fonts, text, VRAM/resident allocation and cursor code are
byte-identical. Item/equipment heights and visible glyph bearings are unchanged.
No new hook or memory reservation. Existing outputs/user save states preserved.

## Evidence and limits

- `build_report.json`: source/CSV pins, per-instruction guards, assembler and
  independent disassembler round-trip, whole-EXE difference whitelist. The
  builder generates identical archive bytes twice and refuses a different
  existing output. Pinned V360 is an explicit legacy dependency; this is not a
  claim that all historical source stages were replayed from scratch.
- `verification.json`: actual renderer346 cases (96 item/equipment descriptions
  at three anchors +58 skills),634 ABI checks, unchanged resident/other group;
  inherited cursor1152 cases. Empty skill0 placeholder is not passed to print.
- Four user AA53 captured RAM copies, both buffer parities: actual background
  geometry updater generates12FT4s with correct outer extents. Skill spans
  y103..145; other three remain y110..156. Writes stay in panel packet storage.
- Actual MP prefix setup and orb-position call were executed in RAM-only CPU
  emulation. Orb-call X is supplied from the captured position before +14;
  the new Y comes from the changed prefix setup. The full BIOS numeric formatter
  was **not** executed. Captured actual MP sprites projected up6px end at143,
  and the observed16px orb projected to126 ends142. Description sprite end125;
  panel bottom145. This is bounds evidence, **not** a rendered game screenshot.
- Legacy full gate's marker2/width69 failures remain exactly unchanged, not
  silently waived. No claim of whole-game regression-free/release readiness.
- `package.json`: separate original-disc staging, all506 data LBAs retained,
 164 patched members read back exactly. EXE LBA268481 follows inherited
  packaging; original EXE was at23. Disc integrity is not PSP/runtime approval.

## Reproduce

From repository root (requires pinned archives, original disc, existing tools
and the read-only uploaded states used by the prior V360 verifier):

```powershell
python -X utf8 02_scripts/build_arc1_v361_skill_compact.py
python -X utf8 02_scripts/verify_arc1_v361_skill_compact.py
python -X utf8 02_scripts/package_arc1_v361_skill_compact.py
```

Packager intentionally refuses existing BIN/CUE output. Do not delete prior
builds to rerun it. Use the layout verifier on an existing image instead.

ZIP SHA256: `B0AA760222B6F9AE3CB063FC49531DB5E9A735BD4EDDA56759F5CAD7CE2426C8`

BIN SHA256: `3BC1E6B99238B02174BD2009491DF3ED7ACA697523C4DD993F44E62CC2057BB8`

## User verification

Open `03_output/V361_SKILL_COMPACT_TEST.cue`, cold boot and load a memory-card
save. Check skill description, level/MP numbers and blue orb, switch skills,
close/reopen the panel, and compare item/equipment screens. Old emulator save
states retain old code/VRAM; loading one is not verification of this build.
Check for border overlap and stale pixels on transitions. The successful
baseline in bible_current is intentionally not promoted before that approval.
