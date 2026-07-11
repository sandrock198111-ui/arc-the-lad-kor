# UI Source Analysis - 2026-07-11

## Scope

- Read-only analysis copies were extracted from `00_original/arc.zip` to
  `01_work/analysis/ui_sources`:
  - `COMM.DAT` SHA256 `B0E7E447BCACA53DB31CE1F9FDBD6C239A5278F4117F6705EBA33E6CD08918A9`
  - `COMM.IMG` SHA256 `6C7565B6C326A99A29266482868F17A144FF7D15B871D7D8F8B852EC41014A26`
  - `PSX.EXE` SHA256 `947EBF893F2D46207EC7E32CA514E4EA670E0BED34EF2144B5F7FB0FDD15BC67`
- No original archive, game file, baseline patch, or output ZIP was modified.

## Results

- `analyze_dialog_blocks.py` finds zero `17 00`/`19 00` dialogue-block candidates in `COMM.DAT`.
- The UI locator byte strings observed on screen in earlier testing were not found verbatim in `COMM.DAT`, `COMM.IMG`, or `PSX.EXE`.
- Therefore the observed strings should be treated as rendered display codes, not direct source-byte signatures.
- UI/menu work must trace the text table or runtime script source before any bytes are changed. The story manifest builder is not suitable for `COMM.DAT` UI patching.

## Tooling

- Python `3.12.10` and Pillow `12.3.0` were restored for the current Windows user.
- `python -m compileall -q 02_scripts` completed successfully.

## Next Safe Step

1. Capture a fresh UI/menu screen and its runtime context.
2. Identify the responsible file/table with a controlled locator that does not alter shared font slots.
3. Patch one confirmed UI string only, then test from a cold boot and memory-card save.
