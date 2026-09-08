# V370 arena event opcode restoration

2026-09-08. Follow-up to the second V368 Sans user capture, folder `upload_0aab59e5-6068-421e-b886-5bfa43d9365e`. Original and user saves remain untouched.

## Root cause and correction of previous analysis

The previous inspection mistook the global VM scratch state for the main thread. The scratch record801FE2B4 belongs to the last processed auxiliary thread. Captured main thread801ADDC4 has index07C7/status1; auxiliary801ADDE6 has index0E1C/status3 and a one-frame wait. Normal auxiliary waiting does not explain main-thread progress.

At S7021:48786, `0B 00 19 00 FD FF` is opcode0B with parameters0019/FFFD. The actual VM consumes all three words and reaches4878C. The historical dialogue corpus incorrectly includes a three-byte “text” at4878A (`FD FF 0E`); its padded variant is`FD FF A1`. This overwrites the next executable opcode000E with00A1. No Hangul font operation is involved.

The captured dispatcher8015AC0C accepts opcodes0..4E. AtA1 it reaches8015B218, sets S1/S0=0 and returns0 after advancing the script index to07C7, exactly matching the captured main-thread index. It is an event-dispatch abort, not a demonstrated CPU infinite loop. Restoring0E lets the original handler consume its arguments and continue. The invalid opcode alone is sufficient to reproduce dispatcher failure; full GPU/scene progression remains a user test.

## Seven-byte repair

Each site has identical verified opcode/parameter context `0B001900FDFF0E000000` in the original and `0B001900FDFFA1000000` in V369. Restore only A1→0E:

| File | Offset |
|---|---|
|7/S7021.DAT|4878C|
|7/S7022.DAT|48C26|
|7/S7023.DAT|48C56|
|7/S7024.DAT|48CBA|
|7/S7025.DAT|48CCA|
|7/S7026.DAT|48F36|
|7/S7028.DAT|47ACA|

Corpus source rows remain historical input and must not be treated as valid dialogue at these sites. The restoration builder explicitly guards and repairs these legacy inputs on every build. Broader parser/corpus completeness is not claimed.

## Tests and outputs

`audit_arc1_v370_event_abort.py` uses a copy of captured RAM with the event script relocated to scratch80100000 and its verified VM base updated; script-relative indexes remain unchanged. CPU dispatch is executed with a bounded instruction count. For each of7files: prefix0B consumes exactly3words; badA1 clears dispatch continuation and returns0; restored0E and original produce identical next index and continuation. Stop-after-first-handler values are not whole-function returns; `bad_dispatcher_return` is separately measured at the actual return sentinel. No emulator input, user save or on-disk game mutation occurs during these trials.

Build checks exact baseline/original hashes, all planned expected bytes, same-input ZIP reconstruction and exact seven-byte scope. Independent final-archive comparison verifies each byte equals original, all other member bytes/sizes unchanged. Sans font, cursor, title, all other dialogue and V369 overflow fix preserved.

Fresh original disc staging:506data LBA/164member readbacks/507extents preserved.34changed sectors only permitted DAT bytes/ISO timestamps;68old/new EDC/ECC checks pass.

- Base V369 ZIP SHA58692673A78F425A206814B7C7193A69E7FAD41CD2A755E9AF5F13BB429EF69F.
- `03_output/arc1_v370_event_restore_TEST_ONLY.zip`, SHA8FE8CF805C571C40E7215CF71CBFEB559F639DB71CF0AF48C40AEF691D7BB404.
- `03_output/V370_EVENT_RESTORE_TEST.cue` / BIN SHA5E7FF5D2D1FBFD61354F7C2A1E4297506C88EED4673791E09CCF448CD3F93007.

Reproduce: run `build_arc1_v370_event_restore.py`, `package_arc1_v370_event_restore.py`, `verify_arc1_v370_disc_delta.py` in02_scripts. Builder runs the CPU audit. Original ZIP and historical frozen archive dependencies are inherited and explicitly hash checked; not an original-only full-translation rebuild claim. Packager refuses existing output discs.

Cold boot new CUE and load memory-card progress before entering the arena. A previously broken savestate restores corrupted script RAM and cannot validate the new disc fix. Full scene completion/GPU/input remains pending. Bible successful baseline not promoted; changelog/test_log/codex_notes updated. Next audit candidate: other opcode parameters misclassified as dialogue, using VM boundaries rather than marker scanning.
