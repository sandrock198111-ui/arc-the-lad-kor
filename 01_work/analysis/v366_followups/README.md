# V366 — five reported Ramada states (TEST_ONLY)

Scope is the five uploaded HASH-477B29575D051C04 states, not every newly found
below45000 dialogue candidate. All writes are in 6/S6054.DAT; EXE, COMM, other
DAT, canonical CSV, original images and user saves are unchanged.

## Changes

- 43A28: 승려: 그럼 장난삼아 / 오셨습니까? — 맞습니다./아닙니다.
- 43A94: 승려: 다음 문제를 다 맞히시면 / 좋은 걸 알려 드리겠습니다.
- 43AFA: 문제: 지금 일행은 모두 몇 명입니까?
- 43B4E: 5명 / 6명 / 7명 / 8명.
- #1746/45E2E: 라마다 승려: 수행이 부족한 것 같습니다. / 다시 찾아오십시오.

An independent second language review recommended 장난삼아 for ひやかし,
일행은 모두 to avoid excluding the player from party count, and 찾아오십시오
for 出直してくる. User authorized repairing the five cases and polite tone.
This remains a non-release trial pending the user's wording/runtime review.
Original choices5/6/7/8 were checked by rendering original COMM glyphs21..24.

The first question preserves two prompt rows and its old E5/newline/event anchors.
The four-option window is independent of the preceding question: all four rows
start at Y32/48/64/80. Each original four-byte option run becomes A1 + digit +
two-byte 명, preserving the E6 and NUL addresses. Its local signed column argument
at43B70 changes0→-2, baseRow remains0 and count remains4. Text startsX54; cursor
topX36, tipX43, eleven pixels before the first text cell. Cursor Y34/50/66/82.
Two-option cursor remainsX60/Y66,82. No global cursor change.

## Verification and rejected method

The first draft attempted to reclaim Bank-B24 by inlining 타이틀로고 and put
E5/E6-bearing choices in that slot. The actual renderer returned15 glyph packets
on one line instead of16 packets on four lines. E2 payload uses a plain glyph
path: treating nested E5/E6 as the normal inline control stream was invalid.
The draft ZIP CF09F674CEBCD56039C1D0690052F4E3113E6EFB3AFD658B4FA89E5B72560FC0
was never packaged into a disc and is quarantined locally as
REJECTED_E2_CHOICES_DO_NOT_USE.zip. Final output preserves Bank-B24 and its old
caller byte-for-byte. No donor text or extra storage allocation is needed.

Final tests:

- Pinned V365 input, exact original bodies, nine disjoint Expected Writes,
  whole164-member diff, stable second ZIP generation and missing-glyph rejection.
- Captured RAM copies match the actual V365 body bytes. Apply final DAT deltas
  in memory, then execute actual 8016B880 initialization and8016B8C8 renderer.
  Five states output33/33/21/12/34 packets, all under64, with4/2/2/4/3 rows.
  Every source pointer returns to its unchanged original NUL boundary.
- Actual event reader8015C48C preserves selection index5/count2 or4/baseRow2 or0.
  Six cursor coordinates tested. Actual vertical pad/bounds block8015E3D8..E464
  tested for both directions from every item:12 cases, wrap0↔last preserved.
  This injects decoded pad bits in a RAM copy and stops before sound callback;
  it does not verify physical input, confirm/cancel branches or GPU presentation.
- Existing legacy failure lists do not grow. All506 data LBAs and164 image
  member readbacks PASS, all507 extent/size values unchanged.30 changed raw
  sectors and60 corresponding old/new EDC/ECC checks PASS; no unexplained bytes.

## Reproduce

Run `python -X utf8 02_scripts/` with these script names in order:

1. build_arc1_v366_followups.py
2. verify_arc1_v366_followups.py
3. package_arc1_v366_followups.py (fresh original staging, refuses overwrites)
4. verify_arc1_v366_disc_delta.py

Input ZIP28EEE68677DB124D91550CF89B2EF437B1CE728686011CA79B419FA1DAB27764.
Final ZIP2443DCCA0451372D4D7A6ACD8B593696EC52734FC467B42C2284EFD14995FEBF.
BIN B2EAB2D6F0B07A023D4680888D18F0D40F7ED09513964A6984CA264292551177.
CUE:03_output/V366_FOLLOWUPS_TEST.cue.

Remaining: cold boot/re-enter conversation, inspect four-option left margin,
select each answer, confirm outcomes/clearing/re-entry. Old mid-dialogue states
retain old DAT and are not final-build runtime evidence. Other low-address
questions/choices remain an explicit separate coverage repair task. Bible's
successful baseline is retained; no global-completion claim.
