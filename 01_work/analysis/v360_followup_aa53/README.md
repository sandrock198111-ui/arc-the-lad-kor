# V360 follow-up: visible spacing and panel height

2026-09-06. **Diagnosis only; no game/code/translation changes.**

Baseline ZIP SHA256:
`9235BCB75903A00477E69BC47713D200E8BAE4C37AFDDDA83EF1878D07441731`.
Inputs: four user states `HASH-AA53DAA1260A4ED6_1..4.sav`. Their hashes, titles,
panel settings and text packets are in `states.json`. All four titles are
V360_UI_RESTORE_TEST; RAM extraction uses the existing Bus/VRAM locator and
six baseline EXE anchors. Local `frame*_0.png`/`frame*_256.png` are direct
framebuffer decodes, not mockups. No state file was modified.

## Confirmed observations

| State | Context | Panel xywh | Description row origins |
|---|---|---|---|
| 1 | Equipment, MP recovery | 60,110,200,46 | (68,116), (68,134) |
| 2 | Equipment, 30% defense | 110,110,200,46 | (118,116), (118,134) |
| 3 | Skill description + level/MP | 60,103,200,46 | (68,109); MP line y133 |
| 4 | Battle item description | 10,110,200,46 | (18,116), (18,134) |

The actual active-OT background FT4 vertices agree with the settings: states
1/2/4 span y110..156 and state3 spans y103..149, all 46px. Different heights
are not observed in these four captures. Skill text and MP layout, however,
uses a 24px origin gap, compared with 18px between two description rows.
MP content mixes 12px label sprites, 16px digit sprites and a 16px blue orb
at y130. Merely moving the bottom border up can collide with that lower row.

The second-line **origin** is not indented. Its visible **ink** differs:

- State1 first glyph (physical8, 아) has ink x3..15; M (740) x0..6.
  Same origin68 produces visible left edges71 and68: 3px difference.
- State2 first glyph (149, 촌) has ink x2..13; digit3 (38) x0..6.
  Same origin118 produces visible left edges120 and118: 2px difference.

Ink bounds are decoded from captured VRAM page5 and each packet's CLUT,
using nonzero RGB palette entries. Active-OT SPRT coordinates also agree
with the text-object coordinates, ruling out a later x-position shift in
these captures. Changing the global M/number glyphs would affect other UI;
any later visual alignment change should be scoped to descriptions.

## Height feasibility probe (not an implemented feature)

For each captured RAM copy, set only panel height at 0x801F078C to28 or46,
then execute the existing geometry updater 0x8016A4F0 with
a0=0x801F0360, ra=0x80060000, sp=0x80050000 in a 2MiB Unicorn RAM map.
Read active parity from *(0x801F12EC)+0x870 and the 12 FT4s at
0x801F0360+480*parity. All eight cases return and produce requested outer
height; changed bytes stay in the panel packet block/height field.
`height_probe.json` records results. This proves the background updater
supports those heights, not an automatic row-count selector or a complete
layout. Existing two-line text/MP must not simply be put into the28px box.

## Latest user scope

After the measurements, the user selected **only the pictured skill panel**
for lowering. Do not implement the earlier general one-line item auto-height
proposal under that narrowed scope. Proposed patch is limited to skill panel
height and its MP/orb vertical layout, preserving item/equipment heights,
text contents, font, VRAM and the confirmed cursor fix. Exact safe geometry
still needs to be selected/tested; no modified build has been produced.

Next: confirm this narrow patch scope, then check actual MP digits/orb and
background primitives together (including both frame buffers). Do not claim
completion using only a logical panel rectangle or only description packets.
