# v106 design: two glyph strips in VRAM the game never draws into

Status: measured and decided, not yet built. Every number below is measured from the
139 savestates or read out of the v103 executable.

## Why

v105 borrows the P6 rectangle while text is on screen and returns it after, which fixed
every reported case except one: the skill range overlay. At low skill level the range is
a single square and nothing is wrong; once it grows to a cross, the overlay tiles render
as glyph pixels.

That case cannot be fixed by time-sharing. The range is shown while the skill name is on
screen, so the patch is holding the rectangle exactly when the game wants it. The game
and the patch want the same VRAM at the same moment, so the glyphs have to move.

## Where they can go

The upload comes from RAM, so the destination is ours to choose, subject to two limits:

- the renderer has one U offset constant and emits one tpage word, so a strip must sit
  inside a single texture page: with C columns, `U + 12C <= 256`, i.e. `x mod 64 <= (256 - 12C)/4`
- `V = (row * 12) & 0xFF`, so V must be a multiple of 4 and must avoid the 24 values the
  base rows already produce: 0, 8, 12, 20, 24, 36, 48, 60, 72, 84, 96, 108, 120, 132,
  144, 156, 168, 180, 192, 204, 216, 228, 240, 252

Measured free space, meaning no savestate ever has a non-zero pixel there:

| columns | glyphs | free single strips |
|--------:|-------:|-------------------:|
| 15 (today) | 60 | 0 |
| 14 | 56 | 0 |
| 13 | 52 | 7 |
| 12 | 48 | 25 |
| 10 | 40 | 67 |

15 columns has nowhere to go. 13 columns fits but holds 52, and 57 are in use, so a
single strip would cost five glyphs.

Exactly one pair of 13-column strips shares an x and a page:

```
page 15,1   tpage word 0x1F   x 961..999   U = 4
  strip A   y 480   V = 224   row 40
  strip B   y 500   V = 244   row 63
```

They do not overlap (480+12 = 492 <= 500) and B ends at 511. Together they hold 104
glyphs, against 57 in use, so nothing is dropped and there is room for 47 more.

## What has to change

### The classifier can no longer be inline

It currently decides on one value:

```
0x801A2204  lbu   v0,0x29(v1)     ; V
0x801A2208  nop                   ; free
0x801A220C  addiu v0,v0,-32
0x801A2210  sltiu v0,v0,1
0x801A2214  bne   v0,s5,0x801A2280
0x801A2218  addu  a1,v1,s4        ; delay slot, must survive
```

Two values do not fit in four instructions. A one-bit mask test, `(V & ~bit) == VA`,
is exact and does fit, but it forces the two V values one bit apart, and that only
admits six-column strips (48 glyphs, fewer than today). A range test cannot work either:
the base V values are at most 12 apart, so any range wide enough to hold two strips
contains one of them.

So the test moves to a subroutine in reserved RAM. This is safe:

- the loop already contains `jal 0x80178F84` at 0x801A2278, so calling from it is fine
- `ra` is saved by the prologue at 0x801A21DC and reloaded at 0x801A2294, after the loop
- `at` and `t0`..`t9` are never read or written anywhere in the loop

It also generalises: the full script needs roughly 947 glyphs, about eighteen strips,
and a subroutine can test any number of V values.

### Addresses and constants

```
0x801A7520              glyph lookup table, 409 entries of 16 bits
physical_index          row * 84 + col * 4 + plane      (84 = 21 columns * 4 planes)
0x8016B588..0x8016B5A8  U = col * 12, V = row * 12, both stored as bytes
0x8016B5C4              U += 4 when the glyph type at 0xD(a2) is 6
0x8016B5D8              j 0x801FE3C4, into the relocated helper
0x801A2194              the tpage word, currently ori a3,a3,0x001B
```

Remap: the 57 entries currently at row 24 columns 0..14 (indices 2016..2075) become
row 40 columns 0..12 (3360..3411, 52 slots) and row 63 columns 0..12 (5292..5343).

### Reserved RAM

Two strips of 13 columns are 39 units wide, so 936 bytes each.

```
0x801FE3C4  helper           276
            glyph strip A    936
            glyph strip B    936
            code            ~300
            state              8
            backup A         936
            backup B         936
                           -----
                            4328 bytes, against 5512 before the heap the game uses
```

The executable grows by one sector to carry the extra glyph data. That is free now:
PSX.EXE sits at the end of the disc under the v104 layout, so nothing moves behind it.

## Verification before building

- the strips must not overlap each other or leave the page
- both V values must be absent from the base set above
- the remapped indices must round-trip through `row * 84 + col * 4 + plane`
- the classifier subroutine must only use `at` and `t0`..`t9`
- `verify_iso_layout.py` must pass on the rebuilt image
