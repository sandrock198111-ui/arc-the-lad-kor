# V353 summon healing skill diagnosis

Status: root cause confirmed; static patch and disc integrity PASS; actual V353 runtime PENDING.

## Symptom

Keraack's healing skill opens its range cursor, but confirm returns control to free movement without the original healing action, animation, or MP spend. Full HP is not a valid explanation: the user's original-game comparison executes the skill even when all three targets are full.

## Static provenance

The live 12-byte record at RAM `0x801932DC` / PSX.EXE file `0x78ADC` is:

| Build | Record | Action word |
|---|---|---|
| Original | `58 38 12 80 6C 3B 12 80 26 00 00 00` | `0x00000026` |
| V206 | same as original | `0x00000026` |
| V207 | `58 38 12 80 6C 3B 12 80 26 E0 0A A3` | `0xA30AE026` |
| V352 | `58 38 12 80 6C 3B 12 80 26 E0 52 A3` | `0xA352E026` |
| V353 | same as original | `0x00000026` |

V207's string mover treated a long zero run beginning at RAM `0x801932E5` as free. That byte is actually byte 1 of the live action word at `0x801932E4`. The three zeros were field value, not unowned space.

The record base is referenced at PSX.EXE file offsets `0x78B48` and `0x78B58`. The former string pointer at file `0x82A6C` now points to `0x8019AF14`, and an exact little-endian scan of all 164 V352 members found zero pointers to `0x801932E5..0x801932EA`.

## Runtime confirmation

- `0x80123778` copies the global command low half to actor offset `+0xA8`.
- `0x80121934` reads it with signed `lh` and multiplies by 16 for the action table.
- V352 produces `0xE026`, signed `-8154`, so the table lookup goes before the valid table and no callback is installed.
- A RAM-only diagnostic changed the record high bytes and the already-computed in-flight command to `0x0026`.
- The actor then held action `0x26`, D0=`0x801A8078`, initial D4=`0x8012EED4`.
- Callback `0x8012EED4` executed, MP changed `56 -> 44`, and the original-stage callback `0x80122620` executed.

This intervention proves the mechanism but is not a runtime test of the V353 disc.

## Patch envelope

Only V352 `PSX.EXE:0x78AE5..0x78AE7` changes:

`E0 52 A3 -> 00 00 00`

`PSX.EXE:0x78AE4` remains `0x26`. Bytes after the 12-byte record remain byte-exact V352. COMM.IMG, every DAT, all other PSX.EXE bytes, archive order, and member sizes are preserved.

## Safety rule

A zero run is not a free-space proof. Future cave selection must exclude live typed records and tables even when their high bytes are zero, and must pin the whole surrounding record against original/donor evidence.
