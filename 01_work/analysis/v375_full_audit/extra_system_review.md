# V375 extra system fragments and direct numeric formats

42 rows: 23 additional pointer records + 15 ASCII format literals + 4 previous-review updates. {'HUD_BINARY': 5, 'PASS_SEMANTIC': 20, 'ACCEPTABLE_ABBREVIATION': 3, 'CONFIRMED_DEFECT': 9, 'NEEDS_SOURCE_CONFIRMATION': 4, 'EMPTY_PLACEHOLDER': 1}

The 6 state-editor labels are proven text consumers but are NOT proven normally player reachable. Native HUD codes are explicitly excluded from prose-decoder failure counts. Source pixels were rendered from original COMM in memory and directly viewed; raw ASCII-looking source25 is colon in the native encoding.

## Findings

- extra_ui:780DC [HUD_BINARY]: 1 → DFEA: native digit fragment, indexed 3-entry selector. Unknown prose decode is not glyph failure.
- extra_ui:780E0 [HUD_BINARY]: 2 → DFEB: native digit fragment, same selector bank.
- extra_ui:780E4 [HUD_BINARY]: 3 → DFEC: native digit fragment, same selector bank.
- extra_ui:780FC [HUD_BINARY]: Original pixels L → DFF4: native HUD letter, not Japanese word.
- extra_ui:78244 [HUD_BINARY]: Original pixel is colon : (raw25 is NOT ASCII % here). Current DFF7 native HUD punctuation.
- extra_ui:82470 [PASS_SEMANTIC]: Original opening corner quote 「 matches current 「; item acquisition message component.
- extra_ui:82534 [ACCEPTABLE_ABBREVIATION]: Japanese subject particle が becomes space in stat-number-increase message, e.g. 공격력 N 상승. Meaning preserved.
- extra_ui:82550 [PASS_SEMANTIC]: Original opening corner quote 「 matches current 「; learned-skill message component.
- extra_ui:82558 [ACCEPTABLE_ABBREVIATION]: Original 」の becomes 」 plus space; possessive particle omitted in named-skill level-up component, meaning retained.
- extra_ui:825F0 [PASS_SEMANTIC]: する → 확인함 is the affirmative cancel-confirmation option, not a generic verb. Table consumer proves row pairing.
- extra_ui:825F4 [PASS_SEMANTIC]: あり → 보기 is help-window ON option; paired with なし.
- extra_ui:825F8 [PASS_SEMANTIC]: なし → 안 보기 is help-window OFF option; paired with あり.
- extra_ui:82630 [CONFIRMED_DEFECT]: Original 勝 (wins) becomes 위 (rank/up). Original win counter renderer loads at80156898 and draws at801568A0.
- extra_ui:82634 [CONFIRMED_DEFECT]: Original pixel 負 (losses) becomes 로 분<CODE:E0ED>, corrupt text. Original loss-counter draw8015691C. Known-buried exception did not mean repaired.
- extra_ui:8299C [NEEDS_SOURCE_CONFIRMATION]: Original pixel 炎 is proven. Current only E0AC has no known Korean mapping; exact current glyph/CPU render still required before deciding corruption versus intentionally preserved symbol. Pointer is skill-alias bank index25.
- extra_ui:82A68 [CONFIRMED_DEFECT]: Original ????? unknown-entry label becomes empty. Explicit unknown branches draw this pointer at8015652C and80156AE0; not an original empty placeholder.
- extra_ui:82938 [EMPTY_PLACEHOLDER]: Original/current empty bank index0; indexed aliases consumed at80156F90,801632E0,80171CA0.
- extra_ui:82AE8 [CONFIRMED_DEFECT]: Native CJK state-editor label is unchanged bytes but Korean glyph mapping changes its visible meaning. Six-entry bank drawn80157E8C. Ordinary-player reachability NOT proven; keep debug/state editor scope separate.
- extra_ui:82AEC [CONFIRMED_DEFECT]: Native CJK state-editor label is unchanged bytes but Korean glyph mapping changes its visible meaning. Six-entry bank drawn80157E8C. Ordinary-player reachability NOT proven; keep debug/state editor scope separate.
- extra_ui:82AF0 [CONFIRMED_DEFECT]: Native CJK state-editor label is unchanged bytes but Korean glyph mapping changes its visible meaning. Six-entry bank drawn80157E8C. Ordinary-player reachability NOT proven; keep debug/state editor scope separate.
- extra_ui:82AF4 [CONFIRMED_DEFECT]: Native CJK state-editor label is unchanged bytes but Korean glyph mapping changes its visible meaning. Six-entry bank drawn80157E8C. Ordinary-player reachability NOT proven; keep debug/state editor scope separate.
- extra_ui:82AF8 [CONFIRMED_DEFECT]: Native CJK state-editor label is unchanged bytes but Korean glyph mapping changes its visible meaning. Six-entry bank drawn80157E8C. Ordinary-player reachability NOT proven; keep debug/state editor scope separate.
- extra_ui:82AFC [CONFIRMED_DEFECT]: Native CJK state-editor label is unchanged bytes but Korean glyph mapping changes its visible meaning. Six-entry bank drawn80157E8C. Ordinary-player reachability NOT proven; keep debug/state editor scope separate.
- ascii_format:8D6A8 [PASS_SEMANTIC]: ASCII numeric format '%2d' unchanged; not native game text.
- ascii_format:8D6AC [PASS_SEMANTIC]: ASCII numeric format '%4d' unchanged; not native game text.
- ascii_format:8D6B0 [PASS_SEMANTIC]: ASCII numeric format '%02d' unchanged; not native game text.
- ascii_format:8DA88 [PASS_SEMANTIC]: ASCII numeric format '%04d' unchanged; not native game text.
- ascii_format:8DA90 [PASS_SEMANTIC]: ASCII numeric format '%05d' unchanged; not native game text.
- ascii_format:8DA98 [PASS_SEMANTIC]: ASCII numeric format '%03d' unchanged; not native game text.
- ascii_format:8DAB8 [PASS_SEMANTIC]: ASCII numeric format '%d' unchanged; not native game text.
- ascii_format:8DAC0 [PASS_SEMANTIC]: ASCII numeric format '%d' unchanged; not native game text.
- ascii_format:8DAC4 [PASS_SEMANTIC]: ASCII numeric format '%02d' unchanged; not native game text.
- ascii_format:8DACC [PASS_SEMANTIC]: ASCII numeric format ' %02d' unchanged; not native game text.
- ascii_format:8DAD4 [PASS_SEMANTIC]: ASCII numeric format ' %02d' unchanged; not native game text.
- ascii_format:8DAFC [PASS_SEMANTIC]: ASCII numeric format '%d' unchanged; not native game text.
- ascii_format:8DB00 [PASS_SEMANTIC]: ASCII numeric format '%%%dd' unchanged; not native game text.
- ascii_format:8DB08 [PASS_SEMANTIC]: ASCII numeric format '%%+%dd' unchanged; not native game text.
- ascii_format:8DB10 [PASS_SEMANTIC]: ASCII numeric format '%d' unchanged; not native game text.
- ui_pointer:781B8 [NEEDS_SOURCE_CONFIRMATION]: Direct original caller8012C7CC passes to8012D734 after selector drawing8012D220; load-only menu reachability still not fully traced.
- ui_pointer:82360 [NEEDS_SOURCE_CONFIRMATION]: Indexed help bank: additional L/R instruction still needs all-input-state proof. No direct static pointer xref found.
- ui_pointer:825E8 [ACCEPTABLE_ABBREVIATION]: Resolved option context: original configuration row1 pairs825E4 normal /825E8 improve; current 일반/사용 expresses normal versus enhanced input. Table loop801608A8/801608C0 proves pairing.
- ui_pointer:82AC8 [NEEDS_SOURCE_CONFIRMATION]: Direct original consumer801666F4 stages equipment prompt and registers callback8016674C; all callers being pre-battle not yet proven.

## Scope boundary

Nearby LUI/low-half reference scan: original EXE code offsets0x800..0x77EFF, maximum64-byte preceding LUI search. This identifies candidates rather than proving dataflow across control flow. Direct native/ascii text calls with immediate a2 were inspected; only runtime scratch buffers were additional direct a2 literals. Format a1 references in title/UI code bands8012C000..8012DFFF and80155000..80171FFF produced the 15 reviewed literals, whose consumers were independently inspected. Indirect and distant register constructions, other wrappers, overlays/DAT, debug reachability and entire-program text population remain outside a completeness guarantee. No claim that these 38 additions exhaust all UI strings. No game/canonical bytes changed.

Helper extra_system_probe.py review regenerates only this CSV/MD. contexts prints candidate native consumers. Existing system_location_review.csv/.md were not altered; merge the four updates explicitly.
