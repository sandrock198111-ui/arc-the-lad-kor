# PSX.EXE UI Table Audit

- Source: `03_output\story_choice_row_alignment_v23_cumulative_patch_only.zip`
- Extracted rows: 503
- Operation: read-only extraction

| Table | Rows | First string offset | Last string offset |
|---|---:|---:|---:|
| 장비 이름 | 64 | 0x80224 | 0x8049C |
| 장비 설명 | 64 | 0x805A4 | 0x80A8C |
| 소비 아이템 이름 | 32 | 0x80B94 | 0x80C94 |
| 소비 아이템 설명 | 32 | 0x80D1C | 0x80F0C |
| 기술 이름 | 59 | 0x80F94 | 0x811B8 |
| 기술 설명 | 59 | 0x812AC | 0x816FC |
| 인물·몬스터 이름 | 108 | 0x817F4 | 0x81B40 |
| 지역 이름 | 30 | 0x81CFC | 0x81E30 |
| 장소 이름 | 55 | 0x81F04 | 0x82164 |

## Notes

- Offsets are PSX.EXE file offsets, not runtime RAM addresses.
- `slot_size` includes the terminating zero and any existing padding.
- Ambiguous font matches are preserved as `<N:...>` markers for manual review.
- No game binary is modified by this audit.
