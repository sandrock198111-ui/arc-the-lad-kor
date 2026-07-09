# Dialogue block candidate summary

- Total candidates: 2544
- High-confidence candidates: 2046

## Top files

| file | candidates |
|---|---:|
| `6/S6054.DAT` | 88 |
| `C2/SC0B6.DAT` | 85 |
| `31/S3024.DAT` | 69 |
| `31/S3014.DAT` | 64 |
| `5/S5013.DAT` | 62 |
| `21/S2045.DAT` | 61 |
| `6/S6014.DAT` | 55 |
| `7/S7012.DAT` | 52 |
| `22/S2046.DAT` | 51 |
| `7/S7028.DAT` | 37 |
| `7/S7026.DAT` | 36 |
| `F/SF041.DAT` | 36 |
| `D/SD031.DAT` | 33 |
| `E5/SE05A.DAT` | 33 |
| `31/S3022.DAT` | 32 |
| `1/S1021.DAT` | 31 |
| `7/S7025.DAT` | 30 |
| `1/S1023.DAT` | 29 |
| `5/S5021.DAT` | 29 |
| `4/S4033.DAT` | 28 |
| `7/S7023.DAT` | 28 |
| `7/S7024.DAT` | 28 |
| `32/S3061.DAT` | 26 |
| `4/S4011.DAT` | 26 |
| `4/S4034.DAT` | 26 |
| `21/S2041.DAT` | 25 |
| `31/S3023.DAT` | 25 |
| `4/S4031.DAT` | 25 |
| `7/S7022.DAT` | 25 |
| `31/S3031.DAT` | 24 |
| `B/SB022.DAT` | 23 |
| `B/SB031.DAT` | 23 |
| `4/S4035.DAT` | 22 |
| `7/S7021.DAT` | 22 |
| `7/S7027.DAT` | 22 |
| `8/S8013.DAT` | 22 |
| `21/S2044.DAT` | 20 |
| `1/S1041.DAT` | 19 |
| `31/S3013.DAT` | 19 |
| `F/SF021.DAT` | 19 |
| `22/S2051.DAT` | 18 |
| `22/S2055.DAT` | 18 |
| `4/S4036.DAT` | 18 |
| `1/S1061.DAT` | 17 |
| `21/S2013.DAT` | 17 |
| `22/S2052.DAT` | 16 |
| `22/S205C.DAT` | 16 |
| `6/S6041.DAT` | 16 |
| `8/S8021.DAT` | 16 |
| `8/S8061.DAT` | 16 |
| `9/S9051.DAT` | 16 |
| `F/SF0B1.DAT` | 16 |
| `23/S2071.DAT` | 15 |
| `5/S5041.DAT` | 15 |
| `F/SF0E1.DAT` | 15 |
| `21/S2042.DAT` | 14 |
| `31/S3012.DAT` | 14 |
| `23/S2061.DAT` | 13 |
| `4/S4022.DAT` | 13 |
| `5/S5012.DAT` | 13 |
| `6/S6013.DAT` | 13 |
| `8/S8062.DAT` | 13 |
| `21/S2014.DAT` | 12 |
| `6/S6053.DAT` | 12 |
| `8/S8012.DAT` | 12 |
| `4/S4032.DAT` | 11 |
| `5/S5011.DAT` | 11 |
| `6/S6051.DAT` | 11 |
| `7/S7011.DAT` | 11 |
| `B/SB072.DAT` | 11 |
| `F/SF091.DAT` | 11 |
| `1/S1072.DAT` | 10 |
| `21/S2021.DAT` | 10 |
| `31/S3032.DAT` | 10 |
| `C2/SC0C1.DAT` | 10 |
| `1/S1011.DAT` | 9 |
| `21/S2022.DAT` | 9 |
| `6/S6012.DAT` | 9 |
| `6/S6031.DAT` | 9 |
| `7/S7032.DAT` | 9 |

## Notes

- `body_start` starts immediately after marker `17 00` or `19 00`.
- `payload_start` is the first byte the patcher may overwrite. A leading `01 00` prefix is preserved.
- Body ends at the first `00 00` boundary; bytes at and after that boundary are treated as control data.
- `high` means a nearby `29 00 .. 7F 00` dialogue header was also found.
- `medium+` means no nearby `29` header, but the body contains linebreaks and text-like bytes.
