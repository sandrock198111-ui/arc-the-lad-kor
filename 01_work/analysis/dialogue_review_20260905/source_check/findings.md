# Original Japanese glyph verification — 2026-09-05

Scope: seventeen nominated records (initial ten plus seven follow-up records), no source CSV, ROM, or build input changes.

`render_source.py` reads `00_original/arc.zip` directly, asserts every nominated record's full raw byte sequence at its documented original DAT offset, and renders the original `COMM.IMG` 12x12 bitmap planes using the existing `extract_story_corpus.bitmap_key_from_comm` implementation. The numeric labels below the pixels are original font indices. E4/E6 pairs are omitted and shown as visual line boundaries for this inspection; these pictures are glyph evidence, not runtime layout or control semantics evidence.

All ten DAT byte assertions passed. Visual inspection of the generated PNGs confirms:

| Row | File / offset | Confirmed original reading | Incorrect CSV reading |
|---|---|---|---|
|1089|4/S4011.DAT / 0x48936|よかろう！人間の非力さを／思い知らせてやろう。|人聞の底力さ|
|1104|4/S4011.DAT / 0x48F6C|俺には関わらない方がいい。|俺にはかわらない方がいい。|
|1640|6/S6022.DAT / 0x47A9C|離れた者にダメージを／与えることができるらしい。|連れた者|
|1650|6/S6031.DAT / 0x47BE6|我々でさえ登ったことのない／ラマダ山に入ろうとは。|帰つたこと|
|2242|8/S8031.DAT / 0x486E8|水の神殿のカギは手に入ったか？|カベ|
|2255|8/S8041.DAT / 0x47B5A|利用できるものをとことん利用し／生きる価値もないようなクズを／消し去って何が悪い？|ク供|
|2261|8/S8051.DAT / 0x48732|まあいい、／神殿のカギが欲しかったのでな。|カベ|
|2263|8/S8051.DAT / 0x487D4|クズどもを殺すのに、／それ以上の理由などない。|ク供|
|2300|9/S9012.DAT / 0x47AE6|エレベータのロープを切って／まとめて始末してやる。|始動|
|2767|F/SF041.DAT / 0x47AAC|そう、この研究所は〔E4:15〕あたらしい〔E4:0B〕／エネルギーの研究を〔E4:15〕している〔E4:3D〕。／つまり生命力エネルギーだ。|エリルベー|

Important glyph evidence: 135=間; 564=非; 396=関; 610=離; 568=登; 401=ギ; 505=ズ; 513=末; 417=ネ. These statements are supported by the original bitmap PNGs for the nominated occurrences. This report does not perform or authorize a global mapping replacement.

Reproduce from E:/korean: `python 01_work/analysis/dialogue_review_20260905/source_check/render_source.py`.

The Japanese readings in this report normalize small っ and punctuation for readability. Original raw bytes remain unchanged. This verification does not validate the runtime behavior of row 2767's E4 control parameters.

## Follow-up seven records

All seven additional original DAT byte assertions also passed. Adjacent source records were read for context; the readings below are confirmed directly by the nominated original glyph PNGs.

|Row|File / offset|Confirmed original reading|Finding|
|---|---|---|---|
|208|21/S2013.DAT / 0x47E08|きくのぉ／よいがさめちまったわい|index 288 is small ぉ, not ふ. Surrounding row 207 invites drinking; row 209 says the player can give Tosh a good fight.|
|347|21/S2044.DAT / 0x484C8|そうじゃ、わしの古の旅から／定められた魂じゃ。|The unusual 古の旅から and 魂 are actually present; do not replace them by conjecture. Following row asks whether they traveled together long ago.|
|601|22/S2056.DAT / 0x47AE6|はい／父さんからの手紙で／古（いにしえ）の事を書いた／伝記がある事がわかりました|index 121 is 事, not こ. Preceding king asks about the Ark; following row says they will search at Orcas Hill.|
|743|31/S3013.DAT / 0x48430|妖樹も、ふえる時にHPが半分に／なりますが、倒した時にもらえる／経験値は変わりませんよ。|妖樹 and the entire HP / experience hint are directly present. Surrounding rows are crew gameplay advice.|
|1481|5/S5025.DAT / 0x47CE0|おまえ、オドンじゃな！！|index 148 is ド, not ト.|
|1482|5/S5025.DAT / 0x47D46|わしの家にオドンが住み着いとるとは………。|Same オドン. Following row says the collection has increased again.|
|2789|F/SF041.DAT / 0x48344|わしはそのほうに／賭けてみたいと思うがのう。|index 673 is 賭, not 負. Preceding row discusses another way to solve things besides returning everything to nothing.|

Additional confirmed original glyphs for these occurrences: 288=ぉ; 121=事; 148=ド; 673=賭. No global mapping or source text replacement was performed.
