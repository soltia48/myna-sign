# myna-sign

マイナンバーカードの **署名用電子証明書** で、任意のファイルや PDF に電子署名を付与し、検証するデスクトップアプリケーション。

- 任意のファイル → OpenPGP 分離署名 (`.asc`)、テキストならクリアテキスト署名も
- PDF → 追記署名 (`adbe.pkcs7.detached`)、署名欄は自動生成 (任意の画像も可)
- RFC 3161 タイムスタンプ (なし / FreeTSA / DigiCert / 任意サーバ)

## 構成

```
crates/myna-sign-core/   署名・検証。カードにも GUI にも依存しない
crates/myna-sign-card/   PC/SC。CardSigner とセッション管理
crates/myna-sign-cli/    myna-sign コマンド
src-tauri/               Tauri アプリ (コマンド定義のみ)
ui/                      Preact + Vite
```

`myna-sign-core` がカードについて知っているのは `DigestSigner` trait 一つだけ
— 「32 バイトの SHA-256 を渡すと 256 バイトの署名が返る」— で、
OpenPGP・CMS・PDF・RFC 3161 の組み立てはすべてこの trait に対して書かれている。
おかげでカードなしに CI で全部テストできる。

## 必要なもの

| | |
|---|---|
| Rust | 1.88 以降 |
| Node.js | 20 以降 |
| PC/SC | Linux: `pcscd` + `libpcsclite1` (ビルド時 `libpcsclite-dev`) / macOS・Windows: OS 内蔵 |
| WebView | Linux: `libwebkit2gtk-4.1-dev`, `libgtk-3-dev`, `libsoup-3.0-dev` / macOS: 内蔵 / Windows: WebView2 |

対象は Linux (x86_64)、macOS (Apple Silicon)、Windows (x64)。

## ビルド

```sh
# ライブラリと CLI。カードもリーダーも要らない。
cargo test --workspace --features myna-sign-core/soft-signer

# GUI。src-tauri は独立したワークスペースになっている。
cd ui && npm install && npm run build
cd ../src-tauri && cargo build --release --features custom-protocol
```

`--features custom-protocol` は省略できない。これが無いと Tauri はフロントエンドを
バイナリに埋め込まず、`build.devUrl` (localhost:5173) を見に行くので、
開発サーバを動かしていない環境では「Connection refused」しか出ない。
`cargo tauri build` を使う場合は自動で付く。

開発中は Vite の開発サーバを併走させる:

```sh
cd ui && npm run dev            # 別の端末で
cd src-tauri && cargo build && ./target/debug/myna-sign-app
```

## 使ってみる (カードなし)

`--soft-key` はその場で作った使い捨ての RSA 鍵で署名する。パイプライン全体を確認するためのもので、
できあがる署名は誰のことも証明しない。

```sh
cargo build -p myna-sign-cli

# 任意ファイル → .asc と公開鍵
./target/debug/myna-sign --soft-key sign contract.txt --public-key
./target/debug/myna-sign verify contract.txt.asc contract.txt

# 本文と署名を 1 ファイルに (テキストのみ)。原本を渡す必要がない。
./target/debug/myna-sign --soft-key sign contract.txt --cleartext
./target/debug/myna-sign verify contract.txt.asc

# PDF → タイムスタンプ付き署名。署名者・日時・理由を記した枠が自動で描かれる。
./target/debug/myna-sign --soft-key --tsa digicert sign-pdf contract.pdf --reason 承認

# 自分の印影を使う / ページに何も出さない
./target/debug/myna-sign --soft-key sign-pdf contract.pdf --image stamp.png
./target/debug/myna-sign --soft-key sign-pdf contract.pdf --invisible
./target/debug/myna-sign verify-pdf contract.pdf.signed.pdf

# 外部ツールの second opinion
gpg --verify contract.txt.asc contract.txt
pdfsig contract.pdf.signed.pdf
```

## カードを使う

```sh
./target/debug/myna-sign readers
./target/debug/myna-sign card
./target/debug/myna-sign --tsa freetsa sign-pdf contract.pdf
```

**署名用パスワードは 5 回間違えるとロックされ、市区町村の窓口でしか解除できない。**
CLI も GUI も、パスワードを送る前に残り回数を表示し、残り 1 回のときは確認を挟む。

## 知っておくべきこと

**署名用電子証明書には基本4情報 (氏名・住所・生年月日・性別) が入っている。**
`.asc` や PDF に埋め込むということは、それらを受け取った相手に開示するということ。
GUI は書き出す前に中身を表示し、埋め込まない選択肢も用意している。

**カードのセキュリティ状態はプロセスより長生きする。** VERIFY の成功はカードが電界を離れるまで残り、
接続を切っても再接続しても消えない。消えるのは電源断のときだけ。
本アプリは切断時とアプリ終了時に必ず電源を落とすが、これは
[`myna-card` が明記している挙動](https://docs.rs/myna-card) であって本アプリの都合ではない。

**失効確認は実装していない。** JPKI は失効情報をオンラインサービスとして別に提供しており、
本アプリはそれを参照しない。だから検証結果に「有効」という表示はなく、
「署名の検証」「証明書チェーン」「失効確認: 未実施」が別々の行として出る。
検証側の窓口は `ocspsign*.jpki.go.jp` の一族とみられるが、
J-LIS との契約なしには到達できない。

## テスト

自作の署名器を自作の検証器で確かめても何も確かめたことにならないので、
外部ツールとの相互検証を完了条件にしている。

```sh
# 単体 + gpg / pdfsig との相互検証
cargo test --workspace --features myna-sign-core/soft-signer

# 実際の TSA に接続するもの (既定では走らない)
cargo test -p myna-sign-core --features soft-signer -- --ignored
```

| 対象 | 判定者 |
|---|---|
| OpenPGP 署名 | `gpg --verify` |
| PDF 署名 | `pdfsig` (poppler-utils) |
| クリアテキスト署名 | `gpg --verify` |
| RFC 3161 | `openssl ts -verify` + 実 TSA 2 社 |

## ライセンス

MIT

同梱している Noto Sans JP (`crates/myna-sign-core/fonts/`) は SIL Open Font License 1.1 で、
ライセンス全文を同じディレクトリに置いてある。配布物にはこれを含めること。
