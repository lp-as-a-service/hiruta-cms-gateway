# hiruta-cms-gateway

KANPAKE LP の Decap CMS 用 Cloudflare Worker OAuth プロキシ。

## 概要

クライアント（蛭田さん）が GitHub アカウントなしで LP コンテンツを編集できるよう、
メール + OTP（ワンタイムパスワード）認証 → GitHub API プロキシを提供する。

```
蛭田さん（Gmail のみ）
  ↓ https://hiruta-lp.pages.dev/admin を開く
Decap CMS
  ↓ /auth にリダイレクト
hiruta-cms-gateway Worker（このWorker）
  ↓ メールアドレス入力 → OTP送信 → 検証 → セッショントークン発行
Decap CMS（認証完了）
  ↓ /github/* にコンテンツ変更リクエスト
このWorker（セッション検証 → GitHub API へ代理リクエスト）
  ↓ PAT で GitHub API を呼ぶ
GitHub リポジトリにコミット
  ↓
Cloudflare Pages が自動再デプロイ → LP 更新
```

## Worker URL

`https://hiruta-cms-gateway.kazu12127823.workers.dev`

## エンドポイント

| メソッド | パス | 説明 |
|---------|------|------|
| GET | `/auth` | メールアドレス入力フォーム |
| POST | `/auth/send-otp` | OTP 生成・メール送信 |
| GET | `/auth/verify` | OTP 入力フォーム |
| POST | `/auth/verify` | OTP 検証 → セッショントークン発行 |
| GET | `/auth/callback` | Decap CMS OAuth callback（postMessage） |
| ANY | `/github/*` | GitHub API プロキシ（セッション検証付き） |
| GET | `/health` | ヘルスチェック |

## Secrets（設定済み）

| Secret | 説明 |
|--------|------|
| `GITHUB_TOKEN` | 管理者の GitHub PAT（repo スコープ必要） |
| `SESSION_SECRET` | HMAC 署名用シークレット（32バイト乱数） |
| `ALLOWED_EMAILS` | 許可メールアドレス（カンマ区切り） |

### ALLOWED_EMAILS に蛭田さんのメールを追加する方法

```bash
cd ~/hiruta/hiruta-cms-gateway
CLOUDFLARE_API_TOKEN="<your-token>" \
npx wrangler secret put ALLOWED_EMAILS
# 入力: Kazu12127823@gmail.com,hiruta@example.com
```

または Cloudflare API で直接設定:

```bash
curl -X PUT "https://api.cloudflare.com/client/v4/accounts/6b4e233890f439ffe0c1cf327df580e1/workers/scripts/hiruta-cms-gateway/secrets" \
  -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
  -H "Content-Type: application/json" \
  --data '{"name":"ALLOWED_EMAILS","text":"Kazu12127823@gmail.com,hiruta@kanpake.com","type":"secret_text"}'
```

## デプロイ方法

```bash
cd ~/hiruta/hiruta-cms-gateway
CLOUDFLARE_API_TOKEN="<token>" CLOUDFLARE_ACCOUNT_ID="6b4e233890f439ffe0c1cf327df580e1" npx wrangler deploy
```

## デバッグ方法

```bash
# リアルタイムログ確認
cd ~/hiruta/hiruta-cms-gateway
CLOUDFLARE_API_TOKEN="<token>" npx wrangler tail

# ログには以下が出力される:
# [OTP] Sending to: xxx@gmail.com, code: 123456  ← メール送信できない場合に確認
# [Auth] GET /github/... - user: xxx@gmail.com   ← 認証済みリクエスト
# [GitHub Proxy] GET https://api.github.com/...  ← GitHub APIへの転送
```

## 既知の制約と注意事項

### OTP メール送信

MailChannels Free API を使用している。Cloudflare Workers から無料で送信可能だが、
`hiruta-lp.pages.dev` ドメインに SPF レコードが設定されていない場合、
迷惑メールに振り分けられることがある。

SPF レコードを追加する場合（Cloudflare DNS の TXT レコード）:
```
v=spf1 include:relay.mailchannels.net ~all
```

### カスタムドメインへの対応

ドメイン取得後は以下を更新:
1. `wrangler.toml` の routes にカスタムドメインを追加
2. `config.yml` の `base_url` を新しい Worker URL に更新

### セッション有効期限

- OTP: 10分
- セッション（ログイン状態）: 4時間

4時間後は再ログインが必要。

### One-time PIN vs Gmail OAuth

現在はメール OTP 認証のみ対応。
将来的に Gmail OAuth（Google IdP）に切り替える場合は、Worker の認証フローを変更する。

### Cloudflare Workers β プランへの移行時の注意（ブランディングについて）

**Worker（この Gateway）側のブランディングは β 移行時に消える。**

Cloudflare Workers の Paid（β）プランに移行すると、このWorkerは削除または再デプロイが必要になる。
その際、`src/index.ts` の `htmlPage()` に書かれた Hiruta Studio ブランディング（認証画面のデザイン・カラー）は引き継がれない。

**ただし Decap CMS 側（`hiruta-lp-astro/public/admin/index.html`）のブランディングは β 移行後も維持される。**

`index.html` は Decap CMS の backend 設定（`base_url`）とは独立しており、
バックエンドが何であれ Hiruta Studio のブランド表示（ロゴ・カラー・フォント・ボタン文言）は機能し続ける。

| コンポーネント | β 移行後の状態 | 理由 |
|--------------|--------------|------|
| Worker 認証画面（/auth）| 要再ブランディング | Worker 自体の再デプロイが必要 |
| Decap CMS admin UI（/admin）| **自動で引き継がれる** | `index.html` は backend 非依存 |

β 移行後に認証画面を再ブランディングする場合は、`src/index.ts` の `htmlPage()` 関数を
ブランドパレット（README の Hiruta Studio 仕様）に合わせて更新してデプロイすること。

## 構成

```
hiruta-cms-gateway/
├── src/
│   └── index.ts      # Worker メインコード
├── wrangler.toml     # Cloudflare 設定
├── package.json
├── tsconfig.json
└── README.md
```

## E2E 動作確認手順（人間が実施）

1. ブラウザで `https://hiruta-lp.pages.dev/admin` を開く
2. Decap CMS が Worker の `/auth` にリダイレクトする（メール入力フォームが表示される）
3. 登録済みのメールアドレス（例: `Kazu12127823@gmail.com`）を入力して「確認コードを送る」
4. メールに届いた6桁のコードを入力
5. Decap CMS の管理画面が表示される
6. 「サイト設定」や「お客様の声」を編集して「Save」
7. GitHub リポジトリ `naruNaru1212/hiruta-lp-astro` に新しいコミットが作成される
8. Cloudflare Pages が自動再デプロイ（1〜2分）
9. `https://hiruta-lp.pages.dev` で変更が反映されていることを確認

### トラブルシューティング

| 症状 | 原因 | 対応 |
|------|------|------|
| OTP メールが届かない | SPF/MailChannels 設定 | `wrangler tail` でコードをログで確認。OTP は `[OTP] Sending to: ... code: XXXXXX` に出力される |
| 「このメールアドレスは登録されていません」 | ALLOWED_EMAILS に未登録 | 上記の Secret 更新手順でメールを追加 |
| 認証後に CMS が開かない | postMessage の受信失敗 | Worker が `/auth/callback` を返しているか確認（ブラウザの開発者ツール → ネットワーク） |
| 保存できない / 401 エラー | セッション切れ | ページを再読み込みして再ログイン |
| GitHub API エラー | PAT の権限不足 | PAT に `repo`（フルアクセス）権限があるか確認 |
