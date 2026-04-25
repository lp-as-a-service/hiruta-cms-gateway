/**
 * hiruta-cms-gateway
 *
 * Cloudflare Worker で Decap CMS の GitHub OAuth プロキシを実装。
 *
 * 設計（ステートレス版）:
 * - クライアント（蛭田さん）は GitHub アカウント不要
 * - メール + OTP で認証（OTP は HMAC 署名付きトークンで検証、KV不要）
 * - GitHub API 呼び出しは Worker 内の PAT で代理実行
 * - セッションも署名付き JWT 形式（KV 不要）
 *
 * エンドポイント:
 * GET  /auth               - OTP ログインフォーム（メールアドレス入力）
 * POST /auth/send-otp      - OTP 生成・メール送信
 * GET  /auth/verify        - OTP 入力フォーム
 * POST /auth/verify        - OTP 検証 → redirect flow でトークンを返す（redirect パラメータ必須）
 * GET  /invite?t=<token>   - 招待URL（メアド登録フォーム表示）
 * POST /invite             - メアド登録処理 → OTP送信 → /auth/verify にリダイレクト
 * GET  /github/*           - GitHub API プロキシ（セッション検証付き）
 * POST /github/*           - GitHub API プロキシ
 * PUT  /github/*           - GitHub API プロキシ
 * PATCH /github/*          - GitHub API プロキシ
 * DELETE /github/*         - GitHub API プロキシ
 *
 * 廃止:
 * GET /auth/callback       - popup flow 用（廃止。redirect flow のみ）
 */

// ============================================================
// SECURITY NOTE:
// HTML出力でユーザー入力を含める際は必ず escapeHtml() を経由すること。
// 新規エンドポイント追加時も同ルールを厳守。
// 詳細: tests/xss-regression.sh を参照（回帰テスト）
// ============================================================

export interface Env {
  GITHUB_TOKEN: string;    // 管理者の GitHub PAT
  SESSION_SECRET: string;  // OTP・セッション署名用シークレット（32文字以上推奨）
  MASTER_EMAIL: string;    // マスター管理者メールアドレス（常時ログイン可能）
  GITHUB_REPO: string;     // "lp-as-a-service/hiruta-lp-astro"
  GITHUB_BRANCH: string;   // "main"
  RESEND_API_KEY: string;  // Resend API key（re_xxx）
  HIRUTA_STUDIO_AUTH: KVNamespace; // 招待トークン・ユーザー管理 KV
  HIRUTA_QUOTA: KVNamespace;       // 顧客別画像アップロード容量quota KV
}

// ================================================================
// HMAC ユーティリティ（KV不要のステートレス署名）
// ================================================================

async function hmacSign(secret: string, data: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data));
  // base64url エンコード（URLセーフ）
  return btoa(String.fromCharCode(...new Uint8Array(sig)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

async function hmacVerify(secret: string, data: string, signature: string): Promise<boolean> {
  const expected = await hmacSign(secret, data);
  // タイミング攻撃対策の定数時間比較
  if (expected.length !== signature.length) return false;
  let diff = 0;
  for (let i = 0; i < expected.length; i++) {
    diff |= expected.charCodeAt(i) ^ signature.charCodeAt(i);
  }
  return diff === 0;
}

// OTP トークン生成: `otp:email:code:timestamp:HMAC`
// - KV不要でステートレス
// - timestamp で10分の有効期限
// - 一度使ったOTPの再使用防止は「同じコードを何度も使えない」=OTPが6桁乱数なので実用上問題なし
async function generateOTPToken(email: string, secret: string): Promise<{ otp: string; token: string }> {
  const otp = String(Math.floor(Math.random() * 1000000)).padStart(6, '0');
  const timestamp = Math.floor(Date.now() / 1000);
  const payload = `${email}:${otp}:${timestamp}`;
  const sig = await hmacSign(secret, payload);
  const token = btoa(`${payload}:${sig}`).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  return { otp, token };
}

async function verifyOTPToken(token: string, inputOTP: string, secret: string): Promise<string | null> {
  try {
    // base64url デコード
    const padded = token.replace(/-/g, '+').replace(/_/g, '/');
    const decoded = atob(padded.padEnd(padded.length + (4 - padded.length % 4) % 4, '='));
    const parts = decoded.split(':');
    if (parts.length < 4) return null;

    const sig = parts[parts.length - 1];
    const timestamp = parseInt(parts[parts.length - 2], 10);
    const storedOTP = parts[parts.length - 3];
    const email = parts.slice(0, -3).join(':');

    const payload = `${email}:${storedOTP}:${timestamp}`;
    const valid = await hmacVerify(secret, payload, sig);
    if (!valid) return null;

    // 10分以内か確認
    const now = Math.floor(Date.now() / 1000);
    if (now - timestamp > 600) return null; // 期限切れ

    // OTPが一致するか確認
    if (storedOTP !== inputOTP) return null;

    return email;
  } catch {
    return null;
  }
}

// セッショントークン生成: base64url( `email:timestamp:HMAC` )
// - 有効期限: 4時間
async function createSessionToken(email: string, secret: string): Promise<string> {
  const timestamp = Math.floor(Date.now() / 1000);
  const payload = `${email}:${timestamp}`;
  const sig = await hmacSign(secret, payload);
  const token = btoa(`${payload}:${sig}`).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  return token;
}

async function verifySessionToken(token: string, secret: string): Promise<string | null> {
  try {
    const padded = token.replace(/-/g, '+').replace(/_/g, '/');
    const decoded = atob(padded.padEnd(padded.length + (4 - padded.length % 4) % 4, '='));
    const parts = decoded.split(':');
    if (parts.length < 3) return null;

    const sig = parts[parts.length - 1];
    const timestamp = parseInt(parts[parts.length - 2], 10);
    const email = parts.slice(0, -2).join(':');

    const payload = `${email}:${timestamp}`;
    const valid = await hmacVerify(secret, payload, sig);
    if (!valid) return null;

    // 4時間以内か確認
    const now = Math.floor(Date.now() / 1000);
    if (now - timestamp > 14400) return null;

    return email;
  } catch {
    return null;
  }
}

async function isAllowedEmail(email: string, env: Env): Promise<boolean> {
  const normalizedEmail = email.toLowerCase().trim();
  // マスターメアドは無条件許可
  if (normalizedEmail === env.MASTER_EMAIL.toLowerCase().trim()) {
    return true;
  }
  // KV で登録済みユーザーを確認
  const user = await env.HIRUTA_STUDIO_AUTH.get<{ allowed: boolean }>(`user:${normalizedEmail}`, 'json');
  return user !== null && user.allowed === true;
}

// ================================================================
// 共通ユーティリティ
// ================================================================

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// ================================================================
// HTML テンプレート
// ================================================================

function htmlPage(title: string, body: string): Response {
  return new Response(`<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${title}</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin="">
  <link href="https://fonts.googleapis.com/css2?family=Shippori+Mincho+B1:wght@400;600;700&family=Noto+Sans+JP:wght@400;500;700&display=swap" rel="stylesheet">
  <style>
    :root {
      --hs-primary:   #3d5a3e;
      --hs-primary-d: #243d26;
      --hs-primary-m: #4a6741;
      --hs-primary-l: #5a7a5c;
      --hs-bg:        #faf8f4;
      --hs-bg-warm:   #f4f0e8;
      --hs-accent:    #8c7355;
      --hs-accent-d:  #6a5a48;
      --hs-text:      #333333;
      --hs-text-sub:  #666666;
      --hs-border:    #ddd0c0;
      --hs-serif:     'Shippori Mincho B1', serif;
      --hs-sans:      'Noto Sans JP', sans-serif;
    }
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    html { font-size: 16px; }
    body {
      font-family: var(--hs-sans);
      background: var(--hs-bg);
      min-height: 100vh;
      min-width: 320px;
      display: flex;
      flex-direction: column;
      color: var(--hs-text);
    }
    /* 固定ヘッダー */
    .hs-header {
      position: fixed;
      top: 0; left: 0; right: 0;
      height: 52px;
      background: var(--hs-primary);
      display: flex;
      align-items: center;
      padding: 0 24px;
      z-index: 100;
    }
    .hs-header-brand {
      font-family: var(--hs-serif);
      font-size: 17px;
      font-weight: 600;
      color: #ffffff;
      letter-spacing: 0.08em;
    }
    /* メインコンテンツ（ヘッダー分下げる） */
    .hs-body {
      flex: 1;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 88px 20px 48px;
    }
    /* カード */
    .card {
      background: white;
      border-radius: 12px;
      padding: 40px 36px 44px;
      width: 100%;
      max-width: 420px;
      box-shadow: 0 4px 32px rgba(61,90,62,0.08);
      border: 1px solid var(--hs-border);
    }
    @media (max-width: 480px) {
      .card { padding: 32px 24px 36px; border-radius: 8px; }
    }
    /* カード内ブランドラベル */
    .brand {
      font-family: var(--hs-serif);
      font-size: 12px;
      font-weight: 600;
      color: var(--hs-primary);
      letter-spacing: 0.15em;
      text-transform: uppercase;
      margin-bottom: 20px;
    }
    /* 見出し・説明 */
    h1 {
      font-family: var(--hs-serif);
      font-size: 21px;
      font-weight: 700;
      color: var(--hs-primary-d);
      line-height: 1.6;
      margin-bottom: 8px;
      letter-spacing: 0.03em;
    }
    p.desc {
      font-size: 14px;
      color: var(--hs-text-sub);
      margin-bottom: 28px;
      line-height: 1.85;
    }
    /* フォームラベル */
    label {
      display: block;
      font-size: 13px;
      font-weight: 500;
      color: var(--hs-accent-d);
      margin-bottom: 6px;
      letter-spacing: 0.02em;
    }
    /* 入力フィールド */
    input[type="email"],
    input[type="text"] {
      width: 100%;
      padding: 12px 14px;
      border: 1.5px solid var(--hs-border);
      border-radius: 7px;
      font-size: 15px;
      font-family: var(--hs-sans);
      color: var(--hs-text);
      outline: none;
      transition: border-color 0.2s, box-shadow 0.2s, background 0.2s;
      margin-bottom: 16px;
      background: var(--hs-bg);
      -webkit-appearance: none;
      appearance: none;
    }
    input:focus {
      border-color: var(--hs-primary);
      box-shadow: 0 0 0 3px rgba(61,90,62,0.14);
      background: white;
    }
    /* 送信ボタン */
    button[type="submit"] {
      width: 100%;
      padding: 14px;
      background: var(--hs-primary);
      color: white;
      border: none;
      border-radius: 7px;
      font-size: 15px;
      font-family: var(--hs-sans);
      font-weight: 500;
      cursor: pointer;
      transition: background 0.18s ease, box-shadow 0.18s ease, transform 0.12s ease;
      letter-spacing: 0.04em;
      -webkit-tap-highlight-color: transparent;
    }
    button[type="submit"]:hover {
      background: var(--hs-primary-m);
      box-shadow: 0 4px 16px rgba(61,90,62,0.22);
      transform: translateY(-1px);
    }
    button[type="submit"]:active {
      background: var(--hs-primary-d);
      box-shadow: none;
      transform: translateY(0);
    }
    button[type="submit"]:focus-visible {
      outline: 3px solid var(--hs-primary);
      outline-offset: 2px;
    }
    /* エラー表示（柔らかい枠付き） */
    .error {
      background: #fef9f9;
      border: 1px solid #f5c6c6;
      border-left: 3px solid #d9534f;
      border-radius: 6px;
      padding: 11px 14px 11px 36px;
      font-size: 13px;
      color: #8b2020;
      margin-bottom: 16px;
      line-height: 1.7;
      position: relative;
    }
    .error::before {
      content: '!';
      position: absolute;
      left: 12px;
      top: 50%;
      transform: translateY(-50%);
      width: 17px;
      height: 17px;
      border-radius: 50%;
      background: #d9534f;
      color: #fff;
      font-size: 11px;
      font-weight: 700;
      display: flex;
      align-items: center;
      justify-content: center;
      line-height: 1;
      text-align: center;
    }
    /* インフォ表示 */
    .info {
      background: var(--hs-bg-warm);
      border: 1px solid var(--hs-border);
      border-left: 3px solid var(--hs-accent);
      color: var(--hs-accent-d);
      padding: 11px 14px;
      border-radius: 6px;
      font-size: 14px;
      margin-bottom: 16px;
      line-height: 1.7;
    }
    .info strong { color: var(--hs-primary-d); font-weight: 700; }
    /* ヒント・リンク */
    .hint { font-size: 13px; color: var(--hs-text-sub); margin-top: 16px; text-align: center; line-height: 1.8; }
    a { color: var(--hs-primary); text-decoration: none; }
    a:hover { text-decoration: underline; color: var(--hs-primary-d); }
  </style>
</head>
<body>
  <header class="hs-header">
    <span class="hs-header-brand">Hiruta Studio</span>
  </header>
  <div class="hs-body">
    <div class="card">
      <div class="brand">Hiruta Studio</div>
      ${body}
    </div>
  </div>
</body>
</html>`, {
    headers: { 'Content-Type': 'text/html; charset=utf-8' }
  });
}

// ================================================================
// メール送信（Resend API）
// https://resend.com/ のAPI経由でOTPメールを送信。
// 送信元ドメイン `onboarding@resend.dev` は Resend 提供の検証済み共有ドメイン。
// 独自ドメインを使う場合は Resend Dashboard で DNS検証後、from を差し替える。
// ================================================================

async function sendOTPEmail(to: string, otp: string, env: Env): Promise<void> {
  console.log(`[OTP] Sending to: ${to}, code: ${otp}`);

  if (!env.RESEND_API_KEY) {
    console.error(`[OTP] RESEND_API_KEY is not set. OTP=${otp} for ${to}`);
    return;
  }

  const htmlBody = `
<div style="font-family:'Helvetica Neue',Arial,'Noto Sans JP',sans-serif;max-width:440px;margin:0 auto;padding:40px 32px;background:#faf8f4;">
  <p style="font-size:18px;font-weight:600;color:#3d5a3e;margin-bottom:28px;letter-spacing:0.06em;">Hiruta Studio</p>
  <div style="background:white;border-radius:16px;padding:36px 32px;border:1px solid #ddd0c0;box-shadow:0 2px 16px rgba(61,90,62,0.06);">
    <h2 style="font-size:18px;font-weight:500;color:#333333;margin-bottom:8px;">ログイン確認コード</h2>
    <p style="color:#666666;font-size:14px;margin-bottom:28px;line-height:1.7;">サイト編集画面にログインするための確認コードです。</p>
    <div style="background:#f4f0e8;border-radius:12px;padding:28px;text-align:center;margin-bottom:28px;border:1px solid #ddd0c0;">
      <span style="font-size:38px;font-weight:700;letter-spacing:12px;color:#3d5a3e;">${otp}</span>
    </div>
    <p style="color:#888;font-size:13px;line-height:1.7;">このコードは<strong style="color:#3d5a3e;">10分間</strong>有効です。<br>身に覚えのない場合は、このメールを無視してください。</p>
  </div>
  <p style="color:#aaa;font-size:12px;margin-top:24px;text-align:center;">Hiruta Studio — サイト編集システム</p>
</div>`;

  const textBody = `確認コード: ${otp}\n\nこのコードは10分間有効です。\nCMS画面に戻って入力してください。\n\n身に覚えのない場合は、このメールを無視してください。`;

  try {
    const response = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${env.RESEND_API_KEY}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        from: 'Hiruta Studio <noreply@mail.tomorrow-akashi.com>',
        to: [to],
        subject: '【Hiruta Studio】ログイン確認コード',
        html: htmlBody,
        text: textBody
      })
    });

    if (!response.ok) {
      const errText = await response.text();
      console.error(`[OTP] Resend failed: ${response.status} ${errText}`);
    } else {
      const result = await response.json() as { id?: string };
      console.log(`[OTP] Email sent successfully to ${to} (id: ${result.id ?? 'unknown'})`);
    }
  } catch (e) {
    console.error(`[OTP] Email exception:`, e);
  }
}

// ================================================================
// 認証ハンドラー
// ================================================================

async function handleAuthGet(request: Request): Promise<Response> {
  const url = new URL(request.url);
  const error = url.searchParams.get('error') || '';
  const errorHtml = error ? `<div class="error">${escapeHtml(decodeURIComponent(error))}</div>` : '';

  // redirect パラメータ（Worker middleware から渡される）と Decap CMS パラメータを保持
  const params = url.searchParams.toString();

  return htmlPage('ログイン - Hiruta Studio', `
    <h1>サイトの編集にログインします</h1>
    <p class="desc">登録済みのメールアドレスに確認コードをお送りします。</p>
    ${errorHtml}
    <form method="POST" action="/auth/send-otp?${params}">
      <label>メールアドレス</label>
      <input type="email" name="email" placeholder="your@email.com" required autofocus>
      <button type="submit">確認コードを送る</button>
    </form>
  `);
}

async function handleSendOTP(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const formData = await request.formData();
  const email = (formData.get('email') as string || '').trim().toLowerCase();

  if (!email) {
    const newUrl = new URL(url);
    newUrl.pathname = '/auth';
    newUrl.searchParams.set('error', encodeURIComponent('メールアドレスを入力してください'));
    return Response.redirect(newUrl.toString(), 302);
  }

  if (!(await isAllowedEmail(email, env))) {
    const newUrl = new URL(url);
    newUrl.pathname = '/auth';
    newUrl.searchParams.set('error', encodeURIComponent('このメールアドレスは登録されていません'));
    return Response.redirect(newUrl.toString(), 302);
  }

  // OTPトークン生成（ステートレス、KV不要）
  const { otp, token } = await generateOTPToken(email, env.SESSION_SECRET);

  // メール送信（非同期、失敗しても処理継続）
  await sendOTPEmail(email, otp, env);

  // OTP入力フォームへリダイレクト（トークンをクエリに含める）
  // 前回の ?error=... が残らないよう delete してから必要なものだけ set する
  const verifyUrl = new URL(url);
  verifyUrl.pathname = '/auth/verify';
  verifyUrl.searchParams.delete('error');
  verifyUrl.searchParams.set('email', email);
  verifyUrl.searchParams.set('t', token);
  return Response.redirect(verifyUrl.toString(), 302);
}

async function handleVerifyGet(request: Request): Promise<Response> {
  const url = new URL(request.url);
  const email = url.searchParams.get('email') || '';
  const error = url.searchParams.get('error') || '';
  const resent = url.searchParams.get('resent') === '1';

  const msgHtml = error
    ? `<div class="error">${escapeHtml(decodeURIComponent(error))}</div>`
    : resent
    ? `<div class="info" style="background:#eaf5ea;border-left:4px solid #3d5a3e;padding:12px 16px;">✓ <strong>${escapeHtml(email)}</strong> に確認コードを再送信しました。受信箱をご確認ください。</div>`
    : `<div class="info">確認コードを <strong>${escapeHtml(email)}</strong> に送信しました。</div>`;

  // hidden で全パラメータを保持（HTML エスケープのみ。URL エンコードしない）
  // ※ resent フラグは再送信確認メッセージの一度きり表示目的なので hiddenInputs から除外
  //    （除外しないと POST /auth/verify 経由で resent=1 が残り続け、誤メッセージ再表示の原因になる）
  const hiddenInputs = Array.from(url.searchParams.entries())
    .filter(([k]) => k !== 'error' && k !== 'resent')
    .map(([k, v]) => `<input type="hidden" name="${escapeHtml(k)}" value="${escapeHtml(v)}">`)
    .join('\n');

  // 再送信フォームの action URL に resent=1 を付与（redirect先で "再送信しました" 表示）
  const resendParams = new URLSearchParams(url.searchParams);
  resendParams.delete('error');
  resendParams.set('resent', '1');

  return htmlPage('確認コードの入力 - Hiruta Studio', `
    <h1>確認コードを入力</h1>
    <p class="desc">メールに届いた6桁のコードを入力してください。</p>
    ${msgHtml}
    <form method="POST" action="/auth/verify">
      ${hiddenInputs}
      <label>確認コード（6桁）</label>
      <input type="text" name="otp" placeholder="000000" maxlength="6"
        pattern="[0-9]{6}" inputmode="numeric" required autofocus
        style="text-align:center;font-size:24px;letter-spacing:8px;">
      <button type="submit">ログイン</button>
    </form>
    <form method="POST" action="/auth/send-otp?${resendParams.toString()}" style="margin-top:12px;">
      <input type="hidden" name="email" value="${escapeHtml(email)}">
      <p class="hint" style="text-align:center;">コードが届かない場合は
        <button type="submit" style="background:none;border:none;color:var(--hs-primary);text-decoration:underline;cursor:pointer;font-size:inherit;padding:0;font-family:inherit;">確認コードを再送信</button>
      </p>
    </form>
  `);
}

async function handleVerifyPost(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const formData = await request.formData();
  const email = (formData.get('email') as string || '').trim().toLowerCase();
  const otp = (formData.get('otp') as string || '').trim();
  const token = formData.get('t') as string || '';

  // OTPトークン検証（ステートレス）
  const verifiedEmail = await verifyOTPToken(token, otp, env.SESSION_SECRET);

  if (!verifiedEmail || verifiedEmail !== email) {
    const verifyUrl = new URL(url);
    verifyUrl.pathname = '/auth/verify';
    // 元のパラメータ（provider, site_id等）を保持しつつエラーを追加
    for (const [k, v] of formData.entries()) {
      if (k !== 'otp') verifyUrl.searchParams.set(k, v as string);
    }
    verifyUrl.searchParams.set('error', encodeURIComponent('コードが正しくないか期限切れです。再度お試しください。'));
    return Response.redirect(verifyUrl.toString(), 302);
  }

  // セッショントークン発行
  const sessionToken = await createSessionToken(verifiedEmail, env.SESSION_SECRET);

  // OTP検証成功 → CMS admin へリダイレクト + Set-Cookie
  // redirect パラメータが欠けた/不正な場合はデフォルト CMS admin URL にフォールバック
  // （OTP検証で認証は既に完了しているため、redirect 未指定でもユーザーを admin に送る）
  const DEFAULT_ADMIN_URL = 'https://hiruta-studio.com/admin/';
  const rawRedirect = formData.get('redirect') as string | null;
  let redirectTarget = DEFAULT_ADMIN_URL;
  if (rawRedirect) {
    try {
      const dest = new URL(rawRedirect);
      // セキュリティ: workers.dev ドメインのみ許可（それ以外はデフォルトにフォールバック）
      if (dest.hostname.endsWith('.workers.dev') || dest.hostname === 'localhost' || dest.hostname === 'hiruta-studio.com' || dest.hostname.endsWith('.hiruta-studio.com')) {
        redirectTarget = rawRedirect;
      }
    } catch {
      // URL パース失敗はデフォルトにフォールバック
    }
  }

  {
    const dest = new URL(redirectTarget);
    // クエリで認証済みフラグ、fragment でトークンを渡す
    dest.searchParams.set('hs_authed', '1');
    const destWithFragment = dest.toString() + '#hs_token=' + encodeURIComponent(sessionToken);

    // Set-Cookie でセッションを設定（次回以降の Worker ガードをパスさせる）
    return new Response(null, {
      status: 302,
      headers: {
        'Location': destWithFragment,
        'Set-Cookie': `hs_session=${sessionToken}; Path=/; Secure; SameSite=Lax; Max-Age=14400`
      }
    });
  }

  // redirect パラメータがない場合はエラー（popup flow は廃止。redirect flow のみ）
  return new Response(`<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>エラー - Hiruta Studio</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=Shippori+Mincho+B1:wght@400;600&family=Noto+Sans+JP:wght@400;500&display=swap" rel="stylesheet">
  <style>
    :root {
      --hs-primary: #3d5a3e; --hs-primary-d: #243d26;
      --hs-bg: #faf8f4; --hs-text: #333; --hs-text-sub: #666;
      --hs-border: #ddd0c0; --hs-serif: 'Shippori Mincho B1',serif; --hs-sans: 'Noto Sans JP',sans-serif;
    }
    *{box-sizing:border-box;margin:0;padding:0;}
    body{font-family:var(--hs-sans);background:var(--hs-bg);min-height:100vh;display:flex;align-items:center;justify-content:center;color:var(--hs-text);}
    .card{background:#fff;border-radius:12px;padding:44px 40px;width:100%;max-width:420px;box-shadow:0 4px 32px rgba(61,90,62,0.08);border:1px solid var(--hs-border);}
    .brand{font-family:var(--hs-serif);font-size:13px;font-weight:600;color:var(--hs-primary);letter-spacing:0.15em;text-transform:uppercase;margin-bottom:24px;}
    h1{font-family:var(--hs-serif);font-size:20px;font-weight:600;color:#333;margin-bottom:12px;}
    p{font-size:14px;color:var(--hs-text-sub);line-height:1.8;margin-bottom:24px;}
    a{display:block;text-align:center;padding:13px;background:var(--hs-primary);color:#fff;border-radius:7px;font-size:15px;font-family:var(--hs-sans);font-weight:500;text-decoration:none;transition:background .18s;}
    a:hover{background:var(--hs-primary-d);}
  </style>
</head>
<body>
  <div class="card">
    <div class="brand">Hiruta Studio</div>
    <h1>リクエストに問題があります</h1>
    <p>ログインページへの直接アクセスはできません。<br>サイト編集画面からログインしてください。</p>
    <a href="https://hiruta-studio.com/admin/">編集画面に戻る</a>
  </div>
</body>
</html>`, {
    status: 400,
    headers: { 'Content-Type': 'text/html; charset=utf-8' }
  });
}

// ================================================================
// 招待 URL ハンドラー
// ================================================================

interface InviteRecord {
  client_name: string;
  created_at: string;
  created_by: string;
}

interface UserRecord {
  allowed: boolean;
  client_name: string;
  role: string;
  added_at: string;
}

async function handleInviteGet(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const token = url.searchParams.get('t') || '';

  if (!token) {
    return htmlPage('このURLは使用できません - Hiruta Studio', `
      <h1>このURLは使用できません</h1>
      <p class="desc">URLの有効期限が切れているか、既に使用済みです。Hiruta Studio運営にお問い合わせください。</p>
    `);
  }

  const invite = await env.HIRUTA_STUDIO_AUTH.get<InviteRecord>(`invite:${token}`, 'json');

  if (!invite) {
    return htmlPage('このURLは使用できません - Hiruta Studio', `
      <h1>このURLは使用できません</h1>
      <p class="desc">URLの有効期限が切れているか、既に使用済みです。Hiruta Studio運営にお問い合わせください。</p>
    `);
  }

  return htmlPage(`${escapeHtml(invite.client_name)} 様へ - Hiruta Studio`, `
    <h1>${escapeHtml(invite.client_name)} 様、ようこそ</h1>
    <p class="desc">Hiruta Studio のログイン用メールアドレスを登録してください。</p>
    <form method="POST" action="/invite">
      <input type="hidden" name="token" value="${escapeHtml(token)}">
      <label>メールアドレス</label>
      <input type="email" name="email" placeholder="your@email.com" required autofocus>
      <button type="submit">登録する</button>
    </form>
    <p class="hint">このメールアドレスで、今後LPを編集できるようになります。</p>
  `);
}

async function handleInvitePost(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  let formData: FormData;
  try {
    formData = await request.formData();
  } catch {
    return new Response('Bad Request', { status: 400 });
  }

  const token = (formData.get('token') as string || '').trim();
  const email = (formData.get('email') as string || '').trim().toLowerCase();

  if (!token || !email) {
    return new Response('Bad Request: token and email are required', { status: 400 });
  }

  // GET→POST間の競合対策: 再検証
  const invite = await env.HIRUTA_STUDIO_AUTH.get<InviteRecord>(`invite:${token}`, 'json');

  if (!invite) {
    return htmlPage('このURLは使用できません - Hiruta Studio', `
      <h1>このURLは使用できません</h1>
      <p class="desc">URLの有効期限が切れているか、既に使用済みです。Hiruta Studio運営にお問い合わせください。</p>
    `);
  }

  // ユーザーを KV に登録
  const userRecord: UserRecord = {
    allowed: true,
    client_name: invite.client_name,
    role: 'client',
    added_at: new Date().toISOString()
  };
  await env.HIRUTA_STUDIO_AUTH.put(`user:${email}`, JSON.stringify(userRecord));

  // トークンをワンタイム化（削除）
  await env.HIRUTA_STUDIO_AUTH.delete(`invite:${token}`);

  // OTP を生成してメール送信
  const { otp, token: otpToken } = await generateOTPToken(email, env.SESSION_SECRET);
  await sendOTPEmail(email, otp, env);

  // /auth/verify にリダイレクト
  // 招待フロー用に redirect パラメータを埋め込む（verify 後に CMS admin へ戻すため）
  const verifyUrl = new URL(url);
  verifyUrl.pathname = '/auth/verify';
  verifyUrl.search = '';
  verifyUrl.searchParams.set('email', email);
  verifyUrl.searchParams.set('t', otpToken);
  verifyUrl.searchParams.set('redirect', 'https://hiruta-studio.com/admin/');
  return Response.redirect(verifyUrl.toString(), 302);
}

// ================================================================
// 顧客別画像アップロード容量quota管理
// ================================================================

const DEFAULT_QUOTA_BYTES = 200 * 1024 * 1024; // 200MB
const MEDIA_FOLDER_PREFIX = 'public/images/uploads/';

interface QuotaRecord {
  email: string;
  used_bytes: number;
  file_count: number;
  last_upload: string;
  quota_bytes: number;
}

/** Decap CMS の画像アップロード（PUT）判定 */
function isImageUpload(method: string, filePath: string): boolean {
  return method === 'PUT' && filePath.startsWith(MEDIA_FOLDER_PREFIX);
}

/** Decap CMS の画像削除（DELETE）判定 */
function isImageDelete(method: string, filePath: string): boolean {
  return method === 'DELETE' && filePath.startsWith(MEDIA_FOLDER_PREFIX);
}

/**
 * /github/repos/{owner}/{repo}/contents/{file_path} のパスから
 * {file_path} 部分を抽出する。マッチしない場合は null。
 */
function extractContentsFilePath(pathname: string): string | null {
  // pathname は /github/repos/owner/repo/contents/... の形式
  const match = pathname.match(/^\/github\/repos\/[^/]+\/[^/]+\/contents\/(.+)$/);
  return match ? match[1] : null;
}

/** base64エンコードされた画像の実バイト数を計算 */
function getBase64ContentSize(content: string): number {
  // base64は 4文字 → 3バイト。末尾の '=' パディングで補正。
  const padCount = (content.match(/={1,2}$/) ?? [''])[0].length;
  return Math.floor(content.length * 3 / 4) - padCount;
}

/** KVから quota レコードを取得（存在しなければデフォルト値を返す） */
async function getQuota(env: Env, email: string): Promise<QuotaRecord> {
  const record = await env.HIRUTA_QUOTA.get<QuotaRecord>(`quota:${email}`, 'json');
  if (record) return record;
  return {
    email,
    used_bytes: 0,
    file_count: 0,
    last_upload: '',
    quota_bytes: DEFAULT_QUOTA_BYTES,
  };
}

/** KVの quota レコードを更新する */
async function updateQuota(
  env: Env,
  email: string,
  deltaBytes: number,
  deltaFiles: number
): Promise<void> {
  const current = await getQuota(env, email);
  const updated: QuotaRecord = {
    ...current,
    used_bytes: Math.max(0, current.used_bytes + deltaBytes),
    file_count: Math.max(0, current.file_count + deltaFiles),
    last_upload: new Date().toISOString(),
  };
  await env.HIRUTA_QUOTA.put(`quota:${email}`, JSON.stringify(updated));
}

// ================================================================
// GitHub API プロキシ
// ================================================================

async function proxyGitHub(request: Request, env: Env, preReadBody?: ArrayBuffer): Promise<Response> {
  const url = new URL(request.url);

  // /github/repos/owner/repo/... → https://api.github.com/repos/owner/repo/...
  // Decap CMS は /api/v1 prefix を使う場合があるので柔軟に対応
  let githubPath = url.pathname.replace(/^\/github/, '');
  if (!githubPath.startsWith('/repos') && !githubPath.startsWith('/user')) {
    // /owner/repo/... の形式の場合は /repos/owner/repo/... に変換
    githubPath = '/repos' + githubPath;
  }
  const githubUrl = `https://api.github.com${githubPath}${url.search}`;

  const headers = new Headers();
  headers.set('Authorization', `token ${env.GITHUB_TOKEN}`);
  headers.set('User-Agent', 'hiruta-cms-gateway/1.0');
  headers.set('Accept', 'application/vnd.github.v3+json');

  // Content-Type は POST/PUT 時のみ転送
  const contentType = request.headers.get('Content-Type');
  if (contentType) headers.set('Content-Type', contentType);

  // preReadBody: quota処理がbodyを先読みした場合はそちらを使う（ストリームは1度しか読めない）
  const body = !['GET', 'HEAD'].includes(request.method)
    ? (preReadBody ?? await request.arrayBuffer())
    : undefined;

  console.log(`[GitHub Proxy] ${request.method} ${githubUrl}`);

  const response = await fetch(githubUrl, {
    method: request.method,
    headers,
    body
  });

  const resHeaders = new Headers();
  resHeaders.set('Content-Type', response.headers.get('Content-Type') || 'application/json');
  resHeaders.set('Access-Control-Allow-Origin', '*');
  resHeaders.set('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS');
  resHeaders.set('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  // GitHub の rate limit ヘッダーを転送
  for (const header of ['X-RateLimit-Limit', 'X-RateLimit-Remaining', 'X-RateLimit-Reset']) {
    const val = response.headers.get(header);
    if (val) resHeaders.set(header, val);
  }

  return new Response(response.body, {
    status: response.status,
    headers: resHeaders
  });
}

// ================================================================
// メインハンドラー
// ================================================================

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const pathname = url.pathname;
    const method = request.method;

    // CORS preflight
    if (method === 'OPTIONS') {
      return new Response(null, {
        status: 204,
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type, Authorization',
          'Access-Control-Max-Age': '86400'
        }
      });
    }

    // ヘルスチェック
    if (pathname === '/health') {
      return new Response(JSON.stringify({ status: 'ok', ts: Date.now() }), {
        headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
      });
    }

    // 認証フロー
    if (pathname === '/auth' && method === 'GET') return handleAuthGet(request);
    if (pathname === '/auth/send-otp' && method === 'POST') return handleSendOTP(request, env);
    if (pathname === '/auth/verify' && method === 'GET') return handleVerifyGet(request);
    if (pathname === '/auth/verify' && method === 'POST') return handleVerifyPost(request, env);

    // セッション生存確認（localStorage のトークンが有効かをクライアントが問い合わせる）
    // hiruta-studio.js が loadDecap() 前に呼び出し、無効なら入口画面に戻す
    if (pathname === '/auth/session' && method === 'GET') {
      const authHeader = request.headers.get('Authorization') || '';
      const token = authHeader.replace(/^(Bearer|token)\s+/i, '').trim();
      if (!token) {
        return new Response(JSON.stringify({ valid: false }), {
          status: 401,
          headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
        });
      }
      const email = await verifySessionToken(token, env.SESSION_SECRET);
      if (!email) {
        return new Response(JSON.stringify({ valid: false }), {
          status: 401,
          headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
        });
      }
      return new Response(JSON.stringify({ valid: true, email }), {
        status: 200,
        headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
      });
    }

    // 招待フロー
    if (pathname === '/invite' && method === 'GET') return handleInviteGet(request, env);
    if (pathname === '/invite' && method === 'POST') return handleInvitePost(request, env);

    // GitHub API プロキシ（セッション検証）
    if (pathname.startsWith('/github/')) {
      const authHeader = request.headers.get('Authorization') || '';
      // "token <session_token>" または "Bearer <session_token>" を受け付ける
      const token = authHeader.replace(/^(Bearer|token)\s+/i, '').trim();

      if (!token) {
        return new Response(JSON.stringify({ error: 'Unauthorized', message: 'Missing Authorization header' }), {
          status: 401,
          headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
        });
      }

      const email = await verifySessionToken(token, env.SESSION_SECRET);
      if (!email) {
        return new Response(JSON.stringify({ error: 'Unauthorized', message: 'Invalid or expired session token' }), {
          status: 401,
          headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
        });
      }

      console.log(`[Auth] ${method} ${pathname} - user: ${email}`);

      // ================================================================
      // quota tracking: 画像アップロード（PUT）/ 削除（DELETE）の検出
      // ================================================================
      const filePath = extractContentsFilePath(pathname);

      if (filePath !== null && isImageDelete(method, filePath)) {
        // 削除: file_count のみ減算（サイズ不明のため used_bytes は変更しない）
        console.log(`[Quota] DELETE ${filePath} - user: ${email}`);
        await updateQuota(env, email, 0, -1);
        return proxyGitHub(request, env);
      }

      if (filePath !== null && isImageUpload(method, filePath)) {
        // bodyを先読みして base64 content を取得
        const rawBody = await request.arrayBuffer();
        let parsedBody: { content?: string } = {};
        try {
          parsedBody = JSON.parse(new TextDecoder().decode(rawBody));
        } catch {
          // JSON parse 失敗時は quota チェックをスキップして既存処理に委譲
          console.warn(`[Quota] Body parse failed for PUT ${filePath} - user: ${email}`);
          return proxyGitHub(request, env, rawBody);
        }

        if (typeof parsedBody.content === 'string') {
          const newSize = getBase64ContentSize(parsedBody.content);
          const quota = await getQuota(env, email);

          console.log(`[Quota] Upload ${filePath} - user: ${email}, size: ${newSize}, used: ${quota.used_bytes}/${quota.quota_bytes}`);

          if (quota.used_bytes + newSize > quota.quota_bytes) {
            // quota 超過 → 413 を GitHub 互換形式で返す
            return new Response(
              JSON.stringify({
                message: `Upload quota exceeded. Used ${Math.round(quota.used_bytes / 1048576)}MB of ${Math.round(quota.quota_bytes / 1048576)}MB. Cannot upload ${Math.round(newSize / 1048576)}MB file.`,
                documentation_url: 'https://hiruta-studio.com/admin/'
              }),
              {
                status: 413,
                headers: {
                  'Content-Type': 'application/json',
                  'Access-Control-Allow-Origin': '*'
                }
              }
            );
          }

          // quota OK → GitHub に転送
          const ghResponse = await proxyGitHub(request, env, rawBody);

          // GitHub が 2xx を返した場合のみ quota を増やす
          if (ghResponse.status >= 200 && ghResponse.status < 300) {
            await updateQuota(env, email, newSize, 1);
            console.log(`[Quota] Updated - user: ${email}, new used: ${quota.used_bytes + newSize}`);
          }

          return ghResponse;
        }
        // content フィールドなし（テキストファイル等）→ 既存処理に委譲
        return proxyGitHub(request, env, rawBody);
      }

      // 上記以外（テキストファイル編集・ツリー取得等）→ 既存処理に委譲
      return proxyGitHub(request, env);
    }

    return new Response(JSON.stringify({ error: 'Not Found' }), {
      status: 404,
      headers: { 'Content-Type': 'application/json' }
    });
  }
};
