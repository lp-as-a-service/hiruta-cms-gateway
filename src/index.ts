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
 * GET  /auth               - OTP ログインフォーム
 * POST /auth/send-otp      - OTP 生成・メール送信
 * GET  /auth/verify        - OTP 入力フォーム
 * POST /auth/verify        - OTP 検証 → セッショントークン発行
 * GET  /auth/callback      - Decap CMS OAuth callback（postMessage）
 * GET  /github/*           - GitHub API プロキシ（セッション検証付き）
 * POST /github/*           - GitHub API プロキシ
 * PUT  /github/*           - GitHub API プロキシ
 * PATCH /github/*          - GitHub API プロキシ
 * DELETE /github/*         - GitHub API プロキシ
 */

export interface Env {
  GITHUB_TOKEN: string;    // 管理者の GitHub PAT
  SESSION_SECRET: string;  // OTP・セッション署名用シークレット（32文字以上推奨）
  ALLOWED_EMAILS: string;  // カンマ区切りの許可メールアドレス
  GITHUB_REPO: string;     // "naruNaru1212/hiruta-lp-astro"
  GITHUB_BRANCH: string;   // "main"
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

function isAllowedEmail(email: string, allowedList: string): boolean {
  const emails = allowedList.split(',').map(e => e.trim().toLowerCase());
  return emails.includes(email.toLowerCase());
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
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      background: #f5f5f0;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .card {
      background: white;
      border-radius: 12px;
      padding: 40px;
      width: 100%;
      max-width: 400px;
      box-shadow: 0 4px 24px rgba(0,0,0,0.08);
    }
    .logo {
      font-size: 13px;
      color: #999;
      margin-bottom: 24px;
      letter-spacing: 0.05em;
      text-transform: uppercase;
    }
    h1 { font-size: 22px; font-weight: 600; color: #1a1a1a; margin-bottom: 8px; }
    p.desc { font-size: 14px; color: #666; margin-bottom: 28px; line-height: 1.6; }
    label { display: block; font-size: 13px; font-weight: 500; color: #444; margin-bottom: 6px; }
    input[type="email"], input[type="text"] {
      width: 100%;
      padding: 12px 14px;
      border: 1.5px solid #e0e0e0;
      border-radius: 8px;
      font-size: 15px;
      color: #1a1a1a;
      outline: none;
      transition: border-color 0.2s;
      margin-bottom: 16px;
    }
    input:focus { border-color: #2563eb; }
    button[type="submit"] {
      width: 100%;
      padding: 13px;
      background: #1a1a1a;
      color: white;
      border: none;
      border-radius: 8px;
      font-size: 15px;
      font-weight: 500;
      cursor: pointer;
      transition: background 0.2s;
    }
    button[type="submit"]:hover { background: #333; }
    .error {
      background: #fef2f2;
      border: 1px solid #fecaca;
      color: #dc2626;
      padding: 10px 14px;
      border-radius: 8px;
      font-size: 14px;
      margin-bottom: 16px;
    }
    .info {
      background: #eff6ff;
      border: 1px solid #bfdbfe;
      color: #1d4ed8;
      padding: 10px 14px;
      border-radius: 8px;
      font-size: 14px;
      margin-bottom: 16px;
    }
    .hint { font-size: 13px; color: #888; margin-top: 12px; text-align: center; }
    a { color: #2563eb; text-decoration: none; }
    a:hover { text-decoration: underline; }
  </style>
</head>
<body>
  <div class="card">
    <div class="logo">KANPAKE CMS</div>
    ${body}
  </div>
</body>
</html>`, {
    headers: { 'Content-Type': 'text/html; charset=utf-8' }
  });
}

// ================================================================
// メール送信（MailChannels Free API）
// Cloudflare Workers から無料で使える
// ================================================================

async function sendOTPEmail(to: string, otp: string): Promise<void> {
  console.log(`[OTP] Sending to: ${to}, code: ${otp}`);

  try {
    const response = await fetch('https://api.mailchannels.net/tx/v1/send', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        from: { email: 'noreply@hiruta-lp.pages.dev', name: 'KANPAKE CMS' },
        personalizations: [{ to: [{ email: to }] }],
        subject: '【KANPAKE CMS】ログイン確認コード',
        content: [
          {
            type: 'text/plain',
            value: `確認コード: ${otp}\n\nこのコードは10分間有効です。\nCMS画面に戻って入力してください。\n\n身に覚えのない場合は、このメールを無視してください。`
          },
          {
            type: 'text/html',
            value: `
<div style="font-family:sans-serif;max-width:400px;margin:0 auto;padding:32px 0;">
  <p style="color:#999;font-size:12px;letter-spacing:0.05em;text-transform:uppercase;margin-bottom:24px;">KANPAKE CMS</p>
  <h2 style="font-size:20px;font-weight:600;color:#1a1a1a;margin-bottom:8px;">ログイン確認コード</h2>
  <p style="color:#666;font-size:14px;margin-bottom:24px;">CMSにログインするための確認コードです。</p>
  <div style="background:#f5f5f0;border-radius:12px;padding:24px;text-align:center;margin-bottom:24px;">
    <span style="font-size:36px;font-weight:700;letter-spacing:12px;color:#1a1a1a;">${otp}</span>
  </div>
  <p style="color:#888;font-size:13px;">このコードは<strong>10分間</strong>有効です。<br>身に覚えのない場合は無視してください。</p>
</div>`
          }
        ]
      })
    });

    if (!response.ok) {
      const errText = await response.text();
      console.error(`[OTP] MailChannels failed: ${response.status} ${errText}`);
    } else {
      console.log(`[OTP] Email sent successfully to ${to}`);
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
  const errorHtml = error ? `<div class="error">${decodeURIComponent(error)}</div>` : '';

  // Decap CMS から渡されるパラメータを保持
  const params = url.searchParams.toString();

  return htmlPage('ログイン - KANPAKE CMS', `
    <h1>コンテンツ管理にログイン</h1>
    <p class="desc">登録済みのメールアドレスを入力してください。確認コードをお送りします。</p>
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

  if (!isAllowedEmail(email, env.ALLOWED_EMAILS)) {
    const newUrl = new URL(url);
    newUrl.pathname = '/auth';
    newUrl.searchParams.set('error', encodeURIComponent('このメールアドレスは登録されていません'));
    return Response.redirect(newUrl.toString(), 302);
  }

  // OTPトークン生成（ステートレス、KV不要）
  const { otp, token } = await generateOTPToken(email, env.SESSION_SECRET);

  // メール送信（非同期、失敗しても処理継続）
  await sendOTPEmail(email, otp);

  // OTP入力フォームへリダイレクト（トークンをクエリに含める）
  const verifyUrl = new URL(url);
  verifyUrl.pathname = '/auth/verify';
  verifyUrl.searchParams.set('email', email);
  verifyUrl.searchParams.set('t', token);
  return Response.redirect(verifyUrl.toString(), 302);
}

async function handleVerifyGet(request: Request): Promise<Response> {
  const url = new URL(request.url);
  const email = url.searchParams.get('email') || '';
  const error = url.searchParams.get('error') || '';

  const msgHtml = error
    ? `<div class="error">${decodeURIComponent(error)}</div>`
    : `<div class="info">確認コードを <strong>${email}</strong> に送信しました。</div>`;

  // hidden で全パラメータを保持
  const hiddenInputs = Array.from(url.searchParams.entries())
    .filter(([k]) => k !== 'error')
    .map(([k, v]) => `<input type="hidden" name="${k}" value="${encodeURIComponent(v)}">`)
    .join('\n');

  return htmlPage('確認コードの入力 - KANPAKE CMS', `
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
    <p class="hint">コードが届かない場合は <a href="/auth?${new URL(request.url).searchParams.toString()}">最初からやり直す</a></p>
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

  // Decap CMS の OAuth callback へリダイレクト
  const callbackUrl = new URL(url);
  callbackUrl.pathname = '/auth/callback';
  callbackUrl.searchParams.set('token', sessionToken);
  return Response.redirect(callbackUrl.toString(), 302);
}

async function handleCallback(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const token = url.searchParams.get('token') || '';

  const email = await verifySessionToken(token, env.SESSION_SECRET);
  if (!email) {
    return htmlPage('認証エラー', `
      <h1>認証に失敗しました</h1>
      <p class="desc">セッションが無効です。<a href="/auth">再度ログイン</a>してください。</p>
    `);
  }

  // Decap CMS が期待する postMessage 形式
  // "authorization:github:success:{"token":"...","provider":"github"}"
  const cmsToken = JSON.stringify({ token: token, provider: 'github' });
  const postMessageContent = `authorization:github:success:${cmsToken}`;

  return new Response(`<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="utf-8">
  <title>認証完了 - KANPAKE CMS</title>
</head>
<body>
  <script>
  (function() {
    var msg = ${JSON.stringify(postMessageContent)};
    if (window.opener) {
      window.opener.postMessage(msg, "*");
      setTimeout(function() { window.close(); }, 500);
    } else {
      document.body.innerHTML = '<p style="font-family:sans-serif;padding:40px;text-align:center;color:#666;">認証完了。このウィンドウを閉じてください。</p>';
    }
  })();
  </script>
  <p style="font-family:sans-serif;padding:40px;text-align:center;color:#666;">認証中...</p>
</body>
</html>`, {
    headers: { 'Content-Type': 'text/html; charset=utf-8' }
  });
}

// ================================================================
// GitHub API プロキシ
// ================================================================

async function proxyGitHub(request: Request, env: Env): Promise<Response> {
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

  const body = !['GET', 'HEAD'].includes(request.method)
    ? await request.arrayBuffer()
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
    if (pathname === '/auth/callback') return handleCallback(request, env);

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
      return proxyGitHub(request, env);
    }

    return new Response(JSON.stringify({ error: 'Not Found' }), {
      status: 404,
      headers: { 'Content-Type': 'application/json' }
    });
  }
};
