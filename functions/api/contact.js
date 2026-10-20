const TURNSTILE_VERIFY_URL = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
const TURNSTILE_ACTION = 'contact_send';
const ALLOWED_HOSTNAMES = new Set(['xenolith.jp', 'www.xenolith.jp']);
const ALLOWED_SUBJECTS = new Set([
  '事業に関するご相談',
  'ゲーム開発のご相談',
  'アプリ開発のご相談',
  'ディレクションのご相談',
  '企画立案のご相談',
  'プロトタイプ開発のご相談',
  'その他'
]);

const json = (body, status = 200) => new Response(JSON.stringify(body), {
  status,
  headers: {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store'
  }
});

export async function onRequestPost(context) {
  const { request, env } = context;

  if (!env.TURNSTILE_SECRET) {
    return json({ ok: false, error: 'server_not_configured' }, 500);
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ ok: false, error: 'invalid_json' }, 400);
  }

  const subject = typeof body.subject === 'string' ? body.subject.trim() : '';
  const message = typeof body.message === 'string' ? body.message : '';
  const token = typeof body.turnstileToken === 'string' ? body.turnstileToken : '';

  if (!ALLOWED_SUBJECTS.has(subject)) {
    return json({ ok: false, error: 'invalid_subject' }, 400);
  }
  if (!message.trim() || message.length > 2048) {
    return json({ ok: false, error: 'invalid_message' }, 400);
  }
  if (!token || token.length > 2048) {
    return json({ ok: false, error: 'invalid_turnstile_token' }, 400);
  }

  const remoteip = request.headers.get('CF-Connecting-IP') || undefined;
  const verifyPayload = {
    secret: env.TURNSTILE_SECRET,
    response: token,
    idempotency_key: crypto.randomUUID()
  };
  if (remoteip) verifyPayload.remoteip = remoteip;

  let verify;
  try {
    const verificationResponse = await fetch(TURNSTILE_VERIFY_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(verifyPayload)
    });
    verify = await verificationResponse.json();
  } catch {
    return json({ ok: false, error: 'turnstile_unavailable' }, 502);
  }

  if (!verify?.success) {
    return json({
      ok: false,
      error: 'turnstile_failed',
      codes: Array.isArray(verify?.['error-codes']) ? verify['error-codes'] : []
    }, 403);
  }

  if (verify.action !== TURNSTILE_ACTION) {
    return json({ ok: false, error: 'turnstile_action_mismatch' }, 403);
  }

  if (!ALLOWED_HOSTNAMES.has(verify.hostname)) {
    return json({ ok: false, error: 'turnstile_hostname_mismatch' }, 403);
  }

  // v5.23 intentionally stops after server-side Turnstile verification.
  // The real recipient address and mail provider will be added only on the
  // server side in the next stage, so no email address is exposed to the page.
  // Do not log the visitor's message body.
  console.log('Xenolith contact verified', {
    subject,
    hostname: verify.hostname,
    verifiedAt: new Date().toISOString()
  });

  return json({
    ok: true,
    preview: true,
    verified: true
  });
}

export function onRequest() {
  return json({ ok: false, error: 'method_not_allowed' }, 405);
}
