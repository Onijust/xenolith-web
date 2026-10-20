const TURNSTILE_VERIFY_URL = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
const RESEND_EMAIL_URL = 'https://api.resend.com/emails';
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

const MAIL_FROM = 'Xenolith Website <noreply@contact.xenolith.jp>';
const EMAIL_MAX_LENGTH = 254;
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/u;
const validEmail = (value) => value.length > 0 && value.length <= EMAIL_MAX_LENGTH && EMAIL_PATTERN.test(value);

const json = (body, status = 200) => new Response(JSON.stringify(body), {
  status,
  headers: {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store'
  }
});

const configured = (value) => typeof value === 'string' && value.trim().length > 0;

export async function onRequestPost(context) {
  const { request, env } = context;

  if (!configured(env.TURNSTILE_SECRET) || !configured(env.RESEND_API_KEY) || !configured(env.CONTACT_TO)) {
    return json({ ok: false, error: 'server_not_configured' }, 500);
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ ok: false, error: 'invalid_json' }, 400);
  }

  const subject = typeof body.subject === 'string' ? body.subject.trim() : '';
  const email = typeof body.email === 'string' ? body.email.trim() : '';
  const message = typeof body.message === 'string' ? body.message : '';
  const token = typeof body.turnstileToken === 'string' ? body.turnstileToken : '';

  if (!ALLOWED_SUBJECTS.has(subject)) {
    return json({ ok: false, error: 'invalid_subject' }, 400);
  }
  if (!validEmail(email)) {
    return json({ ok: false, error: 'invalid_email' }, 400);
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

  if (!ALLOWED_HOSTNAMES.has(verify.hostname)) {
    return json({ ok: false, error: 'turnstile_hostname_mismatch' }, 403);
  }

  const sentAt = new Date().toISOString();
  const mailText = [
    'Xenolith公式サイトからお問い合わせがありました。',
    '',
    `お問い合わせ内容: ${subject}`,
    `お客様のメールアドレス: ${email}`,
    '',
    'メッセージ:',
    message,
    '',
    `受付日時: ${sentAt}`
  ].join('\n');

  let resendResponse;
  let resendBody = {};
  const deliveryId = crypto.randomUUID();

  try {
    resendResponse = await fetch(RESEND_EMAIL_URL, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${env.RESEND_API_KEY}`,
        'Content-Type': 'application/json',
        'Idempotency-Key': `xenolith-contact/${deliveryId}`
      },
      body: JSON.stringify({
        from: MAIL_FROM,
        to: [env.CONTACT_TO.trim()],
        reply_to: email,
        subject: `[Xenolith Website] ${subject}`,
        text: mailText
      })
    });
    resendBody = await resendResponse.json().catch(() => ({}));
  } catch {
    return json({ ok: false, error: 'email_provider_unavailable' }, 502);
  }

  if (!resendResponse.ok || !resendBody?.id) {
    // Do not return provider details to the browser. The status/name are enough
    // for Cloudflare logs while keeping the recipient and message private.
    console.error('Xenolith contact delivery failed', {
      providerStatus: resendResponse.status,
      providerError: typeof resendBody?.name === 'string' ? resendBody.name : 'unknown',
      subject,
      verifiedHostname: verify.hostname
    });
    return json({ ok: false, error: 'email_delivery_failed' }, 502);
  }

  // Never log the visitor's message or the private recipient address.
  console.log('Xenolith contact delivered', {
    subject,
    hostname: verify.hostname,
    resendId: resendBody.id,
    deliveredAt: sentAt
  });

  return json({ ok: true, delivered: true });
}

export function onRequest() {
  return json({ ok: false, error: 'method_not_allowed' }, 405);
}
