// api/resend-webhook.js（2026-11 R-8/R-9）
// EverDNA — Resend Webhook 中継
//   Resend（Svix 方式）の署名を検証し、バウンス・苦情・配送遅延だけを
//   共有シークレット付きで GAS /exec へ転送する。構成は stripe-webhook.js（案A）と同じ。
//
// ・Resend は1アカウント＝Webhook 宛先が共通。dev（FROM=dev@everdna.com）と本番のイベントが
//   同じここに届くため、data.from で転送先 GAS を振り分ける。
// ・個人情報は GAS へ送らない。宛先アドレスは emailHash（GAS の emailHash_ と同じ
//   SHA-256 先頭12桁・小文字化＋trim）に変換して送る。GAS 側で「申込者宛てか BCC 宛てか」を判定する。
// ・GAS が受け付けなかった場合は 500 を返し、Resend（Svix）に再送させる。
//
// 環境変数：RESEND_WEBHOOK_SECRET（whsec_…）
//           GAS_EXEC_URL / PROXY_SHARED_SECRET（本番・既存）
//           GAS_EXEC_URL_DEV / PROXY_SHARED_SECRET_DEV（dev・既存）
import { Webhook } from 'svix';
import { createHash } from 'crypto';

// 署名検証には生ボディが必要なので、Vercel の JSON パースを無効化する
export const config = { api: { bodyParser: false } };

// 転送するイベント（それ以外は 200 で受け流す）
const FORWARD_TYPES = ['email.bounced', 'email.complained', 'email.delivery_delayed'];
// dev の送信元（GAS dev の FROM_EMAIL）
const DEV_FROM = 'dev@everdna.com';

async function readRawBody(req) {
  const chunks = [];
  for await (const chunk of req) {
    chunks.push(typeof chunk === 'string' ? Buffer.from(chunk) : chunk);
  }
  return Buffer.concat(chunks);
}

// GAS の emailHash_ と同じ計算（小文字化＋前後空白除去 → SHA-256 → 先頭12桁）
function emailHash(email) {
  const s = String(email || '').trim().toLowerCase();
  if (!s) return '';
  return createHash('sha256').update(s, 'utf8').digest('hex').slice(0, 12);
}

// "表示名 <addr@x>" からアドレス部分を取り出す
function bareAddress(from) {
  const m = String(from || '').match(/<([^>]+)>/);
  return (m ? m[1] : String(from || '')).trim().toLowerCase();
}

// GAS へ送る最小限の情報（アドレスは送らない）
function toMailEvent(evt) {
  const d = evt.data || {};
  const b = d.bounce || {};
  const to = Array.isArray(d.to) ? d.to : (d.to ? [d.to] : []);
  return {
    type:          evt.type,
    emailId:       d.email_id || '',
    eventAt:       evt.created_at || '',
    bounceType:    b.type || '',
    bounceSubType: b.subType || '',
    toHashes:      to.map(emailHash).filter(Boolean),
  };
}

// stripe-webhook.js と同じ判定（GAS が本当に受け付けたか）
async function gasForwardProblem(resp) {
  if (!resp.ok) return 'HTTP ' + resp.status;
  const text = await resp.text();
  let body;
  try { body = JSON.parse(text); } catch (_) { return 'non-JSON response (HTTP ' + resp.status + ')'; }
  if (!body || typeof body !== 'object') return 'unexpected body';
  if (body.ignored === 'bad_proxy_secret') return 'bad_proxy_secret';
  if (body.success === false) return 'gas_error: ' + (body.reason || 'unknown');
  if (body.error) return 'gas_error';
  if (body.received !== true) return 'unexpected body';
  return null;
}

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).end('Method Not Allowed');
  }

  const SECRET = process.env.RESEND_WEBHOOK_SECRET;
  if (!SECRET) {
    console.error('[resend-webhook] RESEND_WEBHOOK_SECRET が未設定');
    return res.status(500).json({ received: false, error: 'missing env: RESEND_WEBHOOK_SECRET' });
  }

  // ① 署名検証（Svix）。偽 POST は 400 で拒否する
  let evt;
  try {
    const raw = (await readRawBody(req)).toString('utf8');
    evt = new Webhook(SECRET).verify(raw, {
      'svix-id':        req.headers['svix-id'],
      'svix-timestamp': req.headers['svix-timestamp'],
      'svix-signature': req.headers['svix-signature'],
    });
  } catch (err) {
    console.error('[resend-webhook] 署名検証NG:', err.message);
    return res.status(400).json({ received: false, error: 'signature verification failed' });
  }

  if (!evt || FORWARD_TYPES.indexOf(evt.type) === -1) {
    return res.status(200).json({ received: true, ignored: evt && evt.type });
  }

  // ② 転送先の振り分け（dev@ から送ったメールのイベントは dev GAS へ）
  const isDev  = bareAddress(evt.data && evt.data.from) === DEV_FROM;
  const GAS    = isDev ? process.env.GAS_EXEC_URL_DEV : process.env.GAS_EXEC_URL;
  const SHARED = isDev ? process.env.PROXY_SHARED_SECRET_DEV : process.env.PROXY_SHARED_SECRET;
  if (!GAS || !SHARED) {
    console.error('[resend-webhook] 転送先の環境変数が未設定 env=' + (isDev ? 'dev' : 'prod'));
    return res.status(500).json({ received: false, error: 'missing env for ' + (isDev ? 'dev' : 'prod') });
  }

  // ③ 転送。GAS が受け付けなければ 500 → Resend が再送する
  try {
    const resp = await fetch(GAS, {
      method: 'POST',
      headers: { 'Content-Type': 'text/plain' }, // GASのCORSプリフライト回避
      body: JSON.stringify({ proxySecret: SHARED, mailEvent: toMailEvent(evt) }),
      redirect: 'follow',
    });
    const problem = await gasForwardProblem(resp);
    if (problem) throw new Error('GAS転送失敗: ' + problem);
    return res.status(200).json({ received: true, forwarded: isDev ? 'dev' : 'prod' });
  } catch (err) {
    console.error('[resend-webhook] GAS転送エラー:', err.message);
    return res.status(500).json({ received: false, error: err.message });
  }
}
