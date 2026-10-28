// api/stripe-webhook.js
// EverDNA — Stripe Webhook 中継（案A）
// Stripe署名を検証し、検証済みイベントだけを共有シークレット付きでGAS /exec へ転送する。
import Stripe from 'stripe';

// ★重要：Vercelは既定でボディをJSONパースしてしまう。
//   Stripeの署名検証は「生ボディのバイト列」が必要なので、パースを無効化する。
export const config = { api: { bodyParser: false } };

// 生ボディ（Buffer）を読む。bodyParser無効化とセットで使う。
async function readRawBody(req) {
  const chunks = [];
  for await (const chunk of req) {
    chunks.push(typeof chunk === 'string' ? Buffer.from(chunk) : chunk);
  }
  return Buffer.concat(chunks);
}

// GAS の応答が「本当に受け付けた」ものかを判定する（2026-10-28 追加）
//   以前は 500 番台だけを失敗扱いにしていたため、アーカイブ済み /exec の 404 や、
//   HTML のエラーページ、GAS 内部の例外でも Stripe に 200 を返し、取りこぼしに気づけなかった。
//   失敗なら理由（短い文字列）、成功なら null を返す。理由に個人情報は含めない。
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

  // ① Stripe署名を検証（案Aの肝）
  const stripe = new Stripe(process.env.STRIPE_SECRET_KEY); // 遅延初期化（env未設定時のcold-startクラッシュ回避）
  let event;
  try {
    const rawBody = await readRawBody(req);
    const sig = req.headers['stripe-signature'];
    event = stripe.webhooks.constructEvent(rawBody, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.error('署名検証NG:', err.message);
    return res.status(400).send(`Webhook signature verification failed: ${err.message}`);
  }

  // 対象イベント以外は200で受け流す
  if (event.type !== 'checkout.session.completed') {
    return res.status(200).json({ received: true, ignored: event.type });
  }

  // ② 検証済みイベントを共有シークレット付きでGASへ転送
  try {
    const resp = await fetch(process.env.GAS_EXEC_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'text/plain' }, // GASのCORSプリフライト回避
      body: JSON.stringify({ proxySecret: process.env.PROXY_SHARED_SECRET, event }),
      redirect: 'follow', // GASは302→200を返すので、リダイレクトを追って最終200を受ける
    });
    // 200 以外・JSON 以外・GAS 側エラーはすべて失敗 → 500 を返して Stripe に再送させる
    const problem = await gasForwardProblem(resp);
    if (problem) throw new Error('GAS転送失敗: ' + problem);
    return res.status(200).json({ received: true, forwarded: true });
  } catch (err) {
    console.error('GAS転送エラー:', err.message);
    // 500を返すとStripeが自動でリトライしてくれる（取りこぼし防止）
    return res.status(500).json({ received: false, error: err.message });
  }
}
