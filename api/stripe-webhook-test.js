// api/stripe-webhook-test.js
// EverDNA — Stripe Webhook 中継（案A / テスト・dev 専用）
//
// 本番用 api/stripe-webhook.js の複製。参照する環境変数だけをテスト専用に差し替えてある。
// 目的：Stripe サンドボックスの Webhook 宛先を GAS 直指し（案B）から本ルートに変えることで、
//       GAS ウェブアプリが返す 302 を Stripe が「失敗」と記録し続ける問題を解消する。
//       （Stripe は 3xx をリダイレクト追跡せず失敗扱いにする仕様）
//
// ⚠ このファイルは本番ルート（api/stripe-webhook.js）を一切参照・変更しない。
//    両者は別の環境変数セットを使うので、片方の設定ミスがもう片方に波及しない。
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

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).end('Method Not Allowed');
  }

  // ⓪ 設定ガード（環境変数の取り違え防止）
  //    このプロジェクトは過去に「Site Key を Secret Key 欄に入れる」「旧 /exec が残る」等、
  //    環境設定起因の障害を繰り返しているため、起動時に明示的に弾く。
  const SECRET_KEY = process.env.STRIPE_SECRET_KEY_TEST;
  const WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET_TEST;
  const GAS_URL = process.env.GAS_EXEC_URL_DEV;
  const PROXY_SECRET = process.env.PROXY_SHARED_SECRET_DEV;

  const missing = [
    ['STRIPE_SECRET_KEY_TEST', SECRET_KEY],
    ['STRIPE_WEBHOOK_SECRET_TEST', WEBHOOK_SECRET],
    ['GAS_EXEC_URL_DEV', GAS_URL],
    ['PROXY_SHARED_SECRET_DEV', PROXY_SECRET],
  ].filter(([, v]) => !v).map(([k]) => k);

  if (missing.length) {
    console.error('[test-webhook] 環境変数が未設定:', missing.join(', '));
    return res.status(500).json({ received: false, error: 'missing env: ' + missing.join(',') });
  }

  // ライブキーの誤設定を拒否（テスト経路に sk_live が刺さる事故を防ぐ）
  if (!SECRET_KEY.startsWith('sk_test_')) {
    console.error('[test-webhook] STRIPE_SECRET_KEY_TEST が sk_test_ で始まっていない');
    return res.status(500).json({ received: false, error: 'STRIPE_SECRET_KEY_TEST must be a test key' });
  }

  // ① Stripe署名を検証（案Aの肝）
  const stripe = new Stripe(SECRET_KEY); // 遅延初期化（env未設定時のcold-startクラッシュ回避）
  let event;
  try {
    const rawBody = await readRawBody(req);
    const sig = req.headers['stripe-signature'];
    event = stripe.webhooks.constructEvent(rawBody, sig, WEBHOOK_SECRET);
  } catch (err) {
    console.error('[test-webhook] 署名検証NG:', err.message);
    return res.status(400).send(`Webhook signature verification failed: ${err.message}`);
  }

  // ライブイベントがテスト経路に来たら拒否（配線ミスの早期検知）
  if (event.livemode === true) {
    console.error('[test-webhook] livemode イベントを受信。配線ミスの可能性');
    return res.status(400).json({ received: false, error: 'livemode event rejected on test endpoint' });
  }

  // 対象イベント以外は200で受け流す
  if (event.type !== 'checkout.session.completed') {
    return res.status(200).json({ received: true, ignored: event.type });
  }

  // ② 検証済みイベントを共有シークレット付きで dev GAS へ転送
  try {
    const resp = await fetch(GAS_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'text/plain' }, // GASのCORSプリフライト回避
      body: JSON.stringify({ proxySecret: PROXY_SECRET, event }),
      redirect: 'follow', // GASは302→200を返すので、リダイレクトを追って最終200を受ける
    });
    if (!resp.ok && resp.status >= 500) throw new Error('GAS転送失敗 HTTP ' + resp.status);
    return res.status(200).json({ received: true, forwarded: true });
  } catch (err) {
    console.error('[test-webhook] GAS転送エラー:', err.message);
    // 500を返すとStripeが自動でリトライしてくれる（取りこぼし防止）
    return res.status(500).json({ received: false, error: err.message });
  }
}
