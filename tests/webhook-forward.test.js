// tests/webhook-forward.test.js（2026-10-28）
// api/stripe-webhook.js と api/stripe-webhook-test.js の「GAS 転送結果の判定」を確かめる。
// 実行：node tests/webhook-forward.test.js   （ネットワーク・Stripe 不要。fetch と Stripe はモック）
'use strict';
const fs = require('fs');
const path = require('path');

let pass = 0, fail = 0;
function ok(cond, msg) { if (cond) { pass++; } else { fail++; console.log('NG: ' + msg); } }

function loadHandler(file, mockFetch) {
  let src = fs.readFileSync(path.join(__dirname, '..', 'api', file), 'utf8');
  src = src.replace(/^import Stripe from 'stripe';\s*$/m, '')
           .replace(/^export const config\s*=/m, 'const config =')
           .replace(/^export default async function handler/m, 'return async function handler');
  const Stripe = function () {
    return { webhooks: { constructEvent: () => ({ type: 'checkout.session.completed', livemode: file === 'stripe-webhook.js', data: { object: {} } }) } };
  };
  return new Function('Stripe', 'fetch', 'process', 'console', 'Buffer', src)(
    Stripe, mockFetch,
    { env: { STRIPE_SECRET_KEY: 'sk_live_x', STRIPE_WEBHOOK_SECRET: 'w', GAS_EXEC_URL: 'https://gas/prod',
             PROXY_SHARED_SECRET: 'p', STRIPE_SECRET_KEY_TEST: 'sk_test_x', STRIPE_WEBHOOK_SECRET_TEST: 'w',
             GAS_EXEC_URL_DEV: 'https://gas/dev', PROXY_SHARED_SECRET_DEV: 'p' } },
    { error: () => {}, log: () => {} }, Buffer);
}
function mkResp(status, text) { return { ok: status >= 200 && status < 300, status, text: async () => text }; }
function mkReq() {
  return { method: 'POST', headers: { 'stripe-signature': 's' },
           [Symbol.asyncIterator]: async function* () { yield Buffer.from('{}'); } };
}
function mkRes() {
  const r = { code: null, body: null, setHeader() {}, status(c) { r.code = c; return r; },
              json(b) { r.body = b; return r; }, send(b) { r.body = b; return r; }, end(b) { r.body = b; return r; } };
  return r;
}

const cases = [
  // [説明, status, 本文, 期待する Vercel→Stripe の応答コード]
  ['queued（正常）',            200, '{"received":true,"queued":true,"matchBy":"sessionId"}', 200],
  ['duplicate（再送の重複）',    200, '{"received":true,"duplicate":true,"by":"sessionId"}', 200],
  ['not_paid（未払い受け流し）', 200, '{"received":true,"ignored":"not_paid"}', 200],
  ['recovered no_pending',      200, '{"received":true,"recovered":true,"reason":"no_pending"}', 200],
  ['404（アーカイブ済み /exec）', 404, '<html>404</html>', 500],
  ['200 だが HTML（関数なし等）', 200, '<!DOCTYPE html><title>Error</title>', 500],
  ['bad_proxy_secret',          200, '{"received":true,"ignored":"bad_proxy_secret"}', 500],
  ['doPost 例外 server_error',   200, '{"success":false,"reason":"server_error","error":"混み合って…"}', 500],
  ['handleStripeWebhook_ 例外',  200, '{"received":true,"error":"Lock timeout"}', 500],
  ['想定外の JSON',              200, '{"foo":1}', 500],
  ['500',                       500, 'Internal', 500],
  ['403（公開設定ミス）',         403, '<html>denied</html>', 500],
];

(async () => {
  for (const file of ['stripe-webhook.js', 'stripe-webhook-test.js']) {
    for (const [desc, st, text, want] of cases) {
      let calledUrl = null;
      const h = loadHandler(file, async (url) => { calledUrl = url; return mkResp(st, text); });
      const res = mkRes();
      await h(mkReq(), res);
      ok(res.code === want, `${file} / ${desc}: 期待 ${want}, 実際 ${res.code} ${JSON.stringify(res.body)}`);
      ok(calledUrl === (file === 'stripe-webhook.js' ? 'https://gas/prod' : 'https://gas/dev'), `${file} / ${desc}: 転送先 ${calledUrl}`);
      if (want === 500) ok(!/混み合/.test(JSON.stringify(res.body)), `${file} / ${desc}: GAS のエラー文を外に出さない`);
    }
    // fetch 自体の失敗（DNS 等）
    const h2 = loadHandler(file, async () => { throw new Error('network down'); });
    const r2 = mkRes(); await h2(mkReq(), r2);
    ok(r2.code === 500, `${file} / fetch 例外 → 500`);
  }
  console.log(`webhook-forward: ${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
})();
