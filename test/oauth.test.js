import { strict as assert } from 'node:assert';
import { describe, it } from 'node:test';
import { createCoinPayClient, pkceChallenge } from '../index.js';

const SECRET = 'c'.repeat(40);
const CALLBACK = 'https://app.example/auth/coinpay/callback';

/** A fake CoinPay: checks PKCE on the token request, answers userinfo. */
function fakeCoinPay(userinfo) {
  const issued = new Map();
  const calls = [];
  const fetch = async (url, init) => {
    const u = new URL(String(url));
    calls.push(u.pathname);
    if (u.pathname === '/api/oauth/token') {
      const form = new URLSearchParams(String(init.body));
      const challenge = issued.get(form.get('code'));
      if (!challenge || (await pkceChallenge(form.get('code_verifier'))) !== challenge || form.get('client_secret') !== SECRET) {
        return Response.json({ error: 'invalid_grant' }, { status: 400 });
      }
      return Response.json({ access_token: 'at-1', token_type: 'Bearer' });
    }
    if (u.pathname === '/api/oauth/userinfo') {
      if (init.headers.authorization !== 'Bearer at-1') return new Response('no', { status: 401 });
      return Response.json(userinfo);
    }
    return new Response('not found', { status: 404 });
  };
  /** What the provider's authorize page would do for a consenting user. */
  const authorize = (url) => {
    const q = new URL(url).searchParams;
    issued.set('code-1', q.get('code_challenge'));
    return `${q.get('redirect_uri')}?code=code-1&state=${q.get('state')}`;
  };
  return { fetch, authorize, calls };
}

describe('CoinPay sign-in', () => {
  it('asks for did + profile scopes with PKCE S256, and returns the DID as sub', async () => {
    const coinpay = fakeCoinPay({ sub: 'merchant-uuid', did: 'did:key:z6Mk', name: 'Ann', email: 'ann@example.com', email_verified: false });
    const client = createCoinPayClient({ clientId: 'cp_x', clientSecret: SECRET, redirectUri: CALLBACK, fetch: coinpay.fetch });
    const { url, cookie } = await client.begin({ returnTo: '/f/deals' });
    const q = new URL(url).searchParams;
    assert.equal(new URL(url).origin + new URL(url).pathname, 'https://coinpayportal.com/api/oauth/authorize');
    assert.equal(q.get('scope'), 'openid did profile email');
    assert.equal(q.get('code_challenge_method'), 'S256');

    const result = await client.complete(coinpay.authorize(url), cookie);
    assert.deepEqual(result, {
      ok: true,
      user: { sub: 'did:key:z6Mk', name: 'Ann', email: 'ann@example.com', email_verified: false },
      returnTo: '/f/deals',
    });
    assert.deepEqual(coinpay.calls, ['/api/oauth/token', '/api/oauth/userinfo']);
  });

  it('falls back to sub for an account without a DID, and reports provider errors', async () => {
    const coinpay = fakeCoinPay({ sub: 'merchant-uuid' });
    const client = createCoinPayClient({ clientId: 'cp_x', clientSecret: SECRET, redirectUri: CALLBACK, fetch: coinpay.fetch });
    const { url, cookie } = await client.begin();
    const ok = await client.complete(coinpay.authorize(url), cookie);
    assert.equal(ok.ok && ok.user.sub, 'merchant-uuid');

    const denied = await client.begin();
    const state = new URL(denied.url).searchParams.get('state');
    const result = await client.complete(`${CALLBACK}?error=access_denied&state=${state}`, denied.cookie);
    assert.equal(result.ok, false);
    assert.equal(result.error, 'access_denied');
  });
});
