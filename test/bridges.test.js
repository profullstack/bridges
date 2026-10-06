import { strict as assert } from 'node:assert';
import { describe, it } from 'node:test';
import { createBridgeClient, createBridgeHost, normalizeClaims, pkceChallenge } from '../index.js';

const SECRET = 'x'.repeat(40);
const CALLBACK = 'https://app.example/bbs/auth/bridge/callback';
const AUTHORIZE = 'https://host.example/api/v1/bridge/authorize';
const TOKEN = 'https://host.example/api/v1/bridge/token';

function setup({ user = { sub: 'did:key:alice', name: 'Alice', email: 'alice@example.com', emailVerified: true } } = {}) {
  let current = user;
  const host = createBridgeHost({
    clients: { forum: { secret: SECRET, redirectUris: [CALLBACK] } },
    getUser: async () => current,
    loginUrl: (returnTo) => `https://host.example/login?next=${encodeURIComponent(returnTo)}`,
  });
  // The client talks to the host in-process: the token endpoint is the real handler.
  const client = createBridgeClient({
    authorizeUrl: AUTHORIZE,
    tokenUrl: TOKEN,
    clientId: 'forum',
    clientSecret: SECRET,
    redirectUri: CALLBACK,
    fetch: (url, init) => host.token(new Request(url, init)),
  });
  return { host, client, setUser: (u) => (current = u) };
}

async function roundTrip(host, client, options) {
  const { url, cookie } = await client.begin(options);
  const response = await host.authorize(new Request(url));
  return { response, cookie, location: response.headers.get('location') };
}

describe('a signed-in host user', () => {
  it('arrives at the app with their claims, and the code works once', async () => {
    const { host, client } = setup();
    const { location, cookie } = await roundTrip(host, client, { returnTo: '/t/42' });
    assert.ok(location?.startsWith(`${CALLBACK}?`));
    const result = await client.complete(location, cookie);
    assert.deepEqual(result, {
      ok: true,
      user: { sub: 'did:key:alice', name: 'Alice', email: 'alice@example.com', email_verified: true },
      returnTo: '/t/42',
    });
    const again = await client.complete(location, cookie);
    assert.equal(again.ok, false);
    assert.equal(again.error, 'invalid_grant', 'a code is single-use');
  });

  it('never trusts an email the host did not verify', () => {
    assert.equal(normalizeClaims({ sub: 'x', email: 'a@b.co' }).email_verified, false);
    assert.equal(normalizeClaims({ sub: 'x', picture: 'http://insecure/p.png' }).picture, undefined);
    assert.throws(() => normalizeClaims({ name: 'no sub' }));
  });
});

describe('a signed-out host user', () => {
  it('gets login_required on a silent attempt, and nothing is shown', async () => {
    const { host, client } = setup({ user: null });
    const { location, cookie } = await roundTrip(host, client, { prompt: 'none', returnTo: '/f/deals' });
    const result = await client.complete(location, cookie);
    assert.deepEqual(result, { ok: false, error: 'login_required', returnTo: '/f/deals', prompt: 'none' });
  });

  it('is sent to the host login, which returns to the same authorize request', async () => {
    const { host, client } = setup({ user: null });
    const { url } = await client.begin({ prompt: 'login' });
    const response = await host.authorize(new Request(url));
    const login = new URL(response.headers.get('location') ?? '');
    assert.equal(login.pathname, '/login');
    assert.equal(login.searchParams.get('next'), url);
  });
});

describe('refusals', () => {
  it('never redirects to an unregistered callback', async () => {
    const { host, client } = setup();
    const { url } = await client.begin();
    const evil = new URL(url);
    evil.searchParams.set('redirect_uri', 'https://app.example/bbs/auth/bridge/callback.evil.com');
    const response = await host.authorize(new Request(evil));
    assert.equal(response.status, 400);
    assert.equal(response.headers.get('location'), null);
  });

  it('requires PKCE S256', async () => {
    const { host, client } = setup();
    const { url } = await client.begin();
    const plain = new URL(url);
    plain.searchParams.set('code_challenge_method', 'plain');
    const location = (await host.authorize(new Request(plain))).headers.get('location') ?? '';
    assert.equal(new URL(location).searchParams.get('error'), 'invalid_request');
  });

  it('rejects a stolen code without the verifier, a wrong secret, and a forged cookie', async () => {
    const { host, client } = setup();
    const { location, cookie } = await roundTrip(host, client, {});
    const code = new URL(location ?? '').searchParams.get('code') ?? '';
    const form = (extra) =>
      new Request(TOKEN, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code,
          redirect_uri: CALLBACK,
          client_id: 'forum',
          client_secret: SECRET,
          code_verifier: 'a'.repeat(43),
          ...extra,
        }),
      });
    assert.equal((await host.token(form({}))).status, 400, 'wrong verifier');
    assert.equal((await host.token(form({ client_secret: 'y'.repeat(40) }))).status, 401, 'wrong secret');
    const forged = await client.complete(location, `${cookie}x`);
    assert.equal(forged.error, 'expired_state');
    const swapped = new URL(location ?? '');
    swapped.searchParams.set('state', 'other');
    assert.equal((await client.complete(swapped, cookie)).error, 'state_mismatch');
  });

  it('computes the RFC 7636 S256 example', async () => {
    assert.equal(
      await pkceChallenge('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'),
      'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
    );
  });
});
