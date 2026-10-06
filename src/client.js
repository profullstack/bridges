import { normalizeClaims } from './claims.js';
import { assertSecret, pkceChallenge, randomToken, seal, unseal } from './crypto.js';

const STATE_PURPOSE = 'bridge-state-v1';

/**
 * The app side: the product that wants the host's users (a forum, a docs
 * site, a tool) signed in without an account of their own.
 *
 *   const { url, cookie } = await bridge.begin({ returnTo: '/t/42', prompt: 'none' });
 *   // set `cookie` (httpOnly, ~10 min), redirect to `url`
 *   const result = await bridge.complete(callbackUrl, cookieValue);
 *   // { ok: true, user, returnTo } or { ok: false, error, returnTo }
 *
 * The state and PKCE verifier travel in one cookie sealed with the client
 * secret, so the app needs no table for pending sign-ins either.
 */
export function createBridgeClient(options) {
  const { authorizeUrl, tokenUrl, clientId, clientSecret, redirectUri } = options ?? {};
  for (const [key, value] of Object.entries({ authorizeUrl, tokenUrl, clientId, redirectUri })) {
    if (typeof value !== 'string' || !value) throw new Error(`createBridgeClient: ${key} is required`);
  }
  assertSecret(clientSecret, 'createBridgeClient: clientSecret');
  // Looked up per call, so a polyfill or a test stub installed later still applies.
  const fetchImpl = (...args) => (options.fetch ?? globalThis.fetch)(...args);
  const stateTtl = (options.stateTtlSeconds ?? 600) * 1000;

  async function begin({ returnTo = '/', prompt } = {}) {
    const state = randomToken(16);
    const verifier = randomToken(32);
    const url = new URL(authorizeUrl);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('client_id', clientId);
    url.searchParams.set('redirect_uri', redirectUri);
    url.searchParams.set('state', state);
    url.searchParams.set('code_challenge', await pkceChallenge(verifier));
    url.searchParams.set('code_challenge_method', 'S256');
    if (prompt === 'none' || prompt === 'login') url.searchParams.set('prompt', prompt);
    const cookie = await seal(clientSecret, STATE_PURPOSE, {
      s: state,
      v: verifier,
      rt: returnTo,
      p: prompt ?? null,
      exp: Date.now() + stateTtl,
    });
    return { url: url.toString(), cookie, maxAge: Math.floor(stateTtl / 1000) };
  }

  async function complete(callback, cookie) {
    const params =
      callback instanceof URLSearchParams ? callback : new URL(String(callback), 'http://callback.invalid').searchParams;
    const pending = cookie ? await unseal(clientSecret, STATE_PURPOSE, cookie) : null;
    const returnTo = pending?.rt ?? '/';
    const fail = (error) => ({ ok: false, error, returnTo, prompt: pending?.p ?? null });

    if (!pending || pending.exp < Date.now()) return fail('expired_state');
    if (params.get('state') !== pending.s) return fail('state_mismatch');
    const error = params.get('error');
    if (error) return fail(error);
    const code = params.get('code');
    if (!code) return fail('missing_code');

    let response;
    try {
      response = await fetchImpl(tokenUrl, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code,
          redirect_uri: redirectUri,
          client_id: clientId,
          client_secret: clientSecret,
          code_verifier: pending.v,
        }),
        signal: AbortSignal.timeout(options.timeoutMs ?? 10_000),
      });
    } catch {
      return fail('host_unreachable');
    }
    let body = null;
    try {
      body = await response.json();
    } catch {
      // fall through
    }
    if (!response.ok) return fail(body?.error ?? `token_http_${response.status}`);
    try {
      return { ok: true, user: normalizeClaims(body?.user), returnTo };
    } catch {
      return fail('invalid_user');
    }
  }

  return { begin, complete };
}
