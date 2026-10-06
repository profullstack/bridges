import { normalizeClaims } from './claims.js';
import { assertSecret, pkceChallenge, randomToken, seal, unseal } from './crypto.js';

const STATE_PURPOSE = 'oauth-state-v1';

/**
 * Sign people in with an OAuth 2.1 / OpenID Connect provider (CoinPay, or any
 * provider with an authorize, token and userinfo endpoint), with the same
 * begin/complete shape as createBridgeClient. An app can offer a bridge host
 * and a provider side by side and treat the results alike.
 *
 * Authorization code + PKCE S256 only. The access token is used once, for
 * userinfo, and then dropped: this signs people in, it does not act for them.
 */
export function createOAuthClient(options) {
  const { authorizeUrl, tokenUrl, userinfoUrl, clientId, clientSecret, redirectUri } = options ?? {};
  for (const [key, value] of Object.entries({ authorizeUrl, tokenUrl, userinfoUrl, clientId, redirectUri })) {
    if (typeof value !== 'string' || !value) throw new Error(`createOAuthClient: ${key} is required`);
  }
  // The state cookie is sealed with a key of our own, not the provider's
  // secret: a public client has no secret, and the cookie is ours anyway.
  const stateKey = options.stateSecret ?? clientSecret;
  assertSecret(stateKey, 'createOAuthClient: stateSecret (or clientSecret)');
  const scope = (options.scopes ?? ['openid', 'profile']).join(' ');
  const toClaims = options.toClaims ?? ((info) => info);
  const fetchImpl = (...args) => (options.fetch ?? globalThis.fetch)(...args);
  const stateTtl = (options.stateTtlSeconds ?? 600) * 1000;
  const timeout = options.timeoutMs ?? 10_000;

  async function begin({ returnTo = '/', prompt } = {}) {
    const state = randomToken(16);
    const verifier = randomToken(32);
    const url = new URL(authorizeUrl);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('client_id', clientId);
    url.searchParams.set('redirect_uri', redirectUri);
    url.searchParams.set('scope', scope);
    url.searchParams.set('state', state);
    url.searchParams.set('code_challenge', await pkceChallenge(verifier));
    url.searchParams.set('code_challenge_method', 'S256');
    if (prompt === 'none' || prompt === 'login') url.searchParams.set('prompt', prompt);
    const cookie = await seal(stateKey, STATE_PURPOSE, { s: state, v: verifier, rt: returnTo, p: prompt ?? null, exp: Date.now() + stateTtl });
    return { url: url.toString(), cookie, maxAge: Math.floor(stateTtl / 1000) };
  }

  async function complete(callback, cookie) {
    const params =
      callback instanceof URLSearchParams ? callback : new URL(String(callback), 'http://callback.invalid').searchParams;
    const pending = cookie ? await unseal(stateKey, STATE_PURPOSE, cookie) : null;
    const returnTo = pending?.rt ?? '/';
    const fail = (error) => ({ ok: false, error, returnTo, prompt: pending?.p ?? null });

    if (!pending || pending.exp < Date.now()) return fail('expired_state');
    if (params.get('state') !== pending.s) return fail('state_mismatch');
    if (params.get('error')) return fail(params.get('error'));
    const code = params.get('code');
    if (!code) return fail('missing_code');

    let tokens;
    try {
      const body = new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: redirectUri,
        client_id: clientId,
        code_verifier: pending.v,
      });
      if (clientSecret) body.set('client_secret', clientSecret);
      const response = await fetchImpl(tokenUrl, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
        body,
        signal: AbortSignal.timeout(timeout),
      });
      tokens = await response.json().catch(() => null);
      if (!response.ok || !tokens?.access_token) return fail(tokens?.error ?? `token_http_${response.status}`);
    } catch {
      return fail('provider_unreachable');
    }

    try {
      const response = await fetchImpl(userinfoUrl, {
        headers: { authorization: `Bearer ${tokens.access_token}`, accept: 'application/json' },
        signal: AbortSignal.timeout(timeout),
      });
      if (!response.ok) return fail(`userinfo_http_${response.status}`);
      const info = await response.json();
      return { ok: true, user: normalizeClaims(toClaims(info)), returnTo };
    } catch (error) {
      return fail(error instanceof SyntaxError ? 'invalid_userinfo' : 'provider_unreachable');
    }
  }

  return { begin, complete };
}

/**
 * CoinPay (coinpayportal.com) as a sign-in provider. People are identified by
 * their CoinPay DID when they have one, which is also what c0upons.com and
 * other CoinPay-backed sites use, so an app can link the same person whichever
 * way they arrive. CoinPay does not verify emails, so none is marked verified.
 */
export function createCoinPayClient(options) {
  const base = (options?.baseUrl ?? 'https://coinpayportal.com').replace(/\/+$/, '');
  return createOAuthClient({
    authorizeUrl: `${base}/api/oauth/authorize`,
    tokenUrl: `${base}/api/oauth/token`,
    userinfoUrl: `${base}/api/oauth/userinfo`,
    scopes: ['openid', 'did', 'profile', 'email'],
    ...options,
    toClaims: (info) => ({
      sub: typeof info?.did === 'string' && info.did.startsWith('did:') ? info.did : String(info?.sub ?? ''),
      name: info?.name,
      username: info?.preferred_username,
      email: info?.email,
      email_verified: info?.email_verified === true,
      picture: info?.picture,
    }),
  });
}
