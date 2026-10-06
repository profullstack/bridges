import { normalizeClaims } from './claims.js';
import { assertSecret, pkceChallenge, randomToken, safeEqual, seal, unseal } from './crypto.js';

const CODE_PURPOSE = 'bridge-code-v1';

/** Single-use codes, remembered until they would have expired anyway. */
export function createMemoryReplayStore() {
  const seen = new Map();
  return {
    async claim(jti, expiresAt) {
      const now = Date.now();
      for (const [key, exp] of seen) if (exp < now) seen.delete(key);
      if (seen.has(jti)) return false;
      seen.set(jti, expiresAt);
      return true;
    },
  };
}

function redirect(location, status = 302) {
  return new Response(null, { status, headers: { location, 'cache-control': 'no-store' } });
}

function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', pragma: 'no-cache' },
  });
}

/** A plain error page. Used whenever the redirect target itself is not trusted. */
function refuse(message) {
  return new Response(`Bridge request refused: ${message}\n`, {
    status: 400,
    headers: { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' },
  });
}

function withParams(base, params) {
  const url = new URL(base);
  for (const [key, value] of Object.entries(params)) if (value != null) url.searchParams.set(key, value);
  return url.toString();
}

/**
 * The host side: the site whose accounts are the source of truth.
 *
 * Two handlers, both `(Request) => Promise<Response>`, so they mount on Next.js
 * route handlers, Hono, Bun.serve, Workers or anything else speaking fetch:
 *
 *   GET  authorize  OAuth 2.1 authorization endpoint (code + PKCE S256 only)
 *   POST token      exchanges the code for the user's claims
 *
 * The code is sealed with the client's secret and carries everything the token
 * endpoint needs, so the host keeps no table: only a replay store, and the
 * in-memory one is enough for a single process.
 */
export function createBridgeHost(options) {
  const { clients, getUser, loginUrl } = options ?? {};
  if (!clients || typeof clients !== 'object') throw new Error('createBridgeHost: clients is required');
  if (typeof getUser !== 'function') throw new Error('createBridgeHost: getUser(request) is required');
  if (typeof loginUrl !== 'function') throw new Error('createBridgeHost: loginUrl(returnTo, request) is required');
  for (const [id, client] of Object.entries(clients)) {
    assertSecret(client?.secret, `clients.${id}.secret`);
    if (!Array.isArray(client.redirectUris) || client.redirectUris.length === 0) {
      throw new Error(`clients.${id}.redirectUris must list at least one exact callback URL`);
    }
  }
  const codeTtl = (options.codeTtlSeconds ?? 60) * 1000;
  const replay = options.replayStore ?? createMemoryReplayStore();

  async function authorize(request) {
    const url = new URL(request.url);
    const q = url.searchParams;
    const clientId = q.get('client_id') ?? '';
    const client = Object.hasOwn(clients, clientId) ? clients[clientId] : null;
    if (!client) return refuse('unknown client_id');
    const redirectUri = q.get('redirect_uri') ?? '';
    // Exact match, never a prefix: anything looser is an open redirect that
    // hands a code to whoever registered the lookalike URL.
    if (!client.redirectUris.includes(redirectUri)) return refuse('redirect_uri is not registered for this client');

    const state = q.get('state');
    const back = (params) => redirect(withParams(redirectUri, { ...params, state }));
    if (q.get('response_type') !== 'code') return back({ error: 'unsupported_response_type' });
    const challenge = q.get('code_challenge') ?? '';
    if (q.get('code_challenge_method') !== 'S256' || !/^[A-Za-z0-9_-]{43}$/.test(challenge)) {
      return back({ error: 'invalid_request', error_description: 'PKCE S256 is required' });
    }

    const raw = await getUser(request);
    if (!raw) {
      if (q.get('prompt') === 'none') return back({ error: 'login_required' });
      // Send them to sign in, and back to this exact authorize request after.
      return redirect(loginUrl(url.toString(), request));
    }

    let user;
    try {
      user = normalizeClaims(raw);
    } catch (error) {
      return back({ error: 'server_error', error_description: error.message });
    }
    const code = await seal(client.secret, CODE_PURPOSE, {
      c: clientId,
      r: redirectUri,
      ch: challenge,
      u: user,
      exp: Date.now() + codeTtl,
      jti: randomToken(16),
    });
    return back({ code });
  }

  async function token(request) {
    if (request.method !== 'POST') return json({ error: 'invalid_request', error_description: 'POST only' }, 405);
    const type = request.headers.get('content-type') ?? '';
    let form;
    try {
      form = type.includes('application/json')
        ? new URLSearchParams(Object.entries(await request.json()).map(([k, v]) => [k, String(v)]))
        : new URLSearchParams(await request.text());
    } catch {
      return json({ error: 'invalid_request' }, 400);
    }

    let clientId = form.get('client_id') ?? '';
    let secret = form.get('client_secret') ?? '';
    const basic = request.headers.get('authorization');
    if (basic?.startsWith('Basic ')) {
      const [id, pass] = atob(basic.slice(6)).split(':');
      clientId = decodeURIComponent(id ?? '');
      secret = decodeURIComponent(pass ?? '');
    }
    const client = Object.hasOwn(clients, clientId) ? clients[clientId] : null;
    if (!client || !safeEqual(secret, client.secret)) return json({ error: 'invalid_client' }, 401);
    if (form.get('grant_type') !== 'authorization_code') return json({ error: 'unsupported_grant_type' }, 400);

    const payload = await unseal(client.secret, CODE_PURPOSE, form.get('code') ?? '');
    const invalid = (description) => json({ error: 'invalid_grant', error_description: description }, 400);
    if (!payload || payload.c !== clientId) return invalid('unknown code');
    if (payload.exp < Date.now()) return invalid('code expired');
    if (payload.r !== form.get('redirect_uri')) return invalid('redirect_uri does not match');
    const verifier = form.get('code_verifier') ?? '';
    if (!/^[A-Za-z0-9._~-]{43,128}$/.test(verifier) || (await pkceChallenge(verifier)) !== payload.ch) {
      return invalid('PKCE verification failed');
    }
    if (!(await replay.claim(payload.jti, payload.exp))) return invalid('code already used');

    return json({ token_type: 'bridge', user: payload.u });
  }

  /** What a client needs to find the endpoints; serve it at /.well-known/bridge.json if you like. */
  function metadata(base) {
    return {
      authorization_endpoint: new URL(options.authorizePath ?? 'authorize', base).toString(),
      token_endpoint: new URL(options.tokenPath ?? 'token', base).toString(),
      response_types_supported: ['code'],
      code_challenge_methods_supported: ['S256'],
      prompt_values_supported: ['none', 'login'],
    };
  }

  return { authorize, token, metadata };
}
