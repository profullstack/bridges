# @profullstack/bridges

Let the people signed in to your site use an app on it without a second account.

A **host** (your site, which owns the accounts) and an **app** (a forum, docs, a tool) share one client secret. When someone opens the app, it asks the host who they are. If they are signed in there, they come back signed in here, with no prompt and no password. That is the silent sign-in, `prompt=none`. The app links its account to the host's id for that person, so renaming or changing an email on either side never moves anyone into someone else's account.

Under the hood it is the OAuth 2.1 authorization-code flow with PKCE S256, cut down to the one thing this needs:

- **Fetch-style.** Each handler takes a `Request` and returns a `Response`, so it mounts on Next.js route handlers, Hono, Bun.serve, Workers or Express (via a fetch adapter).
- **Stateless.** The code is sealed (AES-256-GCM) with the client secret and carries everything the token endpoint needs. The app's pending sign-in rides in one sealed cookie. Neither side needs a table. The host keeps only a replay set, in memory by default.
- **Zero dependencies.** WebCrypto only. Runs on Node 20+, Bun, Deno, Cloudflare Workers and the edge.

First used by [c0upons.com](https://c0upons.com), whose members are signed in to [c0upons.com/bbs](https://c0upons.com/bbs) (a [tsbb](https://github.com/profullstack/tsbb) board) automatically.

## Install

```sh
npm install @profullstack/bridges
npx @profullstack/bridges client tsbb https://example.com/bbs/auth/bridge/callback
```

The second command prints the host's client entry and the app's settings, with a fresh secret. Put the secret in your vault, not in the repo.

## Host (the site that owns the accounts)

```js
// app/api/v1/bridge/[action]/route.js (Next.js)
import { createBridgeHost } from '@profullstack/bridges';

const bridge = createBridgeHost({
  clients: {
    tsbb: {
      secret: process.env.BRIDGE_TSBB_SECRET,
      redirectUris: ['https://example.com/bbs/auth/bridge/callback'],
    },
  },
  // Who is signed in here? Return null if nobody.
  async getUser(request) {
    const me = await sessionFrom(request);
    return me && { sub: me.id, name: me.name, email: me.email, emailVerified: true };
  },
  // A signed-out person on an interactive sign-in goes here, then back to returnTo.
  loginUrl: (returnTo) => `/login?next=${encodeURIComponent(returnTo)}`,
});

export const GET = (request) => bridge.authorize(request);   // /api/v1/bridge/authorize
export const POST = (request) => bridge.token(request);      // /api/v1/bridge/token
```

`sub` is required and must never change for a person. `name`, `username`, `email` and `picture` are hints for creating the app's account. An email counts as verified only when you pass `emailVerified: true`.

## App (the product that wants the host's users)

```js
import { createBridgeClient } from '@profullstack/bridges';

const bridge = createBridgeClient({
  authorizeUrl: 'https://example.com/api/v1/bridge/authorize',
  tokenUrl: 'https://example.com/api/v1/bridge/token',
  clientId: 'tsbb',
  clientSecret: process.env.BRIDGE_SECRET,
  redirectUri: 'https://example.com/bbs/auth/bridge/callback',
});

// Start: silently ('none') or with the host's login page ('login').
const { url, cookie, maxAge } = await bridge.begin({ returnTo: '/t/42', prompt: 'none' });
// set cookie `bridge_state=<cookie>` (httpOnly, Secure, SameSite=Lax, Max-Age=maxAge), redirect to url

// Callback:
const result = await bridge.complete(request.url, cookies.bridge_state);
if (result.ok) {
  // result.user = { sub, name?, email?, email_verified?, picture?, username? }
  // find the account linked to result.user.sub, or create and link one; sign them in
} else if (result.error === 'login_required') {
  // signed out on the host: carry on as a guest, and don't retry silently for a while
}
// redirect to result.returnTo
```

## Security notes

- **Redirect URIs match exactly.** An unregistered `redirect_uri` gets a plain 400 and never a redirect, so the endpoint can't become an open redirect that leaks codes.
- **Codes live 60 seconds** and work once. Run several host processes? Pass a shared `replayStore` (anything with `claim(jti, expiresAt) => Promise<boolean>`, e.g. Redis `SET NX PX`).
- **The client secret is compared in constant time.** It's sent in the token request body or with HTTP Basic, server to server only.
- **The app must check `returnTo` is a local path** before redirecting to it.

## CLI

```
bridges keygen                                  a new client secret
bridges client <client_id> <callback_url>       host entry + app settings, fresh secret
bridges check <authorize_url> <client_id> <callback_url>
                                                silent sign-in probe; "login_required" means it works
```

## License

MIT, Profullstack, Inc.
