/** What a host vouches for. Only `sub` is required, and only `sub` links accounts. */
export interface BridgeClaims {
  /** The host's own stable id for the person: a DID, UUID or row id. */
  sub: string;
  name?: string;
  username?: string;
  email?: string;
  /** True only when the host verified the email. */
  email_verified?: boolean;
  /** An https URL. */
  picture?: string;
}

export interface BridgeHostClient {
  /** At least 32 characters; `npx @profullstack/bridges keygen`. */
  secret: string;
  /** Exact callback URLs this client may receive codes at. */
  redirectUris: string[];
  name?: string;
}

export interface ReplayStore {
  /** False when the id was already claimed. */
  claim(jti: string, expiresAt: number): Promise<boolean>;
}

export interface BridgeHostOptions {
  clients: Record<string, BridgeHostClient>;
  /** The signed-in person on the host, or null. */
  getUser(request: Request): Promise<(BridgeClaims & { emailVerified?: boolean }) | null>;
  /** Where to send a signed-out person; `returnTo` is the authorize URL to come back to. */
  loginUrl(returnTo: string, request: Request): string;
  /** Default 60. */
  codeTtlSeconds?: number;
  /** Default: in-memory, fine for one process. */
  replayStore?: ReplayStore;
  authorizePath?: string;
  tokenPath?: string;
}

export interface BridgeHost {
  authorize(request: Request): Promise<Response>;
  token(request: Request): Promise<Response>;
  metadata(base: string): Record<string, unknown>;
}

export function createBridgeHost(options: BridgeHostOptions): BridgeHost;
export function createMemoryReplayStore(): ReplayStore;

export interface BridgeClientOptions {
  authorizeUrl: string;
  tokenUrl: string;
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  fetch?: typeof fetch;
  /** How long a started sign-in stays valid. Default 600. */
  stateTtlSeconds?: number;
  timeoutMs?: number;
}

export type BridgeResult =
  | { ok: true; user: BridgeClaims; returnTo: string }
  | { ok: false; error: string; returnTo: string; prompt: 'none' | 'login' | null };

export interface BridgeClient {
  /** `prompt: 'none'` asks the host to answer without showing anything (silent sign-in). */
  begin(options?: { returnTo?: string; prompt?: 'none' | 'login' }): Promise<{
    url: string;
    /** Store in an httpOnly cookie for `maxAge` seconds. */
    cookie: string;
    maxAge: number;
  }>;
  complete(callback: string | URL | URLSearchParams, cookie: string | null | undefined): Promise<BridgeResult>;
}

export function createBridgeClient(options: BridgeClientOptions): BridgeClient;

export interface OAuthClientOptions {
  authorizeUrl: string;
  tokenUrl: string;
  userinfoUrl: string;
  clientId: string;
  /** Omit for a public client; then pass `stateSecret`. */
  clientSecret?: string;
  /** Seals the state cookie. Defaults to `clientSecret`; at least 32 characters. */
  stateSecret?: string;
  redirectUri: string;
  /** Default ['openid', 'profile']. */
  scopes?: string[];
  /** Map the provider's userinfo to claims. Default: userinfo as-is. */
  toClaims?: (userinfo: any) => Partial<BridgeClaims> & { sub: string };
  fetch?: typeof fetch;
  stateTtlSeconds?: number;
  timeoutMs?: number;
}

/** Sign in with any OAuth 2.1 / OIDC provider: code + PKCE S256, then userinfo. Same shape as a bridge client. */
export function createOAuthClient(options: OAuthClientOptions): BridgeClient;

/** CoinPay (coinpayportal.com) sign-in. `sub` is the person's CoinPay DID when they have one. */
export function createCoinPayClient(
  options: Omit<OAuthClientOptions, 'authorizeUrl' | 'tokenUrl' | 'userinfoUrl' | 'toClaims'> & { baseUrl?: string },
): BridgeClient;
export function normalizeClaims(input: unknown): BridgeClaims;
export function pkceChallenge(verifier: string): Promise<string>;
export function randomToken(bytes?: number): string;
