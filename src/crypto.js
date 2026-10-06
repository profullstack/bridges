// WebCrypto only, so the same code runs on Node >= 20, Bun, Deno, Workers and
// the Next.js edge runtime. Nothing here imports a `node:` module.

const enc = new TextEncoder();
const dec = new TextDecoder();
const subtle = () => globalThis.crypto.subtle;

export function toBase64Url(bytes) {
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function fromBase64Url(text) {
  const base64 = text.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

export function randomToken(bytes = 32) {
  return toBase64Url(globalThis.crypto.getRandomValues(new Uint8Array(bytes)));
}

/** RFC 7636 S256: base64url(sha256(verifier)). */
export async function pkceChallenge(verifier) {
  const digest = await subtle().digest('SHA-256', enc.encode(verifier));
  return toBase64Url(new Uint8Array(digest));
}

/**
 * Compare two strings in time that depends only on their length, so a wrong
 * client secret cannot be found one character at a time.
 */
export function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

const keys = new Map();

/** An AES-256-GCM key derived from a shared secret, one per purpose. */
async function keyFor(secret, purpose) {
  const id = `${purpose}\u0000${secret}`;
  const cached = keys.get(id);
  if (cached) return cached;
  const base = await subtle().importKey('raw', enc.encode(secret), 'HKDF', false, ['deriveKey']);
  const key = await subtle().deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: enc.encode('@profullstack/bridges'), info: enc.encode(purpose) },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
  keys.set(id, key);
  return key;
}

/**
 * Encrypt and authenticate a JSON value. Sealed, not merely signed: a code
 * carries the user's email, and it travels through the browser's address bar.
 */
export async function seal(secret, purpose, value) {
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
  const data = enc.encode(JSON.stringify(value));
  const cipher = new Uint8Array(
    await subtle().encrypt({ name: 'AES-GCM', iv }, await keyFor(secret, purpose), data),
  );
  const out = new Uint8Array(iv.length + cipher.length);
  out.set(iv, 0);
  out.set(cipher, iv.length);
  return toBase64Url(out);
}

/** The value, or null for anything forged, truncated, or sealed for another purpose. */
export async function unseal(secret, purpose, sealed) {
  try {
    const bytes = fromBase64Url(String(sealed));
    if (bytes.length < 13 + 16) return null;
    const plain = await subtle().decrypt(
      { name: 'AES-GCM', iv: bytes.slice(0, 12) },
      await keyFor(secret, purpose),
      bytes.slice(12),
    );
    return JSON.parse(dec.decode(plain));
  } catch {
    return null;
  }
}

export function assertSecret(secret, label) {
  if (typeof secret !== 'string' || secret.length < 32) {
    throw new Error(`${label} must be a string of at least 32 characters (try: npx @profullstack/bridges keygen)`);
  }
}
