/**
 * The identity a host vouches for. `sub` is the only required field: it is the
 * host's own stable id for the person (a DID, a UUID, a row id) and is what an
 * app links its account to. Everything else is a hint for a NEW account and is
 * never used to find an existing one, so a changed email or name on the host
 * cannot move someone into another person's account.
 */
export function normalizeClaims(input) {
  if (!input || typeof input !== 'object') throw new Error('getUser must return an object or null');
  const sub = typeof input.sub === 'string' ? input.sub.trim() : '';
  if (!sub || sub.length > 256) throw new Error('claims.sub must be a non-empty string of at most 256 characters');

  const text = (value, max) =>
    typeof value === 'string' && value.trim() ? value.trim().slice(0, max) : undefined;
  const email = text(input.email, 320);
  const picture = text(input.picture, 2048);

  const claims = { sub };
  const name = text(input.name, 120);
  const username = text(input.username, 64);
  if (name) claims.name = name;
  if (username) claims.username = username;
  if (email && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    claims.email = email;
    // Unverified unless the host says otherwise: an app may only treat an
    // email as proof of ownership when the host checked it.
    claims.email_verified = input.email_verified === true || input.emailVerified === true;
  }
  if (picture && /^https:\/\//i.test(picture)) claims.picture = picture;
  return claims;
}
