// Access and refresh tokens, and why they are two different kinds of thing.
//
// An access token is signed and carries its claims, so a service can verify
// it without asking anybody. That is the point of it, and it is also why it
// cannot be revoked: nothing is consulted, so there is nowhere to say no.
// It is therefore short lived, and short means minutes.
//
// A refresh token is the opposite. It is an opaque random string with no
// claims in it at all, it means nothing without a row in the database, and
// so it can be revoked the moment anything looks wrong. It lives for weeks,
// because the whole purpose is that somebody does not sign in again every
// quarter of an hour.
//
// Making both of them JWTs is the common mistake. A long-lived JWT refresh
// token cannot be revoked, which removes the only reason refresh tokens
// exist.

import { createHmac, randomBytes, timingSafeEqual, createHash } from "node:crypto";

export const ACCESS_TTL_SECONDS = 15 * 60;
export const REFRESH_TTL_SECONDS = 60 * 24 * 60 * 60; // 60 days

/** Tolerance for a phone whose clock is wrong. */
export const CLOCK_SKEW_SECONDS = 60;

export interface AccessClaims {
  /** The person. */
  sub: string;
  /** The device, so a token lifted from one phone is visibly out of place. */
  did: string;
  /** The session family, so a revoked family's access tokens can be
   *  recognised by anything that does choose to check. */
  sid: string;
  iat: number;
  exp: number;
}

export class TokenError extends Error {
  constructor(
    message: string,
    readonly code:
      | "malformed"
      | "bad_signature"
      | "expired"
      | "not_yet_valid"
      | "wrong_device",
  ) {
    super(message);
    this.name = "TokenError";
  }
}

function b64url(input: Buffer | string): string {
  return Buffer.from(input)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function unb64url(input: string): Buffer {
  return Buffer.from(input.replace(/-/g, "+").replace(/_/g, "/"), "base64");
}

/**
 * Signs an access token.
 *
 * A compact two part format rather than a JWT, deliberately. A JWT carries
 * an algorithm in its own header, and a verifier that trusts that header is
 * the `alg: none` vulnerability, which has been found in production
 * libraries more than once. Here there is one algorithm, it is not
 * negotiable, and it is not in the token.
 */
export function signAccess(claims: AccessClaims, secret: string): string {
  const payload = b64url(JSON.stringify(claims));
  const sig = b64url(createHmac("sha256", secret).update(payload).digest());
  return `${payload}.${sig}`;
}

export function verifyAccess(
  token: string,
  secret: string,
  now: number = Math.floor(Date.now() / 1000),
): AccessClaims {
  const parts = token.split(".");
  if (parts.length !== 2) {
    throw new TokenError("a token has two parts", "malformed");
  }
  const [payload, sig] = parts as [string, string];

  const expected = createHmac("sha256", secret).update(payload).digest();
  const given = unb64url(sig);

  // Length checked first, because timingSafeEqual throws on a mismatch and
  // the throw itself is a side channel.
  if (given.length !== expected.length || !timingSafeEqual(given, expected)) {
    throw new TokenError("signature does not match", "bad_signature");
  }

  let claims: AccessClaims;
  try {
    claims = JSON.parse(unb64url(payload).toString("utf8")) as AccessClaims;
  } catch {
    throw new TokenError("payload is not readable", "malformed");
  }
  if (!claims.sub || !claims.did || !claims.sid || !claims.exp || !claims.iat) {
    throw new TokenError("payload is missing a field", "malformed");
  }

  // The skew is allowed in both directions. A phone with a clock a minute
  // fast would otherwise present a token nothing accepts yet, and the
  // customer sees a sign-in loop with nothing in the logs to explain it.
  if (now > claims.exp + CLOCK_SKEW_SECONDS) {
    throw new TokenError("token has expired", "expired");
  }
  if (now + CLOCK_SKEW_SECONDS < claims.iat) {
    throw new TokenError("token is not valid yet", "not_yet_valid");
  }
  return claims;
}

/**
 * A refresh token: 32 random bytes and nothing else.
 *
 * Nothing in it is derived from the user, the device or the time, because
 * anything derived is something an attacker can reason about. It means
 * nothing except as a lookup key.
 */
export function newRefreshToken(): string {
  return b64url(randomBytes(32));
}

/**
 * The hash stored in the database.
 *
 * The raw token is never stored, for the same reason a password is not:
 * anybody who reads the table should not thereby be able to use every
 * session in it. A plain SHA-256 rather than a password hash is correct
 * here and would be wrong for a password, because this input is 32 bytes of
 * entropy rather than something a person chose, so there is nothing to
 * brute force and the slow hash would only cost latency on every refresh.
 */
export function hashRefreshToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

/** Compares two hashes without leaking where they differ. */
export function hashesMatch(a: string, b: string): boolean {
  const ab = Buffer.from(a, "utf8");
  const bb = Buffer.from(b, "utf8");
  return ab.length === bb.length && timingSafeEqual(ab, bb);
}
