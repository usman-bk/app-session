/**
 * Where sessions live.
 *
 * A session is a family of refresh tokens, not a single one. Every refresh
 * replaces the token with a new one in the same family, so the family is
 * the thing that is revoked when something goes wrong, and revoking it ends
 * every descendant at once.
 */

export interface Session {
  /** The family. Stable across every rotation. */
  id: string;
  userId: string;
  deviceId: string;

  /** The hash of the token that is currently valid. */
  tokenHash: string;
  /** How many times this family has been rotated, for the logs. */
  generation: number;

  createdAt: Date;
  lastUsedAt: Date;
  expiresAt: Date;

  revokedAt: Date | null;
  /** Why, so a support question has an answer. */
  revokedReason: string | null;
}

export type RevokeReason =
  /** The person signed out. */
  | "signed_out"
  /** Every session for the person, after a password change. */
  | "password_changed"
  /**
   * A token that had already been rotated was presented again.
   *
   * It means two parties hold tokens from one family, so one of them stole
   * it. Which one cannot be known, so the family ends and both are made to
   * sign in again. See SessionService.refresh.
   */
  | "reuse_detected"
  | "admin";

export interface Store {
  create(s: Session): Promise<void>;

  /** Finds a session by the hash of the token presented. */
  byTokenHash(hash: string): Promise<Session | null>;

  /**
   * Replaces the current token with a new one, only if the session still
   * holds the old one.
   *
   * The condition is the whole mechanism, and it has to be inside the
   * write. Two refreshes arriving together, which is what a phone that
   * retried a request looks like, would otherwise both read the same
   * session and both rotate it, and the second would leave a family whose
   * stored hash matches a token the first already replaced.
   *
   * Returns false if the session had already moved on.
   */
  rotate(
    sessionId: string,
    expectedHash: string,
    nextHash: string,
    now: Date,
    expiresAt: Date,
  ): Promise<boolean>;

  /** Ends a family. */
  revoke(sessionId: string, reason: RevokeReason, now: Date): Promise<void>;

  /** Ends every family belonging to a person, and reports how many. */
  revokeAllForUser(userId: string, reason: RevokeReason, now: Date): Promise<number>;

  /** For the "signed in on these devices" screen. */
  listForUser(userId: string): Promise<Session[]>;

  /**
   * Records that a hash belonged to a family, after it was rotated away.
   *
   * This is what makes reuse detectable. Without it, a rotated token is
   * simply unknown, which is indistinguishable from a token somebody made
   * up, and the theft goes unnoticed.
   */
  recordUsedHash(sessionId: string, hash: string, now: Date): Promise<void>;

  /** Finds the family a rotated-away token belonged to. */
  sessionIdForUsedHash(hash: string): Promise<string | null>;

  /** Deletes expired sessions and used hashes, and reports how many. */
  sweep(now: Date): Promise<number>;
}
