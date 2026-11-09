import { randomUUID } from "node:crypto";

import {
  ACCESS_TTL_SECONDS,
  REFRESH_TTL_SECONDS,
  hashRefreshToken,
  newRefreshToken,
  signAccess,
  type AccessClaims,
} from "./tokens/tokens.js";
import type { RevokeReason, Session, Store } from "./store/store.js";

export interface Tokens {
  accessToken: string;
  refreshToken: string;
  /** Seconds, so the app knows when to refresh without parsing anything. */
  expiresIn: number;
  sessionId: string;
}

export class SessionError extends Error {
  constructor(
    message: string,
    readonly code:
      | "unknown_token"
      | "expired"
      | "revoked"
      | "wrong_device"
      | "reuse_detected",
  ) {
    super(message);
    this.name = "SessionError";
  }
}

export interface Clock {
  now(): Date;
}

export const systemClock: Clock = { now: () => new Date() };

export class SessionService {
  constructor(
    private readonly store: Store,
    private readonly secret: string,
    private readonly clock: Clock = systemClock,
  ) {
    if (secret.length < 32) {
      // Refused rather than warned about. A short secret makes every
      // access token forgeable, and a warning in a log at boot is not
      // read by anybody.
      throw new Error("the signing secret must be at least 32 characters");
    }
  }

  /** Starts a session. The caller has already checked who this is. */
  async signIn(userId: string, deviceId: string): Promise<Tokens> {
    const now = this.clock.now();
    const session: Session = {
      id: randomUUID(),
      userId,
      deviceId,
      tokenHash: "",
      generation: 0,
      createdAt: now,
      lastUsedAt: now,
      expiresAt: new Date(now.getTime() + REFRESH_TTL_SECONDS * 1000),
      revokedAt: null,
      revokedReason: null,
    };

    const refresh = newRefreshToken();
    session.tokenHash = hashRefreshToken(refresh);
    await this.store.create(session);

    return this.issue(session, refresh);
  }

  /**
   * Exchanges a refresh token for a new pair, and rotates it.
   *
   * Rotation is what makes a stolen refresh token detectable. The old
   * token stops working the moment it is used, so if it is presented
   * again, two parties hold tokens from one family and one of them is a
   * thief.
   *
   * Which one cannot be known. The victim might be the one refreshing, or
   * the attacker might have got there first and the victim's app is now
   * presenting the token that was rotated away. So the family is revoked
   * and both are made to sign in again. Signing somebody out is an
   * annoyance; leaving an attacker with a working session is not.
   */
  async refresh(refreshToken: string, deviceId: string): Promise<Tokens> {
    const now = this.clock.now();
    const hash = hashRefreshToken(refreshToken);

    const session = await this.store.byTokenHash(hash);
    if (!session) {
      // Not simply unknown. It may be a token this family already rotated
      // away, which is the signal worth acting on.
      const familyId = await this.store.sessionIdForUsedHash(hash);
      if (familyId) {
        await this.store.revoke(familyId, "reuse_detected", now);
        throw new SessionError(
          "a refresh token that had already been used was presented again, so the session was ended",
          "reuse_detected",
        );
      }
      throw new SessionError("unknown refresh token", "unknown_token");
    }

    if (session.revokedAt) {
      throw new SessionError(
        `session was revoked: ${session.revokedReason ?? "unknown"}`,
        "revoked",
      );
    }
    if (session.expiresAt <= now) {
      throw new SessionError("session has expired", "expired");
    }

    // A refresh token is bound to the device it was issued to, so one
    // lifted off a phone and replayed from somewhere else does not work
    // on its own. It is not a strong binding, since an attacker with the
    // token usually has the device id too, and it is one more thing they
    // have to get right.
    if (session.deviceId !== deviceId) {
      await this.store.revoke(session.id, "reuse_detected", now);
      throw new SessionError(
        "refresh token was presented by a different device",
        "wrong_device",
      );
    }

    const next = newRefreshToken();
    const nextHash = hashRefreshToken(next);
    const expiresAt = new Date(now.getTime() + REFRESH_TTL_SECONDS * 1000);

    const rotated = await this.store.rotate(
      session.id,
      hash,
      nextHash,
      now,
      expiresAt,
    );
    if (!rotated) {
      // Somebody else rotated this session between the read and the
      // write. Two concurrent refreshes from one app, which happens when
      // a request is retried, land here. The conservative answer is to
      // treat it as reuse: see the README.
      await this.store.revoke(session.id, "reuse_detected", now);
      throw new SessionError(
        "the session was rotated concurrently, so it was ended",
        "reuse_detected",
      );
    }

    await this.store.recordUsedHash(session.id, hash, now);

    return this.issue(
      { ...session, tokenHash: nextHash, generation: session.generation + 1, expiresAt },
      next,
    );
  }

  async signOut(refreshToken: string): Promise<void> {
    const hash = hashRefreshToken(refreshToken);
    const session = await this.store.byTokenHash(hash);
    if (!session) {
      // Signing out something that is already gone is a success. The
      // alternative is an app that cannot clear its own state because the
      // server said no.
      return;
    }
    await this.store.revoke(session.id, "signed_out", this.clock.now());
  }

  /** Ends every session for a person, which is what a password change does. */
  async signOutEverywhere(userId: string, reason: RevokeReason = "password_changed"): Promise<number> {
    return this.store.revokeAllForUser(userId, reason, this.clock.now());
  }

  async sessionsFor(userId: string): Promise<Session[]> {
    return this.store.listForUser(userId);
  }

  private issue(session: Session, refreshToken: string): Tokens {
    const iat = Math.floor(this.clock.now().getTime() / 1000);
    const claims: AccessClaims = {
      sub: session.userId,
      did: session.deviceId,
      sid: session.id,
      iat,
      exp: iat + ACCESS_TTL_SECONDS,
    };
    return {
      accessToken: signAccess(claims, this.secret),
      refreshToken,
      expiresIn: ACCESS_TTL_SECONDS,
      sessionId: session.id,
    };
  }
}
