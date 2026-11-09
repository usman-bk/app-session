import type { RevokeReason, Session, Store } from "./store.js";

/**
 * An in process Store.
 *
 * It is held to the same conformance suite as the Postgres one, including
 * the part that matters most: rotate has to be conditional, so two
 * concurrent refreshes cannot both succeed.
 */
export class MemoryStore implements Store {
  private readonly sessions = new Map<string, Session>();
  private readonly byHash = new Map<string, string>();
  private readonly usedHashes = new Map<string, { sessionId: string; at: Date }>();

  async create(s: Session): Promise<void> {
    this.sessions.set(s.id, { ...s });
    this.byHash.set(s.tokenHash, s.id);
  }

  async byTokenHash(hash: string): Promise<Session | null> {
    const id = this.byHash.get(hash);
    if (!id) return null;
    const s = this.sessions.get(id);
    return s ? { ...s } : null;
  }

  async rotate(
    sessionId: string,
    expectedHash: string,
    nextHash: string,
    now: Date,
    expiresAt: Date,
  ): Promise<boolean> {
    const s = this.sessions.get(sessionId);
    // The check and the write are not interleaved here because JavaScript
    // runs this synchronously, which is the same guarantee the Postgres
    // store gets from putting the condition in the UPDATE.
    if (!s || s.tokenHash !== expectedHash || s.revokedAt) return false;

    this.byHash.delete(expectedHash);
    s.tokenHash = nextHash;
    s.generation += 1;
    s.lastUsedAt = now;
    s.expiresAt = expiresAt;
    this.byHash.set(nextHash, sessionId);
    return true;
  }

  async revoke(sessionId: string, reason: RevokeReason, now: Date): Promise<void> {
    const s = this.sessions.get(sessionId);
    if (!s || s.revokedAt) return;
    s.revokedAt = now;
    s.revokedReason = reason;
  }

  async revokeAllForUser(userId: string, reason: RevokeReason, now: Date): Promise<number> {
    let n = 0;
    for (const s of this.sessions.values()) {
      if (s.userId === userId && !s.revokedAt) {
        s.revokedAt = now;
        s.revokedReason = reason;
        n += 1;
      }
    }
    return n;
  }

  async listForUser(userId: string): Promise<Session[]> {
    return [...this.sessions.values()]
      .filter((s) => s.userId === userId)
      .map((s) => ({ ...s }))
      .sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime());
  }

  async recordUsedHash(sessionId: string, hash: string, now: Date): Promise<void> {
    this.usedHashes.set(hash, { sessionId, at: now });
  }

  async sessionIdForUsedHash(hash: string): Promise<string | null> {
    return this.usedHashes.get(hash)?.sessionId ?? null;
  }

  async sweep(now: Date): Promise<number> {
    let n = 0;
    for (const [id, s] of this.sessions) {
      if (s.expiresAt <= now) {
        this.sessions.delete(id);
        this.byHash.delete(s.tokenHash);
        n += 1;
      }
    }
    for (const [hash, used] of this.usedHashes) {
      if (!this.sessions.has(used.sessionId)) {
        this.usedHashes.delete(hash);
      }
    }
    return n;
  }

  /** For the tests. */
  get size(): number {
    return this.sessions.size;
  }
}
