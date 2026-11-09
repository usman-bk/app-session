import type { Pool } from "pg";

import type { RevokeReason, Session, Store } from "./store.js";

export const SCHEMA = `
CREATE TABLE IF NOT EXISTS sessions (
    id             uuid        PRIMARY KEY,
    user_id        text        NOT NULL,
    device_id      text        NOT NULL,
    -- The hash, never the token. Anybody who can read this table should
    -- not thereby be able to use every session in it.
    token_hash     text        NOT NULL UNIQUE,
    generation     int         NOT NULL DEFAULT 0,
    created_at     timestamptz NOT NULL,
    last_used_at   timestamptz NOT NULL,
    expires_at     timestamptz NOT NULL,
    revoked_at     timestamptz,
    revoked_reason text,

    CONSTRAINT revocation_has_a_reason CHECK (
        (revoked_at IS NULL AND revoked_reason IS NULL)
        OR (revoked_at IS NOT NULL AND revoked_reason IS NOT NULL)
    )
);

CREATE INDEX IF NOT EXISTS sessions_user_idx ON sessions (user_id);
CREATE INDEX IF NOT EXISTS sessions_expires_idx ON sessions (expires_at);

-- Hashes this family has already rotated away.
--
-- This table is what makes a stolen token detectable. Without it a rotated
-- token is simply unknown, which looks exactly like a token somebody
-- invented, and the theft is never noticed.
CREATE TABLE IF NOT EXISTS used_token_hashes (
    token_hash text        PRIMARY KEY,
    session_id uuid        NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    used_at    timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS used_token_hashes_session_idx
    ON used_token_hashes (session_id);
`;

interface Row {
  id: string;
  user_id: string;
  device_id: string;
  token_hash: string;
  generation: number;
  created_at: Date;
  last_used_at: Date;
  expires_at: Date;
  revoked_at: Date | null;
  revoked_reason: string | null;
}

function toSession(r: Row): Session {
  return {
    id: r.id,
    userId: r.user_id,
    deviceId: r.device_id,
    tokenHash: r.token_hash,
    generation: r.generation,
    createdAt: r.created_at,
    lastUsedAt: r.last_used_at,
    expiresAt: r.expires_at,
    revokedAt: r.revoked_at,
    revokedReason: r.revoked_reason,
  };
}

export class PostgresStore implements Store {
  constructor(private readonly pool: Pool) {}

  async migrate(): Promise<void> {
    await this.pool.query(SCHEMA);
  }

  async create(s: Session): Promise<void> {
    await this.pool.query(
      `INSERT INTO sessions
         (id, user_id, device_id, token_hash, generation,
          created_at, last_used_at, expires_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
      [s.id, s.userId, s.deviceId, s.tokenHash, s.generation,
       s.createdAt, s.lastUsedAt, s.expiresAt],
    );
  }

  async byTokenHash(hash: string): Promise<Session | null> {
    const { rows } = await this.pool.query<Row>(
      `SELECT * FROM sessions WHERE token_hash = $1`, [hash],
    );
    return rows[0] ? toSession(rows[0]) : null;
  }

  /**
   * One statement, with the condition inside the write.
   *
   * Two refreshes arriving together, which is what a retried request looks
   * like, would otherwise both read the same session and both rotate it.
   * The second write would leave the family holding a hash the first had
   * already replaced, and the legitimate app would be signed out while
   * whoever raced it stays in.
   */
  async rotate(
    sessionId: string,
    expectedHash: string,
    nextHash: string,
    now: Date,
    expiresAt: Date,
  ): Promise<boolean> {
    const { rowCount } = await this.pool.query(
      `UPDATE sessions
          SET token_hash = $3, generation = generation + 1,
              last_used_at = $4, expires_at = $5
        WHERE id = $1 AND token_hash = $2 AND revoked_at IS NULL`,
      [sessionId, expectedHash, nextHash, now, expiresAt],
    );
    return (rowCount ?? 0) > 0;
  }

  async revoke(sessionId: string, reason: RevokeReason, now: Date): Promise<void> {
    await this.pool.query(
      `UPDATE sessions SET revoked_at = $2, revoked_reason = $3
        WHERE id = $1 AND revoked_at IS NULL`,
      [sessionId, now, reason],
    );
  }

  async revokeAllForUser(userId: string, reason: RevokeReason, now: Date): Promise<number> {
    const { rowCount } = await this.pool.query(
      `UPDATE sessions SET revoked_at = $2, revoked_reason = $3
        WHERE user_id = $1 AND revoked_at IS NULL`,
      [userId, now, reason],
    );
    return rowCount ?? 0;
  }

  async listForUser(userId: string): Promise<Session[]> {
    const { rows } = await this.pool.query<Row>(
      `SELECT * FROM sessions WHERE user_id = $1 ORDER BY created_at`, [userId],
    );
    return rows.map(toSession);
  }

  async recordUsedHash(sessionId: string, hash: string, now: Date): Promise<void> {
    await this.pool.query(
      `INSERT INTO used_token_hashes (token_hash, session_id, used_at)
       VALUES ($1,$2,$3) ON CONFLICT (token_hash) DO NOTHING`,
      [hash, sessionId, now],
    );
  }

  async sessionIdForUsedHash(hash: string): Promise<string | null> {
    const { rows } = await this.pool.query<{ session_id: string }>(
      `SELECT session_id FROM used_token_hashes WHERE token_hash = $1`, [hash],
    );
    return rows[0]?.session_id ?? null;
  }

  /**
   * Deletes expired sessions. The used hashes go with them through the
   * cascade, which is correct: once the family is gone there is nothing
   * left to detect reuse against.
   */
  async sweep(now: Date): Promise<number> {
    const { rowCount } = await this.pool.query(
      `DELETE FROM sessions WHERE expires_at <= $1`, [now],
    );
    return rowCount ?? 0;
  }
}
