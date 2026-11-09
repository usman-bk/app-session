import assert from "node:assert/strict";
import { describe, it, before, after } from "node:test";
import { randomUUID } from "node:crypto";

import pg from "pg";

import { MemoryStore } from "../src/store/memory.js";
import { PostgresStore } from "../src/store/postgres.js";
import type { Session, Store } from "../src/store/store.js";

/**
 * The contract both stores satisfy.
 *
 * The memory store is what the service tests run against and Postgres is
 * what production runs on, so anything the two disagree about would show
 * up for the first time in production. The one that matters most is
 * rotate: it has to refuse when the session has already moved on, or two
 * concurrent refreshes both succeed and the legitimate app is signed out
 * while whoever raced it stays in.
 */
function contract(name: string, make: () => Promise<Store>, reset: () => Promise<void>): void {
  describe(`${name} store`, () => {
    const now = new Date("2026-10-23T12:00:00Z");
    const later = new Date("2026-12-23T12:00:00Z");

    function session(over: Partial<Session> = {}): Session {
      return {
        id: randomUUID(),
        userId: "user-1",
        deviceId: "device-1",
        tokenHash: "hash-" + randomUUID(),
        generation: 0,
        createdAt: now,
        lastUsedAt: now,
        expiresAt: later,
        revokedAt: null,
        revokedReason: null,
        ...over,
      };
    }

    it("round trips a session", async () => {
      const store = await make();
      await reset();
      const s = session();
      await store.create(s);

      const got = await store.byTokenHash(s.tokenHash);
      assert.ok(got);
      assert.equal(got.id, s.id);
      assert.equal(got.userId, "user-1");
      assert.equal(got.deviceId, "device-1");
      assert.equal(got.revokedAt, null);
    });

    it("returns nothing for an unknown hash", async () => {
      const store = await make();
      await reset();
      assert.equal(await store.byTokenHash("nothing-here"), null);
    });

    it("rotates", async () => {
      const store = await make();
      await reset();
      const s = session();
      await store.create(s);

      const ok = await store.rotate(s.id, s.tokenHash, "hash-next", now, later);
      assert.equal(ok, true);

      assert.equal(await store.byTokenHash(s.tokenHash), null);
      const got = await store.byTokenHash("hash-next");
      assert.equal(got?.generation, 1);
    });

    // The one that matters. Without the condition inside the write, two
    // refreshes arriving together both succeed.
    it("refuses to rotate a session that has already moved on", async () => {
      const store = await make();
      await reset();
      const s = session();
      await store.create(s);

      assert.equal(await store.rotate(s.id, s.tokenHash, "hash-a", now, later), true);
      assert.equal(
        await store.rotate(s.id, s.tokenHash, "hash-b", now, later),
        false,
        "the same old hash rotated twice, so two parties would hold valid tokens",
      );
    });

    it("refuses to rotate a revoked session", async () => {
      const store = await make();
      await reset();
      const s = session();
      await store.create(s);
      await store.revoke(s.id, "signed_out", now);

      assert.equal(await store.rotate(s.id, s.tokenHash, "hash-next", now, later), false);
    });

    it("revokes with a reason", async () => {
      const store = await make();
      await reset();
      const s = session();
      await store.create(s);
      await store.revoke(s.id, "reuse_detected", now);

      const got = await store.byTokenHash(s.tokenHash);
      assert.ok(got?.revokedAt instanceof Date);
      assert.equal(got?.revokedReason, "reuse_detected");
    });

    it("keeps the first revocation reason", async () => {
      const store = await make();
      await reset();
      const s = session();
      await store.create(s);
      await store.revoke(s.id, "signed_out", now);
      await store.revoke(s.id, "admin", now);

      const got = await store.byTokenHash(s.tokenHash);
      assert.equal(
        got?.revokedReason,
        "signed_out",
        "a second revocation overwrote why the session actually ended",
      );
    });

    it("revokes every session for a person and nobody else's", async () => {
      const store = await make();
      await reset();
      await store.create(session({ deviceId: "phone" }));
      await store.create(session({ deviceId: "tablet" }));
      const other = session({ userId: "user-2" });
      await store.create(other);

      assert.equal(await store.revokeAllForUser("user-1", "password_changed", now), 2);

      const theirs = await store.byTokenHash(other.tokenHash);
      assert.equal(theirs?.revokedAt, null, "somebody else's session was revoked");
    });

    it("lists a person's sessions", async () => {
      const store = await make();
      await reset();
      await store.create(session({ deviceId: "phone" }));
      await store.create(session({ deviceId: "tablet" }));
      await store.create(session({ userId: "user-2", deviceId: "phone" }));

      const got = await store.listForUser("user-1");
      assert.equal(got.length, 2);
      assert.deepEqual(got.map((s) => s.deviceId).sort(), ["phone", "tablet"]);
    });

    // Without this, a rotated token is simply unknown, which looks
    // exactly like a token somebody invented and the theft is never
    // noticed.
    it("remembers which family a rotated hash belonged to", async () => {
      const store = await make();
      await reset();
      const s = session();
      await store.create(s);
      await store.rotate(s.id, s.tokenHash, "hash-next", now, later);
      await store.recordUsedHash(s.id, s.tokenHash, now);

      assert.equal(await store.sessionIdForUsedHash(s.tokenHash), s.id);
      assert.equal(await store.sessionIdForUsedHash("never-used"), null);
    });

    it("sweeps expired sessions and leaves live ones", async () => {
      const store = await make();
      await reset();
      const expired = session({ expiresAt: new Date("2026-10-01T00:00:00Z") });
      const live = session();
      await store.create(expired);
      await store.create(live);

      assert.equal(await store.sweep(now), 1);
      assert.equal(await store.byTokenHash(expired.tokenHash), null);
      assert.ok(await store.byTokenHash(live.tokenHash));
    });
  });
}

const memory = new MemoryStore();
contract(
  "memory",
  async () => memory,
  async () => {
    // A fresh one per test, assigned through the closure.
    (memory as unknown as { sessions: Map<string, unknown> }).sessions.clear();
    (memory as unknown as { byHash: Map<string, unknown> }).byHash.clear();
    (memory as unknown as { usedHashes: Map<string, unknown> }).usedHashes.clear();
  },
);

// A real database or nothing. What is under test is a conditional UPDATE
// under concurrency and a foreign key cascade, and a mock has neither.
const dsn = process.env["DATABASE_URL"];
if (dsn) {
  const pool = new pg.Pool({ connectionString: dsn });
  const store = new PostgresStore(pool);

  before(async () => {
    await store.migrate();
  });
  after(async () => {
    await pool.end();
  });

  contract(
    "postgres",
    async () => store,
    async () => {
      await pool.query("TRUNCATE sessions, used_token_hashes CASCADE");
    },
  );

  describe("postgres specifics", () => {
    it("refuses a revoked row with no reason", async () => {
      await pool.query("TRUNCATE sessions CASCADE");
      await pool.query(
        `INSERT INTO sessions (id, user_id, device_id, token_hash, created_at, last_used_at, expires_at)
         VALUES ($1,'u','d','h', now(), now(), now() + interval '1 day')`,
        [randomUUID()],
      );
      // A revoked session with no reason is one a support question has no
      // answer for, so the schema does not allow it.
      await assert.rejects(
        () => pool.query("UPDATE sessions SET revoked_at = now()"),
        /revocation_has_a_reason/,
      );
    });

    it("rejects two sessions holding the same token hash", async () => {
      await pool.query("TRUNCATE sessions CASCADE");
      const same = "duplicate-hash";
      await pool.query(
        `INSERT INTO sessions (id, user_id, device_id, token_hash, created_at, last_used_at, expires_at)
         VALUES ($1,'u','d',$2, now(), now(), now() + interval '1 day')`,
        [randomUUID(), same],
      );
      await assert.rejects(
        () =>
          pool.query(
            `INSERT INTO sessions (id, user_id, device_id, token_hash, created_at, last_used_at, expires_at)
             VALUES ($1,'u2','d2',$2, now(), now(), now() + interval '1 day')`,
            [randomUUID(), same],
          ),
        /duplicate key/,
      );
    });

    it("drops the used hashes when the session goes", async () => {
      await pool.query("TRUNCATE sessions, used_token_hashes CASCADE");
      const id = randomUUID();
      await pool.query(
        `INSERT INTO sessions (id, user_id, device_id, token_hash, created_at, last_used_at, expires_at)
         VALUES ($1,'u','d','h', now(), now(), now() - interval '1 day')`,
        [id],
      );
      await store.recordUsedHash(id, "old-hash", new Date());

      await store.sweep(new Date());

      const { rows } = await pool.query("SELECT count(*)::int AS n FROM used_token_hashes");
      assert.equal(rows[0]?.n, 0, "the used hashes outlived the session they belonged to");
    });
  });
}
