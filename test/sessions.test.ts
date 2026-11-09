import assert from "node:assert/strict";
import { describe, it, beforeEach } from "node:test";

import { SessionService, SessionError, type Clock } from "../src/sessions.js";
import { MemoryStore } from "../src/store/memory.js";
import {
  ACCESS_TTL_SECONDS,
  CLOCK_SKEW_SECONDS,
  TokenError,
  signAccess,
  verifyAccess,
  type AccessClaims,
} from "../src/tokens/tokens.js";

const SECRET = "a-secret-that-is-at-least-thirty-two-chars";

class TestClock implements Clock {
  constructor(private at = new Date("2026-10-23T12:00:00Z")) {}
  now(): Date {
    return this.at;
  }
  advance(seconds: number): void {
    this.at = new Date(this.at.getTime() + seconds * 1000);
  }
}

describe("sessions", () => {
  let store: MemoryStore;
  let clock: TestClock;
  let svc: SessionService;

  beforeEach(() => {
    store = new MemoryStore();
    clock = new TestClock();
    svc = new SessionService(store, SECRET, clock);
  });

  it("refuses a signing secret short enough to brute force", () => {
    assert.throws(() => new SessionService(store, "short", clock), /32 characters/);
  });

  it("issues a usable pair on sign in", async () => {
    const t = await svc.signIn("user-1", "device-1");

    assert.ok(t.accessToken);
    assert.ok(t.refreshToken);
    assert.equal(t.expiresIn, ACCESS_TTL_SECONDS);

    const claims = verifyAccess(t.accessToken, SECRET, Math.floor(clock.now().getTime() / 1000));
    assert.equal(claims.sub, "user-1");
    assert.equal(claims.did, "device-1");
    assert.equal(claims.sid, t.sessionId);
  });

  it("gives a different refresh token every time it is used", async () => {
    const first = await svc.signIn("user-1", "device-1");
    const second = await svc.refresh(first.refreshToken, "device-1");
    const third = await svc.refresh(second.refreshToken, "device-1");

    assert.notEqual(first.refreshToken, second.refreshToken);
    assert.notEqual(second.refreshToken, third.refreshToken);
    // The family is the same throughout, which is what gets revoked.
    assert.equal(second.sessionId, first.sessionId);
    assert.equal(third.sessionId, first.sessionId);
  });

  it("stops accepting a refresh token once it has been rotated", async () => {
    const first = await svc.signIn("user-1", "device-1");
    await svc.refresh(first.refreshToken, "device-1");

    await assert.rejects(
      () => svc.refresh(first.refreshToken, "device-1"),
      (e: unknown) => e instanceof SessionError && e.code === "reuse_detected",
    );
  });

  // The reason rotation is worth doing at all. A stolen refresh token is
  // invisible until the moment both parties are using one family, and
  // then it is unmistakable.
  it("ends the whole family when a rotated token is presented again", async () => {
    const victim = await svc.signIn("user-1", "device-1");
    const stolen = victim.refreshToken;

    // The attacker gets there first and rotates it.
    const attacker = await svc.refresh(stolen, "device-1");

    // The victim's app, still holding the old token, refreshes.
    await assert.rejects(
      () => svc.refresh(stolen, "device-1"),
      (e: unknown) => e instanceof SessionError && e.code === "reuse_detected",
    );

    // And the attacker's token is dead too. Which party is the thief
    // cannot be known, so both are signed out. An annoyance for the
    // victim; the end of the session for the attacker.
    await assert.rejects(
      () => svc.refresh(attacker.refreshToken, "device-1"),
      (e: unknown) => e instanceof SessionError && e.code === "revoked",
    );

    const sessions = await svc.sessionsFor("user-1");
    assert.equal(sessions.length, 1);
    assert.equal(sessions[0]?.revokedReason, "reuse_detected");
  });

  it("refuses a refresh token presented by another device", async () => {
    const t = await svc.signIn("user-1", "device-1");

    await assert.rejects(
      () => svc.refresh(t.refreshToken, "device-2"),
      (e: unknown) => e instanceof SessionError && e.code === "wrong_device",
    );
    // And the session is gone, because a token arriving from the wrong
    // device is a token that left the device it was issued to.
    const sessions = await svc.sessionsFor("user-1");
    assert.equal(sessions[0]?.revokedAt instanceof Date, true);
  });

  it("refuses a token it has never seen", async () => {
    await assert.rejects(
      () => svc.refresh("made-up-token", "device-1"),
      (e: unknown) => e instanceof SessionError && e.code === "unknown_token",
    );
  });

  it("refuses a refresh token after the session expires", async () => {
    const t = await svc.signIn("user-1", "device-1");
    clock.advance(61 * 24 * 60 * 60);

    await assert.rejects(
      () => svc.refresh(t.refreshToken, "device-1"),
      (e: unknown) => e instanceof SessionError && e.code === "expired",
    );
  });

  it("extends the session on every refresh", async () => {
    const first = await svc.signIn("user-1", "device-1");
    const before = (await svc.sessionsFor("user-1"))[0]?.expiresAt;

    clock.advance(24 * 60 * 60);
    await svc.refresh(first.refreshToken, "device-1");

    const after = (await svc.sessionsFor("user-1"))[0]?.expiresAt;
    assert.ok(before && after && after > before, "a used session did not have its life extended");
  });

  it("signs out", async () => {
    const t = await svc.signIn("user-1", "device-1");
    await svc.signOut(t.refreshToken);

    await assert.rejects(
      () => svc.refresh(t.refreshToken, "device-1"),
      (e: unknown) => e instanceof SessionError && e.code === "revoked",
    );
  });

  // Signing out something already gone is a success. The alternative is
  // an app that cannot clear its own state because the server said no.
  it("treats signing out an unknown token as success", async () => {
    await svc.signOut("never-existed");
  });

  it("signs out everywhere, which is what a password change does", async () => {
    const a = await svc.signIn("user-1", "phone");
    const b = await svc.signIn("user-1", "tablet");
    const other = await svc.signIn("user-2", "phone");

    const n = await svc.signOutEverywhere("user-1");
    assert.equal(n, 2);

    for (const t of [a, b]) {
      await assert.rejects(
        () => svc.refresh(t.refreshToken, t === a ? "phone" : "tablet"),
        (e: unknown) => e instanceof SessionError && e.code === "revoked",
      );
    }
    // And nobody else is affected.
    const still = await svc.refresh(other.refreshToken, "phone");
    assert.ok(still.accessToken);
  });

  it("lists the devices somebody is signed in on", async () => {
    await svc.signIn("user-1", "phone");
    await svc.signIn("user-1", "tablet");

    const sessions = await svc.sessionsFor("user-1");
    assert.deepEqual(sessions.map((s) => s.deviceId).sort(), ["phone", "tablet"]);
  });

  it("keeps one device's session alive when another is revoked", async () => {
    const phone = await svc.signIn("user-1", "phone");
    const tablet = await svc.signIn("user-1", "tablet");

    await svc.signOut(phone.refreshToken);

    const t = await svc.refresh(tablet.refreshToken, "tablet");
    assert.ok(t.accessToken, "signing out one device ended the other");
  });

  it("counts generations, so a log can show how long a family has run", async () => {
    let t = await svc.signIn("user-1", "device-1");
    for (let i = 0; i < 3; i += 1) {
      t = await svc.refresh(t.refreshToken, "device-1");
    }
    const sessions = await svc.sessionsFor("user-1");
    assert.equal(sessions[0]?.generation, 3);
  });

  it("sweeps expired sessions", async () => {
    await svc.signIn("user-1", "device-1");
    assert.equal(store.size, 1);

    clock.advance(61 * 24 * 60 * 60);
    const n = await store.sweep(clock.now());

    assert.equal(n, 1);
    assert.equal(store.size, 0);
  });
});

describe("access tokens", () => {
  const now = 1_700_000_000;
  const claims = { sub: "u1", did: "d1", sid: "s1", iat: now, exp: now + 900 };

  it("round trips", () => {
    const token = signFor(claims);
    const got = verifyAccess(token, SECRET, now);
    assert.deepEqual(got, claims);
  });

  it("refuses a token signed with another secret", () => {
    const token = signFor(claims);
    assert.throws(
      () => verifyAccess(token, "a-different-secret-of-sufficient-length", now),
      (e: unknown) => e instanceof TokenError && e.code === "bad_signature",
    );
  });

  it("refuses a token whose payload was edited", () => {
    const token = signFor(claims);
    const sig = token.split(".")[1] as string;

    const tampered = Buffer.from(
      JSON.stringify({ ...claims, sub: "somebody-else" }),
    )
      .toString("base64")
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");

    assert.throws(
      () => verifyAccess(`${tampered}.${sig}`, SECRET, now),
      (e: unknown) => e instanceof TokenError && e.code === "bad_signature",
    );
  });

  it("refuses a malformed token rather than throwing something unhelpful", () => {
    for (const bad of ["", "nodot", "a.b.c", "....", "x."]) {
      assert.throws(
        () => verifyAccess(bad, SECRET, now),
        (e: unknown) => e instanceof TokenError,
        `"${bad}" did not produce a TokenError`,
      );
    }
  });

  it("expires", () => {
    const token = signFor(claims);
    assert.throws(
      () => verifyAccess(token, SECRET, now + 901 + CLOCK_SKEW_SECONDS),
      (e: unknown) => e instanceof TokenError && e.code === "expired",
    );
  });

  // A phone with a clock a minute fast would otherwise present a token
  // nothing accepts yet, and the customer sees a sign-in loop with
  // nothing in the logs to explain it.
  it("tolerates a clock that is wrong in either direction", () => {
    const token = signFor(claims);
    assert.ok(verifyAccess(token, SECRET, now + 900 + CLOCK_SKEW_SECONDS - 1));
    assert.ok(verifyAccess(token, SECRET, now - CLOCK_SKEW_SECONDS + 1));
  });

  it("refuses a token from the future beyond the skew", () => {
    const future = { ...claims, iat: now + 600, exp: now + 1500 };
    assert.throws(
      () => verifyAccess(signFor(future), SECRET, now),
      (e: unknown) => e instanceof TokenError && e.code === "not_yet_valid",
    );
  });
});

function signFor(c: AccessClaims): string {
  return signAccess(c, SECRET);
}
