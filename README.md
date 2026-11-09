# app-session

_Built with AI assistance._

Sessions for a native app: short access tokens, rotating refresh tokens,
and what to do when one of them is stolen.

TypeScript 5.7 in strict mode, Node 22, Postgres. One runtime dependency,
`pg`. The tests are `node:test`.

```
src/tokens/tokens.ts   signing, hashing, and the clock skew
src/sessions.ts        sign in, refresh, rotation, reuse detection
src/store/             the contract, in memory, and Postgres
```

## Two kinds of token, for two different reasons

An **access token** is signed and carries its claims, so a service can
verify it without asking anybody. That is the point of it, and it is also
why it cannot be revoked: nothing is consulted, so there is nowhere to say
no. It therefore lives fifteen minutes.

A **refresh token** is 32 random bytes and nothing else. It carries no
claims, means nothing without a row in the database, and can be revoked the
instant anything looks wrong. It lives sixty days, because the point is
that nobody signs in again every quarter of an hour.

Making both of them JWTs is the common mistake. A long-lived JWT refresh
token cannot be revoked, which removes the only reason refresh tokens
exist.

### The access token is not a JWT either

It is `base64url(claims).base64url(hmac)`, two parts.

A JWT carries its algorithm in its own header, and a verifier that trusts
that header is the `alg: none` vulnerability, which has been found in
production libraries more than once. Here there is one algorithm, it is not
negotiable, and it is not in the token. The cost is that nothing else can
verify it without this code, which for a token this service issues and this
service checks is not a cost.

### What is stored

The hash, never the token. Anybody who can read the sessions table should
not thereby be able to use every session in it.

A plain SHA-256 rather than a password hash, which is correct here and
would be wrong for a password: the input is 32 bytes of entropy rather than
something a person chose, so there is nothing to brute force, and a slow
hash would only add latency to every refresh.

## Rotation, and what reuse means

Every refresh replaces the token with a new one in the same **family**. The
old one stops working immediately.

That is what makes a stolen refresh token detectable. If a token that has
already been rotated is presented again, two parties hold tokens from one
family, and one of them is a thief.

**Which one cannot be known.** The victim might be the one refreshing now,
or the attacker might have got there first and the victim's app is holding
the token that was rotated away. So the whole family is revoked and both
are made to sign in again.

Signing the victim out is an annoyance. Leaving an attacker with a working
session is not, so the trade is not close.

    sign in    ─▶ token A
    refresh A  ─▶ token B      A is remembered as used
    refresh A  ─▶ the family is revoked, B stops working too

Detecting this needs the used hashes to be kept. Without that table a
rotated token is simply *unknown*, which looks exactly like a token
somebody invented, and the theft is never noticed. That is the whole
purpose of `used_token_hashes`.

## Rotation has to be conditional

```sql
UPDATE sessions
   SET token_hash = $3, generation = generation + 1, ...
 WHERE id = $1 AND token_hash = $2 AND revoked_at IS NULL
```

The condition is inside the write. Two refreshes arriving together, which
is what a retried request looks like, would otherwise both read the same
session and both rotate it, and the second would leave the family holding a
hash the first had already replaced. The legitimate app is then signed out
while whoever won the race stays in.

Removing `token_hash = $2` from that statement makes four conformance tests
fail, which was checked rather than assumed.

**A concurrent rotation is treated as reuse**, and that is a deliberate
choice with a real cost: an app that retries a refresh in flight gets
signed out. The alternative is to tell the two cases apart, and they cannot
be told apart from the server, because a thief racing the victim looks
exactly like the victim racing itself. The app avoids it by not sending two
refreshes at once, which it controls and the server does not.

## Everything else that is deliberate

**The refresh token is bound to its device.** One lifted off a phone and
replayed from elsewhere does not work on its own. It is a weak binding,
since an attacker with the token usually has the device id too, and it is
one more thing they have to get right.

**Clock skew is tolerated in both directions**, by a minute. A phone whose
clock is a minute fast would otherwise present a token nothing accepts yet,
and the customer sees a sign-in loop with nothing in the logs to explain it.

**Signing out an unknown token succeeds.** The alternative is an app that
cannot clear its own state because the server said no.

**A short signing secret is refused at construction**, not warned about. A
warning at boot is not read by anybody, and a short secret makes every
access token forgeable.

**A revoked row must carry a reason**, enforced by a check constraint, and
the first reason wins. "Why am I signed out" is a support question that
should have an answer.

## Running the tests

    npm test                      48 cases
    DATABASE_URL=... npm test     adds the Postgres half

`npm test` typechecks first, then compiles, then runs. Node's
`--experimental-strip-types` cannot run this code, because stripping types
does not handle constructor parameter properties, so the build is a real
`tsc` build rather than a trick.

Both stores are held to one conformance suite, because the memory store is
what the service tests run against and Postgres is what production runs on,
so anything they disagree about appears for the first time in production.

## Out of scope

**No authentication.** `signIn` takes a user id that somebody else has
already verified. Passwords, one time codes and the rest are a different
service.

**No token binding to anything cryptographic.** Device binding here is a
string comparison, not an attested key, so it raises the cost of replay
rather than preventing it.

**No rate limiting.** Refresh is an unauthenticated endpoint in the sense
that the token is the only credential, and it should be limited by IP and
by device. That belongs at the edge.

**Access tokens are not checked against revocation anywhere.** That is the
trade they exist for, and it means a revoked session keeps working for up
to fifteen minutes. Shortening the access TTL shortens that window and
costs more refreshes.
