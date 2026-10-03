# `@paperclipai/paperclip-relay`

Client half of the Paperclip relay: the wire protocol, fail-closed configuration,
per-user relay credentials, and the deployment-mode precondition an instance must
satisfy before it may publish itself.

The hosted service subscribers connect to is a separate repository,
`paperclip-relay-server`. This package is what runs inside a subscriber's
Paperclip instance.

## What it does

A relay lets someone reach a Paperclip instance that sits behind a home router, a
corporate NAT, or a cloud firewall. The instance dials **out** over a WebSocket and
holds the connection open, so no inbound port is opened anywhere and nothing needs
to be configured on the customer's router.

Three lanes carry that traffic, and the split is deliberate:

| Lane | Transport | Carries |
| --- | --- | --- |
| control | one long-lived `wss://` socket from dialer to relay | newline-delimited JSON: registration, version selection, stream lifecycle, response heads |
| tunnel | one short-lived `wss://` socket per browser connection | raw bytes, no framing: request body up, response body down |
| data | browser to relay | ordinary HTTP and WebSocket |

Bodies never travel on the control channel. That is why there is no multiplexer
here and no partial-message state machine: each browser connection maps to exactly
one tunnel socket, so a stream is either served or refused, never half-interpreted.

## Two things it will not do

**It will not publish a `local_trusted` instance.** That mode grants an implicit
instance-admin board actor to anything that can reach the server, with no credential
(`server/src/middleware/auth.ts`). A relay exists to make the server reachable from
the internet, so publishing one would hand a shell on the machine — and everything
in its repositories — to anyone who learns the hostname. The check in `src/gate.ts`
is an allowlist of the single safe mode rather than a denylist of `local_trusted`,
so a deployment mode this build does not recognise is refused rather than assumed
safe.

**It will not trust the relay to name an actor.** A relay credential authorises one
*local board user*. Adding an instance-admin user to the instance later does not
widen what the relay can act as, because no credential was issued for them.

## Transport security

The relay credential is presented as a bearer token on the control socket's upgrade
request, so `ws://` is refused unless `PAPERCLIP_RELAY_ALLOW_INSECURE_TRANSPORT=true`
is set explicitly. Credentials are deliberately *not* read from the environment — they
are issued per user and stored hashed — because a 256-bit secret in an env var ends
up in `docker inspect` output and process listings.

Tokens carry 256 bits of entropy, so they are hashed with SHA-256 rather than a
password KDF, matching the instance's existing `agent_api_keys` and `board_api_keys`.
Verification is constant-time regardless.

## Staying in sync with the relay server

The two repositories implement this protocol independently, so
`src/protocol/conformance/vectors.ts` is the tie-breaker. It is canonical here;
`paperclip-relay-server` vendors a byte-identical copy and runs the same assertions
over it, so a schema change that does not update the vectors fails CI in whichever
repository forgot.

Each vector pins **both** directions from one literal: the decoder must reproduce the
expected message, and re-encoding that message must reproduce the exact input bytes.

Version skew is handled separately by mandatory negotiation. A dialer advertises the
protocol versions it speaks and the relay picks the highest common one; a dialer
sharing no version with the relay is refused with a stable code. That is what makes
the duplicated codec survivable — skew is a clean refusal, never a misparse.

## Tests

```sh
pnpm --filter @paperclipai/paperclip-relay test
pnpm --filter @paperclipai/paperclip-relay typecheck
```