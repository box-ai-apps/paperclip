---
title: Relay publishing
summary: Reach a Paperclip instance from anywhere without opening a port
---

Relay publishing lets a Paperclip instance be reached from anywhere, without
opening an inbound port or configuring a router, Tailscale, or a reverse proxy.

The instance dials **out** over a WebSocket and holds the connection open. That
is why it works from behind a home router, a corporate NAT, or a cloud firewall:
nothing needs to accept a connection at the subscriber's end.

## What a relay is, and is not

A relay is a byte pipe with a subscription gate. It holds a browser connection,
asks the instance to serve it, and pairs the two together.

It is **not** a remote-control system that grants the relay operator access to
your instance. That distinction is enforced by construction:

- The browser authenticates to Paperclip directly. Its session cookie rides the
  tunnel, so **your instance** authenticates the request — with your own session,
  membership, and company scoping. Your audit log records what actually happened.
- The relay has no knowledge of Paperclip's users or roles, and the protocol has
  no field in which it could name one. A conformance vector asserts that a stream
  naming an actor is rejected as an unknown field.
- Therefore a relay operator can read or alter the bytes passing through — that is
  inherent to any relay — but **cannot escalate**, because every request they
  inject still needs a valid Paperclip credential that originated from you.

A relay credential answers exactly one question: *does this control socket belong
to the instance that owns this slug?*

## Requirements

1. **`PAPERCLIP_DEPLOYMENT_MODE=authenticated`.** Publishing refuses to start in
   `local_trusted`, which grants unauthenticated instance-admin to anything that
   reaches the socket. A relay's whole purpose is to make that socket reachable
   from the internet, so publishing a `local_trusted` instance would hand a shell
   on your machine — and everything in its repositories — to anyone who learns the
   hostname.
2. **A claimed instance.** Create a board user and claim the instance from the
   browser first, so there is a real session for relayed requests to authenticate
   against.
3. **An issued relay credential.** See below.

## Setup

```sh
PAPERCLIP_DEPLOYMENT_MODE=authenticated
PAPERCLIP_RELAY_ENABLED=true
PAPERCLIP_RELAY_URL=wss://relay.example.com/control
PAPERCLIP_RELAY_INSTANCE_SLUG=acme-laptop
```

Then issue a credential, which writes it to a `0600` file and shows the token
once:

```sh
curl -X POST https://your-board/api/relay/credentials \
  -H "cookie: $PAPERCLIP_SESSION" \
  -H "content-type: application/json" \
  -d '{"label":"laptop"}'
```

Restart the server. The dialer connects, negotiates a protocol version, and the
instance appears on the relay under its slug.

### Board endpoints

All require instance admin. There is deliberately no per-user credential and no
endpoint that names an actor.

| Endpoint | Purpose |
|----------|---------|
| `GET /api/relay/status` | Connection state, slug, negotiated version, active streams. Never a credential or a hash. |
| `GET /api/relay/credentials` | Credential metadata: labels, last use, revocation. Never the secret. |
| `POST /api/relay/credentials` | Issue a credential. Returns the token **once**. |
| `POST /api/relay/credentials/:id/revoke` | Revoke. Removes the stored token too, so it stops being presented immediately. |
| `POST /api/relay/retry` | Ask a permanently-refused dialer to try again. |

## How a request is served

Three lanes carry the traffic, and the split is deliberate:

| Lane | Carries |
|------|---------|
| control | one long-lived socket; registration, version negotiation, liveness, stream lifecycle |
| tunnel | one short-lived socket per browser connection; raw bytes only |
| data | the browser's own HTTP or WebSocket |

Bodies never travel on the control channel. That is why there is no multiplexer
and no partial-message state machine: each browser connection maps to exactly one
tunnel socket, so a stream is either served or refused, never half-interpreted.
Agent-control traffic is low concurrency, so the extra TLS handshake per stream is
not worth the correctness risk of a hand-written multiplexer.

Before the request reaches your app, the client half rewrites `Host`, `Origin`,
and `Referer` to the loopback authority — exactly what a reverse proxy in front of
the app does. Two mechanisms would otherwise reject every relayed request:
`board-mutation-guard` requires a mutation's `Origin` to match the origin the
request itself presents (so every create, update, and delete fails while reads
appear to work), and Better Auth's trusted-origin check rejects the unfamiliar
host outright.

**`Origin` is rewritten, never invented.** A request that arrives without one
leaves without one. Synthesising an `Origin` would hand every cross-site form post
a passing CSRF check, which is exactly the attack that guard exists to stop.

### WebSockets

`/api/realtime/live-events` and the terminal socket work through a relay. The
client half does **not** negotiate its own WebSocket with your app: it forwards the
browser's upgrade request over a raw TCP socket and relays your app's own `101`
back verbatim. `Sec-WebSocket-Accept` is derived from the key in the *browser's*
request, so a locally negotiated handshake would produce a value the browser
rejects.

## Security posture

- **Duplicate JSON keys are rejected**, not resolved last-wins. On a protocol shared
  between two independently released implementations, last-wins is request
  smuggling.
- **Unknown fields are a hard error**, because an ignored field is
  indistinguishable from one the sender believed was honoured.
- **Framing headers are refused as relayed input** — `Host`, `Content-Length`,
  `Transfer-Encoding`, `Connection`, `Upgrade`, `Expect`, `TE`, and the
  `X-Forwarded-*` family. A peer must not dictate message framing or forge its own
  address in your logs. `Connection` and `Upgrade` are the exception on a WebSocket
  stream, where they *are* the negotiation.
- **The client address arrives as a validated field**, not a header, so it cannot
  be confused with one the browser supplied.
- **Version negotiation is mandatory.** Both sides intersect the versions they
  speak; a client sharing none is refused cleanly rather than misparsing.
- **`ws://` is refused** unless `PAPERCLIP_RELAY_ALLOW_INSECURE_TRANSPORT=true`,
  because the credential rides that socket as a bearer token.
- **A relay cannot redirect streams elsewhere.** The tunnel endpoint arrives in
  `hello_ok` and must be the same origin as the control socket.

## Trust and self-hosting

You are trusting the relay operator with the bytes in transit. Mitigations in
place: per-instance credentials, no identity assertion, a full audit trail, and
one-tap `revoke`.

The relay server is a separate open-source repository,
`paperclip-relay-server`, which vendors the protocol's conformance vectors and
runs the same assertions over its own codec. That is what makes a self-hosted
relay — or an audit of one — a real option rather than a claim.

## Troubleshooting

| State | Meaning |
|-------|---------|
| `refused` / `unauthorized_control` | No credential issued, or the stored one is revoked or expired. Issue one. |
| `refused` / `instance_not_entitled` | The subscription is not active. |
| `refused` / `instance_slug_conflict` | Another live session owns this slug. |
| `refused` / `no_common_protocol_version` | The relay is too old or too new for this build. |
| `connecting` with repeated drops | The relay is unreachable from here, or a proxy is not forwarding WebSocket upgrades. |