import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { decodeRelayMessage } from "../protocol/decode.js";
import type { RelayMessage } from "../protocol/messages.js";
import {
  RelayDialer,
  type RelayControlSocket,
  type RelayDialerEvent,
} from "./control-client.js";

/**
 * A scriptable stand-in for the `ws` client.
 *
 * It records what the dialer sent and lets a test drive the socket lifecycle and
 * inbound frames by hand, so every assertion below is about the dialer's
 * decisions rather than about timing.
 */
class FakeSocket implements RelayControlSocket {
  readonly sent: RelayMessage[] = [];
  readonly rawSent: string[] = [];
  closeCalls: Array<{ code?: number; reason?: string }> = [];

  private readonly listeners = new Map<string, Array<(...args: never[]) => void>>();

  on(event: string, listener: (...args: never[]) => void): void {
    const existing = this.listeners.get(event) ?? [];
    existing.push(listener);
    this.listeners.set(event, existing);
  }

  send(data: string): void {
    this.rawSent.push(data);
    // Parse what we sent so a test can assert on real messages rather than
    // string comparisons, which would pass on a reformatting change.
    this.sent.push(decodeRelayMessage(data.trimEnd()));
  }

  close(code?: number, reason?: string): void {
    this.closeCalls.push({ code, reason });
  }

  // --- test drivers -------------------------------------------------------

  emitOpen(): void {
    this.fire("open");
  }

  emitMessage(message: RelayMessage): void {
    this.fire("message", `${JSON.stringify(message)}\n` as never);
  }

  emitRaw(text: string): void {
    this.fire("message", text as never);
  }

  emitClose(code = 1000, reason = ""): void {
    this.fire("close", code as never, reason as never);
  }

  emitError(error: Error): void {
    this.fire("error", error as never);
  }

  private fire(event: string, ...args: unknown[]): void {
    for (const listener of this.listeners.get(event) ?? []) {
      (listener as (...a: unknown[]) => void)(...args);
    }
  }
}

interface Harness {
  readonly dialer: RelayDialer;
  readonly events: RelayDialerEvent[];
  readonly sockets: FakeSocket[];
  latest(): FakeSocket;
}

function createHarness(
  overrides: {
    resolveCredential?: () => Promise<string | null>;
    handshakeTimeoutMs?: number;
    maxConcurrentStreams?: number;
    backoffBaseMs?: number;
  } = {},
): Harness {
  const sockets: FakeSocket[] = [];
  const events: RelayDialerEvent[] = [];

  const dialer = new RelayDialer({
    url: "wss://relay.example.com/control",
    instanceSlug: "acme-laptop",
    paperclipVersion: "0.3.1",
    resolveCredential: overrides.resolveCredential ?? (async () => "pcp_relay_token"),
    createSocket: () => {
      const socket = new FakeSocket();
      sockets.push(socket);
      return socket;
    },
    handshakeTimeoutMs: overrides.handshakeTimeoutMs ?? 5_000,
    maxConcurrentStreams: overrides.maxConcurrentStreams,
    // Zero jitter and a fixed base make every reconnect deterministic.
    backoff: { baseDelayMs: overrides.backoffBaseMs ?? 100, maxDelayMs: 1_000, jitterRatio: 0 },
    random: () => 0,
  });

  dialer.on((event) => events.push(event));

  return {
    dialer,
    events,
    sockets,
    latest: () => {
      const socket = sockets[sockets.length - 1];
      if (!socket) throw new Error("no socket was opened");
      return socket;
    },
  };
}

const HELLO_OK: RelayMessage = {
  v: 1,
  type: "hello_ok",
  protocolVersion: 1,
  sessionId: "sess-1",
  heartbeatIntervalMs: 1_000,
  maxConcurrentStreams: 32,
  capabilities: ["http", "websocket"],
};

const OPEN_STREAM: RelayMessage = {
  v: 1,
  type: "open_stream",
  streamId: "s-1",
  streamNonce: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  kind: "http",
  method: "GET",
  path: "/api/health",
  headers: { cookie: "paperclip-x.session_token=abc" },
};

/** Connect and complete the handshake, leaving the dialer in `ready`. */
async function reachReady(harness: Harness): Promise<void> {
  harness.dialer.start();
  await vi.waitFor(() => expect(harness.sockets).toHaveLength(1));
  harness.latest().emitOpen();
  harness.latest().emitMessage(HELLO_OK);
  expect(harness.dialer.currentState).toBe("ready");
}

describe("RelayDialer handshake", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it("presents the resolved credential to the socket factory", async () => {
    const seen: Array<{ url: string; token: string }> = [];
    const dialer = new RelayDialer({
      url: "wss://relay.example.com/control",
      instanceSlug: "acme-laptop",
      resolveCredential: async () => "pcp_relay_abc",
      createSocket: (url, token) => {
        seen.push({ url, token });
        return new FakeSocket();
      },
      backoff: { baseDelayMs: 10, jitterRatio: 0 },
    });
    dialer.start();
    await vi.advanceTimersByTimeAsync(0);
    expect(seen).toEqual([{ url: "wss://relay.example.com/control", token: "pcp_relay_abc" }]);
    dialer.stop();
  });

  it("sends hello with the slug, capabilities, and supported versions", async () => {
    const harness = createHarness();
    harness.dialer.start();
    await vi.waitFor(() => expect(harness.sockets).toHaveLength(1));
    harness.latest().emitOpen();

    expect(harness.latest().sent).toEqual([
      {
        v: 1,
        type: "hello",
        supportedProtocolVersions: [1],
        instanceSlug: "acme-laptop",
        paperclipVersion: "0.3.1",
        capabilities: ["http", "websocket"],
      },
    ]);
  });

  it("reports ready and clears the handshake deadline", async () => {
    const harness = createHarness({ handshakeTimeoutMs: 5_000 });
    harness.dialer.start();
    await vi.waitFor(() => expect(harness.sockets).toHaveLength(1));
    harness.latest().emitOpen();
    // A long heartbeat interval keeps the separate liveness timeout out of this
    // test, so the only deadline under examination is the handshake one.
    harness.latest().emitMessage({ ...HELLO_OK, heartbeatIntervalMs: 600_000 } as RelayMessage);

    expect(harness.events).toContainEqual({
      type: "ready",
      sessionId: "sess-1",
      protocolVersion: 1,
      // The relay offered 32; our local ceiling of 8 wins.
      maxConcurrentStreams: 8,
    });
    expect(harness.dialer.currentState).toBe("ready");
    expect(harness.dialer.protocolVersion).toBe(1);

    // Well past the handshake deadline. If that timer leaked, the session would
    // have ended and a second socket would be open by now.
    await vi.advanceTimersByTimeAsync(30_000);
    expect(harness.sockets).toHaveLength(1);
    expect(harness.dialer.currentState).toBe("ready");
    expect(
      harness.events.some((event) => event.type === "disconnected" && event.message.includes("handshake")),
    ).toBe(false);
  });

  it("clamps the relay's stream ceiling to the local floor", async () => {
    const harness = createHarness({ maxConcurrentStreams: 2 });
    harness.dialer.start();
    await vi.waitFor(() => expect(harness.sockets).toHaveLength(1));
    harness.latest().emitOpen();
    harness.latest().emitMessage({ ...HELLO_OK, maxConcurrentStreams: 64 } as RelayMessage);

    const ready = harness.events.find((event) => event.type === "ready");
    expect(ready).toMatchObject({ maxConcurrentStreams: 2 });
  });

  it("does not let a relay raise our ceiling above the local floor", async () => {
    const harness = createHarness({ maxConcurrentStreams: 4 });
    harness.dialer.start();
    await vi.waitFor(() => expect(harness.sockets).toHaveLength(1));
    harness.latest().emitOpen();
    harness.latest().emitMessage({ ...HELLO_OK, maxConcurrentStreams: 1 } as RelayMessage);

    const ready = harness.events.find((event) => event.type === "ready");
    expect(ready).toMatchObject({ maxConcurrentStreams: 1 });
  });

  it("gives up when the relay never completes the handshake", async () => {
    const harness = createHarness({ handshakeTimeoutMs: 5_000 });
    harness.dialer.start();
    await vi.waitFor(() => expect(harness.sockets).toHaveLength(1));
    harness.latest().emitOpen();

    await vi.advanceTimersByTimeAsync(5_001);

    expect(harness.events).toContainEqual({
      type: "disconnected",
      code: "internal_error",
      message: "the relay did not complete the handshake in time",
      permanent: false,
    });
    expect(harness.dialer.currentState).toBe("connecting");
  });
});

describe("RelayDialer permanent refusal", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it("stops after a hello_reject that needs an operator", async () => {
    const harness = createHarness();
    harness.dialer.start();
    await vi.waitFor(() => expect(harness.sockets).toHaveLength(1));
    harness.latest().emitOpen();
    harness.latest().emitMessage({
      v: 1,
      type: "hello_reject",
      code: "instance_not_entitled",
      message: "subscription is not active",
    });

    expect(harness.events).toContainEqual({
      type: "refused",
      code: "instance_not_entitled",
      message: "subscription is not active",
      permanent: true,
    });
    expect(harness.dialer.currentState).toBe("stopped");
  });

  it("does not reconnect after a permanent refusal", async () => {
    const harness = createHarness();
    harness.dialer.start();
    await vi.waitFor(() => expect(harness.sockets).toHaveLength(1));
    harness.latest().emitOpen();
    harness.latest().emitMessage({
      v: 1,
      type: "hello_reject",
      code: "credential_revoked",
      message: "revoked",
    });

    await vi.advanceTimersByTimeAsync(120_000);
    expect(harness.sockets).toHaveLength(1);
  });

  it("refuses when the relay selects a protocol version we do not speak", async () => {
    const harness = createHarness();
    harness.dialer.start();
    await vi.waitFor(() => expect(harness.sockets).toHaveLength(1));
    harness.latest().emitOpen();
    // Negotiation runs against the relay's *selection*, not just its offer, so a
    // relay claiming a version we never advertised cannot install it on us.
    harness.latest().emitMessage({ ...HELLO_OK, protocolVersion: 99 } as RelayMessage);

    expect(harness.events).toContainEqual({
      type: "refused",
      code: "no_common_protocol_version",
      message: expect.stringContaining("99"),
      permanent: true,
    });
    expect(harness.dialer.currentState).toBe("stopped");
  });

  it("refuses when the instance has no credential at all", async () => {
    const harness = createHarness({ resolveCredential: async () => null });
    harness.dialer.start();
    await vi.advanceTimersByTimeAsync(0);

    expect(harness.events).toContainEqual({
      type: "refused",
      code: "unauthorized_control",
      message: "this instance has no relay credential to publish with",
      permanent: true,
    });
    expect(harness.sockets).toHaveLength(0);
  });

  it("retries when the credential store throws, treating it as transient", async () => {
    const harness = createHarness({
      resolveCredential: async () => {
        throw new Error("connection terminated");
      },
    });
    harness.dialer.start();
    await vi.advanceTimersByTimeAsync(0);
    expect(harness.dialer.currentState).toBe("connecting");

    // A database blip must not permanently refuse publishing.
    await vi.advanceTimersByTimeAsync(100);
    expect(harness.events.filter((event) => event.type === "disconnected").length).toBeGreaterThan(1);
    expect(harness.events.some((event) => event.type === "refused")).toBe(false);
  });

  it("treats a policy-violation close as permanent rather than hammering", async () => {
    const harness = createHarness();
    await reachReady(harness);
    harness.latest().emitClose(1008, "not entitled");

    expect(harness.events).toContainEqual({
      type: "refused",
      code: "unauthorized_control",
      message: "not entitled",
      permanent: true,
    });

    await vi.advanceTimersByTimeAsync(120_000);
    expect(harness.sockets).toHaveLength(1);
  });

  it("reconnects immediately when an established session drops transiently", async () => {
    const harness = createHarness();
    await reachReady(harness);
    harness.latest().emitClose(1006, "abnormal closure");

    await vi.waitFor(() => expect(harness.sockets).toHaveLength(2));
    harness.latest().emitOpen();
    // A session that had worked is not a backoff candidate: hammering the relay
    // after a network blip would be the wrong response.
    expect(harness.latest().sent[0]).toMatchObject({ type: "hello" });
  });
});

describe("RelayDialer heartbeat", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it("sends one heartbeat per agreed interval", async () => {
    const harness = createHarness();
    await reachReady(harness);
    const socket = harness.latest();

    // The relay answers each beat, which is what a live relay does; otherwise the
    // liveness timeout would (correctly) end the session before three intervals.
    for (let i = 1; i <= 3; i += 1) {
      await vi.advanceTimersByTimeAsync(1_000);
      socket.emitMessage({ v: 1, type: "heartbeat", seq: i });
    }

    const beats = socket.sent.filter((message) => message.type === "heartbeat");
    expect(beats.map((beat) => (beat as { seq: number }).seq)).toEqual([1, 2, 3]);
  });

  it("tears the session down when the relay goes quiet past the timeout", async () => {
    const harness = createHarness();
    await reachReady(harness);
    // Interval 1000ms, multiplier 2.5, so the deadline is 2500ms of silence. The
    // check runs on the interval, so it is observed on the next tick past that.
    await vi.advanceTimersByTimeAsync(3_000);

    expect(harness.events).toContainEqual({
      type: "disconnected",
      code: "internal_error",
      message: expect.stringContaining("past the agreed heartbeat"),
      permanent: false,
    });
    expect(harness.dialer.currentState).not.toBe("ready");
  });

  it("stays connected while the relay keeps answering", async () => {
    const harness = createHarness();
    await reachReady(harness);
    for (let i = 0; i < 5; i += 1) {
      await vi.advanceTimersByTimeAsync(1_000);
      harness.latest().emitMessage({ v: 1, type: "heartbeat", seq: i });
    }
    expect(harness.dialer.currentState).toBe("ready");
  });

  it("does not reconnect while the relay answers, however long the session runs", async () => {
    const harness = createHarness();
    await reachReady(harness);
    for (let i = 1; i <= 40; i += 1) {
      await vi.advanceTimersByTimeAsync(1_000);
      harness.latest().emitMessage({ v: 1, type: "heartbeat", seq: i });
    }
    expect(harness.sockets).toHaveLength(1);
    expect(harness.dialer.currentState).toBe("ready");
  });

  it("refuses a heartbeat timeout multiplier that would fire before the first beat", () => {
    expect(
      () =>
        new RelayDialer({
          url: "wss://relay.example.com/control",
          instanceSlug: "acme-laptop",
          resolveCredential: async () => "t",
          createSocket: () => new FakeSocket(),
          heartbeatTimeoutMultiplier: 1,
        }),
    ).toThrow();
  });
});

describe("RelayDialer stream dispatch", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it("surfaces an open_stream request with its nonce and headers", async () => {
    const harness = createHarness();
    await reachReady(harness);
    harness.latest().emitMessage(OPEN_STREAM);

    expect(harness.events).toContainEqual({
      type: "open_stream",
      request: {
        streamId: "s-1",
        streamNonce: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        kind: "http",
        method: "GET",
        path: "/api/health",
        headers: { cookie: "paperclip-x.session_token=abc" },
      },
    });
  });

  it("carries no actor field, because the relay must not name a user", async () => {
    const harness = createHarness();
    await reachReady(harness);
    harness.latest().emitMessage(OPEN_STREAM);

    const event = harness.events.find((candidate) => candidate.type === "open_stream");
    expect(event && "request" in event && event.request).not.toHaveProperty("actorUserId");
  });

  it("sends a rejection when the dialer declines a stream", async () => {
    const harness = createHarness();
    await reachReady(harness);
    expect(
      harness.dialer.respondToStream("s-9", {
        accept: false,
        code: "stream_limit_reached",
        message: "at the local ceiling",
      }),
    ).toBe(true);

    expect(harness.latest().sent).toContainEqual({
      v: 1,
      type: "stream_reject",
      streamId: "s-9",
      code: "stream_limit_reached",
      message: "at the local ceiling",
    });
  });

  it("treats acceptance as silence, because the tunnel socket is the real acknowledgement", async () => {
    const harness = createHarness();
    await reachReady(harness);
    const before = harness.latest().rawSent.length;
    expect(harness.dialer.respondToStream("s-9", { accept: true })).toBe(true);
    expect(harness.latest().rawSent).toHaveLength(before);
  });

  it("refuses to answer once the session is no longer live", async () => {
    const harness = createHarness();
    await reachReady(harness);
    harness.latest().emitClose(1006, "gone");
    expect(harness.dialer.respondToStream("s-9", { accept: true })).toBe(false);
  });

  it("relays a close_stream from the relay", async () => {
    const harness = createHarness();
    await reachReady(harness);
    harness.latest().emitMessage({
      v: 1,
      type: "close_stream",
      streamId: "s-1",
      code: "stream_quota_exceeded",
    });

    expect(harness.events).toContainEqual({
      type: "close_stream",
      streamId: "s-1",
      code: "stream_quota_exceeded",
    });
  });

  it("refuses a stream request that arrives before the handshake completes", async () => {
    const harness = createHarness();
    harness.dialer.start();
    await vi.waitFor(() => expect(harness.sockets).toHaveLength(1));
    harness.latest().emitOpen();
    harness.latest().emitMessage(OPEN_STREAM);

    expect(harness.events).toContainEqual({
      type: "disconnected",
      code: "internal_error",
      message: "the relay asked for a stream before completing the handshake",
      permanent: false,
    });
    expect(harness.events.some((event) => event.type === "open_stream")).toBe(false);
  });
});

describe("RelayDialer hostile input", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it("drops the session on a frame it cannot decode", async () => {
    const harness = createHarness();
    await reachReady(harness);
    harness.latest().emitRaw("{not json}\n");

    expect(harness.events).toContainEqual({
      type: "disconnected",
      code: "malformed_json",
      message: expect.stringContaining("could not accept"),
      permanent: false,
    });
    expect(harness.dialer.currentState).not.toBe("ready");
  });

  it("drops the session on an unknown field, since an ignored field is not a honoured one", async () => {
    const harness = createHarness();
    await reachReady(harness);
    harness.latest().emitRaw('{"v":1,"type":"open_stream","streamId":"s-1","actorUserId":"usr_1"}\n');

    expect(harness.events).toContainEqual({
      type: "disconnected",
      code: "unknown_field",
      message: expect.stringContaining("could not accept"),
      permanent: false,
    });
  });

  it("drops the session on a client-only message arriving from the relay", async () => {
    const harness = createHarness();
    await reachReady(harness);
    harness.latest().emitMessage({ v: 1, type: "hello", supportedProtocolVersions: [1], instanceSlug: "other", paperclipVersion: null, capabilities: [] });

    expect(harness.events).toContainEqual({
      type: "disconnected",
      code: "internal_error",
      message: expect.stringContaining("client-only hello message"),
      permanent: false,
    });
  });

  it("drops the session on a frame declaring a different version mid-session", async () => {
    const harness = createHarness();
    await reachReady(harness);
    harness.latest().emitRaw('{"v":2,"type":"heartbeat","seq":1}\n');

    expect(harness.events).toContainEqual({
      type: "disconnected",
      code: "unsupported_protocol_version",
      message: expect.stringContaining("could not accept"),
      permanent: false,
    });
  });

  it("handles several frames arriving in one message", async () => {
    const harness = createHarness();
    await reachReady(harness);
    harness.latest().emitRaw(
      '{"v":1,"type":"open_stream","streamId":"s-1","streamNonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","kind":"http","method":"GET","path":"/a","headers":{},"actorUserId":"x"}\n',
    );
    // The first frame is rejected outright, so the second must never be acted
    // on even though it is valid.
    harness.latest().emitRaw(
      '{"v":1,"type":"open_stream","streamId":"s-2","streamNonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","kind":"http","method":"GET","path":"/b","headers":{}}\n',
    );

    expect(harness.events.some((event) => event.type === "open_stream")).toBe(false);
  });
});

describe("RelayDialer lifecycle", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it("does not start twice", async () => {
    const harness = createHarness();
    harness.dialer.start();
    await vi.waitFor(() => expect(harness.sockets).toHaveLength(1));
    harness.dialer.start();
    await vi.advanceTimersByTimeAsync(0);
    expect(harness.sockets).toHaveLength(1);
  });

  it("stays stopped once stopped, so a late event cannot revive it", async () => {
    const harness = createHarness();
    await reachReady(harness);
    harness.dialer.stop();
    expect(harness.dialer.currentState).toBe("stopped");

    await vi.advanceTimersByTimeAsync(120_000);
    expect(harness.sockets).toHaveLength(1);
    expect(harness.dialer.currentState).toBe("stopped");
  });

  it("retries after a refusal once an operator asks it to", async () => {
    const harness = createHarness();
    harness.dialer.start();
    await vi.waitFor(() => expect(harness.sockets).toHaveLength(1));
    harness.latest().emitOpen();
    harness.latest().emitMessage({
      v: 1,
      type: "hello_reject",
      code: "instance_not_entitled",
      message: "inactive",
    });
    expect(harness.dialer.currentState).toBe("stopped");

    harness.dialer.retryAfterRefusal();
    await vi.waitFor(() => expect(harness.sockets).toHaveLength(2));
    // `hello` goes out on socket open, so the new socket has to be opened before
    // there is anything to assert.
    harness.latest().emitOpen();
    expect(harness.latest().sent[0]).toMatchObject({ type: "hello" });
  });

  it("survives a listener that throws", async () => {
    const harness = createHarness();
    harness.dialer.on(() => {
      throw new Error("status callback exploded");
    });
    harness.dialer.start();
    await vi.waitFor(() => expect(harness.sockets).toHaveLength(1));
    harness.latest().emitOpen();
    harness.latest().emitMessage(HELLO_OK);

    // A broken status callback must not tear down a healthy session.
    expect(harness.dialer.currentState).toBe("ready");
  });

  it("removes a listener when its unsubscribe is called", async () => {
    const harness = createHarness();
    const seen: RelayDialerEvent[] = [];
    const off = harness.dialer.on((event) => seen.push(event));
    off();
    await reachReady(harness);
    expect(seen).toEqual([]);
  });
});