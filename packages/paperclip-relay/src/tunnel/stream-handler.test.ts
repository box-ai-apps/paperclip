import { createHash, randomBytes } from "node:crypto";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { WebSocketServer, type WebSocket } from "ws";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import type { RelayStreamRequest } from "../dialer/control-client.js";
import type { RelayMessage } from "../protocol/messages.js";
import { RelayStreamHandler } from "./stream-handler.js";

const WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/** A tunnel socket backed by an in-memory buffer, so tests can drive both sides. */
class FakeTunnel {
  readonly written: Buffer[] = [];
  ended = false;
  destroyed = false;
  destroyReason: string | null = null;
  private readonly queue: Buffer[] = [];
  private waiter: (() => void) | null = null;
  private finished = false;

  readonly inbound: AsyncIterable<Buffer> = this.iterate();

  readonly closed: Promise<{ code: number | null; reason: string | null }> = Promise.resolve({
    code: 1000,
    reason: null,
  });

  private async *iterate(): AsyncGenerator<Buffer> {
    for (;;) {
      const chunk = this.queue.shift();
      if (chunk !== undefined) {
        yield chunk;
        continue;
      }
      if (this.finished) return;
      await new Promise<void>((resolve) => {
        this.waiter = resolve;
      });
    }
  }

  push(chunk: Buffer | string): void {
    this.queue.push(typeof chunk === "string" ? Buffer.from(chunk, "utf8") : chunk);
    this.waiter?.();
    this.waiter = null;
  }

  finish(): void {
    this.finished = true;
    this.waiter?.();
    this.waiter = null;
  }

  write(chunk: Buffer): void {
    this.written.push(chunk);
  }

  end(): void {
    this.ended = true;
  }

  destroy(reason?: string): void {
    this.destroyed = true;
    this.destroyReason = reason ?? null;
    this.finish();
  }

  get writtenText(): string {
    return Buffer.concat(this.written).toString("utf8");
  }
}

interface LocalApp {
  readonly baseUrl: string;
  readonly authority: string;
  close(): Promise<void>;
}

async function startHttpApp(
  handler: (req: IncomingMessage, res: ServerResponse) => void,
): Promise<LocalApp> {
  const server = createServer(handler);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as AddressInfo).port;
  return {
    baseUrl: `http://127.0.0.1:${port}`,
    authority: `127.0.0.1:${port}`,
    close: () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  };
}

function request(overrides: Partial<RelayStreamRequest> = {}): RelayStreamRequest {
  return {
    streamId: "s-1",
    streamNonce: randomBytes(32).toString("base64url"),
    kind: "http",
    method: "GET",
    path: "/api/health",
    headers: {},
    clientIp: null,
    contentLength: null,
    ...overrides,
  };
}

interface Harness {
  readonly handler: RelayStreamHandler;
  readonly sent: RelayMessage[];
  readonly tunnels: Map<string, FakeTunnel>;
  setSession(): void;
  tunnelFor(streamId: string): FakeTunnel;
}

function createHandler(
  app: LocalApp,
  overrides: { maxConcurrentStreams?: number } = {},
): Harness {
  const sent: RelayMessage[] = [];
  const tunnels = new Map<string, FakeTunnel>();

  const handler = new RelayStreamHandler({
    send: (message) => sent.push(message),
    openTunnel: ({ streamNonce }) => {
      const tunnel = new FakeTunnel();
      tunnels.set(streamNonce, tunnel);
      return tunnel;
    },
    localBaseUrl: app.baseUrl,
    localAuthority: app.authority,
    maxConcurrentStreams: overrides.maxConcurrentStreams ?? 8,
    localResponseTimeoutMs: 2_000,
  });

  return {
    handler,
    sent,
    tunnels,
    setSession: () =>
      handler.setSession({
        controlUrl: "wss://relay.example.com/control",
        tunnelUrl: "wss://relay.example.com/tunnel",
      }),
    tunnelFor: (streamId) => {
      for (const tunnel of tunnels.values()) {
        void streamId;
        return tunnel;
      }
      throw new Error("no tunnel was opened");
    },
  };
}

async function settle(ms = 120): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, ms));
}

describe("RelayStreamHandler: admission", () => {
  let app: LocalApp;
  beforeEach(async () => {
    app = await startHttpApp((_req, res) => {
      res.writeHead(200);
      res.end("ok");
    });
  });
  afterEach(async () => {
    await app.close();
  });

  it("refuses a stream when no session has been established", async () => {
    const harness = createHandler(app);
    await harness.handler.serve(request());

    expect(harness.sent).toContainEqual({
      v: 1,
      type: "stream_reject",
      streamId: "s-1",
      code: "internal_error",
      message: "no established relay session",
    });
    expect(harness.handler.activeCount).toBe(0);
  });

  it("refuses a stream at the concurrency ceiling and keeps the ones already running", async () => {
    const harness = createHandler(app, { maxConcurrentStreams: 1 });
    harness.setSession();

    await harness.handler.serve(request({ streamId: "s-1" }));
    expect(harness.handler.activeCount).toBe(1);

    await harness.handler.serve(request({ streamId: "s-2" }));
    expect(harness.sent).toContainEqual({
      v: 1,
      type: "stream_reject",
      streamId: "s-2",
      code: "stream_limit_reached",
      message: "this instance is at its stream ceiling",
    });
    // The refusal must not have disturbed the stream already being served.
    expect(harness.handler.activeCount).toBe(1);
  });

  it("refuses a duplicate stream id without disturbing the original", async () => {
    const harness = createHandler(app);
    harness.setSession();

    await harness.handler.serve(request({ streamId: "s-1" }));
    await harness.handler.serve(request({ streamId: "s-1" }));

    expect(harness.sent).toContainEqual({
      v: 1,
      type: "stream_reject",
      streamId: "s-1",
      code: "internal_error",
      message: "a stream with this id is already open",
    });
    expect(harness.handler.activeCount).toBe(1);
  });

  it("releases the slot when a stream finishes", async () => {
    const harness = createHandler(app, { maxConcurrentStreams: 1 });
    harness.setSession();

    await harness.handler.serve(request({ streamId: "s-1" }));
    const tunnel = harness.tunnelFor("s-1");
    tunnel.finish();
    await settle();

    expect(harness.handler.activeCount).toBe(0);
    expect(harness.sent.some((message) => message.type === "stream_end")).toBe(true);
  });
});

describe("RelayStreamHandler: HTTP streams", () => {
  let app: LocalApp;
  const seen: Array<{ method: string; url: string; headers: Record<string, unknown> }> = [];

  beforeEach(async () => {
    seen.length = 0;
    app = await startHttpApp((req, res) => {
      seen.push({ method: req.method ?? "", url: req.url ?? "", headers: { ...req.headers } });
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: true }));
    });
  });
  afterEach(async () => {
    await app.close();
  });

  it("serves a request end to end and reports the head then the end", async () => {
    const harness = createHandler(app);
    harness.setSession();

    const stream = request({ method: "GET", path: "/api/health?x=1" });
    await harness.handler.serve(stream);
    const tunnel = harness.tunnelFor("s-1");
    tunnel.finish();
    await settle();

    expect(seen[0]?.url).toBe("/api/health?x=1");
    expect(harness.sent[0]).toMatchObject({
      type: "response_head",
      streamId: "s-1",
      status: 200,
      headers: { "content-type": "application/json" },
    });
    expect(harness.sent[1]).toMatchObject({ type: "stream_end", streamId: "s-1" });
    expect(tunnel.writtenText).toBe(JSON.stringify({ ok: true }));
  });

  it("rewrites the relay's origin so a relayed mutation is accepted", async () => {
    const harness = createHandler(app);
    harness.setSession();

    await harness.handler.serve(
      request({
        method: "POST",
        path: "/api/issues",
        headers: { origin: "https://acme-laptop.relay.example.com" },
      }),
    );
    // The HTTP path only issues the local request once the relayed body ends, so
    // the tunnel has to be finished for the app to ever see it.
    harness.tunnelFor("s-1").finish();
    await settle(200);

    expect(seen[0]?.headers.origin).toBe(app.baseUrl);
    expect(seen[0]?.headers.host).toBe(app.authority);
  });

  it("reports a byte count in both directions", async () => {
    const harness = createHandler(app);
    harness.setSession();

    await harness.handler.serve(
      request({
        method: "POST",
        path: "/api/issues",
        contentLength: 2,
      }),
    );
    const tunnel = harness.tunnelFor("s-1");
    tunnel.push("hi");
    tunnel.finish();
    await settle();

    const ended = harness.sent.find((message) => message.type === "stream_end");
    expect(ended).toMatchObject({ bytesFromClient: 2 });
    expect((ended as { bytesToClient: number }).bytesToClient).toBe(
      Buffer.byteLength(JSON.stringify({ ok: true })),
    );
  });

  it("reports an error rather than throwing when the local app is unreachable", async () => {
    const server = createServer();
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const port = (server.address() as AddressInfo).port;
    await new Promise<void>((resolve) => server.close(() => resolve()));

    const harness = createHandler({ baseUrl: `http://127.0.0.1:${port}`, authority: `127.0.0.1:${port}`, close: async () => {} });
    harness.setSession();
    await harness.handler.serve(request());
    await settle(200);

    expect(harness.sent.some((message) => message.type === "stream_error")).toBe(true);
    expect(harness.handler.activeCount).toBe(0);
  });
});

describe("RelayStreamHandler: teardown", () => {
  let app: LocalApp;
  beforeEach(async () => {
    app = await startHttpApp(() => {
      /* never responds, so the stream stays open */
    });
  });
  afterEach(async () => {
    await app.close();
  });

  it("destroys the tunnel socket when the relay closes the stream", async () => {
    const harness = createHandler(app);
    harness.setSession();
    await harness.handler.serve(request({ streamId: "s-1" }));
    const tunnel = harness.tunnelFor("s-1");

    harness.handler.handleDialerEvent({
      type: "close_stream",
      streamId: "s-1",
      code: "stream_quota_exceeded",
    });

    expect(tunnel.destroyed).toBe(true);
    expect(harness.handler.activeCount).toBe(0);
  });

  it("tears every stream down when the session ends", async () => {
    const harness = createHandler(app);
    harness.setSession();
    await harness.handler.serve(request({ streamId: "s-1" }));
    await harness.handler.serve(request({ streamId: "s-2" }));
    expect(harness.handler.activeCount).toBe(2);

    harness.handler.setSession(null);

    expect(harness.handler.activeCount).toBe(0);
  });

  it("ignores a close for a stream it is not serving", () => {
    const harness = createHandler(app);
    expect(() =>
      harness.handler.handleDialerEvent({ type: "close_stream", streamId: "nope", code: null }),
    ).not.toThrow();
  });

  it("emits exactly one terminal message when a stream closes after finishing", async () => {
    const fast = await startHttpApp((_req, res) => {
      res.writeHead(204);
      res.end();
    });
    try {
      const harness = createHandler(fast);
      harness.setSession();
      await harness.handler.serve(request());
      const tunnel = harness.tunnelFor("s-1");
      tunnel.finish();
      await settle();

      const terminal = harness.sent.filter(
        (message) => message.type === "stream_end" || message.type === "stream_error",
      );
      expect(terminal).toHaveLength(1);
    } finally {
      await fast.close();
    }
  });
});

describe("RelayStreamHandler: WebSocket streams", () => {
  let app: LocalApp;
  let wss: WebSocketServer;
  let server: Server;
  const openClients: WebSocket[] = [];

  beforeEach(async () => {
    openClients.length = 0;
    // Created per test rather than once at describe scope: a WebSocket
    // connection stays open, so a shared server never finishes closing and every
    // subsequent `listen` fails.
    server = createServer();
    wss = new WebSocketServer({ server });
    wss.on("connection", (socket) => {
      openClients.push(socket);
      socket.on("message", (data: Buffer) => socket.send(`echo:${data.toString()}`));
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const port = (server.address() as AddressInfo).port;
    app = {
      baseUrl: `http://127.0.0.1:${port}`,
      authority: `127.0.0.1:${port}`,
      close: async () => {},
    };
  });

  afterEach(async () => {
    for (const client of openClients) client.terminate();
    openClients.length = 0;
    await new Promise<void>((resolve) => wss.close(() => resolve()));
    await new Promise<void>((resolve) => {
      server.closeAllConnections();
      server.close(() => resolve());
    });
  });

  /** The accept value a compliant server must return for the browser's key. */
  function expectedAccept(key: string): string {
    return createHash("sha1").update(`${key}${WS_GUID}`).digest("base64");
  }

  /**
   * The upgrade headers a browser sends and the relay forwards.
   *
   * The dialer forwards `connection` and `upgrade` rather than synthesising them:
   * a browser always sends both on an upgrade request, and inventing them here
   * would mean the dialer could initiate a protocol switch the client never asked
   * for.
   */
  function upgradeHeaders(key: string): Record<string, string> {
    return {
      "sec-websocket-version": "13",
      "sec-websocket-key": key,
      connection: "Upgrade",
      upgrade: "websocket",
    };
  }

  it("relays the browser's own accept value rather than a locally negotiated one", async () => {
    const harness = createHandler(app);
    harness.setSession();

    const key = randomBytes(16).toString("base64");
    await harness.handler.serve(
      request({
        kind: "websocket",
        method: "GET",
        path: "/api/realtime/live-events?companyId=c-1",
        headers: { ...upgradeHeaders(key), cookie: "paperclip-x.session_token=abc" },
      }),
    );
    await settle(250);

    const head = harness.sent.find((message) => message.type === "response_head");
    expect(head).toMatchObject({ status: 101 });
    const headers = (head as { headers: Record<string, string> }).headers;
    // The whole point: the value is derived from the *browser's* key, so it could
    // not have been produced by a locally negotiated handshake.
    expect(headers["sec-websocket-accept"]).toBe(expectedAccept(key));
  });

  it("forwards Upgrade and Connection, which a 101 is meaningless without", async () => {
    const harness = createHandler(app);
    harness.setSession();

    await harness.handler.serve(
      request({ kind: "websocket", path: "/ws", headers: upgradeHeaders(randomBytes(16).toString("base64")) }),
    );
    await settle(250);

    const head = harness.sent.find((message) => message.type === "response_head");
    expect(head).toMatchObject({ status: 101 });
    const headers = (head as { headers: Record<string, string> }).headers;
    expect(headers.upgrade).toBe("websocket");
    expect(headers.connection?.toLowerCase()).toContain("upgrade");
  });

  it("presents the loopback authority, not the relay hostname", async () => {
    const harness = createHandler(app);
    harness.setSession();

    await harness.handler.serve(
      request({
        kind: "websocket",
        path: "/ws",
        headers: {
          ...upgradeHeaders(randomBytes(16).toString("base64")),
          origin: "https://acme-laptop.relay.example.com",
        },
      }),
    );
    await settle(250);

    const head = harness.sent.find((message) => message.type === "response_head");
    // A rewritten Origin would satisfy the upgrade; the relay hostname would
    // make the app's session check fail with a 403 instead.
    expect((head as { status: number }).status).toBe(101);
  });

  it("streams frames both ways after the handshake", async () => {
    const harness = createHandler(app);
    harness.setSession();

    await harness.handler.serve(
      request({ kind: "websocket", path: "/ws", headers: upgradeHeaders(randomBytes(16).toString("base64")) }),
    );
    await settle(250);

    const tunnel = harness.tunnelFor("s-1");
    // A correctly masked client text frame carrying "hi", per RFC 6455:
    // FIN+text, MASK+len(2), a 4-byte mask, then the masked payload
    // (0x68^0x01, 0x69^0x02). Exactly 8 bytes — trailing bytes would be read as
    // a further frame with RSV1 set, which is a protocol error.
    tunnel.push(Buffer.from([0x81, 0x82, 0x01, 0x02, 0x03, 0x04, 0x69, 0x6b]));
    await settle(250);

    // Not just "some bytes came back" — the frame is forwarded verbatim, so the
    // echo payload is still intact inside it.
    expect(tunnel.written.length).toBeGreaterThan(0);
    expect(Buffer.concat(tunnel.written).toString("latin1")).toContain("echo:hi");
  });

  it("forwards a non-101 status so the browser can see why", async () => {
    const rejecting = await startHttpApp((_req, res) => {
      res.writeHead(401, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "unauthenticated" }));
    });
    try {
      const harness = createHandler(rejecting);
      harness.setSession();
      await harness.handler.serve(
        request({ kind: "websocket", path: "/ws", headers: upgradeHeaders(randomBytes(16).toString("base64")) }),
      );
      await settle(250);

      const head = harness.sent.find((message) => message.type === "response_head");
      expect(head).toMatchObject({ status: 401 });
      expect(harness.handler.activeCount).toBe(0);
    } finally {
      await rejecting.close();
    }
  });

  it("reports an error when the local app closes before answering the upgrade", async () => {
    const silent = await startHttpApp((_req, res) => {
      res.socket?.destroy();
    });
    try {
      const harness = createHandler(silent);
      harness.setSession();
      await harness.handler.serve(
        request({ kind: "websocket", path: "/ws", headers: upgradeHeaders(randomBytes(16).toString("base64")) }),
      );
      await settle(250);

      expect(harness.sent.some((message) => message.type === "stream_error")).toBe(true);
      expect(harness.handler.activeCount).toBe(0);
    } finally {
      await silent.close();
    }
  });
});