import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { AddressInfo } from "node:net";
import { PassThrough, Readable } from "node:stream";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { RelayStreamRequest } from "../dialer/control-client.js";
import { serveRelayHttpStream } from "./local-request.js";

interface Recorded {
  readonly method: string;
  readonly url: string;
  readonly headers: Record<string, string | string[] | undefined>;
  readonly body: string;
}

interface Harness {
  readonly baseUrl: string;
  readonly authority: string;
  readonly seen: Recorded[];
  close(): Promise<void>;
}

/** A local app that records what it received and replies with fixed behaviour. */
async function startLocalApp(
  handler: (req: IncomingMessage, res: ServerResponse) => void,
): Promise<Harness> {
  const seen: Recorded[] = [];
  const server: Server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => {
      seen.push({
        method: req.method ?? "",
        url: req.url ?? "",
        headers: { ...req.headers },
        body: Buffer.concat(chunks).toString("utf8"),
      });
      handler(req, res);
    });
  });

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address() as AddressInfo;

  return {
    baseUrl: `http://127.0.0.1:${address.port}`,
    authority: `127.0.0.1:${address.port}`,
    seen,
    close: () =>
      new Promise<void>((resolve) => {
        // A test that leaves a request hanging would otherwise block close()
        // until its own timeout, turning one slow assertion into a suite-wide
        // stall.
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  };
}

interface RunResult {
  readonly status: number | null;
  readonly headers: Record<string, string> | null;
  readonly body: string;
  readonly counts: { bytesFromClient: number; bytesToClient: number } | null;
  readonly error: { code: string; message: string } | null;
}

function run(
  harness: Harness,
  request: Partial<RelayStreamRequest> & Pick<RelayStreamRequest, "method" | "path" | "headers">,
  requestBody = "",
  localResponseTimeoutMs?: number,
): Promise<RunResult> {
  return new Promise((resolve) => {
    const body = Readable.from([Buffer.from(requestBody, "utf8")]);
    const sink = new PassThrough();
    const chunks: Buffer[] = [];

    let status: number | null = null;
    let headers: Record<string, string> | null = null;
    let counts: { bytesFromClient: number; bytesToClient: number } | null = null;
    let error: { code: string; message: string } | null = null;
    let settled = false;

    sink.on("data", (chunk: Buffer) => chunks.push(chunk));
    sink.on("end", () => {
      if (settled) return;
      settled = true;
      resolve({
        status,
        headers,
        body: Buffer.concat(chunks).toString("utf8"),
        counts,
        error,
      });
    });

    serveRelayHttpStream({
      request: {
        streamId: "s-1",
        streamNonce: "A".repeat(43),
        kind: "http",
        clientIp: null,
        ...request,
      } as RelayStreamRequest,
      body,
      responseSink: sink,
      localBaseUrl: harness.baseUrl,
      localAuthority: harness.authority,
      ...(localResponseTimeoutMs === undefined ? {} : { localResponseTimeoutMs }),
      onHead: (headStatus, headHeaders) => {
        status = headStatus;
        headers = headHeaders;
      },
      onEnd: (endCounts) => {
        counts = endCounts;
      },
      onError: (code, message) => {
        error = { code, message };
        if (!settled) {
          settled = true;
          sink.end();
          resolve({ status, headers, body: Buffer.concat(chunks).toString("utf8"), counts, error });
        }
      },
    });
  });
}

describe("serveRelayHttpStream", () => {
  let harness: Harness;

  beforeEach(async () => {
    harness = await startLocalApp((_req, res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: true }));
    });
  });

  afterEach(async () => {
    await harness.close();
  });

  it("forwards method, path, and query", async () => {
    await run(harness, { method: "GET", path: "/api/issues?companyId=c-1", headers: {} });
    expect(harness.seen[0]?.method).toBe("GET");
    expect(harness.seen[0]?.url).toBe("/api/issues?companyId=c-1");
  });

  it("presents the loopback authority as Host, not the relay hostname", async () => {
    await run(harness, { method: "GET", path: "/", headers: {} });
    expect(harness.seen[0]?.headers.host).toBe(harness.authority);
  });

  it("rewrites Origin so a relayed mutation passes the CSRF guard", async () => {
    await run(harness, {
      method: "POST",
      path: "/api/issues",
      headers: { origin: "https://acme-laptop.relay.example.com" },
    });
    // The app must never see the relay's hostname, or board-mutation-guard
    // rejects every write and the relay looks broken for writes only.
    expect(harness.seen[0]?.headers.origin).toBe(harness.baseUrl);
  });

  it("sends no Origin when the client sent none", async () => {
    await run(harness, { method: "POST", path: "/api/issues", headers: {} });
    expect(harness.seen[0]?.headers.origin).toBeUndefined();
  });

  it("forwards the subscriber's cookie and authorization headers", async () => {
    await run(harness, {
      method: "GET",
      path: "/api/me",
      headers: {
        cookie: "paperclip-x.session_token=abc",
        authorization: "Bearer pcp_board_abc",
      },
    });
    expect(harness.seen[0]?.headers.cookie).toBe("paperclip-x.session_token=abc");
    expect(harness.seen[0]?.headers.authorization).toBe("Bearer pcp_board_abc");
  });

  it("streams the request body through", async () => {
    await run(
      harness,
      { method: "POST", path: "/api/issues", headers: { "content-type": "application/json" } },
      JSON.stringify({ title: "relayed" }),
    );
    expect(harness.seen[0]?.body).toBe(JSON.stringify({ title: "relayed" }));
  });

  it("reports the response head before the body", async () => {
    const result = await run(harness, { method: "GET", path: "/", headers: {} });
    expect(result.status).toBe(200);
    expect(result.headers?.["content-type"]).toBe("application/json");
    expect(JSON.parse(result.body)).toEqual({ ok: true });
  });

  it("counts bytes in both directions", async () => {
    const payload = JSON.stringify({ title: "relayed" });
    const result = await run(
      harness,
      { method: "POST", path: "/api/issues", headers: { "content-type": "application/json" } },
      payload,
    );
    expect(result.counts?.bytesFromClient).toBe(Buffer.byteLength(payload));
    expect(result.counts?.bytesToClient).toBe(Buffer.byteLength(JSON.stringify({ ok: true })));
  });

  it("sets x-forwarded-for from the relay-observed client address", async () => {
    await run(harness, { method: "GET", path: "/", headers: {}, clientIp: "203.0.113.7" });
    expect(harness.seen[0]?.headers["x-forwarded-for"]).toBe("203.0.113.7");
  });

  it("does not let a client forge its own address", async () => {
    await run(harness, {
      method: "GET",
      path: "/",
      headers: { "x-forwarded-for": "10.9.9.9" },
      clientIp: "203.0.113.7",
    });
    expect(harness.seen[0]?.headers["x-forwarded-for"]).toBe("203.0.113.7");
  });
});

describe("serveRelayHttpStream: framing", () => {
  it("strips transfer-encoding from the response, which would otherwise hang the browser", async () => {
    // Node has already de-chunked by the time headers are read, so forwarding
    // this would tell the browser to wait for chunk framing that no longer exists.
    const harness = await startLocalApp((_req, res) => {
      res.writeHead(200, { "content-type": "text/plain", "transfer-encoding": "chunked" });
      res.write("one");
      res.end("two");
    });
    try {
      const result = await run(harness, { method: "GET", path: "/", headers: {} });
      expect(result.headers).not.toHaveProperty("transfer-encoding");
      expect(result.body).toBe("onetwo");
    } finally {
      await harness.close();
    }
  });

  it("keeps content-length, because the byte count is still accurate", async () => {
    const harness = await startLocalApp((_req, res) => {
      res.writeHead(200, { "content-length": "5", "content-type": "text/plain" });
      res.end("hello");
    });
    try {
      const result = await run(harness, { method: "GET", path: "/", headers: {} });
      expect(result.headers?.["content-length"]).toBe("5");
      expect(result.body).toBe("hello");
    } finally {
      await harness.close();
    }
  });

  it("strips hop-by-hop response headers", async () => {
    const harness = await startLocalApp((_req, res) => {
      res.writeHead(200, { connection: "keep-alive", "x-keep": "yes" });
      res.end("ok");
    });
    try {
      const result = await run(harness, { method: "GET", path: "/", headers: {} });
      expect(result.headers).not.toHaveProperty("connection");
      expect(result.headers?.["x-keep"]).toBe("yes");
    } finally {
      await harness.close();
    }
  });

  it("joins a repeated response header rather than dropping it", async () => {
    const harness = await startLocalApp((_req, res) => {
      res.setHeader("set-cookie", ["a=1; Path=/", "b=2; Path=/"]);
      res.writeHead(200);
      res.end("ok");
    });
    try {
      const result = await run(harness, { method: "GET", path: "/", headers: {} });
      // Folding to "a=1, b=2" is wrong for Set-Cookie, but the relay re-frames the
      // response anyway; the point is the header is not silently lost.
      expect(result.headers?.["set-cookie"]).toContain("a=1");
      expect(result.headers?.["set-cookie"]).toContain("b=2");
    } finally {
      await harness.close();
    }
  });

  it("relays a non-2xx status without treating it as a failure", async () => {
    const harness = await startLocalApp((_req, res) => {
      res.writeHead(409, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "conflict" }));
    });
    try {
      const result = await run(harness, { method: "POST", path: "/api/issues", headers: {} });
      expect(result.status).toBe(409);
      expect(result.error).toBeNull();
      expect(JSON.parse(result.body)).toEqual({ error: "conflict" });
    } finally {
      await harness.close();
    }
  });
});

describe("serveRelayHttpStream: failure", () => {
  it("reports a connection failure when the local app is not listening", async () => {
    const server = createServer();
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const port = (server.address() as AddressInfo).port;
    await new Promise<void>((resolve) => server.close(() => resolve()));

    const result = await run(
      { baseUrl: `http://127.0.0.1:${port}`, authority: `127.0.0.1:${port}`, seen: [], close: async () => {} },
      { method: "GET", path: "/", headers: {} },
    );
    expect(result.error).not.toBeNull();
    expect(result.error?.code).toBe("internal_error");
  });

  it("gives up when the local app never sends response headers", async () => {
    const harness = await startLocalApp(() => {
      // Deliberately never respond.
    });
    try {
      const result = await run(harness, { method: "GET", path: "/", headers: {} }, "", 150);
      // A head-of-line stall would otherwise hold the stream, the tunnel socket,
      // and a concurrency slot indefinitely.
      expect(result.error?.code).toBe("internal_error");
      expect(result.error?.message).toContain("150ms");
      expect(result.status).toBeNull();
    } finally {
      await harness.close();
    }
  });

  it("settles exactly once when a response arrives after the deadline", async () => {
    const harness = await startLocalApp((_req, res) => {
      // Responds well after the deadline has fired. Without a settled guard the
      // late head would be reported a second time for the same stream, and a
      // caller that trusted "the first callback wins" would emit two events.
      setTimeout(() => {
        res.writeHead(200);
        res.end("late");
      }, 250);
    });
    try {
      let calls = 0;
      const body = Readable.from([Buffer.alloc(0)]);
      const sink = new PassThrough();
      sink.resume();

      serveRelayHttpStream({
        request: {
          streamId: "s-1",
          streamNonce: "A".repeat(43),
          kind: "http",
          clientIp: null,
          method: "GET",
          path: "/",
          headers: {},
        } as RelayStreamRequest,
        body,
        responseSink: sink,
        localBaseUrl: harness.baseUrl,
        localAuthority: harness.authority,
        localResponseTimeoutMs: 40,
        onHead: () => {
          calls += 1;
        },
        onEnd: () => {
          calls += 1;
        },
        onError: () => {
          calls += 1;
        },
      });

      await vi.waitFor(() => expect(calls).toBeGreaterThanOrEqual(1));
      await new Promise((resolve) => setTimeout(resolve, 400));
      expect(calls).toBe(1);
    } finally {
      await harness.close();
    }
  });
});