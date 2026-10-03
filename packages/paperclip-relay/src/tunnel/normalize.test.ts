import { describe, expect, it } from "vitest";

import {
  AUTHORITY_HEADERS,
  HOP_BY_HOP_HEADERS,
  normalizeRelayedRequestHeaders,
  RelayNormalizeError,
} from "./normalize.js";

const OPTIONS = {
  localAuthority: "127.0.0.1:3100",
  localOrigin: "http://127.0.0.1:3100",
};

function normalize(
  relayed: Record<string, string>,
  clientIp?: string | null,
): Record<string, string> {
  return normalizeRelayedRequestHeaders(relayed, { ...OPTIONS, clientIp: clientIp ?? null }).headers;
}

describe("normalizeRelayedRequestHeaders: origin rewriting", () => {
  it("rewrites Origin so the CSRF guard sees the request's own origin", () => {
    const headers = normalize({
      origin: "https://acme-laptop.relay.example.com",
      cookie: "paperclip-x.session_token=abc",
    });
    expect(headers.origin).toBe("http://127.0.0.1:3100");
    expect(headers.cookie).toBe("paperclip-x.session_token=abc");
  });

  it("never leaves the relay's hostname in an authority header", () => {
    const headers = normalize({
      origin: "https://acme-laptop.relay.example.com",
      referer: "https://acme-laptop.relay.example.com/board/issues?x=1",
      host: "acme-laptop.relay.example.com",
      "x-forwarded-host": "acme-laptop.relay.example.com",
      "x-forwarded-proto": "https",
      "x-forwarded-for": "10.9.9.9",
    });
    const serialised = JSON.stringify(headers);
    expect(serialised).not.toContain("relay.example.com");
    expect(serialised).not.toContain("10.9.9.9");
  });

  it("does not invent an Origin when the client sent none", () => {
    // This is the rule that protects board mutations. A cross-site form post
    // arrives here without an Origin; adding one would wave it through the CSRF
    // guard that exists to stop exactly that.
    const headers = normalize({ "user-agent": "curl/8" });
    expect(headers).not.toHaveProperty("origin");
    expect(headers).not.toHaveProperty("referer");
  });

  it("does not invent a Referer when only an Origin was sent", () => {
    const headers = normalize({ origin: "https://acme.relay.example.com" });
    expect(headers.origin).toBe("http://127.0.0.1:3100");
    expect(headers).not.toHaveProperty("referer");
  });

  it("keeps the Referer path so a Referer cannot be widened", () => {
    const headers = normalize({
      referer: "https://acme.relay.example.com/board/issues/42?tab=activity#frag",
    });
    expect(headers.referer).toBe("http://127.0.0.1:3100/board/issues/42?tab=activity");
  });

  it("leaves a relative Referer alone rather than fabricating a document address", () => {
    const headers = normalize({ referer: "/board/issues" });
    expect(headers.referer).toBe("/board/issues");
  });

  it("reduces an unparseable absolute Referer to the bare origin", () => {
    const headers = normalize({ referer: "https://[malformed" });
    expect(headers.referer).toBe("http://127.0.0.1:3100");
  });

  it("matches header names case-insensitively on the way in", () => {
    const headers = normalize({ Origin: "https://acme.relay.example.com" });
    expect(headers.origin).toBe("http://127.0.0.1:3100");
    expect(headers).not.toHaveProperty("Origin");
  });

  it("emits every header name in lowercase", () => {
    const headers = normalize({
      "Content-Type": "application/json",
      "User-Agent": "Mozilla/5.0",
      Authorization: "Bearer pcp_board_x",
    });
    expect(Object.keys(headers).sort()).toEqual(["authorization", "content-type", "user-agent"]);
  });
});

describe("normalizeRelayedRequestHeaders: hop-by-hop headers", () => {
  it("drops every hop-by-hop header so a client cannot describe its own connection", () => {
    for (const name of HOP_BY_HOP_HEADERS) {
      const headers = normalize({ [name]: "anything" });
      expect(headers, `${name} must not be forwarded`).not.toHaveProperty(name);
    }
  });

  it("drops transfer-encoding, which would let a client disagree about message boundaries", () => {
    // This is the request-smuggling primitive: the relay framing the body one way
    // and the app another.
    const headers = normalize({ "transfer-encoding": "chunked", "content-type": "application/json" });
    expect(headers).not.toHaveProperty("transfer-encoding");
    expect(headers["content-type"]).toBe("application/json");
  });

  it("drops connection and upgrade, so a relayed request cannot force a protocol switch", () => {
    const headers = normalize({ connection: "Upgrade", upgrade: "websocket" });
    expect(headers).toEqual({});
  });

  it("keeps the sec-websocket-* headers a WebSocket handshake needs", () => {
    // These are end-to-end header fields, not hop-by-hop ones: they describe the
    // handshake the app will perform, not the relay-to-app connection.
    const headers = normalize({
      "sec-websocket-version": "13",
      "sec-websocket-key": "dGhlIHNhbXBsZSBub25jZQ==",
    });
    expect(headers["sec-websocket-version"]).toBe("13");
    expect(headers["sec-websocket-key"]).toBe("dGhlIHNhbXBsZSBub25jZQ==");
  });
});

describe("normalizeRelayedRequestHeaders: subscriber credentials", () => {
  it("passes the cookie and authorization headers through untouched", () => {
    const headers = normalize({
      cookie: "paperclip-x.session_token=abc; other=1",
      authorization: "Bearer pcp_board_abc",
    });
    expect(headers.cookie).toBe("paperclip-x.session_token=abc; other=1");
    expect(headers.authorization).toBe("Bearer pcp_board_abc");
  });
});

describe("normalizeRelayedRequestHeaders: client address", () => {
  it("sets x-forwarded-for from the relay-observed address", () => {
    expect(normalize({}, "203.0.113.7")["x-forwarded-for"]).toBe("203.0.113.7");
  });

  it("accepts an IPv6 address as-is", () => {
    expect(normalize({}, "2001:db8::1")["x-forwarded-for"]).toBe("2001:db8::1");
  });

  it("sets nothing when the relay could not determine the address", () => {
    // Reporting loopback here would be a lie: it would put 127.0.0.1 in the audit
    // trail for a request that came from somewhere else entirely.
    const headers = normalize({}, null);
    expect(headers).not.toHaveProperty("x-forwarded-for");
  });

  it("sets nothing when no address was supplied at all", () => {
    const headers = normalizeRelayedRequestHeaders({}, OPTIONS).headers;
    expect(headers).not.toHaveProperty("x-forwarded-for");
  });
});

describe("normalizeRelayedRequestHeaders: configuration", () => {
  it("refuses an origin whose host is not the authority", () => {
    // A wiring mistake that would otherwise present as "reads work, writes all
    // fail with a confusing CSRF error".
    expect(() =>
      normalizeRelayedRequestHeaders(
        {},
        { localAuthority: "127.0.0.1:3100", localOrigin: "https://acme.relay.example.com" },
      ),
    ).toThrow(RelayNormalizeError);
  });

  it("refuses an unparseable origin", () => {
    expect(() =>
      normalizeRelayedRequestHeaders(
        {},
        { localAuthority: "127.0.0.1:3100", localOrigin: "not-a-url" },
      ),
    ).toThrow(RelayNormalizeError);
  });

  it("refuses an origin carrying a path", () => {
    expect(() =>
      normalizeRelayedRequestHeaders(
        {},
        { localAuthority: "127.0.0.1:3100", localOrigin: "http://127.0.0.1:3100/board" },
      ),
    ).toThrow(/no path/);
  });

  it("works with a loopback host that includes a port", () => {
    const headers = normalizeRelayedRequestHeaders(
      { origin: "https://acme.relay.example.com" },
      { localAuthority: "localhost:3100", localOrigin: "http://localhost:3100" },
    ).headers;
    expect(headers.origin).toBe("http://localhost:3100");
  });
});

describe("normalizeRelayedRequestHeaders: degenerate input", () => {
  it("returns an empty map for an empty request", () => {
    expect(normalize({})).toEqual({});
  });

  it("preserves an empty header value rather than dropping it", () => {
    expect(normalize({ "x-note": "" })).toEqual({ "x-note": "" });
  });

  it("does not mutate the relayed headers it was given", () => {
    const relayed = { Origin: "https://acme.relay.example.com", Host: "acme.relay.example.com" };
    const snapshot = { ...relayed };
    normalizeRelayedRequestHeaders(relayed, OPTIONS);
    expect(relayed).toEqual(snapshot);
  });
});

describe("the authority header denylist covers what it must", () => {
  it("includes the headers a client could use to forge its identity", () => {
    for (const name of [
      "host",
      "origin",
      "referer",
      "x-forwarded-for",
      "x-forwarded-host",
      "x-forwarded-proto",
      "x-forwarded-port",
      "x-real-ip",
    ]) {
      expect(AUTHORITY_HEADERS.has(name), `${name} must be re-derived, not forwarded`).toBe(true);
    }
  });
});