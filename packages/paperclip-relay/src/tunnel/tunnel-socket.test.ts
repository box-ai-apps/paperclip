import { describe, expect, it } from "vitest";

import { isRelayErrorCode } from "../protocol/error-codes.js";
import { RelayProtocolError } from "../protocol/errors.js";
import {
  isRelayTunnelError,
  openTunnelSocket,
  type RelayTunnelSocket,
  RelayTunnelError,
} from "./tunnel-socket.js";

const CONTROL_URL = "wss://relay.example.com/control";

function fakeSocket(): { socket: RelayTunnelSocket; opened: string[] } {
  const opened: string[] = [];
  const socket: RelayTunnelSocket = {
    inbound: (async function* () {
      yield Buffer.alloc(0);
    })(),
    write: () => {},
    end: () => {},
    destroy: () => {},
    closed: Promise.resolve({ code: 1000, reason: null }),
  };
  return { socket, opened };
}

describe("openTunnelSocket", () => {
  it("carries the stream nonce as a query parameter", () => {
    const { socket, opened } = fakeSocket();
    openTunnelSocket({
      tunnelUrl: "wss://relay.example.com/tunnel",
      controlUrl: CONTROL_URL,
      streamNonce: "abc",
      createSocket: (url) => {
        opened.push(url);
        return socket;
      },
    });
    expect(new URL(opened[0] ?? "").searchParams.get("t")).toBe("abc");
  });

  it("preserves the relay's configured path", () => {
    const { socket, opened } = fakeSocket();
    openTunnelSocket({
      tunnelUrl: "wss://relay.example.com/edge/tunnel",
      controlUrl: CONTROL_URL,
      streamNonce: "abc",
      createSocket: (url) => {
        opened.push(url);
        return socket;
      },
    });
    expect(new URL(opened[0] ?? "").pathname).toBe("/edge/tunnel");
  });

  it("keeps routing parameters the relay configured", () => {
    const { socket, opened } = fakeSocket();
    openTunnelSocket({
      tunnelUrl: "wss://relay.example.com/tunnel?region=eu",
      controlUrl: CONTROL_URL,
      streamNonce: "abc",
      createSocket: (url) => {
        opened.push(url);
        return socket;
      },
    });
    const parsed = new URL(opened[0] ?? "");
    expect(parsed.searchParams.get("region")).toBe("eu");
    expect(parsed.searchParams.get("t")).toBe("abc");
  });

  it("does not leak a credential into the URL", () => {
    const { socket, opened } = fakeSocket();
    openTunnelSocket({
      tunnelUrl: "wss://relay.example.com/tunnel",
      controlUrl: CONTROL_URL,
      streamNonce: "super-secret-nonce",
      createSocket: (url) => {
        opened.push(url);
        return socket;
      },
    });
    // The nonce is single-use and worthless without the control socket, but it
    // still must not be the instance credential.
    expect(opened[0]).not.toContain("pcp_relay_");
  });
});

describe("openTunnelSocket: origin enforcement", () => {
  const cases: Array<{ label: string; tunnelUrl: string }> = [
    { label: "a different host", tunnelUrl: "wss://evil.example.net/tunnel" },
    { label: "a different scheme", tunnelUrl: "ws://relay.example.com/tunnel" },
    { label: "a different port", tunnelUrl: "wss://relay.example.com:8443/tunnel" },
    { label: "a host that merely ends with ours", tunnelUrl: "wss://relay.example.com.evil.net/tunnel" },
    { label: "a subdomain of ours", tunnelUrl: "wss://sub.relay.example.com/tunnel" },
  ];

  for (const { label, tunnelUrl } of cases) {
    it(`refuses ${label}`, () => {
      const { socket, opened } = fakeSocket();
      expect(() =>
        openTunnelSocket({
          tunnelUrl,
          controlUrl: CONTROL_URL,
          streamNonce: "abc",
          createSocket: (url) => {
            opened.push(url);
            return socket;
          },
        }),
      ).toThrow(RelayTunnelError);
      expect(opened).toHaveLength(0);
    });
  }

  it("accepts the same host on the same scheme and port", () => {
    const { socket, opened } = fakeSocket();
    expect(() =>
      openTunnelSocket({
        tunnelUrl: "wss://relay.example.com/anything",
        controlUrl: CONTROL_URL,
        streamNonce: "abc",
        createSocket: (url) => {
          opened.push(url);
          return socket;
        },
      }),
    ).not.toThrow();
  });

  it("throws rather than returning a socket that never delivers", () => {
    const { socket, opened } = fakeSocket();
    try {
      openTunnelSocket({
        tunnelUrl: "wss://evil.example.net/tunnel",
        controlUrl: CONTROL_URL,
        streamNonce: "abc",
        createSocket: (url) => {
          opened.push(url);
          return socket;
        },
      });
      throw new Error("expected a refusal");
    } catch (error) {
      expect(isRelayTunnelError(error)).toBe(true);
      expect((error as RelayTunnelError).code).toBe("internal_error");
    }
  });
});

describe("isRelayTunnelError", () => {
  it("recognises its own errors", () => {
    expect(isRelayTunnelError(new RelayTunnelError("internal_error", "x"))).toBe(true);
  });

  it("recognises protocol errors, which surface from the same call site", () => {
    expect(isRelayTunnelError(new RelayProtocolError("malformed_frame", "x"))).toBe(true);
  });

  it("does not claim unrelated errors", () => {
    expect(isRelayTunnelError(new Error("socket hang up"))).toBe(false);
    expect(isRelayTunnelError("nope")).toBe(false);
  });
});

describe("the tunnel error code is in the shared vocabulary", () => {
  it("so the relay can branch on it", () => {
    expect(isRelayErrorCode("internal_error")).toBe(true);
  });
});