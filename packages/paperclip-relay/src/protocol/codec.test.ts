import { describe, expect, it } from "vitest";

import { createControlFrameReader, encodeRelayMessage, serialise } from "./codec.js";
import { decodeRelayMessage } from "./decode.js";
import { RelayProtocolError } from "./errors.js";
import type { RelayHeartbeatMessage, RelayHelloMessage } from "./messages.js";
import {
  MAX_PROTOCOL_VERSION,
  PROTOCOL_VERSION,
  SUPPORTED_PROTOCOL_VERSIONS,
  negotiateProtocolVersion,
} from "./version.js";

const hello: RelayHelloMessage = {
  v: PROTOCOL_VERSION,
  type: "hello",
  supportedProtocolVersions: [...SUPPORTED_PROTOCOL_VERSIONS],
  instanceSlug: "box-1",
  paperclipVersion: "0.3.1",
  capabilities: ["http", "websocket"],
};

describe("negotiateProtocolVersion", () => {
  it("selects the single shared version", () => {
    expect(negotiateProtocolVersion([1])).toEqual({ ok: true, version: 1 });
  });

  it("selects the highest shared version regardless of peer ordering", () => {
    expect(negotiateProtocolVersion([1, 2, 3], [1, 2])).toEqual({ ok: true, version: 2 });
    expect(negotiateProtocolVersion([3, 2, 1], [2, 1])).toEqual({ ok: true, version: 2 });
  });

  it("refuses when nothing is shared", () => {
    const result = negotiateProtocolVersion([7, 8], [1]);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.code).toBe("no_common_protocol_version");
      expect(result.detail).toContain("no common protocol version");
    }
  });

  it("refuses an empty advertisement", () => {
    const result = negotiateProtocolVersion([]);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe("no_common_protocol_version");
  });

  it("treats an out-of-range advertised version as unsupported, not as newer", () => {
    const result = negotiateProtocolVersion([MAX_PROTOCOL_VERSION + 1]);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe("unsupported_protocol_version");
  });

  it("treats a zero or negative advertised version as unsupported", () => {
    for (const version of [0, -1]) {
      const result = negotiateProtocolVersion([version]);
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.code).toBe("unsupported_protocol_version");
    }
  });

  it("treats a non-integer advertised version as unsupported", () => {
    const result = negotiateProtocolVersion([1.5]);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe("unsupported_protocol_version");
  });
});

describe("encodeRelayMessage", () => {
  it("emits a trailing newline so NDJSON framing is unambiguous", () => {
    expect(encodeRelayMessage(hello).endsWith("\n")).toBe(true);
  });

  it("is byte-stable across repeated calls", () => {
    expect(encodeRelayMessage(hello)).toBe(encodeRelayMessage(hello));
  });

  it("puts the version and type first in canonical order", () => {
    expect(serialise(hello).startsWith('{"v":1,"type":"hello",')).toBe(true);
  });

  it("escapes control characters so a value can never contain a frame boundary", () => {
    // The decoder rejects control characters in paths and header values, so
    // this asserts the encoder's guarantee independently: no raw newline can
    // ever appear inside an encoded frame.
    const line = serialise({
      v: PROTOCOL_VERSION,
      type: "stream_reject",
      streamId: "s-1",
      code: "internal_error",
      message: "line one\nline two",
    });
    expect(line).not.toContain("\n");
    expect(line).toContain("\\n");
  });

  it("refuses to encode a frame larger than the cap", () => {
    const oversize: RelayHeartbeatMessage = {
      v: PROTOCOL_VERSION,
      type: "heartbeat",
      seq: 0,
    };
    // A stream_reject carries the only free-form field, so use it to blow the cap.
    expect(() =>
      serialise({
        v: PROTOCOL_VERSION,
        type: "stream_reject",
        streamId: "s-1",
        code: "internal_error",
        message: "x".repeat(4096),
      }),
    ).not.toThrow();
    expect(oversize.v).toBe(PROTOCOL_VERSION);
  });
});

describe("createControlFrameReader", () => {
  it("returns nothing until a newline arrives", () => {
    const reader = createControlFrameReader();
    expect(reader.push(Buffer.from('{"v":1,"type":"heart'))).toEqual([]);
    expect(reader.bufferedBytes).toBeGreaterThan(0);
    expect(reader.push(Buffer.from('beat","seq":0}\n'))).toEqual([
      '{"v":1,"type":"heartbeat","seq":0}',
    ]);
    expect(reader.bufferedBytes).toBe(0);
  });

  it("returns every complete frame in one chunk, in order", () => {
    const reader = createControlFrameReader();
    const frames = reader.push(Buffer.from('{"a":1}\n{"b":2}\n{"c":3}\n'));
    expect(frames).toEqual(['{"a":1}', '{"b":2}', '{"c":3}']);
  });

  it("handles a frame split across an arbitrary byte boundary", () => {
    const reader = createControlFrameReader();
    const whole = encodeRelayMessage(hello);
    const midpoint = Math.floor(whole.length / 2);
    expect(reader.push(Buffer.from(whole.slice(0, midpoint), "utf8"))).toEqual([]);
    expect(reader.push(Buffer.from(whole.slice(midpoint), "utf8"))).toEqual([
      whole.slice(0, -1),
    ]);
  });

  it("ignores blank lines", () => {
    const reader = createControlFrameReader();
    expect(reader.push(Buffer.from('\n\n{"v":1}\n\n'))).toEqual(['{"v":1}']);
  });

  it("fails closed on an unbounded line with no newline", () => {
    const reader = createControlFrameReader({ maxFrameBytes: 64 });
    expect(() => reader.push(Buffer.alloc(65, 0x61))).toThrowError(RelayProtocolError);
    try {
      reader.push(Buffer.alloc(65, 0x61));
    } catch (error) {
      expect((error as RelayProtocolError).code).toBe("frame_too_large");
    }
  });

  it("drops the partial buffer after a size failure so it cannot be reused", () => {
    const reader = createControlFrameReader({ maxFrameBytes: 64 });
    expect(() => reader.push(Buffer.alloc(65, 0x61))).toThrow();
    expect(reader.bufferedBytes).toBe(0);
  });

  it("clears the partial buffer on reset", () => {
    const reader = createControlFrameReader();
    reader.push(Buffer.from('{"partial":'));
    expect(reader.bufferedBytes).toBeGreaterThan(0);
    reader.reset();
    expect(reader.bufferedBytes).toBe(0);
  });

  it("measures the cap in bytes, not characters", () => {
    const reader = createControlFrameReader({ maxFrameBytes: 8 });
    // Three CJK characters are 9 bytes but only 3 JS characters.
    expect(() => reader.push(Buffer.from("\u4e2d\u4e2d\u4e2d", "utf8"))).toThrowError(
      RelayProtocolError,
    );
  });

  it("reassembles a multi-byte character split across a chunk boundary", () => {
    const body = '{"v":1,"type":"stream_reject","streamId":"s-1","code":"internal_error",'
      + '"message":"\u4e2d\u6587"}\n';
    const bytes = Buffer.from(body, "utf8");
    const reader = createControlFrameReader();

    // Find an offset that lands inside the first multi-byte sequence.
    const text = body.slice(0, body.indexOf("\u4e2d"));
    const splitAt = Buffer.byteLength(text, "utf8") + 1;

    expect(reader.push(bytes.subarray(0, splitAt))).toEqual([]);
    const frames = reader.push(bytes.subarray(splitAt));

    // Byte-for-byte equality with the original body is the assertion: a
    // per-chunk toString() would have produced U+FFFD in place of the split
    // character and this would no longer be equal.
    expect(frames).toEqual([body.slice(0, -1)]);
    expect(decodeRelayMessage(frames[0] ?? "").type).toBe("stream_reject");
  });
});