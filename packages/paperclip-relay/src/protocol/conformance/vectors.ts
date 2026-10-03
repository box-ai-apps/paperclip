/**
 * Canonical conformance vectors for the relay control protocol.
 *
 * WHY THIS FILE EXISTS. The client half lives in the Paperclip repository and
 * the relay server lives in a separate `paperclip-relay-server` repository, each
 * with its own release cadence. Nothing structurally prevents the two decoders
 * from drifting apart, and a drifted decoder is worse than no decoder: it turns
 * a schema change into a field one side reads as required and the other ignores.
 *
 * So this file is the tie-breaker. It is canonical here, and the relay-server
 * repository vendors a byte-identical copy and runs the same assertions over it.
 * A change to the wire format that does not update these vectors fails CI in
 * whichever repository forgot.
 *
 * This module is deliberately **self-contained**: no imports, no helpers, no
 * constructors from the encoder. Everything is written out literally so that
 * vendoring it into another repository is a file copy and a re-export, and so
 * that no bug in the encoder can quietly author its own passing test.
 */
import type { RelayErrorCode } from "../error-codes.js";
import type { RelayMessage } from "../messages.js";

export interface RelayDecodeVector {
  readonly name: string;
  /** Exact frame body the peer puts on the wire, including the trailing newline. */
  readonly body: string;
  /** Set when the frame must be rejected; `expectMessage` must be absent. */
  readonly expectCode?: RelayErrorCode;
  /** Set when the frame must be accepted; the decode result must equal it. */
  readonly expectMessage?: RelayMessage;
}

/** The protocol version these vectors were authored against. */
export const CONFORMANCE_PROTOCOL_VERSION = 1;

/** 32 bytes of base64url used as a stream nonce in the vectors. */
const NONCE = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

export const RELAY_DECODE_VECTORS: readonly RelayDecodeVector[] = [
  // --- accepted: client half -> relay -------------------------------------
  {
    name: "hello with every field populated",
    body: `{"v":1,"type":"hello","supportedProtocolVersions":[1],"instanceSlug":"acme-laptop","paperclipVersion":"0.3.1","capabilities":["http","websocket"]}\n`,
    expectMessage: {
      v: 1,
      type: "hello",
      supportedProtocolVersions: [1],
      instanceSlug: "acme-laptop",
      paperclipVersion: "0.3.1",
      capabilities: ["http", "websocket"],
    },
  },
  {
    name: "hello with a null paperclip version",
    body: `{"v":1,"type":"hello","supportedProtocolVersions":[1],"instanceSlug":"box-1","paperclipVersion":null,"capabilities":[]}\n`,
    expectMessage: {
      v: 1,
      type: "hello",
      supportedProtocolVersions: [1],
      instanceSlug: "box-1",
      paperclipVersion: null,
      capabilities: [],
    },
  },
  {
    name: "hello advertising several supported versions",
    body: `{"v":1,"type":"hello","supportedProtocolVersions":[1,2],"instanceSlug":"box-1","paperclipVersion":null,"capabilities":["http"]}\n`,
    expectMessage: {
      v: 1,
      type: "hello",
      supportedProtocolVersions: [1, 2],
      instanceSlug: "box-1",
      paperclipVersion: null,
      capabilities: ["http"],
    },
  },
  {
    name: "heartbeat",
    body: `{"v":1,"type":"heartbeat","seq":0}\n`,
    expectMessage: { v: 1, type: "heartbeat", seq: 0 },
  },
  {
    name: "response head with no headers",
    body: `{"v":1,"type":"response_head","streamId":"s-1","status":204,"headers":{}}\n`,
    expectMessage: { v: 1, type: "response_head", streamId: "s-1", status: 204, headers: {} },
  },
  {
    name: "response head carrying set-cookie",
    body: `{"v":1,"type":"response_head","streamId":"s-1","status":200,"headers":{"content-type":"application/json","set-cookie":"paperclip-x.session_token=abc; Path=/; HttpOnly"}}\n`,
    expectMessage: {
      v: 1,
      type: "response_head",
      streamId: "s-1",
      status: 200,
      headers: {
        "content-type": "application/json",
        "set-cookie": "paperclip-x.session_token=abc; Path=/; HttpOnly",
      },
    },
  },
  {
    name: "websocket 101 response keeps upgrade and connection",
    // The denylist exists so a peer cannot dictate request framing. Responses are
    // the instance half speaking about its own app, and a WebSocket handshake is
    // incomplete without these two. Pinning it here stops either repository from
    // "simplifying" the asymmetry away and breaking every relayed live-events and
    // terminal socket.
    body: `{"v":1,"type":"response_head","streamId":"s-1","status":101,"headers":{"connection":"Upgrade","upgrade":"websocket","sec-websocket-accept":"s3pPLMBiTxaQ9kYGzzhZRbK+xOo="}}\n`,
    expectMessage: {
      v: 1,
      type: "response_head",
      streamId: "s-1",
      status: 101,
      headers: {
        connection: "Upgrade",
        upgrade: "websocket",
        "sec-websocket-accept": "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=",
      },
    },
  },
  {
    name: "response head with a transfer-encoding header",
    body: `{"v":1,"type":"response_head","streamId":"s-1","status":200,"headers":{"transfer-encoding":"chunked"}}\n`,
    expectMessage: {
      v: 1,
      type: "response_head",
      streamId: "s-1",
      status: 200,
      headers: { "transfer-encoding": "chunked" },
    },
  },
  {
    name: "response header value carrying CRLF",
    body: `{"v":1,"type":"response_head","streamId":"s-1","status":200,"headers":{"x-note":"a\\r\\nX-Injected: yes"}}\n`,
    expectCode: "invalid_header_value",
  },
  {
    name: "stream end with byte accounting",
    body: `{"v":1,"type":"stream_end","streamId":"s-1","bytesFromClient":1024,"bytesToClient":4096}\n`,
    expectMessage: {
      v: 1,
      type: "stream_end",
      streamId: "s-1",
      bytesFromClient: 1024,
      bytesToClient: 4096,
    },
  },
  {
    name: "stream reject for an exhausted local stream ceiling",
    body: `{"v":1,"type":"stream_reject","streamId":"s-1","code":"stream_limit_reached","message":"stream refused"}\n`,
    expectMessage: {
      v: 1,
      type: "stream_reject",
      streamId: "s-1",
      code: "stream_limit_reached",
      message: "stream refused",
    },
  },
  {
    name: "stream error",
    body: `{"v":1,"type":"stream_error","streamId":"s-1","code":"internal_error","message":"upstream reset"}\n`,
    expectMessage: {
      v: 1,
      type: "stream_error",
      streamId: "s-1",
      code: "internal_error",
      message: "upstream reset",
    },
  },

  // --- accepted: relay -> client half -------------------------------------
  {
    name: "hello ok",
    body: `{"v":1,"type":"hello_ok","protocolVersion":1,"sessionId":"sess-1","heartbeatIntervalMs":15000,"maxConcurrentStreams":8,"capabilities":["http","websocket"],"tunnelUrl":"wss://relay.example.com/tunnel"}\n`,
    expectMessage: {
      v: 1,
      type: "hello_ok",
      protocolVersion: 1,
      sessionId: "sess-1",
      heartbeatIntervalMs: 15000,
      maxConcurrentStreams: 8,
      capabilities: ["http", "websocket"],
      tunnelUrl: "wss://relay.example.com/tunnel",
    },
  },
  {
    name: "hello reject for an inactive subscription",
    body: `{"v":1,"type":"hello_reject","code":"instance_not_entitled","message":"subscription is not active"}\n`,
    expectMessage: {
      v: 1,
      type: "hello_reject",
      code: "instance_not_entitled",
      message: "subscription is not active",
    },
  },
  {
    name: "open stream for a websocket carrying the subscriber's own session",
    body: `{"v":1,"type":"open_stream","streamId":"s-1","streamNonce":"${NONCE}","kind":"websocket","method":"GET","path":"/api/realtime/live-events?companyId=c-1","headers":{"authorization":"Bearer pcp_board_x","cookie":"paperclip-x.session_token=abc","sec-websocket-version":"13"},"clientIp":"203.0.113.7","contentLength":null}\n`,
    expectMessage: {
      v: 1,
      type: "open_stream",
      streamId: "s-1",
      streamNonce: NONCE,
      kind: "websocket",
      method: "GET",
      path: "/api/realtime/live-events?companyId=c-1",
      headers: {
        authorization: "Bearer pcp_board_x",
        cookie: "paperclip-x.session_token=abc",
        "sec-websocket-version": "13",
      },
clientIp: "203.0.113.7",
      contentLength: null,
    },
  },
  {
    name: "open stream for a POST body",
    body: `{"v":1,"type":"open_stream","streamId":"s-2","streamNonce":"${NONCE}","kind":"http","method":"POST","path":"/api/issues","headers":{"content-type":"application/json"},"clientIp":null,"contentLength":null}\n`,
    expectMessage: {
      v: 1,
      type: "open_stream",
      streamId: "s-2",
      streamNonce: NONCE,
      kind: "http",
      method: "POST",
      path: "/api/issues",
      headers: { "content-type": "application/json" },
      clientIp: null,
      contentLength: null,
    },
  },
  {
    name: "open stream naming an actor is refused as an unknown field",
    // The relay must not be able to say who a stream acts as. If this ever
    // decodes, the no-escalation property of the design has been lost.
    body: `{"v":1,"type":"open_stream","streamId":"s-3","streamNonce":"${NONCE}","kind":"http","method":"GET","path":"/","headers":{},"clientIp":null,"actorUserId":"usr_01H","contentLength":null}\n`,
    expectCode: "unknown_field",
  },
  {
    name: "open stream carrying an IPv6 client address",
    body: `{"v":1,"type":"open_stream","streamId":"s-4","streamNonce":"${NONCE}","kind":"http","method":"GET","path":"/","headers":{},"clientIp":"2001:db8::1","contentLength":null}\n`,
    expectMessage: {
      v: 1,
      type: "open_stream",
      streamId: "s-4",
      streamNonce: NONCE,
      kind: "http",
      method: "GET",
      path: "/",
      headers: {},
      clientIp: "2001:db8::1",
      contentLength: null,
    },
  },
  {
    name: "client address that is not an IP literal",
    body: `{"v":1,"type":"open_stream","streamId":"s-5","streamNonce":"${NONCE}","kind":"http","method":"GET","path":"/","headers":{},"clientIp":"not-an-ip","contentLength":null}\n`,
    expectCode: "invalid_field",
  },
  {
    name: "client address carrying a port",
    // A host:port pair would need splitting before it could go into
    // x-forwarded-for, and guessing at the split is how an address gets forged.
    body: `{"v":1,"type":"open_stream","streamId":"s-5","streamNonce":"${NONCE}","kind":"http","method":"GET","path":"/","headers":{},"clientIp":"203.0.113.7:443","contentLength":null}\n`,
    expectCode: "invalid_field",
  },
  {
    name: "client address as an IPv4-mapped IPv6 literal",
    // Valid, and forwarded as-is. Normalising it to the IPv4 form here would mean
    // re-parsing an address the platform already parsed, and the mapped form is
    // what a dual-stack listener actually observes.
    body: `{"v":1,"type":"open_stream","streamId":"s-5","streamNonce":"${NONCE}","kind":"http","method":"GET","path":"/","headers":{},"clientIp":"::ffff:203.0.113.7","contentLength":null}\n`,
    expectMessage: {
      v: 1,
      type: "open_stream",
      streamId: "s-5",
      streamNonce: NONCE,
      kind: "http",
      method: "GET",
      path: "/",
      headers: {},
      clientIp: "::ffff:203.0.113.7",
      contentLength: null,
    },
  },
  {
    name: "client address of the wrong type",
    body: `{"v":1,"type":"open_stream","streamId":"s-5","streamNonce":"${NONCE}","kind":"http","method":"GET","path":"/","headers":{},"clientIp":12345,"contentLength":null}\n`,
    expectCode: "invalid_field",
  },
  {
    name: "open stream with a declared body length",
    body: `{"v":1,"type":"open_stream","streamId":"s-6","streamNonce":"${NONCE}","kind":"http","method":"POST","path":"/api/issues","headers":{"content-type":"application/json"},"clientIp":"203.0.113.7","contentLength":4096}\n`,
    expectMessage: {
      v: 1,
      type: "open_stream",
      streamId: "s-6",
      streamNonce: NONCE,
      kind: "http",
      method: "POST",
      path: "/api/issues",
      headers: { "content-type": "application/json" },
      clientIp: "203.0.113.7",
      contentLength: 4096,
    },
  },
  {
    name: "open stream with a zero body length",
    body: `{"v":1,"type":"open_stream","streamId":"s-7","streamNonce":"${NONCE}","kind":"http","method":"POST","path":"/api/issues","headers":{},"clientIp":null,"contentLength":0}\n`,
    expectMessage: {
      v: 1,
      type: "open_stream",
      streamId: "s-7",
      streamNonce: NONCE,
      kind: "http",
      method: "POST",
      path: "/api/issues",
      headers: {},
      clientIp: null,
      contentLength: 0,
    },
  },
  {
    name: "negative body length",
    body: `{"v":1,"type":"open_stream","streamId":"s-8","streamNonce":"${NONCE}","kind":"http","method":"POST","path":"/api/issues","headers":{},"clientIp":null,"contentLength":-1}\n`,
    expectCode: "invalid_field",
  },
  {
    name: "body length of the wrong type",
    body: `{"v":1,"type":"open_stream","streamId":"s-8","streamNonce":"${NONCE}","kind":"http","method":"POST","path":"/api/issues","headers":{},"clientIp":null,"contentLength":"4096"}\n`,
    expectCode: "invalid_field",
  },
  {
    name: "body length above the size cap",
    // The length decides how many bytes the instance half will read, so an
    // unvalidated value would be a way to make it wait on a body that never comes.
    body: `{"v":1,"type":"open_stream","streamId":"s-8","streamNonce":"${NONCE}","kind":"http","method":"POST","path":"/api/issues","headers":{},"clientIp":null,"contentLength":999999999999}\n`,
    expectCode: "invalid_field",
  },
  {
    name: "hello ok with a tunnel URL on another scheme",
    body: `{"v":1,"type":"hello_ok","protocolVersion":1,"sessionId":"sess-1","heartbeatIntervalMs":15000,"maxConcurrentStreams":8,"capabilities":["http"],"tunnelUrl":"https://relay.example.com/tunnel"}\n`,
    expectCode: "invalid_field",
  },
  {
    name: "hello ok with a tunnel URL carrying credentials",
    body: `{"v":1,"type":"hello_ok","protocolVersion":1,"sessionId":"sess-1","heartbeatIntervalMs":15000,"maxConcurrentStreams":8,"capabilities":["http"],"tunnelUrl":"wss://user:pass@relay.example.com/tunnel"}\n`,
    expectCode: "invalid_field",
  },
  {
    name: "hello ok without a tunnel URL",
    body: `{"v":1,"type":"hello_ok","protocolVersion":1,"sessionId":"sess-1","heartbeatIntervalMs":15000,"maxConcurrentStreams":8,"capabilities":["http"]}\n`,
    expectCode: "invalid_field",
  },
  {
    name: "close stream with no code",
    body: `{"v":1,"type":"close_stream","streamId":"s-1","code":null}\n`,
    expectMessage: { v: 1, type: "close_stream", streamId: "s-1", code: null },
  },
  {
    name: "close stream carrying a code",
    body: `{"v":1,"type":"close_stream","streamId":"s-1","code":"stream_limit_reached"}\n`,
    expectMessage: { v: 1, type: "close_stream", streamId: "s-1", code: "stream_limit_reached" },
  },
  {
    name: "error prose carrying non-ASCII text",
    body: `{"v":1,"type":"stream_reject","streamId":"s-1","code":"stream_limit_reached","message":"stream refused for Renée"}\n`,
    expectMessage: {
      v: 1,
      type: "stream_reject",
      streamId: "s-1",
      code: "stream_limit_reached",
      message: "stream refused for Renée",
    },
  },

  // --- rejected: framing --------------------------------------------------
  {
    name: "empty frame",
    body: `\n`,
    expectCode: "malformed_frame",
  },
  {
    name: "frame that is not JSON",
    body: `not json\n`,
    expectCode: "malformed_json",
  },
  {
    name: "frame with a JSON array",
    body: `[]\n`,
    expectCode: "malformed_message",
  },
  {
    name: "frame with trailing content after the value",
    body: `{"v":1,"type":"heartbeat","seq":0} {"v":1}\n`,
    expectCode: "malformed_json",
  },
  {
    name: "frame with a duplicate top-level key",
    body: `{"v":1,"v":1,"type":"heartbeat","seq":0}\n`,
    expectCode: "duplicate_key",
  },
  {
    name: "frame with a duplicate nested key",
    body: `{"v":1,"type":"response_head","streamId":"s-1","status":200,"headers":{},"headers":{"host":"evil"}}\n`,
    expectCode: "duplicate_key",
  },
  {
    name: "frame declaring an unimplemented version",
    body: `{"v":2,"type":"heartbeat","seq":0}\n`,
    expectCode: "unsupported_protocol_version",
  },
  {
    name: "frame with a non-integer version",
    body: `{"v":"1","type":"heartbeat","seq":0}\n`,
    expectCode: "unsupported_protocol_version",
  },

  // --- rejected: shape ----------------------------------------------------
  {
    name: "unrecognised message type",
    body: `{"v":1,"type":"exfiltrate"}\n`,
    expectCode: "unknown_message_type",
  },
  {
    name: "unknown field on a known type",
    body: `{"v":1,"type":"heartbeat","seq":0,"extra":true}\n`,
    expectCode: "unknown_field",
  },
  {
    name: "missing required field",
    body: `{"v":1,"type":"heartbeat"}\n`,
    expectCode: "invalid_field",
  },
  {
    name: "integer field sent as a string",
    body: `{"v":1,"type":"heartbeat","seq":"0"}\n`,
    expectCode: "invalid_field",
  },
  {
    name: "negative byte count",
    body: `{"v":1,"type":"stream_end","streamId":"s-1","bytesFromClient":-1,"bytesToClient":0}\n`,
    expectCode: "invalid_field",
  },
  {
    name: "out-of-range HTTP status",
    body: `{"v":1,"type":"response_head","streamId":"s-1","status":999,"headers":{}}\n`,
    expectCode: "invalid_field",
  },
  {
  name: "error code outside the shared vocabulary",
    body: `{"v":1,"type":"stream_reject","streamId":"s-1","code":"totally_made_up","message":"x"}\n`,
    expectCode: "invalid_field",
  },
  {
    name: "error prose forging a second log line",
    body: `{"v":1,"type":"stream_reject","streamId":"s-1","code":"internal_error","message":"failed\\nstream opened"}\n`,
    expectCode: "invalid_field",
  },
  {
    name: "error prose carrying an ANSI escape",
    body: `{"v":1,"type":"stream_reject","streamId":"s-1","code":"internal_error","message":"\\u001b[31mred"}\n`,
    expectCode: "invalid_field",
  },

  // --- rejected: smuggling surface ----------------------------------------
  {
    name: "relayed host header",
    body: `{"v":1,"type":"open_stream","streamId":"s-1","streamNonce":"${NONCE}","kind":"http","method":"GET","path":"/","headers":{"host":"evil.example.com"},"clientIp":null,"contentLength":null}\n`,
    expectCode: "forbidden_header",
  },
  {
    name: "relayed content-length header",
    body: `{"v":1,"type":"open_stream","streamId":"s-1","streamNonce":"${NONCE}","kind":"http","method":"POST","path":"/api/issues","headers":{"content-length":"4"},"clientIp":null,"contentLength":null}\n`,
    expectCode: "forbidden_header",
  },
  {
    name: "relayed transfer-encoding header",
    body: `{"v":1,"type":"open_stream","streamId":"s-1","streamNonce":"${NONCE}","kind":"http","method":"POST","path":"/api/issues","headers":{"transfer-encoding":"chunked"},"clientIp":null,"contentLength":null}\n`,
    expectCode: "forbidden_header",
  },
  {
    name: "relayed x-forwarded-for header",
    body: `{"v":1,"type":"open_stream","streamId":"s-1","streamNonce":"${NONCE}","kind":"http","method":"GET","path":"/","headers":{"x-forwarded-for":"10.0.0.1"},"clientIp":null,"contentLength":null}\n`,
    expectCode: "forbidden_header",
  },
  {
    name: "relayed upgrade header",
    body: `{"v":1,"type":"open_stream","streamId":"s-1","streamNonce":"${NONCE}","kind":"websocket","method":"GET","path":"/ws","headers":{"upgrade":"websocket"},"clientIp":null,"contentLength":null}\n`,
    expectCode: "forbidden_header",
  },
  {
    name: "header value carrying CRLF",
    body: `{"v":1,"type":"open_stream","streamId":"s-1","streamNonce":"${NONCE}","kind":"http","method":"GET","path":"/","headers":{"x-note":"a\\r\\nX-Injected: yes"},"clientIp":null,"contentLength":null}\n`,
    expectCode: "invalid_header_value",
  },
  {
    name: "header value carrying a bare NUL",
    body: `{"v":1,"type":"open_stream","streamId":"s-1","streamNonce":"${NONCE}","kind":"http","method":"GET","path":"/","headers":{"x-note":"a\\u0000b"},"clientIp":null,"contentLength":null}\n`,
    expectCode: "invalid_header_value",
  },
  {
    name: "uppercase header name",
    body: `{"v":1,"type":"open_stream","streamId":"s-1","streamNonce":"${NONCE}","kind":"http","method":"GET","path":"/","headers":{"X-Note":"a"},"clientIp":null,"contentLength":null}\n`,
    expectCode: "invalid_header_name",
  },
  {
    name: "header map sent as an array",
    body: `{"v":1,"type":"open_stream","streamId":"s-1","streamNonce":"${NONCE}","kind":"http","method":"GET","path":"/","headers":[["a","b"]],"clientIp":null,"contentLength":null}\n`,
    expectCode: "invalid_field",
  },
  {
    name: "path that is not origin-form",
    body: `{"v":1,"type":"open_stream","streamId":"s-1","streamNonce":"${NONCE}","kind":"http","method":"GET","path":"api/issues","headers":{},"clientIp":null,"contentLength":null}\n`,
    expectCode: "invalid_path",
  },
  {
    name: "path beginning with double slash",
    body: `{"v":1,"type":"open_stream","streamId":"s-1","streamNonce":"${NONCE}","kind":"http","method":"GET","path":"//evil.example.com/x","headers":{},"clientIp":null,"contentLength":null}\n`,
    expectCode: "invalid_path",
  },
  {
    name: "path carrying a control character",
    body: `{"v":1,"type":"open_stream","streamId":"s-1","streamNonce":"${NONCE}","kind":"http","method":"GET","path":"/a\\u0007b","headers":{},"clientIp":null,"contentLength":null}\n`,
    expectCode: "invalid_path",
  },
  {
    name: "unsupported HTTP method",
    body: `{"v":1,"type":"open_stream","streamId":"s-1","streamNonce":"${NONCE}","kind":"http","method":"TRACE","path":"/","headers":{},"clientIp":null,"contentLength":null}\n`,
    expectCode: "invalid_method",
  },
  {
    name: "lowercase HTTP method",
    body: `{"v":1,"type":"open_stream","streamId":"s-1","streamNonce":"${NONCE}","kind":"http","method":"get","path":"/","headers":{},"clientIp":null,"contentLength":null}\n`,
    expectCode: "invalid_method",
  },

  // --- rejected: stream identity -----------------------------------------
  {
    name: "stream nonce of the wrong length",
    body: `{"v":1,"type":"open_stream","streamId":"s-1","streamNonce":"AAAA","kind":"http","method":"get","path":"/","headers":{},"clientIp":null,"contentLength":null}\n`,
    expectCode: "invalid_field",
  },
  {
    name: "stream nonce that is not base64url",
    body: `{"v":1,"type":"open_stream","streamId":"s-1","streamNonce":"${"A".repeat(42)}+","kind":"http","method":"get","path":"/","headers":{},"clientIp":null,"contentLength":null}\n`,
    expectCode: "invalid_field",
  },
  {
    name: "instance slug with uppercase characters",
    body: `{"v":1,"type":"hello","supportedProtocolVersions":[1],"instanceSlug":"Acme-Laptop","paperclipVersion":null,"capabilities":[]}\n`,
    expectCode: "invalid_field",
  },
  {
    name: "instance slug with an underscore",
    body: `{"v":1,"type":"hello","supportedProtocolVersions":[1],"instanceSlug":"acme_laptop","paperclipVersion":null,"capabilities":[]}\n`,
    expectCode: "invalid_field",
  },
  {
    name: "instance slug of a single character",
    body: `{"v":1,"type":"hello","supportedProtocolVersions":[1],"instanceSlug":"a","paperclipVersion":null,"capabilities":[]}\n`,
    expectCode: "invalid_field",
  },
  {
    name: "instance slug with a leading hyphen",
    body: `{"v":1,"type":"hello","supportedProtocolVersions":[1],"instanceSlug":"-acme","paperclipVersion":null,"capabilities":[]}\n`,
    expectCode: "invalid_field",
  },
  {
    name: "instance slug with a trailing hyphen",
    body: `{"v":1,"type":"hello","supportedProtocolVersions":[1],"instanceSlug":"acme-","paperclipVersion":null,"capabilities":[]}\n`,
    expectCode: "invalid_field",
  },
  {
    name: "instance slug of 41 characters",
    body: `{"v":1,"type":"hello","supportedProtocolVersions":[1],"instanceSlug":"${"a".repeat(41)}","paperclipVersion":null,"capabilities":[]}\n`,
    expectCode: "invalid_field",
  },
  {
    name: "empty supported version list",
    body: `{"v":1,"type":"hello","supportedProtocolVersions":[],"instanceSlug":"box-1","paperclipVersion":null,"capabilities":[]}\n`,
    expectCode: "unsupported_protocol_version",
  },
  {
    name: "duplicate capability",
    body: `{"v":1,"type":"hello","supportedProtocolVersions":[1],"instanceSlug":"box-1","paperclipVersion":null,"capabilities":["http","http"]}\n`,
    expectCode: "invalid_field",
  },
  {
    name: "non-semver paperclip version",
    body: `{"v":1,"type":"hello","supportedProtocolVersions":[1],"instanceSlug":"box-1","paperclipVersion":"nightly","capabilities":[]}\n`,
    expectCode: "invalid_field",
  },
];