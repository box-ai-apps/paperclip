/**
 * Opening one tunnel socket per stream.
 *
 * The relay holds a browser connection and a dialer control socket, and the two
 * only meet through this socket. The relay mints a 256-bit nonce per stream and
 * names it in `open_stream`; the dialer opens a socket carrying that nonce as a
 * query parameter, and the relay pairs the two sides.
 *
 * Putting the nonce in the query string is a deliberate exception to the rule
 * elsewhere in this package that secrets do not travel in URLs. It is not a
 * long-lived credential: it is single-use, expires within seconds, and is useless
 * without the control socket that already proved the dialer's identity. A
 * `Sec-WebSocket-Protocol` header would avoid the URL but is semantically wrong —
 * it is a subprotocol negotiation, and some intermediaries rewrite them.
 *
 * ## One socket per stream, and why there is no multiplexer
 *
 * Each stream is its own socket with its own TLS handshake and its own
 * backpressure. That sounds wasteful next to multiplexing many streams over one
 * connection, and it is — but multiplexing means implementing flow control, half
 * close, and reset semantics correctly, and getting any of them wrong corrupts a
 * live request rather than failing cleanly. Agent-control traffic is low
 * concurrency: a handful of tabs, one live-events socket, maybe one terminal. One
 * socket per stream makes every failure isolated and every stream testable on its
 * own. If that ever stops being true, the tunnel URL is the seam to change.
 */
import { RelayProtocolError } from "../protocol/errors.js";
import { isSameOriginTunnelUrl } from "../protocol/validate.js";

/**
 * The duplex a tunnel socket provides.
 *
 * Bytes written here go toward the browser; bytes read here came from it. No
 * framing: the relay owns HTTP framing on the browser side, and the dialer owns it
 * on the local-app side.
 */
export interface RelayTunnelSocket {
  /** Bytes arriving from the browser, i.e. the request body. */
  readonly inbound: AsyncIterable<Buffer>;
  /** Bytes to send toward the browser, i.e. the response body. */
  write(chunk: Buffer): void;
  /** Signal that no more response bytes will be written. */
  end(): void;
  /** Tear the socket down immediately. */
  destroy(reason?: string): void;
  /** Resolves when the socket closes, with the reason if it failed. */
  readonly closed: Promise<{ code: number | null; reason: string | null }>;
}

export interface OpenTunnelSocketInput {
  /** Base tunnel URL from `hello_ok`, without a query string. */
  readonly tunnelUrl: string;
  /** The control URL this dialer connected to. Enforced same-origin. */
  readonly controlUrl: string;
  /** Single-use nonce naming this stream. */
  readonly streamNonce: string;
  /** The nonce is the stream's only credential; never log it. */
  readonly createSocket: (url: string) => RelayTunnelSocket;
  /** Injected for tests. */
  readonly now?: () => number;
}

export class RelayTunnelError extends Error {
  constructor(
    readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "RelayTunnelError";
  }
}

/**
 * Open the tunnel socket for one stream.
 *
 * Throws rather than returning a half-open socket: the caller has already been
 * told a stream is wanted, and a failure here has to surface as a rejection for
 * that stream, not as a socket that quietly never delivers.
 */
export function openTunnelSocket(input: OpenTunnelSocketInput): RelayTunnelSocket {
  if (!isSameOriginTunnelUrl(input.controlUrl, input.tunnelUrl)) {
    throw new RelayTunnelError(
      "internal_error",
      "the relay asked for tunnel sockets on a different origin than the control socket; refusing",
    );
  }

  let url: URL;
  try {
    url = new URL(input.tunnelUrl);
  } catch {
    throw new RelayTunnelError("internal_error", "the relay sent an unusable tunnel URL");
  }

  // Preserve any path and any query the relay configured for routing, and add the
  // nonce as a parameter rather than replacing the query outright.
  url.searchParams.set("t", input.streamNonce);

  return input.createSocket(url.toString());
}

/** Narrowing guard used by the stream handler's error branch. */
export function isRelayTunnelError(value: unknown): value is RelayTunnelError {
  return value instanceof RelayTunnelError || RelayProtocolError.is(value);
}