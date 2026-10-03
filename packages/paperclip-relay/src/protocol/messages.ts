/**
 * The relay control-channel message union.
 *
 * The control channel is newline-delimited JSON. It carries *decisions and
 * framing* — registration, version selection, stream lifecycle, response heads.
 * Request and response **bodies** deliberately do not travel here: they move as
 * raw bytes over a dedicated tunnel socket, so the control channel never has to
 * frame a body, chunk it, or reassemble one. That split is the main reason the
 * protocol has no multiplexer and no partial-message state machine.
 *
 * Every message carries `v`, the negotiated protocol version, and is rejected
 * outright when it names a version this build does not implement. Unknown
 * fields are a hard error rather than a forward-compatibility allowance,
 * because a silently ignored field is indistinguishable from one the peer
 * believed was honoured.
 */
import type { RelayErrorCode } from "./error-codes.js";

/** What kind of client connection a stream carries. */
export type RelayStreamKind = "http" | "websocket";

export type RelayMessageType =
  | "hello"
  | "hello_ok"
  | "hello_reject"
  | "heartbeat"
  | "open_stream"
  | "stream_reject"
  | "close_stream"
  | "response_head"
  | "stream_end"
  | "stream_error";

interface MessageBase {
  /** Negotiated protocol version. */
  readonly v: number;
  readonly type: RelayMessageType;
}

/** Client half -> relay. First message on a control socket. */
export interface RelayHelloMessage extends MessageBase {
  readonly type: "hello";
  readonly supportedProtocolVersions: number[];
  readonly instanceSlug: string;
  readonly paperclipVersion: string | null;
  /** Capability tokens; see `RELAY_CAPABILITIES`. */
  readonly capabilities: string[];
}

/** Relay -> client half. Version selected and session established. */
export interface RelayHelloOkMessage extends MessageBase {
  readonly type: "hello_ok";
  readonly protocolVersion: number;
  readonly sessionId: string;
  readonly heartbeatIntervalMs: number;
  readonly maxConcurrentStreams: number;
  readonly capabilities: string[];
}

/** Relay -> client half. Session refused; the socket closes after this. */
export interface RelayHelloRejectMessage extends MessageBase {
  readonly type: "hello_reject";
  readonly code: RelayErrorCode;
  readonly message: string;
}

/** Both directions. Liveness probe. */
export interface RelayHeartbeatMessage extends MessageBase {
  readonly type: "heartbeat";
  readonly seq: number;
}

/**
 * Relay -> client half. Serve one browser connection.
 *
 * `streamNonce` is the relay's proof that it authorised this stream. The client
 * half opens `ws(s)://<relay>/tunnel?t=<nonce>` and the relay pairs that socket
 * with the waiting browser connection, so an attacker who guesses a `streamId`
 * cannot join the stream without also being the party that minted the nonce.
 */
export interface RelayOpenStreamMessage extends MessageBase {
  readonly type: "open_stream";
  readonly streamId: string;
  readonly streamNonce: string;
  readonly kind: RelayStreamKind;
  readonly method: string;
  readonly path: string;
  readonly headers: Record<string, string>;
  /** Local Paperclip user this stream acts as. Must map to an issued credential. */
  readonly actorUserId: string;
}

/** Client half -> relay. This stream will not be served. */
export interface RelayStreamRejectMessage extends MessageBase {
  readonly type: "stream_reject";
  readonly streamId: string;
  readonly code: RelayErrorCode;
  readonly message: string;
}

/** Relay -> client half. Tear the stream down; no more bytes will flow. */
export interface RelayCloseStreamMessage extends MessageBase {
  readonly type: "close_stream";
  readonly streamId: string;
  readonly code: RelayErrorCode | null;
}

/**
 * Client half -> relay. Upstream response head.
 *
 * Sent once, before the body starts flowing over the tunnel socket. The relay
 * synthesises the downstream response line and headers from this, which is why
 * the header rules in `validate.ts` apply symmetrically to both directions.
 */
export interface RelayResponseHeadMessage extends MessageBase {
  readonly type: "response_head";
  readonly streamId: string;
  readonly status: number;
  readonly headers: Record<string, string>;
}

/** Client half -> relay. Stream finished cleanly. */
export interface RelayStreamEndMessage extends MessageBase {
  readonly type: "stream_end";
  readonly streamId: string;
  /** Bytes the client half read from the relayed client (request side). */
  readonly bytesFromClient: number;
  /** Bytes the client half wrote back toward the relayed client (response side). */
  readonly bytesToClient: number;
}

/** Client half -> relay. Stream aborted. */
export interface RelayStreamErrorMessage extends MessageBase {
  readonly type: "stream_error";
  readonly streamId: string;
  readonly code: RelayErrorCode;
  readonly message: string;
}

export type RelayMessage =
  | RelayHelloMessage
  | RelayHelloOkMessage
  | RelayHelloRejectMessage
  | RelayHeartbeatMessage
  | RelayOpenStreamMessage
  | RelayStreamRejectMessage
  | RelayCloseStreamMessage
  | RelayResponseHeadMessage
  | RelayStreamEndMessage
  | RelayStreamErrorMessage;

/**
 * Capability tokens the client half advertises in `hello`.
 *
 * `http` and `websocket` name stream kinds. A relay that is asked for a kind it
 * was not told about must refuse the stream rather than attempt it, so this list
 * is the negotiation surface for adding a kind later.
 */
export const RELAY_CAPABILITIES: readonly string[] = ["http", "websocket"];

/** Messages the client half accepts from the relay. */
export type InboundRelayMessage =
  | RelayHelloOkMessage
  | RelayHelloRejectMessage
  | RelayHeartbeatMessage
  | RelayOpenStreamMessage
  | RelayCloseStreamMessage;

/** Messages the client half sends to the relay. */
export type OutboundRelayMessage =
  | RelayHelloMessage
  | RelayHeartbeatMessage
  | RelayStreamRejectMessage
  | RelayResponseHeadMessage
  | RelayStreamEndMessage
  | RelayStreamErrorMessage;