/**
 * The stable error vocabulary shared by the client half and the relay server.
 *
 * Two rules make this list a contract rather than decoration:
 *
 * 1. Codes are part of the wire format. A code is never removed or repurposed;
 *    new conditions get new codes. Either side may switch on them.
 * 2. Codes are safe to log and to hand back to an untrusted peer. They name a
 *    condition, never a path, a header value, a hostname, a SQL fragment, or a
 *    command line. Human-facing prose travels in the separate `message` field
 *    and is never used for control flow.
 */

/** Every code the relay protocol can produce. */
export const RELAY_ERROR_CODES = [
  // --- framing and decode -------------------------------------------------
  /** Frame body exceeded the byte cap; the reader must destroy the stream. */
  "frame_too_large",
  /** Length prefix, UTF-8, or trailing-content violation. */
  "malformed_frame",
  /** Body was not valid JSON. */
  "malformed_json",
  /** Object contained the same key twice; see the strict JSON parser. */
  "duplicate_key",
  /** Message declared a version this build does not implement. */
  "unsupported_protocol_version",
  /** Structurally valid JSON that is not a valid protocol message. */
  "malformed_message",
  /** `type` is not a member of the message union. */
  "unknown_message_type",
  /** A required field was absent, of the wrong type, or failed its shape check. */
  "invalid_field",
  /** Unknown fields are a hard error, not a forward-compatibility allowance. */
  "unknown_field",
  /** HTTP method token was not a supported uppercase method. */
  "invalid_method",
  /** Request target was not a safe origin-form path. */
  "invalid_path",
  /** Header name was not a lowercase RFC 7230 token. */
  "invalid_header_name",
  /** Header value contained a control character or was otherwise untransmittable. */
  "invalid_header_value",
  /** Header is one the stream server owns and must never accept from a peer. */
  "forbidden_header",

  // --- negotiation and session -------------------------------------------
  /** Neither side speaks a version the other accepts. */
  "no_common_protocol_version",
  /**
   * The control-channel credential was absent, malformed, unrecognised, or has
   * no usable row in the instance.
   *
   * The only identity-adjacent code in the vocabulary. There is deliberately no
   * "unknown actor" and no actor field on `open_stream`: the relay never names a
   * human, and the subscriber's own Paperclip session authenticates the request
   * inside the instance. A relay that could assert an identity would be a relay
   * an operator could use to escalate.
   */
  "unauthorized_control",
  /** The credential resolved to a locally revoked relay credential. */
  "credential_revoked",
  /** Subscription is not active, or an entitlement limit is already reached. */
  "instance_not_entitled",
  /** Another live control session already owns this instance slug. */
  "instance_slug_conflict",

  // --- stream lifecycle ---------------------------------------------------
  /** The instance is already serving its configured concurrent-stream ceiling. */
  "stream_limit_reached",
  /** The instance's monthly byte allowance is exhausted. */
  "stream_quota_exceeded",
  /** The client half refused this stream. */
  "stream_rejected_by_dialer",
  /** A stream message referenced an id this side is not serving. */
  "unknown_stream",

  // --- client-half preconditions -----------------------------------------
  /**
   * The instance is in `local_trusted` deployment mode.
   *
   * `local_trusted` grants unauthenticated instance-admin to anything that can
   * reach the socket, so publishing such an instance through a relay would hand
   * a full agent shell to every stranger who learns the hostname. The dialer
   * refuses to start rather than publish.
   */
  "deployment_mode_unsupported",
  /** Relay environment is absent, so there is nothing to publish. */
  "relay_not_configured",

  // --- transport ----------------------------------------------------------
  /** Unexpected failure. Never carries internal detail. */
  "internal_error",
] as const;

export type RelayErrorCode = (typeof RELAY_ERROR_CODES)[number];

/** Narrowing guard for values arriving off the wire. */
export function isRelayErrorCode(value: unknown): value is RelayErrorCode {
  return typeof value === "string" && (RELAY_ERROR_CODES as readonly string[]).includes(value);
}

/** Shape of any control-channel failure message. */
export interface RelayErrorDetail {
  readonly code: RelayErrorCode;
  /** Human-facing prose. May be logged; never used for control flow. */
  readonly message: string;
}