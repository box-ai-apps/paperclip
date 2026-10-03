import type { RelayErrorCode } from "./error-codes.js";

/**
 * A decode or validation failure carrying a stable, machine-readable code.
 *
 * The `message` is prose for a human reading a log line or a CLI. It is never
 * used for control flow, and it never contains a header value, a path, a
 * hostname, or anything else derived from peer input — the code is the whole
 * contract, and the message is best-effort context.
 */
export class RelayProtocolError extends Error {
  constructor(
    readonly code: RelayErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "RelayProtocolError";
  }

  /** Narrowing guard so callers can re-throw foreign errors unchanged. */
  static is(value: unknown): value is RelayProtocolError {
    return value instanceof RelayProtocolError;
  }
}