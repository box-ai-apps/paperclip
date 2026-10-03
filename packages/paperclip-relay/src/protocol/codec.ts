/**
 * Canonical encoder and newline-delimited framing for the control channel.
 *
 * Encoding is deterministic: field order is fixed by the declared field set, so
 * the same message always produces the same bytes. That is what lets
 * `conformance/vectors.json` assert exact output rather than "some equivalent
 * JSON", which is the whole point of pinning vectors across two independently
 * released repositories.
 *
 * Framing is one JSON value per line. No length prefix is needed because JSON
 * values here cannot contain a raw newline — the strict encoder escapes control
 * characters — so a newline is an unambiguous frame boundary.
 */
import { StringDecoder } from "node:string_decoder";

import { RelayProtocolError } from "./errors.js";
import type { RelayMessage, RelayMessageType } from "./messages.js";
import { MAX_CONTROL_FRAME_BYTES } from "./validate.js";

/** Serialise a message to a single line, including its trailing newline. */
export function encodeRelayMessage(message: RelayMessage): string {
  const line = `${serialise(message)}\n`;
  const bytes = Buffer.byteLength(line, "utf8");
  if (bytes > MAX_CONTROL_FRAME_BYTES) {
    throw new RelayProtocolError("frame_too_large", "encoded control frame exceeds the byte cap");
  }
  return line;
}

/** Serialise a message without the trailing newline. */
export function serialise(message: RelayMessage): string {
  return JSON.stringify(orderFields(message));
}

/**
 * Emit fields in the canonical order.
 *
 * `JSON.stringify` follows insertion order, so building a fresh object in the
 * declared order is enough. Doing it explicitly rather than trusting the
 * interface to be built in the right order keeps the wire bytes stable against
 * an innocuous refactor on either side.
 */
function orderFields(message: RelayMessage): Record<string, unknown> {
  const out: Record<string, unknown> = { v: message.v, type: message.type };
  switch (message.type) {
    case "hello":
      out.supportedProtocolVersions = message.supportedProtocolVersions;
      out.instanceSlug = message.instanceSlug;
      out.paperclipVersion = message.paperclipVersion;
      out.capabilities = message.capabilities;
      return out;
    case "hello_ok":
      out.protocolVersion = message.protocolVersion;
      out.sessionId = message.sessionId;
      out.heartbeatIntervalMs = message.heartbeatIntervalMs;
      out.maxConcurrentStreams = message.maxConcurrentStreams;
      out.capabilities = message.capabilities;
      return out;
    case "hello_reject":
      out.code = message.code;
      out.message = message.message;
      return out;
    case "heartbeat":
      out.seq = message.seq;
      return out;
    case "open_stream":
      out.streamId = message.streamId;
      out.streamNonce = message.streamNonce;
      out.kind = message.kind;
      out.method = message.method;
      out.path = message.path;
      out.headers = message.headers;
      return out;
    case "stream_reject":
      out.streamId = message.streamId;
      out.code = message.code;
      out.message = message.message;
      return out;
    case "close_stream":
      out.streamId = message.streamId;
      out.code = message.code;
      return out;
    case "response_head":
      out.streamId = message.streamId;
      out.status = message.status;
      out.headers = message.headers;
      return out;
    case "stream_end":
      out.streamId = message.streamId;
      out.bytesFromClient = message.bytesFromClient;
      out.bytesToClient = message.bytesToClient;
      return out;
    case "stream_error":
      out.streamId = message.streamId;
      out.code = message.code;
      out.message = message.message;
      return out;
  }
}

/** A message type carried across an in-process boundary. */
export interface ControlFrameReader {
  /**
   * Feed bytes and receive every complete frame body they finish, in order.
   *
   * @throws RelayProtocolError `frame_too_large` when the buffered partial frame
   *   exceeds the cap. The caller must destroy the socket: the buffer is
   *   unusable afterwards and the peer is not going to send a shorter frame.
   */
  push(chunk: Buffer): string[];
  /** Bytes currently held in the partial-frame buffer, including undecoded tails. */
  readonly bufferedBytes: number;
  /** Drop any partial frame. Used when resetting after a negotiation failure. */
  reset(): void;
}

export interface ControlFrameReaderOptions {
  readonly maxFrameBytes?: number;
}

/**
 * Incremental NDJSON reader.
 *
 * Two details here are load-bearing rather than incidental.
 *
 * The cap is enforced on **raw bytes received but not yet consumed**, tracked as
 * a running count rather than recomputed from the decoded string. A peer cannot
 * make the process hold an unbounded line by simply never sending a newline.
 *
 * Decoding goes through `StringDecoder`, because a chunk boundary can fall in
 * the middle of a multi-byte UTF-8 sequence. Calling `chunk.toString("utf8")`
 * per chunk turns the split remainder of a single character into U+FFFD, which
 * silently rewrites frame content — including header values, whose bytes are
 * not required to be ASCII.
 */
export function createControlFrameReader(
  options: ControlFrameReaderOptions = {},
): ControlFrameReader {
  const maxFrameBytes = options.maxFrameBytes ?? MAX_CONTROL_FRAME_BYTES;
  let decoder = new StringDecoder("utf8");
  let buffered = "";
  let bufferedBytes = 0;

  const clear = (): void => {
    decoder = new StringDecoder("utf8");
    buffered = "";
    bufferedBytes = 0;
  };

  const overflow = (): never => {
    clear();
    throw new RelayProtocolError("frame_too_large", "control frame exceeds the byte cap");
  };

  return {
    push(chunk: Buffer): string[] {
      bufferedBytes += chunk.byteLength;
      if (bufferedBytes > maxFrameBytes) overflow();
      buffered += decoder.write(chunk);

      const frames: string[] = [];
      let newlineIndex = buffered.indexOf("\n");
      while (newlineIndex !== -1) {
        const frame = buffered.slice(0, newlineIndex);
        buffered = buffered.slice(newlineIndex + 1);
        if (frame.length > 0) frames.push(frame);
        // `+ 1` for the newline that terminated this frame.
        bufferedBytes -= Buffer.byteLength(frame, "utf8") + 1;
        if (bufferedBytes < 0) {
          // Cannot happen: the count is derived from the same bytes. Guarded
          // anyway so a future edit to the accounting cannot turn into a
          // silently unbounded buffer.
          clear();
          throw new RelayProtocolError("internal_error", "control frame accounting underflow");
        }
        if (bufferedBytes > maxFrameBytes) overflow();
        newlineIndex = buffered.indexOf("\n");
      }

      return frames;
    },
    get bufferedBytes(): number {
      return bufferedBytes;
    },
    reset(): void {
      clear();
    },
  };
}

/** Narrowing helper for a value already known to be a protocol message type. */
export function isRelayMessageType(value: unknown): value is RelayMessageType {
  return (
    typeof value === "string"
    && (value === "hello"
      || value === "hello_ok"
      || value === "hello_reject"
      || value === "heartbeat"
      || value === "open_stream"
      || value === "stream_reject"
      || value === "close_stream"
      || value === "response_head"
      || value === "stream_end"
      || value === "stream_error")
  );
}