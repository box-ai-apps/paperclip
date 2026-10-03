/**
 * Strict decoder for relay control-channel messages.
 *
 * Decoding is complete before any caller sees a value: the frame is size-checked,
 * parsed with the duplicate-key-rejecting parser, checked for exactly the field
 * set the message type allows, and each field run through the validators in
 * `validate.ts`. Nothing here has a side effect, so a rejected frame leaves the
 * connection state untouched and the peer can be answered or dropped on the
 * strength of the returned code alone.
 */
import { RelayProtocolError } from "./errors.js";
import type {
  RelayCloseStreamMessage,
  RelayHelloMessage,
  RelayHelloOkMessage,
  RelayHelloRejectMessage,
  RelayHeartbeatMessage,
  RelayMessage,
  RelayMessageType,
  RelayOpenStreamMessage,
  RelayResponseHeadMessage,
  RelayStreamEndMessage,
  RelayStreamErrorMessage,
  RelayStreamRejectMessage,
} from "./messages.js";
import { PROTOCOL_VERSION } from "./version.js";
import { DuplicateJsonKeyError, parseJsonNoDuplicateKeys } from "./strict-json.js";
import {
  MAX_CONTROL_FRAME_BYTES,
  assertActorUserId,
  assertCapabilityList,
  assertHeaderMap,
  assertHttpStatus,
  assertInstanceSlug,
  assertMethod,
  assertNonNegativeInteger,
  assertOptionalVersion,
  assertOriginFormPath,
  assertPositiveInteger,
  assertProtocolVersionField,
  assertProtocolVersionList,
  assertRelayErrorCode,
  assertRequestId,
  assertSafeMessage,
  assertStreamId,
  assertStreamKind,
  assertStreamNonce,
} from "./validate.js";

/**
 * Exact field set per message type.
 *
 * Enumerated rather than derived so that adding a field is a deliberate act in
 * both repositories. A peer sending an unrecognised field is refused with
 * `unknown_field` instead of having it ignored, because an ignored field is
 * indistinguishable from one the sender believed was honoured.
 */
const ALLOWED_FIELDS: Readonly<Record<RelayMessageType, readonly string[]>> = {
  hello: ["v", "type", "supportedProtocolVersions", "instanceSlug", "paperclipVersion", "capabilities"],
  hello_ok: ["v", "type", "protocolVersion", "sessionId", "heartbeatIntervalMs", "maxConcurrentStreams", "capabilities"],
  hello_reject: ["v", "type", "code", "message"],
  heartbeat: ["v", "type", "seq"],
  open_stream: ["v", "type", "streamId", "streamNonce", "kind", "method", "path", "headers", "actorUserId"],
  stream_reject: ["v", "type", "streamId", "code", "message"],
  close_stream: ["v", "type", "streamId", "code"],
  response_head: ["v", "type", "streamId", "status", "headers"],
  stream_end: ["v", "type", "streamId", "bytesFromClient", "bytesToClient"],
  stream_error: ["v", "type", "streamId", "code", "message"],
};

const MESSAGE_TYPES: ReadonlySet<string> = new Set(Object.keys(ALLOWED_FIELDS));

/**
 * Decode one control frame body into a validated message.
 *
 * @param frame UTF-8 JSON body. A trailing newline is tolerated because the
 *   framing is newline-delimited JSON; anything after the value is not.
 * @param options.expectedVersion The version agreed during negotiation. Every
 *   subsequent message must carry exactly this value, so a peer cannot switch a
 *   live connection to a version it never negotiated.
 */
export function decodeRelayMessage(
  frame: string,
  options: { readonly expectedVersion?: number } = {},
): RelayMessage {
  const expectedVersion = options.expectedVersion ?? PROTOCOL_VERSION;
  if (frame.length > MAX_CONTROL_FRAME_BYTES) {
    throw new RelayProtocolError("frame_too_large", "control frame exceeds the byte cap");
  }

  const trimmed = frame.endsWith("\n") ? frame.slice(0, -1) : frame;
  if (trimmed.length === 0) {
    throw new RelayProtocolError("malformed_frame", "empty control frame");
  }

  let parsed: unknown;
  try {
    parsed = parseJsonNoDuplicateKeys(trimmed);
  } catch (error) {
    if (error instanceof DuplicateJsonKeyError) {
      throw new RelayProtocolError("duplicate_key", "control frame contains a duplicate object key");
    }
    throw new RelayProtocolError("malformed_json", "control frame is not valid JSON");
  }

  const obj = asObject(parsed);
  const type = obj.type;
  if (typeof type !== "string" || !MESSAGE_TYPES.has(type)) {
    throw new RelayProtocolError("unknown_message_type", "unrecognised message type");
  }
  const messageType = type as RelayMessageType;
  assertExactFields(obj, ALLOWED_FIELDS[messageType]);
  const version = assertProtocolVersionField(obj.v);
  if (version !== expectedVersion) {
    throw new RelayProtocolError(
      "unsupported_protocol_version",
      `frame declares version ${version}, expected ${expectedVersion}`,
    );
  }

  switch (messageType) {
    case "hello":
      return decodeHello(obj, version);
    case "hello_ok":
      return decodeHelloOk(obj, version);
    case "hello_reject":
      return decodeHelloReject(obj, version);
    case "heartbeat":
      return { v: version, type: "heartbeat", seq: assertNonNegativeInteger(obj.seq) };
    case "open_stream":
      return decodeOpenStream(obj, version);
    case "stream_reject":
      return {
        v: version,
        type: "stream_reject",
        streamId: assertStreamId(obj.streamId),
        code: assertRelayErrorCode(obj.code),
        message: assertSafeMessage(obj.message),
      };
    case "close_stream":
      return {
        v: version,
        type: "close_stream",
        streamId: assertStreamId(obj.streamId),
        code: obj.code === null ? null : assertRelayErrorCode(obj.code),
      };
    case "response_head": {
      const { headers } = assertHeaderMap(obj.headers);
      return {
        v: version,
        type: "response_head",
        streamId: assertStreamId(obj.streamId),
        status: assertHttpStatus(obj.status),
        headers,
      };
    }
    case "stream_end":
      return {
        v: version,
        type: "stream_end",
        streamId: assertStreamId(obj.streamId),
        bytesFromClient: assertNonNegativeInteger(obj.bytesFromClient),
        bytesToClient: assertNonNegativeInteger(obj.bytesToClient),
      };
    case "stream_error":
      return {
        v: version,
        type: "stream_error",
        streamId: assertStreamId(obj.streamId),
        code: assertRelayErrorCode(obj.code),
        message: assertSafeMessage(obj.message),
      };
  }
}

function decodeHello(obj: Record<string, unknown>, v: number): RelayHelloMessage {
  return {
    v,
    type: "hello",
    supportedProtocolVersions: assertProtocolVersionList(obj.supportedProtocolVersions),
    instanceSlug: assertInstanceSlug(obj.instanceSlug),
    paperclipVersion: assertOptionalVersion(obj.paperclipVersion),
    capabilities: assertCapabilityList(obj.capabilities),
  };
}

function decodeHelloOk(obj: Record<string, unknown>, v: number): RelayHelloOkMessage {
  return {
    v,
    type: "hello_ok",
    protocolVersion: assertProtocolVersionField(obj.protocolVersion),
    sessionId: assertRequestId(obj.sessionId),
    heartbeatIntervalMs: assertPositiveInteger(obj.heartbeatIntervalMs),
    maxConcurrentStreams: assertPositiveInteger(obj.maxConcurrentStreams),
    capabilities: assertCapabilityList(obj.capabilities),
  };
}

function decodeHelloReject(obj: Record<string, unknown>, v: number): RelayHelloRejectMessage {
  return {
    v,
    type: "hello_reject",
    code: assertRelayErrorCode(obj.code),
    message: assertSafeMessage(obj.message),
  };
}

function decodeOpenStream(obj: Record<string, unknown>, v: number): RelayOpenStreamMessage {
  const { headers } = assertHeaderMap(obj.headers);
  return {
    v,
    type: "open_stream",
    streamId: assertStreamId(obj.streamId),
    streamNonce: assertStreamNonce(obj.streamNonce),
    kind: assertStreamKind(obj.kind),
    method: assertMethod(obj.method),
    path: assertOriginFormPath(obj.path),
    headers,
    actorUserId: assertActorUserId(obj.actorUserId),
  };
}

function asObject(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new RelayProtocolError("malformed_message", "control frame must be a JSON object");
  }
  return value as Record<string, unknown>;
}

function assertExactFields(obj: Record<string, unknown>, allowed: readonly string[]): void {
  const allowedSet = new Set(allowed);
  for (const key of Object.keys(obj)) {
    if (!allowedSet.has(key)) {
      throw new RelayProtocolError("unknown_field", `unrecognised field: ${key}`);
    }
  }
  for (const key of allowed) {
    if (!Object.hasOwn(obj, key)) {
      throw new RelayProtocolError("invalid_field", `missing field: ${key}`);
    }
  }
}