/**
 * Public surface of the relay control protocol.
 *
 * The relay-server repository vendors `conformance/vectors.ts` from this package
 * and implements the same codec against it. Keep the exported names stable
 * across both implementations; they are the contract.
 */
export {
  CONFORMANCE_PROTOCOL_VERSION,
  type RelayDecodeVector,
  RELAY_DECODE_VECTORS,
} from "./conformance/vectors.js";
export { createControlFrameReader, type ControlFrameReader, type ControlFrameReaderOptions, encodeRelayMessage, isRelayMessageType, serialise } from "./codec.js";
export { decodeRelayMessage } from "./decode.js";
export {
  isRelayErrorCode,
  type RelayErrorCode,
  type RelayErrorDetail,
  RELAY_ERROR_CODES,
} from "./error-codes.js";
export { RelayProtocolError } from "./errors.js";
export {
  type InboundRelayMessage,
  type OutboundRelayMessage,
  RELAY_CAPABILITIES,
  type RelayCloseStreamMessage,
  type RelayHeartbeatMessage,
  type RelayHelloMessage,
  type RelayHelloOkMessage,
  type RelayHelloRejectMessage,
  type RelayMessage,
  type RelayMessageType,
  type RelayOpenStreamMessage,
  type RelayResponseHeadMessage,
  type RelayStreamEndMessage,
  type RelayStreamErrorMessage,
  type RelayStreamKind,
  type RelayStreamRejectMessage,
} from "./messages.js";
export {
  assertClientIp,
  assertHeaderName,
  assertHeaderValue,
  assertRequestHeaderMap,
  assertResponseHeaderMap,
  assertInstanceSlug,
  assertMethod,
  assertOriginFormPath,
  assertStreamId,
  assertStreamNonce,
  FORBIDDEN_RELAY_HEADERS,
  isInstanceSlug,
  MAX_CONTROL_FRAME_BYTES,
  MAX_HEADER_BLOCK_BYTES,
  MAX_HEADER_COUNT,
  MAX_HEADER_LINE_BYTES,
  MAX_PATH_LENGTH,
  SUPPORTED_METHODS,
} from "./validate.js";
export {
  MAX_PROTOCOL_VERSION,
  type NegotiationResult,
  negotiateProtocolVersion,
  PROTOCOL_VERSION,
  SUPPORTED_PROTOCOL_VERSIONS,
} from "./version.js";