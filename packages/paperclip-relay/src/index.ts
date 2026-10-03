/**
 * Client half of the Paperclip relay.
 *
 * This package is everything a Paperclip instance needs in order to publish
 * itself through a relay: the wire protocol, fail-closed configuration, per-user
 * relay credentials, and the deployment-mode precondition. The transport
 * (outbound control socket, tunnel sockets, loopback stream server) is layered on
 * top of these primitives by `server/src/services/relay`.
 *
 * The relay server that subscribers connect to is a separate repository,
 * `paperclip-relay-server`, which vendors `protocol/conformance/vectors.ts` from
 * here and implements the same codec against it.
 */
export * from "./protocol/index.js";
export {
  createBackoffSequence,
  type BackoffOptions,
  type BackoffSequence,
  isPermanentRelayError,
} from "./dialer/backoff.js";
export {
  type RelayControlSocket,
  type RelayControlSocketFactory,
  RelayDialer,
  type RelayDialerEvent,
  type RelayDialerListener,
  type RelayDialerOptions,
  type RelayDialerState,
  type RelayStreamDecision,
  type RelayStreamRequest,
} from "./dialer/control-client.js";
export {
  isRelayEnabled,
  loadRelayConfig,
  type RelayClientConfig,
  type RelayConfigOptions,
  RelayConfigError,
} from "./config.js";
export {
  hashRelayCredential,
  isRelayCredentialLive,
  isRelayCredentialShaped,
  issueRelayCredential,
  type IssuedRelayCredential,
  parseBearerRelayCredential,
  redactRelayCredential,
  type RelayCredentialRecord,
  type RelayCredentialResolution,
  type RelayCredentialStore,
  RELAY_CREDENTIAL_PREFIX,
  RELAY_CREDENTIAL_REDACTION,
  verifyRelayCredential,
} from "./credential.js";
export {
  assertRelayPublishable,
  type RelayDeploymentExposure,
  type RelayDeploymentMode,
  type RelayGateSubject,
  RelayGateError,
  relayPublishBlockedReason,
} from "./gate.js";