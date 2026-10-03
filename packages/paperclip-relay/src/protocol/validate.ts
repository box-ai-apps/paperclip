/**
 * Field validators for the relay wire protocol.
 *
 * Everything here runs on bytes that arrived from a peer, so each assertion is
 * written to fail closed and to return the validated value rather than a
 * boolean, which keeps call sites from decoding an unvalidated value after a
 * check they could forget.
 *
 * The header rules are the security-critical ones. `open_stream` tells the
 * client half to construct an HTTP request from peer-supplied names and values,
 * so an unchecked CR/LF in a header value is a request-smuggling primitive and
 * an unchecked name is a way to shadow a header the stream server owns.
 */
import { isIP } from "node:net";

import { RELAY_ERROR_CODES, type RelayErrorCode } from "./error-codes.js";
import { RelayProtocolError } from "./errors.js";

/** Membership set for {@link assertRelayErrorCode}. */
const ERROR_CODE_SET: ReadonlySet<string> = new Set(RELAY_ERROR_CODES);

/** Bytes allowed in a single control frame body. */
export const MAX_CONTROL_FRAME_BYTES = 16 * 1024;

/** Upper bound on a request target. */
export const MAX_PATH_LENGTH = 2048;

/** Upper bound on a single header line. */
export const MAX_HEADER_LINE_BYTES = 8192;

/** Upper bound on the serialized size of an entire header map. */
export const MAX_HEADER_BLOCK_BYTES = 8192;

/** Upper bound on header count in one message. */
export const MAX_HEADER_COUNT = 64;

/** HTTP methods the relay is willing to forward. */
export const SUPPORTED_METHODS: readonly string[] = [
  "GET",
  "HEAD",
  "POST",
  "PUT",
  "PATCH",
  "DELETE",
  "OPTIONS",
];

/**
 * Headers the stream server sets itself and therefore refuses to accept from a
 * peer.
 *
 * Two distinct reasons, both load-bearing:
 *
 * - Framing and routing (`host`, `content-length`, `transfer-encoding`,
 *   `connection`, `upgrade`, `expect`, `te`, `trailer`, `proxy-*`). A peer that
 *   sets these chooses its own message framing, which is exactly how a proxy
 *   ends up disagreeing with its upstream about where one request ends and the
 *   next begins.
 * - Normalisation (`x-forwarded-*`). The stream server derives the forwarded
 *   chain from the real socket peer, so accepting a peer's copy would let a
 *   client forge its own address in the instance's logs.
 *
 * Deliberately *not* forbidden: `authorization` and `cookie`. Those are the
 * subscriber's own Paperclip credentials and must reach the instance untouched.
 */
export const FORBIDDEN_RELAY_HEADERS: ReadonlySet<string> = new Set([
  "host",
  "content-length",
  "transfer-encoding",
  "connection",
  "keep-alive",
  "upgrade",
  "expect",
  "te",
  "trailer",
  "proxy-authorization",
  "proxy-connection",
  "x-forwarded-for",
  "x-forwarded-host",
  "x-forwarded-proto",
  "x-forwarded-port",
]);

/** lowercase RFC 7230 token. */
const HEADER_NAME_RE = /^[a-z0-9!#$%&'*+.^_`|~-]+$/;

/** Uppercase HTTP token, restricted to the supported set. */
const REQUEST_ID_RE = /^[A-Za-z0-9_-]{1,64}$/;

/** base64url, no padding. 32 random bytes is exactly 43 characters. */
const STREAM_NONCE_RE = /^[A-Za-z0-9_-]{43}$/;

/**
 * Lowercase DNS-label slug.
 *
 * The middle group is `{0,38}` rather than `{1,38}` so the minimum length is 2,
 * which is what the rejection message states. Every other rule here is stated
 * once and reused: `config.ts` loads the slug from an environment variable and
 * must reject exactly what the wire decoder rejects, so a slug that survives
 * configuration cannot fail later at the handshake.
 */
const INSTANCE_SLUG_RE = /^[a-z0-9][a-z0-9-]{0,38}[a-z0-9]$/;

/** Lowercase alphanumeric slug of 2-40 characters, usable as a DNS label. */
export function isInstanceSlug(value: unknown): value is string {
  return typeof value === "string" && INSTANCE_SLUG_RE.test(value);
}

/**
 * Length cap on free-form human-facing prose.
 *
 * Non-ASCII is allowed here, unlike in the actor and slug fields. Error prose
 * routinely quotes a hostname, a company name, or a header the operator needs to
 * see, and rejecting those because they contain an accent would make the codes
 * fine but the messages useless. The rule that actually matters is the absence
 * of control characters, which is what stops an error string from forging log
 * lines or emitting terminal escape sequences.
 */
const MAX_MESSAGE_LENGTH = 512;

const SEMVER_RE = /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]{1,64})?$/;

const CAPABILITY_RE = /^[a-z0-9]+(?:[-_][a-z0-9]+)*$/;

/** Upper bound on `streamNonce` length before validating, to bound the work. */
const MAX_NONCE_CHARS = 128;

/**
 * True when the string contains a C0 control character or DEL.
 *
 * Written as a scan rather than a regex character class so the rule is stated
 * in terms of character codes. The same judgement applies to header values
 * below.
 */
function containsControlCharacter(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= 0x1f || code === 0x7f) return true;
  }
  return false;
}

/**
 * Validate the client address the relay observed.
 *
 * This is a first-class field rather than a relayed `x-forwarded-for` header for
 * two reasons. A header is indistinguishable from one the end client supplied,
 * so accepting it would let a client forge its own address in the instance's
 * audit trail — the exact thing `FORBIDDEN_RELAY_HEADERS` exists to prevent. And
 * an address is not prose: validating it against `node:net`'s `isIP` is exact and
 * needs no hand-rolled parser, so there is no opportunity to disagree with the
 * platform about what a valid address is.
 *
 * Null means "the relay could not determine it", which is a real state for a
 * connection that arrived over a proxy the relay does not control. It is not the
 * same as loopback and must not be reported as one.
 */
export function assertClientIp(value: unknown): string | null {
  if (value === null) return null;
  if (typeof value !== "string") {
    throw new RelayProtocolError("invalid_field", "clientIp must be a string or null");
  }
  if (value.length > 45) {
    // 45 is the longest textual IPv6 address with an embedded IPv4 suffix.
    throw new RelayProtocolError("invalid_field", "clientIp exceeds the length cap");
  }
  if (isIP(value) === 0) {
    throw new RelayProtocolError("invalid_field", "clientIp must be a bare IPv4 or IPv6 literal");
  }
  return value;
}

/**
 * Validate a `ws:`/`wss:` URL used for a socket we will open.
 *
 * Only the two WebSocket schemes, and no embedded credentials — a URL that
 * carries its own secret ends up in log lines and crash reports. Whether the
 * URL is *the same origin* as the control socket is a policy question the dialer
 * answers with {@link isSameOriginTunnelUrl}, because only it knows the control
 * URL it connected to.
 */
export function assertWebSocketUrl(value: unknown): string {
  if (typeof value !== "string" || value.length > 2048) {
    throw new RelayProtocolError("invalid_field", "expected a ws: or wss: URL");
  }
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new RelayProtocolError("invalid_field", "tunnelUrl is not a valid URL");
  }
  if (url.protocol !== "ws:" && url.protocol !== "wss:") {
    throw new RelayProtocolError("invalid_field", "tunnelUrl must use ws: or wss:");
  }
  if (url.username !== "" || url.password !== "") {
    throw new RelayProtocolError("invalid_field", "tunnelUrl must not embed credentials");
  }
  return url.toString();
}

/**
 * True when a tunnel URL is the same origin as the control URL.
 *
 * Compared on scheme, host, and effective port. `wss:` on 443 and `wss:` with an
 * explicit `:443` are the same origin, so the default port is filled in before
 * comparing — otherwise a relay sending a fully-specified URL would be rejected
 * for no reason, and callers would be tempted to loosen the check to make it fit.
 */
export function isSameOriginTunnelUrl(controlUrl: string, tunnelUrl: string): boolean {
  let control: URL;
  let tunnel: URL;
  try {
    control = new URL(controlUrl);
    tunnel = new URL(tunnelUrl);
  } catch {
    return false;
  }
  return (
    control.protocol === tunnel.protocol
    && control.hostname === tunnel.hostname
    && effectivePort(control) === effectivePort(tunnel)
  );
}

function effectivePort(url: URL): string {
  if (url.port !== "") return url.port;
  return url.protocol === "wss:" || url.protocol === "https:" ? "443" : "80";
}

/**
 * Validate a body length, or null for "chunked".
 *
 * Bounded well below anything a real request needs, because this number decides
 * how many bytes the instance half will read. An unvalidated value here would be
 * a way to make the dialer wait on a body that never arrives.
 */
export const MAX_RELAY_BODY_LENGTH = 512 * 1024 * 1024;

export function assertContentLength(value: unknown): number | null {
  if (value === null) return null;
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new RelayProtocolError(
      "invalid_field",
      "contentLength must be a non-negative safe integer or null",
    );
  }
  if (value > MAX_RELAY_BODY_LENGTH) {
    throw new RelayProtocolError("invalid_field", "contentLength exceeds the size cap");
  }
  return value;
}

export function assertProtocolVersionField(value: unknown): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 1) {
    throw new RelayProtocolError("unsupported_protocol_version", "v must be a positive safe integer");
  }
  return value;
}

export function assertRequestId(value: unknown): string {
  if (typeof value !== "string" || !REQUEST_ID_RE.test(value)) {
    throw new RelayProtocolError("invalid_field", "identifier must be 1-64 url-safe characters");
  }
  return value;
}

export function assertStreamId(value: unknown): string {
  if (typeof value !== "string" || !REQUEST_ID_RE.test(value)) {
    throw new RelayProtocolError("invalid_field", "streamId must be 1-64 url-safe characters");
  }
  return value;
}

/**
 * A stream nonce is 32 random bytes in unpadded base64url.
 *
 * The length is pinned rather than merely bounded so there is exactly one
 * canonical encoding of a given nonce. A peer cannot present the same secret in
 * two spellings and have those spellings compare unequal downstream.
 */
export function assertStreamNonce(value: unknown): string {
  if (typeof value !== "string") {
    throw new RelayProtocolError("invalid_field", "streamNonce must be a string");
  }
  if (value.length > MAX_NONCE_CHARS) {
    throw new RelayProtocolError("invalid_field", "streamNonce exceeds the length cap");
  }
  if (!STREAM_NONCE_RE.test(value)) {
    throw new RelayProtocolError(
      "invalid_field",
      "streamNonce must be 32 random bytes in unpadded base64url",
    );
  }
  return value;
}

export function assertInstanceSlug(value: unknown): string {
  if (!isInstanceSlug(value)) {
    throw new RelayProtocolError(
      "invalid_field",
      "instanceSlug must be a lowercase alphanumeric slug of 2-40 characters",
    );
  }
  return value;
}

export function assertSafeMessage(value: unknown): string {
  if (typeof value !== "string" || value.length > MAX_MESSAGE_LENGTH) {
    throw new RelayProtocolError(
      "invalid_field",
      `message must be a string of at most ${MAX_MESSAGE_LENGTH} characters`,
    );
  }
  if (containsControlCharacter(value)) {
    throw new RelayProtocolError(
      "invalid_field",
      "message must not contain control characters",
    );
  }
  return value;
}

export function assertMethod(value: unknown): string {
  if (typeof value !== "string" || !SUPPORTED_METHODS.includes(value)) {
    throw new RelayProtocolError(
      "invalid_method",
      `method must be one of ${SUPPORTED_METHODS.join(", ")}`,
    );
  }
  return value;
}

/**
 * Validate an origin-form request target.
 *
 * `//host/path` is rejected outright. It is origin-form by the letter of the
 * grammar but is read as an authority by enough clients and proxies that
 * forwarding it turns the stream server into an open redirector.
 */
export function assertOriginFormPath(value: unknown): string {
  if (typeof value !== "string") {
    throw new RelayProtocolError("invalid_path", "path must be a string");
  }
  if (value.length > MAX_PATH_LENGTH) {
    throw new RelayProtocolError("invalid_path", "path exceeds the length cap");
  }
  if (!value.startsWith("/")) {
    throw new RelayProtocolError("invalid_path", "path must start with /");
  }
  if (value.startsWith("//")) {
    throw new RelayProtocolError("invalid_path", "path must not start with //");
  }
  if (containsControlCharacter(value)) {
    throw new RelayProtocolError("invalid_path", "path must not contain control characters");
  }
  return value;
}

/**
 * Validate a header *name* for a relayed request.
 *
 * {@link FORBIDDEN_RELAY_HEADERS} applies here and only here. A peer choosing a
 * request's framing or its own apparent address is a request-smuggling and
 * log-forging primitive, so those names are refused. The same names are
 * legitimate in a response — a `101 Switching Protocols` is nothing without
 * `Upgrade` and `Connection`, and the instance half is the authority on its own
 * app's responses — which is why response headers go through
 * {@link assertResponseHeaderMap} instead.
 */
export function assertRequestHeaderName(value: unknown): string {
  if (typeof value !== "string" || value.length === 0 || !HEADER_NAME_RE.test(value)) {
    throw new RelayProtocolError(
      "invalid_header_name",
      "header name must be a lowercase RFC 7230 token",
    );
  }
  if (FORBIDDEN_RELAY_HEADERS.has(value)) {
    throw new RelayProtocolError(
      "forbidden_header",
      `header ${value} is owned by the stream server and must not be relayed`,
    );
  }
  return value;
}

/** Validate a header name in either direction. No denylist. */
export function assertHeaderName(value: unknown): string {
  if (typeof value !== "string" || value.length === 0 || !HEADER_NAME_RE.test(value)) {
    throw new RelayProtocolError(
      "invalid_header_name",
      "header name must be a lowercase RFC 7230 token",
    );
  }
  return value;
}

/**
 * Reject anything that could terminate the header line early.
 *
 * CR and LF are the smuggling primitive. NUL and the remaining C0 controls go
 * with them because no legitimate `Cookie` or `User-Agent` value contains one,
 * and downstream log writers disagree about how to render them. Bytes above
 * 0x7f are accepted: header values are bytes, not text, and `Cookie` carries
 * base64 padding while `User-Agent` carries UTF-8 product names.
 */
export function assertHeaderValue(name: string, value: unknown): string {
  if (typeof value !== "string") {
    throw new RelayProtocolError("invalid_header_value", `header ${name} must be a string`);
  }
  if (value.length > MAX_HEADER_LINE_BYTES) {
    throw new RelayProtocolError("invalid_header_value", `header ${name} exceeds the line cap`);
  }
  if (containsControlCharacter(value)) {
    throw new RelayProtocolError(
      "invalid_header_value",
      `header ${name} contains a character that cannot be transmitted safely`,
    );
  }
  return value;
}

export interface ValidatedHeaderMap {
  readonly headers: Record<string, string>;
}

function validateHeaderMap(
  value: unknown,
  assertName: (name: unknown) => string,
): ValidatedHeaderMap {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new RelayProtocolError("invalid_field", "headers must be a JSON object");
  }
  const entries = Object.entries(value as Record<string, unknown>);
  if (entries.length > MAX_HEADER_COUNT) {
    throw new RelayProtocolError("invalid_header_name", "too many headers");
  }

  const headers: Record<string, string> = {};
  let totalBytes = 0;
  for (const [rawName, rawValue] of entries) {
    const name = assertName(rawName);
    const headerValue = assertHeaderValue(name, rawValue);
    // A duplicate would already have been rejected by the strict JSON parser,
    // so this guards a caller that builds the map in-process instead.
    if (Object.hasOwn(headers, name)) {
      throw new RelayProtocolError("invalid_header_name", `duplicate header name: ${name}`);
    }
    totalBytes += Buffer.byteLength(name, "utf8") + Buffer.byteLength(headerValue, "utf8") + 4;
    if (totalBytes > MAX_HEADER_BLOCK_BYTES) {
      throw new RelayProtocolError("invalid_header_value", "header block exceeds the byte cap");
    }
    headers[name] = headerValue;
  }
  return { headers };
}

/**
 * Validate headers on a relayed **request**.
 *
 * Keys must be unique, lowercase, transmittable, and not owned by the stream
 * server; count and total size are bounded.
 */
export function assertRequestHeaderMap(value: unknown): ValidatedHeaderMap {
  return validateHeaderMap(value, assertRequestHeaderName);
}

/**
 * Validate headers on a **response** heading back through the tunnel.
 *
 * The {@link FORBIDDEN_RELAY_HEADERS} denylist is intentionally *not* applied
 * here. Those names describe who owns framing and apparent address in a
 * *request*; in a response they are the protocol speaking for itself. A
 * `101 Switching Protocols` carries `Upgrade` and `Connection`, and a WebSocket
 * handshake is only complete with `Sec-WebSocket-Accept` — forbidding them would
 * make every relay connection to `/api/realtime/live-events` impossible.
 *
 * Control characters, header count, and byte caps still apply, because those
 * protect the frame rather than express ownership.
 */
export function assertResponseHeaderMap(value: unknown): ValidatedHeaderMap {
  return validateHeaderMap(value, assertHeaderName);
}

export function assertHttpStatus(value: unknown): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 100 || value > 599) {
    throw new RelayProtocolError("invalid_field", "status must be an integer in [100, 599]");
  }
  return value;
}

export function assertNonNegativeInteger(value: unknown): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new RelayProtocolError("invalid_field", "expected a non-negative safe integer");
  }
  return value;
}

export function assertPositiveInteger(value: unknown): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value <= 0) {
    throw new RelayProtocolError("invalid_field", "expected a positive safe integer");
  }
  return value;
}

/**
 * Validate an optional semver-shaped version string.
 *
 * Loose about pre-release and build metadata, strict about the character set,
 * because the value is echoed into an audit record and a subscriber's version
 * is not always a clean semver.
 */
export function assertOptionalVersion(value: unknown): string | null {
  if (value === null || value === undefined) return null;
  if (typeof value !== "string" || !SEMVER_RE.test(value)) {
    throw new RelayProtocolError("invalid_field", "expected a semver-shaped version string or null");
  }
  return value;
}

/** Validate a capability token: lowercase, hyphen-separated, bounded. */
export function assertCapability(value: unknown): string {
  if (typeof value !== "string" || value.length > 64 || !CAPABILITY_RE.test(value)) {
    throw new RelayProtocolError(
      "invalid_field",
      "capability must be a lowercase token of at most 64 characters",
    );
  }
  return value;
}

export function assertCapabilityList(value: unknown): string[] {
  if (!Array.isArray(value)) {
    throw new RelayProtocolError("invalid_field", "capabilities must be an array");
  }
  if (value.length > 32) {
    throw new RelayProtocolError("invalid_field", "too many capabilities");
  }
  const seen = new Set<string>();
  for (const entry of value) {
    const capability = assertCapability(entry);
    if (seen.has(capability)) {
      throw new RelayProtocolError("invalid_field", "duplicate capability");
    }
    seen.add(capability);
  }
  return [...seen];
}

export function assertProtocolVersionList(value: unknown): number[] {
  if (!Array.isArray(value)) {
    throw new RelayProtocolError("unsupported_protocol_version", "supportedProtocolVersions must be an array");
  }
  if (value.length === 0 || value.length > 16) {
    throw new RelayProtocolError(
      "unsupported_protocol_version",
      "supportedProtocolVersions must contain between 1 and 16 versions",
    );
  }
  const versions: number[] = [];
  for (const entry of value) {
    versions.push(assertProtocolVersionField(entry));
  }
  return versions;
}

export function assertStreamKind(value: unknown): "http" | "websocket" {
  if (value !== "http" && value !== "websocket") {
    throw new RelayProtocolError("invalid_field", 'kind must be "http" or "websocket"');
  }
  return value;
}

/**
 * Assert a code belongs to the shared vocabulary.
 *
 * Used when re-emitting a peer's error code into a reply, so a side cannot
 * invent a code the other side has never heard of and then branch on it.
 */
export function assertRelayErrorCode(value: unknown): RelayErrorCode {
  if (typeof value !== "string" || !ERROR_CODE_SET.has(value)) {
    throw new RelayProtocolError("invalid_field", "unknown error code");
  }
  return value as RelayErrorCode;
}