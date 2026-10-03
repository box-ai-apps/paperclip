/**
 * Turning a relayed request into a request the local app accepts as its own.
 *
 * THE PROBLEM. A browser reaches the instance at the relay's hostname, so it
 * sends `Host: acme-laptop.relay.example.com` and
 * `Origin: https://acme-laptop.relay.example.com`. The local app is listening on
 * `127.0.0.1:3100` and knows nothing about that hostname. Forward the headers
 * unchanged and two separate mechanisms reject the request:
 *
 * - `board-mutation-guard.ts` requires a board mutation's `Origin`/`Referer` to
 *   match the origin the request itself presents. A mismatch fails every
 *   create, update, and delete — the relay would appear to work for reads and be
 *   mysteriously broken for writes.
 * - Better Auth's trusted-origin derivation and `PAPERCLIP_ALLOWED_HOSTNAMES`
 *   would reject the unfamiliar host outright.
 *
 * THE FIX. Rewrite `Host`, `Origin`, and `Referer` to the loopback authority, the
 * same thing a reverse proxy in front of the app does. The relayed request then
 * arrives looking exactly like a direct one, and the app's existing session,
 * membership, and company-scoping logic runs untouched. That is the whole reason
 * the relay needs no trusted-header lane and no way to name an actor: the
 * subscriber's own session cookie rides along and authenticates the request.
 *
 * THE RULE THAT MATTERS MOST. Origin is rewritten, never invented. If the client
 * sent no `Origin` and no `Referer`, none is added. Synthesising one would hand
 * every cross-site form post a passing CSRF check, which is precisely the attack
 * `board-mutation-guard.ts` exists to stop. An attacker who can suppress `Origin`
 * in their own browser cannot forge one here.
 */

/**
 * Headers describing a single hop, which a proxy must not pass along.
 *
 * RFC 7230 §6.1: these are meaningful only for the connection they arrived on.
 * Forwarding them lets a client describe *its* connection to the app — including
 * `connection: upgrade` to attempt a protocol switch the app never agreed to, and
 * `transfer-encoding` to disagree with the app about where a message ends, which
 * is request smuggling.
 *
 * `upgrade` is dropped unconditionally here because the WebSocket case never
 * reaches this function: the stream handler opens its own local WebSocket and
 * frames the response itself.
 */
export const HOP_BY_HOP_HEADERS: ReadonlySet<string> = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "proxy-connection",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
]);

/**
 * Headers this module owns. Dropped from the relayed set and re-derived, so a
 * client cannot dictate its own apparent authority.
 *
 * `host` and `origin` and `referer` are covered by the rewrite; the
 * `x-forwarded-*` family is dropped because the instance half is the only thing
 * that should be asserting a chain, and it asserts one from `clientIp`.
 */
export const AUTHORITY_HEADERS: ReadonlySet<string> = new Set([
  "host",
  "origin",
  "referer",
  "x-forwarded-for",
  "x-forwarded-host",
  "x-forwarded-proto",
  "x-forwarded-port",
  "x-real-ip",
]);

export interface RelayNormalizeOptions {
  /**
   * Authority the local request presents, e.g. `127.0.0.1:3100`.
   *
   * Also used as the `Host` header, which the HTTP client sets separately.
   */
  readonly localAuthority: string;
  /**
   * Origin that `Origin` and `Referer` are rewritten to, e.g.
   * `http://127.0.0.1:3100`. Must correspond to {@link localAuthority}; a
   * mismatch would reintroduce exactly the origin disagreement this module
   * exists to remove, so it is checked rather than assumed.
   */
  readonly localOrigin: string;
  /** Address the relay observed, or null when it could not determine one. */
  readonly clientIp?: string | null;
}

export interface NormalizedRelayRequest {
  /** Headers for the local request, excluding `Host`. */
  readonly headers: Record<string, string>;
}

export class RelayNormalizeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RelayNormalizeError";
  }
}

/**
 * Produce the headers for a relayed request aimed at the local app.
 *
 * Pure, so the whole origin-rewriting contract is testable without a socket.
 *
 * @throws RelayNormalizeError when `localOrigin` does not correspond to
 *   `localAuthority`.
 */
export function normalizeRelayedRequestHeaders(
  relayed: Readonly<Record<string, string>>,
  options: RelayNormalizeOptions,
): NormalizedRelayRequest {
  assertOriginMatchesAuthority(options.localOrigin, options.localAuthority);

  const headers: Record<string, string> = {};
  for (const [name, value] of Object.entries(relayed)) {
    const lower = name.toLowerCase();
    if (HOP_BY_HOP_HEADERS.has(lower)) continue;
    if (AUTHORITY_HEADERS.has(lower)) continue;
    headers[lower] = value;
  }

  // Rewrite, never invent. A request that arrived without an Origin keeps
  // arriving without one, so the CSRF guard still sees exactly what the client
  // actually said.
  if (hasHeader(relayed, "origin")) headers.origin = options.localOrigin;
  if (hasHeader(relayed, "referer")) headers.referer = rewriteRefererPath(relayed, options);

  const clientIp = options.clientIp ?? null;
  if (clientIp !== null) {
    // Appended rather than set, so a chain of trusted hops in front of the relay
    // is preserved and this hop is added at the end, which is the position that
    // means "closest to the app".
    headers["x-forwarded-for"] = clientIp;
  }

  return { headers };
}

function hasHeader(
  headers: Readonly<Record<string, string>>,
  name: string,
): boolean {
  const target = name.toLowerCase();
  return Object.keys(headers).some((key) => key.toLowerCase() === target);
}

/**
 * Rewrite a Referer's origin but keep its path.
 *
 * Better Auth compares a Referer against trusted origins including path scoping,
 * and dropping the path would silently widen what a Referer vouches for.
 */
function rewriteRefererPath(
  relayed: Readonly<Record<string, string>>,
  options: RelayNormalizeOptions,
): string {
  const referer = findHeader(relayed, "referer");
  if (referer === undefined) return options.localOrigin;
  // Only rewrite an absolute referer. A relative one is already origin-free, and
  // prefixing it with an origin would fabricate a document address.
  if (!/^https?:\/\//i.test(referer)) return referer;
  try {
    const parsed = new URL(referer);
    return `${options.localOrigin}${parsed.pathname}${parsed.search}`;
  } catch {
    // An unparseable absolute referer cannot be trusted to describe anything.
    // Reduce it to the bare origin rather than forwarding it.
    return options.localOrigin;
  }
}

function findHeader(
  headers: Readonly<Record<string, string>>,
  name: string,
): string | undefined {
  const target = name.toLowerCase();
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() === target) return value;
  }
  return undefined;
}

/**
 * Refuse a mismatched authority/origin pair.
 *
 * This is a wiring mistake, not an attack: an operator who points `localOrigin`
 * at the public relay hostname while `localAuthority` is loopback would get every
 * request rejected by the CSRF guard and no useful error. Failing at
 * construction turns a silent "everything is broken" into a sentence.
 */
function assertOriginMatchesAuthority(origin: string, authority: string): void {
  let parsed: URL;
  try {
    parsed = new URL(origin);
  } catch {
    throw new RelayNormalizeError(`localOrigin is not a valid URL: ${origin}`);
  }
  if (parsed.host !== authority) {
    throw new RelayNormalizeError(
      `localOrigin host does not match localAuthority: ${parsed.host} vs ${authority}`,
    );
  }
  if (parsed.pathname !== "/" || parsed.search !== "" || parsed.hash !== "") {
    throw new RelayNormalizeError("localOrigin must be a bare origin with no path");
  }
}