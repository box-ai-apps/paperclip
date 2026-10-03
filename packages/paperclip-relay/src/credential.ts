/**
 * Relay credential issue, storage, and verification.
 *
 * A relay credential answers exactly one question: "does this control socket
 * belong to the instance that owns this slug?" It says nothing about which human
 * is using the tunnel, because the relay cannot know and must not be believed
 * if it claimed to.
 *
 * That is worth being explicit about, because the obvious alternative — a
 * per-user credential plus a trusted header telling the instance which local user
 * each stream acts as — is what this design deliberately does not do:
 *
 * - The subscriber's own Paperclip session rides the tunnel, so the instance
 *   authenticates the request itself, with its own membership and company
 *   scoping. The audit log describes what actually happened.
 * - The relay has no knowledge of Paperclip's users or roles, so anything it
 *   asserted would be a claim the instance had to take on faith.
 * - An operator running the relay is already in the data path and can read or
 *   alter bytes; that is inherent to a relay. What they must not be able to do
 *   is escalate, and with no actor assertion there is nothing to escalate into —
 *   every injected request still needs a valid Paperclip credential that
 *   originated from the subscriber.
 *
 * Tokens carry 256 bits of entropy from the CSPRNG, so they are hashed with
 * SHA-256 rather than a password KDF. This is the same reasoning, and the same
 * trade, as the instance's existing `agent_api_keys` and `board_api_keys`: a slow
 * KDF exists to make guessing a low-entropy secret expensive, and there is
 * nothing to guess here. Verification stays constant-time anyway, because the
 * hash comparison is against a value an attacker can supply.
 */
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

/**
 * Token prefix, matching the instance's existing credential convention
 * (`pcp_board_`, `pcp_cli_auth_`).
 *
 * The prefix is not a security boundary — it is an operational one. It lets a
 * secret scanner recognise a leaked relay credential in a log or a repository,
 * and it lets the CLI tell a subscriber which credential they are looking at.
 */
export const RELAY_CREDENTIAL_PREFIX = "pcp_relay_";

/** Bytes of entropy in a credential token. */
const TOKEN_ENTROPY_BYTES = 32;

/** Length of the base64url portion after the prefix: 32 bytes, unpadded. */
const TOKEN_BODY_LENGTH = 43;

/** Displayed when a credential is redacted for a log line. */
export const RELAY_CREDENTIAL_REDACTION = "[redacted relay credential]";

export interface IssuedRelayCredential {
  /** Full token. Shown to the operator once and never again. */
  readonly token: string;
  /** Lowercase hex SHA-256. This is what gets persisted. */
  readonly tokenHash: string;
}

/**
 * Mint a new relay credential.
 *
 * The plaintext token exists only in this return value. Persist `tokenHash`.
 */
export function issueRelayCredential(): IssuedRelayCredential {
  const token = RELAY_CREDENTIAL_PREFIX + randomBytes(TOKEN_ENTROPY_BYTES).toString("base64url");
  return { token, tokenHash: hashRelayCredential(token) };
}

/** Lowercase hex SHA-256 of a token. */
export function hashRelayCredential(token: string): string {
  return createHash("sha256").update(token, "utf8").digest("hex");
}

/**
 * Verify a presented token against a stored hash in constant time.
 *
 * The length check runs first and returns early. That leaks only whether the
 * stored value is the expected length, which is fixed and public, so there is no
 * oracle in it — whereas the byte comparison itself must not short-circuit.
 */
export function verifyRelayCredential(token: unknown, expectedHash: string): boolean {
  if (typeof token !== "string") return false;
  if (!/^[0-9a-f]{64}$/.test(expectedHash)) {
    // A malformed stored hash is a bug, not an authentication failure. Fail
    // closed rather than treating it as a mismatch and reporting success for an
    // empty expected value.
    return false;
  }
  const actual = Buffer.from(hashRelayCredential(token), "hex");
  const expected = Buffer.from(expectedHash, "hex");
  if (actual.byteLength !== expected.byteLength) return false;
  return timingSafeEqual(actual, expected);
}

/** Structural check on a token, independent of any stored hash. */
export function isRelayCredentialShaped(token: unknown): token is string {
  return (
    typeof token === "string"
    && token.startsWith(RELAY_CREDENTIAL_PREFIX)
    && token.length === RELAY_CREDENTIAL_PREFIX.length + TOKEN_BODY_LENGTH
    && /^[A-Za-z0-9_-]+$/.test(token.slice(RELAY_CREDENTIAL_PREFIX.length))
  );
}

/**
 * Reduce a token to something safe to put in a log line.
 *
 * Anything that is not recognisably a relay credential is passed through
 * unchanged, because this is a defence-in-depth net for values the credential
 * parser did not see — a raw Authorization header, for instance — and silently
 * blanking an unrecognised value would hide the very leak it exists to surface.
 */
export function redactRelayCredential(value: unknown): string {
  if (typeof value !== "string") return RELAY_CREDENTIAL_REDACTION;
  return isRelayCredentialShaped(value) ? RELAY_CREDENTIAL_REDACTION : value;
}

/**
 * Pull a relay credential out of an `Authorization: Bearer` header value.
 *
 * Returns null rather than throwing, so a caller can fold "no credential" into
 * its normal unauthenticated path. A present-but-malformed value is also null:
 * the distinction between "absent" and "wrong" is not one an unauthenticated
 * caller should be able to observe anyway.
 */
export function parseBearerRelayCredential(headerValue: unknown): string | null {
  if (typeof headerValue !== "string") return null;
  const match = /^bearer[ ]+(.+)$/i.exec(headerValue.trim());
  if (!match) return null;
  const token = match[1]?.trim() ?? "";
  return isRelayCredentialShaped(token) ? token : null;
}

/** A row from the instance's relay credential table. */
export interface RelayCredentialRecord {
  readonly id: string;
  readonly tokenHash: string;
  readonly revokedAt: Date | null;
  readonly expiresAt: Date | null;
}

/**
 * Outcome of resolving a presented credential.
 *
 * `unauthorized` covers every "no" — absent, unknown, revoked, expired — on
 * purpose. Distinguishing them for an unauthenticated peer hands an attacker a
 * probe for which tokens once existed, so the codes are equal and only the
 * instance's own audit log tells them apart.
 */
export type RelayCredentialResolution =
  | { readonly ok: true; readonly credential: RelayCredentialRecord }
  | { readonly ok: false; readonly reason: "unauthorized" };

/**
 * Where the dialer gets its credential.
 *
 * An interface rather than a query so the dialer, the control socket, and the
 * stream server can all be tested without a database. The production
 * implementation lives in `server/src/services/relay` and is the only thing that
 * knows about drizzle.
 */
export interface RelayCredentialStore {
  /**
   * Resolve a presented token to a live credential row.
   *
   * @param now Injectable clock so expiry is testable without waiting.
   */
  resolveByToken(token: string, now?: Date): Promise<RelayCredentialResolution>;
}

/**
 * True when a row is neither revoked nor expired at `now`.
 *
 * Exported so the store implementation and its tests agree on one definition.
 */
export function isRelayCredentialLive(
  record: Pick<RelayCredentialRecord, "revokedAt" | "expiresAt">,
  now: Date,
): boolean {
  if (record.revokedAt !== null && record.revokedAt.getTime() <= now.getTime()) return false;
  if (record.expiresAt !== null && record.expiresAt.getTime() <= now.getTime()) return false;
  return true;
}