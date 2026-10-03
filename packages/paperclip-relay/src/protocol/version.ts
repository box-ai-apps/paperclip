/**
 * Wire protocol version negotiation for the Paperclip relay.
 *
 * WHY NEGOTIATION IS NOT OPTIONAL HERE. The relay server and the Paperclip
 * client half are versioned and released independently, and a subscriber's
 * dialer can outlive any given relay by months: an instance running Paperclip
 * `0.3.1` must keep working against a relay that has since moved to protocol
 * `v2`. Without negotiation, the only two outcomes are a silent misparse (a
 * field the newer side reads as required is absent, so the message decodes into
 * something plausible and wrong) or a total outage for every pinned subscriber
 * the moment the relay ships a change.
 *
 * So both sides exchange the versions they can speak and select the highest
 * version both accept. A dialer that shares no version with the relay is
 * refused with a stable code and a human-readable reason — a clean, actionable
 * failure instead of a misparse. This is also what makes the duplicated codec
 * in the relay-server repository survivable: version skew is a refusal, never
 * a misinterpretation.
 */

/** The protocol version this build of the client half implements. */
export const PROTOCOL_VERSION = 1;

/** Every protocol version this build is able to speak, newest first. */
export const SUPPORTED_PROTOCOL_VERSIONS: readonly number[] = [1];

/**
 * Upper bound on any version number accepted from a peer.
 *
 * A peer claiming an absurd version must not be able to make us allocate or
 * retain anything proportional to it, and it must be obvious in an audit log
 * that the peer is confused rather than merely newer.
 */
export const MAX_PROTOCOL_VERSION = 1000;

/** The stable, machine-readable negotiation outcome. */
export type NegotiationResult =
  | { readonly ok: true; readonly version: number }
  | { readonly ok: false; readonly code: "unsupported_protocol_version" | "no_common_protocol_version"; readonly detail: string };

/**
 * Intersect a peer's advertised versions with ours and choose the highest
 * common version.
 *
 * Ordering is by numeric value, not by the order either side listed, so a peer
 * that lists its versions oldest-first still negotiates correctly.
 */
export function negotiateProtocolVersion(
  peerSupported: readonly number[],
  ours: readonly number[] = SUPPORTED_PROTOCOL_VERSIONS,
): NegotiationResult {
  if (peerSupported.length === 0) {
    return {
      ok: false,
      code: "no_common_protocol_version",
      detail: "peer advertised no supported protocol versions",
    };
  }

  // A peer advertising a version above MAX_PROTOCOL_VERSION is not "newer", it
  // is malformed or hostile. Treat it as unsupported rather than silently
  // ignoring it, so the refusal names the real problem.
  const outOfRange = peerSupported.find(
    (version) => !Number.isSafeInteger(version) || version < 1 || version > MAX_PROTOCOL_VERSION,
  );
  if (outOfRange !== undefined) {
    return {
      ok: false,
      code: "unsupported_protocol_version",
      detail: `peer advertised an out-of-range protocol version: ${String(outOfRange)}`,
    };
  }

  const ourSet = new Set(ours);
  const common = peerSupported
    .filter((version) => ourSet.has(version))
    .sort((a, b) => b - a);

  const selected = common[0];
  if (selected === undefined) {
    return {
      ok: false,
      code: "no_common_protocol_version",
      detail:
        `no common protocol version: peer offered [${peerSupported.join(", ")}], `
        + `this build speaks [${ours.join(", ")}]`,
    };
  }

  return { ok: true, version: selected };
}