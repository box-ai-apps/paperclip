/**
 * Reconnect backoff for the relay control socket.
 *
 * WHY NOT JUST SLEEP A SECOND. Every tunneled instance that loses its
 * connection at the same moment — a relay deploy, a NAT table expiring, a laptop
 * lid closing — would otherwise retry in lockstep forever. That is a
 * self-inflicted thundering herd against the one server all of them depend on,
 * and the recovery gets slower exactly when the relay is already struggling.
 *
 * WHY *EQUAL* JITTER AND NOT FULL JITTER. Full jitter (`random() * ceiling`)
 * is optimal for throughput but can hand out a near-zero delay, which looks like
 * a hot loop in a log and makes the backoff hard to reason about. Equal jitter
 * keeps half the ceiling as a floor: the spread still de-synchronises clients,
 * while no attempt ever retries instantly.
 *
 * `random` is injectable so tests can assert the exact sequence.
 */

export interface BackoffOptions {
  /** Delay before the first retry. Defaults to 500ms. */
  readonly baseDelayMs?: number;
  /** Ceiling on any single delay. Defaults to 30s. */
  readonly maxDelayMs?: number;
  /** Growth per attempt. Defaults to 2. */
  readonly factor?: number;
  /** Fraction of the delay that is randomised, 0-1. Defaults to 0.5. */
  readonly jitterRatio?: number;
  /** Uniform [0,1) source. Injectable for deterministic tests. */
  readonly random?: () => number;
}

export interface BackoffSequence {
  /** Delay for the next attempt, then advances the attempt counter. */
  next(): number;
  /** Forget accumulated attempts, so the next delay is the base delay again. */
  reset(): void;
  /** Attempts consumed since the last reset. */
  readonly attempts: number;
}

const DEFAULT_BASE_DELAY_MS = 500;
const DEFAULT_MAX_DELAY_MS = 30_000;
const DEFAULT_FACTOR = 2;
const DEFAULT_JITTER_RATIO = 0.5;

export function createBackoffSequence(options: BackoffOptions = {}): BackoffSequence {
  const baseDelayMs = options.baseDelayMs ?? DEFAULT_BASE_DELAY_MS;
  const maxDelayMs = options.maxDelayMs ?? DEFAULT_MAX_DELAY_MS;
  const factor = options.factor ?? DEFAULT_FACTOR;
  const jitterRatio = options.jitterRatio ?? DEFAULT_JITTER_RATIO;
  const random = options.random ?? Math.random;

  assertPositiveFinite("baseDelayMs", baseDelayMs);
  assertPositiveFinite("maxDelayMs", maxDelayMs);
  assertPositiveFinite("factor", factor);
  if (maxDelayMs < baseDelayMs) {
    throw new Error("maxDelayMs must not be smaller than baseDelayMs");
  }
  if (jitterRatio < 0 || jitterRatio > 1) {
    throw new Error("jitterRatio must be within [0, 1]");
  }

  let attempts = 0;

  return {
    next(): number {
      // The exponent is clamped before it is used so a long outage cannot
      // overflow to Infinity and turn `Math.min` into a NaN delay.
      const exponent = Math.min(attempts, 32);
      const ceiling = Math.min(maxDelayMs, baseDelayMs * Math.pow(factor, exponent));
      // Equal jitter: the un-jittered half is the floor.
      const fixed = ceiling * (1 - jitterRatio);
      const delay = fixed + random() * (ceiling - fixed);
      attempts += 1;
      return Math.round(delay);
    },
    reset(): void {
      attempts = 0;
    },
    get attempts(): number {
      return attempts;
    },
  };
}

/**
 * Failures that will not fix themselves by retrying.
 *
 * A refused credential, a lapsed subscription, a taken slug, or an
 * unsupported protocol version all need an operator to act. Reconnecting on a
 * timer after one of those produces a client that hammers the relay forever and
 * a dashboard that says "connected" intermittently while nothing is published.
 * The dialer stops instead and waits to be told to try again.
 */
const PERMANENT_RELAY_ERROR_CODES: ReadonlySet<string> = new Set([
  "unauthorized_control",
  "credential_revoked",
  "instance_not_entitled",
  "instance_slug_conflict",
  "no_common_protocol_version",
]);

export function isPermanentRelayError(code: string): boolean {
  return PERMANENT_RELAY_ERROR_CODES.has(code);
}

function assertPositiveFinite(name: string, value: number): void {
  if (typeof value !== "number" || !Number.isFinite(value) || value <= 0) {
    throw new Error(`${name} must be a positive finite number`);
  }
}