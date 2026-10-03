/**
 * Environment-driven configuration for the relay client half.
 *
 * Every value is validated and every missing or contradictory combination makes
 * the loader throw, so a misconfigured instance fails at startup with a sentence
 * an operator can act on instead of silently not publishing. This mirrors
 * `packages/tailscale-https-broker/src/config.ts`.
 *
 * Relay **credentials** are deliberately absent from this file. They are issued
 * per board user, stored hashed in the instance database, and rotated from the
 * board UI or the CLI, because a 256-bit secret that lives in an environment
 * variable ends up in `docker inspect` output, systemd unit dumps, and process
 * listings. Only non-secret connection settings come from the environment.
 */
import { isInstanceSlug } from "./protocol/validate.js";

export interface RelayClientConfig {
  /** Relay control endpoint, always `ws:` or `wss:`. */
  readonly url: string;
  /** Slug this instance publishes as. Unique on the relay. */
  readonly instanceSlug: string;
  /**
   * Local concurrency ceiling, independent of whatever the relay advertises.
   *
   * The relay's number is authoritative for its own capacity, but a dialer that
   * accepts only what a peer says it can accept has no floor of its own. This is
   * the local floor.
   */
  readonly maxConcurrentStreams: number;
  /** True when `url` is `ws:` and the operator has explicitly allowed it. */
  readonly insecureTransportAllowed: boolean;
  /** Version reported in `hello`; null when it could not be resolved. */
  readonly paperclipVersion: string | null;
}

export interface RelayConfigOptions {
  /**
   * Version reported to the relay in the `hello` handshake.
   *
   * Optional because the value comes from the Paperclip package manifest rather
   * than from configuration; a development checkout may not be able to resolve
   * it at all, and `hello` carries a nullable version precisely so an unknown
   * version is reported as unknown rather than invented.
   */
  readonly paperclipVersion?: string | null;
}

const ENV_ENABLED = "PAPERCLIP_RELAY_ENABLED";
const ENV_URL = "PAPERCLIP_RELAY_URL";
const ENV_SLUG = "PAPERCLIP_RELAY_INSTANCE_SLUG";
const ENV_MAX_STREAMS = "PAPERCLIP_RELAY_MAX_STREAMS";
const ENV_ALLOW_INSECURE = "PAPERCLIP_RELAY_ALLOW_INSECURE_TRANSPORT";

const DEFAULT_MAX_CONCURRENT_STREAMS = 8;

/**
 * Is relay publishing switched on?
 *
 * Absent or unrecognised means off. A typo in an operator's env must not
 * silently enable a public tunnel, so only these literals turn it on.
 */
export function isRelayEnabled(env: NodeJS.ProcessEnv): boolean {
  const raw = env[ENV_ENABLED]?.trim().toLowerCase();
  return raw === "true" || raw === "1";
}

export class RelayConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RelayConfigError";
  }
}

/**
 * Load relay connection settings.
 *
 * @returns `null` when relay publishing is off. Throws when it is on but the
 *   configuration cannot be used.
 */
export function loadRelayConfig(
  env: NodeJS.ProcessEnv,
  options: RelayConfigOptions = {},
): RelayClientConfig | null {
  if (!isRelayEnabled(env)) return null;

  const rawUrl = requireEnv(env, ENV_URL);
  const url = parseRelayUrl(rawUrl);

  const instanceSlug = requireSlug(env, ENV_SLUG);
  const insecureTransportAllowed = parseBooleanFlag(env, ENV_ALLOW_INSECURE);

  if (url.protocol === "ws:" && !insecureTransportAllowed) {
    throw new RelayConfigError(
      `refusing to publish over an unencrypted control channel: ${ENV_URL} is ws:. `
      + `The relay credential is presented on this socket as a bearer token, so a plain `
      + `connection hands it to anyone on the path. Terminate TLS and use wss:, or set `
      + `${ENV_ALLOW_INSECURE}=true if you are deliberately testing on a trusted network.`,
    );
  }

  const maxConcurrentStreams = parsePositiveInt(env, ENV_MAX_STREAMS) ?? DEFAULT_MAX_CONCURRENT_STREAMS;

  return {
    url: url.toString(),
    instanceSlug,
    maxConcurrentStreams,
    insecureTransportAllowed,
    paperclipVersion: options.paperclipVersion ?? null,
  };
}

/**
 * Validate the relay endpoint.
 *
 * Only `ws:` and `wss:` are accepted. Embedded userinfo is refused outright: a
 * URL that carries its own credentials is a URL that ends up in log lines and
 * crash reports, and nothing here needs one. Query strings are allowed because
 * a relay may route control sockets by path or tenant, but they are not where a
 * secret belongs.
 */
export function parseRelayUrl(raw: string): URL {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new RelayConfigError(`${ENV_URL} is not a valid URL`);
  }

  if (url.protocol !== "ws:" && url.protocol !== "wss:") {
    throw new RelayConfigError(`${ENV_URL} must use ws: or wss: (received ${url.protocol})`);
  }
  if (url.username !== "" || url.password !== "") {
    throw new RelayConfigError(`${ENV_URL} must not embed credentials; use a relay credential instead`);
  }
  if (url.hostname === "") {
    throw new RelayConfigError(`${ENV_URL} must include a host`);
  }
  return url;
}

function requireEnv(env: NodeJS.ProcessEnv, key: string): string {
  const value = env[key]?.trim();
  if (!value) {
    throw new RelayConfigError(`${key} is required when ${ENV_ENABLED} is on`);
  }
  return value;
}

function requireSlug(env: NodeJS.ProcessEnv, key: string): string {
  const value = requireEnv(env, key);
  // Reuses the wire validator rather than restating the rule, so a slug that
  // passes configuration cannot fail later at the handshake.
  if (!isInstanceSlug(value)) {
    throw new RelayConfigError(
      `${key} must be a lowercase alphanumeric slug of 2-40 characters so it can be a DNS label`,
    );
  }
  return value;
}

function parseBooleanFlag(env: NodeJS.ProcessEnv, key: string): boolean {
  const raw = env[key]?.trim().toLowerCase();
  return raw === "true" || raw === "1";
}

function parsePositiveInt(env: NodeJS.ProcessEnv, key: string): number | null {
  const raw = env[key]?.trim();
  if (!raw) return null;
  if (!/^[0-9]+$/.test(raw) || (raw.length > 1 && raw[0] === "0")) {
    throw new RelayConfigError(`${key} must be a canonical positive integer`);
  }
  const parsed = Number(raw);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    throw new RelayConfigError(`${key} must be a positive integer`);
  }
  return parsed;
}