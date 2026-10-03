/**
 * Where the dialer gets the token it presents to the relay.
 *
 * The database holds only a hash — a plaintext secret in a table would be
 * exfiltrated by any read-only dump — so it cannot be the source. The
 * environment is rejected for the same reason it is rejected for the config: a
 * secret in an env var ends up in `docker inspect` output, systemd unit dumps, and
 * process listings.
 *
 * A `0600` file under the instance's data directory is the third option, and the
 * one the CLI already uses for its own credential (`cli/src/config/home.ts`).
 * The file is written when a credential is issued and removed when it is revoked,
 * so a local revocation takes effect at the next dial without waiting for the
 * relay to notice.
 */
import { chmod, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";

import { logger } from "../../middleware/logger.js";

const RELAY_STORE_VERSION = 1;

interface RelayTokenStoreShape {
  version: number;
  /** Plaintext token. Never logged, never serialised to the board UI. */
  token: string;
  credentialId: string;
  issuedAt: string;
}

/** Resolve the directory holding relay state, alongside the instance's data. */
export function relayTokenStorePath(env: NodeJS.ProcessEnv = process.env): string {
  const override = env.PAPERCLIP_RELAY_STATE_PATH?.trim();
  if (override) return override;
  const home = env.PAPERCLIP_HOME?.trim() || join(env.HOME ?? env.USERPROFILE ?? process.cwd(), ".paperclip");
  return join(home, "relay-token.json");
}

/**
 * Read the stored token.
 *
 * Returns null when there is none, which the dialer treats as "nothing to publish
 * with" and refuses permanently. A missing file is an ordinary state for an
 * instance that has never issued a credential, not an error.
 */
export async function readRelayToken(path?: string): Promise<string | null> {
  const target = path ?? relayTokenStorePath();
  let raw: string;
  try {
    raw = await readFile(target, "utf8");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
    logger.warn({ err: error }, "could not read the relay token store");
    return null;
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    logger.error({ path: target }, "the relay token store is not valid JSON");
    return null;
  }

  if (typeof parsed !== "object" || parsed === null) return null;
  const store = parsed as Partial<RelayTokenStoreShape>;
  if (store.version !== RELAY_STORE_VERSION) {
    logger.error({ path: target, version: store.version }, "unsupported relay token store version");
    return null;
  }
  if (typeof store.token !== "string" || store.token.length === 0) return null;
  return store.token;
}

/**
 * Write a newly issued token with owner-only permissions.
 *
 * The file is written `0600` and its directory `0700` before the token lands in
 * it. Written the other way round there is a window in which the secret exists on
 * disk with looser permissions, which on a shared machine is long enough.
 */
export async function writeRelayToken(
  input: { token: string; credentialId: string },
  path?: string,
): Promise<void> {
  const target = path ?? relayTokenStorePath();
  await mkdir(dirname(target), { recursive: true, mode: 0o700 });
  // `writeFile` honours mode only when creating, so an existing file keeps
  // whatever it had. Force it either way.
  await writeFile(target, JSON.stringify({
    version: RELAY_STORE_VERSION,
    token: input.token,
    credentialId: input.credentialId,
    issuedAt: new Date().toISOString(),
  } satisfies RelayTokenStoreShape), { encoding: "utf8", mode: 0o600 });
  await chmod(target, 0o600);
}

/**
 * Remove the stored token.
 *
 * Used on revocation and on rotation, so a rotated-out credential stops being
 * presented immediately rather than whenever the relay next rejects it.
 */
export async function deleteRelayToken(path?: string): Promise<void> {
  const target = path ?? relayTokenStorePath();
  try {
    await rm(target, { force: true });
  } catch (error) {
    logger.warn({ err: error }, "could not remove the relay token store");
  }
}