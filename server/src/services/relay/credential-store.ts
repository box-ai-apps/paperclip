/**
 * The credential source the dialer uses to authenticate itself to the relay.
 *
 * Reads `relay_instance_credentials`, verifies the presented token against the
 * stored hash in constant time, and refuses anything revoked or expired.
 *
 * Every negative case resolves to the same `unauthorized` reason. Distinguishing
 * "unknown" from "revoked" for a caller on the internet hands an attacker a probe
 * for which tokens once existed, so the distinction is left to this module's own
 * logging rather than to the response.
 */
import { and, eq, isNull } from "drizzle-orm";

import {
  hashRelayCredential,
  isRelayCredentialLive,
  type RelayCredentialResolution,
  type RelayCredentialStore,
  verifyRelayCredential,
} from "@paperclipai/paperclip-relay";
import { relayInstanceCredentials } from "@paperclipai/db";
import { logger } from "../../middleware/logger.js";

export type RelayDb = {
  select: unknown;
  update: unknown;
  insert: unknown;
};

/**
 * Resolve a presented relay credential.
 *
 * The lookup is by hash rather than by token so the database never sees a
 * plaintext secret, matching how the instance's other credential tables work.
 */
export function createRelayCredentialStore(db: RelayDb): RelayCredentialStore {
  return {
    async resolveByToken(token: string, now: Date = new Date()): Promise<RelayCredentialResolution> {
      const tokenHash = hashRelayCredential(token);
      const rows = await (db as any)
        .select({
          id: relayInstanceCredentials.id,
          tokenHash: relayInstanceCredentials.tokenHash,
          revokedAt: relayInstanceCredentials.revokedAt,
          expiresAt: relayInstanceCredentials.expiresAt,
          label: relayInstanceCredentials.label,
        })
        .from(relayInstanceCredentials)
        .where(eq(relayInstanceCredentials.tokenHash, tokenHash))
        .limit(1);

      const row = rows[0] as
        | {
            id: string;
            tokenHash: string;
            revokedAt: Date | null;
            expiresAt: Date | null;
            label: string;
          }
        | undefined;

      if (!row) return { ok: false, reason: "unauthorized" };

      if (!verifyRelayCredential(token, row.tokenHash)) {
        // The hash matched the lookup key but not the constant-time comparison,
        // which means the stored value is malformed. Fail closed.
        logger.error({ credentialId: row.id }, "relay credential hash did not verify");
        return { ok: false, reason: "unauthorized" };
      }

      if (!isRelayCredentialLive(row, now)) {
        // Logged distinctly because an operator needs to know a revoked
        // credential is still being presented.
        logger.warn(
          {
            credentialId: row.id,
            label: row.label,
            revoked: row.revokedAt !== null,
            expired: row.expiresAt !== null,
          },
          "refused a revoked or expired relay credential",
        );
        return { ok: false, reason: "unauthorized" };
      }

      // Best-effort. A failure to record use must not stop a legitimate dialer
      // from connecting, so it is logged rather than propagated.
      void touchCredential(db, row.id);

      return {
        ok: true,
        credential: {
          id: row.id,
          tokenHash: row.tokenHash,
          revokedAt: row.revokedAt,
          expiresAt: row.expiresAt,
        },
      };
    },
  };
}

async function touchCredential(db: RelayDb, credentialId: string): Promise<void> {
  try {
    // Guarded on `revokedAt IS NULL` so a use recorded microseconds before a
    // revocation cannot resurrect the row's timestamp ordering.
    await (db as any)
      .update(relayInstanceCredentials)
      .set({ lastUsedAt: new Date(), updatedAt: new Date() })
      .where(
        and(
          eq(relayInstanceCredentials.id, credentialId),
          isNull(relayInstanceCredentials.revokedAt),
        ),
      );
  } catch (error) {
    logger.warn(
      { err: error, credentialId },
      "could not record relay credential use",
    );
  }
}