/**
 * Board routes for relay credentials and status.
 *
 * A relay credential authenticates the *instance* to the relay, not a person, so
 * every route here is instance-admin only. There is deliberately no per-user
 * credential and no endpoint that names an actor: the subscriber's own Paperclip
 * session authenticates relayed requests inside the instance, so the relay's
 * authority needs no expression here.
 */
import { Router, type Request } from "express";
import { and, desc, eq, isNull } from "drizzle-orm";
import { z } from "zod";

import {
  hashRelayCredential,
  isRelayCredentialShaped,
  issueRelayCredential,
} from "@paperclipai/paperclip-relay";
import { relayInstanceCredentials, relayInstanceSettings } from "@paperclipai/db";

import { badRequest, notFound } from "../errors.js";
import { assertInstanceAdmin } from "./authz.js";
import { logger } from "../middleware/logger.js";
import type { RelayRuntime } from "../services/relay/index.js";
import { deleteRelayToken, writeRelayToken } from "../services/relay/token-store.js";

const issueSchema = z.object({
  label: z.string().trim().min(1).max(80),
});

export function relayRoutes(db: any, runtime: RelayRuntime | null): Router {
  const router = Router();

  /**
   * Current state.
   *
   * Safe for any board user to read: it contains no credential, no token hash,
   * and no relay hostname beyond what the operator configured.
   */
  router.get("/status", (req: Request, res) => {
    assertInstanceAdmin(req);
    res.json({
      enabled: isEnabled(runtime),
      status: runtime?.currentStatus ?? null,
      blockedReason: runtime?.blockedReason() ?? null,
    });
  });

  /** Instance-admin only. Lists credential metadata; never the secret. */
  router.get("/credentials", async (req: Request, res, next) => {
    try {
      assertInstanceAdmin(req);
      const rows = await db
        .select({
          id: relayInstanceCredentials.id,
          label: relayInstanceCredentials.label,
          issuedByUserId: relayInstanceCredentials.issuedByUserId,
          lastUsedAt: relayInstanceCredentials.lastUsedAt,
          revokedAt: relayInstanceCredentials.revokedAt,
          expiresAt: relayInstanceCredentials.expiresAt,
          createdAt: relayInstanceCredentials.createdAt,
        })
        .from(relayInstanceCredentials)
        .orderBy(desc(relayInstanceCredentials.createdAt));

      res.json({ credentials: rows });
    } catch (error) {
      next(error);
    }
  });

  /**
   * Issue a credential and write its plaintext to the `0600` token store.
   *
   * The plaintext is returned exactly once, in this response. Only its hash is
   * persisted, which is why the token store file has to be written here rather
   * than reconstructed later.
   */
  router.post("/credentials", async (req: Request, res, next) => {
    try {
      assertInstanceAdmin(req);
      const parsed = issueSchema.safeParse(req.body);
      if (!parsed.success) {
        throw badRequest("label is required and must be at most 80 characters");
      }

      const issued = issueRelayCredential();
      const inserted = await db
        .insert(relayInstanceCredentials)
        .values({
          issuedByUserId: req.actor.userId,
          label: parsed.data.label,
          tokenHash: hashRelayCredential(issued.token),
        })
        .returning({ id: relayInstanceCredentials.id });

      const credentialId = inserted[0]?.id;
      if (!credentialId) {
        throw badRequest("could not persist the relay credential");
      }

      // Writing the token store is what makes the credential usable. If it fails
      // the row is revoked rather than left behind, so a credential nobody can
      // present does not linger looking active.
      try {
        await writeRelayToken({ token: issued.token, credentialId });
      } catch (error) {
        logger.error({ err: error, credentialId }, "could not write the relay token store");
        await revokeCredentialRow(db, credentialId);
        throw badRequest("could not store the relay credential on this instance");
      }

      runtime?.retry();

      res.status(201).json({
        credential: { id: credentialId, label: parsed.data.label },
        // Shown once. The database holds only a hash, so this cannot be recovered.
        token: issued.token,
      });
    } catch (error) {
      next(error);
    }
  });

  /**
   * Revoke a credential.
   *
   * Timestamped rather than deleted, so a revoked credential stays auditable and
   * the dialer's store check can tell "revoked" from "never existed".
   */
  router.post("/credentials/:id/revoke", async (req: Request, res, next) => {
    try {
      assertInstanceAdmin(req);
      const id = req.params.id;
      if (typeof id !== "string" || id.length === 0) {
        throw badRequest("a credential id is required");
      }

      const updated = await revokeCredentialRow(db, id);
      if (updated === 0) {
        throw notFound("no such relay credential");
      }

      // Remove the presented token too, so revocation is immediate rather than
      // waiting for the relay to reject the next connection.
      await deleteRelayToken();
      await persistConnectionState(db, "refused", "credential_revoked", "the relay credential was revoked");

      res.json({ revoked: true });
    } catch (error) {
      next(error);
    }
  });

  /** Instance-admin only. Clears the last recorded error and asks for a retry. */
  router.post("/retry", async (req: Request, res, next) => {
    try {
      assertInstanceAdmin(req);
      runtime?.retry();
      await persistConnectionState(db, "connecting", null, null);
      res.json({ retried: true, status: runtime?.currentStatus ?? null });
    } catch (error) {
      next(error);
    }
  });

  return router;
}

function isEnabled(runtime: RelayRuntime | null): boolean {
  return runtime?.currentStatus.enabled ?? false;
}

async function revokeCredentialRow(db: any, id: string): Promise<number> {
  const rows = await db
    .update(relayInstanceCredentials)
    .set({ revokedAt: new Date(), updatedAt: new Date() })
    .where(and(eq(relayInstanceCredentials.id, id), isNull(relayInstanceCredentials.revokedAt)))
    .returning({ id: relayInstanceCredentials.id });
  return rows.length;
}

/**
 * Record the connection state for the board UI.
 *
 * Never carries a credential or a token hash. This is a display value only —
 * liveness is a property of the open socket, and nothing in the authorisation
 * path reads this row.
 */
export async function persistConnectionState(
  db: any,
  state: string,
  errorCode: string | null,
  errorMessage: string | null,
): Promise<void> {
  try {
    const now = new Date();
    await db
      .insert(relayInstanceSettings)
      .values({
        singletonKey: "default",
        connectionState: state,
        lastErrorCode: errorCode,
        lastErrorMessage: errorMessage === null ? null : errorMessage.slice(0, 512),
        ...(state === "connected" ? { lastConnectedAt: now } : {}),
        ...(state === "disconnected" || state === "refused" ? { lastDisconnectedAt: now } : {}),
        updatedAt: now,
      })
      .onConflictDoUpdate({
        target: relayInstanceSettings.singletonKey,
        set: {
          connectionState: state,
          lastErrorCode: errorCode,
          lastErrorMessage: errorMessage === null ? null : errorMessage.slice(0, 512),
          updatedAt: now,
        },
      });
  } catch (error) {
    logger.warn({ err: error }, "could not persist relay connection state");
  }
}

/** Narrowing guard used by the UI-facing serializers. */
export function isRelayCredentialShapedForTransport(value: unknown): value is string {
  return isRelayCredentialShaped(value);
}