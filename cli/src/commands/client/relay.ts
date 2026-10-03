import type { Command } from "commander";
import pc from "picocolors";

import {
  addCommonClientOptions,
  handleCommandError,
  printOutput,
  resolveCommandContext,
  type BaseClientOptions,
} from "./common.js";

interface RelayStatusOptions extends BaseClientOptions {}

interface RelayIssueOptions extends BaseClientOptions {
  label?: string;
}

interface RelayRevokeOptions extends BaseClientOptions {}

interface RelayCredentialRow {
  id: string;
  label: string;
  issuedByUserId: string;
  lastUsedAt: string | null;
  revokedAt: string | null;
  expiresAt: string | null;
  createdAt: string;
}

interface RelayStatusResponse {
  enabled: boolean;
  blockedReason: string | null;
  status: {
    published: boolean;
    instanceSlug: string | null;
    state: string;
    protocolVersion: number | null;
    maxConcurrentStreams: number | null;
    activeStreams: number;
    lastErrorCode: string | null;
    lastErrorMessage: string | null;
  } | null;
}

/**
 * `paperclipai relay …` — instance-level relay publishing commands.
 *
 * Every command here needs instance-admin access, because a relay credential
 * authenticates the instance to the relay. There is deliberately no per-user
 * credential and no command that names an actor: the subscriber's own Paperclip
 * session authenticates relayed requests inside the instance, so the relay's
 * authority never needs expressing.
 */
export function registerClientRelayCommands(relay: Command): void {
  addCommonClientOptions(
    relay
      .command("status")
      .description("Show relay publishing status")
      .action(async (opts: RelayStatusOptions) => {
        try {
          const ctx = resolveCommandContext(opts);
          const result = await ctx.api.get<RelayStatusResponse>("/api/relay/status");
          if (opts.json) {
            printOutput(result, { json: true });
            return;
          }
          printRelayStatus(result);
        } catch (error) {
          handleCommandError(error);
        }
      }),
  ),

  addCommonClientOptions(
    relay
      .command("credentials")
      .description("List relay credentials (never shows the secret)")
      .action(async (opts: RelayStatusOptions) => {
        try {
          const ctx = resolveCommandContext(opts);
          const result = await ctx.api.get<{ credentials: RelayCredentialRow[] }>(
            "/api/relay/credentials",
          );
          if (opts.json) {
            printOutput(result, { json: true });
            return;
          }
          const rows = result?.credentials ?? [];
          if (rows.length === 0) {
            console.log(pc.dim("No relay credentials yet."));
            return;
          }
          for (const row of rows) {
            const state = row.revokedAt
              ? pc.red("revoked")
              : row.expiresAt && new Date(row.expiresAt).getTime() <= Date.now()
                ? pc.yellow("expired")
                : pc.green("active");
            const lastUsed = row.lastUsedAt ? pc.dim(` last used ${row.lastUsedAt}`) : "";
            console.log(`${row.id}  ${row.label}  ${state}${lastUsed}`);
          }
        } catch (error) {
          handleCommandError(error);
        }
      }),
  ),

  addCommonClientOptions(
    relay
      .command("issue")
      .description("Issue a relay credential and store it on this instance")
      .option("--label <label>", "Human-readable label", "cli")
      .action(async (opts: RelayIssueOptions) => {
        try {
          const ctx = resolveCommandContext(opts);
          const result = await ctx.api.post<{ credential: { id: string; label: string }; token: string }>(
            "/api/relay/credentials",
            { label: opts.label },
          );
          if (opts.json) {
            printOutput(result, { json: true });
            return;
          }
          // Shown once and never again: the instance stores only a hash, so this
          // cannot be recovered later.
          console.log(pc.green("Relay credential issued."));
          console.log(`id:    ${result?.credential.id}`);
          console.log(`token: ${result?.token}`);
          console.log();
          console.log(pc.dim("Stored on this instance with 0600 permissions. Shown only once."));
        } catch (error) {
          handleCommandError(error);
        }
      }),
  ),

  addCommonClientOptions(
    relay
      .command("revoke")
      .description("Revoke a relay credential and stop presenting it")
      .argument("<id>", "Credential id")
      .action(async (id: string, opts: RelayRevokeOptions) => {
        try {
          const ctx = resolveCommandContext(opts);
          await ctx.api.post(`/api/relay/credentials/${encodeURIComponent(id)}/revoke`);
          console.log(pc.green("Revoked. The stored token was removed too."));
        } catch (error) {
          handleCommandError(error);
        }
      }),
  ),

  addCommonClientOptions(
    relay
      .command("retry")
      .description("Ask a refused dialer to try connecting again")
      .action(async (opts: RelayRevokeOptions) => {
        try {
          const ctx = resolveCommandContext(opts);
          await ctx.api.post("/api/relay/retry");
          console.log(pc.green("Retrying."));
        } catch (error) {
          handleCommandError(error);
        }
      }),
  );
}

function printRelayStatus(result: RelayStatusResponse | null): void {
  if (!result) {
    console.log(pc.dim("No relay status available."));
    return;
  }
  if (result.blockedReason) {
    console.log(pc.red("Blocked:"));
    console.log(result.blockedReason);
    return;
  }
  if (!result.enabled) {
    console.log(pc.dim("Relay publishing is off."));
    console.log(pc.dim("Set PAPERCLIP_RELAY_ENABLED=true and restart to publish this instance."));
    return;
  }

  const status = result.status;
  if (!status) {
    console.log(pc.dim("Relay publishing is on but has not connected yet."));
    return;
  }

  console.log(`slug:     ${status.instanceSlug ?? pc.dim("(none)")}`);
  console.log(`state:    ${status.published ? pc.green("connected") : pc.yellow(status.state)}`);
  if (status.protocolVersion !== null) {
    console.log(`protocol: v${status.protocolVersion}`);
  }
  if (status.maxConcurrentStreams !== null) {
    console.log(`streams:  ${status.activeStreams} active of ${status.maxConcurrentStreams}`);
  }
  if (status.lastErrorCode) {
    console.log();
    console.log(pc.red(`${status.lastErrorCode}: ${status.lastErrorMessage ?? ""}`));
  }
}