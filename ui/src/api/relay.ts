import { readApiJson } from "./response";

/**
 * Client for the instance-level relay endpoints.
 *
 * The token field exists only on the issue response and is deliberately not part
 * of any type this module will re-read: the instance stores a hash, so the secret
 * is unrecoverable afterwards and there is nothing to fetch back.
 */

export interface RelayStatus {
  readonly published: boolean;
  readonly instanceSlug: string | null;
  readonly sessionId: string | null;
  readonly state: "disabled" | "connecting" | "connected" | "disconnected" | "refused";
  readonly protocolVersion: number | null;
  readonly maxConcurrentStreams: number | null;
  readonly activeStreams: number;
  readonly lastErrorCode: string | null;
  readonly lastErrorMessage: string | null;
}

export interface RelayStatusResponse {
  readonly enabled: boolean;
  readonly blockedReason: string | null;
  readonly status: RelayStatus | null;
}

export interface RelayCredential {
  readonly id: string;
  readonly label: string;
  readonly issuedByUserId: string;
  readonly lastUsedAt: string | null;
  readonly revokedAt: string | null;
  readonly expiresAt: string | null;
  readonly createdAt: string;
}

export interface IssuedRelayCredential {
  readonly credential: { readonly id: string; readonly label: string };
  /** Shown once. The instance keeps only a hash. */
  readonly token: string;
}

async function readErrorMessage(response: Response, fallback: string): Promise<never> {
  const body = await readApiJson(response).catch(() => null);
  const detail =
    typeof body === "object" && body !== null && "message" in body
      ? String((body as { message?: unknown }).message ?? "")
      : typeof body === "object" && body !== null && "error" in body
        ? String((body as { error?: unknown }).error ?? "")
        : "";
  throw new Error(detail.trim() || fallback);
}

export async function fetchRelayStatus(signal?: AbortSignal): Promise<RelayStatusResponse> {
  const response = await fetch("/api/relay/status", { credentials: "include", signal });
  if (!response.ok) await readErrorMessage(response, "Could not read relay status");
  return (await readApiJson(response)) as RelayStatusResponse;
}

export async function fetchRelayCredentials(signal?: AbortSignal): Promise<RelayCredential[]> {
  const response = await fetch("/api/relay/credentials", { credentials: "include", signal });
  if (!response.ok) await readErrorMessage(response, "Could not list relay credentials");
  const body = (await readApiJson(response)) as { credentials?: RelayCredential[] };
  return body.credentials ?? [];
}

export async function issueRelayCredential(label: string): Promise<IssuedRelayCredential> {
  const response = await fetch("/api/relay/credentials", {
    method: "POST",
    credentials: "include",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ label }),
  });
  if (!response.ok) await readErrorMessage(response, "Could not issue a relay credential");
  return (await readApiJson(response)) as IssuedRelayCredential;
}

export async function revokeRelayCredential(id: string): Promise<void> {
  const response = await fetch(`/api/relay/credentials/${encodeURIComponent(id)}/revoke`, {
    method: "POST",
    credentials: "include",
  });
  if (!response.ok) await readErrorMessage(response, "Could not revoke that relay credential");
}

export async function retryRelayConnection(): Promise<void> {
  const response = await fetch("/api/relay/retry", { method: "POST", credentials: "include" });
  if (!response.ok) await readErrorMessage(response, "Could not ask the dialer to retry");
}