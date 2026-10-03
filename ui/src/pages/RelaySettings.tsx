import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, Copy, KeyRound, RefreshCw, ShieldAlert } from "lucide-react";

import {
  fetchRelayCredentials,
  fetchRelayStatus,
  issueRelayCredential,
  type RelayCredential,
  retryRelayConnection,
  revokeRelayCredential,
} from "@/api/relay";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { useBreadcrumbs } from "@/context/BreadcrumbContext";

const STATUS_TONE: Record<string, "default" | "secondary" | "destructive" | "outline"> = {
  connected: "default",
  connecting: "secondary",
  refused: "destructive",
  disconnected: "secondary",
  disabled: "outline",
};

function credentialState(credential: RelayCredential): {
  label: string;
  variant: "default" | "secondary" | "outline";
} {
  if (credential.revokedAt) return { label: "Revoked", variant: "outline" };
  if (credential.expiresAt && new Date(credential.expiresAt).getTime() <= Date.now()) {
    return { label: "Expired", variant: "outline" };
  }
  if (credential.lastUsedAt) return { label: "Active", variant: "default" };
  return { label: "Unused", variant: "secondary" };
}

export function RelaySettingsPage() {
  const queryClient = useQueryClient();
  const { setBreadcrumbs } = useBreadcrumbs();
  const [label, setLabel] = useState("");
  const [issuedToken, setIssuedToken] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const status = useQuery({
    queryKey: ["relay", "status"],
    queryFn: ({ signal }) => fetchRelayStatus(signal),
  });

  const credentials = useQuery({
    queryKey: ["relay", "credentials"],
    queryFn: ({ signal }) => fetchRelayCredentials(signal),
  });

  const issue = useMutation({
    mutationFn: (value: string) => issueRelayCredential(value),
    onSuccess: (result) => {
      setIssuedToken(result.token);
      setCopied(false);
      setLabel("");
      void queryClient.invalidateQueries({ queryKey: ["relay"] });
    },
  });

  const revoke = useMutation({
    mutationFn: (id: string) => revokeRelayCredential(id),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["relay"] });
    },
  });

  const retry = useMutation({
    mutationFn: () => retryRelayConnection(),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["relay"] });
    },
  });

  const relay = status.data;
  const blocked = relay?.blockedReason ?? null;
  const live = relay?.status ?? null;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-bold">Relay publishing</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Publish this instance through a relay so it can be reached from anywhere, without opening an
          inbound port. The instance dials out and holds the connection open, so it works from behind a
          home router, a corporate NAT, or a cloud firewall.
        </p>
      </div>

      {blocked ? (
        <Card className="border-destructive/40 p-4">
          <div className="flex gap-3">
            <ShieldAlert aria-hidden="true" className="mt-0.5 size-4 shrink-0 text-destructive" />
            <div className="space-y-2">
              <p className="text-sm font-semibold">This instance cannot publish yet</p>
              <p className="text-sm text-muted-foreground">{blocked}</p>
            </div>
          </div>
        </Card>
      ) : null}

      <Card className="p-4">
        <div className="flex items-center justify-between gap-4">
          <div className="space-y-1">
            <p className="text-sm font-semibold">Status</p>
            <p className="text-xs text-muted-foreground">
              {!relay
                ? "Loading…"
                : !relay.enabled
                  ? "Relay publishing is off. Set PAPERCLIP_RELAY_ENABLED=true and restart to publish."
                  : live?.instanceSlug
                    ? `Published as ${live.instanceSlug}`
                    : "Publishing is on but has not connected yet."}
            </p>
          </div>
          <div className="flex shrink-0 items-center gap-2">
            {live ? (
              <Badge variant={STATUS_TONE[live.state] ?? "outline"}>
                {live.state === "connected" ? "Connected" : live.state}
              </Badge>
            ) : null}
            {relay?.enabled && live?.state === "refused" ? (
              <Button variant="outline" size="sm" onClick={() => retry.mutate()} disabled={retry.isPending}>
                <RefreshCw aria-hidden="true" />
                Retry
              </Button>
            ) : null}
          </div>
        </div>

        {live && (live.protocolVersion !== null || live.maxConcurrentStreams !== null) ? (
          <div className="mt-4 grid gap-2 sm:grid-cols-2">
            <PropertyRow label="Protocol version" value={live.protocolVersion ? `v${live.protocolVersion}` : null} />
            <PropertyRow
              label="Streams"
              value={
                live.maxConcurrentStreams === null
                  ? null
                  : `${live.activeStreams} active of ${live.maxConcurrentStreams}`
              }
            />
          </div>
        ) : null}

        {live?.lastErrorCode ? (
          <div className="mt-4 flex gap-2 rounded-md bg-destructive/10 p-3">
            <AlertTriangle aria-hidden="true" className="mt-0.5 size-4 shrink-0 text-destructive" />
            <div>
              <p className="text-sm font-medium text-destructive">{live.lastErrorCode}</p>
              {live.lastErrorMessage ? (
                <p className="text-xs text-muted-foreground">{live.lastErrorMessage}</p>
              ) : null}
            </div>
          </div>
        ) : null}
      </Card>

      {issuedToken ? (
        <Card className="border-primary/40 p-4">
          <div className="space-y-3">
            <div className="flex items-center gap-2">
              <KeyRound aria-hidden="true" className="size-4 text-primary" />
              <p className="text-sm font-semibold">Credential issued</p>
            </div>
            <p className="text-sm text-muted-foreground">
              Copy this now. The instance keeps only a hash, so the token cannot be shown again.
            </p>
            <div className="flex items-center gap-2">
              <code className="flex-1 rounded-md bg-muted p-3 font-mono text-xs break-all">
                {issuedToken}
              </code>
              <Button
                variant="outline"
                size="sm"
                onClick={() => {
                  void navigator.clipboard?.writeText(issuedToken);
                  setCopied(true);
                }}
              >
                <Copy aria-hidden="true" />
                {copied ? "Copied" : "Copy"}
              </Button>
            </div>
            <Button variant="ghost" size="sm" onClick={() => setIssuedToken(null)}>
              Done
            </Button>
          </div>
        </Card>
      ) : null}

      <Card className="p-4">
        <div className="space-y-4">
          <div>
            <p className="text-sm font-semibold">Credentials</p>
            <p className="text-xs text-muted-foreground">
              A credential authenticates this instance to the relay. It does not grant anyone access:
              subscribers authenticate with their own Paperclip session, and the relay never learns who
              they are.
            </p>
          </div>

          <div className="flex items-end gap-2">
            <div className="flex-1 space-y-1">
              <label className="text-xs text-muted-foreground" htmlFor="relay-credential-label">
                Label
              </label>
              <Input
                id="relay-credential-label"
                value={label}
                placeholder="laptop"
                maxLength={80}
                onChange={(event) => setLabel(event.target.value)}
              />
            </div>
            <Button
              onClick={() => issue.mutate(label.trim() || "cli")}
              disabled={issue.isPending}
            >
              Issue
            </Button>
          </div>

          {issue.isError ? (
            <p className="text-xs text-destructive">{String(issue.error?.message ?? issue.error)}</p>
          ) : null}

          {credentials.data && credentials.data.length > 0 ? (
            <div className="divide-y divide-border rounded-md border border-border">
              {credentials.data.map((credential) => {
                const state = credentialState(credential);
                return (
                  <div key={credential.id} className="flex items-center justify-between gap-3 p-3">
                    <div className="min-w-0 space-y-0.5">
                      <div className="flex items-center gap-2">
                        <span className="truncate text-sm font-medium">{credential.label}</span>
                        <Badge variant={state.variant}>{state.label}</Badge>
                      </div>
                      <p className="text-xs text-muted-foreground">
                        {credential.lastUsedAt
                          ? `Last used ${new Date(credential.lastUsedAt).toLocaleString()}`
                          : `Created ${new Date(credential.createdAt).toLocaleString()}`}
                      </p>
                    </div>
                    <Button
                      variant="outline"
                      size="sm"
                      disabled={Boolean(credential.revokedAt) || revoke.isPending}
                      onClick={() => revoke.mutate(credential.id)}
                    >
                      Revoke
                    </Button>
                  </div>
                );
              })}
            </div>
          ) : (
            <p className="text-xs text-muted-foreground">No credentials yet.</p>
          )}

          {revoke.isError ? (
            <p className="text-xs text-destructive">{String(revoke.error?.message ?? revoke.error)}</p>
          ) : null}
        </div>
      </Card>
    </div>
  );
}

function PropertyRow({ label, value }: { label: string; value: string | null }) {
  return (
    <div className="flex items-center justify-between py-1">
      <span className="text-xs text-muted-foreground">{label}</span>
      <span className="font-mono text-xs">{value}</span>
    </div>
  );
}