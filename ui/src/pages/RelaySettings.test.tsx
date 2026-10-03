// @vitest-environment jsdom

import { flushSync } from "react-dom";
import { createRoot, type Root } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const mockRelayApi = vi.hoisted(() => ({
  fetchRelayStatus: vi.fn(),
  fetchRelayCredentials: vi.fn(),
  issueRelayCredential: vi.fn(),
  revokeRelayCredential: vi.fn(),
  retryRelayConnection: vi.fn(),
}));

vi.mock("@/api/relay", () => mockRelayApi);

vi.mock("../context/BreadcrumbContext", () => ({
  useBreadcrumbs: () => ({ setBreadcrumbs: vi.fn() }),
}));

const { RelaySettingsPage } = await import("./RelaySettings");

let container: HTMLDivElement;
let root: Root;

async function act(callback: () => void | Promise<void>) {
  let result: void | Promise<void> = undefined;
  flushSync(() => {
    result = callback();
  });
  await result;
}

function render() {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: 0 } },
  });
  return act(() => {
    root.render(
      <QueryClientProvider client={client}>
        <RelaySettingsPage />
      </QueryClientProvider>,
    );
  });
}

async function settle(): Promise<void> {
  await act(async () => {
    await Promise.resolve();
  });
  await act(async () => {
    await new Promise((resolve) => setTimeout(resolve, 0));
  });
}

function text(): string {
  return container.textContent ?? "";
}

describe("RelaySettingsPage", () => {
  beforeEach(() => {
    container = document.createElement("div");
    document.body.appendChild(container);
    root = createRoot(container);
    mockRelayApi.fetchRelayStatus.mockResolvedValue({
      enabled: false,
      blockedReason: null,
      status: null,
    });
    mockRelayApi.fetchRelayCredentials.mockResolvedValue([]);
  });

  afterEach(() => {
    act(() => root.unmount());
    container.remove();
    vi.clearAllMocks();
  });

  it("explains how to turn publishing on when it is off", async () => {
    await render();
    await settle();
    expect(text()).toContain("Relay publishing is off");
    expect(text()).toContain("PAPERCLIP_RELAY_ENABLED");
  });

  it("surfaces the deployment-mode refusal instead of showing an empty status", async () => {
    mockRelayApi.fetchRelayStatus.mockResolvedValue({
      enabled: true,
      blockedReason:
        "refusing to publish this instance through a relay: it runs in PAPERCLIP_DEPLOYMENT_MODE=local_trusted",
      status: null,
    });
    await render();
    await settle();
    expect(text()).toContain("This instance cannot publish yet");
    expect(text()).toContain("local_trusted");
  });

  it("shows the slug and connected state when publishing", async () => {
    mockRelayApi.fetchRelayStatus.mockResolvedValue({
      enabled: true,
      blockedReason: null,
      status: {
        published: true,
        instanceSlug: "acme-laptop",
        sessionId: "sess-1",
        state: "connected",
        protocolVersion: 1,
        maxConcurrentStreams: 8,
        activeStreams: 2,
        lastErrorCode: null,
        lastErrorMessage: null,
      },
    });
    await render();
    await settle();
    expect(text()).toContain("acme-laptop");
    expect(text()).toContain("Connected");
    expect(text()).toContain("2 active of 8");
  });

  it("shows the stable error code when the relay refused", async () => {
    mockRelayApi.fetchRelayStatus.mockResolvedValue({
      enabled: true,
      blockedReason: null,
      status: {
        published: false,
        instanceSlug: "acme-laptop",
        sessionId: null,
        state: "refused",
        protocolVersion: null,
        maxConcurrentStreams: null,
        activeStreams: 0,
        lastErrorCode: "instance_not_entitled",
        lastErrorMessage: "subscription is not active",
      },
    });
    await render();
    await settle();
    expect(text()).toContain("instance_not_entitled");
    expect(text()).toContain("subscription is not active");
  });

  it("offers a retry only when refused, not while merely connecting", async () => {
    mockRelayApi.fetchRelayStatus.mockResolvedValue({
      enabled: true,
      blockedReason: null,
      status: {
        published: false,
        instanceSlug: "acme-laptop",
        sessionId: null,
        state: "connecting",
        protocolVersion: null,
        maxConcurrentStreams: null,
        activeStreams: 0,
        lastErrorCode: null,
        lastErrorMessage: null,
      },
    });
    await render();
    await settle();
    expect(text()).not.toContain("Retry");
  });

  it("shows the issued token once and says it cannot be shown again", async () => {
    mockRelayApi.issueRelayCredential.mockResolvedValue({
      credential: { id: "cred-1", label: "laptop" },
      token: "pcp_relay_abc123",
    });
    await render();
    await settle();

    await act(() => {
      const button = [...container.querySelectorAll("button")].find(
        (candidate) => candidate.textContent?.trim() === "Issue",
      );
      button?.click();
    });
    await settle();

    expect(text()).toContain("pcp_relay_abc123");
    expect(text()).toContain("cannot be shown again");
  });

  it("marks a revoked credential and refuses to revoke it twice", async () => {
    mockRelayApi.fetchRelayCredentials.mockResolvedValue([
      {
        id: "cred-1",
        label: "old laptop",
        issuedByUserId: "usr_1",
        lastUsedAt: "2026-06-01T00:00:00.000Z",
        revokedAt: "2026-06-02T00:00:00.000Z",
        expiresAt: null,
        createdAt: "2026-05-01T00:00:00.000Z",
      },
    ]);
    await render();
    await settle();

    expect(text()).toContain("old laptop");
    expect(text()).toContain("Revoked");
    const revoke = [...container.querySelectorAll("button")].find(
      (candidate) => candidate.textContent?.trim() === "Revoke",
    ) as HTMLButtonElement | undefined;
    expect(revoke?.disabled).toBe(true);
  });

  it("never renders a token hash", async () => {
    mockRelayApi.fetchRelayCredentials.mockResolvedValue([
      {
        id: "cred-1",
        label: "laptop",
        issuedByUserId: "usr_1",
        lastUsedAt: null,
        revokedAt: null,
        expiresAt: null,
        createdAt: "2026-05-01T00:00:00.000Z",
      },
    ]);
    await render();
    await settle();
    // The list endpoint returns metadata only; a hash appearing here would mean the
    // serializer leaked it.
    expect(text()).not.toMatch(/[0-9a-f]{64}/);
  });

  it("states that a credential grants no one access", async () => {
    await render();
    await settle();
    // The trust model is the part a reader most needs to get right.
    expect(text()).toContain("does not grant anyone access");
  });
});