import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  hashRelayCredential,
  issueRelayCredential,
  RelayGateError,
  type RelayCredentialStore,
  type RelayCredentialResolution,
} from "@paperclipai/paperclip-relay";

import { RelayRuntime } from "./index.js";
import { writeRelayToken } from "./token-store.js";

const ENABLED_ENV: NodeJS.ProcessEnv = {
  PAPERCLIP_RELAY_ENABLED: "true",
  PAPERCLIP_RELAY_URL: "wss://relay.example.com/control",
  PAPERCLIP_RELAY_INSTANCE_SLUG: "acme-laptop",
};

function createRuntime(
  overrides: Partial<ConstructorParameters<typeof RelayRuntime>[0]> = {},
  env: NodeJS.ProcessEnv = ENABLED_ENV,
): RelayRuntime {
  return new RelayRuntime({
    db: {} as never,
    deploymentMode: "authenticated",
    localBaseUrl: "http://127.0.0.1:3100",
    localAuthority: "127.0.0.1:3100",
    credentialStore: {
      resolveByToken: async (): Promise<RelayCredentialResolution> => ({ ok: false, reason: "unauthorized" }),
    },
    createControlSocket: () => {
      throw new Error("no socket should be created in these tests");
    },
    createTunnelSocket: () => {
      throw new Error("no socket should be created in these tests");
    },
    ...overrides,
    env,
  });
}

describe("RelayRuntime: the deployment-mode gate", () => {
  it("refuses to publish a local_trusted instance", () => {
    const runtime = createRuntime({ deploymentMode: "local_trusted" });
    // The single most important behaviour in this feature. local_trusted grants
    // unauthenticated instance-admin to anything that reaches the socket, and a
    // relay exists to make the socket reachable from the internet.
    expect(() => runtime.start()).toThrow(RelayGateError);
  });

  it("names authenticated mode as the way out", () => {
    let message = "";
    try {
      createRuntime({ deploymentMode: "local_trusted" }).start();
    } catch (error) {
      message = (error as Error).message;
    }
    expect(message).toContain("PAPERCLIP_DEPLOYMENT_MODE=authenticated");
  });

  it("opens no socket before refusing", () => {
    const createControlSocket = vi.fn(() => {
      throw new Error("should never be called");
    });
    const runtime = createRuntime({ deploymentMode: "local_trusted", createControlSocket });
    expect(() => runtime.start()).toThrow(RelayGateError);
    // Ordering, not just outcome: a gate that ran after connecting would have
    // already published this instance by the time it noticed.
    expect(createControlSocket).not.toHaveBeenCalled();
  });

  it("refuses an unrecognised deployment mode rather than assuming it is safe", () => {
    const runtime = createRuntime({ deploymentMode: "some_future_mode" as never });
    expect(() => runtime.start()).toThrow(RelayGateError);
  });

  it("explains the refusal without throwing, for a board UI", () => {
    const runtime = createRuntime({ deploymentMode: "local_trusted" });
    expect(runtime.blockedReason()).toContain("PAPERCLIP_DEPLOYMENT_MODE=authenticated");
  });

  it("reports no blockage when publishing is simply switched off", () => {
    // A disabled instance is not a broken one; the UI must not show an error.
    expect(createRuntime({}, {}).blockedReason()).toBeNull();
    expect(createRuntime({ deploymentMode: "local_trusted" }, {}).blockedReason()).toBeNull();
  });
});

describe("RelayRuntime: inert when disabled", () => {
  it("does nothing and stays disabled", () => {
    const runtime = createRuntime({}, { PAPERCLIP_RELAY_ENABLED: "false" });
    runtime.start();
    expect(runtime.currentStatus).toMatchObject({
      enabled: false,
      published: false,
      state: "disabled",
    });
  });

  it("is safe to start and stop repeatedly", () => {
    const runtime = createRuntime({}, {});
    expect(() => {
      runtime.start();
      runtime.start();
      runtime.stop();
      runtime.stop();
    }).not.toThrow();
  });

  it("does not connect when disabled", () => {
    const createControlSocket = vi.fn(() => {
      throw new Error("should never be called");
    });
    createRuntime({ createControlSocket }, {}).start();
    expect(createControlSocket).not.toHaveBeenCalled();
  });
});

describe("RelayRuntime: configuration", () => {
  it("refuses a half-configured relay rather than publishing nothing quietly", () => {
    const runtime = createRuntime({}, { PAPERCLIP_RELAY_ENABLED: "true" });
    expect(() => runtime.start()).toThrow(/PAPERCLIP_RELAY_URL/);
  });

  it("stays enabled but disconnected after a stop", () => {
    const runtime = createRuntime();
    // `enabled` is a configuration fact — this instance was told to publish — so
    // it survives a stop. Only the connection state changes.
    runtime.start().stop();
    expect(runtime.currentStatus).toMatchObject({
      enabled: true,
      published: false,
      state: "disconnected",
    });
  });

  it("preserves the slug it was configured with", () => {
    const runtime = createRuntime();
    runtime.start();
    expect(runtime.currentStatus.instanceSlug).toBe("acme-laptop");
    runtime.stop();
  });
});

describe("RelayRuntime: credential handling", () => {
  let tokenPath: string;
  let tempDir: string;

  beforeEach(async () => {
    const { mkdtemp } = await import("node:fs/promises");
    const { tmpdir } = await import("node:os");
    const { join } = await import("node:path");
    tempDir = await mkdtemp(join(tmpdir(), "paperclip-relay-runtime-"));
    tokenPath = join(tempDir, "relay-token.json");
  });

  afterEach(async () => {
    const { rm } = await import("node:fs/promises");
    await rm(tempDir, { recursive: true, force: true });
  });

  function withToken(token: string): NodeJS.ProcessEnv {
    return { ...ENABLED_ENV, PAPERCLIP_RELAY_STATE_PATH: tokenPath, __token: token } as NodeJS.ProcessEnv;
  }

  it("refuses to publish when no credential has been issued", async () => {
    const resolveByToken = vi.fn(async () => ({ ok: false as const, reason: "unauthorized" as const }));
    // No token store file at all: the ordinary state of an instance that has
    // never issued a credential.
    const runtime = createRuntime(
      { credentialStore: { resolveByToken } },
      { ...ENABLED_ENV, PAPERCLIP_RELAY_STATE_PATH: tokenPath },
    );

    runtime.start();
    await vi.waitFor(() => expect(runtime.currentStatus.state).toBe("refused"));
    // Nothing was presented, so the store was never even consulted.
    expect(resolveByToken).not.toHaveBeenCalled();
    runtime.stop();
  });

  it("does not present a credential the local store says is unusable", async () => {
    const issued = issueRelayCredential();
    await writeRelayToken({ token: issued.token, credentialId: "cred-1" }, tokenPath);

    const resolveByToken = vi.fn(async () => ({ ok: false as const, reason: "unauthorized" as const }));
    const runtime = createRuntime({ credentialStore: { resolveByToken } }, withToken(issued.token));
    runtime.start();

    // A locally revoked credential stops being presented immediately rather than
    // whenever the relay next rejects it.
    await vi.waitFor(() => expect(runtime.currentStatus.state).toBe("refused"));
    expect(resolveByToken).toHaveBeenCalledWith(issued.token);
    expect(runtime.currentStatus.lastErrorCode).toBe("unauthorized_control");
    runtime.stop();
  });

  it("presents a usable credential", async () => {
    const issued = issueRelayCredential();
    await writeRelayToken({ token: issued.token, credentialId: "cred-1" }, tokenPath);

    const resolveByToken = vi.fn(async () => ({
      ok: true as const,
      credential: {
        id: "cred-1",
        tokenHash: hashRelayCredential(issued.token),
        revokedAt: null,
        expiresAt: null,
      },
    }));
    const runtime = createRuntime({ credentialStore: { resolveByToken } }, withToken(issued.token));
    runtime.start();

    await vi.waitFor(() => expect(resolveByToken).toHaveBeenCalledTimes(1));
    expect(resolveByToken).toHaveBeenCalledWith(issued.token);
    runtime.stop();
  });
});

describe("RelayRuntime: status surface", () => {
  it("never exposes a credential or a token hash", () => {
    const runtime = createRuntime();
    runtime.start();
    const serialised = JSON.stringify(runtime.currentStatus);
    expect(serialised).not.toMatch(/pcp_relay_/);
    expect(serialised).not.toMatch(/[0-9a-f]{64}/);
    runtime.stop();
  });

  it("notifies status listeners and can be unsubscribed", () => {
    const runtime = createRuntime({}, {});
    const seen: string[] = [];
    const off = runtime.onStatus((status) => seen.push(status.state));
    runtime.start();
    runtime.stop();
    expect(seen.length).toBeGreaterThan(0);

    const before = seen.length;
    off();
    runtime.start();
    runtime.stop();
    expect(seen).toHaveLength(before);
  });

  it("survives a status listener that throws", () => {
    const runtime = createRuntime({}, {});
    runtime.onStatus(() => {
      throw new Error("status callback exploded");
    });
    // A broken status callback must not be able to break the lifecycle.
    expect(() => {
      runtime.start();
      runtime.stop();
    }).not.toThrow();
  });
});

describe("RelayRuntime: credential store contract", () => {
  it("issues a token whose hash round-trips", () => {
    // Documents the contract the store relies on, so a change to credential
    // hashing that breaks it fails here rather than at a live handshake.
    const issued = issueRelayCredential();
    expect(hashRelayCredential(issued.token)).toBe(issued.tokenHash);
  });

  it("treats every negative case identically to the caller", async () => {
    const store: RelayCredentialStore = {
      resolveByToken: async () => ({ ok: false, reason: "unauthorized" }),
    };
    const unknown = await store.resolveByToken("pcp_relay_never_existed");
    const revoked = await store.resolveByToken("pcp_relay_revoked");
    // Indistinguishable on purpose: telling an internet caller which tokens once
    // existed is a probe worth avoiding.
    expect(unknown).toEqual(revoked);
  });
});