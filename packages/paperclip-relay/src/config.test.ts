import { describe, expect, it } from "vitest";

import { isRelayEnabled, loadRelayConfig, type RelayClientConfig, RelayConfigError } from "./config.js";

function enabledEnv(overrides: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv {
  return {
    PAPERCLIP_RELAY_ENABLED: "true",
    PAPERCLIP_RELAY_URL: "wss://relay.example.com/tunnel",
    PAPERCLIP_RELAY_INSTANCE_SLUG: "acme-laptop",
    ...overrides,
  };
}

describe("isRelayEnabled", () => {
  it("is off when the variable is absent", () => {
    expect(isRelayEnabled({})).toBe(false);
  });

  it("is off for any unrecognised value, so a typo cannot publish a tunnel", () => {
    for (const value of ["", "yes", "on", "false", "0", "TRUEISH"]) {
      expect(isRelayEnabled({ PAPERCLIP_RELAY_ENABLED: value })).toBe(false);
    }
  });

  it("is on only for the two affirmative literals, case- and space-insensitively", () => {
    expect(isRelayEnabled({ PAPERCLIP_RELAY_ENABLED: "true" })).toBe(true);
    expect(isRelayEnabled({ PAPERCLIP_RELAY_ENABLED: " TRUE " })).toBe(true);
    expect(isRelayEnabled({ PAPERCLIP_RELAY_ENABLED: "1" })).toBe(true);
  });
});

describe("loadRelayConfig", () => {
  it("returns null when relay publishing is off, without validating anything else", () => {
    expect(loadRelayConfig({})).toBeNull();
    // A broken URL alongside a disabled flag must not throw: an operator who has
    // not opted in should not be blocked by a half-finished configuration.
    expect(loadRelayConfig({ PAPERCLIP_RELAY_URL: "nonsense" })).toBeNull();
  });

  it("loads a complete wss configuration", () => {
    const config = loadRelayConfig(enabledEnv(), { paperclipVersion: "0.3.1" });
    expect(config).toEqual({
      url: "wss://relay.example.com/tunnel",
      instanceSlug: "acme-laptop",
      maxConcurrentStreams: 8,
      insecureTransportAllowed: false,
      paperclipVersion: "0.3.1",
    });
  });

  it("defaults the version to null rather than inventing one", () => {
    const config = loadRelayConfig(enabledEnv());
    expect(config?.paperclipVersion).toBeNull();
  });

  it("requires the URL", () => {
    expect(() => loadRelayConfig({ PAPERCLIP_RELAY_ENABLED: "true" })).toThrow(/PAPERCLIP_RELAY_URL/);
  });

  it("requires the slug", () => {
    expect(() =>
      loadRelayConfig({ PAPERCLIP_RELAY_ENABLED: "true", PAPERCLIP_RELAY_URL: "wss://r.example.com" }),
    ).toThrow(/PAPERCLIP_RELAY_INSTANCE_SLUG/);
  });

  it("refuses a slug that cannot be a DNS label", () => {
    for (const slug of ["Acme-Laptop", "acme_laptop", "a", "-acme", "acme-", "acme laptop"]) {
      expect(() => loadRelayConfig(enabledEnv({ PAPERCLIP_RELAY_INSTANCE_SLUG: slug }))).toThrow(
        RelayConfigError,
      );
    }
  });

  it("refuses an http or https relay URL", () => {
    for (const url of ["http://relay.example.com", "https://relay.example.com"]) {
      expect(() => loadRelayConfig(enabledEnv({ PAPERCLIP_RELAY_URL: url }))).toThrow(
        /must use ws: or wss:/,
      );
    }
  });

  it("refuses a URL carrying embedded credentials", () => {
    expect(() =>
      loadRelayConfig(enabledEnv({ PAPERCLIP_RELAY_URL: "wss://user:pass@relay.example.com" })),
    ).toThrow(/must not embed credentials/);
  });

  it("refuses an unparseable URL", () => {
    expect(() => loadRelayConfig(enabledEnv({ PAPERCLIP_RELAY_URL: "not a url" }))).toThrow(
      RelayConfigError,
    );
  });

  describe("transport security", () => {
    it("refuses ws: by default, naming both ways out", () => {
      let message = "";
      try {
        loadRelayConfig(enabledEnv({ PAPERCLIP_RELAY_URL: "ws://relay.local:8080" }));
      } catch (error) {
        message = (error as Error).message;
      }
      expect(message).toContain("wss:");
      expect(message).toContain("PAPERCLIP_RELAY_ALLOW_INSECURE_TRANSPORT");
    });

    it("allows ws: only after an explicit opt-in", () => {
      const config = loadRelayConfig(
        enabledEnv({
          PAPERCLIP_RELAY_URL: "ws://relay.local:8080",
          PAPERCLIP_RELAY_ALLOW_INSECURE_TRANSPORT: "true",
        }),
      );
      expect(config?.url).toBe("ws://relay.local:8080/");
      expect(config?.insecureTransportAllowed).toBe(true);
    });

    it("treats a junk opt-in value as not opted in", () => {
      expect(() =>
        loadRelayConfig(
          enabledEnv({
            PAPERCLIP_RELAY_URL: "ws://relay.local:8080",
            PAPERCLIP_RELAY_ALLOW_INSECURE_TRANSPORT: "yes",
          }),
        ),
      ).toThrow(RelayConfigError);
    });

    it("does not mark a wss configuration as insecure", () => {
      const config = loadRelayConfig(enabledEnv());
      expect(config?.insecureTransportAllowed).toBe(false);
    });
  });

  describe("local stream ceiling", () => {
    it("defaults to 8", () => {
      expect(loadRelayConfig(enabledEnv())?.maxConcurrentStreams).toBe(8);
    });

    it("is overridable", () => {
      const config = loadRelayConfig(enabledEnv({ PAPERCLIP_RELAY_MAX_STREAMS: "16" }));
      expect(config?.maxConcurrentStreams).toBe(16);
    });

    it("refuses a non-canonical or non-positive value instead of silently defaulting", () => {
      for (const value of ["0", "-1", "016", "1.5", "abc", " 8 8"]) {
        expect(() => loadRelayConfig(enabledEnv({ PAPERCLIP_RELAY_MAX_STREAMS: value }))).toThrow(
          RelayConfigError,
        );
      }
    });
  });

  it("returns a frozen-shaped config with every documented field present", () => {
    const config: RelayClientConfig | null = loadRelayConfig(enabledEnv());
    expect(Object.keys(config ?? {}).sort()).toEqual([
      "insecureTransportAllowed",
      "instanceSlug",
      "maxConcurrentStreams",
      "paperclipVersion",
      "url",
    ]);
  });
});