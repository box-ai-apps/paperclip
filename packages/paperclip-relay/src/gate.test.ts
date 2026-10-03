import { describe, expect, it } from "vitest";

import {
  assertRelayPublishable,
  type RelayDeploymentMode,
  RelayGateError,
  relayPublishBlockedReason,
} from "./gate.js";

describe("assertRelayPublishable", () => {
  it("allows an authenticated instance", () => {
    expect(() =>
      assertRelayPublishable({ deploymentMode: "authenticated" }),
    ).not.toThrow();
  });

  it("allows an authenticated instance regardless of its declared exposure", () => {
    // The instance's own listener exposure is not the relay's exposure. Refusing
    // a `private` authenticated instance would be refusing the safe case.
    for (const deploymentExposure of ["private", "public"] as const) {
      expect(() =>
        assertRelayPublishable({ deploymentMode: "authenticated", deploymentExposure }),
      ).not.toThrow();
    }
  });

  it("refuses a local_trusted instance", () => {
    expect(() => assertRelayPublishable({ deploymentMode: "local_trusted" })).toThrow(
      RelayGateError,
    );
  });

  it("refuses local_trusted even when the instance claims private exposure", () => {
    // This is the combination an operator is most likely to reach for. `private`
    // describes the instance's own listener; it does not make a relay private.
    expect(() =>
      assertRelayPublishable({ deploymentMode: "local_trusted", deploymentExposure: "private" }),
    ).toThrow(RelayGateError);
  });

  it("refuses a local_trusted instance even when it is bound to loopback", () => {
    // Binding to loopback does not help: the relay's stream server is on this
    // machine and forwards on the subscriber's behalf.
    expect(() =>
      assertRelayPublishable({ deploymentMode: "local_trusted", deploymentExposure: "private" }),
    ).toThrow(/relay/i);
  });

  it("explains the reason and names the way out", () => {
    let message = "";
    try {
      assertRelayPublishable({ deploymentMode: "local_trusted" });
    } catch (error) {
      message = (error as Error).message;
    }
    expect(message).toContain("unauthenticated");
    expect(message).toContain("PAPERCLIP_DEPLOYMENT_MODE=authenticated");
  });

  it("carries a stable machine code for callers that branch on the refusal", () => {
    try {
      assertRelayPublishable({ deploymentMode: "local_trusted" });
      throw new Error("expected a refusal");
    } catch (error) {
      expect(RelayGateError.is(error)).toBe(true);
      expect((error as RelayGateError).code).toBe("deployment_mode_unsupported");
    }
  });

  it("refuses an unrecognised deployment mode rather than defaulting to allowed", () => {
    const modes: string[] = ["", "AUTHENTICATED", "trusted", "local-trusted", "public"];
    for (const deploymentMode of modes) {
      expect(() =>
        assertRelayPublishable({ deploymentMode: deploymentMode as RelayDeploymentMode }),
      ).toThrow(RelayGateError);
    }
  });
});

describe("relayPublishBlockedReason", () => {
  it("is null for a publishable instance", () => {
    expect(relayPublishBlockedReason({ deploymentMode: "authenticated" })).toBeNull();
  });

  it("explains a blocked instance without throwing", () => {
    const reason = relayPublishBlockedReason({ deploymentMode: "local_trusted" });
    expect(reason).toContain("PAPERCLIP_DEPLOYMENT_MODE=authenticated");
  });
});