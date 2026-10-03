import { describe, expect, it } from "vitest";

import {
  hashRelayCredential,
  isRelayCredentialShaped,
  issueRelayCredential,
  parseBearerRelayCredential,
  redactRelayCredential,
  RELAY_CREDENTIAL_PREFIX,
  RELAY_CREDENTIAL_REDACTION,
  verifyRelayCredential,
} from "./credential.js";

describe("issueRelayCredential", () => {
  it("returns a prefixed token and the hash of that token", () => {
    const { token, tokenHash } = issueRelayCredential();
    expect(token.startsWith(RELAY_CREDENTIAL_PREFIX)).toBe(true);
    expect(tokenHash).toMatch(/^[0-9a-f]{64}$/);
    expect(hashRelayCredential(token)).toBe(tokenHash);
  });

  it("never repeats", () => {
    const tokens = new Set(Array.from({ length: 512 }, () => issueRelayCredential().token));
    expect(tokens.size).toBe(512);
  });

  it("carries 256 bits of entropy in an unpadded base64url body", () => {
    const body = issueRelayCredential().token.slice(RELAY_CREDENTIAL_PREFIX.length);
    expect(body).toHaveLength(43);
    expect(body).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });
});

describe("verifyRelayCredential", () => {
  it("accepts the token it was issued for", () => {
    const { token, tokenHash } = issueRelayCredential();
    expect(verifyRelayCredential(token, tokenHash)).toBe(true);
  });

  it("rejects a different token against the stored hash", () => {
    const { tokenHash } = issueRelayCredential();
    expect(verifyRelayCredential(issueRelayCredential().token, tokenHash)).toBe(false);
  });

  it("rejects a token one character away from the right one", () => {
    const { token, tokenHash } = issueRelayCredential();
    const body = token.slice(RELAY_CREDENTIAL_PREFIX.length);
    const flipped = (body[0] === "A" ? "B" : "A") + body.slice(1);
    expect(verifyRelayCredential(RELAY_CREDENTIAL_PREFIX + flipped, tokenHash)).toBe(false);
  });

  it("rejects a token with the right body but the wrong prefix", () => {
    const { token, tokenHash } = issueRelayCredential();
    const wrongPrefix = "pcp_board_" + token.slice(RELAY_CREDENTIAL_PREFIX.length);
    expect(verifyRelayCredential(wrongPrefix, tokenHash)).toBe(false);
  });

  it("rejects non-string inputs without throwing", () => {
    const { tokenHash } = issueRelayCredential();
    for (const value of [undefined, null, 42, {}, [], Buffer.from("x")]) {
      expect(verifyRelayCredential(value, tokenHash)).toBe(false);
    }
  });

  it("fails closed on a malformed stored hash", () => {
    const { token } = issueRelayCredential();
    // A malformed stored value is a bug. It must not read as a match.
    expect(verifyRelayCredential(token, "")).toBe(false);
    expect(verifyRelayCredential(token, "nothex")).toBe(false);
    expect(verifyRelayCredential(token, "A".repeat(64))).toBe(false);
    expect(verifyRelayCredential(token, "a".repeat(63))).toBe(false);
  });
});

describe("isRelayCredentialShaped", () => {
  it("accepts a freshly issued token", () => {
    expect(isRelayCredentialShaped(issueRelayCredential().token)).toBe(true);
  });

  it("rejects the wrong length", () => {
    expect(isRelayCredentialShaped(`${RELAY_CREDENTIAL_PREFIX}short`)).toBe(false);
    expect(isRelayCredentialShaped(`${RELAY_CREDENTIAL_PREFIX}${"A".repeat(44)}`)).toBe(false);
    expect(isRelayCredentialShaped(RELAY_CREDENTIAL_PREFIX)).toBe(false);
  });

  it("rejects non-base64url characters", () => {
    expect(isRelayCredentialShaped(`${RELAY_CREDENTIAL_PREFIX}${"A".repeat(42)}+`)).toBe(false);
    expect(isRelayCredentialShaped(`${RELAY_CREDENTIAL_PREFIX}${"A".repeat(42)}=`)).toBe(false);
    expect(isRelayCredentialShaped(`${RELAY_CREDENTIAL_PREFIX}${"A".repeat(42)}.`)).toBe(false);
  });

  it("rejects the wrong prefix", () => {
    expect(isRelayCredentialShaped(`pcp_board_${"A".repeat(43)}`)).toBe(false);
    expect(isRelayCredentialShaped(`${"A".repeat(43)}`)).toBe(false);
  });

  it("rejects non-strings", () => {
    for (const value of [undefined, null, 42, {}, []]) {
      expect(isRelayCredentialShaped(value)).toBe(false);
    }
  });
});

describe("redactRelayCredential", () => {
  it("blanks a real relay credential", () => {
    expect(redactRelayCredential(issueRelayCredential().token)).toBe(RELAY_CREDENTIAL_REDACTION);
  });

  it("blanks a non-string, which cannot be logged safely", () => {
    expect(redactRelayCredential(undefined)).toBe(RELAY_CREDENTIAL_REDACTION);
    expect(redactRelayCredential({ secret: true })).toBe(RELAY_CREDENTIAL_REDACTION);
  });

  it("passes an unrecognised string through so the leak stays visible", () => {
    // The redaction is a net for values the credential parser never saw. Blanking
    // something it does not recognise would hide the very leak it exists to catch.
    expect(redactRelayCredential("Bearer ghp_somethingElse")).toBe("Bearer ghp_somethingElse");
    expect(redactRelayCredential("pcp_relay_short")).toBe("pcp_relay_short");
  });
});

describe("parseBearerRelayCredential", () => {
  const token = issueRelayCredential().token;

  it("extracts the token from a bearer header, case-insensitively", () => {
    expect(parseBearerRelayCredential(`Bearer ${token}`)).toBe(token);
    expect(parseBearerRelayCredential(`bearer ${token}`)).toBe(token);
    expect(parseBearerRelayCredential(`BEARER  ${token} `)).toBe(token);
  });

  it("returns null when there is no usable credential", () => {
    for (const value of [
      undefined,
      null,
      "",
      "Bearer",
      `Basic ${token}`,
      `Bearer ${RELAY_CREDENTIAL_PREFIX}short`,
      `Bearer ${"A".repeat(43)}`,
      42,
    ]) {
      expect(parseBearerRelayCredential(value)).toBeNull();
    }
  });

  it("does not report an absent credential differently from a wrong one", () => {
    expect(parseBearerRelayCredential(undefined)).toBeNull();
    expect(parseBearerRelayCredential("Bearer not-a-relay-credential")).toBeNull();
  });
});