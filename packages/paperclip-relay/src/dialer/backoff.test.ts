import { describe, expect, it } from "vitest";

import { createBackoffSequence, isPermanentRelayError } from "./backoff.js";

describe("createBackoffSequence", () => {
  it("grows the un-jittered ceiling exponentially up to the max", () => {
    // jitterRatio 0 removes the random term entirely, so the ceiling is visible.
    const backoff = createBackoffSequence({
      baseDelayMs: 100,
      maxDelayMs: 5000,
      jitterRatio: 0,
    });
    expect([backoff.next(), backoff.next(), backoff.next(), backoff.next(), backoff.next()]).toEqual([
      100, 200, 400, 800, 1600,
    ]);
  });

  it("never exceeds the max delay", () => {
    const backoff = createBackoffSequence({ baseDelayMs: 100, maxDelayMs: 1000, jitterRatio: 0 });
    const delays = Array.from({ length: 30 }, () => backoff.next());
    expect(Math.max(...delays)).toBe(1000);
    expect(delays.every((delay) => delay <= 1000)).toBe(true);
  });

  it("does not overflow to a non-finite delay after a very long outage", () => {
    // Without clamping the exponent, base * 2^200 is Infinity and
    // `Infinity - Infinity` in the jitter arithmetic yields NaN.
    const backoff = createBackoffSequence({ baseDelayMs: 1000, maxDelayMs: 30_000 });
    const delays = Array.from({ length: 5000 }, () => backoff.next());
    expect(delays.every((delay) => Number.isFinite(delay) && delay >= 0)).toBe(true);
  });

  it("keeps half the ceiling as a floor, so no attempt retries instantly", () => {
    // random() === 0 would give the shortest possible equal-jitter delay.
    const backoff = createBackoffSequence({
      baseDelayMs: 1000,
      maxDelayMs: 30_000,
      jitterRatio: 0.5,
      random: () => 0,
    });
    expect(backoff.next()).toBe(500);
    expect(backoff.next()).toBe(1000);
    expect(backoff.next()).toBe(2000);
  });

  it("spreads delays across the jitter window to de-synchronise clients", () => {
    const low = createBackoffSequence({ random: () => 0 });
    const high = createBackoffSequence({ random: () => 0.999999 });
    expect(low.next()).toBeLessThan(high.next());
  });

  it("resets the accumulated attempts", () => {
    const backoff = createBackoffSequence({ baseDelayMs: 100, maxDelayMs: 10_000, jitterRatio: 0 });
    backoff.next();
    backoff.next();
    backoff.next();
    expect(backoff.attempts).toBe(3);
    backoff.reset();
    expect(backoff.attempts).toBe(0);
    expect(backoff.next()).toBe(100);
  });

  it("rejects a configuration that could produce a zero or negative delay", () => {
    expect(() => createBackoffSequence({ baseDelayMs: 0 })).toThrow();
    expect(() => createBackoffSequence({ baseDelayMs: -1 })).toThrow();
    expect(() => createBackoffSequence({ factor: 0 })).toThrow();
    expect(() => createBackoffSequence({ maxDelayMs: 0 })).toThrow();
  });

  it("rejects a max below the base, which would make the first attempt violate the max", () => {
    expect(() => createBackoffSequence({ baseDelayMs: 1000, maxDelayMs: 500 })).toThrow();
  });

  it("rejects a jitter ratio outside [0, 1]", () => {
    expect(() => createBackoffSequence({ jitterRatio: -0.1 })).toThrow();
    expect(() => createBackoffSequence({ jitterRatio: 1.1 })).toThrow();
  });

  it("produces integer millisecond delays", () => {
    const backoff = createBackoffSequence({ baseDelayMs: 333, maxDelayMs: 5000 });
    for (let i = 0; i < 20; i += 1) {
      expect(Number.isInteger(backoff.next())).toBe(true);
    }
  });
});

describe("isPermanentRelayError", () => {
  it("treats refusals that need an operator as permanent", () => {
    for (const code of [
      "unauthorized_control",
      "credential_revoked",
      "instance_not_entitled",
      "instance_slug_conflict",
      "no_common_protocol_version",
    ]) {
      expect(isPermanentRelayError(code)).toBe(true);
    }
  });

  it("treats transport and quota conditions as worth retrying", () => {
    for (const code of [
      "internal_error",
      "frame_too_large",
      "stream_limit_reached",
      "stream_quota_exceeded",
      "malformed_message",
    ]) {
      expect(isPermanentRelayError(code)).toBe(false);
    }
  });

  it("treats an unrecognised code as transient, so a new code cannot silently halt publishing", () => {
    // Fail towards retrying: an unknown code stops nothing until it is
    // classified, and backoff bounds how hard it retries.
    expect(isPermanentRelayError("something_new_from_the_relay")).toBe(false);
  });
});