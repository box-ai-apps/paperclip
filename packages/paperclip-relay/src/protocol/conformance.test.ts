/**
 * Conformance suite over the canonical vectors.
 *
 * Both directions are pinned from one vector. For an accepted frame the decoder
 * must reproduce the expected message *and* re-encoding that message must
 * reproduce the exact input bytes. That second half is what makes the vectors
 * usable by the relay-server repository: a drifted encoder is as much a contract
 * break as a drifted decoder, and a byte-exact round trip catches either.
 *
 * The relay-server repository vendors `vectors.ts` verbatim and runs this same
 * file against its own decoder.
 */
import { describe, expect, it } from "vitest";

import { decodeRelayMessage } from "./decode.js";
import { encodeRelayMessage } from "./codec.js";
import { RelayProtocolError } from "./errors.js";
import { RELAY_DECODE_VECTORS } from "./conformance/vectors.js";

describe("relay protocol conformance vectors", () => {
  it("has no vector that is neither accepted nor rejected", () => {
    for (const vector of RELAY_DECODE_VECTORS) {
      expect(
        (vector.expectMessage === undefined) !== (vector.expectCode === undefined),
        `vector "${vector.name}" must set exactly one of expectMessage / expectCode`,
      ).toBe(true);
    }
  });

  it("has no duplicate vector names", () => {
    const names = RELAY_DECODE_VECTORS.map((vector) => vector.name);
    expect(new Set(names).size).toBe(names.length);
  });

  for (const vector of RELAY_DECODE_VECTORS) {
    if (vector.expectMessage !== undefined) {
      const expected = vector.expectMessage;
      it(`accepts: ${vector.name}`, () => {
        expect(decodeRelayMessage(vector.body)).toEqual(expected);
      });

      it(`round-trips: ${vector.name}`, () => {
        expect(encodeRelayMessage(expected)).toBe(vector.body);
      });
      continue;
    }

    const code = vector.expectCode;
    it(`rejects: ${vector.name}`, () => {
      expect(() => decodeRelayMessage(vector.body)).toThrowError(RelayProtocolError);
      try {
        decodeRelayMessage(vector.body);
        throw new Error("expected a rejection");
      } catch (error) {
        expect(RelayProtocolError.is(error)).toBe(true);
        expect((error as RelayProtocolError).code).toBe(code);
      }
    });
  }
});