import { mkdtemp, readFile, stat, writeFile, chmod } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { deleteRelayToken, readRelayToken, relayTokenStorePath, writeRelayToken } from "./token-store.js";

async function tempPath(): Promise<{ dir: string; file: string }> {
  const dir = await mkdtemp(join(tmpdir(), "paperclip-relay-token-"));
  return { dir, file: join(dir, "nested", "relay-token.json") };
}

describe("relay token store", () => {
  let paths: { dir: string; file: string };

  beforeEach(async () => {
    paths = await tempPath();
  });

  afterEach(async () => {
    const { rm } = await import("node:fs/promises");
    await rm(paths.dir, { recursive: true, force: true });
  });

  describe("readRelayToken", () => {
    it("returns null when nothing has been issued", async () => {
      // The ordinary state of an instance that has never issued a credential,
      // not an error. The dialer turns this into a permanent refusal.
      expect(await readRelayToken(paths.file)).toBeNull();
    });

    it("round-trips a written token", async () => {
      await writeRelayToken({ token: "pcp_relay_abc", credentialId: "cred-1" }, paths.file);
      expect(await readRelayToken(paths.file)).toBe("pcp_relay_abc");
    });

    it("returns null for a file that is not valid JSON", async () => {
      const { mkdir } = await import("node:fs/promises");
      await mkdir(join(paths.dir, "nested"), { recursive: true });
      await writeFile(paths.file, "{not json", "utf8");
      expect(await readRelayToken(paths.file)).toBeNull();
    });

    it("returns null for an unsupported store version", async () => {
      // Forward compatibility has to be explicit. Guessing at a newer layout is
      // how a token gets presented in a format the relay cannot read.
      const { mkdir } = await import("node:fs/promises");
      await mkdir(join(paths.dir, "nested"), { recursive: true });
      await writeFile(paths.file, JSON.stringify({ version: 99, token: "x" }), "utf8");
      expect(await readRelayToken(paths.file)).toBeNull();
    });

    it("returns null when the token field is missing or empty", async () => {
      const { mkdir } = await import("node:fs/promises");
      await mkdir(join(paths.dir, "nested"), { recursive: true });
      await writeFile(paths.file, JSON.stringify({ version: 1 }), "utf8");
      expect(await readRelayToken(paths.file)).toBeNull();
      await writeFile(paths.file, JSON.stringify({ version: 1, token: "" }), "utf8");
      expect(await readRelayToken(paths.file)).toBeNull();
    });

    it("returns null when the file holds a JSON scalar", async () => {
      const { mkdir } = await import("node:fs/promises");
      await mkdir(join(paths.dir, "nested"), { recursive: true });
      await writeFile(paths.file, '"a string"', "utf8");
      expect(await readRelayToken(paths.file)).toBeNull();
    });
  });

  describe("writeRelayToken", () => {
    it("creates the file owner-only", async () => {
      // The whole reason for a file rather than the environment: this is a
      // 256-bit secret that must not be readable by another account.
      await writeRelayToken({ token: "pcp_relay_abc", credentialId: "cred-1" }, paths.file);
      const stats = await stat(paths.file);
      // Windows does not model POSIX permission bits, so the mode assertion is
      // skipped there rather than passing vacuously.
      if (process.platform !== "win32") {
        expect(stats.mode & 0o777).toBe(0o600);
      }
    });

    it("creates the parent directory owner-only", async () => {
      await writeRelayToken({ token: "pcp_relay_abc", credentialId: "cred-1" }, paths.file);
      if (process.platform === "win32") return;
      const stats = await stat(join(paths.dir, "nested"));
      expect(stats.mode & 0o777).toBe(0o700);
    });

    it("tightens permissions on an existing loosely-permissioned file", async () => {
      const { mkdir } = await import("node:fs/promises");
      await mkdir(join(paths.dir, "nested"), { recursive: true });
      await writeFile(paths.file, JSON.stringify({ version: 1, token: "old" }), "utf8");
      await chmod(paths.file, 0o644);
      if (process.platform === "win32") return;

      await writeRelayToken({ token: "pcp_relay_new", credentialId: "cred-2" }, paths.file);
      // `writeFile`'s mode only applies when creating, so without an explicit
      // chmod the secret would sit world-readable after a rotation.
      expect((await stat(paths.file)).mode & 0o777).toBe(0o600);
      expect(await readRelayToken(paths.file)).toBe("pcp_relay_new");
    });

    it("never writes the token hash alongside the token", async () => {
      await writeRelayToken({ token: "pcp_relay_abc", credentialId: "cred-1" }, paths.file);
      const raw = await readFile(paths.file, "utf8");
      expect(raw).toContain("pcp_relay_abc");
      expect(raw).not.toMatch(/[0-9a-f]{64}/);
    });
  });

  describe("deleteRelayToken", () => {
    it("removes the file so a revoked credential stops being presented", async () => {
      await writeRelayToken({ token: "pcp_relay_abc", credentialId: "cred-1" }, paths.file);
      await deleteRelayToken(paths.file);
      expect(await readRelayToken(paths.file)).toBeNull();
    });

    it("is a no-op when there is nothing to remove", async () => {
      await expect(deleteRelayToken(paths.file)).resolves.toBeUndefined();
    });
  });

  describe("relayTokenStorePath", () => {
    it("honours an explicit override", () => {
      expect(relayTokenStorePath({ PAPERCLIP_RELAY_STATE_PATH: "/tmp/x.json" })).toBe("/tmp/x.json");
    });

    it("keeps the store under the instance home by default", () => {
      const path = relayTokenStorePath({ PAPERCLIP_HOME: "/srv/paperclip" });
      expect(path).toContain(join("srv", "paperclip"));
      expect(path.endsWith("relay-token.json")).toBe(true);
    });

    it("does not put the store next to the database", () => {
      // A token sitting beside a world-readable database dump would be no better
      // than storing it in the database.
      const path = relayTokenStorePath({ PAPERCLIP_HOME: "/srv/paperclip" });
      expect(path).not.toContain("pglite");
    });
  });
});