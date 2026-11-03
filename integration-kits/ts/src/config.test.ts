import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { createHash } from "node:crypto";
import { once } from "node:events";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setImmediate } from "node:timers/promises";
import express from "express";
import { ConfigurableSpilman, SpilmanConfig } from "./config.js";
import { init } from "./index.js";

const realFetch = globalThis.fetch;
const key = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const secretKey = "0".repeat(63) + "1";
const units = ["sat", "msat", "usd"];
const keysets = units.map(unit => ({
  id: "01" + createHash("sha256").update(`1:${key}|unit:${unit}`).digest("hex"),
  unit,
  active: true,
}));

function gate() {
  let release!: () => void;
  const promise = new Promise<void>(resolve => { release = resolve; });
  return { promise, release };
}

async function firstParams(ctx: ConfigurableSpilman) {
  const app = express();
  ctx.initExpress(app);
  const server = app.listen(0, "127.0.0.1");
  try {
    await once(server, "listening");
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("Expected TCP listener");
    const response = await realFetch(`http://127.0.0.1:${address.port}/channel/params`);
    expect(response.status).toBe(200);
    return await response.json();
  } finally {
    await new Promise<void>((resolve, reject) => {
      server.close(error => error ? reject(error) : resolve());
    });
  }
}

describe("configured server startup", () => {
  let directory: string;

  beforeAll(async () => { await init(); });
  beforeEach(() => {
    directory = mkdtempSync(join(tmpdir(), "spilman-startup-"));
    vi.stubEnv("MINT_URL", "");
  });
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.unstubAllEnvs();
    vi.restoreAllMocks();
    rmSync(directory, { recursive: true, force: true });
  });

  function configFile(mints: string[]) {
    const config: SpilmanConfig = {
      mints: Object.fromEntries(mints.map(mint => [mint, units])),
      min_expiry_seconds: 3600,
      pricing: Object.fromEntries(units.map(unit => [unit, {
        min_capacity: 10,
        variables: { chars: 1 },
      }])),
    };
    const path = join(directory, "config.yaml");
    writeFileSync(path, JSON.stringify(config));
    return path;
  }

  it("waits for delayed keys and includes all initialized units in the first pricing response", async () => {
    const keysRequested = gate();
    const keysResponse = gate();
    vi.stubGlobal("fetch", vi.fn(async (url: string) => {
      if (url.endsWith("/v1/keysets")) {
        return new Response(JSON.stringify({ keysets }));
      }
      const keyset = keysets.find(entry => url.endsWith(`/v1/keys/${entry.id}`));
      if (!keyset) throw new Error(`Unexpected fetch: ${url}`);
      keysRequested.release();
      await keysResponse.promise;
      return new Response(JSON.stringify({ keysets: [{ ...keyset, keys: { "1": key } }] }));
    }));

    let settled = false;
    const loading = ConfigurableSpilman.fromYaml(configFile(["https://mint.test"]), secretKey)
      .then(ctx => { settled = true; return ctx; });
    try {
      await keysRequested.promise;
      // Give a prematurely fulfilled fromYaml promise a turn to notify its caller.
      // The response gate remains closed; there is no wall-clock delay or polling.
      await setImmediate();
      expect(settled).toBe(false);
    } finally {
      keysResponse.release();
      await loading;
    }

    const params = await firstParams(await loading);
    expect(Object.keys(params.pricing).sort()).toEqual([...units].sort());
    for (const keyset of keysets) {
      expect(params.mints_units_keysets["https://mint.test"][keyset.unit]).toContain(keyset.id);
    }
  });

  it("waits for a successful mint even when another mint fails, retaining best-effort startup", async () => {
    const successRequested = gate();
    const successResponse = gate();
    const warning = vi.spyOn(console, "error").mockImplementation(() => {});
    vi.stubGlobal("fetch", vi.fn(async (url: string) => {
      if (url.startsWith("https://failed.test/")) return new Response("unavailable", { status: 503 });
      if (url === "https://mint.test/v1/keysets") {
        successRequested.release();
        await successResponse.promise;
        return new Response(JSON.stringify({ keysets }));
      }
      const keyset = keysets.find(entry => url === `https://mint.test/v1/keys/${entry.id}`);
      if (!keyset) throw new Error(`Unexpected fetch: ${url}`);
      return new Response(JSON.stringify({ keysets: [{ ...keyset, keys: { "1": key } }] }));
    }));

    let settled = false;
    const loading = ConfigurableSpilman.fromYaml(
      configFile(["https://failed.test", "https://mint.test"]), secretKey,
    ).then(ctx => { settled = true; return ctx; });
    try {
      await successRequested.promise;
      await setImmediate();
      expect(settled).toBe(false);
    } finally {
      successResponse.release();
      await loading;
    }

    const params = await firstParams(await loading);
    expect(Object.keys(params.pricing).sort()).toEqual([...units].sort());
    expect(params.mints_units_keysets["https://failed.test"]).toBeUndefined();
    expect(warning).toHaveBeenCalledWith(expect.stringContaining("Failed to fetch keysets from https://failed.test"));
  });
});
