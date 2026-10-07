import { describe, it, expect, beforeAll, afterEach, vi } from "vitest";
import { createHash } from "node:crypto";
import { init } from "./index.js";
import { fetchAllKeysetsFromMint } from "./keysets.js";
import { demoFetchActiveKeysetInfo, KEYSET_VERSIONS_V2 } from "./demo.js";
import { discover_keysets_json, select_active_keyset_json } from "../wasm/cdk_wasm.js";

const key = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const v1 = "00" + createHash("sha256").update(Buffer.from(key, "hex")).digest("hex").slice(0, 14);
const v2 = "01" + createHash("sha256").update(`1:${key}|unit:sat`).digest("hex");
const future = { id: "02opaque", active: true, unit: "sat", keys: false };
beforeAll(async () => { await init(); });
afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks(); });

describe("keyset version discovery", () => {
  it.each([0, 1, 2])("skips future entries at position %i before fetching keys", async (position) => {
    const entries: any[] = [{ id: v1, active: false, unit: "sat" }, { id: v2, active: true, unit: "sat" }];
    entries.splice(position, 0, future);
    const listing = JSON.stringify({ keysets: entries });
    const report = JSON.parse(discover_keysets_json(listing));
    expect(report.skipped).toHaveLength(1);
    expect(report.keysets).toHaveLength(2);
    expect(select_active_keyset_json(listing, "sat", JSON.stringify({ allowed_versions: KEYSET_VERSIONS_V2 }))).toBe(v2);
    const fetchMock = vi.fn(async (url: string) => {
      if (url.endsWith("/v1/keysets")) return new Response(listing);
      const id = url.split("/").pop();
      expect([v1, v2]).toContain(id);
      return new Response(JSON.stringify({ keysets: [future, { id, unit: "sat", keys: { "1": key } }] }));
    });
    vi.stubGlobal("fetch", fetchMock);
    const results = await fetchAllKeysetsFromMint("https://mint.test", { sat: { min_capacity: 1, variables: {} } });
    expect(results.map(k => k.active)).toEqual([false, true]);
    expect(fetchMock).toHaveBeenCalledTimes(3);
    expect((await demoFetchActiveKeysetInfo("https://mint.test", "sat", KEYSET_VERSIONS_V2)).keysetId).toBe(v2);
  });

  it("warns for unsupported-only units and rejects malformed supported IDs", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({ keysets: [future] }))));
    await expect(demoFetchActiveKeysetInfo("https://mint.test")).rejects.toBeTruthy();
    expect(warn).toHaveBeenCalledWith(expect.stringContaining("unsupported active"));
    for (const id of ["00bad", "01bad", "xx", "+0"]) {
      expect(() => discover_keysets_json(JSON.stringify({ keysets: [{ id }] }))).toThrow();
    }
  });
});
