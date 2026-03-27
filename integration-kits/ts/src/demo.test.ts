import { describe, it, expect, beforeAll } from "vitest";
import { demoFetchActiveKeysetInfo, demoMintPlainProofs } from "./demo.js";
import { init } from "./index.js";

beforeAll(async () => {
  await init();
});

const MINT_URL = process.env.MINT_URL;

describe("demo helpers", () => {
  describe("demoFetchActiveKeysetInfo", () => {
    it.skipIf(!MINT_URL)("integration: fetches keyset info from mint", async () => {
      const ki = await demoFetchActiveKeysetInfo(MINT_URL!, "sat");

      expect(ki).toHaveProperty("keysetId");
      expect(ki).toHaveProperty("unit", "sat");
      expect(ki).toHaveProperty("keys");
      expect(ki).toHaveProperty("inputFeePpk");

      // keysetId should be a hex string
      expect(typeof ki.keysetId).toBe("string");
      expect(ki.keysetId.length).toBeGreaterThan(0);

      // keys should be an object with numeric keys
      expect(typeof ki.keys).toBe("object");
      expect(Object.keys(ki.keys).length).toBeGreaterThan(0);

      console.log(`Keyset ID: ${ki.keysetId}`);
      console.log(`Number of keys: ${Object.keys(ki.keys).length}`);
    });
  });

  describe("demoMintPlainProofs", () => {
    it.skipIf(!MINT_URL)("integration: mints valid proofs from mint", async () => {
      // 1. Fetch keyset info
      const ki = await demoFetchActiveKeysetInfo(MINT_URL!, "sat");
      const kiJson = JSON.stringify(ki);

      // 2. Mint plain proofs
      const amount = 100;
      const proofsJson = await demoMintPlainProofs(MINT_URL!, amount, kiJson, "sat");

      // 3. Parse result as JSON array
      const proofs = JSON.parse(proofsJson) as Array<Record<string, unknown>>;

      expect(Array.isArray(proofs)).toBe(true);
      expect(proofs.length).toBeGreaterThan(0);
      console.log(`Minted ${proofs.length} proofs`);

      // 4. Verify proofs have expected fields
      let totalAmount = 0;
      for (const proof of proofs) {
        expect(proof).toHaveProperty("amount");
        expect(proof).toHaveProperty("id");
        expect(proof).toHaveProperty("secret");
        expect(proof).toHaveProperty("C");

        totalAmount += proof.amount as number;
      }

      // Total should be at least the requested amount
      expect(totalAmount).toBeGreaterThanOrEqual(amount);
      console.log(`Total proof amount: ${totalAmount} sat`);
    });
  });
});
