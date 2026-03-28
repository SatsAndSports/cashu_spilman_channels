import { describe, it, expect, beforeEach, beforeAll } from "vitest";
import { InMemorySpilmanClientHost } from "./in_memory_client_host.js";
import { init } from "./index.js";
import * as secp from "@noble/secp256k1";

// Initialize WASM before running any tests
beforeAll(async () => {
  await init();
});

// Generate a test keypair
function generateTestKeypair(): { secretHex: string; pubkeyHex: string } {
  const secretBytes = secp.utils.randomPrivateKey();
  const pubkeyBytes = secp.getPublicKey(secretBytes, true);
  return {
    secretHex: Buffer.from(secretBytes).toString("hex"),
    pubkeyHex: Buffer.from(pubkeyBytes).toString("hex"),
  };
}

describe("InMemorySpilmanClientHost", () => {
  let host: InMemorySpilmanClientHost;
  let keypair: { secretHex: string; pubkeyHex: string };

  beforeEach(() => {
    keypair = generateTestKeypair();
    host = new InMemorySpilmanClientHost(keypair.secretHex);
  });

  describe("funding storage", () => {
    it("getChannelFunding returns null for unknown channel", () => {
      expect(host.getChannelFunding("unknown")).toBeNull();
    });

    it("saveOpeningChannel stores data and getChannelFunding retrieves it", () => {
      const channelId = "test-channel-123";
      const fundingJson = '{"params_json":"{}","funding_proofs_json":"[]"}';

      host.saveOpeningChannel(channelId, fundingJson);
      expect(host.getChannelFunding(channelId)).toBe(fundingJson);
    });

    it("saveOpeningChannel sets state to opening", () => {
      const channelId = "test-channel-456";
      host.saveOpeningChannel(channelId, "{}");
      expect(host.getChannelState(channelId)).toBe("opening");
    });

    it("markChannelOpen transitions state to open", () => {
      const channelId = "test-channel-789";
      host.saveOpeningChannel(channelId, "{}");
      expect(host.getChannelState(channelId)).toBe("opening");

      host.markChannelOpen(channelId, "[]");
      expect(host.getChannelState(channelId)).toBe("open");
    });
  });

  describe("payment state", () => {
    it("getPaymentState returns null initially", () => {
      expect(host.getPaymentState("any-channel")).toBeNull();
    });

    it("recordPayment stores state and getPaymentState retrieves it", () => {
      const channelId = "test-channel";
      const stateJson = '{"balance":100,"signature":"abc123"}';

      host.recordPayment(channelId, stateJson);
      expect(host.getPaymentState(channelId)).toBe(stateJson);
    });

    it("recordPayment updates existing state", () => {
      const channelId = "test-channel";
      host.recordPayment(channelId, '{"balance":100}');
      host.recordPayment(channelId, '{"balance":200}');
      expect(host.getPaymentState(channelId)).toBe('{"balance":200}');
    });
  });

  describe("lifecycle", () => {
    it("getChannelState returns 'open' for unknown channel", () => {
      expect(host.getChannelState("unknown")).toBe("open");
    });

    it("markChannelClosed changes state to 'closed'", () => {
      const channelId = "test-channel";
      host.saveOpeningChannel(channelId, "{}");
      host.markChannelOpen(channelId, "[]");
      expect(host.getChannelState(channelId)).toBe("open");

      host.markChannelClosed(channelId);
      expect(host.getChannelState(channelId)).toBe("closed");
    });

    it("listChannelIds returns all stored channels", () => {
      host.saveOpeningChannel("channel-1", "{}");
      host.saveOpeningChannel("channel-2", "{}");

      const ids = host.listChannelIds();
      expect(ids).toHaveLength(2);
      expect(ids).toContain("channel-1");
      expect(ids).toContain("channel-2");
    });

    it("deleteChannel removes channel and all its data", () => {
      const channelId = "test-channel";
      host.saveOpeningChannel(channelId, '{"funding":true}');
      host.recordPayment(channelId, '{"payment":true}');
      host.markChannelClosed(channelId);

      // Verify data exists
      expect(host.getChannelFunding(channelId)).not.toBeNull();
      expect(host.getPaymentState(channelId)).not.toBeNull();
      expect(host.getChannelState(channelId)).toBe("closed");
      expect(host.listChannelIds()).toContain(channelId);

      // Delete
      host.deleteChannel(channelId);

      // Verify data is gone
      expect(host.getChannelFunding(channelId)).toBeNull();
      expect(host.getPaymentState(channelId)).toBeNull();
      expect(host.getChannelState(channelId)).toBe("open"); // Default for unknown
      expect(host.listChannelIds()).not.toContain(channelId);
    });
  });

  describe("time", () => {
    it("nowSeconds returns reasonable Unix timestamp", () => {
      const before = BigInt(Math.floor(Date.now() / 1000));
      const got = host.nowSeconds();
      const after = BigInt(Math.floor(Date.now() / 1000));

      expect(got).toBeGreaterThanOrEqual(before);
      expect(got).toBeLessThanOrEqual(after);
    });
  });

  describe("crypto", () => {
    it("computeChannelSecret produces deterministic result", () => {
      const receiver = generateTestKeypair();

      const secret1 = host.computeChannelSecret(keypair.pubkeyHex, receiver.pubkeyHex);
      const secret2 = host.computeChannelSecret(keypair.pubkeyHex, receiver.pubkeyHex);

      expect(secret1).toBe(secret2);
      expect(secret1).toHaveLength(64); // 32 bytes hex encoded
    });

    it("signWithTweakedKey produces valid signature", () => {
      const messageHex = "0000000000000000000000000000000000000000000000000000000000000001";
      const tweakHex = "0000000000000000000000000000000000000000000000000000000000000002";

      const sig = host.signWithTweakedKey(keypair.pubkeyHex, messageHex, tweakHex);
      expect(sig).toHaveLength(128); // 64 bytes hex encoded
    });

    it("signWithTweakedKey produces valid hex", () => {
      const messageHex = "0000000000000000000000000000000000000000000000000000000000000001";
      const tweakHex = "0000000000000000000000000000000000000000000000000000000000000002";

      const sig = host.signWithTweakedKey(keypair.pubkeyHex, messageHex, tweakHex);

      // Verify it's valid lowercase hex
      expect(sig).toMatch(/^[0-9a-f]{128}$/);
    });
  });
});
