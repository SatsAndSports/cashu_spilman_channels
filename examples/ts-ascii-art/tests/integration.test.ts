/**
 * Integration tests for CDK WASM bindings.
 *
 * These tests require a Cashu mint running at MINT_URL (default: http://localhost:3338).
 *
 * Run with: MINT_URL=http://localhost:3338 npm test
 */

import { describe, it, expect, beforeAll } from "vitest";
import { randomBytes } from "crypto";
import * as secp from "@noble/secp256k1";
import {
  init,
  compute_channel_secret,
  compute_funding_token_amount,
  channel_parameters_get_channel_id,
  create_funding_outputs,
} from "cdk-spilman-kit";

beforeAll(async () => {
  await init();
});

const MINT_URL = process.env.MINT_URL || "http://localhost:3338";

interface KeysetInfo {
  keysetId: string;
  unit: string;
  keys: Record<string, string>;
  inputFeePpk: number;
}

/**
 * Generate a secp256k1 keypair using @noble/secp256k1
 */
function generateKeypair(): { secret: string; pubkey: string } {
  const secretBytes = randomBytes(32);
  const pubkeyBytes = secp.getPublicKey(secretBytes, true);
  return {
    secret: secretBytes.toString("hex"),
    pubkey: Buffer.from(pubkeyBytes).toString("hex"),
  };
}

/**
 * Derive public key from a secret key
 */
function secretKeyToPubkey(secretHex: string): string {
  const secretBytes = Buffer.from(secretHex, "hex");
  const pubkeyBytes = secp.getPublicKey(secretBytes, true);
  return Buffer.from(pubkeyBytes).toString("hex");
}

/**
 * Fetch the active keyset for a unit from the mint.
 */
async function fetchActiveKeyset(
  mintUrl: string,
  unit: string
): Promise<KeysetInfo | null> {
  try {
    // Get keysets
    const keysetsResp = await fetch(`${mintUrl}/v1/keysets`);
    const keysetsData = await keysetsResp.json();
    const keysets = keysetsData.keysets;

    // Find active keyset for unit
    const activeKeyset = keysets.find(
      (k: { unit: string; active: boolean }) => k.unit === unit && k.active
    );
    if (!activeKeyset) return null;

    const keysetId = activeKeyset.id;
    const inputFeePpk = activeKeyset.input_fee_ppk || 0;

    // Get keys for this keyset
    const keysResp = await fetch(`${mintUrl}/v1/keys/${keysetId}`);
    const keysData = await keysResp.json();
    const keys = keysData.keysets[0].keys;

    return {
      keysetId,
      unit,
      keys,
      inputFeePpk,
    };
  } catch (e) {
    console.error("Failed to fetch keyset:", e);
    return null;
  }
}

describe("Mint Connectivity", () => {
  it("should connect to the mint and get info", async () => {
    const response = await fetch(`${MINT_URL}/v1/info`);
    expect(response.status).toBe(200);

    const info = await response.json();
    console.log(
      `Connected to mint: ${info.name || "unknown"} (version ${info.version || "unknown"})`
    );
  });
});

describe("Channel Setup", () => {
  it("should generate keypair", () => {
    const { secret, pubkey } = generateKeypair();

    expect(secret).toHaveLength(64);
    expect(pubkey).toHaveLength(66);
    expect(pubkey.startsWith("02") || pubkey.startsWith("03")).toBe(true);

    console.log(`Generated keypair: pubkey=${pubkey.slice(0, 16)}...`);
  });

  it("should derive pubkey from secret", () => {
    const { secret, pubkey: expectedPubkey } = generateKeypair();

    const derivedPubkey = secretKeyToPubkey(secret);
    expect(derivedPubkey).toBe(expectedPubkey);
  });

  it("should compute channel secret", () => {
    const alice = generateKeypair();
    const bob = generateKeypair();

    // Both parties should compute the same channel secret
    const sharedAlice = compute_channel_secret(alice.secret, bob.pubkey);
    const sharedBob = compute_channel_secret(bob.secret, alice.pubkey);

    expect(sharedAlice).toBe(sharedBob);
    expect(sharedAlice).toHaveLength(64);

    console.log(`Computed channel secret: ${sharedAlice.slice(0, 16)}...`);
  });

  it("should create funding outputs and channel ID", async () => {
    // Generate keypairs
    const alice = generateKeypair();
    console.log(`Generated sender pubkey: ${alice.pubkey.slice(0, 16)}...`);

    const receiver = generateKeypair();
    console.log(`Generated receiver pubkey: ${receiver.pubkey.slice(0, 16)}...`);

    // Fetch active keyset from mint
    const keysetInfo = await fetchActiveKeyset(MINT_URL, "sat");
    expect(keysetInfo).not.toBeNull();
    const keysetJson = JSON.stringify(keysetInfo);
    console.log(`Fetched keyset: ${keysetInfo!.keysetId}`);

    // Compute channel secret
    const channelSecret = compute_channel_secret(alice.secret, receiver.pubkey);
    console.log(`Computed channel secret: ${channelSecret.slice(0, 16)}...`);

    // Build channel parameters
    const now = Math.floor(Date.now() / 1000);
    const fundingTokenAmount = Number(compute_funding_token_amount(
      BigInt(100),
      keysetJson,
      BigInt(64),
    ));
    const params = {
      sender_pubkey: alice.pubkey,
      receiver_pubkey: receiver.pubkey,
      mint: MINT_URL,
      unit: "sat",
      capacity: 100,
      funding_token_amount: fundingTokenAmount,
      maximum_amount: 64,
      expiry_timestamp: now + 7200,
      setup_timestamp: now,
      keyset_id: keysetInfo!.keysetId,
      input_fee_ppk: keysetInfo!.inputFeePpk,
    };
    const paramsJson = JSON.stringify(params);

    // Get channel ID
    const channelId = channel_parameters_get_channel_id(
      paramsJson,
      channelSecret,
      keysetJson
    );
    expect(channelId).toHaveLength(64);
    console.log(`Channel ID: ${channelId}`);

    // Create funding outputs
    const fundingJson = create_funding_outputs(
      paramsJson,
      alice.secret,
      keysetJson
    );
    const funding = JSON.parse(fundingJson);

    const fundingNominal = funding.funding_token_nominal;
    const blindedMessages = funding.blinded_messages;

    console.log(
      `Funding nominal: ${fundingNominal} sat, outputs: ${blindedMessages.length}`
    );

    // Verify we got reasonable outputs
    expect(fundingNominal).toBeGreaterThanOrEqual(100);
    expect(blindedMessages.length).toBeGreaterThan(0);
  });

  it("should compute channel ID deterministically", async () => {
    const alice = generateKeypair();
    const receiver = generateKeypair();

    const keysetInfo = await fetchActiveKeyset(MINT_URL, "sat");
    expect(keysetInfo).not.toBeNull();
    const keysetJson = JSON.stringify(keysetInfo);

    const channelSecret = compute_channel_secret(alice.secret, receiver.pubkey);

    const now = Math.floor(Date.now() / 1000);
    const fundingTokenAmount = Number(compute_funding_token_amount(
      BigInt(100),
      keysetJson,
      BigInt(64),
    ));
    const params = {
      sender_pubkey: alice.pubkey,
      receiver_pubkey: receiver.pubkey,
      mint: MINT_URL,
      unit: "sat",
      capacity: 100,
      funding_token_amount: fundingTokenAmount,
      maximum_amount: 64,
      expiry_timestamp: now + 7200,
      setup_timestamp: now,
      keyset_id: keysetInfo!.keysetId,
      input_fee_ppk: keysetInfo!.inputFeePpk,
    };
    const paramsJson = JSON.stringify(params);

    // Compute channel ID twice
    const channelId1 = channel_parameters_get_channel_id(
      paramsJson,
      channelSecret,
      keysetJson
    );
    const channelId2 = channel_parameters_get_channel_id(
      paramsJson,
      channelSecret,
      keysetJson
    );

    expect(channelId1).toBe(channelId2);
    console.log(`Channel ID is deterministic: ${channelId1}`);
  });
});
