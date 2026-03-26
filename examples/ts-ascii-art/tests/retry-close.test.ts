/**
 * Test: Full automatic retry of cooperative close via WASM bridge with real mint
 *
 * This exercises the WASM `executeCooperativeClose` retry path:
 * 1. Fund a real channel (real mint, real P2BK proofs)
 * 2. Build a WasmSpilmanBridge with a "lying" host that reports a fake keyset as active
 * 3. Call bridge.executeCooperativeClose()
 * 4. First swap attempt targets the fake keyset -> real mint rejects (UnknownKeySet)
 * 5. Bridge calls refreshAllKeysets -> host switches to reporting the real keyset
 * 6. Retry targets the real keyset -> real mint accepts
 * 7. DLEQ verification passes, markChannelClosed receives real proofs
 *
 * This is the only test that exercises the WASM async retry path end-to-end
 * with real mint rejection and real mint acceptance.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { randomBytes } from 'crypto';
import * as secp from '@noble/secp256k1';

import {
  init,
  WasmSpilmanBridge,
  compute_channel_secret,
  compute_funding_token_amount,
  channel_parameters_get_channel_id,
  create_funding_outputs,
  construct_proofs,
  spilman_channel_sender_create_signed_balance_update,
  sign_with_tweaked_key,
} from 'cdk-spilman-kit';

beforeAll(async () => {
  await init();
});

const MINT_URL = process.env.MINT_URL || 'http://localhost:3338';

// Generate a random keypair
function generateKeypair(): { secretHex: string; pubkeyHex: string } {
  const secretBytes = randomBytes(32);
  const secretHex = secretBytes.toString('hex');
  const pubkeyBytes = secp.getPublicKey(secretBytes, true);
  const pubkeyHex = Buffer.from(pubkeyBytes).toString('hex');
  return { secretHex, pubkeyHex };
}

// Fetch keyset info from mint (same pattern as payment.test.ts)
async function fetchKeysetInfo(mintUrl: string, keysetId: string): Promise<any> {
  const keysRes = await fetch(`${mintUrl}/v1/keys/${keysetId}`);
  const keysData = await keysRes.json() as any;

  const keysetsRes = await fetch(`${mintUrl}/v1/keysets`);
  const keysetsData = await keysetsRes.json() as any;
  const keyset = keysetsData.keysets.find((k: any) => k.id === keysetId);

  const keys: Record<string, string> = {};
  if (keysData.keysets && keysData.keysets[0]?.keys) {
    for (const [amount, pubkey] of Object.entries(keysData.keysets[0].keys)) {
      keys[amount] = pubkey as string;
    }
  }

  return {
    keysetId,
    unit: keyset?.unit || 'sat',
    keys,
    inputFeePpk: keyset?.input_fee_ppk || 0,
  };
}

// Get the first active keyset ID for a unit from the mint
async function getActiveKeysetId(mintUrl: string, unit: string): Promise<string> {
  const res = await fetch(`${mintUrl}/v1/keysets`);
  const data = await res.json() as any;
  const keyset = data.keysets.find((k: any) => k.unit === unit && k.active);
  if (!keyset) throw new Error(`No active keyset for unit "${unit}"`);
  return keyset.id;
}

// Mint proofs via the real mint (FakeWallet auto-pays)
async function mintFundingProofs(
  mintUrl: string,
  channelParamsJson: string,
  aliceSecretHex: string,
  keysetInfo: any,
  fundingTokenNominal: number,
): Promise<{ proofs: any[]; proofsJson: string }> {
  // Generate deterministic funding outputs
  const fundingOutputsJson = create_funding_outputs(
    channelParamsJson, aliceSecretHex, JSON.stringify(keysetInfo),
  );
  const fundingOutputs = JSON.parse(fundingOutputsJson);

  // Create mint quote
  const quoteRes = await fetch(`${mintUrl}/v1/mint/quote/bolt11`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ amount: fundingTokenNominal, unit: keysetInfo.unit }),
  });
  const quote = await quoteRes.json() as any;

  // Wait for FakeWallet auto-payment
  for (let i = 0; i < 30; i++) {
    const statusRes = await fetch(`${mintUrl}/v1/mint/quote/bolt11/${quote.quote}`);
    const status = await statusRes.json() as any;
    if (status.state === 'PAID') break;
    await new Promise(r => setTimeout(r, 100));
  }

  // Mint tokens
  const mintReq = {
    quote: quote.quote,
    outputs: fundingOutputs.blinded_messages.map((bm: any) => ({
      amount: bm.amount, id: bm.id, B_: bm.B_,
    })),
  };
  const mintRes = await fetch(`${mintUrl}/v1/mint/bolt11`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(mintReq),
  });
  const mintData = await mintRes.json() as any;

  // Construct proofs (unblind)
  const proofsJson = construct_proofs(
    JSON.stringify(mintData.signatures),
    JSON.stringify(fundingOutputs.secrets_with_blinding),
    JSON.stringify(keysetInfo),
  );
  const proofs = JSON.parse(proofsJson);

  return { proofs, proofsJson };
}


describe('WASM close retry with real mint', () => {
  it('retries cooperative close with refreshed keysets after first swap fails', async () => {
    // ================================================================
    // Setup: generate keys, build channel params, fund the channel
    // ================================================================

    const alice = generateKeypair();
    const charlie = generateKeypair();

    const keysetId = await getActiveKeysetId(MINT_URL, 'sat');
    const keysetInfo = await fetchKeysetInfo(MINT_URL, keysetId);
    const keysetInfoJson = JSON.stringify(keysetInfo);

    const capacity = 100;
    const maximumAmount = 64;
    const setupTimestamp = Math.floor(Date.now() / 1000);
    const expiryTimestamp = setupTimestamp + 7 * 24 * 60 * 60;

    const fundingTokenAmount = Number(compute_funding_token_amount(
      BigInt(capacity), keysetInfoJson, BigInt(maximumAmount),
    ));

    const channelParams = {
      mint: MINT_URL,
      unit: 'sat',
      capacity,
      funding_token_amount: fundingTokenAmount,
      keyset_id: keysetId,
      input_fee_ppk: keysetInfo.inputFeePpk,
      maximum_amount: maximumAmount,
      setup_timestamp: setupTimestamp,
      sender_pubkey: alice.pubkeyHex,
      receiver_pubkey: charlie.pubkeyHex,
      expiry_timestamp: expiryTimestamp,
    };
    const channelParamsJson = JSON.stringify(channelParams);

    const channelSecret = compute_channel_secret(alice.secretHex, charlie.pubkeyHex);
    const channelId = channel_parameters_get_channel_id(
      channelParamsJson, channelSecret, keysetInfoJson,
    );

    // Mint real funding proofs
    const { proofs, proofsJson } = await mintFundingProofs(
      MINT_URL, channelParamsJson, alice.secretHex, keysetInfo,
      fundingTokenAmount,
    );

    console.log(`Channel ${channelId}: capacity=${capacity}, funding=${fundingTokenAmount}, proofs=${proofs.length}`);

    // Create a signed balance update (Alice authorizes balance=50 to Charlie)
    const balance = 50;
    const balanceUpdateJson = spilman_channel_sender_create_signed_balance_update(
      channelParamsJson, keysetInfoJson, alice.secretHex, proofsJson, BigInt(balance),
    );
    const balanceUpdate = JSON.parse(balanceUpdateJson);
    console.log(`Balance update: balance=${balanceUpdate.amount}, sig=${balanceUpdate.signature.substring(0, 16)}...`);

    // ================================================================
    // Build a "lying" SpilmanHost that reports a fake keyset as active
    // ================================================================

    // The fake keyset: clone real keyset info but change the ID
    const fakeKeysetId = '00deadbeef000000';
    const fakeKeysetInfo = { ...keysetInfo, keysetId: fakeKeysetId };

    // Track calls
    let swapCallCount = 0;
    let refreshCount = 0;
    let reportedActiveKeysets: string[] = [fakeKeysetId]; // Start with lie
    let closedData: any = null;

    // Channel state management
    let channelState = 'open';
    let closingData: any = null;
    let storedPayment: [number, string] | null = null;

    const lyingHost = {
      receiverKeyIsAcceptable: (_pubkey: string) => true,
      mintAndKeysetIsAcceptable: (_mint: string, _keysetId: string) => true,

      getFundingAndParams: (chId: string) => {
        if (chId !== channelId) return null;
        return [channelParamsJson, proofsJson, channelSecret, keysetInfoJson];
      },
      saveFunding: () => {},

      getAmountDue: (_chId: string, _ctx: string | null) => BigInt(balance),
      recordPayment: (_chId: string, bal: number, sig: string, _ctx: string) => {
        storedPayment = [Number(bal), sig];
      },

      getChannelState: (_chId: string) => channelState,
      markChannelClosing: (_chId: string, lt: number, bal: number, sig: string) => {
        channelState = 'closing';
        storedPayment = [Number(bal), sig];
        closingData = { expiry_timestamp: Number(lt), balance: Number(bal), signature: sig };
      },
      getClosingData: (_chId: string) => closingData,

      getChannelPolicy: (_unit: string) => ({
        min_expiry_in_seconds: 3600,
        min_capacity: 10,
      }),
      nowSeconds: () => BigInt(Math.floor(Date.now() / 1000)),

      getBalanceAndSignatureForUnilateralExit: (_chId: string) => storedPayment,

      // THE LIE: initially returns fake keyset, switches after refresh
      getActiveKeysetIds: (_mint: string, _unit: string) => {
        return reportedActiveKeysets;
      },
      getKeysetInfo: (_mint: string, kid: string) => {
        if (kid === keysetId) return keysetInfoJson;
        if (kid === fakeKeysetId) return JSON.stringify(fakeKeysetInfo);
        return null;
      },

      // THE SWITCH: refresh corrects the lie
      refreshAllKeysets: async (_mint: string) => {
        refreshCount++;
        reportedActiveKeysets = [keysetId]; // Now report the real keyset
      },

      // REAL MINT: actually POST to the mint
      callMintSwap: async (mintUrl: string, swapRequestJson: string): Promise<string> => {
        swapCallCount++;
        const response = await fetch(`${mintUrl}/v1/swap`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: swapRequestJson,
        });
        const text = await response.text();
        if (!response.ok) {
          throw (text || `Mint rejected swap with status ${response.status}`);
        }
        return text;
      },

      markChannelClosed: (
        _chId: string, _lt: number, bal: number,
        receiverProofsJson: string, senderProofsJson: string,
        receiverSum: number, senderSum: number,
      ) => {
        channelState = 'closed';
        closedData = {
          balance: Number(bal),
          totalValue: Number(receiverSum) + Number(senderSum),
          receiverProofsJson,
          senderProofsJson,
        };
      },

      computeChannelSecret: (_charliePubHex: string, alicePubHex: string) => {
        return compute_channel_secret(charlie.secretHex, alicePubHex);
      },
      signWithTweakedKey: (_signerPubHex: string, messageHex: string, tweakHex: string) => {
        return sign_with_tweaked_key(charlie.secretHex, messageHex, tweakHex);
      },
    };

    // ================================================================
    // Execute cooperative close -- expect retry
    // ================================================================

    const bridge = new WasmSpilmanBridge(lyingHost);

    const paymentJson = JSON.stringify({
      channel_id: channelId,
      balance,
      signature: balanceUpdate.signature,
    });

    console.log('Executing cooperative close (expecting retry)...');
    const result = await bridge.executeCooperativeClose(paymentJson);

    console.log('Close result:', JSON.stringify(result));

    // ================================================================
    // Assertions
    // ================================================================

    // The swap was called twice (first rejected, second accepted)
    expect(swapCallCount).toBe(2);
    console.log('  call_mint_swap called exactly 2 times');

    // refresh_all_keysets was called exactly once
    expect(refreshCount).toBe(1);
    console.log('  refresh_all_keysets called exactly once');

    // Channel is closed
    expect(channelState).toBe('closed');
    console.log('  Channel state is closed');

    // markChannelClosed was called with real proofs
    expect(closedData).not.toBeNull();
    expect(closedData.totalValue).toBeGreaterThan(0);
    console.log(`  markChannelClosed: balance=${closedData.balance}, total=${closedData.totalValue}`);

    const receiverProofs = JSON.parse(closedData.receiverProofsJson);
    const senderProofs = JSON.parse(closedData.senderProofsJson);
    expect(receiverProofs.length).toBeGreaterThan(0);
    console.log(`  Receiver got ${receiverProofs.length} proofs, sender got ${senderProofs.length} proofs`);

    // Result should indicate success
    expect(result.channel_id).toBe(channelId);
    expect(result.total_value).toBeGreaterThan(0);
    console.log(`  CloseSuccess: total_value=${result.total_value}`);

    console.log('PASSED: Full WASM cooperative close retry with real mint');
  }, 30000); // 30s timeout for mint interactions
});
