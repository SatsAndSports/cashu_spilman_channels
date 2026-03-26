import express from "express";
import { getChannelStatus, PricingTable, SpilmanStores } from "./stores.js";
import { getBridgeErrorReason, mapBridgeErrorStatus } from "./express.js";
import { build_cashu_b_token } from "../wasm/cdk_wasm.js";

export interface ManagementRouterDeps {
  bridge: {
    executeCooperativeClose: (body: string) => Promise<unknown>;
    executeUnilateralClose: (channelId: string) => Promise<unknown>;
    fundChannel: (body: string) => unknown;
  };
  receiverPubkey: string;
  pricing: PricingTable;
  stores: SpilmanStores;
  pricingScale?: number;
  getActivePricing?: () => PricingTable;
}

function parseSenderProofs(raw: unknown): unknown {
  if (typeof raw === "string") {
    try {
      return JSON.parse(raw);
    } catch {
      return [];
    }
  }
  return raw ?? [];
}

function parseCloseError(e: unknown): { status: number; reason: string; extra: Record<string, unknown> } {
  if (typeof e === "object" && e !== null && "type" in e) {
    const closeError = e as { status?: number; reason?: string; mint_error?: string };
    return {
      status: closeError.status ?? 402,
      reason: closeError.reason ?? closeError.mint_error ?? String(e),
      extra: e as Record<string, unknown>,
    };
  }

  const errorMsg = (e as Error)?.message || String(e);
  try {
    const closeError = JSON.parse(errorMsg) as { status?: number; reason?: string; mint_error?: string };
    return {
      status: closeError.status ?? 402,
      reason: closeError.reason ?? closeError.mint_error ?? String(closeError),
      extra: closeError as Record<string, unknown>,
    };
  } catch {
    return {
      status: 502,
      reason: errorMsg,
      extra: { type: "MintRejected", reason: errorMsg, status: 502 },
    };
  }
}

export function createSpilmanManagementRouter(deps: ManagementRouterDeps): express.Router {
  const router = express.Router();

  router.get("/params", (_req, res) => {
    const rawPricing = deps.getActivePricing ? deps.getActivePricing() : deps.pricing;

    // Emit each pricing entry with snake_case fields only.
    const pricing: Record<string, any> = {};
    for (const [unit, entry] of Object.entries(rawPricing)) {
      const obj: Record<string, any> = {
        min_capacity: entry.min_capacity ?? 0,
        variables: entry.variables ?? {},
      };
      const maxOutput = entry.max_amount_per_output;
      if (maxOutput !== undefined) {
        obj.max_amount_per_output = maxOutput;
      }
      pricing[unit] = obj;
    }

    res.json({
      receiver_pubkey: deps.receiverPubkey,
      pricing,
      mints_units_keysets: deps.stores.keysetCache.getMintsUnitsKeysets(),
      pricing_scale: deps.pricingScale ?? 1,
      min_expiry_in_seconds: 3600,
    });
  });

  router.get("/:id/status", (req, res) => {
    const channelId = req.params.id;
    try {
      const status = getChannelStatus(channelId, deps.pricing, deps.stores, deps.pricingScale ?? 1);
      res.json(status);
    } catch (e) {
      const message = (e as Error).message;
      if (message === "unknown channel") {
        res.status(404).json({ error: "unknown channel" });
      } else {
        res.status(500).json({ error: message });
      }
    }
  });

  router.post("/:id/close", async (req, res) => {
    const channelId = req.params.id;
    const { balance, signature } = req.body;

    if (balance === undefined || !signature) {
      res.status(400).json({ error: "missing balance or signature" });
      return;
    }

    const closedData = deps.stores.channelClosed.get(channelId);
    if (closedData !== null) {
      if (balance === closedData.closedAmount) {
        res.json({
          success: true,
          channel_id: channelId,
          total_value: closedData.valueAfterStage1,
          receiver_sum: closedData.receiverSum,
          sender_sum: closedData.senderSum,
          sender_proofs: parseSenderProofs(closedData.senderProofsJson),
          already_closed: true,
        });
        return;
      }
      res.status(400).json({
        error: "channel already closed with a different amount",
        closed_amount: closedData.closedAmount,
        requested_amount: balance,
      });
      return;
    }

    const { params, funding_proofs } = req.body;
    const closeBody: Record<string, unknown> = { channel_id: channelId, balance, signature };
    if (params) closeBody.params = params;
    if (funding_proofs) closeBody.funding_proofs = funding_proofs;

    try {
      const result = (await deps.bridge.executeCooperativeClose(JSON.stringify(closeBody))) as {
        channel_id: string;
        total_value: number;
        receiver_sum: number;
        sender_sum: number;
        sender_proofs: unknown;
        already_closed: boolean;
      };
      res.json({
        success: true,
        channel_id: result.channel_id,
        total_value: result.total_value,
        receiver_sum: result.receiver_sum,
        sender_sum: result.sender_sum,
        sender_proofs: parseSenderProofs(result.sender_proofs),
        already_closed: result.already_closed,
      });
    } catch (e) {
      const { status, reason, extra } = parseCloseError(e);
      res.status(status).json({ success: false, error: reason, ...extra });
    }
  });

  router.post("/:id/unilateral-close", async (req, res) => {
    const channelId = req.params.id;

    const closedData = deps.stores.channelClosed.get(channelId);
    if (closedData !== null) {
      res.json({
        success: true,
        channel_id: channelId,
        earnedBeforeStage2Fees: closedData.receiverSum,
        already_closed: true,
      });
      return;
    }

    if (!deps.stores.channelFunding.get(channelId)) {
      res.status(404).json({ error: "unknown channel" });
      return;
    }

    try {
      const result = (await deps.bridge.executeUnilateralClose(channelId)) as {
        channel_id: string;
        receiver_sum: number;
      };
      res.json({
        success: true,
        channel_id: channelId,
        earnedBeforeStage2Fees: result.receiver_sum,
        already_closed: false,
      });
    } catch (e) {
      const { status, reason, extra } = parseCloseError(e);
      res.status(status || 500).json({ success: false, error: reason, ...extra });
    }
  });

  router.post("/register", (req, res) => {
    const { channel_id, balance, signature, params, funding_proofs } = req.body;

    if (!channel_id || signature === undefined || !params || !funding_proofs) {
      res.status(400).json({
        error: "Bad request",
        reason: "missing required fields: channel_id, signature, params, funding_proofs",
      });
      return;
    }

    if (balance !== 0) {
      res.status(400).json({
        error: "Bad request",
        reason: `funding requires balance=0, got ${balance}`,
      });
      return;
    }

    const registerBody = { channel_id, balance: 0, signature, params, funding_proofs };

    try {
      const result = deps.bridge.fundChannel(JSON.stringify(registerBody)) as {
        channel_id: string;
        capacity: number;
        already_known: boolean;
      };
      res.json({
        success: true,
        channel_id: result.channel_id,
        capacity: result.capacity,
        already_known: result.already_known,
      });
    } catch (e) {
      const reason = getBridgeErrorReason(e);
      const status = mapBridgeErrorStatus(e);
      res.status(status).json({
        success: false,
        error: "Registration failed",
        reason,
        status,
      });
    }
  });

  router.get("/closed/receiver-tokens", (_req, res) => {
    const closedChannels = deps.stores.channelClosed.list();

    const tokens: Array<{
      channel_id: string;
      mint: string;
      unit: string;
      receiver_sum: number;
      token: string;
    }> = [];
    const errors: Array<{ channel_id: string; reason: string }> = [];

    for (const { channelId, data } of closedChannels) {
      try {
        const funding = deps.stores.channelFunding.get(channelId);
        if (!funding) {
          errors.push({ channel_id: channelId, reason: "missing funding data" });
          continue;
        }

        const params = JSON.parse(funding.paramsJson);
        const mint: string = params.mint;
        const unit: string = params.unit ?? "sat";

        if (!mint) {
          errors.push({ channel_id: channelId, reason: "missing mint in params" });
          continue;
        }

        if (!data.receiverProofsJson || data.receiverProofsJson === "[]") {
          errors.push({ channel_id: channelId, reason: "no receiver proofs" });
          continue;
        }

        const token = build_cashu_b_token(mint, unit, data.receiverProofsJson);
        tokens.push({
          channel_id: channelId,
          mint,
          unit,
          receiver_sum: data.receiverSum,
          token,
        });
      } catch (e) {
        errors.push({
          channel_id: channelId,
          reason: (e as Error).message || String(e),
        });
      }
    }

    res.json({ count: tokens.length, tokens, errors });
  });

  return router;
}
