import { readFileSync } from "fs";
import { parse } from "yaml";
import express from "express";
import { WasmSpilmanBridge } from "../wasm/cdk_wasm.js";
import { createSpilmanHost, getServerPubkey } from "./host.js";
import { createSpilmanManagementRouter } from "./router.js";
import { createInMemoryStores, getActivePricing, PricingTable, SpilmanStores } from "./stores.js";
import { createSqliteStores } from "./sqlite_stores.js";
import { fetchAndCacheKeysetsForMint } from "./keysets.js";
import { Spilman } from "./express.js";

export interface SpilmanConfig {
  mints: Record<string, string[]>;
  min_expiry_seconds: number;
  pricing_scale?: number;
  storage?: {
    type: "memory" | "sqlite";
    path?: string;
  };
  pricing: PricingTable;
}

export class ConfigurableSpilman {
  constructor(
    public readonly config: SpilmanConfig,
    public readonly stores: SpilmanStores,
    public readonly host: any,
    public readonly bridge: WasmSpilmanBridge,
    public readonly spilman: Spilman,
    public readonly router: express.Router
  ) {}

  static async fromYaml(configPath: string, secretKeyHex: string): Promise<ConfigurableSpilman> {
    const yamlContent = readFileSync(configPath, "utf8");
    const config = parse(yamlContent) as SpilmanConfig;

    // Support MINT_URL override like Rust version
    if (process.env.MINT_URL) {
      const mintUrl = process.env.MINT_URL;
      const allUnits = Object.keys(config.pricing);
      config.mints = { [mintUrl]: allUnits };
    }

    if (config.pricing_scale === undefined) {
      config.pricing_scale = 1;
    }

    // Initialize stores
    let stores: SpilmanStores;
    if (config.storage?.type === "sqlite" && config.storage.path) {
      stores = createSqliteStores(config.storage.path);
    } else {
      stores = createInMemoryStores();
    }

    const host = createSpilmanHost({
      secretKeyHex,
      mints: config.mints,
      pricing: config.pricing,
      stores,
      pricingScale: config.pricing_scale,
      minExpirySeconds: config.min_expiry_seconds,
      refreshKeysets: async (mint: string) => {
        await fetchAndCacheKeysetsForMint(mint, config.pricing, stores.keysetCache);
      },
    });

    const bridge = new WasmSpilmanBridge(host);
    const spilman = new Spilman(bridge, host);

    const receiverPubkey = getServerPubkey(secretKeyHex);

    const router = createSpilmanManagementRouter({
      bridge,
      receiverPubkey,
      pricing: config.pricing,
      stores,
      pricingScale: config.pricing_scale,
      getActivePricing: () => getActivePricing(config.pricing, stores.keysetCache),
    });

    const instance = new ConfigurableSpilman(config, stores, host, bridge, spilman, router);
    
    // Initial keyset fetch (non-blocking)
    instance.initializeKeysets().catch(e => console.error(`Failed to initialize keysets: ${e}`));

    return instance;
  }

  /**
   * Registers the management router with an Express app.
   * 
   * @param app Express application
   * @returns Spilman instance for processing requests
   */
  initExpress(app: express.Application): Spilman {
    app.use("/channel", this.router);
    return this.spilman;
  }

  async initializeKeysets(): Promise<void> {
    const mintUrls = Object.keys(this.config.mints);
    const results = await Promise.allSettled(
      mintUrls.map((url) => fetchAndCacheKeysetsForMint(url, this.config.pricing, this.stores.keysetCache))
    );

    for (let i = 0; i < results.length; i++) {
      const res = results[i];
      if (res.status === "rejected") {
        console.error(`WARNING: Failed to fetch keysets from ${mintUrls[i]}: ${res.reason}`);
      }
    }
  }
}
