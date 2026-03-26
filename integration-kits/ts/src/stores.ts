export interface ChannelFundingData {
  paramsJson: string;
  fundingProofsJson: string;
  channelSecret: string;
  keysetInfoJson: string;
  secretKey?: string;  // Server's secret key at funding time (for key rotation)
}

export interface ChannelBalance {
  balance: number;
  signature: string;
}

export type UsageMap = Record<string, number>;

export interface ClosingChannelData {
  expiry_timestamp: number;
  balance: number;
  signature: string;
}

export interface ClosedChannelData {
  expiry_timestamp: number;
  closedAmount: number;
  valueAfterStage1: number;
  receiverSum: number;
  senderSum: number;
  receiverProofsJson: string;
  senderProofsJson: string;
}

export interface KeysetCacheEntry {
  infoJson: string;
  active: boolean;
  unit: string;
}

export interface PricingEntry {
  min_capacity: number;
  max_amount_per_output?: number;
  variables: UsageMap;
}

export type PricingTable = Record<string, PricingEntry>;

export interface ChannelFundingStore {
  get(channelId: string): ChannelFundingData | null;
  insert(channelId: string, data: ChannelFundingData): void;
  all(): Map<string, ChannelFundingData>;
}

export interface ChannelBalanceStore {
  get(channelId: string): ChannelBalance | null;
  update(channelId: string, balance: number, signature: string): void;
}

export interface ChannelUsageStore {
  getUsage(channelId: string): UsageMap | null;
  incrementUsage(channelId: string, increments: UsageMap): void;
}

export interface ChannelClosingStore {
  isClosing(channelId: string): boolean;
  markClosing(channelId: string, expiry_timestamp: number, balance: number, signature: string): void;
  get(channelId: string): ClosingChannelData | null;
  remove(channelId: string): void;
}

export interface ChannelClosedStore {
  isClosed(channelId: string): boolean;
  markClosed(
    channelId: string,
    expiry_timestamp: number,
    closedAmount: number,
    valueAfterStage1: number,
    receiverSum: number,
    senderSum: number,
    receiverProofsJson: string,
    senderProofsJson: string
  ): void;
  get(channelId: string): ClosedChannelData | null;
  list(): Array<{ channelId: string; data: ClosedChannelData }>;
}

export interface KeysetCache {
  get(mint: string, keysetId: string): KeysetCacheEntry | null;
  set(mint: string, keysetId: string, entry: KeysetCacheEntry): void;
  has(mint: string, keysetId: string): boolean;
  getActiveIds(mint: string, unit: string): string[];
  clearForMint(mint: string): void;
  getMintsUnitsKeysets(): Record<string, Record<string, string[]>>;
  getActiveUnits(): Set<string>;
}

export interface SpilmanStores {
  channelFunding: ChannelFundingStore;
  channelBalance: ChannelBalanceStore;
  channelUsage: ChannelUsageStore;
  channelClosing: ChannelClosingStore;
  channelClosed: ChannelClosedStore;
  keysetCache: KeysetCache;
}

export function createInMemoryStores(): SpilmanStores {
  const channelFundingStore = new Map<string, ChannelFundingData>();
  const channelBalanceStore = new Map<string, ChannelBalance>();
  const channelUsageStore = new Map<string, UsageMap>();
  const channelClosingStore = new Map<string, ClosingChannelData>();
  const channelClosedStore = new Map<string, ClosedChannelData>();
  const keysetCacheStore = new Map<string, KeysetCacheEntry>();

  const channelFunding: ChannelFundingStore = {
    get(channelId) {
      return channelFundingStore.get(channelId) ?? null;
    },
    insert(channelId, data) {
      if (!channelFundingStore.has(channelId)) {
        channelFundingStore.set(channelId, data);
      }
    },
    all() {
      return channelFundingStore;
    },
  };

  const channelBalance: ChannelBalanceStore = {
    get(channelId) {
      return channelBalanceStore.get(channelId) ?? null;
    },
    update(channelId, balance, signature) {
      const current = channelBalanceStore.get(channelId);
      if (!current || balance > current.balance) {
        channelBalanceStore.set(channelId, { balance, signature });
      }
    },
  };

  const channelUsage: ChannelUsageStore = {
    getUsage(channelId) {
      return channelUsageStore.get(channelId) ?? null;
    },
    incrementUsage(channelId, increments) {
      let usage = channelUsageStore.get(channelId);
      if (!usage) {
        usage = {};
        channelUsageStore.set(channelId, usage);
      }
      for (const [varName, delta] of Object.entries(increments)) {
        usage[varName] = (usage[varName] ?? 0) + delta;
      }
    },
  };

  const channelClosing: ChannelClosingStore = {
    isClosing(channelId) {
      return channelClosingStore.has(channelId);
    },
    markClosing(channelId, expiry_timestamp, balance, signature) {
      channelClosingStore.set(channelId, { expiry_timestamp, balance, signature });
    },
    get(channelId) {
      return channelClosingStore.get(channelId) ?? null;
    },
    remove(channelId) {
      channelClosingStore.delete(channelId);
    },
  };

  const channelClosed: ChannelClosedStore = {
    isClosed(channelId) {
      return channelClosedStore.has(channelId);
    },
    markClosed(
      channelId,
      expiry_timestamp,
      closedAmount,
      valueAfterStage1,
      receiverSum,
      senderSum,
      receiverProofsJson,
      senderProofsJson
    ) {
      channelClosing.remove(channelId);
      channelClosedStore.set(channelId, {
        expiry_timestamp,
        closedAmount,
        valueAfterStage1,
        receiverSum,
        senderSum,
        receiverProofsJson,
        senderProofsJson,
      });
    },
    get(channelId) {
      return channelClosedStore.get(channelId) ?? null;
    },
    list() {
      const result: Array<{ channelId: string; data: ClosedChannelData }> = [];
      for (const [channelId, data] of channelClosedStore) {
        result.push({ channelId, data });
      }
      return result;
    },
  };

  const keysetKey = (mint: string, keysetId: string): string => `${mint}|${keysetId}`;

  const keysetCache: KeysetCache = {
    get(mint, keysetId) {
      return keysetCacheStore.get(keysetKey(mint, keysetId)) ?? null;
    },
    set(mint, keysetId, entry) {
      keysetCacheStore.set(keysetKey(mint, keysetId), entry);
    },
    has(mint, keysetId) {
      return keysetCacheStore.has(keysetKey(mint, keysetId));
    },
    getActiveIds(mint, unit) {
      const result: string[] = [];
      for (const [key, entry] of keysetCacheStore) {
        if (key.startsWith(mint + "|") && entry.unit === unit && entry.active) {
          result.push(key.split("|")[1]);
        }
      }
      return result;
    },
    clearForMint(mint) {
      const prefix = mint + "|";
      for (const key of keysetCacheStore.keys()) {
        if (key.startsWith(prefix)) {
          keysetCacheStore.delete(key);
        }
      }
    },
    getMintsUnitsKeysets() {
      const result: Record<string, Record<string, string[]>> = {};
      for (const [key, entry] of keysetCacheStore) {
        if (!entry.active) continue;
        const [mint, keysetId] = key.split("|");
        if (!result[mint]) result[mint] = {};
        if (!result[mint][entry.unit]) result[mint][entry.unit] = [];
        result[mint][entry.unit].push(keysetId);
      }
      return result;
    },
    getActiveUnits() {
      const units = new Set<string>();
      for (const entry of keysetCacheStore.values()) {
        if (entry.active) units.add(entry.unit);
      }
      return units;
    },
  };

  return {
    channelFunding,
    channelBalance,
    channelUsage,
    channelClosing,
    channelClosed,
    keysetCache,
  };
}

export interface ChannelStatus {
  channel_id: string;
  capacity: number;
  balance: number;
  usage: UsageMap;
  amount_due: number;
  closed: boolean;
  closed_amount?: number;
}

export function getChannelStatus(
  channelId: string,
  pricing: PricingTable,
  stores: SpilmanStores,
  pricingScale: number = 1
): ChannelStatus {
  const funding = stores.channelFunding.get(channelId);
  if (!funding) {
    throw new Error("unknown channel");
  }

  const params = JSON.parse(funding.paramsJson);
  const balance = stores.channelBalance.get(channelId);
  const usage = stores.channelUsage.getUsage(channelId) ?? {};
  const closedData = stores.channelClosed.get(channelId);

  const unitPricing = pricing[params.unit];
  let total = 0;
  if (unitPricing) {
    for (const [varName, price] of Object.entries(unitPricing.variables)) {
      total += (usage[varName] ?? 0) * price;
    }
  }
  const scale = pricingScale > 0 ? pricingScale : 1;
  const amountDue = Math.ceil(total / scale);

  return {
    channel_id: channelId,
    capacity: params.capacity,
    balance: balance?.balance ?? 0,
    usage,
    amount_due: amountDue,
    closed: closedData !== null,
    ...(closedData && { closed_amount: closedData.closedAmount }),
  };
}

export function getActivePricing(
  pricing: PricingTable,
  keysetCache: KeysetCache
): PricingTable {
  const activeUnits = keysetCache.getActiveUnits();
  const result: PricingTable = {};
  for (const unit of activeUnits) {
    if (unit in pricing) {
      result[unit] = pricing[unit];
    }
  }
  return result;
}
