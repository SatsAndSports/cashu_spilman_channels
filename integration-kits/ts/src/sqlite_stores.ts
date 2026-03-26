import Database from "better-sqlite3";
import {
  SpilmanStores,
  ChannelFundingStore,
  ChannelBalanceStore,
  ChannelUsageStore,
  ChannelClosingStore,
  ChannelClosedStore,
  KeysetCache,
  ChannelFundingData,
  UsageMap,
  KeysetCacheEntry,
} from "./stores.js";

export function createSqliteStores(dbPath: string): SpilmanStores {
  const db = new Database(dbPath);
  const fundingCache = new Map<string, ChannelFundingData>();

  // Initialize schema
  db.exec(`
    CREATE TABLE IF NOT EXISTS spilman_channels (
        channel_id    TEXT NOT NULL PRIMARY KEY,
        funding_json  TEXT NOT NULL,
        balance       INTEGER NOT NULL DEFAULT 0,
        signature     TEXT NOT NULL DEFAULT '',
        state         TEXT NOT NULL DEFAULT 'Open',
        closing_json  TEXT,
        closed_json   TEXT
    );

    CREATE TABLE IF NOT EXISTS spilman_usage (
        channel_id TEXT NOT NULL,
        var_name   TEXT NOT NULL,
        count      INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (channel_id, var_name)
    );

    CREATE TABLE IF NOT EXISTS spilman_keysets (
        mint_url   TEXT NOT NULL,
        keyset_id  TEXT NOT NULL,
        entry_json TEXT NOT NULL,
        PRIMARY KEY (mint_url, keyset_id)
    );
  `);

  const channelFunding: ChannelFundingStore = {
    get(channelId) {
      const cached = fundingCache.get(channelId);
      if (cached) return cached;

      const row = db.prepare("SELECT funding_json FROM spilman_channels WHERE channel_id = ?").get(channelId) as any;
      if (!row) return null;
      try {
        const data = JSON.parse(row.funding_json);
        const funding: ChannelFundingData = {
          paramsJson: data.params_json,
          fundingProofsJson: data.funding_proofs_json,
          channelSecret: data.channel_secret_hex,
          keysetInfoJson: data.keyset_info_json,
          ...(data.secret_key && { secretKey: data.secret_key }),
        };
        fundingCache.set(channelId, funding);
        return funding;
      } catch {
        return null;
      }
    },
    insert(channelId, data) {
      const json = JSON.stringify({
        params_json: data.paramsJson,
        funding_proofs_json: data.fundingProofsJson,
        channel_secret_hex: data.channelSecret,
        keyset_info_json: data.keysetInfoJson,
        ...(data.secretKey && { secret_key: data.secretKey }),
      });
      const result = db.prepare("INSERT INTO spilman_channels (channel_id, funding_json) VALUES (?, ?) ON CONFLICT DO NOTHING").run(channelId, json);
      if (result.changes > 0) {
        fundingCache.set(channelId, data);
      } else {
        // Conflict occurred. Invalidate cache to be safe
        fundingCache.delete(channelId);
      }
    },
    all() {
      const rows = db.prepare("SELECT channel_id, funding_json FROM spilman_channels").all() as any[];
      const map = new Map<string, ChannelFundingData>();
      for (const row of rows) {
        try {
          const data = JSON.parse(row.funding_json);
          const fd: ChannelFundingData = {
            paramsJson: data.params_json,
            fundingProofsJson: data.funding_proofs_json,
            channelSecret: data.channel_secret_hex,
            keysetInfoJson: data.keyset_info_json,
            ...(data.secret_key && { secretKey: data.secret_key }),
          };
          map.set(row.channel_id, fd);
          fundingCache.set(row.channel_id, fd);
        } catch {}
      }
      return map;
    },
  };

  const channelBalance: ChannelBalanceStore = {
    get(channelId) {
      const row = db.prepare("SELECT balance, signature FROM spilman_channels WHERE channel_id = ? AND signature != ''").get(channelId) as any;
      if (!row) return null;
      return { balance: row.balance, signature: row.signature };
    },
    update(channelId, balance, signature) {
      db.prepare(`
        UPDATE spilman_channels
        SET balance = ?, signature = ?
        WHERE channel_id = ?
          AND (balance < ? OR signature = '')
      `).run(balance, signature, channelId, balance);
    },
  };

  const channelUsage: ChannelUsageStore = {
    getUsage(channelId) {
      const rows = db.prepare("SELECT var_name, count FROM spilman_usage WHERE channel_id = ?").all(channelId) as any[];
      if (rows.length === 0) return null;
      const usage: UsageMap = {};
      for (const row of rows) {
        usage[row.var_name] = row.count;
      }
      return usage;
    },
    incrementUsage(channelId, increments) {
      const insert = db.prepare(`
        INSERT INTO spilman_usage (channel_id, var_name, count)
        VALUES (?, ?, ?)
        ON CONFLICT(channel_id, var_name)
        DO UPDATE SET count = spilman_usage.count + excluded.count
      `);
      
      const transaction = db.transaction((id: string, incs: UsageMap) => {
        for (const [varName, delta] of Object.entries(incs)) {
          insert.run(id, varName, delta);
        }
      });
      
      transaction(channelId, increments);
    },
  };

  const channelClosing: ChannelClosingStore = {
    isClosing(channelId) {
      const row = db.prepare("SELECT state FROM spilman_channels WHERE channel_id = ?").get(channelId) as any;
      return row?.state === "Closing";
    },
    markClosing(channelId, expiry_timestamp, balance, signature) {
      const json = JSON.stringify({ expiry_timestamp, balance, signature });
      db.prepare("UPDATE spilman_channels SET state = 'Closing', closing_json = ? WHERE channel_id = ? AND state != 'Closed'").run(json, channelId);
    },
    get(channelId) {
      const row = db.prepare("SELECT closing_json FROM spilman_channels WHERE channel_id = ? AND state = 'Closing'").get(channelId) as any;
      if (!row?.closing_json) return null;
      return JSON.parse(row.closing_json);
    },
    remove(channelId) {
      // In SQLite we don't 'remove', we change state. But this is used when moving to Closed.
      // Actually the markClosed implementation handles state transition.
    },
  };

  const channelClosed: ChannelClosedStore = {
    isClosed(channelId) {
      const row = db.prepare("SELECT state FROM spilman_channels WHERE channel_id = ?").get(channelId) as any;
      return row?.state === "Closed";
    },
    markClosed(channelId, expiry_timestamp, closedAmount, valueAfterStage1, receiverSum, senderSum, receiverProofsJson, senderProofsJson) {
      const json = JSON.stringify({
        expiry_timestamp,
        closed_amount: closedAmount,
        value_after_stage1: valueAfterStage1,
        receiver_sum: receiverSum,
        sender_sum: senderSum,
        receiver_proofs_json: receiverProofsJson,
        sender_proofs_json: senderProofsJson,
      });
      db.prepare("UPDATE spilman_channels SET state = 'Closed', closed_json = ?, closing_json = NULL WHERE channel_id = ? AND state != 'Closed'").run(json, channelId);
      fundingCache.delete(channelId);
    },
    get(channelId) {
      const row = db.prepare("SELECT closed_json FROM spilman_channels WHERE channel_id = ? AND state = 'Closed'").get(channelId) as any;
      if (!row?.closed_json) return null;
      const data = JSON.parse(row.closed_json);
      return {
        expiry_timestamp: data.expiry_timestamp,
        closedAmount: data.closed_amount,
        valueAfterStage1: data.value_after_stage1,
        receiverSum: data.receiver_sum,
        senderSum: data.sender_sum,
        receiverProofsJson: data.receiver_proofs_json,
        senderProofsJson: data.sender_proofs_json,
      };
    },
    list() {
      const rows = db.prepare("SELECT channel_id, closed_json FROM spilman_channels WHERE state = 'Closed'").all() as any[];
      return rows
        .filter((r: any) => r.closed_json)
        .map((r: any) => {
          const data = JSON.parse(r.closed_json);
          return {
            channelId: r.channel_id,
            data: {
              expiry_timestamp: data.expiry_timestamp,
              closedAmount: data.closed_amount,
              valueAfterStage1: data.value_after_stage1,
              receiverSum: data.receiver_sum,
              senderSum: data.sender_sum,
              receiverProofsJson: data.receiver_proofs_json,
              senderProofsJson: data.sender_proofs_json,
            },
          };
        });
    },
  };

  const keysetCache: KeysetCache = {
    get(mint, keysetId) {
      const row = db.prepare("SELECT entry_json FROM spilman_keysets WHERE mint_url = ? AND keyset_id = ?").get(mint, keysetId) as any;
      if (!row) return null;
      return JSON.parse(row.entry_json);
    },
    set(mint, keysetId, entry) {
      const json = JSON.stringify(entry);
      db.prepare("INSERT INTO spilman_keysets (mint_url, keyset_id, entry_json) VALUES (?, ?, ?) ON CONFLICT(mint_url, keyset_id) DO UPDATE SET entry_json = ?").run(mint, keysetId, json, json);
    },
    has(mint, keysetId) {
      const row = db.prepare("SELECT 1 FROM spilman_keysets WHERE mint_url = ? AND keyset_id = ?").get(mint, keysetId);
      return row !== undefined;
    },
    getActiveIds(mint, unit) {
      const rows = db.prepare("SELECT keyset_id, entry_json FROM spilman_keysets WHERE mint_url = ?").all(mint) as any[];
      return rows.filter(r => {
        const entry = JSON.parse(r.entry_json);
        return entry.active && entry.unit === unit;
      }).map(r => r.keyset_id);
    },
    clearForMint(mint) {
      db.prepare("DELETE FROM spilman_keysets WHERE mint_url = ?").run(mint);
    },
    getMintsUnitsKeysets() {
      const rows = db.prepare("SELECT mint_url, keyset_id, entry_json FROM spilman_keysets").all() as any[];
      const result: Record<string, Record<string, string[]>> = {};
      for (const row of rows) {
        const entry = JSON.parse(row.entry_json);
        if (!entry.active) continue;
        if (!result[row.mint_url]) result[row.mint_url] = {};
        if (!result[row.mint_url][entry.unit]) result[row.mint_url][entry.unit] = [];
        result[row.mint_url][entry.unit].push(row.keyset_id);
      }
      return result;
    },
    getActiveUnits() {
      const rows = db.prepare("SELECT entry_json FROM spilman_keysets").all() as any[];
      const units = new Set<string>();
      for (const row of rows) {
        const entry = JSON.parse(row.entry_json);
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
