import json
import sqlite3
import threading
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple, Set

UsageMap = Dict[str, int]

@dataclass
class ChannelClosedData:
    expiry_timestamp: int
    balance: int
    receiver_proofs: List[Dict[str, Any]]
    sender_proofs: List[Dict[str, Any]]
    receiver_sum: int
    sender_sum: int

@dataclass
class KeysetCacheEntry:
    info_json: str
    active: bool
    unit: str

class SpilmanStores:
    """In-memory implementation of Spilman stores."""
    def __init__(self):
        # channel_id -> {params, proofs, channel_secret, keyset_info}
        self.channel_funding: Dict[str, Dict[str, str]] = {}
        # channel_id -> {balance: int, signature: str}
        self.channel_largest_payment: Dict[str, Dict[str, Any]] = {}
        # channel_id -> {expiry_timestamp, balance, signature}
        self.channel_closing: Dict[str, Dict[str, Any]] = {}
        # channel_id -> ChannelClosedData
        self.channel_closed: Dict[str, ChannelClosedData] = {}
        # (mint, keyset_id) -> KeysetCacheEntry
        self.keyset_cache: Dict[Tuple[str, str], KeysetCacheEntry] = {}
        # channel_id -> UsageMap
        self.channel_usage: Dict[str, UsageMap] = {}

    def get_usage(self, channel_id: str) -> UsageMap:
        return self.channel_usage.get(channel_id, {})

    def increment_usage(self, channel_id: str, increments: UsageMap):
        usage = self.channel_usage.get(channel_id, {})
        for var_name, delta in increments.items():
            usage[var_name] = usage.get(var_name, 0) + delta
        self.channel_usage[channel_id] = usage

    def get_active_pricing(self, all_pricing: Dict[str, Any]) -> Dict[str, Any]:
        active_units = {entry.unit for entry in self.keyset_cache.values() if entry.active}
        return {u: p for u, p in all_pricing.items() if u in active_units}

    def get_active_units(self) -> Set[str]:
        return {entry.unit for entry in self.keyset_cache.values() if entry.active}

    def get_mints_units_keysets(self) -> Dict[str, Dict[str, List[str]]]:
        result = {}
        for (mint, kid), entry in self.keyset_cache.items():
            if not entry.active:
                continue
            if mint not in result:
                result[mint] = {}
            if entry.unit not in result[mint]:
                result[mint][entry.unit] = []
            result[mint][entry.unit].append(kid)
        return result

class SqliteSpilmanStores(SpilmanStores):
    """SQLite implementation of Spilman stores, mirroring the Rust schema."""
    def __init__(self, db_path: str):
        super().__init__()
        self.db_path = db_path
        self._local = threading.local()
        self._funding_cache = {}
        self._funding_cache_lock = threading.Lock()
        self._init_db()

    def _get_conn(self):
        if not hasattr(self._local, "conn"):
            self._local.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self._local.conn.row_factory = sqlite3.Row
        return self._local.conn

    def _init_db(self):
        conn = self._get_conn()
        conn.executescript("""
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
        """)
        conn.commit()

    # We need to override properties to use SQL instead of self.channel_funding dict
    @property
    def channel_funding(self):
        return _SqliteFundingProxy(self._get_conn(), self._funding_cache, self._funding_cache_lock)
    
    @channel_funding.setter
    def channel_funding(self, value): pass

    @property
    def channel_largest_payment(self):
        return _SqliteBalanceProxy(self._get_conn())
    
    @channel_largest_payment.setter
    def channel_largest_payment(self, value): pass

    @property
    def channel_closing(self):
        return _SqliteClosingProxy(self._get_conn())
    
    @channel_closing.setter
    def channel_closing(self, value): pass

    @property
    def channel_closed(self):
        return _SqliteClosedProxy(self._get_conn(), self._funding_cache, self._funding_cache_lock)
    
    @channel_closed.setter
    def channel_closed(self, value): pass

    @property
    def keyset_cache(self):
        return _SqliteKeysetProxy(self._get_conn())
    
    @keyset_cache.setter
    def keyset_cache(self, value): pass

    def get_usage(self, channel_id: str) -> UsageMap:
        conn = self._get_conn()
        cursor = conn.execute("SELECT var_name, count FROM spilman_usage WHERE channel_id = ?", (channel_id,))
        return {row["var_name"]: row["count"] for row in cursor.fetchall()}

    def increment_usage(self, channel_id: str, increments: UsageMap):
        conn = self._get_conn()
        with conn:
            for var_name, delta in increments.items():
                conn.execute("""
                    INSERT INTO spilman_usage (channel_id, var_name, count)
                    VALUES (?, ?, ?)
                    ON CONFLICT(channel_id, var_name)
                    DO UPDATE SET count = spilman_usage.count + excluded.count
                """, (channel_id, var_name, delta))

    def get_active_units(self) -> Set[str]:
        conn = self._get_conn()
        cursor = conn.execute("SELECT entry_json FROM spilman_keysets")
        units = set()
        for row in cursor.fetchall():
            entry = json.loads(row["entry_json"])
            if entry.get("active"):
                units.add(entry.get("unit"))
        return units

    def get_mints_units_keysets(self) -> Dict[str, Dict[str, List[str]]]:
        conn = self._get_conn()
        cursor = conn.execute("SELECT mint_url, keyset_id, entry_json FROM spilman_keysets")
        result = {}
        for row in cursor.fetchall():
            entry = json.loads(row["entry_json"])
            if not entry.get("active"):
                continue
            mint = row["mint_url"]
            if mint not in result:
                result[mint] = {}
            unit = entry.get("unit")
            if unit not in result[mint]:
                result[mint][unit] = []
            result[mint][unit].append(row["keyset_id"])
        return result

# Proxy classes to make SQLite look like the dicts expected by BaseSpilmanHost

class _SqliteFundingProxy:
    def __init__(self, conn, cache, lock):
        self.conn = conn
        self.cache = cache
        self.lock = lock

    def get(self, key, default=None):
        with self.lock:
            if key in self.cache:
                return self.cache[key]

        row = self.conn.execute("SELECT funding_json FROM spilman_channels WHERE channel_id = ?", (key,)).fetchone()
        if not row: return default
        d = json.loads(row["funding_json"])
        funding = {
            "params": d["params_json"],
            "proofs": d["funding_proofs_json"],
            "channel_secret": d["channel_secret_hex"],
            "keyset_info": d["keyset_info_json"]
        }
        with self.lock:
            # Double check
            if key in self.cache:
                return self.cache[key]
            self.cache[key] = funding
        return funding

    def __getitem__(self, key):
        val = self.get(key)
        if val is None: raise KeyError(key)
        return val

    def __setitem__(self, key, value):
        json_str = json.dumps({
            "params_json": value["params"],
            "funding_proofs_json": value["proofs"],
            "channel_secret_hex": value["channel_secret"],
            "keyset_info_json": value["keyset_info"]
        })
        res = self.conn.execute("INSERT INTO spilman_channels (channel_id, funding_json) VALUES (?, ?) ON CONFLICT DO NOTHING", (key, json_str))
        self.conn.commit()
        with self.lock:
            if res.rowcount > 0:
                self.cache[key] = value
            else:
                # Conflict occurred. Invalidate cache to be safe
                self.cache.pop(key, None)

    def __contains__(self, key): return self.get(key) is not None
    def values(self):
        rows = self.conn.execute("SELECT channel_id, funding_json FROM spilman_channels").fetchall()
        for row in rows:
            d = json.loads(row["funding_json"])
            funding = {
                "params": d["params_json"],
                "proofs": d["funding_proofs_json"],
                "channel_secret": d["channel_secret_hex"],
                "keyset_info": d["keyset_info_json"]
            }
            with self.lock:
                self.cache[row["channel_id"]] = funding
            yield funding
    def items(self):
        rows = self.conn.execute("SELECT channel_id, funding_json FROM spilman_channels").fetchall()
        for row in rows:
            d = json.loads(row["funding_json"])
            funding = {
                "params": d["params_json"],
                "proofs": d["funding_proofs_json"],
                "channel_secret": d["channel_secret_hex"],
                "keyset_info": d["keyset_info_json"]
            }
            with self.lock:
                self.cache[row["channel_id"]] = funding
            yield row["channel_id"], funding

class _SqliteBalanceProxy:
    def __init__(self, conn): self.conn = conn
    def get(self, key, default=None):
        row = self.conn.execute("SELECT balance, signature FROM spilman_channels WHERE channel_id = ? AND signature != ''", (key,)).fetchone()
        if not row: return default
        return {"balance": row["balance"], "signature": row["signature"]}
    def __setitem__(self, key, value):
        self.conn.execute("""
            UPDATE spilman_channels 
            SET balance = ?, signature = ? 
            WHERE channel_id = ? AND (balance < ? OR signature = '')
        """, (value["balance"], value["signature"], key, value["balance"]))
        self.conn.commit()

class _SqliteClosingProxy:
    def __init__(self, conn): self.conn = conn
    def get(self, key, default=None):
        row = self.conn.execute("SELECT closing_json FROM spilman_channels WHERE channel_id = ? AND state = 'Closing'", (key,)).fetchone()
        if not row or not row["closing_json"]: return default
        return json.loads(row["closing_json"])
    def __setitem__(self, key, value):
        self.conn.execute("UPDATE spilman_channels SET state = 'Closing', closing_json = ? WHERE channel_id = ? AND state != 'Closed'", (json.dumps(value), key))
        self.conn.commit()
    def __contains__(self, key):
        row = self.conn.execute("SELECT 1 FROM spilman_channels WHERE channel_id = ? AND state = 'Closing'", (key,)).fetchone()
        return row is not None

class _SqliteClosedProxy:
    def __init__(self, conn, funding_cache=None, funding_lock=None):
        self.conn = conn
        self.funding_cache = funding_cache
        self.funding_lock = funding_lock
    def __contains__(self, key):
        row = self.conn.execute("SELECT 1 FROM spilman_channels WHERE channel_id = ? AND state = 'Closed'", (key,)).fetchone()
        return row is not None
    def __setitem__(self, key, value):
        d = {
            "expiry_timestamp": value.expiry_timestamp,
            "balance": value.balance,
            "receiver_proofs": value.receiver_proofs,
            "sender_proofs": value.sender_proofs,
            "receiver_sum": value.receiver_sum,
            "sender_sum": value.sender_sum
        }
        self.conn.execute("UPDATE spilman_channels SET state = 'Closed', closed_json = ?, closing_json = NULL WHERE channel_id = ? AND state != 'Closed'", (json.dumps(d), key))
        self.conn.commit()
        if self.funding_cache is not None and self.funding_lock is not None:
            with self.funding_lock:
                self.funding_cache.pop(key, None)
    def __getitem__(self, key):
        row = self.conn.execute("SELECT closed_json FROM spilman_channels WHERE channel_id = ? AND state = 'Closed'", (key,)).fetchone()
        if not row: raise KeyError(key)
        d = json.loads(row["closed_json"])
        return ChannelClosedData(**d)

class _SqliteKeysetProxy:
    def __init__(self, conn): self.conn = conn
    def __getitem__(self, key): # key is (mint, keyset_id)
        row = self.conn.execute("SELECT entry_json FROM spilman_keysets WHERE mint_url = ? AND keyset_id = ?", key).fetchone()
        if not row: raise KeyError(key)
        d = json.loads(row["entry_json"])
        return KeysetCacheEntry(**d)
    def __setitem__(self, key, value):
        d = {"info_json": value.info_json, "active": value.active, "unit": value.unit}
        self.conn.execute("INSERT INTO spilman_keysets (mint_url, keyset_id, entry_json) VALUES (?, ?, ?) ON CONFLICT(mint_url, keyset_id) DO UPDATE SET entry_json = ?", (key[0], key[1], json.dumps(d), json.dumps(d)))
        self.conn.commit()
    def __contains__(self, key):
        row = self.conn.execute("SELECT 1 FROM spilman_keysets WHERE mint_url = ? AND keyset_id = ?", key).fetchone()
        return row is not None
    def items(self):
        rows = self.conn.execute("SELECT mint_url, keyset_id, entry_json FROM spilman_keysets").fetchall()
        for row in rows:
            d = json.loads(row["entry_json"])
            yield (row["mint_url"], row["keyset_id"]), KeysetCacheEntry(**d)
    def clear_for_mint(self, mint):
        self.conn.execute("DELETE FROM spilman_keysets WHERE mint_url = ?", (mint,))
        self.conn.commit()
