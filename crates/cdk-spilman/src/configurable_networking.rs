//! Networking for Spilman bridges using `reqwest`.
//!
//! Provides:
//! - [`ReqwestClientNetworking`] — a sync [`SpilmanClientNetworking`] implementation
//!   for client-side mint communication (swap, restore, keyset queries).
//! - [`ReqwestNetworking`] — an async [`SpilmanAsyncNetworking`] implementation
//!   for server-side mint communication (swap, keyset refresh).
//! - Keyset fetching helpers for populating a [`ConfigurableHost`] cache.
//!
//! Gated behind the `configurable-host-reqwest` feature.

use async_trait::async_trait;
use std::sync::Arc;

use crate::configurable_host::{ConfigurableHost, KeysetCacheEntry};
use crate::{SpilmanAsyncNetworking, SpilmanClientNetworking};
use cashu::nuts::{CurrencyUnit, Id};

/// Keyset with full key data, as fetched from a mint.
#[derive(Debug, Clone)]
pub struct MintKeysetWithKeys {
    /// Mint-assigned keyset identifier.
    pub id: Id,
    /// Currency unit supported by this keyset.
    pub unit: CurrencyUnit,
    /// Whether the mint reports this keyset as active.
    pub active: bool,
    /// Input fee rate in parts per thousand.
    pub input_fee_ppk: u64,
    /// Raw key map payload returned by the mint.
    pub keys: serde_json::Value,
}

/// Fetch all keysets (with full keys) from a mint.
///
/// Calls `GET /v1/keysets` to list keysets, then `GET /v1/keys/{id}` for each
/// one to retrieve the full key material.
pub async fn fetch_all_keysets_from_mint(
    mint_url: &str,
) -> Result<Vec<MintKeysetWithKeys>, String> {
    let client = reqwest::Client::new();

    let keysets_url = format!("{mint_url}/v1/keysets");
    let keysets_resp: serde_json::Value = client
        .get(&keysets_url)
        .send()
        .await
        .map_err(|e| format!("Failed to fetch keysets: {e}"))?
        .json()
        .await
        .map_err(|e| format!("Failed to parse keysets response: {e}"))?;

    let keysets = keysets_resp
        .get("keysets")
        .and_then(|k| k.as_array())
        .ok_or("Invalid keysets response")?;

    let mut result = Vec::new();
    for keyset in keysets {
        let id: Id = keyset
            .get("id")
            .and_then(|v| v.as_str())
            .ok_or("Keyset missing id")?
            .parse()
            .map_err(|e| format!("Invalid keyset id: {e}"))?;
        let unit: CurrencyUnit = keyset
            .get("unit")
            .and_then(|v| v.as_str())
            .ok_or("Keyset missing unit")?
            .parse()
            .map_err(|e| format!("Invalid unit: {e}"))?;
        let active = keyset
            .get("active")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let input_fee_ppk = keyset
            .get("input_fee_ppk")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        let keys_url = format!("{mint_url}/v1/keys/{id}");
        let keys_resp: serde_json::Value = client
            .get(&keys_url)
            .send()
            .await
            .map_err(|e| format!("Failed to fetch keys for {id}: {e}"))?
            .json()
            .await
            .map_err(|e| format!("Failed to parse keys response for {id}: {e}"))?;

        let keys = keys_resp
            .get("keysets")
            .and_then(|k| k.as_array())
            .and_then(|arr| arr.first())
            .and_then(|k| k.get("keys"))
            .cloned()
            .unwrap_or(serde_json::json!({}));

        result.push(MintKeysetWithKeys {
            id,
            unit,
            active,
            input_fee_ppk,
            keys,
        });
    }

    Ok(result)
}

/// Build the keyset info JSON blob expected by the bridge.
///
/// This produces the format consumed by [`parse_keyset_info_from_json`](crate::parse_keyset_info_from_json).
pub fn build_keyset_info_json(
    keyset_id: &Id,
    unit: &CurrencyUnit,
    keys: &serde_json::Value,
    input_fee_ppk: u64,
) -> String {
    serde_json::json!({
        "keysetId": keyset_id.to_string(),
        "unit": unit.to_string(),
        "keys": keys,
        "inputFeePpk": input_fee_ppk,
    })
    .to_string()
}

/// Fetch keysets from a mint and populate the host's keyset cache.
pub async fn fetch_and_cache_keysets(
    host: &ConfigurableHost,
    mint_url: &str,
) -> Result<(), String> {
    let keysets = fetch_all_keysets_from_mint(mint_url).await?;
    for ks in keysets {
        let info_json = build_keyset_info_json(&ks.id, &ks.unit, &ks.keys, ks.input_fee_ppk);
        host.set_keyset(
            mint_url,
            ks.id,
            KeysetCacheEntry {
                info_json,
                active: ks.active,
                unit: ks.unit,
            },
        )?;
    }
    Ok(())
}

/// Ready-made [`SpilmanClientNetworking`] implementation using `reqwest`.
///
/// Provides HTTP-based mint communication for client-side operations:
/// swap, restore, keyset listing, and key fetching.
///
/// Uses `tokio::task::block_in_place` to bridge the sync trait with async
/// reqwest calls. Requires a multi-threaded tokio runtime.
///
/// # Example
///
/// ```ignore
/// let networking = ReqwestClientNetworking::new();
/// let bridge = SpilmanClientBridge::new(client_host, networking);
/// let keyset_info = bridge.fetch_keyset_info(mint_url, keyset_id)?;
/// ```
#[derive(Debug)]
pub struct ReqwestClientNetworking {
    client: reqwest::Client,
    runtime: tokio::runtime::Handle,
}

impl ReqwestClientNetworking {
    /// Create a new `ReqwestClientNetworking` using the current tokio runtime handle.
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
            runtime: tokio::runtime::Handle::current(),
        }
    }

    fn blocking_get(&self, url: &str) -> Result<String, String> {
        let client = self.client.clone();
        let url = url.to_string();
        tokio::task::block_in_place(|| {
            self.runtime.block_on(async {
                let resp = client
                    .get(&url)
                    .send()
                    .await
                    .map_err(|e| format!("GET {url} failed: {e}"))?;
                if !resp.status().is_success() {
                    let status = resp.status();
                    let body = resp.text().await.unwrap_or_default();
                    return Err(format!("GET {url}: {status} - {body}"));
                }
                resp.text()
                    .await
                    .map_err(|e| format!("GET {url} read body: {e}"))
            })
        })
    }

    fn blocking_post(&self, url: &str, body: &str) -> Result<String, String> {
        let client = self.client.clone();
        let url = url.to_string();
        let body = body.to_string();
        tokio::task::block_in_place(|| {
            self.runtime.block_on(async {
                let resp = client
                    .post(&url)
                    .header("Content-Type", "application/json")
                    .body(body)
                    .send()
                    .await
                    .map_err(|e| format!("POST {url} failed: {e}"))?;
                if !resp.status().is_success() {
                    let status = resp.status();
                    let body = resp.text().await.unwrap_or_default();
                    return Err(body);
                }
                resp.text()
                    .await
                    .map_err(|e| format!("POST {url} read body: {e}"))
            })
        })
    }
}

impl SpilmanClientNetworking for ReqwestClientNetworking {
    fn call_mint_swap(&self, mint_url: &str, swap_request_json: &str) -> Result<String, String> {
        self.blocking_post(&format!("{mint_url}/v1/swap"), swap_request_json)
    }

    fn call_mint_restore(
        &self,
        mint_url: &str,
        restore_request_json: &str,
    ) -> Result<String, String> {
        self.blocking_post(&format!("{mint_url}/v1/restore"), restore_request_json)
    }

    fn call_mint_keysets(&self, mint_url: &str) -> Result<String, String> {
        self.blocking_get(&format!("{mint_url}/v1/keysets"))
    }

    fn call_mint_keys(&self, mint_url: &str, keyset_id: &str) -> Result<String, String> {
        self.blocking_get(&format!("{mint_url}/v1/keys/{keyset_id}"))
    }
}

/// Ready-made [`SpilmanAsyncNetworking`] implementation using `reqwest`.
///
/// Wraps a shared [`ConfigurableHost`] and provides:
/// - `call_mint_swap` — POST to `/v1/swap`
/// - `refresh_all_keysets` — re-fetches and caches all keysets
///
/// # Example
///
/// ```ignore
/// let host = Arc::new(ConfigurableHost::from_yaml(&yaml, &key)?);
/// host.initialize_keysets().await?;
/// let networking = Arc::new(ReqwestNetworking::new(host.clone()));
/// ```
#[derive(Debug)]
pub struct ReqwestNetworking {
    host: Arc<ConfigurableHost>,
}

impl ReqwestNetworking {
    /// Create a new `ReqwestNetworking` wrapping the given host.
    pub fn new(host: Arc<ConfigurableHost>) -> Self {
        Self { host }
    }
}

#[async_trait]
impl SpilmanAsyncNetworking for ReqwestNetworking {
    async fn call_mint_swap(
        &self,
        mint_url: &str,
        swap_request_json: &str,
    ) -> Result<String, String> {
        let client = reqwest::Client::new();
        let url = format!("{mint_url}/v1/swap");

        let resp = client
            .post(&url)
            .header("Content-Type", "application/json")
            .body(swap_request_json.to_string())
            .send()
            .await
            .map_err(|e| format!("Swap request failed: {e}"))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();

            // Try to parse the body as a NUT-00 error: {"detail": "...", "code": ...}
            // Mints may also include an "error" field (e.g. nutmix).
            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&body) {
                let code = parsed.get("code").and_then(|v| v.as_u64());
                let detail = parsed
                    .get("detail")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();
                tracing::warn!(
                    %status,
                    nut00_code = ?code,
                    detail,
                    "Mint rejected swap (NUT-00 error)"
                );
                // Return the raw JSON body so callers can deserialize it.
                return Err(body);
            }

            return Err(format!("Swap failed: {status} - {body}"));
        }

        resp.text()
            .await
            .map_err(|e| format!("Failed to read swap response: {e}"))
    }

    async fn refresh_all_keysets(&self, mint: &str) -> Result<(), String> {
        tracing::info!("Refreshing keysets from {mint}...");
        fetch_and_cache_keysets(&self.host, mint).await?;
        tracing::info!("Keyset refresh complete for {mint}");
        Ok(())
    }
}
