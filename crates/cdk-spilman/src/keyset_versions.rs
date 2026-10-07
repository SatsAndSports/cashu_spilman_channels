//! Library capabilities, application selection policy, and tolerant mint discovery.
use cashu::nuts::Id;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;

#[cfg(test)]
pub(crate) mod tests;

/// A keyset version implemented by this library (wire prefixes 00 and 01).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeysetVersion {
    /// Version 1, prefix byte 0x00.
    V1,
    /// Version 2, prefix byte 0x01.
    V2,
}

/// An explicit version set. Serialized as an array such as `["v1", "v2"]`.
/// Fixed constants never expand when library capabilities increase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "Vec<KeysetVersion>", into = "Vec<KeysetVersion>")]
pub struct KeysetVersions(u8);

impl KeysetVersions {
    /// Allow only V1.
    pub const V1: Self = Self(1);
    /// Allow only V2.
    pub const V2: Self = Self(2);
    /// Allow exactly V1 and V2, even after future library upgrades.
    pub const V1_AND_V2: Self = Self(3);

    /// Follow the library's implemented capabilities, including future additions.
    pub const fn library_supported() -> Self {
        Self::V1_AND_V2
    }

    /// Whether this set allows the given implemented version.
    pub fn contains(self, version: KeysetVersion) -> bool {
        self.0
            & match version {
                KeysetVersion::V1 => 1,
                KeysetVersion::V2 => 2,
            }
            != 0
    }

    /// Whether a typed keyset ID is allowed.
    pub fn allows(self, id: Id) -> bool {
        self.contains(match id.get_version() {
            cashu::nuts::nut02::KeySetVersion::Version00 => KeysetVersion::V1,
            cashu::nuts::nut02::KeySetVersion::Version01 => KeysetVersion::V2,
        })
    }
}

impl<const N: usize> From<[KeysetVersion; N]> for KeysetVersions {
    fn from(value: [KeysetVersion; N]) -> Self {
        Self::from(value.to_vec())
    }
}

impl From<Vec<KeysetVersion>> for KeysetVersions {
    fn from(value: Vec<KeysetVersion>) -> Self {
        Self(value.iter().fold(0, |bits, v| {
            bits | match v {
                KeysetVersion::V1 => 1,
                KeysetVersion::V2 => 2,
            }
        }))
    }
}

impl From<KeysetVersions> for Vec<KeysetVersion> {
    fn from(value: KeysetVersions) -> Self {
        [KeysetVersion::V1, KeysetVersion::V2]
            .into_iter()
            .filter(|v| value.contains(*v))
            .collect()
    }
}

/// Per-operation policy for selecting new output keysets, never an input/cache filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeysetSelectionPolicy {
    /// Explicitly allowed versions. Empty means no eligible output keyset.
    pub allowed_versions: KeysetVersions,
}

/// Classify the first hex byte, fully validating IDs with supported prefixes.
/// `None` means an identifiable unsupported version; its remaining format is opaque.
pub fn supported_keyset_id(raw: &str) -> Result<Option<Id>, String> {
    let prefix = raw
        .get(..2)
        .ok_or("Keyset ID must start with a hex version byte")?;
    if !prefix.as_bytes().iter().all(u8::is_ascii_hexdigit) {
        return Err("Keyset ID must start with a hex version byte".to_string());
    }
    let byte = u8::from_str_radix(prefix, 16)
        .map_err(|_| "Keyset ID must start with a hex version byte".to_string())?;
    if byte > 1 {
        return Ok(None);
    }
    raw.parse::<Id>()
        .map(Some)
        .map_err(|e| format!("Invalid supported keyset ID: {e}"))
}

/// Metadata about an entry skipped without interpreting its unknown key material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkippedKeysetVersion {
    /// Unknown version prefix byte.
    pub version_byte: u8,
    /// Unit if recognizable in the otherwise opaque entry.
    pub unit: Option<String>,
    /// Whether the entry explicitly advertised itself as active.
    pub active: bool,
}

/// Supported listing plus diagnostics. No application policy is applied here.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeysetDiscovery {
    /// All supported entries, including inactive entries, in mint order.
    pub keysets: Vec<Value>,
    /// Unsupported entries skipped before fetching or interpreting keys.
    pub skipped: Vec<SkippedKeysetVersion>,
    /// Units with unsupported active entries and no supported active entry.
    /// `None` indicates entries whose unit was not recognizable.
    pub unsupported_active_units: Vec<Option<String>>,
}

impl KeysetDiscovery {
    /// Classify a mint-wide response. Malformed supported entries remain errors.
    pub fn from_json(json: &str) -> Result<Self, String> {
        let response: Value = serde_json::from_str(json).map_err(|e| e.to_string())?;
        let entries = response
            .get("keysets")
            .and_then(Value::as_array)
            .ok_or("Invalid /v1/keysets response: missing 'keysets' array")?;
        let mut keysets = Vec::new();
        let mut skipped = Vec::new();
        let mut supported_active = BTreeSet::new();
        let mut unsupported_active = BTreeSet::new();
        for entry in entries {
            let raw = entry
                .get("id")
                .and_then(Value::as_str)
                .ok_or("Missing or invalid keyset id")?;
            let unit = entry.get("unit").and_then(Value::as_str).map(str::to_owned);
            let active = entry
                .get("active")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            match supported_keyset_id(raw)? {
                Some(_) => {
                    // Validate standard metadata without interpreting unknown-version schemas.
                    serde_json::from_value::<cashu::nuts::KeySetInfo>(entry.clone())
                        .map_err(|e| format!("Invalid supported keyset metadata: {e}"))?;
                    if active {
                        supported_active.insert(unit);
                    }
                    keysets.push(entry.clone());
                }
                None => {
                    if active {
                        unsupported_active.insert(unit.clone());
                    }
                    skipped.push(SkippedKeysetVersion {
                        version_byte: u8::from_str_radix(&raw[..2], 16)
                            .map_err(|e| e.to_string())?,
                        unit,
                        active,
                    });
                }
            }
        }
        Ok(Self {
            keysets,
            skipped,
            unsupported_active_units: unsupported_active
                .difference(&supported_active)
                .cloned()
                .collect(),
        })
    }

    /// Emit one warning per affected unit; callers can also inspect diagnostics directly.
    pub fn warn_if_no_supported_active(&self, mint_url: &str) {
        for unit in &self.unsupported_active_units {
            tracing::warn!(mint = mint_url, unit = ?unit,
                "Mint advertises unsupported active keysets but no supported active keyset for this unit; this library supports V1 (00) and V2 (01)");
        }
    }

    /// Select the first active allowed keyset for a unit from the validated listing.
    /// This is metadata selection only; callers must also enforce expiry/output rules.
    pub fn select_active(&self, unit: &str, policy: KeysetSelectionPolicy) -> Result<Id, String> {
        for entry in &self.keysets {
            let info: cashu::nuts::KeySetInfo =
                serde_json::from_value(entry.clone()).map_err(|e| e.to_string())?;
            if info.active
                && info.unit.to_string() == unit
                && policy.allowed_versions.allows(info.id)
            {
                return Ok(info.id);
            }
        }
        Err(format!(
            "No compatible active keyset for unit '{unit}' with allowed versions {:?}",
            Vec::<KeysetVersion>::from(policy.allowed_versions)
        ))
    }
}

/// JSON discovery report for language bindings; uses the same validation as Rust.
pub fn discover_keysets_json(response_json: &str) -> Result<String, String> {
    serde_json::to_string(&KeysetDiscovery::from_json(response_json)?).map_err(|e| e.to_string())
}

/// Select from a mint listing using a JSON policy (`{"allowed_versions":["v1","v2"]}`).
pub fn select_active_keyset_json(
    response_json: &str,
    unit: &str,
    policy_json: &str,
) -> Result<String, String> {
    let policy = serde_json::from_str(policy_json)
        .map_err(|e| format!("Invalid keyset selection policy: {e}"))?;
    KeysetDiscovery::from_json(response_json)?
        .select_active(unit, policy)
        .map(|id| id.to_string())
}
