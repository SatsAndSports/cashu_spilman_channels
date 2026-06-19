/// Extract the NUT-00 error code from a raw mint error string.
///
/// Returns `None` when the string is not valid JSON or does not contain a
/// numeric `code` field.
pub fn extract_nut00_error_code(raw: &str) -> Option<u32> {
    serde_json::from_str::<serde_json::Value>(raw)
        .ok()
        .and_then(|value| value.get("code")?.as_u64())
        .map(|code| code as u32)
}

/// True when a NUT-00 error code represents stale/unknown keyset state.
///
/// NUT-00 reserves the 12xxx range for keyset errors. Code `99999` is treated
/// as retryable for Nutmix, which currently uses that catch-all code instead of
/// the spec-standard 12001 ("Keyset is not known").
pub fn is_retryable_keyset_error_code(code: u32) -> bool {
    (12000..13000).contains(&code) || code == 99999
}

/// True when a raw mint error should trigger one keyset refresh and retry.
pub fn is_retryable_keyset_mint_error(raw: &str) -> bool {
    extract_nut00_error_code(raw).is_some_and(is_retryable_keyset_error_code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_nut00_error_code() {
        assert_eq!(extract_nut00_error_code(r#"{"code":12001}"#), Some(12001));
        assert_eq!(extract_nut00_error_code(r#"{"detail":"missing"}"#), None);
        assert_eq!(extract_nut00_error_code("not json"), None);
    }

    #[test]
    fn classifies_retryable_keyset_codes() {
        assert!(is_retryable_keyset_error_code(12000));
        assert!(is_retryable_keyset_error_code(12001));
        assert!(is_retryable_keyset_error_code(12999));
        assert!(is_retryable_keyset_error_code(99999));

        assert!(!is_retryable_keyset_error_code(11001));
        assert!(!is_retryable_keyset_error_code(13000));
    }

    #[test]
    fn classifies_retryable_keyset_mint_errors() {
        assert!(is_retryable_keyset_mint_error(
            r#"{"code":12001,"detail":"keyset is not known"}"#
        ));
        assert!(is_retryable_keyset_mint_error(
            r#"{"code":99999,"detail":"unknown"}"#
        ));

        assert!(!is_retryable_keyset_mint_error(
            r#"{"code":11001,"detail":"proofs already spent"}"#
        ));
        assert!(!is_retryable_keyset_mint_error(
            r#"{"code":13000,"detail":"not keyset"}"#
        ));
        assert!(!is_retryable_keyset_mint_error(
            r#"{"detail":"missing code"}"#
        ));
        assert!(!is_retryable_keyset_mint_error("transport failure"));
    }
}
