use super::*;
use serde_json::json;

pub(crate) fn fixtures() -> (Value, Value, Value, Value) {
    let info = crate::params::mock_keyset_info(vec![1, 2, 4], 42);
    let v1 = info.keyset_id.to_string();
    let v2 = Id::v2_from_data(&info.active_keys, &info.unit, 42, Some(9_999_999_999)).to_string();
    (
        json!({"id": v1, "unit":"sat", "active":false, "input_fee_ppk":42}),
        json!({"id": v2, "unit":"sat", "active":true, "input_fee_ppk":42, "final_expiry":9_999_999_999_u64}),
        json!({"id":"02opaque-future-format", "unit":"sat", "active":true, "keys":false, "input_fee_ppk":"future"}),
        serde_json::to_value(info.active_keys).unwrap(),
    )
}

#[test]
fn prefix_classification_and_fixed_sets() {
    for id in ["02", "ffanything", "ABfuture"] {
        assert_eq!(supported_keyset_id(id).unwrap(), None);
    }
    for id in ["", "0", "xxfoo", "00", "01", "00nothex", "éx"] {
        assert!(supported_keyset_id(id).is_err(), "{id}");
    }
    let explicit = KeysetVersions::from([KeysetVersion::V1, KeysetVersion::V2]);
    assert_eq!(explicit, KeysetVersions::V1_AND_V2);
    assert_eq!(serde_json::to_string(&explicit).unwrap(), r#"["v1","v2"]"#);
    assert!(serde_json::from_str::<KeysetVersions>(r#"["v3"]"#).is_err());
    assert_eq!(
        serde_json::from_str::<KeysetVersions>(r#"["v2","v2"]"#).unwrap(),
        KeysetVersions::V2
    );
}

#[test]
fn mixed_orderings_preserve_supported_and_filter_selection() {
    let (mut v1, v2, future, _) = fixtures();
    v1["active"] = json!(true);
    for index in 0..=2 {
        let mut entries = vec![v1.clone(), v2.clone()];
        entries.insert(index, future.clone());
        let discovery =
            KeysetDiscovery::from_json(&json!({"keysets": entries}).to_string()).unwrap();
        assert_eq!(discovery.keysets, vec![v1.clone(), v2.clone()]);
        assert_eq!(discovery.skipped.len(), 1);
        assert!(discovery.unsupported_active_units.is_empty());
        for (allowed_versions, expected) in [
            (KeysetVersions::V1, &v1),
            (KeysetVersions::V2, &v2),
            (KeysetVersions::V1_AND_V2, &v1),
        ] {
            assert_eq!(
                discovery
                    .select_active("sat", KeysetSelectionPolicy { allowed_versions })
                    .unwrap()
                    .to_string(),
                expected["id"]
            );
        }
        assert!(discovery
            .select_active(
                "sat",
                KeysetSelectionPolicy {
                    allowed_versions: KeysetVersions::from([])
                }
            )
            .is_err());
    }
}

#[test]
fn diagnostics_and_malformed_supported_metadata() {
    let (v1, v2, future, _) = fixtures();
    let report =
        KeysetDiscovery::from_json(&json!({"keysets":[v1.clone(), future]}).to_string()).unwrap();
    assert_eq!(
        report.unsupported_active_units,
        vec![Some("sat".to_string())]
    );
    assert_eq!(report.keysets, vec![v1]);
    assert!(report
        .select_active(
            "sat",
            KeysetSelectionPolicy {
                allowed_versions: KeysetVersions::V1_AND_V2
            }
        )
        .is_err());
    assert!(KeysetDiscovery::from_json(r#"{"keysets":[]}"#)
        .unwrap()
        .skipped
        .is_empty());
    for bad in [
        json!({"id": null}),
        json!({"id":"00bad"}),
        json!({"id":"no"}),
    ] {
        assert!(
            KeysetDiscovery::from_json(&json!({"keysets":[bad, v2.clone()]}).to_string()).is_err()
        );
    }
    let mut bad_fee = v2.clone();
    bad_fee["input_fee_ppk"] = json!("bad");
    let mut bad_expiry = v2;
    bad_expiry["final_expiry"] = json!(-1);
    for entry in [bad_fee, bad_expiry] {
        assert!(KeysetDiscovery::from_json(&json!({"keysets":[entry]}).to_string()).is_err());
    }
}

#[test]
fn keys_response_matches_requested_id_and_metadata() {
    let (v1, v2, future, keys) = fixtures();
    let listing = json!({"keysets":[v1.clone(), v2.clone(), future.clone()]}).to_string();
    let mut matched = json!({"id":v2["id"], "unit":"sat", "keys":keys});
    let id = v2["id"].as_str().unwrap();
    let build = |entries| {
        crate::client_bridge::build_keyset_info_from_responses(
            &listing,
            &json!({"keysets":entries}).to_string(),
            id,
        )
    };
    assert!(build(vec![future, matched.clone()]).is_ok());
    assert!(build(vec![matched.clone(), matched.clone()]).is_err());
    assert!(build(vec![json!({"id":v1["id"], "unit":"sat", "keys":keys})]).is_err());
    matched["unit"] = json!("msat");
    assert!(build(vec![matched.clone()]).is_err());
    matched["unit"] = json!("sat");
    matched["final_expiry"] = json!(0);
    assert!(build(vec![matched.clone()]).is_err());
    matched.as_object_mut().unwrap().remove("final_expiry");
    matched["keys"] = json!({});
    assert!(build(vec![matched]).is_err());
}
