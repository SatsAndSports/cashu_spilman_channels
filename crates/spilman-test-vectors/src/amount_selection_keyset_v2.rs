//! V2-keyset test vectors for deterministic output amount selection.

use crate::channel_id::spilman_test_vector_channel_id_keysetv2;

/// Canonical name of the 64-sat maximum amount-selection fixture.
pub const SPILMAN_TEST_VECTOR_AMOUNT_SELECTION_KEYSETV2_NAME: &str =
    "spilman-test-vector-amount-selection-keysetv2";
/// Canonical name of the 32-sat maximum amount-selection fixture.
pub const SPILMAN_TEST_VECTOR_AMOUNT_SELECTION_KEYSETV2_MAX32_NAME: &str =
    "spilman-test-vector-amount-selection-keysetv2-max32";

/// Fixed input and expected output for deterministic amount selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AmountSelectionTestVector {
    /// Nominal target amount.
    pub target: u64,
    /// Largest permitted denomination.
    pub maximum_amount: u64,
    /// Amounts selected in largest-first order.
    pub amounts: &'static [u64],
}

/// Return the fixed 64-sat-maximum amount-selection vector.
pub fn spilman_test_vector_amount_selection_keysetv2() -> AmountSelectionTestVector {
    AmountSelectionTestVector {
        target: 100,
        maximum_amount: 64,
        amounts: &[64, 32, 4],
    }
}

/// Return the fixed 32-sat-maximum amount-selection vector.
pub fn spilman_test_vector_amount_selection_keysetv2_max32() -> AmountSelectionTestVector {
    AmountSelectionTestVector {
        target: 100,
        maximum_amount: 32,
        amounts: &[32, 32, 32, 4],
    }
}

/// Independently select amounts with the NUT-XX largest-first greedy algorithm.
///
/// # Panics
///
/// Panics if the fixed vector target is not representable by its keyset.
pub fn derive_amount_selection_reference(vector: AmountSelectionTestVector) -> Vec<u64> {
    let keyset = spilman_test_vector_channel_id_keysetv2();
    let mut denominations: Vec<u64> = keyset
        .public_keys
        .iter()
        .map(|(amount, _)| *amount)
        .filter(|amount| vector.maximum_amount == 0 || *amount <= vector.maximum_amount)
        .collect();
    denominations.sort_unstable_by(|left, right| right.cmp(left));

    let mut remaining = vector.target;
    let mut selected = Vec::new();
    for amount in denominations {
        while remaining >= amount {
            remaining -= amount;
            selected.push(amount);
        }
    }
    assert_eq!(remaining, 0, "test-vector target must be representable");
    selected
}

#[cfg(test)]
mod tests {
    use super::{
        derive_amount_selection_reference,
        spilman_test_vector_amount_selection_keysetv2 as get_test_vector_details,
        spilman_test_vector_amount_selection_keysetv2_max32 as get_max32_test_vector_details,
        SPILMAN_TEST_VECTOR_AMOUNT_SELECTION_KEYSETV2_MAX32_NAME,
        SPILMAN_TEST_VECTOR_AMOUNT_SELECTION_KEYSETV2_NAME,
    };

    #[test]
    fn spilman_test_vector_amount_selection_keysetv2() {
        let vector = get_test_vector_details();
        assert_eq!(
            derive_amount_selection_reference(vector),
            vector.amounts,
            "{SPILMAN_TEST_VECTOR_AMOUNT_SELECTION_KEYSETV2_NAME}: independent amount selection"
        );
    }

    #[test]
    fn spilman_test_vector_amount_selection_keysetv2_max32() {
        let vector = get_max32_test_vector_details();
        assert_eq!(
            derive_amount_selection_reference(vector),
            vector.amounts,
            "{SPILMAN_TEST_VECTOR_AMOUNT_SELECTION_KEYSETV2_MAX32_NAME}: independent amount selection"
        );
    }
}
