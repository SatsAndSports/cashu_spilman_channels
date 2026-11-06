//! Pure ordinary/rerandomized swap primitives. These do not select channel mode,
//! submit, inspect funding, or mutate custody. Hosts authenticate retained requests
//! and recovery evidence before calling them, and durably store verified results.

use std::{collections::HashSet, fmt};

use cashu::nuts::nut03::{derive_rerandomization_tweak, tweak_swap_outputs, RerandomizationR};
use cashu::nuts::{
    BlindedMessage, Proof, RestoreRequest, RestoreResponse, SecretKey,
    SpendingConditionVerification, SwapRequest, SwapResponse,
};
use cashu::secret::Secret;

use crate::bindings::{complete_exact_signatures, match_restore_response, PreparedOutput};
use crate::KeysetInfo;

/// Confidential recovery material for one original, pre-rerandomization output.
/// Keep it with the immutable request; never log or publicly export its secrets.
#[derive(Clone)]
pub struct PreparedSwapOutput {
    /// Original amount, keyset ID and blinded point, in request order.
    pub blinded_message: BlindedMessage,
    /// Original output secret.
    pub secret: Secret,
    /// Original blinding factor, before any mint tweak.
    pub blinding_factor: SecretKey,
}

impl fmt::Debug for PreparedSwapOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreparedSwapOutput").finish_non_exhaustive()
    }
}

/// Canonical digest for an external BIP-340 signer; sign directly, do not rehash.
/// The request's flag selects ordinary or rerandomized authorization for *both*
/// signers. Digest construction does not validate the request's authorization.
pub fn swap_authorization_digest(request: &SwapRequest) -> [u8; 32] {
    request.sig_all_message_hash()
}

/// Derive exact NUT-09 query outputs. Ordinary requests require no `R`;
/// rerandomized requests require `R` from the successful response or validated
/// committed-input evidence. `R` alone is not evidence that a channel close won.
pub fn swap_restore_request(
    request: &SwapRequest,
    r: Option<RerandomizationR>,
) -> Result<RestoreRequest, String> {
    if request.outputs().is_empty() {
        return Err("empty prepared swap outputs".to_string());
    }
    let mut points = HashSet::new();
    if request
        .outputs()
        .iter()
        .any(|o| !points.insert(o.blinded_secret))
    {
        return Err("duplicate prepared swap outputs".to_string());
    }
    let outputs = match (request.is_rerandomized(), r) {
        (false, None) => request.outputs().clone(),
        (true, Some(r)) => tweak_swap_outputs(&r.0, request.outputs())
            .map_err(|_| "invalid derived swap points".to_string())?,
        _ => return Err("swap mode/randomness mismatch".to_string()),
    };
    Ok(RestoreRequest { outputs })
}

fn effective_outputs(
    request: &SwapRequest,
    prepared: &[PreparedSwapOutput],
    keys: &KeysetInfo,
    r: Option<RerandomizationR>,
) -> Result<Vec<PreparedOutput>, String> {
    let derived = swap_restore_request(request, r)?;
    if prepared.len() != request.outputs().len() {
        return Err("prepared swap output count mismatch".to_string());
    }
    let tweak = r
        .map(|r| {
            derive_rerandomization_tweak(&r.0).map_err(|_| "invalid mint randomness".to_string())
        })
        .transpose()?;
    let mut secrets = HashSet::new();
    prepared
        .iter()
        .zip(request.outputs())
        .zip(derived.outputs)
        .map(|((p, original), output)| {
            if &p.blinded_message != original
                || original.keyset_id != keys.keyset_id
                || keys.active_keys.amount_key(original.amount).is_none()
                || !secrets.insert(p.secret.to_string())
            {
                return Err("prepared swap output binding mismatch".to_string());
            }
            let (point, _) =
                cashu::dhke::blind_message(&p.secret.to_bytes(), Some(p.blinding_factor.clone()))
                    .map_err(|_| "invalid original swap blinding".to_string())?;
            if point != original.blinded_secret {
                return Err("prepared swap secrets do not match original points".to_string());
            }
            let blinding_factor = match tweak {
                None => p.blinding_factor.clone(),
                Some(tweak) => {
                    let original = bitcoin::secp256k1::SecretKey::from_slice(
                        p.blinding_factor.as_secret_bytes(),
                    )
                    .map_err(|_| "invalid original blinding scalar".to_string())?;
                    let effective = original
                        .add_tweak(&tweak)
                        .map_err(|_| "invalid effective blinding scalar".to_string())?;
                    SecretKey::from_slice(&effective.secret_bytes())
                        .map_err(|_| "invalid effective blinding scalar".to_string())?
                }
            };
            Ok(PreparedOutput {
                blinded_message: output,
                secret: p.secret.clone(),
                blinding_factor,
            })
        })
        .collect()
}

fn complete(
    signatures: Vec<cashu::nuts::BlindSignature>,
    outputs: Vec<PreparedOutput>,
    keys: &KeysetInfo,
) -> Result<Vec<Proof>, String> {
    let proofs = complete_exact_signatures(signatures, outputs, keys, None)
        .map_err(|_| "invalid complete swap signature set or DLEQ".to_string())?;
    for proof in &proofs {
        let key = keys
            .active_keys
            .amount_key(proof.amount)
            .ok_or_else(|| "missing proof denomination key".to_string())?;
        proof
            .verify_dleq(key)
            .map_err(|_| "invalid unblinded swap proof DLEQ".to_string())?;
    }
    Ok(proofs)
}

/// Verify every returned signature against the exact issued points, then unblind
/// using `r + tweak(R)` in rerandomized mode. Verify resulting proof DLEQs too.
/// Requires one caller-authenticated retained output keyset; no clock/activity
/// checks are applied to historical keys. Any mismatch fails the whole batch.
pub fn complete_swap_response(
    request: &SwapRequest,
    prepared: &[PreparedSwapOutput],
    response: SwapResponse,
    keys: &KeysetInfo,
) -> Result<Vec<Proof>, String> {
    let outputs = effective_outputs(request, prepared, keys, response.rerandomization_r)?;
    complete(response.signatures, outputs, keys)
}

/// Complete exact NUT-09 recovery using the retained request/secrets and committed
/// randomness. Reordered output/signature pairs are accepted and canonicalized.
/// Only two empty arrays mean absence; partial/duplicate/unknown outputs, missing
/// DLEQ and mode/randomness mismatch reject. No partial proofs are returned.
pub fn complete_swap_restore(
    request: &SwapRequest,
    prepared: &[PreparedSwapOutput],
    r: Option<RerandomizationR>,
    response: RestoreResponse,
    keys: &KeysetInfo,
) -> Result<Option<Vec<Proof>>, String> {
    let outputs = effective_outputs(request, prepared, keys, r)?;
    if response.outputs.is_empty() && response.signatures.is_empty() {
        return Ok(None);
    }
    let expected = outputs
        .iter()
        .map(|o| o.blinded_message.clone())
        .collect::<Vec<_>>();
    let signatures = match_restore_response(response, &expected, "swap")
        .map_err(|_| "invalid exact swap restore".to_string())?;
    complete(signatures, outputs, keys).map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_preparations_and_degenerate_effective_blinding_reject_without_panic() {
        let mint_key = SecretKey::generate();
        let keys =
            cashu::nuts::Keys::new([(1.into(), mint_key.public_key())].into_iter().collect());
        let id = cashu::nuts::Id::v1_from_keys(&keys);
        let info = KeysetInfo::new(id, cashu::nuts::CurrencyUnit::Sat, keys, 0, None);
        let randomness = RerandomizationR([42; 32]);
        let tweak = derive_rerandomization_tweak(&randomness.0).unwrap();
        let negative = bitcoin::secp256k1::SecretKey::from_slice(&tweak.to_be_bytes())
            .unwrap()
            .negate();
        let blinding_factor = SecretKey::from_slice(&negative.secret_bytes()).unwrap();
        let secret = Secret::new("test-private-material".to_string());
        let (point, _) =
            cashu::dhke::blind_message(&secret.to_bytes(), Some(blinding_factor.clone())).unwrap();
        let output = BlindedMessage::new(1.into(), id, point);
        let prepared = PreparedSwapOutput {
            blinded_message: output.clone(),
            secret,
            blinding_factor,
        };
        let request = SwapRequest::new(vec![], vec![output.clone()]).with_rerandomization();
        let empty = RestoreResponse {
            outputs: vec![],
            signatures: vec![],
        };
        let error = complete_swap_restore(
            &request,
            std::slice::from_ref(&prepared),
            Some(randomness),
            empty.clone(),
            &info,
        )
        .err()
        .unwrap();
        assert_eq!(error, "invalid effective blinding scalar");
        assert!(!error.contains("test-private-material"));
        assert!(complete_swap_restore(&request, &[], Some(randomness), empty, &info).is_err());
        assert!(swap_restore_request(
            &SwapRequest::new(vec![], vec![output.clone(), output]),
            None
        )
        .is_err());
        assert!(swap_restore_request(&SwapRequest::new(vec![], vec![]), None).is_err());
    }
}
