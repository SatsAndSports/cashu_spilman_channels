//! Spilman Payment Channels
//!
//! This module implements Spilman-style unidirectional payment channels for Cashu.
//!
//! A Spilman channel allows Alice (sender) to make incremental payments to Charlie (receiver)
//! without requiring on-chain transactions for each payment. The channel uses:
//!
//! - 2-of-2 multisig funding with expiry-based refund for Alice
//! - Deterministic output derivation using a channel secret
//! - Off-chain balance updates signed by Alice
//! - Final commitment transaction signed by both parties

#[cfg(feature = "spilman-axum")]
pub mod axum;
mod balance_update;
mod bindings;
mod bridge;
mod client_bridge;
mod client_storage;
mod configurable_client_host;
#[cfg(feature = "configurable-host")]
pub mod configurable_host;
#[cfg(feature = "configurable-host-reqwest")]
pub mod configurable_networking;
#[cfg(feature = "client-sqlite")]
pub mod sqlite_client_storage;
#[cfg(feature = "configurable-host-reqwest")]
pub use configurable_networking::ReqwestClientNetworking;
mod deterministic;
mod established_channel;
mod keyset_retry;
mod keysets_and_amounts;
mod mint_errors;
mod params;
mod sender_and_receiver;

pub use balance_update::{
    get_signatures_from_swap_request, BalanceUpdateMessage, UnsignedBalanceUpdate,
};
pub use bindings::{
    attach_signature_to_balance_update, build_cashu_a_token, build_cashu_b_token,
    channel_parameters_get_channel_id, compute_channel_from_proofs,
    compute_channel_from_proofs_with_input_keysets, compute_channel_from_token,
    compute_channel_from_token_with_input_keysets, compute_channel_secret_from_hex,
    compute_funding_token_amount, create_funding_outputs, create_funding_swap,
    create_signed_balance_update, create_unsigned_balance_update, parse_keyset_info_from_json,
    sign_with_tweaked_key_util,
};
#[cfg(feature = "wallet")]
pub use bindings::{
    complete_funding_swap, complete_funding_swap_with_plain_change, complete_plain_change_restore,
    compute_channel_from_proofs_with_input_keysets_and_funding_amount, construct_proofs,
    create_funding_swap_with_plain_change, create_plain_blinded_messages,
    create_plain_change_restore_request, mint_proofs_from_mint,
};
pub use bridge::{
    unblind_and_verify_stage1_response, BridgeError, BridgeErrorResponse, ChannelFunding,
    ChannelPolicy, ChannelState, CloseData, CloseError, ClosePreparationError, CloseSuccess,
    ClosingData, CompletedClose, FundChannelResult, Payment, PaymentProof, PaymentSuccess,
    PaymentValidationResult, PreparedClose, PreparedCloseTransition, SpilmanAsyncKeysetRefresher,
    SpilmanAsyncMintClient, SpilmanBridge, SpilmanHost, SpilmanKeysetRefresher, SpilmanMintClient,
    UnblindResult, ValidatedNewChannel,
};
pub use client_bridge::{
    base64_decode, ClientChannelInfo, OpenChannelError, OpenChannelFailureStage, OpenChannelResult,
    SpilmanClientAsyncNetworking, SpilmanClientBridge, SpilmanClientHost, SpilmanClientNetworking,
};
#[cfg(feature = "wallet")]
pub use client_bridge::{
    CompletedOpenChannel, CompletedOpenRecovery, PreparedOpenChannel, PreparedOpenRecovery,
};
pub use client_storage::{
    ClientChannelFunding, ClientChannelOpeningFromSwap, ClientChannelState, ClientKeysetCacheEntry,
    ClientOpeningFailure, ClientPaymentState, ClientStorage, MemoryClientStorage,
};
pub use configurable_client_host::ConfigurableClientHost;
pub use deterministic::{
    CommitmentOutputs, DeterministicOutputsForOneContext, DeterministicSecretWithBlinding,
    MintConnection,
};
pub use established_channel::{
    EstablishedChannel, FundingSpendKind, PreparedSenderRefund, PreparedSenderRefundOutput,
};
pub use keyset_retry::{
    with_active_keyset_retry, with_active_keyset_retry_async, ActiveKeysetSelection,
    KeysetRetryError, KeysetRetrySuccess, SelectedOutputKeyset,
};
pub use keysets_and_amounts::{KeysetInfo, OrderedListOfAmounts};
pub use mint_errors::{
    extract_nut00_error_code, is_retryable_keyset_error_code, is_retryable_keyset_mint_error,
};
pub use params::{compute_channel_secret, ChannelId, ChannelParameters};
pub use sender_and_receiver::{
    verify_valid_channel, ChannelVerificationError, ChannelVerificationResult, SpilmanChannelSender,
};
#[cfg(feature = "client-sqlite")]
pub use sqlite_client_storage::SqliteClientStorage;
