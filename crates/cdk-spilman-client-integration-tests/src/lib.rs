//! Integration tests for SpilmanClientBridge against SpilmanBridge
//!
//! This crate tests the client-side bridge (`SpilmanClientBridge`) against
//! the server-side bridge (`SpilmanBridge`), using an in-memory mint.
//!
//! The tests verify that:
//! - Payments created by the client are accepted by the server
//! - Channel state is correctly tracked on both sides
//! - The `Payment` struct works as the shared wire format

pub use cdk_spilman_test_mint::{
    create_test_mint, mint_test_proofs, InMemoryMintNetworking, TestMintHelper, TestServerHost,
};
