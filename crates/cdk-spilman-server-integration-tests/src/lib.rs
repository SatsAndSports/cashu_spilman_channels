//! Integration tests for Spilman payment channel servers.
//!
//! This crate provides a test harness for testing Spilman payment channel
//! server implementations (TypeScript, Rust, Python, Go) using a Rust test client.
//!
//! # Architecture
//!
//! The test suite is organized as follows:
//!
//! - `orchestration`: Spawning and managing mint and server processes
//! - `helpers`: Channel funding, payment creation, HTTP requests
//! - `context`: Test context/fixtures providing server connection info
//!
//! Tests run against different server implementations by setting the `SERVER_TYPE`
//! environment variable to one of: `ts`, `rust`, `python`, `go`.

pub mod context;
pub mod helpers;
pub mod orchestration;
