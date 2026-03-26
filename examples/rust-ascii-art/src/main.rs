//! ASCII Art Server - Pay per character using Spilman payment channels.
//!
//! Demonstrates Spilman payment channels in Rust using Axum with a
//! [`ConfigurableHost`] that reads pricing from `config.yaml`.
//!
//! Endpoints:
//!   GET  /channel/params              - Get server pubkey and pricing info
//!   POST /channel/register            - Pre-register a channel (balance=0, no usage)
//!   POST /ascii                       - Generate ASCII art (requires X-Cashu-Channel header)
//!   GET  /channel/:id/status          - Get channel status and amount_due
//!   POST /channel/:id/close           - Close channel cooperatively (client-initiated)
//!   POST /channel/:id/unilateral-close - Close channel unilaterally (server-initiated)

mod routes;

use std::env;
use std::sync::Arc;

use tokio::net::TcpListener;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use cdk_spilman::configurable_host::ConfigurableHost;
use cdk_spilman::configurable_networking::ReqwestNetworking;
use cdk_spilman::SpilmanBridge;

use routes::{create_router, AppStateInner};

// ============================================================================
// Configuration
// ============================================================================

/// Default secret key for development (same pattern as TS/Python/Go servers)
const DEFAULT_SECRET_KEY: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// Default port
const DEFAULT_PORT: u16 = 5003;

/// Default config file path
const DEFAULT_CONFIG_PATH: &str = "config.yaml";

// ============================================================================
// Main Entry Point
// ============================================================================

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,cdk_ascii_art=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    println!("{}", "=".repeat(60));
    println!("ASCII Art Server - Spilman Payment Channel Demo (Rust)");
    println!("{}", "=".repeat(60));
    println!();

    // Read config from environment
    let port: u16 = env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(DEFAULT_PORT);

    let secret_key_hex =
        env::var("SERVER_SECRET_KEY").unwrap_or_else(|_| DEFAULT_SECRET_KEY.to_string());

    let config_path = env::var("CONFIG_PATH").unwrap_or_else(|_| DEFAULT_CONFIG_PATH.to_string());

    // Load YAML config — search multiple locations.
    let search_paths = [
        config_path.clone(),
        format!("examples/rust-ascii-art/{}", config_path),
    ];
    let yaml_content = search_paths
        .iter()
        .find_map(|p| std::fs::read_to_string(p).ok())
        .unwrap_or_else(|| {
            eprintln!("Failed to find config file. Searched: {:?}", search_paths);
            eprintln!(
                "Hint: set CONFIG_PATH env var or run from the examples/rust-ascii-art directory"
            );
            std::process::exit(1);
        });

    // Allow MINT_URL env var to override config file.
    // We do a simple line-level replacement so we don't need serde_yml in
    // the server crate itself.  The override mint gets all units from the
    // pricing section.
    let yaml_content = if let Ok(mint_url) = env::var("MINT_URL") {
        // Collect unit names from "pricing:" section (lines like "  sat:")
        let mut units = Vec::new();
        let mut in_pricing = false;
        for line in yaml_content.lines() {
            if line.trim_start().starts_with("pricing:") {
                in_pricing = true;
            } else if in_pricing {
                // A top-level key (no leading whitespace) ends the pricing block
                if !line.is_empty() && !line.starts_with(' ') && !line.starts_with('\t') {
                    break;
                }
                // Unit entries are indented exactly two spaces: "  sat:"
                if line.starts_with("  ") && !line.starts_with("    ") {
                    if let Some(unit) = line.trim().strip_suffix(':') {
                        units.push(unit.to_string());
                    }
                }
            }
        }
        let units_str = units.join(", ");

        // Replace the mints block with the override mint trusting all units
        let mut out = Vec::new();
        let mut skipping = false;
        for line in yaml_content.lines() {
            if line.trim_start().starts_with("mints:") {
                out.push(format!("mints:\n  \"{}\": [{}]", mint_url, units_str));
                skipping = true;
            } else if skipping {
                // Skip continuation lines (indented entries under mints:)
                if line.starts_with("  ") {
                    continue;
                }
                skipping = false;
                out.push(line.to_string());
            } else {
                out.push(line.to_string());
            }
        }
        out.join("\n")
    } else {
        yaml_content
    };

    // Create configurable host
    let host = Arc::new(
        ConfigurableHost::from_yaml(&yaml_content, &secret_key_hex)
            .expect("Failed to create ConfigurableHost"),
    );

    // Fetch keysets from each configured mint at startup
    if let Err(e) = host.initialize_keysets().await {
        eprintln!("WARNING: {e}");
        eprintln!("Payment validation may fail for new channels");
    }
    println!();

    let mint_urls: Vec<&String> = host.mints().keys().collect();

    // Create bridge
    let bridge = Arc::new(SpilmanBridge::new((*host).clone()));

    // Create networking (for close operations)
    let networking = Arc::new(ReqwestNetworking::new(host.clone()));

    // Load figlet font
    let figlet_font = figlet_rs::FIGfont::standard().expect("Failed to load figlet font");

    // Create app state
    let state = Arc::new(AppStateInner {
        bridge,
        host: host.clone(),
        networking,
        figlet_font,
    });

    // Create router
    let app = create_router(state);

    // Start server
    let addr = format!("0.0.0.0:{}", port);
    let listener = TcpListener::bind(&addr)
        .await
        .expect("Failed to bind to address");

    println!("Server pubkey: {}", host.server_pubkey().to_hex());
    let mint_display: Vec<&str> = mint_urls.iter().map(|s| s.as_str()).collect();
    println!("Mints:         {}", mint_display.join(", "));

    let active_units = host.get_active_units();
    let active_pricing = host.get_active_pricing();
    let pricing_str: String = active_pricing
        .iter()
        .filter(|(unit, _)| active_units.contains(*unit))
        .map(|(u, p)| {
            let vars: Vec<String> = p
                .variables
                .iter()
                .map(|(var, price)| format!("{price}/{var}"))
                .collect();
            format!("{u}={}", vars.join("+"))
        })
        .collect::<Vec<_>>()
        .join(", ");
    println!(
        "Pricing:       {}",
        if pricing_str.is_empty() {
            "(no active units)".to_string()
        } else {
            pricing_str
        }
    );
    println!("Listening on:  http://{}", addr);
    println!();
    println!("Endpoints:");
    println!("  GET  http://localhost:{}/channel/params", port);
    println!("  POST http://localhost:{}/channel/register", port);
    println!("  POST http://localhost:{}/ascii", port);
    println!("  POST http://localhost:{}/ascii/preflight", port);
    println!("  GET  http://localhost:{}/channel/:id/status", port);
    println!("  POST http://localhost:{}/channel/:id/close", port);
    println!(
        "  POST http://localhost:{}/channel/:id/unilateral-close",
        port
    );
    println!();
    println!("{}", "=".repeat(60));
    println!();

    tracing::info!("Rust ASCII Art server listening on {}", addr);

    axum::serve(listener, app)
        .await
        .expect("Server failed to start");
}
