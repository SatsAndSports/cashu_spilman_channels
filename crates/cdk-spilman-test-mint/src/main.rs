//! Binary entry point for the standalone test mint daemon.

use std::env;

use anyhow::{anyhow, Result};
use cdk_spilman_test_mint::{serve_mint, TestMintConfig};

fn print_usage(binary: &str) {
    eprintln!("Usage: {binary} [--listen-host HOST] [--listen-port PORT] [--base-url URL]");
}

fn parse_args() -> Result<TestMintConfig> {
    let mut config = TestMintConfig::default();
    let mut base_url_override: Option<String> = None;
    let binary = env::args()
        .next()
        .unwrap_or_else(|| "cdk-spilman-test-mintd".to_string());
    let mut args = env::args().skip(1);

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--listen-host" | "--host" => {
                config.listen_host = args
                    .next()
                    .ok_or_else(|| anyhow!("Missing value for {arg}"))?;
            }
            "--listen-port" | "--port" => {
                let port = args
                    .next()
                    .ok_or_else(|| anyhow!("Missing value for {arg}"))?;
                config.listen_port = port.parse()?;
            }
            "--base-url" => {
                base_url_override = Some(
                    args.next()
                        .ok_or_else(|| anyhow!("Missing value for --base-url"))?,
                );
            }
            "-h" | "--help" => {
                print_usage(&binary);
                std::process::exit(0);
            }
            _ => {
                return Err(anyhow!("Unknown argument: {arg}"));
            }
        }
    }

    config.base_url =
        base_url_override.unwrap_or_else(|| format!("http://127.0.0.1:{}", config.listen_port));

    Ok(config)
}

fn setup_tracing() {
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    let _ = tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_ansi(false)
        .try_init();
}

#[tokio::main]
async fn main() -> Result<()> {
    setup_tracing();
    let config = parse_args()?;
    serve_mint(config).await
}
