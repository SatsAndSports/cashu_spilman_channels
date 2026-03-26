//! Process orchestration for mint and server processes.
//!
//! This module handles spawning, monitoring, and cleanup of:
//! - standalone test mint (`cdk-spilman-test-mintd`)
//! - ASCII art servers (TS, Rust, Python, Go)
//!
//! # Process Group Management
//!
//! All spawned processes are placed in their own process groups using `setsid`.
//! This ensures that when we kill a process, we kill the entire tree (including
//! any child processes spawned by shell scripts or `go run`).

use std::env;
use std::fs;

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use command_group::{CommandGroup, GroupChild, Signal, UnixChildExt};
use serde_json::Value;
use std::process::Command;
use tokio::time::sleep;

/// Find an available port by binding to port 0
pub fn find_available_port() -> Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0").context("Failed to bind to port 0")?;
    let port = listener.local_addr()?.port();
    drop(listener);
    Ok(port)
}

/// Get the project root directory.
///
/// This crate is at `crates/cdk-spilman-server-integration-tests`,
/// so the workspace root is two levels up from `CARGO_MANIFEST_DIR`.
pub fn project_root() -> PathBuf {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(manifest_dir)
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."))
}

fn test_mint_manifest() -> PathBuf {
    project_root().join("Cargo.toml")
}

fn test_mint_binary() -> PathBuf {
    project_root().join("target/debug/cdk-spilman-test-mintd")
}

fn mint_unit_order(unit: &str) -> (u8, &str) {
    match unit {
        "sat" => (0, unit),
        "msat" => (1, unit),
        "usd" => (2, unit),
        _ => (99, unit),
    }
}

async fn mint_ready_line(client: &reqwest::Client, source: &str, mint_url: &str) -> Result<String> {
    let info_url = format!("{}/v1/info", mint_url);
    let keysets_url = format!("{}/v1/keysets", mint_url);

    let info = client
        .get(&info_url)
        .send()
        .await?
        .error_for_status()?
        .json::<Value>()
        .await?;
    let keysets = client
        .get(&keysets_url)
        .send()
        .await?
        .error_for_status()?
        .json::<Value>()
        .await?;

    let name = info
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let version = info
        .get("version")
        .and_then(Value::as_str)
        .unwrap_or("unknown");

    let mut units: Vec<String> = keysets
        .get("keysets")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|entry| entry.get("unit").and_then(Value::as_str))
        .map(|unit| unit.to_string())
        .collect();
    units.sort_by(|left, right| mint_unit_order(left).cmp(&mint_unit_order(right)));
    units.dedup();

    let name_json = serde_json::to_string(name)?;
    let version_json = serde_json::to_string(version)?;

    Ok(format!(
        "MINT_READY source={} url={} name={} version={} units=[{}]",
        source,
        mint_url,
        name_json,
        version_json,
        units.join(",")
    ))
}

async fn log_mint_ready(source: &str, mint_url: &str) -> Result<()> {
    let client = reqwest::Client::new();
    println!("{}", mint_ready_line(&client, source, mint_url).await?);
    Ok(())
}

/// Server type enum
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerType {
    TypeScript,
    Rust,
    Python,
    Go,
}

impl ServerType {
    /// Parse from environment variable
    pub fn from_env() -> Result<Self> {
        let server_type = env::var("SERVER_TYPE").unwrap_or_else(|_| "ts".to_string());
        match server_type.to_lowercase().as_str() {
            "ts" | "typescript" => Ok(Self::TypeScript),
            "rust" | "rs" => Ok(Self::Rust),
            "python" | "py" => Ok(Self::Python),
            "go" | "golang" => Ok(Self::Go),
            _ => Err(anyhow!(
                "Unknown SERVER_TYPE '{}'. Use: ts, rust, python, or go",
                server_type
            )),
        }
    }

    /// Get display name
    pub fn name(&self) -> &'static str {
        match self {
            Self::TypeScript => "TypeScript",
            Self::Rust => "Rust",
            Self::Python => "Python",
            Self::Go => "Go",
        }
    }
}

/// A running mint process (in its own process group)
pub struct MintProcess {
    child: GroupChild,
    pub port: u16,
    pub url: String,
}

impl MintProcess {
    /// Spawn the standalone test mint.
    pub async fn spawn() -> Result<Self> {
        let port = find_available_port()?;

        // Clear all inherited CARGO_* env vars so build-script
        // fingerprints match regardless of whether we are invoked from
        // `cargo test` (which sets CARGO_MANIFEST_DIR,
        // CARGO_PKG_VERSION_MAJOR, etc.) or from a plain shell.
        // Without this, `ring`'s build script sees changed CARGO_*
        // values on every invocation and recompiles ~15 crates
        // unnecessarily.  The child `cargo build` process sets the
        // correct CARGO_* vars for the crate it is building.
        let mut build_cmd = Command::new("cargo");
        build_cmd
            .arg("build")
            .arg("-p")
            .arg("cdk-spilman-test-mint")
            .arg("--manifest-path")
            .arg(test_mint_manifest());

        for (key, _) in env::vars() {
            // Preserve CARGO_NET_OFFLINE and CARGO_HOME for containerized builds
            if key.starts_with("CARGO_") && key != "CARGO_NET_OFFLINE" && key != "CARGO_HOME" {
                build_cmd.env_remove(&key);
            }
        }

        let build_status = build_cmd
            .status()
            .context("Failed to build standalone test mint")?;

        if !build_status.success() {
            return Err(anyhow!("Failed to build standalone test mint"));
        }

        let mintd_bin = test_mint_binary();

        if !mintd_bin.exists() {
            return Err(anyhow!(
                "standalone test mint binary not found at {} after build",
                mintd_bin.display()
            ));
        }

        let mint_url = format!("http://127.0.0.1:{}", port);

        tracing::info!(
            "Starting mint on port {} using {}",
            port,
            mintd_bin.display()
        );

        let mut cmd = Command::new(&mintd_bin);
        cmd.arg("--listen-port")
            .arg(port.to_string())
            .arg("--base-url")
            .arg(&mint_url)
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());

        let child = cmd.group_spawn().context("Failed to spawn mint process")?;

        let mint = Self {
            child,
            port,
            url: mint_url,
        };

        mint.wait_for_ready().await?;

        Ok(mint)
    }

    /// Wait for the mint to be ready by polling /v1/info
    async fn wait_for_ready(&self) -> Result<()> {
        let client = reqwest::Client::new();
        let info_url = format!("{}/v1/info", self.url);

        for i in 0..60 {
            match client.get(&info_url).send().await {
                Ok(resp) if resp.status().is_success() => {
                    tracing::info!("Mint ready after {} attempts", i + 1);
                    log_mint_ready("spawned", &self.url).await?;
                    return Ok(());
                }
                _ => {
                    sleep(Duration::from_millis(500)).await;
                }
            }
        }

        Err(anyhow!("Mint failed to become ready within 30 seconds"))
    }
}

impl Drop for MintProcess {
    fn drop(&mut self) {
        tracing::info!("Stopping mint process group on port {}", self.port);

        // Send SIGTERM to the entire process group for graceful shutdown
        if let Err(e) = self.child.signal(Signal::SIGTERM) {
            tracing::warn!("Failed to send SIGTERM to mint process group: {}", e);
        }

        // Give processes a moment to shut down gracefully
        std::thread::sleep(Duration::from_millis(100));

        // Force kill the entire process group
        if let Err(e) = self.child.signal(Signal::SIGKILL) {
            tracing::warn!("Failed to send SIGKILL to mint process group: {}", e);
        }

        // Reap the zombie
        let _ = self.child.wait();
    }
}

/// A running server process (in its own process group)
pub struct ServerProcess {
    child: GroupChild,
    pub port: u16,
    pub base_url: String,
    pub server_type: ServerType,
}

impl ServerProcess {
    /// Spawn a server of the specified type.
    /// The process is spawned in its own process group so we can kill all children.
    pub async fn spawn(server_type: ServerType, mint_url: &str) -> Result<Self> {
        let port = find_available_port()?;
        let root = project_root();

        tracing::info!(
            "Starting {} server on port {} with mint {}",
            server_type.name(),
            port,
            mint_url
        );

        let child = match server_type {
            ServerType::TypeScript => Self::spawn_ts_server(&root, port, mint_url)?,
            ServerType::Rust => Self::spawn_rust_server(&root, port, mint_url)?,
            ServerType::Python => Self::spawn_python_server(&root, port, mint_url)?,
            ServerType::Go => Self::spawn_go_server(&root, port, mint_url)?,
        };

        let base_url = format!("http://localhost:{}", port);
        let server = Self {
            child,
            port,
            base_url,
            server_type,
        };

        // Wait for server to be ready
        server.wait_for_ready().await?;

        Ok(server)
    }

    fn spawn_ts_server(root: &Path, port: u16, mint_url: &str) -> Result<GroupChild> {
        let server_dir = root.join("examples/ts-ascii-art");
        let kit_dir = root.join("integration-kits/ts");

        // Ensure kit dependencies are installed
        let kit_node_modules = kit_dir.join("node_modules");
        if !kit_node_modules.exists() {
            let status = Command::new("npm")
                .args(["install", "--no-package-lock", "--no-fund", "--no-audit"])
                .current_dir(&kit_dir)
                .status()
                .context("Failed to run npm install for TypeScript kit")?;
            if !status.success() {
                return Err(anyhow!("npm install failed for TypeScript kit"));
            }
        }

        let status = Command::new("npm")
            .arg("link")
            .current_dir(&kit_dir)
            .status()
            .context("Failed to run npm link for TypeScript kit")?;
        if !status.success() {
            return Err(anyhow!("npm link failed for TypeScript kit"));
        }

        let node_modules = server_dir.join("node_modules");
        let kit_module = node_modules.join("cdk-spilman-kit");
        let mut needs_install = !node_modules.exists();

        if !needs_install {
            if !kit_module.exists() {
                needs_install = true;
            } else {
                let is_symlink = fs::symlink_metadata(&kit_module)
                    .map(|m| m.file_type().is_symlink())
                    .unwrap_or(false);
                if !is_symlink {
                    let _ = fs::remove_dir_all(&kit_module);
                    needs_install = true;
                }
            }
        }

        if needs_install {
            let status = Command::new("npm")
                .args(["install", "--no-package-lock", "--no-fund", "--no-audit"])
                .current_dir(&server_dir)
                .status()
                .context("Failed to run npm install for TypeScript demo")?;
            if !status.success() {
                return Err(anyhow!("npm install failed for TypeScript demo"));
            }
        }

        let status = Command::new("npm")
            .args(["link", "cdk-spilman-kit"])
            .current_dir(&server_dir)
            .status()
            .context("Failed to run npm link cdk-spilman-kit for TypeScript demo")?;
        if !status.success() {
            return Err(anyhow!(
                "npm link cdk-spilman-kit failed for TypeScript demo"
            ));
        }

        Command::new("npx")
            .args(["tsx", "src/index.ts", "server"])
            .env("PORT", port.to_string())
            .env("MINT_URL", mint_url)
            .current_dir(&server_dir)
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .group_spawn()
            .context("Failed to spawn TypeScript server")
    }

    fn spawn_rust_server(root: &Path, port: u16, mint_url: &str) -> Result<GroupChild> {
        let binary = root.join("target/debug/rust-ascii-art");

        Command::new(&binary)
            .env("PORT", port.to_string())
            .env("MINT_URL", mint_url)
            .current_dir(root)
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .group_spawn()
            .context("Failed to spawn Rust server")
    }

    fn spawn_python_server(root: &Path, port: u16, mint_url: &str) -> Result<GroupChild> {
        let server_dir = root.join("examples/python-ascii-art");
        let venv_python = root.join("crates/cdk-spilman-python/.venv/bin/python");

        // Use standalone venv python if available, otherwise system python
        let python = if venv_python.exists() {
            venv_python
        } else {
            PathBuf::from("python3")
        };

        Command::new(&python)
            .arg("server.py")
            .env("PORT", port.to_string())
            .env("MINT_URL", mint_url)
            .current_dir(&server_dir)
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .group_spawn()
            .context("Failed to spawn Python server")
    }

    fn spawn_go_server(root: &Path, port: u16, mint_url: &str) -> Result<GroupChild> {
        let server_dir = root.join("examples/go-ascii-art");
        let ld_library_path = root.join("target/debug");

        Command::new("go")
            .args(["run", "-tags", "spilman_dev", ".", "server"])
            .env("PORT", port.to_string())
            .env("MINT_URL", mint_url)
            .env("LD_LIBRARY_PATH", &ld_library_path)
            .current_dir(&server_dir)
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .group_spawn()
            .context("Failed to spawn Go server")
    }

    /// Wait for the server to be ready by polling /channel/params
    async fn wait_for_ready(&self) -> Result<()> {
        let client = reqwest::Client::new();
        let params_url = format!("{}/channel/params", self.base_url);

        for i in 0..60 {
            match client.get(&params_url).send().await {
                Ok(resp) if resp.status().is_success() => {
                    tracing::info!(
                        "{} server ready after {} attempts",
                        self.server_type.name(),
                        i + 1
                    );
                    return Ok(());
                }
                _ => {
                    sleep(Duration::from_millis(500)).await;
                }
            }
        }

        Err(anyhow!(
            "{} server failed to become ready within 30 seconds",
            self.server_type.name()
        ))
    }
}

impl Drop for ServerProcess {
    fn drop(&mut self) {
        tracing::info!(
            "Stopping {} server process group on port {}",
            self.server_type.name(),
            self.port
        );

        // Send SIGTERM to the entire process group for graceful shutdown
        if let Err(e) = self.child.signal(Signal::SIGTERM) {
            tracing::warn!("Failed to send SIGTERM to server process group: {}", e);
        }

        // Give processes a moment to shut down gracefully
        std::thread::sleep(Duration::from_millis(100));

        // Force kill the entire process group
        if let Err(e) = self.child.signal(Signal::SIGKILL) {
            tracing::warn!("Failed to send SIGKILL to server process group: {}", e);
        }

        // Reap the zombie
        let _ = self.child.wait();
    }
}

/// Test environment with mint and server.
///
/// Supports two modes:
/// - **Spawned**: Spawns mint and server as child processes (default)
/// - **External**: Connects to externally-running services via URLs (for containerized tests)
///
/// Set `MINT_URL` and `SERVER_URL` environment variables to use external mode.
pub struct TestEnvironment {
    // Process handles (None when using external services)
    // These are held to keep the processes alive; dropped when TestEnvironment drops
    #[allow(dead_code)]
    mint_process: Option<MintProcess>,
    #[allow(dead_code)]
    server_process: Option<ServerProcess>,
    // URLs (always set)
    mint_url: String,
    server_url: String,
    server_type: ServerType,
}

/// Wrapper to provide backwards-compatible access patterns.
/// This allows context.rs to access `env.mint.url` and `env.server.base_url`.
pub struct MintRef<'a> {
    pub url: &'a str,
}

pub struct ServerRef<'a> {
    pub base_url: &'a str,
    pub server_type: ServerType,
}

impl TestEnvironment {
    /// Create a new test environment with the specified server type.
    ///
    /// If `MINT_URL` and `SERVER_URL` environment variables are set, connects to
    /// external services. Otherwise, spawns local mint and server processes.
    pub async fn new(server_type: ServerType) -> Result<Self> {
        // Check if we should use external mint/server
        if let (Ok(mint_url), Ok(server_url)) = (env::var("MINT_URL"), env::var("SERVER_URL")) {
            tracing::info!(
                "Using external services: mint at {}, server at {}",
                mint_url,
                server_url
            );

            // Wait for external services to be ready
            Self::wait_for_external_mint(&mint_url).await?;
            log_mint_ready("external", &mint_url).await?;
            Self::wait_for_external_server(&server_url).await?;

            return Ok(Self {
                mint_process: None,
                server_process: None,
                mint_url,
                server_url,
                server_type,
            });
        }

        // Spawn our own mint and server
        let mint = MintProcess::spawn().await?;
        let server = ServerProcess::spawn(server_type, &mint.url).await?;

        let mint_url = mint.url.clone();
        let server_url = server.base_url.clone();

        Ok(Self {
            mint_process: Some(mint),
            server_process: Some(server),
            mint_url,
            server_url,
            server_type,
        })
    }

    /// Wait for external mint to be ready
    async fn wait_for_external_mint(mint_url: &str) -> Result<()> {
        let client = reqwest::Client::new();
        let info_url = format!("{}/v1/info", mint_url);

        for i in 0..60 {
            match client.get(&info_url).send().await {
                Ok(resp) if resp.status().is_success() => {
                    tracing::info!("External mint ready after {} attempts", i + 1);
                    return Ok(());
                }
                _ => {
                    sleep(Duration::from_millis(500)).await;
                }
            }
        }

        Err(anyhow!(
            "External mint at {} failed to become ready within 30 seconds",
            mint_url
        ))
    }

    /// Wait for external server to be ready
    async fn wait_for_external_server(server_url: &str) -> Result<()> {
        let client = reqwest::Client::new();
        let params_url = format!("{}/channel/params", server_url);

        for i in 0..60 {
            match client.get(&params_url).send().await {
                Ok(resp) if resp.status().is_success() => {
                    tracing::info!("External server ready after {} attempts", i + 1);
                    return Ok(());
                }
                _ => {
                    sleep(Duration::from_millis(500)).await;
                }
            }
        }

        Err(anyhow!(
            "External server at {} failed to become ready within 30 seconds",
            server_url
        ))
    }

    /// Get access to mint URL (backwards-compatible accessor)
    pub fn mint(&self) -> MintRef<'_> {
        MintRef {
            url: &self.mint_url,
        }
    }

    /// Get access to server (backwards-compatible accessor)
    pub fn server(&self) -> ServerRef<'_> {
        ServerRef {
            base_url: &self.server_url,
            server_type: self.server_type,
        }
    }

    /// Get the mint URL
    pub fn mint_url(&self) -> &str {
        &self.mint_url
    }

    /// Get the server base URL
    pub fn server_url(&self) -> &str {
        &self.server_url
    }
}
