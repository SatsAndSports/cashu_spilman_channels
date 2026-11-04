use anyhow::{anyhow, Context, Result};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};

pub struct MintProcess {
    child: Child,
    pub url: String,
    database: PathBuf,
    drain: Option<tokio::task::JoinHandle<()>>,
}

impl MintProcess {
    pub async fn start(database: &Path) -> Result<Self> {
        let mut command = Command::new(env!("CARGO_BIN_EXE_cdk-spilman-test-mintd"));
        command
            .args([
                "--listen-host",
                "127.0.0.1",
                "--listen-port",
                "0",
                "--input-fee-ppk",
                "0",
                "--database",
            ])
            .arg(database)
            .env("RUST_LOG", "warn,cdk_spilman_test_mint=info")
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true);
        for unit in ["SAT", "MSAT", "USD"] {
            command.env_remove(format!("TEST_MINT_FEE_PPK_{unit}"));
            command.env_remove(format!("CDK_MINTD_INPUT_FEE_PPK_{unit}"));
        }
        let mut child = command.spawn()?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow!("no child stdout"))?;
        let mut lines = BufReader::new(stdout).lines();
        let url = tokio::time::timeout(Duration::from_secs(20), async {
            while let Some(line) = lines.next_line().await? {
                if let Some(address) = line.split("Standalone test mint listening on ").nth(1) {
                    return Ok::<_, anyhow::Error>(format!("http://{}", address.trim()));
                }
            }
            Err(anyhow!("mint exited before listening"))
        })
        .await
        .context("mint startup deadline")??;
        // Keep draining logs, otherwise a full stdout pipe can stall the mint.
        // The task owns only the pipe and exits when the awaited child stops.
        let drain =
            tokio::spawn(async move { while matches!(lines.next_line().await, Ok(Some(_))) {} });
        Ok(Self {
            child,
            url,
            database: database.to_path_buf(),
            drain: Some(drain),
        })
    }

    pub async fn stop(&mut self) -> Result<()> {
        self.child.kill().await?;
        self.child.wait().await?;
        if let Some(drain) = self.drain.take() {
            drain.await?;
        }
        Ok(())
    }

    pub async fn restart(&mut self) -> Result<()> {
        self.stop().await?;
        *self = Self::start(&self.database).await?;
        Ok(())
    }
}

impl Drop for MintProcess {
    fn drop(&mut self) {
        if let Some(drain) = self.drain.take() {
            drain.abort();
        }
    }
}
