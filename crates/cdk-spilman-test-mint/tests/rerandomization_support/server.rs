use anyhow::Result;
use std::sync::Arc;
use tokio::sync::oneshot;

/// The existing real CDK test mint, hosted over loopback with in-memory SQLite.
pub struct HttpMint {
    pub url: String,
    mint: Arc<cdk::Mint>,
    shutdown: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
}

impl HttpMint {
    pub async fn start() -> Result<Self> {
        // This existing builder explicitly configures zero fees without env overrides.
        let mint = Arc::new(cdk_spilman_test_mint::create_test_mint().await?);
        let router = cdk_spilman_test_mint::build_router(Arc::clone(&mint)).await?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let url = format!("http://{}", listener.local_addr()?);
        let (shutdown, receiver) = oneshot::channel();
        let task = tokio::spawn(async move {
            axum::serve(listener, router)
                .with_graceful_shutdown(async {
                    let _ = receiver.await;
                })
                .await
        });
        Ok(Self {
            url,
            mint,
            shutdown: Some(shutdown),
            task,
        })
    }

    pub async fn stop(mut self) -> Result<()> {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        (&mut self.task).await??;
        self.mint.stop().await?;
        Ok(())
    }
}

impl Drop for HttpMint {
    fn drop(&mut self) {
        self.task.abort();
    }
}
