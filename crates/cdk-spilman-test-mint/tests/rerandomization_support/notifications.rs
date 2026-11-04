use anyhow::{anyhow, bail, ensure, Result};
use cashu::nuts::PublicKey;
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_tungstenite::{connect_async, tungstenite::Message, MaybeTlsStream, WebSocketStream};

pub struct Subscription {
    socket: WebSocketStream<MaybeTlsStream<TcpStream>>,
    buffered: VecDeque<Value>,
    y: PublicKey,
}

impl Subscription {
    pub async fn open(url: &str, y: PublicKey) -> Result<Self> {
        let (mut socket, _) =
            connect_async(format!("{}/v1/ws", url.replacen("http://", "ws://", 1))).await?;
        socket
            .send(Message::Text(
                json!({"jsonrpc":"2.0", "id":1, "method":"subscribe",
            "params":{"kind":"proof_state","filters":[y.to_hex()],"subId":"proof"}})
                .to_string()
                .into(),
            ))
            .await?;
        let mut subscription = Self {
            socket,
            buffered: VecDeque::new(),
            y,
        };
        for _ in 0..16 {
            let frame = subscription.frame().await?;
            ensure!(frame.get("error").is_none(), "subscription rejected");
            if frame["id"] == 1 {
                ensure!(frame["result"]["status"] == "OK", "invalid ack");
                return Ok(subscription);
            }
            subscription.buffered.push_back(frame);
        }
        bail!("subscription ack missing")
    }

    async fn frame(&mut self) -> Result<Value> {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                match self
                    .socket
                    .next()
                    .await
                    .ok_or_else(|| anyhow!("socket closed"))??
                {
                    Message::Text(text) => return Ok(serde_json::from_str(text.as_ref())?),
                    Message::Ping(_) | Message::Pong(_) => continue,
                    _ => bail!("unexpected WebSocket frame"),
                }
            }
        })
        .await?
    }

    pub async fn spent(&mut self, r: Option<&str>) -> Result<()> {
        for _ in 0..32 {
            let frame = match self.buffered.pop_front() {
                Some(frame) => frame,
                None => self.frame().await?,
            };
            ensure!(
                frame["method"] == "subscribe" && frame["params"]["subId"] == "proof",
                "wrong notification"
            );
            let state = &frame["params"]["payload"];
            ensure!(state["Y"] == self.y.to_hex(), "wrong proof notification");
            match state["state"].as_str() {
                Some("PENDING" | "UNSPENT") => ensure!(
                    state.get("rerandomization_r").is_none(),
                    "R leaked before commit"
                ),
                Some("SPENT") => {
                    ensure!(
                        state["rerandomization_r"].as_str() == r,
                        "wrong committed R"
                    );
                    if r.is_none() {
                        ensure!(
                            state.get("rerandomization_r").is_none(),
                            "ordinary notification has R"
                        );
                    }
                    return Ok(());
                }
                _ => bail!("invalid proof state"),
            }
        }
        bail!("no spent notification")
    }
}
