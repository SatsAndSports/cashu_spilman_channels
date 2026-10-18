use super::*;
use crate::configurable_host::{ConfigurableHostConfig, StorageConfig};
use std::{collections::HashMap, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const LIMIT: usize = 4 * 1024 * 1024;

pub(crate) struct Reply {
    pub status: &'static str,
    pub body: String,
    pub declared: Option<usize>,
    pub stall: bool,
}

impl Reply {
    pub(crate) fn ok(body: String) -> Self {
        Self {
            status: "200 OK",
            body,
            declared: None,
            stall: false,
        }
    }
}

pub(crate) struct Server {
    pub url: String,
    task: tokio::task::JoinHandle<()>,
}

impl Server {
    pub(crate) async fn start(reply: impl Fn(&str, &str) -> Reply + Send + 'static) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            loop {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut headers = Vec::new();
                while !headers.ends_with(b"\r\n\r\n") {
                    assert!(headers.len() < 8192);
                    headers.push(socket.read_u8().await.unwrap());
                }
                let headers = String::from_utf8(headers).unwrap();
                let path = headers.split_whitespace().nth(1).unwrap();
                let size = headers
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().unwrap())
                    })
                    .unwrap_or(0);
                assert!(size <= LIMIT);
                let mut body = vec![0; size];
                socket.read_exact(&mut body).await.unwrap();
                let reply = reply(path, std::str::from_utf8(&body).unwrap());
                let length = reply
                    .declared
                    .map(|n| format!("Content-Length: {n}\r\n"))
                    .unwrap_or_default();
                let headers = format!("HTTP/1.1 {}\r\nContent-Type: application/json\r\n{length}Connection: close\r\n\r\n", reply.status);
                if socket.write_all(headers.as_bytes()).await.is_ok() {
                    let _ = socket.write_all(reply.body.as_bytes()).await;
                    if reply.stall {
                        // Keep the body incomplete until the actual client deadline closes it.
                        let _ = socket.read_u8().await;
                    }
                }
            }
        });
        Self { url, task }
    }

    pub(crate) fn host(&self) -> ConfigurableHost {
        ConfigurableHost::new(
            ConfigurableHostConfig {
                mints: HashMap::from([(self.url.clone(), vec!["sat".to_owned()])]),
                min_expiry_seconds: 0,
                pricing_scale: 1,
                storage: StorageConfig::Memory,
                pricing: HashMap::from([(
                    "sat".to_owned(),
                    crate::configurable_host::UnitPricingConfig {
                        min_capacity: 1,
                        max_amount_per_output: None,
                        variables: HashMap::new(),
                    },
                )]),
            },
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .unwrap()
    }

    pub(crate) fn networking(&self) -> ReqwestNetworking {
        ReqwestNetworking::new(Arc::new(self.host()))
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[tokio::test]
async fn swap_bounds_success_and_error_bodies_before_parsing() {
    for status in ["200 OK", "500 Internal Server Error"] {
        for declared in [false, true] {
            let server = Server::start(move |path, body| {
                assert_eq!((path, body), ("/v1/swap", "{}"));
                Reply {
                    status,
                    body: if declared {
                        String::new()
                    } else {
                        " ".repeat(LIMIT + 1)
                    },
                    declared: declared.then_some(LIMIT + 1),
                    stall: false,
                }
            })
            .await;
            let result = server.networking().call_mint_swap(&server.url, "{}").await;
            assert!(result.is_err(), "oversized success body must be refused");
            assert!(
                result.unwrap_err().contains("byte limit"),
                "{status}, declared={declared}"
            );
        }
    }
}

#[tokio::test]
async fn swap_preserves_small_success_and_nut00_errors() {
    for (status, body, success) in [
        ("200 OK", r#"{"signatures":[]}"#, true),
        (
            "400 Bad Request",
            r#"{"code":12001,"detail":"inactive keyset"}"#,
            false,
        ),
    ] {
        let server = Server::start(move |_, _| Reply {
            status,
            body: body.to_owned(),
            declared: Some(body.len()),
            stall: false,
        })
        .await;
        let result = server.networking().call_mint_swap(&server.url, "{}").await;
        assert_eq!(
            result,
            if success {
                Ok(body.to_owned())
            } else {
                Err(body.to_owned())
            }
        );
    }
}

#[tokio::test]
async fn swap_stalled_body_obeys_production_deadline() {
    let server = Server::start(|_, _| Reply {
        status: "200 OK",
        body: "{".to_owned(),
        declared: None,
        stall: true,
    })
    .await;
    let start = std::time::Instant::now();
    let result = tokio::time::timeout(
        Duration::from_secs(35),
        server.networking().call_mint_swap(&server.url, "{}"),
    )
    .await
    .expect("swap body exceeded the production deadline");
    assert!(result.is_err());
    assert!(start.elapsed() >= Duration::from_secs(29));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_bounds_swap_restore_and_keyset_responses() {
    for status in ["200 OK", "500 Internal Server Error"] {
        for declared in [false, true] {
            let server = Server::start(move |_, _| Reply {
                status,
                body: if declared {
                    String::new()
                } else {
                    " ".repeat(LIMIT + 1)
                },
                declared: declared.then_some(LIMIT + 1),
                stall: false,
            })
            .await;
            let networking = ReqwestClientNetworking::new(Duration::from_secs(5)).unwrap();
            for result in [
                networking.call_mint_swap(&server.url, "{}"),
                networking.call_mint_restore(&server.url, "{}"),
                networking.call_mint_keysets(&server.url),
                networking.call_mint_keys(&server.url, "test-keyset"),
            ] {
                assert!(result.unwrap_err().contains("byte limit"));
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn accepts_exact_limit_and_preserves_client_errors() {
    let server = Server::start(|_, _| Reply::ok(" ".repeat(LIMIT))).await;
    assert_eq!(
        server
            .networking()
            .call_mint_swap(&server.url, "{}")
            .await
            .unwrap()
            .len(),
        LIMIT
    );
    let networking = ReqwestClientNetworking::new(Duration::from_secs(5)).unwrap();
    assert_eq!(
        networking
            .call_mint_restore(&server.url, "{}")
            .unwrap()
            .len(),
        LIMIT
    );

    let server = Server::start(|_, _| Reply {
        status: "400 Bad Request",
        body: r#"{"code":12001,"detail":"inactive keyset"}"#.to_owned(),
        declared: None,
        stall: false,
    })
    .await;
    assert_eq!(
        networking.call_mint_swap(&server.url, "{}").unwrap_err(),
        r#"{"code":12001,"detail":"inactive keyset"}"#
    );
}

#[tokio::test]
async fn metadata_refuses_oversized_body_before_parsing() {
    let server = Server::start(|_, _| Reply::ok(" ".repeat(LIMIT + 1))).await;
    assert!(fetch_all_keysets_from_mint(&server.url)
        .await
        .unwrap_err()
        .contains("byte limit"));
}
