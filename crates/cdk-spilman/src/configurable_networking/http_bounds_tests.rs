use super::*;
use crate::configurable_host::{ConfigurableHostConfig, StorageConfig};
use std::io::Write;
use std::{collections::HashMap, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const LIMIT: usize = 4 * 1024 * 1024;

pub(crate) struct Reply {
    pub status: &'static str,
    pub body: Vec<u8>,
    pub headers: &'static str,
    pub declared: Option<usize>,
    pub stall: bool,
}

impl Reply {
    pub(crate) fn ok(body: impl Into<Vec<u8>>) -> Self {
        Self {
            status: "200 OK",
            body: body.into(),
            headers: "",
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
                let headers = format!("HTTP/1.1 {}\r\nContent-Type: application/json\r\n{}{length}Connection: close\r\n\r\n", reply.status, reply.headers);
                if socket.write_all(headers.as_bytes()).await.is_ok() {
                    let _ = socket.write_all(&reply.body).await;
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
                        Vec::new()
                    } else {
                        vec![b' '; LIMIT + 1]
                    },
                    declared: declared.then_some(LIMIT + 1),
                    headers: "",
                    stall: false,
                }
            })
            .await;
            let result = server.networking().call_mint_swap(&server.url, "{}").await;
            assert!(result.is_err(), "oversized success body must be refused");
            assert!(
                result.unwrap_err().to_string().contains("byte limit"),
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
            body: body.as_bytes().to_vec(),
            headers: "",
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
                crate::MintResponse {
                    status: 400,
                    body: body.to_owned(),
                }
                .into_result()
            }
        );
    }
}

#[tokio::test]
async fn swap_stalled_body_obeys_production_deadline() {
    let server = Server::start(|_, _| Reply {
        status: "200 OK",
        body: b"{".to_vec(),
        headers: "",
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
                    Vec::new()
                } else {
                    vec![b' '; LIMIT + 1]
                },
                declared: declared.then_some(LIMIT + 1),
                headers: "",
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
                assert!(result.unwrap_err().to_string().contains("byte limit"));
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
        body: br#"{"code":12001,"detail":"inactive keyset"}"#.to_vec(),
        headers: "",
        declared: None,
        stall: false,
    })
    .await;
    assert_eq!(
        networking
            .call_mint_swap(&server.url, "{}")
            .unwrap_err()
            .rejection()
            .unwrap()
            .code(),
        12001
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invalid_utf8_is_not_repaired_into_a_retryable_mint_error() {
    let server = Server::start(|_, _| Reply {
        status: "400 Bad Request",
        ..Reply::ok(b"{\"code\":12002,\"detail\":\"\xff\"}".to_vec())
    })
    .await;
    let client = ReqwestClientNetworking::new(Duration::from_secs(5)).unwrap();
    for error in [
        server
            .networking()
            .call_mint_swap(&server.url, "{}")
            .await
            .unwrap_err(),
        client.call_mint_swap(&server.url, "{}").unwrap_err(),
    ] {
        assert!(error.to_string().contains("UTF-8"), "{error}");
        assert!(!error.permits_keyset_retry());
    }
}

#[tokio::test]
async fn metadata_rejects_invalid_utf8_instead_of_repairing_it() {
    // The old Response::json path rejected this; lossy decoding would silently
    // turn the invalid byte into a valid JSON string and accept the empty list.
    let server =
        Server::start(|_, _| Reply::ok(b"{\"keysets\":[],\"extra\":\"\xff\"}".to_vec())).await;
    assert!(fetch_all_keysets_from_mint(&server.url)
        .await
        .unwrap_err()
        .contains("UTF-8"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gzip_limit_applies_to_decoded_bytes_on_success_and_error() {
    for size in [LIMIT, LIMIT + 1] {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(&vec![b' '; size]).unwrap();
        let compressed = encoder.finish().unwrap();
        assert!(compressed.len() < LIMIT);
        for status in ["200 OK", "500 Internal Server Error"] {
            let compressed = compressed.clone();
            let server = Server::start(move |_, _| Reply {
                status,
                declared: Some(compressed.len()),
                headers: "Content-Encoding: gzip\r\n",
                ..Reply::ok(compressed.clone())
            })
            .await;
            let client = ReqwestClientNetworking::new(Duration::from_secs(5)).unwrap();
            for result in [
                server.networking().call_mint_swap(&server.url, "{}").await,
                client.call_mint_swap(&server.url, "{}"),
                client.call_mint_restore(&server.url, "{}"),
                client.call_mint_keysets(&server.url),
                client.call_mint_keys(&server.url, "test-keyset"),
            ] {
                if size > LIMIT {
                    assert!(result.unwrap_err().to_string().contains("byte limit"));
                } else if status == "200 OK" {
                    assert_eq!(result.unwrap().len(), LIMIT);
                } else {
                    assert!(!result.unwrap_err().to_string().contains("byte limit"));
                }
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn chunked_and_truncated_bodies_never_expose_a_retryable_prefix() {
    for oversized in [false, true] {
        let server = Server::start(move |_, _| {
            let mut body = br#"{"code":12002,"detail":"inactive keyset"}"#.to_vec();
            if oversized {
                body.resize(LIMIT + 1, b' ');
            }
            let mut chunks = Vec::new();
            for chunk in body.chunks(4096) {
                write!(chunks, "{:x}\r\n", chunk.len()).unwrap();
                chunks.extend_from_slice(chunk);
                chunks.extend_from_slice(b"\r\n");
            }
            // No terminating chunk: even a complete-looking JSON prefix is
            // ambiguous until the entire HTTP response has been received.
            Reply {
                status: "400 Bad Request",
                headers: "Transfer-Encoding: chunked\r\n",
                ..Reply::ok(chunks)
            }
        })
        .await;
        let client = ReqwestClientNetworking::new(Duration::from_secs(5)).unwrap();
        for error in [
            server
                .networking()
                .call_mint_swap(&server.url, "{}")
                .await
                .unwrap_err(),
            client.call_mint_swap(&server.url, "{}").unwrap_err(),
        ] {
            if oversized {
                assert!(error.to_string().contains("byte limit"), "{error}");
            }
            assert!(!error.permits_keyset_retry());
        }
    }
}

#[tokio::test]
async fn discovery_bounds_per_keyset_keys_and_rejects_http_errors_without_reading_them() {
    for metadata_error in [false, true] {
        let server = Server::start(move |path, _| {
            if metadata_error || path.starts_with("/v1/keys/") {
                return Reply {
                    status: if metadata_error {
                        "503 Service Unavailable"
                    } else {
                        "200 OK"
                    },
                    // Do not send a body: rejecting headers must not wait for it.
                    declared: Some(LIMIT + 1),
                    stall: true,
                    ..Reply::ok(Vec::new())
                };
            }
            assert_eq!(path, "/v1/keysets");
            Reply::ok(r#"{"keysets":[{"id":"0000000000000001","unit":"sat","active":true}]}"#)
        })
        .await;
        let error = tokio::time::timeout(
            Duration::from_secs(2),
            fetch_all_keysets_from_mint(&server.url),
        )
        .await
        .unwrap()
        .unwrap_err();
        if metadata_error {
            assert!(error.contains("503"), "{error}");
        } else {
            assert!(error.contains("byte limit"), "{error}");
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_timeout_covers_stalled_success_and_error_bodies() {
    for status in ["200 OK", "400 Bad Request"] {
        let server = Server::start(move |_, _| Reply {
            status,
            stall: true,
            ..Reply::ok(br#"{"code":12002}"#.to_vec())
        })
        .await;
        let client = ReqwestClientNetworking::new(Duration::from_millis(100)).unwrap();
        for result in [
            client.call_mint_swap(&server.url, "{}"),
            client.call_mint_restore(&server.url, "{}"),
            client.call_mint_keysets(&server.url),
        ] {
            let error = result.unwrap_err();
            assert!(!error.permits_keyset_retry());
        }
    }
}

#[tokio::test]
async fn swap_stalled_headers_obey_production_deadline() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        // Read the request but withhold all response headers until the client's
        // deadline closes the connection. No sleeps or server-side deadline.
        tokio::io::copy(&mut socket, &mut tokio::io::sink())
            .await
            .unwrap();
    });
    let server = Server { url, task };
    let start = std::time::Instant::now();
    let result = tokio::time::timeout(
        Duration::from_secs(35),
        server.networking().call_mint_swap(&server.url, "{}"),
    )
    .await;
    let error = result
        .expect("swap headers exceeded the production deadline")
        .unwrap_err();
    assert!(start.elapsed() >= Duration::from_secs(29));
    assert!(!error.permits_keyset_retry());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn complete_chunked_body_accepts_exact_limit_excluding_framing() {
    let server = Server::start(|_, _| {
        let mut chunks = Vec::new();
        for chunk in vec![b' '; LIMIT].chunks(4096) {
            write!(chunks, "{:x}\r\n", chunk.len()).unwrap();
            chunks.extend_from_slice(chunk);
            chunks.extend_from_slice(b"\r\n");
        }
        chunks.extend_from_slice(b"0\r\n\r\n");
        assert!(chunks.len() > LIMIT);
        Reply {
            headers: "Transfer-Encoding: chunked\r\n",
            ..Reply::ok(chunks)
        }
    })
    .await;
    let client = ReqwestClientNetworking::new(Duration::from_secs(5)).unwrap();
    assert_eq!(
        server
            .networking()
            .call_mint_swap(&server.url, "{}")
            .await
            .unwrap()
            .len(),
        LIMIT
    );
    assert_eq!(
        client.call_mint_restore(&server.url, "{}").unwrap().len(),
        LIMIT
    );
}
