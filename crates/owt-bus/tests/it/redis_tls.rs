//! The bus over `rediss://`: TLS to the Redis, verified against the system's roots.
//!
//! Needs `REDIS_TLS_URL` (a `rediss://` URL whose host the server's certificate
//! names) and, for a test CA, `SSL_CERT_FILE` pointing at its certificate; skipped
//! without the URL. Verification is shown to be on, not just the transport: the same
//! server under a name its certificate does not cover is refused.
//!
//! Locally: `openssl` a CA and a certificate for `IP:127.0.0.1`, run
//! `redis-server --port 0 --tls-port 6380 --tls-cert-file … --tls-key-file …
//! --tls-ca-cert-file … --tls-auth-clients no`, then
//! `SSL_CERT_FILE=ca.crt REDIS_TLS_URL=rediss://127.0.0.1:6380 cargo test -p owt-bus`.

use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use owt_bus::{Bus, Message, Options, Topic};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct Room(u8);

impl fmt::Display for Room {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "room-{}", self.0)
    }
}

impl Topic for Room {
    fn parse(channel: &str) -> Option<Self> {
        channel.strip_prefix("room-")?.parse().ok().map(Room)
    }
}

#[derive(Debug)]
struct Text(String);

impl Message for Text {
    fn decode(text: String) -> Option<Self> {
        Some(Text(text))
    }
    fn text(&self) -> &str {
        &self.0
    }
}

async fn publisher(url: &str) -> redis::RedisResult<redis::aio::ConnectionManager> {
    let client = redis::Client::open(url)?;
    tokio::time::timeout(
        Duration::from_secs(5),
        redis::aio::ConnectionManager::new(client),
    )
    .await
    .map_err(|_| redis::RedisError::from((redis::ErrorKind::Io, "connecting timed out")))?
}

#[tokio::test]
async fn replicas_hear_each_other_over_tls_and_an_unnamed_host_is_refused() {
    let Ok(url) = std::env::var("REDIS_TLS_URL") else {
        return;
    };
    assert!(
        url.starts_with("rediss://"),
        "REDIS_TLS_URL must be rediss://"
    );
    let prefix = format!("owt-bus-tls-{}", std::process::id());
    // As an app does before its first rediss:// connection made outside the bus.
    owt_bus::ensure_crypto_provider();

    let one: Bus<Room, Text> = Bus::redis(
        &url,
        publisher(&url)
            .await
            .expect("TLS connects with the CA trusted"),
        &prefix,
        Options::default(),
    )
    .unwrap();
    let two: Bus<Room, Text> = Bus::redis(
        &url,
        publisher(&url).await.unwrap(),
        &prefix,
        Options::default(),
    )
    .unwrap();
    let heard = Arc::new(Mutex::new(0usize));
    let h = heard.clone();
    two.on_notice(Arc::new(move |_| *h.lock().unwrap() += 1));
    let mut sub = two.subscribe();
    sub.join(Room(1));
    tokio::time::timeout(Duration::from_secs(5), async {
        while *heard.lock().unwrap() == 0 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the subscription over TLS came up");
    tokio::time::sleep(Duration::from_millis(200)).await;
    one.publish(Room(1), Text("over tls".into()).into()).await;
    let got = tokio::time::timeout(Duration::from_secs(5), sub.recv())
        .await
        .expect("a message arrived over TLS")
        .unwrap();
    assert_eq!(got.0, "over tls");

    // The same server, under a name the certificate does not cover: the handshake
    // must fail, or a `rediss://` URL would be no more than a transport.
    let parsed = url::Url::parse(&url).unwrap();
    let host = parsed.host_str().unwrap();
    let other = if host == "127.0.0.1" {
        "localhost"
    } else {
        "127.0.0.1"
    };
    let mut unnamed = parsed.clone();
    unnamed.set_host(Some(other)).unwrap();
    // One attempt, not the manager's retries: the error is the handshake's.
    let refused = tokio::time::timeout(
        Duration::from_secs(5),
        redis::Client::open(unnamed.as_str())
            .unwrap()
            .get_multiplexed_async_connection(),
    )
    .await
    .expect("the handshake fails rather than hangs");
    let err = refused.err().unwrap_or_else(|| {
        panic!("{unnamed} connected: the certificate was not verified against the host")
    });
    let text = err.to_string();
    assert!(
        text.contains("certificate") || text.contains("Certificate") || text.contains("name"),
        "refused for another reason: {text}"
    );
}
