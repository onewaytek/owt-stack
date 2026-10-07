//! Another tenant of the Redis publishing into this bus's channels.
//!
//! The bus cannot authenticate a message (see the crate docs: the Redis is inside the
//! trust boundary), but nothing published there may stop it: bytes that are not text,
//! channels that name no topic, payloads the app's decoder refuses. After all of
//! them, a real message still arrives. Needs `REDIS_URL`; skipped without it.

use std::fmt;
use std::sync::Arc;
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
struct Json(String);

impl Message for Json {
    /// Only what looks like the app's own messages.
    fn decode(text: String) -> Option<Self> {
        text.starts_with('{').then_some(Json(text))
    }
    fn text(&self) -> &str {
        &self.0
    }
}

#[tokio::test]
async fn hostile_publishes_are_dropped_and_the_bus_carries_on() {
    let Ok(url) = std::env::var("REDIS_URL") else {
        return;
    };
    let prefix = format!("owt-bus-hostile-{}", std::process::id());
    let client = redis::Client::open(url.clone()).unwrap();
    let publisher = redis::aio::ConnectionManager::new(client.clone())
        .await
        .unwrap();
    let bus: Bus<Room, Json> = Bus::redis(&url, publisher, &prefix, Options::default()).unwrap();
    let notices = Arc::new(std::sync::Mutex::new(Vec::<Option<String>>::new()));
    let heard = notices.clone();
    bus.on_notice(Arc::new(move |k| {
        heard.lock().unwrap().push(k.map(str::to_owned));
    }));
    let mut sub = bus.subscribe();
    sub.join(Room(1));
    // Subscribed once the hook hears its first `None`.
    tokio::time::timeout(Duration::from_secs(5), async {
        while notices.lock().unwrap().is_empty() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the bus subscribes");

    let mut raw = client.get_multiplexed_async_connection().await.unwrap();
    let big = vec![b'{'; 2 * 1024 * 1024];
    let hostile: Vec<(String, Vec<u8>)> = vec![
        // Not text.
        (format!("{prefix}:room-1"), vec![0xff, 0xfe, 0x00, 0x80]),
        // Text the decoder refuses.
        (
            format!("{prefix}:room-1"),
            b"<script>alert(1)</script>".to_vec(),
        ),
        // No such topic, an unparseable one, the reserved names with junk.
        (format!("{prefix}:room-999"), b"{}".to_vec()),
        (format!("{prefix}:\u{0}\r\n*"), b"{}".to_vec()),
        (format!("{prefix}:~beat"), vec![0xff; 64]),
        (format!("{prefix}:~changed"), vec![0xff; 64]),
        (format!("{prefix}:"), b"{}".to_vec()),
        // A topic nobody here is in.
        (format!("{prefix}:room-2"), b"{\"for\":\"nobody\"}".to_vec()),
        // Large, and well formed: delivered, and the queue survives it.
        (format!("{prefix}:room-1"), big.clone()),
    ];
    for (channel, payload) in &hostile {
        let _: i64 = redis::cmd("PUBLISH")
            .arg(channel.as_bytes())
            .arg(payload.as_slice())
            .query_async(&mut raw)
            .await
            .unwrap();
    }
    bus.publish(Room(1), Arc::new(Json("{\"real\":true}".into())))
        .await;

    let mut got = Vec::new();
    while got.len() < 2 {
        let m = tokio::time::timeout(Duration::from_secs(5), sub.recv())
            .await
            .expect("the bus is still delivering")
            .unwrap();
        got.push(m.0.len());
    }
    assert_eq!(got, [big.len(), "{\"real\":true}".len()]);
    assert!(sub.rx.try_recv().is_err(), "nothing else got through");
    // The junk notice was not text, so the hook never saw it.
    assert!(notices.lock().unwrap().iter().all(Option::is_none));
}
