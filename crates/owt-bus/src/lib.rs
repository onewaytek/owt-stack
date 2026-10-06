//! Topic fan-out to this replica's sockets and streams, across replicas.
//!
//! A [`Subscription`] is one socket or stream: a bounded queue plus the set of topics
//! it currently belongs to, which it may change at any time. Publishing to a topic
//! reaches every subscription in it, on every replica.
//!
//! **One decode per replica, none per subscriber.** A message travels as text. A
//! replica with no subscriber in its topic drops it unread. Otherwise it decodes it
//! once, into the app's [`Message`] type, and every subscriber is handed the same
//! `Arc`.
//!
//! **Two transports behind one [`Bus`]:**
//! * Redis (production): publishing is `PUBLISH <prefix>:<topic>`, pipelined for a
//!   batch; each replica holds one `PSUBSCRIBE <prefix>:*`. The prefix keeps
//!   deployments and test runs that share a Redis apart. One pattern subscription, no
//!   per-topic subscribe traffic: every replica sees every message and drops what it
//!   has no one for.
//! * Local (tests, one process): publishing goes straight to local subscribers.
//!
//! **Trust.** A message is not authenticated: whoever can `PUBLISH` to the Redis can
//! put text in front of every subscriber, and apps publish rendered HTML. So the
//! Redis is part of the app's trust boundary. Give it a password or an ACL user
//! limited to `<prefix>:*`, keep other workloads off its network, and use a
//! `rediss://` URL (TLS, verified against the system's roots) wherever the path to
//! it leaves the node.
//!
//! **Failure handling**, each learnt from a fault-injection run:
//! * A publish Redis refuses is delivered locally: a Redis blip degrades to
//!   single-replica behaviour instead of silence.
//! * Each replica publishes a heartbeat to itself every 2 s and treats 6 s of silence
//!   on its subscription as death. A Redis killed outright can leave a subscription
//!   half-open: no error, and no message, ever again.
//! * Messages published while a replica was unsubscribed are gone. On resubscribing,
//!   every local subscriber is handed [`Message::resync`], so it can replay its
//!   client's current state as a reconnecting client would, and the notice hook is
//!   told changes may have been missed.
//! * A subscriber whose queue is full loses the message rather than stalling the
//!   publisher (counted, if metrics are configured).
//!
//! **Notices** ([`Bus::on_notice`]) are a side channel for cache invalidation: a short
//! key, delivered to the hook on every replica before any message published after it.

use std::collections::{HashMap, HashSet};
use std::fmt::Display;
use std::hash::Hash;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

use tokio::sync::mpsc;

/// What a message is addressed to. Its `Display` is the channel name after the prefix
/// and [`Topic::parse`] reads it back; names must not start with `~` (reserved).
pub trait Topic: Copy + Eq + Hash + Display + Send + Sync + 'static {
    /// The topic a channel name (without the prefix) stands for.
    fn parse(channel: &str) -> Option<Self>;
}

/// A message as subscribers receive it: decoded once per replica, shared by all.
pub trait Message: Send + Sync + Sized + 'static {
    /// Decode `text`; `None` drops it.
    fn decode(text: String) -> Option<Self>;
    /// The text that travels.
    fn text(&self) -> &str;
    /// What subscribers are handed after the subscription was re-established, when
    /// broadcasts may have been lost. `None`: nothing is.
    #[must_use]
    fn resync() -> Option<Self> {
        None
    }
}

/// A delivered message.
pub type Delivered<M> = Arc<M>;

/// The notice hook: `Some(key)` for a notice, `None` when notices may have been missed.
pub type OnNotice = Arc<dyn Fn(Option<&str>) + Send + Sync>;

const NOTICES: &str = "~changed";
const BEAT: &str = "~beat";

/// Tuning, and the metric names to record under.
#[derive(Clone, Debug)]
pub struct Options {
    /// Per-subscriber queue depth.
    pub capacity: usize,
    /// How often a replica publishes its heartbeat.
    pub beat_every: Duration,
    /// Silence after which the subscription is presumed dead.
    pub silence_limit: Duration,
    /// Metric names; `None` records nothing.
    pub metrics: Option<MetricNames>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            capacity: 1000,
            beat_every: Duration::from_secs(2),
            silence_limit: Duration::from_secs(6),
            metrics: None,
        }
    }
}

/// Where the bus records what it does.
#[derive(Clone, Debug)]
pub struct MetricNames {
    /// Histogram: time to publish one batch.
    pub publish_seconds: String,
    /// Counter: batches Redis refused (delivered locally only).
    pub publish_failures: String,
    /// Counter: messages dropped at a full subscriber queue.
    pub dropped: String,
}

impl MetricNames {
    /// `<prefix>_bus_publish_seconds`, `<prefix>_bus_publish_failures_total`,
    /// `<prefix>_bus_dropped_messages_total`.
    #[must_use]
    pub fn prefixed(prefix: &str) -> Self {
        Self {
            publish_seconds: format!("{prefix}_bus_publish_seconds"),
            publish_failures: format!("{prefix}_bus_publish_failures_total"),
            dropped: format!("{prefix}_bus_dropped_messages_total"),
        }
    }

    /// Describe the metrics to the recorder.
    pub fn describe(&self) {
        metrics::describe_histogram!(
            self.publish_seconds.clone(),
            metrics::Unit::Seconds,
            "Time to publish a message (or a pipeline of them) to Redis."
        );
        metrics::describe_counter!(
            self.publish_failures.clone(),
            "Publishes Redis refused; they were delivered on this replica only."
        );
        metrics::describe_counter!(
            self.dropped.clone(),
            "Messages dropped because a subscriber's queue was full: a client that fell behind lost them."
        );
    }
}

struct Registry<T, M> {
    topics: HashMap<T, HashMap<u64, mpsc::Sender<Delivered<M>>>>,
}

impl<T: Topic, M: Message> Registry<T, M> {
    fn deliver(&self, topic: T, msg: &Delivered<M>, dropped: Option<&str>) {
        if let Some(subs) = self.topics.get(&topic) {
            for tx in subs.values() {
                if tx.try_send(msg.clone()).is_err() {
                    count_drop(dropped);
                    tracing::warn!(%topic, "subscriber queue full or closed; dropping message");
                }
            }
        }
    }

    /// Hand `msg` to every subscriber once, whatever topics it is in.
    fn deliver_all(&self, msg: &Delivered<M>, dropped: Option<&str>) {
        let mut seen = HashSet::new();
        for subs in self.topics.values() {
            for (id, tx) in subs {
                if seen.insert(*id) && tx.try_send(msg.clone()).is_err() {
                    count_drop(dropped);
                }
            }
        }
    }
}

fn count_drop(name: Option<&str>) {
    if let Some(n) = name {
        metrics::counter!(n.to_owned()).increment(1);
    }
}

struct Shared<T, M> {
    registry: Mutex<Registry<T, M>>,
    next_id: AtomicU64,
    on_notice: OnceLock<OnNotice>,
    options: Options,
}

impl<T: Topic, M: Message> Shared<T, M> {
    fn registry(&self) -> MutexGuard<'_, Registry<T, M>> {
        self.registry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn notice(&self, key: Option<&str>) {
        if let Some(f) = self.on_notice.get() {
            f(key);
        }
    }

    fn dropped(&self) -> Option<&str> {
        self.options.metrics.as_ref().map(|m| m.dropped.as_str())
    }

    fn resync(&self) {
        if let Some(msg) = M::resync() {
            self.registry().deliver_all(&Arc::new(msg), self.dropped());
        }
    }
}

/// The fan-out. Cheap to clone; clones share subscribers.
pub struct Bus<T, M> {
    shared: Arc<Shared<T, M>>,
    redis: Option<redis::aio::ConnectionManager>,
    /// `"<prefix>:"`, prepended to every topic to make its channel.
    prefix: Arc<str>,
}

impl<T, M> Clone for Bus<T, M> {
    fn clone(&self) -> Self {
        Self {
            shared: self.shared.clone(),
            redis: self.redis.clone(),
            prefix: self.prefix.clone(),
        }
    }
}

impl<T: Topic, M: Message> Bus<T, M> {
    fn with(options: Options, redis: Option<redis::aio::ConnectionManager>, prefix: &str) -> Self {
        Self {
            shared: Arc::new(Shared {
                registry: Mutex::new(Registry {
                    topics: HashMap::new(),
                }),
                next_id: AtomicU64::new(1),
                on_notice: OnceLock::new(),
                options,
            }),
            redis,
            prefix: Arc::from(prefix),
        }
    }

    /// In this process only.
    #[must_use]
    pub fn local(options: Options) -> Self {
        Self::with(options, None, "")
    }

    /// Across replicas through the Redis at `url`: `publisher` carries publishes and
    /// the heartbeat; a task of its own holds the pattern subscription and feeds local
    /// subscribers, reconnecting for the life of the process.
    pub fn redis(
        url: &str,
        publisher: redis::aio::ConnectionManager,
        prefix: &str,
        options: Options,
    ) -> anyhow::Result<Self> {
        let bus = Self::with(options, Some(publisher.clone()), &format!("{prefix}:"));
        let client = redis::Client::open(url)?;
        tokio::spawn(heartbeat(
            publisher,
            format!("{}{BEAT}", bus.prefix),
            bus.shared.options.beat_every,
        ));
        tokio::spawn(subscribe(client, bus.prefix.clone(), bus.shared.clone()));
        Ok(bus)
    }

    /// Who to tell about notices (see the crate docs). Called in the subscriber's
    /// delivery loop, before any message published after the notice reaches a local
    /// subscriber, so it must be quick and must not block. Set once; later calls are
    /// ignored.
    pub fn on_notice(&self, f: OnNotice) {
        let _ = self.shared.on_notice.set(f);
    }

    /// Send `msg` to everyone in `topic`, on every replica.
    pub async fn publish(&self, topic: T, msg: Delivered<M>) {
        self.publish_batch(None, vec![(topic, msg)]).await;
    }

    /// Send a notice, if any, then each message to its topic, in one round trip (a
    /// pipeline). Every replica hears the notice before any of the messages.
    pub async fn publish_batch(&self, notice: Option<&str>, msgs: Vec<(T, Delivered<M>)>) {
        if msgs.is_empty() && notice.is_none() {
            return;
        }
        if let Some(conn) = &self.redis {
            let mut conn = conn.clone();
            let mut pipe = redis::pipe();
            if let Some(key) = notice {
                pipe.cmd("PUBLISH")
                    .arg(format!("{}{NOTICES}", self.prefix))
                    .arg(key)
                    .ignore();
            }
            for (topic, msg) in &msgs {
                pipe.cmd("PUBLISH")
                    .arg(format!("{}{topic}", self.prefix))
                    .arg(msg.text())
                    .ignore();
            }
            let started = Instant::now();
            let result: redis::RedisResult<()> = pipe.query_async(&mut conn).await;
            if let Some(m) = &self.shared.options.metrics {
                metrics::histogram!(m.publish_seconds.clone())
                    .record(started.elapsed().as_secs_f64());
                if result.is_err() {
                    metrics::counter!(m.publish_failures.clone()).increment(1);
                }
            }
            match result {
                Ok(()) => return,
                Err(e) => {
                    tracing::warn!(error = %e, count = msgs.len(), "bus: publish failed; delivering locally only");
                }
            }
        }
        if notice.is_some() {
            self.shared.notice(notice);
        }
        let registry = self.shared.registry();
        for (topic, msg) in &msgs {
            registry.deliver(*topic, msg, self.shared.dropped());
        }
    }

    /// Hand every local subscriber [`Message::resync`].
    pub fn resync_local(&self) {
        self.shared.resync();
    }

    /// A new subscription, in no topic yet.
    #[must_use]
    pub fn subscribe(&self) -> Subscription<T, M> {
        let (tx, rx) = mpsc::channel(self.shared.options.capacity);
        Subscription {
            id: self.shared.next_id.fetch_add(1, Ordering::Relaxed),
            tx,
            rx,
            topics: HashSet::new(),
            shared: self.shared.clone(),
        }
    }

    /// Whether any local subscriber is in `topic`.
    #[must_use]
    pub fn has_subscribers(&self, topic: T) -> bool {
        self.shared.registry().topics.contains_key(&topic)
    }
}

async fn heartbeat(mut conn: redis::aio::ConnectionManager, channel: String, every: Duration) {
    let mut tick = tokio::time::interval(every);
    loop {
        tick.tick().await;
        let _: redis::RedisResult<i64> = redis::cmd("PUBLISH")
            .arg(&channel)
            .arg("")
            .query_async(&mut conn)
            .await;
    }
}

async fn subscribe<T: Topic, M: Message>(
    client: redis::Client,
    prefix: Arc<str>,
    shared: Arc<Shared<T, M>>,
) {
    use futures::StreamExt;
    let silence = shared.options.silence_limit;
    let mut subscribed_before = false;
    loop {
        match client.get_async_pubsub().await {
            Ok(mut pubsub) => {
                if let Err(e) = pubsub.psubscribe(format!("{prefix}*")).await {
                    tracing::error!(error = %e, "bus: psubscribe failed");
                } else {
                    tracing::info!("bus: subscribed to Redis fan-out");
                    // Notices published while unsubscribed are lost, and so are
                    // broadcasts: local subscribers replay the current state.
                    shared.notice(None);
                    if subscribed_before {
                        shared.resync();
                    }
                    subscribed_before = true;
                    let mut stream = pubsub.into_on_message();
                    loop {
                        let msg = match tokio::time::timeout(silence, stream.next()).await {
                            Ok(Some(msg)) => msg,
                            Ok(None) => break,
                            Err(_) => {
                                tracing::warn!(
                                    "bus: nothing heard for {}s, not even this replica's own heartbeat; resubscribing",
                                    silence.as_secs()
                                );
                                break;
                            }
                        };
                        let channel = msg.get_channel_name();
                        let Some(name) = channel.strip_prefix(&*prefix) else {
                            continue;
                        };
                        if name == BEAT {
                            continue;
                        }
                        if name == NOTICES {
                            if let Ok(key) = msg.get_payload::<String>() {
                                shared.notice(Some(&key));
                            }
                            continue;
                        }
                        // Most messages are for another replica's subscribers: drop
                        // them unread.
                        let Some(topic) = T::parse(name) else {
                            continue;
                        };
                        if !shared.registry().topics.contains_key(&topic) {
                            continue;
                        }
                        let Ok(payload) = msg.get_payload::<String>() else {
                            continue;
                        };
                        let Some(decoded) = M::decode(payload) else {
                            continue;
                        };
                        shared
                            .registry()
                            .deliver(topic, &Arc::new(decoded), shared.dropped());
                    }
                    tracing::warn!("bus: Redis subscription ended; reconnecting");
                }
            }
            Err(e) => tracing::error!(error = %e, "bus: cannot connect to Redis; retrying"),
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

/// One listener: a queue of messages and the topics it is currently in. Dropping it
/// leaves them all.
pub struct Subscription<T: Topic, M: Message> {
    id: u64,
    tx: mpsc::Sender<Delivered<M>>,
    /// The queue, for `select!` loops that need the receiver itself.
    pub rx: mpsc::Receiver<Delivered<M>>,
    topics: HashSet<T>,
    shared: Arc<Shared<T, M>>,
}

impl<T: Topic, M: Message> Subscription<T, M> {
    /// Start receiving `topic`'s messages.
    pub fn join(&mut self, topic: T) {
        if self.topics.insert(topic) {
            self.shared
                .registry()
                .topics
                .entry(topic)
                .or_default()
                .insert(self.id, self.tx.clone());
        }
    }

    /// Stop receiving `topic`'s messages.
    pub fn leave(&mut self, topic: T) {
        if self.topics.remove(&topic) {
            let mut reg = self.shared.registry();
            if let Some(subs) = reg.topics.get_mut(&topic) {
                subs.remove(&self.id);
                if subs.is_empty() {
                    reg.topics.remove(&topic);
                }
            }
        }
    }

    /// The topics this subscription is in.
    #[must_use]
    pub fn topics(&self) -> &HashSet<T> {
        &self.topics
    }

    /// The next message.
    pub async fn recv(&mut self) -> Option<Delivered<M>> {
        self.rx.recv().await
    }
}

impl<T: Topic, M: Message> Drop for Subscription<T, M> {
    fn drop(&mut self) {
        let mut reg = self.shared.registry();
        for t in &self.topics {
            if let Some(subs) = reg.topics.get_mut(t) {
                subs.remove(&self.id);
                if subs.is_empty() {
                    reg.topics.remove(t);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fmt;

    use super::*;

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    enum Room {
        A,
        B,
    }

    impl fmt::Display for Room {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(match self {
                Room::A => "a",
                Room::B => "b",
            })
        }
    }

    impl Topic for Room {
        fn parse(c: &str) -> Option<Self> {
            match c {
                "a" => Some(Room::A),
                "b" => Some(Room::B),
                _ => None,
            }
        }
    }

    #[derive(Debug, PartialEq)]
    struct Text(String);

    impl Message for Text {
        fn decode(text: String) -> Option<Self> {
            Some(Text(text))
        }
        fn text(&self) -> &str {
            &self.0
        }
        fn resync() -> Option<Self> {
            Some(Text("~resync".into()))
        }
    }

    fn msg(s: &str) -> Delivered<Text> {
        Arc::new(Text(s.into()))
    }

    #[tokio::test]
    async fn topics_route_messages() {
        let bus: Bus<Room, Text> = Bus::local(Options::default());
        let (mut a, mut b) = (bus.subscribe(), bus.subscribe());
        a.join(Room::A);
        b.join(Room::A);
        b.join(Room::B);
        bus.publish(Room::A, msg("x")).await;
        bus.publish(Room::B, msg("y")).await;
        assert_eq!(a.recv().await.unwrap().0, "x");
        assert_eq!(b.recv().await.unwrap().0, "x");
        assert_eq!(b.recv().await.unwrap().0, "y");
        b.leave(Room::A);
        bus.publish(Room::A, msg("z")).await;
        assert_eq!(a.recv().await.unwrap().0, "z");
        assert!(b.rx.try_recv().is_err());
        drop(a);
        assert!(!bus.has_subscribers(Room::A));
    }

    #[tokio::test]
    async fn subscribers_share_one_delivery_and_resync_reaches_each_once() {
        let bus: Bus<Room, Text> = Bus::local(Options::default());
        let (mut a, mut b) = (bus.subscribe(), bus.subscribe());
        a.join(Room::A);
        b.join(Room::A);
        b.join(Room::B);
        bus.publish(Room::A, msg("x")).await;
        let (da, db) = (a.recv().await.unwrap(), b.recv().await.unwrap());
        assert!(Arc::ptr_eq(&da, &db));
        bus.resync_local();
        assert_eq!(b.recv().await.unwrap().0, "~resync");
        assert!(b.rx.try_recv().is_err(), "once, though in two topics");
        assert_eq!(a.recv().await.unwrap().0, "~resync");
    }

    #[tokio::test]
    async fn full_queues_drop_rather_than_block() {
        let bus: Bus<Room, Text> = Bus::local(Options {
            capacity: 1,
            ..Options::default()
        });
        let mut a = bus.subscribe();
        a.join(Room::A);
        bus.publish(Room::A, msg("1")).await;
        bus.publish(Room::A, msg("2")).await;
        assert_eq!(a.recv().await.unwrap().0, "1");
        assert!(a.rx.try_recv().is_err());
    }

    /// Two buses on one Redis and prefix are two replicas. Needs `REDIS_URL`; skipped
    /// without it.
    #[tokio::test]
    async fn replicas_hear_each_other_and_notices_come_first() {
        let Ok(url) = std::env::var("REDIS_URL") else {
            return;
        };
        let prefix = format!("owt-bus-test-{}", std::process::id());
        let conn = |u: String| async move {
            redis::aio::ConnectionManager::new(redis::Client::open(u).unwrap())
                .await
                .unwrap()
        };
        let one: Bus<Room, Text> =
            Bus::redis(&url, conn(url.clone()).await, &prefix, Options::default()).unwrap();
        let two: Bus<Room, Text> =
            Bus::redis(&url, conn(url.clone()).await, &prefix, Options::default()).unwrap();
        let heard = Arc::new(Mutex::new(Vec::<Option<String>>::new()));
        let h = heard.clone();
        two.on_notice(Arc::new(move |k| {
            h.lock().unwrap().push(k.map(str::to_owned));
        }));
        let mut sub = two.subscribe();
        sub.join(Room::B);
        // Wait for both subscriptions (each reports `None` on subscribing; `one` has no
        // hook, so give it the same time).
        tokio::time::timeout(Duration::from_secs(5), async {
            while heard.lock().unwrap().is_empty() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        one.publish_batch(
            Some("k1"),
            vec![(Room::B, msg("hello")), (Room::A, msg("nobody"))],
        )
        .await;
        let got = tokio::time::timeout(Duration::from_secs(5), sub.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got.0, "hello");
        assert_eq!(
            heard.lock().unwrap().last().cloned().flatten().as_deref(),
            Some("k1")
        );
        assert!(sub.rx.try_recv().is_err());
    }

    #[test]
    fn tls_urls_are_understood() {
        let client = redis::Client::open("rediss://user:pw@redis.example:6380/0").unwrap();
        assert!(matches!(
            client.get_connection_info().addr(),
            redis::ConnectionAddr::TcpTls {
                insecure: false,
                ..
            }
        ));
    }
}
