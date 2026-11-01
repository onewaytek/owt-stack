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
//! **Failure handling:**
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
//!   publisher (counted, if metrics are configured). The first loss marks it lagged
//!   and logs one warning; it is handed [`Message::resync`] as soon as its queue has
//!   room again, whether [`Subscription::recv`] finds the queue empty or the next
//!   message for it arrives, after which a later loss warns again.
//!
//! **Notices** ([`Bus::on_notice`]) are a side channel for cache invalidation: a short
//! key, delivered to the hook on every replica before any message published after it.

use std::collections::{HashMap, HashSet};
use std::fmt::Display;
use std::hash::Hash;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
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
    /// What subscribers are handed when broadcasts may have been lost: after the
    /// Redis subscription was re-established, and to a subscriber whose full queue
    /// lost messages, once it has room. `None`: nothing is.
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

/// One subscription's end of its queue, as the registry holds it.
struct Sink<M> {
    tx: mpsc::Sender<Delivered<M>>,
    /// Set when a message was lost at a full queue, cleared when the subscriber is
    /// handed [`Message::resync`].
    lagged: Arc<AtomicBool>,
}

impl<M> Clone for Sink<M> {
    fn clone(&self) -> Self {
        Self {
            tx: self.tx.clone(),
            lagged: self.lagged.clone(),
        }
    }
}

impl<M: Message> Sink<M> {
    /// Queue `msg`, first handing a lagged subscriber [`Message::resync`] if there is
    /// room for both.
    fn send(&self, msg: &Delivered<M>, dropped: Option<&str>) {
        if self.lagged.load(Ordering::Acquire) {
            self.catch_up(dropped, false);
        }
        if self.tx.try_send(msg.clone()).is_err() {
            self.lost(dropped);
        }
    }

    /// Hand the subscriber [`Message::resync`] if its queue has room, which ends a lag.
    /// `count`: a full queue loses the resync itself (a broadcast resync), rather than
    /// leaving a lag pending (a catch-up before a message).
    fn catch_up(&self, dropped: Option<&str>, count: bool) {
        let Some(msg) = M::resync() else {
            self.lagged.store(false, Ordering::Release);
            return;
        };
        match self.tx.try_reserve() {
            Ok(permit) => {
                self.lagged.store(false, Ordering::Release);
                permit.send(Arc::new(msg));
            }
            Err(_) if count => self.lost(dropped),
            Err(_) => {}
        }
    }

    /// A message was lost: counted every time, logged when it starts a lag.
    fn lost(&self, dropped: Option<&str>) {
        count_drop(dropped);
        if !self.tx.is_closed() && !self.lagged.swap(true, Ordering::AcqRel) {
            tracing::warn!("subscriber queue full; dropping its messages until it drains");
        }
    }
}

struct Registry<T, M> {
    topics: HashMap<T, HashMap<u64, Sink<M>>>,
}

impl<T: Topic, M: Message> Registry<T, M> {
    fn deliver(&self, topic: T, msg: &Delivered<M>, dropped: Option<&str>) {
        if let Some(subs) = self.topics.get(&topic) {
            for sink in subs.values() {
                sink.send(msg, dropped);
            }
        }
    }

    /// Hand every subscriber [`Message::resync`] once, whatever topics it is in.
    fn resync_all(&self, dropped: Option<&str>) {
        let mut seen = HashSet::new();
        for subs in self.topics.values() {
            for (id, sink) in subs {
                if seen.insert(*id) {
                    sink.catch_up(dropped, true);
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
        if M::resync().is_some() {
            self.registry().resync_all(self.dropped());
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
    ///
    /// # Errors
    ///
    /// A `prefix` that is not ASCII letters, digits, `_`, `.` and `-` (the
    /// subscription is the glob `<prefix>:*`, so `*`, `?`, `[` or `:` in it would
    /// match other deployments' channels), a zero `beat_every`, or a bad `url`.
    pub fn redis(
        url: &str,
        publisher: redis::aio::ConnectionManager,
        prefix: &str,
        options: Options,
    ) -> anyhow::Result<Self> {
        checked_prefix(prefix)?;
        anyhow::ensure!(
            !options.beat_every.is_zero(),
            "the bus heartbeat period is zero"
        );
        let bus = Self::with(options, Some(publisher.clone()), &format!("{prefix}:"));
        ensure_crypto_provider();
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
            sink: Sink {
                tx,
                lagged: Arc::new(AtomicBool::new(false)),
            },
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

/// A prefix the channel glob matches only literally, with nothing nested under it.
/// The same rule as `owt-runtime`'s cache and leases, which share their own copy:
/// this crate does not depend on that one.
fn checked_prefix(prefix: &str) -> anyhow::Result<()> {
    let literal = !prefix.is_empty()
        && prefix
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'));
    anyhow::ensure!(
        literal,
        "a bus prefix is ASCII letters, digits, `_`, `.` and `-`: {prefix:?}"
    );
    Ok(())
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
    sink: Sink<M>,
    /// The queue, for `select!` loops that need the receiver itself. Reading it
    /// directly skips the resync [`Subscription::recv`] hands a lagged subscription
    /// whose queue it finds empty; the subscription still gets it ahead of its next
    /// message.
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
                .insert(self.id, self.sink.clone());
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

    /// The next message. A subscription that lost messages at a full queue is handed
    /// [`Message::resync`] once it has read what was queued.
    pub async fn recv(&mut self) -> Option<Delivered<M>> {
        match self.rx.try_recv() {
            Ok(msg) => return Some(msg),
            Err(mpsc::error::TryRecvError::Disconnected) => return None,
            Err(mpsc::error::TryRecvError::Empty) => {}
        }
        if self.sink.lagged.swap(false, Ordering::AcqRel)
            && let Some(msg) = M::resync()
        {
            return Some(Arc::new(msg));
        }
        self.rx.recv().await
    }

    /// Whether this subscription lost messages at a full queue and has not yet been
    /// handed [`Message::resync`] for it.
    #[must_use]
    pub fn is_lagged(&self) -> bool {
        self.sink.lagged.load(Ordering::Acquire)
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

/// rustls needs one process-wide crypto provider before the first `rediss://`
/// handshake. It picks one itself only when exactly one backend is compiled in; an
/// app whose dependencies bring both ring and aws-lc-rs, or neither, would otherwise
/// panic on its first TLS connection to the Redis. Call this before building a
/// connection (`Bus::redis` does) and before [`redis::aio::ConnectionManager::new`]
/// on a `rediss://` client made elsewhere. Installing after another provider is in
/// place is a no-op.
pub fn ensure_crypto_provider() {
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    }
}

#[cfg(test)]
mod tests {
    use std::fmt;

    use super::*;

    /// The subscription is `PSUBSCRIBE <prefix>:*`: a prefix with glob characters, or
    /// one another deployment's prefix nests under, would hear that deployment.
    #[test]
    fn a_prefix_is_matched_literally() {
        for ok in ["myapp", "my-app_2.staging"] {
            assert!(checked_prefix(ok).is_ok(), "{ok}");
        }
        for bad in ["", "*", "my*", "my?app", "[ab]", "staging:x", "my app", "é"] {
            assert!(checked_prefix(bad).is_err(), "{bad}");
        }
    }

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

    #[tokio::test]
    async fn a_subscriber_that_lost_messages_is_resynced_once_it_drains() {
        let bus: Bus<Room, Text> = Bus::local(Options {
            capacity: 1,
            ..Options::default()
        });
        let mut a = bus.subscribe();
        a.join(Room::A);
        bus.publish(Room::A, msg("1")).await;
        assert!(!a.is_lagged());
        bus.publish(Room::A, msg("2")).await;
        bus.publish(Room::A, msg("3")).await;
        assert!(a.is_lagged());
        assert_eq!(a.recv().await.unwrap().0, "1");
        assert_eq!(a.recv().await.unwrap().0, "~resync");
        assert!(!a.is_lagged());
        assert!(a.rx.try_recv().is_err(), "one resync for the whole lag");
        bus.publish(Room::A, msg("4")).await;
        assert_eq!(a.recv().await.unwrap().0, "4");
    }

    #[tokio::test]
    async fn a_lagged_subscriber_read_directly_gets_the_resync_before_its_next_message() {
        let bus: Bus<Room, Text> = Bus::local(Options {
            capacity: 2,
            ..Options::default()
        });
        let mut a = bus.subscribe();
        a.join(Room::A);
        for m in ["1", "2", "3"] {
            bus.publish(Room::A, msg(m)).await;
        }
        assert_eq!(a.rx.try_recv().unwrap().0, "1");
        assert_eq!(a.rx.try_recv().unwrap().0, "2");
        assert!(a.is_lagged(), "reading rx directly does not end the lag");
        bus.publish(Room::A, msg("4")).await;
        assert!(!a.is_lagged());
        assert_eq!(a.rx.try_recv().unwrap().0, "~resync");
        assert_eq!(a.rx.try_recv().unwrap().0, "4");
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

    #[test]
    fn rediss_can_build_its_tls_config() {
        // redis builds `rustls::ClientConfig::builder()`, which panics unless a
        // provider is installed or exactly one backend is compiled in. Built alone,
        // this crate compiles in none; an app may compile in two.
        ensure_crypto_provider();
        let _ = rustls::ClientConfig::builder();
    }
}
