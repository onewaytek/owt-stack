//! Prometheus metrics: the recorder, HTTP timings, sampled gauges, and `/metrics` on a
//! listener of its own (never through the public Route).
//!
//! Metric names belong to the app, which keeps its catalogue in one place; everything
//! here takes names as arguments. Times are seconds and latencies are histograms,
//! which survive any scrape interval.

use std::sync::OnceLock;
use std::time::{Duration, Instant};

use axum::extract::{MatchedPath, Request, State};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use metrics::{gauge, histogram};
use metrics_exporter_prometheus::{Matcher, PrometheusBuilder, PrometheusHandle};

/// Request-sized latencies: 1 ms to 10 s.
pub const LATENCY_BUCKETS: &[f64] = &[
    0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

static HANDLE: OnceLock<PrometheusHandle> = OnceLock::new();

/// Install the process-wide recorder with [`LATENCY_BUCKETS`] for every histogram
/// except those named in `overrides`, then run `describe` (the app's `describe_*!`
/// calls). Once per process: later calls return the first handle and ignore their
/// arguments, so tests may call it freely.
///
/// # Panics
/// If another crate installed a global recorder first.
pub fn install(overrides: &[(&str, &[f64])], describe: impl FnOnce()) -> &'static PrometheusHandle {
    HANDLE.get_or_init(|| {
        let mut b = PrometheusBuilder::new()
            .set_buckets(LATENCY_BUCKETS)
            .expect("the bucket list is not empty");
        for (name, buckets) in overrides {
            b = b
                .set_buckets_for_metric(Matcher::Full((*name).to_owned()), buckets)
                .expect("override bucket lists are not empty");
        }
        let handle = b
            .install_recorder()
            .expect("no other metrics recorder is installed");
        describe();
        metrics_process::Collector::default().describe();
        handle
    })
}

/// The histogram [`http`] records into, by name.
#[derive(Clone, Copy, Debug)]
pub struct HttpTimer(pub &'static str);

/// Middleware body, for `from_fn_with_state(HttpTimer("app_http_request_seconds"),
/// metrics::http)`: time every request, labelled by `route` (the pattern, not the
/// path), `method` and `status`. Unmatched requests are `route="unmatched"` and a
/// method outside the standard nine is `method="other"`, so neither a scan of random
/// paths nor requests with invented methods (hyper accepts any token, and proxies
/// pass them on) can grow the label set, each new set being a histogram kept for the
/// life of the process. Layer it on the routed router, so the matched path is known.
pub async fn http(State(timer): State<HttpTimer>, req: Request, next: Next) -> Response {
    let route = req
        .extensions()
        .get::<MatchedPath>()
        .map_or_else(|| "unmatched".to_owned(), |p| p.as_str().to_owned());
    let method = method_label(req.method());
    let started = Instant::now();
    let response = next.run(req).await;
    let status = response.status().as_u16().to_string();
    histogram!(timer.0, "route" => route, "method" => method, "status" => status)
        .record(started.elapsed().as_secs_f64());
    response
}

/// A standard method's name, else `other`: the label's values are a fixed set.
fn method_label(method: &axum::http::Method) -> &'static str {
    use axum::http::Method;
    match *method {
        Method::GET => "GET",
        Method::HEAD => "HEAD",
        Method::POST => "POST",
        Method::PUT => "PUT",
        Method::PATCH => "PATCH",
        Method::DELETE => "DELETE",
        Method::OPTIONS => "OPTIONS",
        Method::CONNECT => "CONNECT",
        Method::TRACE => "TRACE",
        _ => "other",
    }
}

/// Gauges for the async runtime, named `<prefix>_runtime_*`.
#[derive(Clone, Debug)]
pub struct RuntimeGauges {
    workers: String,
    alive_tasks: String,
    global_queue_depth: String,
    busy_seconds: String,
}

impl RuntimeGauges {
    /// Gauges named `<prefix>_runtime_{workers,alive_tasks,global_queue_depth,busy_seconds}`.
    #[must_use]
    pub fn prefixed(prefix: &str) -> Self {
        Self {
            workers: format!("{prefix}_runtime_workers"),
            alive_tasks: format!("{prefix}_runtime_alive_tasks"),
            global_queue_depth: format!("{prefix}_runtime_global_queue_depth"),
            busy_seconds: format!("{prefix}_runtime_busy_seconds"),
        }
    }

    /// Describe the gauges (call from `install`'s `describe`).
    pub fn describe(&self) {
        metrics::describe_gauge!(self.workers.clone(), "Async runtime worker threads.");
        metrics::describe_gauge!(self.alive_tasks.clone(), "Async tasks alive.");
        metrics::describe_gauge!(
            self.global_queue_depth.clone(),
            "Tasks waiting in the runtime's global queue: sustained depth means the workers can't keep up."
        );
        metrics::describe_gauge!(
            self.busy_seconds.clone(),
            metrics::Unit::Seconds,
            "Time the runtime's workers have spent running tasks, summed over workers; only ever grows. rate() ÷ workers is how busy they were."
        );
    }

    /// Read the current runtime's numbers into the gauges.
    #[expect(clippy::cast_precision_loss, reason = "gauges are f64")]
    pub fn sample(&self) {
        let rt = tokio::runtime::Handle::current().metrics();
        let workers = rt.num_workers();
        gauge!(self.workers.clone()).set(workers as f64);
        gauge!(self.alive_tasks.clone()).set(rt.num_alive_tasks() as f64);
        gauge!(self.global_queue_depth.clone()).set(rt.global_queue_depth() as f64);
        let busy: Duration = (0..workers).map(|w| rt.worker_total_busy_duration(w)).sum();
        gauge!(self.busy_seconds.clone()).set(busy.as_secs_f64());
    }
}

/// Gauges for connection pools, named `<prefix>_db_pool_connections` (by `pool` and
/// `state`: `in_use`, `idle`) and `<prefix>_db_pool_max_connections` (by `pool`).
#[derive(Clone, Debug)]
pub struct PoolGauges {
    connections: String,
    max: String,
}

impl PoolGauges {
    /// Gauges with this prefix.
    #[must_use]
    pub fn prefixed(prefix: &str) -> Self {
        Self {
            connections: format!("{prefix}_db_pool_connections"),
            max: format!("{prefix}_db_pool_max_connections"),
        }
    }

    /// Describe the gauges.
    pub fn describe(&self) {
        metrics::describe_gauge!(
            self.connections.clone(),
            "Database connections by `pool` and `state` (in_use, idle)."
        );
        metrics::describe_gauge!(self.max.clone(), "Each pool's maximum size, by `pool`.");
    }

    /// Read `pool`'s numbers into the gauges, labelled `pool=name`.
    #[expect(clippy::cast_precision_loss, reason = "gauges are f64")]
    pub fn sample(&self, name: &'static str, pool: &sqlx::PgPool) {
        let (size, idle) = (f64::from(pool.size()), pool.num_idle() as f64);
        gauge!(self.connections.clone(), "pool" => name, "state" => "idle").set(idle);
        gauge!(self.connections.clone(), "pool" => name, "state" => "in_use").set(size - idle);
        gauge!(self.max.clone(), "pool" => name)
            .set(f64::from(pool.options().get_max_connections()));
    }
}

/// Serve `GET /metrics` on `listener` until the process ends. Each scrape first runs
/// `sample` (to refresh gauges that are read rather than counted) and the process
/// collector (CPU, memory, file descriptors).
///
/// # Panics
/// If [`install`] was never called.
pub async fn serve<F>(listener: tokio::net::TcpListener, sample: F) -> anyhow::Result<()>
where
    F: Fn() + Clone + Send + Sync + 'static,
{
    let handle = HANDLE
        .get()
        .expect("metrics::install runs before metrics::serve");
    let app = axum::Router::new().route(
        "/metrics",
        axum::routing::get(move || {
            let sample = sample.clone();
            async move {
                sample();
                metrics_process::Collector::default().collect();
                (
                    [(
                        axum::http::header::CONTENT_TYPE,
                        "text/plain; version=0.0.4",
                    )],
                    handle.render(),
                )
                    .into_response()
            }
        }),
    );
    tracing::info!(addr = %listener.local_addr()?, "metrics listening");
    // This port has no router or `Limits` in front to bound a slow client, so each
    // connection gets a lifetime (a scrape takes well under one), and few at once.
    // A scraper sends its request at once: a short head timeout frees a slot an idle
    // socket holds well inside a scrape's timeout (Prometheus waits 10 s).
    let options = crate::serve::ServeOptions {
        header_read_timeout: std::time::Duration::from_secs(3),
        max_connection_age: Some(std::time::Duration::from_secs(15)),
        max_connections: 64,
        ..crate::serve::ServeOptions::default()
    };
    crate::serve::run(listener, app, std::future::pending(), options).await;
    Ok(())
}

/// Bind `addr` and serve `/metrics` on it from a task of its own ([`serve`]), returning
/// the bound address (the port, when `addr` asked for 0) and the task, which runs until
/// the process ends. Binding happens here, so a port already taken fails the start
/// instead of the task; the task logs the address it listens on.
///
/// `addr` must name an interface: an unspecified address (`0.0.0.0`, `::`, and
/// `::ffff:0.0.0.0`, which binds every IPv4 interface) is refused with
/// [`InvalidInput`](std::io::ErrorKind::InvalidInput), so an address read from a default
/// or an unset variable cannot expose the endpoint on every interface. Pass
/// `127.0.0.1:port` to keep it on the host, or a pod's address to open it to the
/// scraper; [`spawn_listener_on_all_interfaces`] is the deliberate way to bind them all.
///
/// # Errors
/// The address is unspecified, or cannot be bound.
///
/// # Panics
/// If [`install`] was never called.
pub async fn spawn_listener<F>(
    addr: std::net::SocketAddr,
    sample: F,
) -> std::io::Result<(std::net::SocketAddr, tokio::task::JoinHandle<()>)>
where
    F: Fn() + Clone + Send + Sync + 'static,
{
    // `::ffff:0.0.0.0` binds every IPv4 interface too.
    if addr.ip().to_canonical().is_unspecified() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "the metrics listener was given {addr}, which is every interface: \
                 name one, or call spawn_listener_on_all_interfaces"
            ),
        ));
    }
    bind_and_spawn(addr, sample).await
}

/// [`spawn_listener`] on every IPv4 interface (`0.0.0.0`) at `port`: for a pod, whose
/// scraper reaches it by the pod's address and is admitted by a `NetworkPolicy` (the
/// `OpenShift` template's). Named for what it does, so no caller gets it by omission.
///
/// # Errors
/// The port cannot be bound.
///
/// # Panics
/// If [`install`] was never called.
pub async fn spawn_listener_on_all_interfaces<F>(
    port: u16,
    sample: F,
) -> std::io::Result<(std::net::SocketAddr, tokio::task::JoinHandle<()>)>
where
    F: Fn() + Clone + Send + Sync + 'static,
{
    bind_and_spawn((std::net::Ipv4Addr::UNSPECIFIED, port).into(), sample).await
}

async fn bind_and_spawn<F>(
    addr: std::net::SocketAddr,
    sample: F,
) -> std::io::Result<(std::net::SocketAddr, tokio::task::JoinHandle<()>)>
where
    F: Fn() + Clone + Send + Sync + 'static,
{
    assert!(
        HANDLE.get().is_some(),
        "metrics::install runs before the metrics listener is spawned"
    );
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let bound = listener.local_addr()?;
    let task = tokio::spawn(async move {
        if let Err(e) = serve(listener, sample).await {
            tracing::error!(error = %e, "the metrics listener stopped");
        }
    });
    Ok((bound, task))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn the_listener_serves_on_the_address_it_was_given() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        install(&[], || {});
        let sampled = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&sampled);
        let (addr, task) = spawn_listener("127.0.0.1:0".parse().unwrap(), move || {
            counter.fetch_add(1, Ordering::SeqCst);
        })
        .await
        .unwrap();
        assert!(addr.ip().is_loopback() && addr.port() != 0, "{addr}");
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(b"GET /metrics HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut out = String::new();
        stream.read_to_string(&mut out).await.unwrap();
        assert!(out.starts_with("HTTP/1.1 200"), "{out}");
        assert_eq!(sampled.load(Ordering::SeqCst), 1);
        task.abort();
    }

    #[tokio::test]
    async fn an_unspecified_address_is_refused_and_a_taken_port_fails_the_start() {
        install(&[], || {});
        for addr in ["0.0.0.0:0", "[::]:0", "[::ffff:0.0.0.0]:0"] {
            let refused = spawn_listener(addr.parse().unwrap(), || {})
                .await
                .unwrap_err();
            assert_eq!(refused.kind(), std::io::ErrorKind::InvalidInput, "{addr}");
        }
        let (taken, task) = spawn_listener("127.0.0.1:0".parse().unwrap(), || {})
            .await
            .unwrap();
        let clash = spawn_listener(taken, || {}).await.unwrap_err();
        assert_eq!(clash.kind(), std::io::ErrorKind::AddrInUse);
        task.abort();
    }

    /// Invented methods share one label value: a client cannot mint label sets.
    #[test]
    fn a_method_label_is_one_of_ten() {
        use axum::http::Method;
        let mut seen = std::collections::BTreeSet::new();
        for m in [
            "GET", "POST", "DELETE", "TRACE", "AAAA1", "AAAA2", "get", "PROPFIND",
        ] {
            seen.insert(method_label(&Method::from_bytes(m.as_bytes()).unwrap()));
        }
        assert_eq!(
            seen.into_iter().collect::<Vec<_>>(),
            ["DELETE", "GET", "POST", "TRACE", "other"]
        );
    }
}
