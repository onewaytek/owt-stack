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
/// path), `method` and `status`. Unmatched requests are `route="unmatched"`, so a scan
/// of random paths cannot grow the label set. Layer it on the routed router, so the
/// matched path is known.
pub async fn http(State(timer): State<HttpTimer>, req: Request, next: Next) -> Response {
    let route = req
        .extensions()
        .get::<MatchedPath>()
        .map_or_else(|| "unmatched".to_owned(), |p| p.as_str().to_owned());
    let method = req.method().as_str().to_owned();
    let started = Instant::now();
    let response = next.run(req).await;
    let status = response.status().as_u16().to_string();
    histogram!(timer.0, "route" => route, "method" => method, "status" => status)
        .record(started.elapsed().as_secs_f64());
    response
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
    axum::serve(listener, app).await?;
    Ok(())
}
