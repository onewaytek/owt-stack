//! Logging, and (feature `otel`) trace export.
//!
//! Logs go to stderr: stdout belongs to what a command prints, which scripts read (a
//! slow-statement warning in the middle of `seed --json` breaks the JSON). Production
//! logs are JSON lines; development logs are human-readable. `RUST_LOG` overrides the
//! default filter.
//!
//! With feature `otel`, spans are exported over OTLP gRPC when `otel_endpoint` is set
//! (the exporter itself reads the standard `OTEL_EXPORTER_OTLP_*` and
//! `OTEL_TRACES_SAMPLER*` variables).

use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer, fmt};

/// How to log.
#[derive(Clone, Debug)]
pub struct Options {
    /// The service name traces carry.
    pub service: &'static str,
    /// The filter when `RUST_LOG` is unset, e.g. `"app=info,tower_http=info"`.
    pub default_filter: String,
    /// JSON lines (production) rather than human-readable text.
    pub json: bool,
    /// Where to export traces; `None` exports nothing.
    pub otel_endpoint: Option<String>,
}

/// Keeps the trace exporter alive; dropping it flushes and shuts the exporter down.
/// Hold it in `main` for the life of the process.
#[must_use = "dropping the guard stops trace export"]
pub struct Guard {
    #[cfg(feature = "otel")]
    provider: Option<opentelemetry_sdk::trace::SdkTracerProvider>,
}

impl Drop for Guard {
    fn drop(&mut self) {
        #[cfg(feature = "otel")]
        if let Some(p) = self.provider.take() {
            let _ = p.shutdown();
        }
    }
}

/// Install the global subscriber. Call once, first thing in `main`; a second call
/// (or a test harness's own subscriber) leaves the first in place.
pub fn init(opts: &Options) -> Guard {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&opts.default_filter));
    let fmt_layer = if opts.json {
        fmt::layer().json().with_writer(std::io::stderr).boxed()
    } else {
        fmt::layer().with_writer(std::io::stderr).boxed()
    };

    #[cfg(feature = "otel")]
    {
        use opentelemetry::trace::TracerProvider as _;
        let provider = opts.otel_endpoint.as_ref().and_then(|endpoint| {
            let exporter = opentelemetry_otlp::SpanExporter::builder()
                .with_tonic()
                .build()
                .map_err(|e| eprintln!("OTLP exporter for {endpoint} failed: {e}"))
                .ok()?;
            Some(
                opentelemetry_sdk::trace::SdkTracerProvider::builder()
                    .with_batch_exporter(exporter)
                    .with_resource(
                        opentelemetry_sdk::Resource::builder()
                            .with_service_name(opts.service)
                            .build(),
                    )
                    .build(),
            )
        });
        let otel_layer = provider
            .as_ref()
            .map(|p| tracing_opentelemetry::layer().with_tracer(p.tracer(opts.service)));
        let _ = tracing_subscriber::registry()
            .with(filter)
            .with(fmt_layer)
            .with(otel_layer)
            .try_init();
        Guard { provider }
    }
    #[cfg(not(feature = "otel"))]
    {
        if opts.otel_endpoint.is_some() {
            eprintln!(
                "an OTLP endpoint is set but this build has no `otel` feature; not exporting"
            );
        }
        let _ = tracing_subscriber::registry()
            .with(filter)
            .with(fmt_layer)
            .try_init();
        Guard {}
    }
}
