//! Logging, and (feature `otel`) trace export.
//!
//! Logs go to stderr: stdout belongs to what a command prints, which scripts read (a
//! slow-statement warning in the middle of `seed --json` breaks the JSON). Production
//! logs are JSON lines; development logs are human-readable. `RUST_LOG` overrides the
//! default filter.
//!
//! A field whose name is on a denylist (`password`, `token`, `email`, `name`, `note`
//! and others; see [`Options::redact_fields`]) is logged as `[redacted]` in both
//! formats, and [`Sensitive`] wraps a value that must never print. Both are a safety
//! net: a value interpolated into a message (`info!("saw {}", name)`) is not a field
//! and is not caught.
//!
//! With feature `otel`, spans are exported over OTLP gRPC when `otel_endpoint` is set
//! (the exporter itself reads the standard `OTEL_EXPORTER_OTLP_*` and
//! `OTEL_TRACES_SAMPLER*` variables).

mod redaction;
mod sensitive;

use tracing::Subscriber;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer, fmt};

pub use sensitive::Sensitive;

use redaction::{RedactingFields, RedactingJsonEvent, RedactingJsonFields, Redactor};

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
    /// Field names to redact in addition to the defaults, compared
    /// case-insensitively (a dotted name such as `user.email` is also judged by its
    /// last segment). The defaults are `password`, `passwd`, `secret`, `token`,
    /// `access_token`, `refresh_token`, `id_token`, `authorization`, `cookie`,
    /// `set_cookie`, `api_key`, `apikey`, `private_key`, `ssn`, `dob`, `date_of_birth`,
    /// `email`, `phone`, `address`, `name`, `first_name`, `last_name`, `diagnosis`,
    /// `note`, `notes`, `body`, `content`, `transcript`, `mrn` and `patient_name`, and
    /// any name ending in `_secret`, `_token`, `_password` or `_key`.
    pub redact_fields: Vec<String>,
    /// Whether the defaults apply. `false` redacts exactly `redact_fields`.
    pub redact_defaults: bool,
}

impl Default for Options {
    /// Human-readable logs at `info`, no export, the default redaction.
    fn default() -> Self {
        Self {
            service: "app",
            default_filter: "info".into(),
            json: false,
            otel_endpoint: None,
            redact_fields: Vec::new(),
            redact_defaults: true,
        }
    }
}

/// The output layer: JSON lines or text, to `writer`, with `opts`' redaction.
fn fmt_layer<S, W>(opts: &Options, writer: W, ansi: bool) -> Box<dyn Layer<S> + Send + Sync>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    W: for<'w> MakeWriter<'w> + Send + Sync + 'static,
{
    let redactor = Redactor::new(opts.redact_defaults, &opts.redact_fields);
    if opts.json {
        fmt::layer()
            .fmt_fields(RedactingJsonFields::new(redactor.clone()))
            .event_format(RedactingJsonEvent::new(redactor))
            .with_writer(writer)
            .boxed()
    } else {
        fmt::layer()
            .fmt_fields(RedactingFields::new(redactor))
            .with_ansi(ansi)
            .with_writer(writer)
            .boxed()
    }
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
    let fmt_layer = fmt_layer(opts, std::io::stderr, true);

    #[cfg(feature = "otel")]
    {
        use opentelemetry::trace::TracerProvider as _;
        let provider = opts.otel_endpoint.as_ref().and_then(|endpoint| {
            use opentelemetry_otlp::WithTonicConfig as _;
            use opentelemetry_otlp::tonic_types::transport::ClientTlsConfig;
            // An https collector is verified against the system's roots (where a
            // cluster's service CA is installed) and the public web's; without roots
            // the exporter's default TLS would trust nothing. Only an https one: TLS
            // configured for `http://` or `unix://` fails the exporter outright. An
            // image with no system bundle (scratch, distroless) falls back to the
            // public web's roots alone.
            let build = |tls: Option<ClientTlsConfig>| {
                use opentelemetry_otlp::WithExportConfig as _;
                // The endpoint whose scheme was checked, not one the exporter would
                // read from its own variables (a traces-only one, say).
                let builder = opentelemetry_otlp::SpanExporter::builder()
                    .with_tonic()
                    .with_endpoint(endpoint.clone());
                match tls {
                    Some(tls) => builder.with_tls_config(tls).build(),
                    None => builder.build(),
                }
            };
            let exporter = if endpoint.to_ascii_lowercase().starts_with("https://") {
                build(Some(ClientTlsConfig::new().with_enabled_roots())).or_else(|e| {
                    eprintln!(
                        "OTLP exporter for {endpoint}: {e}; trusting the public web's roots only"
                    );
                    build(Some(ClientTlsConfig::new().with_webpki_roots()))
                })
            } else {
                build(None)
            }
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

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;

    /// Collects everything a layer writes.
    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Capture {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for Capture {
        type Writer = Capture;
        fn make_writer(&'a self) -> Capture {
            self.clone()
        }
    }

    /// Runs `f` under a subscriber built from `opts` and returns what it wrote.
    fn capture(opts: &Options, f: impl FnOnce()) -> String {
        let out = Capture::default();
        let subscriber = tracing_subscriber::registry().with(fmt_layer(opts, out.clone(), false));
        tracing::subscriber::with_default(subscriber, f);
        let bytes = out.0.lock().unwrap().clone();
        String::from_utf8(bytes).unwrap()
    }

    fn both(f: impl Fn() + Copy) -> [(bool, String); 2] {
        [true, false].map(|json| {
            (
                json,
                capture(
                    &Options {
                        json,
                        ..Options::default()
                    },
                    f,
                ),
            )
        })
    }

    #[test]
    fn denied_event_fields_are_redacted_and_others_pass() {
        for (json, out) in both(|| {
            tracing::info!(password = "hunter2", user = "ann", count = 3, "login");
        }) {
            assert!(!out.contains("hunter2"), "json={json}: {out}");
            assert!(out.contains("[redacted]"), "json={json}: {out}");
            assert!(
                out.contains("ann") && out.contains("login") && out.contains('3'),
                "{out}"
            );
        }
    }

    #[test]
    fn every_value_type_is_redacted() {
        for (json, out) in both(|| {
            tracing::info!(
                email = "a@b.example",
                ssn = 123_456_789_u64,
                dob = -19_800_101_i64,
                phone = 5.55123,
                note = true,
                address = ?vec!["12 Elm St"],
                body = %"free text",
            );
        }) {
            for leaked in [
                "a@b.example",
                "123456789",
                "19800101",
                "5.55123",
                "Elm",
                "free text",
                "true",
            ] {
                assert!(!out.contains(leaked), "json={json} leaked {leaked}: {out}");
            }
        }
    }

    #[test]
    fn names_match_case_insensitively_by_suffix_and_by_last_segment() {
        for (json, out) in both(|| {
            tracing::info!(
                PASSWORD = "v1",
                session_token = "v2",
                stripe_key = "v3",
                db_password = "v4",
                client_secret = "v5",
                user.email = "v6",
                keyboard = "shown",
            );
        }) {
            for leaked in ["v1", "v2", "v3", "v4", "v5", "v6"] {
                assert!(!out.contains(leaked), "json={json} leaked {leaked}: {out}");
            }
            assert!(out.contains("shown"), "{out}");
        }
    }

    #[test]
    fn sensitive_prints_redacted_under_debug_and_display() {
        for (json, out) in both(|| {
            let s = Sensitive::new("hunter2".to_string());
            tracing::info!(cred = ?s, other = %s, "x");
        }) {
            assert!(!out.contains("hunter2"), "json={json}: {out}");
            assert_eq!(out.matches("[redacted]").count(), 2, "{out}");
        }
    }

    #[test]
    fn span_fields_and_later_records_are_redacted() {
        for (json, out) in both(|| {
            let span = tracing::info_span!(
                "req",
                token = "t0ken",
                route = "/x",
                late_secret = tracing::field::Empty,
                late_ok = tracing::field::Empty,
            );
            let _g = span.enter();
            span.record("late_secret", "s3cret");
            span.record("late_ok", "fine");
            tracing::info!("inside");
        }) {
            assert!(
                !out.contains("t0ken") && !out.contains("s3cret"),
                "json={json}: {out}"
            );
            assert!(out.contains("/x") && out.contains("fine"), "{out}");
            assert!(out.contains("[redacted]"), "{out}");
        }
    }

    #[test]
    fn json_output_is_valid_and_structured() {
        let out = capture(
            &Options {
                json: true,
                ..Options::default()
            },
            || {
                let span = tracing::info_span!("req", id = 7, password = "p");
                let _g = span.enter();
                tracing::warn!(name = "n", ok = true, "hello");
            },
        );
        let v: serde_json::Value = serde_json::from_str(out.trim_end()).unwrap();
        assert_eq!(v["level"], "WARN");
        assert_eq!(v["fields"]["message"], "hello");
        assert_eq!(v["fields"]["name"], "[redacted]");
        assert_eq!(v["fields"]["ok"], true);
        assert_eq!(v["span"]["name"], "req");
        assert_eq!(v["span"]["id"], 7);
        assert_eq!(v["spans"][0]["password"], "[redacted]");
        assert!(v["timestamp"].is_string() && v["target"].is_string());
    }

    #[test]
    fn extra_names_add_to_the_defaults_and_can_replace_them() {
        let extra = Options {
            redact_fields: vec!["Nickname".into()],
            ..Options::default()
        };
        let out = capture(&extra, || {
            tracing::info!(nickname = "nv1", password = "pv2");
        });
        assert!(!out.contains("nv1") && !out.contains("pv2"), "{out}");

        let only = Options {
            redact_fields: vec!["nickname".into()],
            redact_defaults: false,
            ..Options::default()
        };
        let out = capture(&only, || {
            tracing::info!(nickname = "nv1", password = "pv2", a_key = "kv3");
        });
        assert!(
            !out.contains("nv1") && out.contains("pv2") && out.contains("kv3"),
            "{out}"
        );
    }

    #[test]
    fn a_message_is_not_inspected() {
        let out = capture(&Options::default(), || {
            let name = "ann";
            tracing::info!("saw {name}");
        });
        assert!(out.contains("saw ann"), "{out}");
    }
}
