//! Logging, and (feature `otel`) trace export.
//!
//! Logs go to stderr: stdout belongs to what a command prints, which scripts read (a
//! slow-statement warning in the middle of `seed --json` breaks the JSON). Production
//! logs are JSON lines; development logs are human-readable. `RUST_LOG` overrides the
//! default filter.
//!
//! A field whose name matches a denylist (`password`, `token`, `email`, `name` and
//! others; see [`Options::redact_fields`]) is logged as `[redacted]` in both formats
//! and, with feature `otel`, in the exported span and event attributes. The defaults
//! are credentials and personal identifiers; a domain's vocabulary is the app's to add
//! through [`Options::redact_words`] ([`HEALTH_WORDS`] for health records).
//! [`Sensitive`] wraps a value that must never print.
//!
//! With JSON output, [`init`] also installs a panic hook that logs a panic's location
//! and thread as one `error` event and leaves out its payload: an `expect` message or
//! an unwrapped error's `Debug` can carry data, and the default hook writes it to
//! stderr, which is the log stream.
//!
//! Both are a safety net, and they judge names only:
//!
//! * A value interpolated into a message (`info!("saw {}", name)`) is not a field and
//!   is not caught. A bridged `log` record carries only a message, so it is not
//!   caught either.
//! * A `Debug` or `Display` value is not inspected. `info!(req = ?login)` prints every
//!   member of `login`, and an error's message prints whatever it contains (a unique
//!   violation names the duplicate value). Wrap struct members in [`Sensitive`], whose
//!   `Debug` stays redacted inside a derived one, and log an error's code or kind
//!   where data may appear in its message.
//! * With feature `otel`, span names, event names and status descriptions are
//!   exported as written, like a message.
//! * The list is a floor. A field named for something the list does not know is
//!   logged.
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

pub use redaction::HEALTH_WORDS;
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
    /// Field names to redact in addition to the defaults. A name is normalized
    /// before it is compared: `accessToken`, `Access-Token` and `access.token` all
    /// become `access_token`, and each segment of a dotted name is judged on its own
    /// (`password.value`). The defaults are the names `password`, `passwd`, `pwd`,
    /// `secret`, `token`, `access_token`, `refresh_token`, `id_token`, `authorization`,
    /// `cookie`, `set_cookie`, `api_key`, `apikey`, `private_key`, `ssn`, `dob`,
    /// `date_of_birth`, `email`, `phone`, `address`, `name`, `first_name`, `last_name`
    /// and `content`;
    /// a name ending `_secret`, `_token` or `_password`; a name that is, or ends in
    /// `_`, one of `api_key`, `private_key`, `secret_key`, `access_key`, `signing_key`
    /// and `encryption_key`; a name starting `ssn` or `authorization`; and a name with
    /// a `_`-separated word (trailing digits ignored) `password`, `passwd`, `pwd`,
    /// `secret`, `token`, `authorization`, `cookie`, `apikey`, `ssn`, `dob`, `email`,
    /// `phone`, `address` or `name`, so `user_email`, `phone_number` and `password1`
    /// are caught. Operational names the word rule would catch are listed in
    /// `redact_allow`.
    pub redact_fields: Vec<String>,
    /// `_`-separated words (trailing digits ignored) that redact a name wherever they
    /// appear in it, like the default words: the app's own vocabulary. It applies
    /// whether or not `redact_defaults` does. An app handling health records adds
    /// [`HEALTH_WORDS`] (`diagnosis`, `note`, `notes`, `transcript`, `mrn`), so
    /// `diagnosis_code` and `visit_notes` are caught.
    pub redact_words: Vec<String>,
    /// Whether the defaults apply. `false` redacts exactly `redact_fields`.
    pub redact_defaults: bool,
    /// Names that are never redacted, normalized like `redact_fields`; it wins over
    /// every other rule, and an allowed segment of a dotted name is not judged on its
    /// own. The defaults already pass the attributes the tracing layers write, by
    /// exact name (`code.filepath`, `code.lineno`, `code.module.name`, `otel.name`,
    /// `otel.kind`, `otel.status_code`, `thread.id`, `thread.name`, `target`, `level`,
    /// `message`) and a few operational names (`server.address`, `host.name`,
    /// `db.name`, `service.name`, `token_count`, `max_tokens`).
    pub redact_allow: Vec<String>,
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
            redact_words: Vec::new(),
            redact_defaults: true,
            redact_allow: Vec::new(),
        }
    }
}

/// The output layer: JSON lines or text, to `writer`, with `opts`' redaction. `None`
/// leaves colour to tracing-subscriber's default (on unless `NO_COLOR` is set).
fn fmt_layer<S, W>(opts: &Options, writer: W, ansi: Option<bool>) -> Box<dyn Layer<S> + Send + Sync>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    W: for<'w> MakeWriter<'w> + Send + Sync + 'static,
{
    let redactor = redactor(opts);
    if opts.json {
        fmt::layer()
            .fmt_fields(RedactingJsonFields::new(redactor.clone()))
            .event_format(RedactingJsonEvent::new(redactor))
            .with_writer(writer)
            .boxed()
    } else {
        let layer = fmt::layer()
            .fmt_fields(RedactingFields::new(redactor))
            .with_writer(writer);
        match ansi {
            Some(ansi) => layer.with_ansi(ansi).boxed(),
            None => layer.boxed(),
        }
    }
}

/// The matcher `opts` describes.
fn redactor(opts: &Options) -> Redactor {
    Redactor::new(
        opts.redact_defaults,
        &opts.redact_fields,
        &opts.redact_allow,
    )
    .words(&opts.redact_words)
}

/// Logs a panic as one `error` event naming its location and thread. The payload is
/// left out: it can carry data (an `expect` message, an unwrapped error's `Debug`).
fn log_panic(info: &std::panic::PanicHookInfo<'_>) {
    let location = info.location().map_or_else(
        || "unknown".to_owned(),
        |l| format!("{}:{}", l.file(), l.line()),
    );
    let thread = std::thread::current();
    tracing::error!(
        panic.location = %location,
        thread.name = thread.name().unwrap_or("unnamed"),
        "panic; payload not logged"
    );
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
    let fmt_layer = fmt_layer(opts, std::io::stderr, None);
    if opts.json {
        std::panic::set_hook(Box::new(log_panic));
    }

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
                    .with_batch_exporter(redaction::RedactingExporter::new(
                        exporter,
                        redactor(opts),
                    ))
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
        let subscriber =
            tracing_subscriber::registry().with(fmt_layer(opts, out.clone(), Some(false)));
        tracing::subscriber::with_default(subscriber, f);
        let bytes = out.0.lock().unwrap().clone();
        String::from_utf8(bytes).unwrap()
    }

    fn json(f: impl FnOnce()) -> serde_json::Value {
        let out = capture(
            &Options {
                json: true,
                ..Options::default()
            },
            f,
        );
        serde_json::from_str(out.trim_end()).unwrap_or_else(|e| panic!("{e}: {out}"))
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
                secret = true,
                address = ?vec!["12 Elm St"],
                content = %"free text",
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
    fn matcher_normalizes_names() {
        let r = redaction::Redactor::new(true, &[], &[]);
        for name in [
            "PASSWORD",
            "passwordHash",
            "accessToken",
            "refreshToken",
            "clientSecret",
            "privateKey",
            "x-api-key",
            "set-cookie",
            "Set Cookie",
            "pwd",
            "ssn_last4",
            "ssnLast4",
            "authorization_header",
            "db_password",
            "session_token",
            "secret_key",
            "stripe_secret_key",
            "user.email",
            "password.value",
            "secret.hint",
            "r#name",
            "APIKey",
            "user_email",
            "patient_email",
            "emailAddress",
            "phone_number",
            "full_name",
            "customer_name",
            "home_address",
            "patient_dob",
            "dob_year",
            "password1",
            "token2",
            "secret2",
            "access_token2",
            "thread.password",
            "thread.token",
            "user.name",
            "otel.secret",
            "otel.token",
            "otel.email",
            "code.password",
            "code.email",
            "private.key",
            "x.api.key",
            "x.access.key",
            "date.of.birth",
        ] {
            assert!(r.denies(name), "{name} should be denied");
        }
        for name in [
            "keyboard",
            "cache_key",
            "primary_key",
            "idempotency_key",
            "max_tokens",
            "token_count",
            "body",
            "user",
            "route",
            "thread.id",
            "thread.name",
            "status",
            "code.module.name",
            "code.filepath",
            "code.lineno",
            "code.namespace",
            "otel.name",
            "otel.status_code",
            "target",
            "level",
            "message",
            "server.address",
            "host.name",
            "db.name",
            "content_type",
            "x.cache.key",
        ] {
            assert!(!r.denies(name), "{name} should pass");
        }
    }

    #[test]
    fn health_words_are_the_apps_to_add() {
        let neutral = redaction::Redactor::new(true, &[], &[]);
        for name in ["diagnosis_code", "mrn_number", "visit_notes", "transcript"] {
            assert!(!neutral.denies(name), "{name} is not a default");
        }
        let words: Vec<String> = HEALTH_WORDS.iter().map(|w| (*w).to_owned()).collect();
        let health = redaction::Redactor::new(true, &[], &[]).words(&words);
        for name in [
            "diagnosis_code",
            "mrn_number",
            "visitNotes",
            "transcript2",
            "note",
        ] {
            assert!(health.denies(name), "{name} should be denied");
        }
        assert!(health.denies("password"), "the defaults still apply");
        let only = redaction::Redactor::new(false, &[], &[]).words(&words);
        assert!(only.denies("diagnosis") && !only.denies("password"));
        let allowed = redaction::Redactor::new(true, &[], &["note_count".into()]).words(&words);
        assert!(!allowed.denies("note_count"));
    }

    #[test]
    fn a_panic_logs_its_location_and_not_its_payload() {
        let out = capture(
            &Options {
                json: true,
                ..Options::default()
            },
            || {
                let previous = std::panic::take_hook();
                std::panic::set_hook(Box::new(log_panic));
                let caught = std::panic::catch_unwind(|| panic!("patient 4711"));
                std::panic::set_hook(previous);
                assert!(caught.is_err());
            },
        );
        assert!(!out.contains("4711"), "{out}");
        assert!(out.contains("logging.rs"), "{out}");
        assert!(out.contains("payload not logged"), "{out}");
    }

    #[test]
    fn allow_beats_every_rule_and_extra_beats_the_default_allowlist() {
        let allow = redaction::Redactor::new(true, &[], &["customer_name".into(), "Email".into()]);
        assert!(!allow.denies("customerName"));
        assert!(!allow.denies("email"));
        assert!(allow.denies("user_email"));
        assert!(
            !allow.denies("user.customer_name"),
            "an allowed segment is not judged alone"
        );

        let extra = redaction::Redactor::new(true, &["host_name".into()], &[]);
        assert!(extra.denies("host.name"));

        let none = redaction::Redactor::new(false, &["user_email".into()], &[]);
        assert!(none.denies("userEmail"));
        assert!(!none.denies("password"));
    }

    #[test]
    fn denied_names_are_redacted_in_events() {
        for (json, out) in both(|| {
            tracing::info!(
                PASSWORD = "v1",
                session_token = "v2",
                secret_key = "v3",
                db_password = "v4",
                clientSecret = "v5",
                user.email = "v6",
                passwordHash = "v7",
                password.value = "v8",
                keyboard = "shown",
                cache_key = "also_shown",
            );
        }) {
            for leaked in ["v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8"] {
                assert!(!out.contains(leaked), "json={json} leaked {leaked}: {out}");
            }
            assert!(out.contains("shown") && out.contains("also_shown"), "{out}");
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
        let v = json(|| {
            let span =
                tracing::info_span!("req", id = 7, password = "p", late = tracing::field::Empty);
            let _g = span.enter();
            span.record("late", "after");
            tracing::warn!(name = "n", ok = true, ratio = 0.5, "he said \"hi\"\n");
        });
        assert_eq!(v["level"], "WARN");
        assert_eq!(v["fields"]["message"], "he said \"hi\"\n");
        assert_eq!(v["fields"]["name"], "[redacted]");
        assert_eq!(v["fields"]["ok"], true);
        assert_eq!(v["fields"]["ratio"], 0.5);
        assert_eq!(v["span"]["name"], "req");
        assert_eq!(v["span"]["id"], 7);
        assert_eq!(v["span"]["late"], "after");
        assert_eq!(v["spans"][0]["password"], "[redacted]");
        assert!(v["timestamp"].is_string() && v["target"].is_string());
    }

    #[test]
    fn nested_spans_list_root_first() {
        let v = json(|| {
            let outer = tracing::info_span!("outer");
            let _o = outer.enter();
            let inner = tracing::info_span!("inner");
            let _i = inner.enter();
            tracing::info!("x");
        });
        assert_eq!(v["span"]["name"], "inner");
        assert_eq!(v["spans"][0]["name"], "outer");
        assert_eq!(v["spans"][1]["name"], "inner");
    }

    #[test]
    fn a_span_field_called_name_does_not_replace_the_span_name() {
        let opts = Options {
            json: true,
            redact_defaults: false,
            ..Options::default()
        };
        let out = capture(&opts, || {
            let span = tracing::info_span!("req", name = "kept");
            let _g = span.enter();
            tracing::info!("x");
        });
        let v: serde_json::Value = serde_json::from_str(out.trim_end()).unwrap();
        assert_eq!(v["span"]["name"], "req");
        assert_eq!(v["span"]["field.name"], "kept");
    }

    #[test]
    fn a_bridged_log_record_keeps_its_target_and_drops_log_fields() {
        let v = json(|| {
            use log::Log as _;
            tracing_log::LogTracer::new().log(
                &log::Record::builder()
                    .args(format_args!("select 1"))
                    .level(log::Level::Warn)
                    .target("sqlx::query")
                    .build(),
            );
        });
        assert_eq!(v["target"], "sqlx::query");
        assert_eq!(v["level"], "WARN");
        assert_eq!(v["fields"]["message"], "select 1");
        assert!(
            v["fields"]
                .as_object()
                .unwrap()
                .keys()
                .all(|k| !k.starts_with("log.")),
            "{v}"
        );
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
            tracing::info!(nickname = "nv1", password = "pv2", secret_key = "kv3");
        });
        assert!(
            !out.contains("nv1") && out.contains("pv2") && out.contains("kv3"),
            "{out}"
        );
    }

    /// The limits the module documentation states.
    #[test]
    fn values_are_not_inspected() {
        #[derive(Debug)]
        #[allow(dead_code)]
        struct Login {
            email: &'static str,
        }
        for (json, out) in both(|| {
            let name = "ann";
            tracing::info!("saw {name}");
            tracing::info!(req = ?Login { email: "member@example" });
            tracing::info!(error = "Key (email)=(dup@example) already exists");
        }) {
            assert!(out.contains("saw ann"), "json={json}: {out}");
            assert!(out.contains("member@example"), "json={json}: {out}");
            assert!(out.contains("dup@example"), "json={json}: {out}");
        }
    }

    #[cfg(feature = "otel")]
    #[test]
    fn exported_attributes_are_redacted() {
        use opentelemetry::KeyValue;
        use opentelemetry::trace::{
            SpanContext, SpanId, TraceFlags, TraceId, TraceState, TracerProvider as _,
        };
        use opentelemetry_sdk::trace::{InMemorySpanExporter, SdkTracerProvider};
        use tracing_opentelemetry::OpenTelemetrySpanExt as _;

        let memory = InMemorySpanExporter::default();
        let provider = SdkTracerProvider::builder()
            .with_batch_exporter(redaction::RedactingExporter::new(
                memory.clone(),
                Redactor::new(true, &["nickname".into()], &["route_name".into()]),
            ))
            .build();
        let subscriber = tracing_subscriber::registry()
            .with(tracing_opentelemetry::layer().with_tracer(provider.tracer("test")));
        tracing::subscriber::with_default(subscriber, || {
            let span = tracing::info_span!(
                "req",
                password = "p4ss",
                route = "/x",
                route_name = "kept",
                thread.password = "tp",
                late_token = tracing::field::Empty,
            );
            let _g = span.enter();
            span.record("late_token", "t0k");
            span.add_link_with_attributes(
                SpanContext::new(
                    TraceId::from(7_u128),
                    SpanId::from(7_u64),
                    TraceFlags::SAMPLED,
                    false,
                    TraceState::default(),
                ),
                vec![
                    KeyValue::new("email", "link@x"),
                    KeyValue::new("kind", "follows"),
                ],
            );
            tracing::info!(
                email = "e@x",
                nickname = "nick0",
                visible = "fine",
                "bad zed.msg"
            );
        });
        provider.force_flush().unwrap();
        let spans = memory.get_finished_spans().unwrap();
        let dump = format!("{spans:?}");
        for leaked in ["p4ss", "t0k", "e@x", "nick0", "\"tp\"", "link@x"] {
            assert!(!dump.contains(leaked), "leaked {leaked}: {dump}");
        }
        for kept in ["/x", "fine", "kept", "follows"] {
            assert!(dump.contains(kept), "lost {kept}: {dump}");
        }
        assert!(dump.contains("[redacted]"), "{dump}");

        // The layer's own attributes pass; `thread.password` is an application field.
        let span = &spans[0];
        let value = |key: &str| {
            span.attributes
                .iter()
                .find(|kv| kv.key.as_str() == key)
                .map(|kv| kv.value.to_string())
        };
        assert_ne!(value("thread.name").as_deref(), Some("[redacted]"));
        assert!(value("thread.id").is_some_and(|v| v != "[redacted]"));
        assert_eq!(value("thread.password").as_deref(), Some("[redacted]"));
        assert!(
            value("code.module.name").is_some_and(|v| v != "[redacted]"),
            "{dump}"
        );
        assert!(
            value("code.file.path").is_some_and(|v| v != "[redacted]"),
            "{dump}"
        );

        // Names are exported as written, like a message.
        assert!(dump.contains("bad zed.msg"), "{dump}");
    }
}
