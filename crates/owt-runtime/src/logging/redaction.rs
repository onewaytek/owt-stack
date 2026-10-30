//! Field-name redaction for the subscriber's formatters and the OTLP exporter.
//!
//! A field whose name matches the denylist is recorded as `[redacted]`: the visitor
//! that formats a value replaces it before the value is formatted, so the original
//! never reaches a writer. The text formatter wraps tracing-subscriber's default
//! visitor. The JSON formatter is a streaming visitor and an event formatter of its
//! own, because tracing-subscriber's JSON event formatter serializes event fields
//! without consulting the configured field formatter. With feature `otel`, an
//! exporter wrapper applies the same matcher to span, event and link attributes
//! before they leave the process. Span names, event names and status descriptions are
//! exported as written, so they must never carry data.
//!
//! Only names are judged. A `Debug` or `Display` value is not inspected, so a struct
//! logged as one field prints all of its members and an error's message prints
//! whatever it contains.

use std::borrow::Cow;
use std::collections::HashSet;
use std::fmt::{self, Write as _};
use std::sync::Arc;

use serde_json::{Map, Value};
use tracing::field::{Field, Visit};
use tracing::{Event, Subscriber};
use tracing_log::NormalizeEvent;
use tracing_subscriber::field::{MakeVisitor, RecordFields, VisitOutput};
use tracing_subscriber::fmt::format::{DefaultFields, FormatEvent, FormatFields, Writer};
use tracing_subscriber::fmt::time::{FormatTime, SystemTime};
use tracing_subscriber::fmt::{FmtContext, FormattedFields};
use tracing_subscriber::registry::{LookupSpan, SpanRef};

use super::sensitive::REDACTED;

/// Normalized names redacted by default.
const DEFAULT_NAMES: &[&str] = &[
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "access_token",
    "refresh_token",
    "id_token",
    "authorization",
    "cookie",
    "set_cookie",
    "api_key",
    "apikey",
    "private_key",
    "ssn",
    "dob",
    "date_of_birth",
    "email",
    "phone",
    "address",
    "name",
    "first_name",
    "last_name",
    "diagnosis",
    "note",
    "notes",
    "content",
    "transcript",
    "mrn",
    "patient_name",
];

/// Key names redacted when they are the whole name or its last `_` segment.
const DEFAULT_KEYS: &[&str] = &[
    "api_key",
    "private_key",
    "secret_key",
    "access_key",
    "signing_key",
    "encryption_key",
];

/// Name endings redacted by default.
const DEFAULT_SUFFIXES: &[&str] = &["_secret", "_token", "_password"];

/// Name prefixes redacted by default.
const DEFAULT_PREFIXES: &[&str] = &["ssn", "authorization"];

/// `_`-separated words that redact a name wherever they appear in it, with trailing
/// digits ignored (`user_email`, `phone_number`, `password1`).
const DEFAULT_WORDS: &[&str] = &[
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "authorization",
    "cookie",
    "apikey",
    "ssn",
    "dob",
    "email",
    "phone",
    "address",
    "name",
    "diagnosis",
    "note",
    "notes",
    "transcript",
    "mrn",
];

/// Normalized names the defaults never redact: the attributes the tracing layers
/// write, OpenTelemetry's operational ones, and names the word rule would catch by
/// accident.
const DEFAULT_ALLOW: &[&str] = &[
    "thread_id",
    "thread_name",
    "target",
    "level",
    "message",
    "busy_ns",
    "idle_ns",
    "token_count",
    "max_tokens",
    "server_address",
    "host_name",
    "db_name",
    "service_name",
];

/// Dotted prefixes the defaults never redact (`code.module.name`, `otel.status_code`).
const DEFAULT_ALLOW_PREFIXES: &[&str] = &["code.", "otel."];

/// Decides which field names are redacted. The order of precedence is `allow`, then
/// `extra`, then the defaults' own allowlist, then the default rules.
#[derive(Clone, Debug)]
pub(crate) struct Redactor {
    extra: Arc<HashSet<String>>,
    allow: Arc<HashSet<String>>,
    defaults: bool,
}

impl Redactor {
    /// The default rules when `defaults`, plus the `extra` names, minus the `allow`
    /// names.
    pub(crate) fn new(defaults: bool, extra: &[String], allow: &[String]) -> Self {
        let set = |names: &[String]| -> Arc<HashSet<String>> {
            Arc::new(names.iter().map(|n| normalize(n).into_owned()).collect())
        };
        Self {
            extra: set(extra),
            allow: set(allow),
            defaults,
        }
    }

    /// Whether the value of the field called `name` is redacted. The whole name is
    /// judged, and each segment of a dotted one (`password.value`).
    pub(crate) fn denies(&self, name: &str) -> bool {
        let name = name.strip_prefix("r#").unwrap_or(name);
        let whole = normalize(name);
        if self.allow.contains(&*whole) {
            return false;
        }
        if self.extra.contains(&*whole) {
            return true;
        }
        if self.defaults
            && (DEFAULT_ALLOW.contains(&&*whole)
                || DEFAULT_ALLOW_PREFIXES.iter().any(|p| name.starts_with(p)))
        {
            return false;
        }
        self.judge(&whole)
            || (name.contains('.') && name.split('.').any(|s| self.judge(&normalize(s))))
    }

    /// Judges a normalized name against the rules.
    fn judge(&self, n: &str) -> bool {
        if self.extra.contains(n) {
            return true;
        }
        self.defaults
            && (DEFAULT_NAMES.contains(&n)
                || DEFAULT_SUFFIXES.iter().any(|s| n.ends_with(s))
                || DEFAULT_KEYS.iter().any(|k| {
                    n.strip_suffix(k)
                        .is_some_and(|p| p.is_empty() || p.ends_with('_'))
                })
                || DEFAULT_PREFIXES.iter().any(|p| n.starts_with(p))
                || n.split('_').any(|w| {
                    DEFAULT_WORDS.contains(&w.trim_end_matches(|c: char| c.is_ascii_digit()))
                }))
    }
}

/// Lowercase snake case: `accessToken`, `x-api-key` and `set cookie` become
/// `access_token`, `x_api_key` and `set_cookie`. A name already in that form is
/// borrowed.
fn normalize(name: &str) -> Cow<'_, str> {
    if name
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
    {
        return Cow::Borrowed(name);
    }
    let mut out = String::with_capacity(name.len() + 4);
    let mut prev: Option<char> = None;
    let mut chars = name.chars().peekable();
    while let Some(c) = chars.next() {
        if matches!(c, '-' | '.' | ' ') {
            out.push('_');
        } else if c.is_uppercase() {
            let boundary = prev.is_some_and(|p| {
                p.is_lowercase()
                    || p.is_ascii_digit()
                    || (p.is_uppercase() && chars.peek().is_some_and(|n| n.is_lowercase()))
            });
            if boundary {
                out.push('_');
            }
            out.extend(c.to_lowercase());
        } else {
            out.push(c);
        }
        prev = Some(c);
    }
    Cow::Owned(out)
}

/// A value whose `Debug` is the redaction marker, unquoted.
struct Marker;

impl fmt::Debug for Marker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

// === Text ===

/// The text formatter's field formatter: the default one, with denied values
/// replaced.
#[derive(Clone, Debug)]
pub(crate) struct RedactingFields {
    redactor: Redactor,
}

impl RedactingFields {
    pub(crate) fn new(redactor: Redactor) -> Self {
        Self { redactor }
    }
}

impl<'w> FormatFields<'w> for RedactingFields {
    fn format_fields<R: RecordFields>(&self, writer: Writer<'w>, fields: R) -> fmt::Result {
        let mut visitor = TextVisitor {
            inner: DefaultFields::new().make_visitor(writer),
            redactor: &self.redactor,
        };
        fields.record(&mut visitor);
        visitor.inner.finish()
    }
}

/// Forwards to the default visitor, with a denied field's value replaced by [`Marker`].
struct TextVisitor<'a, V> {
    inner: V,
    redactor: &'a Redactor,
}

impl<V: Visit> Visit for TextVisitor<'_, V> {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        if self.redactor.denies(field.name()) {
            self.inner.record_debug(field, &Marker);
        } else {
            self.inner.record_debug(field, value);
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        if self.redactor.denies(field.name()) {
            self.inner.record_debug(field, &Marker);
        } else {
            self.inner.record_str(field, value);
        }
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        if self.redactor.denies(field.name()) {
            self.inner.record_debug(field, &Marker);
        } else {
            self.inner.record_i64(field, value);
        }
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        if self.redactor.denies(field.name()) {
            self.inner.record_debug(field, &Marker);
        } else {
            self.inner.record_u64(field, value);
        }
    }

    fn record_f64(&mut self, field: &Field, value: f64) {
        if self.redactor.denies(field.name()) {
            self.inner.record_debug(field, &Marker);
        } else {
            self.inner.record_f64(field, value);
        }
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        if self.redactor.denies(field.name()) {
            self.inner.record_debug(field, &Marker);
        } else {
            self.inner.record_bool(field, value);
        }
    }

    fn record_error(&mut self, field: &Field, value: &(dyn std::error::Error + 'static)) {
        if self.redactor.denies(field.name()) {
            self.inner.record_debug(field, &Marker);
        } else {
            self.inner.record_error(field, value);
        }
    }
}

// === JSON ===

/// Appends `s` to `out` with JSON string escapes (no quotes).
fn escape(out: &mut String, s: &str) {
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
}

/// Appends `s` to `out` as a JSON string.
fn push_str(out: &mut String, s: &str) {
    out.push('"');
    escape(out, s);
    out.push('"');
}

/// A `fmt::Write` that JSON-escapes what it receives.
struct Escaper<'a>(&'a mut String);

impl fmt::Write for Escaper<'_> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        escape(self.0, s);
        Ok(())
    }
}

/// Appends `"name":value` pairs, comma-separated, to a string, denied values
/// replaced. The caller writes the braces.
struct JsonVisitor<'a> {
    out: &'a mut String,
    redactor: &'a Redactor,
    first: bool,
    /// Keeps the key `name` free for a span object's own name.
    rename_name: bool,
}

impl<'a> JsonVisitor<'a> {
    fn new(out: &'a mut String, redactor: &'a Redactor, rename_name: bool) -> Self {
        Self {
            out,
            redactor,
            first: true,
            rename_name,
        }
    }

    fn put(&mut self, field: &Field, value: impl FnOnce(&mut String)) {
        let raw = field.name();
        if raw.starts_with("log.") {
            return;
        }
        let name = raw.strip_prefix("r#").unwrap_or(raw);
        if !std::mem::take(&mut self.first) {
            self.out.push(',');
        }
        self.out.push('"');
        if self.rename_name && name == "name" {
            self.out.push_str("field.");
        }
        escape(self.out, name);
        self.out.push_str("\":");
        if self.redactor.denies(name) {
            push_str(self.out, REDACTED);
        } else {
            value(self.out);
        }
    }
}

impl Visit for JsonVisitor<'_> {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.put(field, |out| {
            out.push('"');
            let _ = write!(Escaper(out), "{value:?}");
            out.push('"');
        });
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.put(field, |out| push_str(out, value));
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.put(field, |out| {
            let _ = write!(out, "{value}");
        });
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.put(field, |out| {
            let _ = write!(out, "{value}");
        });
    }

    fn record_f64(&mut self, field: &Field, value: f64) {
        self.put(field, |out| {
            if value.is_finite() {
                let _ = write!(out, "{value}");
            } else {
                out.push_str("null");
            }
        });
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.put(field, |out| {
            out.push_str(if value { "true" } else { "false" });
        });
    }
}

/// The JSON formatter's field formatter. A span's fields are stored as one JSON
/// object, written once when the span is created. A later `record` parses it, adds
/// the new fields and writes it back.
#[derive(Clone, Debug)]
pub(crate) struct RedactingJsonFields {
    redactor: Redactor,
}

impl RedactingJsonFields {
    pub(crate) fn new(redactor: Redactor) -> Self {
        Self { redactor }
    }

    fn object(&self, fields: impl RecordFields) -> String {
        let mut out = String::from("{");
        fields.record(&mut JsonVisitor::new(&mut out, &self.redactor, true));
        out.push('}');
        out
    }
}

impl<'w> FormatFields<'w> for RedactingJsonFields {
    fn format_fields<R: RecordFields>(&self, mut writer: Writer<'w>, fields: R) -> fmt::Result {
        writer.write_str(&self.object(fields))
    }

    fn add_fields(
        &self,
        current: &'w mut FormattedFields<Self>,
        fields: &tracing::span::Record<'_>,
    ) -> fmt::Result {
        // A stored object that fails to parse is replaced rather than allowed to
        // drop the new fields; the formatter wrote it, so this does not happen.
        let mut map: Map<String, Value> = serde_json::from_str(current).unwrap_or_default();
        if let Ok(Value::Object(added)) = serde_json::from_str(&self.object(fields)) {
            map.extend(added);
        }
        current.fields = Value::Object(map).to_string();
        Ok(())
    }
}

/// One JSON object per event: `timestamp`, `level`, `fields`, `target`, then `span`
/// (the innermost) and `spans` (root first) when the event is inside a span. A
/// bridged `log` record carries its own target and level, as in tracing-subscriber's
/// JSON formatter.
#[derive(Clone, Debug)]
pub(crate) struct RedactingJsonEvent {
    redactor: Redactor,
}

impl RedactingJsonEvent {
    pub(crate) fn new(redactor: Redactor) -> Self {
        Self { redactor }
    }
}

/// Appends a span's stored fields with its `name`. The stored object is spliced in as
/// written, not parsed.
fn push_span<S: for<'a> LookupSpan<'a>>(out: &mut String, span: &SpanRef<'_, S>) {
    let ext = span.extensions();
    let stored = ext
        .get::<FormattedFields<RedactingJsonFields>>()
        .map_or("{}", |f| f.fields.as_str());
    match stored.strip_suffix('}') {
        Some(head) if head.starts_with('{') && head.len() > 1 => {
            out.push_str(head);
            out.push(',');
        }
        _ => out.push('{'),
    }
    out.push_str("\"name\":");
    push_str(out, span.name());
    out.push('}');
}

impl<S> FormatEvent<S, RedactingJsonFields> for RedactingJsonEvent
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, RedactingJsonFields>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        let normalized = event.normalized_metadata();
        let meta = normalized.as_ref().unwrap_or_else(|| event.metadata());
        let mut timestamp = String::new();
        SystemTime.format_time(&mut Writer::new(&mut timestamp))?;

        let mut out = String::with_capacity(256);
        out.push_str("{\"timestamp\":");
        push_str(&mut out, &timestamp);
        out.push_str(",\"level\":");
        push_str(&mut out, meta.level().as_str());
        out.push_str(",\"fields\":{");
        event.record(&mut JsonVisitor::new(&mut out, &self.redactor, false));
        out.push_str("},\"target\":");
        push_str(&mut out, meta.target());

        if let Some(scope) = ctx.event_scope() {
            let spans: Vec<_> = scope.collect();
            if let Some(innermost) = spans.first() {
                out.push_str(",\"span\":");
                push_span(&mut out, innermost);
                out.push_str(",\"spans\":[");
                for (i, span) in spans.iter().rev().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    push_span(&mut out, span);
                }
                out.push(']');
            }
        }
        out.push_str("}\n");
        writer.write_str(&out)
    }
}

// === OTLP ===

/// Wraps a span exporter and replaces the value of every span, event and link
/// attribute whose key matches, before the batch reaches the exporter. Span names,
/// event names (a tracing event's message) and status descriptions are exported as
/// written, like a message. The resource is not rewritten: it holds the service name
/// and what the SDK reads from `OTEL_RESOURCE_ATTRIBUTES`.
#[cfg(feature = "otel")]
#[derive(Debug)]
pub(crate) struct RedactingExporter<E> {
    inner: E,
    redactor: Redactor,
}

#[cfg(feature = "otel")]
impl<E> RedactingExporter<E> {
    pub(crate) fn new(inner: E, redactor: Redactor) -> Self {
        Self { inner, redactor }
    }

    fn redact(&self, attributes: &mut [opentelemetry::KeyValue]) {
        for kv in attributes {
            if self.redactor.denies(kv.key.as_str()) {
                kv.value = opentelemetry::Value::String(REDACTED.into());
            }
        }
    }
}

#[cfg(feature = "otel")]
impl<E: opentelemetry_sdk::trace::SpanExporter> opentelemetry_sdk::trace::SpanExporter
    for RedactingExporter<E>
{
    fn export(
        &self,
        mut batch: Vec<opentelemetry_sdk::trace::SpanData>,
    ) -> impl std::future::Future<Output = opentelemetry_sdk::error::OTelSdkResult> + Send {
        for span in &mut batch {
            self.redact(&mut span.attributes);
            for event in &mut span.events.events {
                self.redact(&mut event.attributes);
            }
            for link in &mut span.links.links {
                self.redact(&mut link.attributes);
            }
        }
        self.inner.export(batch)
    }

    fn shutdown_with_timeout(
        &self,
        timeout: std::time::Duration,
    ) -> opentelemetry_sdk::error::OTelSdkResult {
        self.inner.shutdown_with_timeout(timeout)
    }

    fn force_flush(&self) -> opentelemetry_sdk::error::OTelSdkResult {
        self.inner.force_flush()
    }

    fn set_resource(&mut self, resource: &opentelemetry_sdk::Resource) {
        self.inner.set_resource(resource);
    }
}
