//! Field-name redaction for the subscriber's formatters.
//!
//! A field whose name is on the denylist is recorded as `[redacted]`: the visitor
//! that formats a field's value replaces it before the value is formatted, so the
//! original never reaches a writer. The text formatter wraps tracing-subscriber's
//! default visitor; the JSON formatter is a visitor and an event formatter of its
//! own, because tracing-subscriber's JSON event formatter serializes event fields
//! without consulting the configured field formatter.

use std::collections::HashSet;
use std::fmt;
use std::sync::Arc;

use serde_json::{Map, Value};
use tracing::field::{Field, Visit};
use tracing::{Event, Subscriber};
use tracing_subscriber::field::{MakeVisitor, RecordFields, VisitOutput};
use tracing_subscriber::fmt::format::{DefaultFields, FormatEvent, FormatFields, Writer};
use tracing_subscriber::fmt::time::{FormatTime, SystemTime};
use tracing_subscriber::fmt::{FmtContext, FormattedFields};
use tracing_subscriber::registry::LookupSpan;

use super::sensitive::REDACTED;

/// Field names redacted by default, compared case-insensitively.
const DEFAULT_NAMES: &[&str] = &[
    "password",
    "passwd",
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
    "body",
    "content",
    "transcript",
    "mrn",
    "patient_name",
];

/// Name endings redacted by default, compared case-insensitively.
const DEFAULT_SUFFIXES: &[&str] = &["_secret", "_token", "_password", "_key"];

/// Decides which field names are redacted.
#[derive(Clone, Debug)]
pub(crate) struct Redactor {
    names: Arc<HashSet<String>>,
    suffixes: bool,
}

impl Redactor {
    /// The default names and suffixes when `defaults`, plus `extra` names.
    pub(crate) fn new(defaults: bool, extra: &[String]) -> Self {
        let mut names: HashSet<String> = extra.iter().map(|n| n.to_ascii_lowercase()).collect();
        if defaults {
            names.extend(DEFAULT_NAMES.iter().map(|n| (*n).to_owned()));
        }
        Self {
            names: Arc::new(names),
            suffixes: defaults,
        }
    }

    /// Whether the value of the field called `name` is redacted. A dotted name
    /// (`user.email`) is judged by its last segment as well as whole.
    pub(crate) fn denies(&self, name: &str) -> bool {
        let name = name.strip_prefix("r#").unwrap_or(name).to_ascii_lowercase();
        self.denies_exact(&name)
            || name
                .rsplit('.')
                .next()
                .is_some_and(|s| self.denies_exact(s))
    }

    fn denies_exact(&self, name: &str) -> bool {
        self.names.contains(name)
            || (self.suffixes && DEFAULT_SUFFIXES.iter().any(|s| name.ends_with(s)))
    }
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

/// Collects fields into a JSON object, denied values replaced.
struct JsonVisitor<'a> {
    map: &'a mut Map<String, Value>,
    redactor: &'a Redactor,
}

impl JsonVisitor<'_> {
    fn put(&mut self, field: &Field, value: impl FnOnce() -> Value) {
        let name = field.name();
        let value = if self.redactor.denies(name) {
            Value::from(REDACTED)
        } else {
            value()
        };
        self.map
            .insert(name.strip_prefix("r#").unwrap_or(name).to_owned(), value);
    }
}

impl Visit for JsonVisitor<'_> {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.put(field, || Value::from(format!("{value:?}")));
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.put(field, || Value::from(value));
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.put(field, || Value::from(value));
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.put(field, || Value::from(value));
    }

    fn record_f64(&mut self, field: &Field, value: f64) {
        self.put(field, || Value::from(value));
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.put(field, || Value::from(value));
    }
}

/// The JSON formatter's field formatter. A span's fields are stored as one JSON
/// object; a later `record` parses it, adds the new fields and writes it back.
#[derive(Clone, Debug)]
pub(crate) struct RedactingJsonFields {
    redactor: Redactor,
}

impl RedactingJsonFields {
    pub(crate) fn new(redactor: Redactor) -> Self {
        Self { redactor }
    }

    fn write(&self, mut map: Map<String, Value>, fields: impl RecordFields) -> String {
        fields.record(&mut JsonVisitor {
            map: &mut map,
            redactor: &self.redactor,
        });
        Value::Object(map).to_string()
    }
}

impl<'w> FormatFields<'w> for RedactingJsonFields {
    fn format_fields<R: RecordFields>(&self, mut writer: Writer<'w>, fields: R) -> fmt::Result {
        let json = self.write(Map::new(), fields);
        fmt::Write::write_str(&mut writer, &json)
    }

    fn add_fields(
        &self,
        current: &'w mut FormattedFields<Self>,
        fields: &tracing::span::Record<'_>,
    ) -> fmt::Result {
        let map = if current.is_empty() {
            Map::new()
        } else {
            serde_json::from_str(current).map_err(|_| fmt::Error)?
        };
        current.fields = self.write(map, fields);
        Ok(())
    }
}

/// One JSON object per event: `timestamp`, `level`, `fields`, `target`, then `span`
/// (the innermost) and `spans` (root first) when the event is inside a span.
#[derive(Clone, Debug)]
pub(crate) struct RedactingJsonEvent {
    redactor: Redactor,
}

impl RedactingJsonEvent {
    pub(crate) fn new(redactor: Redactor) -> Self {
        Self { redactor }
    }
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
        let meta = event.metadata();
        let mut timestamp = String::new();
        SystemTime.format_time(&mut Writer::new(&mut timestamp))?;

        let mut fields = Map::new();
        event.record(&mut JsonVisitor {
            map: &mut fields,
            redactor: &self.redactor,
        });

        let mut out = Map::new();
        out.insert("timestamp".into(), timestamp.into());
        out.insert("level".into(), meta.level().as_str().into());
        out.insert("fields".into(), Value::Object(fields));
        out.insert("target".into(), meta.target().into());

        if let Some(scope) = ctx.event_scope() {
            let mut spans: Vec<Value> = scope
                .map(|span| {
                    let mut object = span
                        .extensions()
                        .get::<FormattedFields<RedactingJsonFields>>()
                        .and_then(|f| serde_json::from_str::<Map<String, Value>>(f).ok())
                        .unwrap_or_default();
                    object.insert("name".into(), span.name().into());
                    Value::Object(object)
                })
                .collect();
            if let Some(innermost) = spans.first().cloned() {
                out.insert("span".into(), innermost);
                spans.reverse();
                out.insert("spans".into(), Value::Array(spans));
            }
        }

        fmt::Write::write_str(&mut writer, &Value::Object(out).to_string())?;
        fmt::Write::write_char(&mut writer, '\n')
    }
}
