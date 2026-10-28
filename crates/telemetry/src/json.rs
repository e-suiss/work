//! The redacting JSON log format (OP-18 rule 1, OP-19, T-39 rule 4): byte values and fields the
//! content guard forbids are written as [`REDACTED`], so a body or secret never reaches a log line
//! even when a layer runs without [`crate::ContentGuard`].

use std::fmt;

use serde_json::{Map, Value};
use tracing::field::{Field, Visit};
use tracing::{Event, Subscriber};
use tracing_subscriber::field::RecordFields;
use tracing_subscriber::fmt::format::{FormatEvent, FormatFields, Writer};
use tracing_subscriber::fmt::time::{FormatTime, SystemTime};
use tracing_subscriber::fmt::{FmtContext, FormattedFields};
use tracing_subscriber::registry::LookupSpan;

use crate::guard::forbidden_field;

/// The marker written in place of a redacted value.
pub const REDACTED: &str = "[redacted]";

#[derive(Default)]
struct Fields(Map<String, Value>);

impl Fields {
    fn put(&mut self, field: &Field, value: Value) {
        let value = if forbidden_field(field.name()).is_some() {
            Value::from(REDACTED)
        } else {
            value
        };
        self.0.insert(field.name().to_owned(), value);
    }
}

impl Visit for Fields {
    fn record_f64(&mut self, field: &Field, value: f64) {
        self.put(field, Value::from(value));
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.put(field, Value::from(value));
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.put(field, Value::from(value));
    }

    fn record_i128(&mut self, field: &Field, value: i128) {
        self.put(field, Value::from(value.to_string()));
    }

    fn record_u128(&mut self, field: &Field, value: u128) {
        self.put(field, Value::from(value.to_string()));
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.put(field, Value::from(value));
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.put(field, Value::from(value));
    }

    fn record_bytes(&mut self, field: &Field, _value: &[u8]) {
        self.put(field, Value::from(REDACTED));
    }

    fn record_error(&mut self, field: &Field, value: &(dyn std::error::Error + 'static)) {
        self.put(field, Value::from(value.to_string()));
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.put(field, Value::from(format!("{value:?}")));
    }
}

fn record<R: RecordFields>(fields: R) -> Map<String, Value> {
    let mut visitor = Fields::default();
    fields.record(&mut visitor);
    visitor.0
}

/// Span fields stored as a JSON object, with the same redaction as event fields.
#[derive(Clone, Copy, Debug, Default)]
pub struct RedactingFields;

impl<'writer> FormatFields<'writer> for RedactingFields {
    fn format_fields<R: RecordFields>(
        &self,
        mut writer: Writer<'writer>,
        fields: R,
    ) -> fmt::Result {
        write!(writer, "{}", Value::Object(record(fields)))
    }

    fn add_fields(
        &self,
        current: &'writer mut FormattedFields<Self>,
        fields: &tracing::span::Record<'_>,
    ) -> fmt::Result {
        let mut map: Map<String, Value> = serde_json::from_str(&current.fields).unwrap_or_default();
        map.extend(record(fields));
        current.fields = Value::Object(map).to_string();
        Ok(())
    }
}

/// One JSON object per event: `timestamp`, `level`, `target`, `fields` and the current `span`.
#[derive(Clone, Copy, Debug, Default)]
pub struct RedactingJson;

impl<S> FormatEvent<S, RedactingFields> for RedactingJson
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, RedactingFields>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        let mut timestamp = String::new();
        SystemTime.format_time(&mut Writer::new(&mut timestamp))?;
        let metadata = event.metadata();
        let mut line = Map::new();
        line.insert("timestamp".to_owned(), Value::from(timestamp));
        line.insert("level".to_owned(), Value::from(metadata.level().as_str()));
        line.insert("target".to_owned(), Value::from(metadata.target()));
        line.insert("fields".to_owned(), Value::Object(record(event)));
        if let Some(span) = ctx.lookup_current() {
            let mut fields: Map<String, Value> = span
                .extensions()
                .get::<FormattedFields<RedactingFields>>()
                .and_then(|f| serde_json::from_str(&f.fields).ok())
                .unwrap_or_default();
            fields.insert("name".to_owned(), Value::from(span.name()));
            line.insert("span".to_owned(), Value::Object(fields));
        }
        writeln!(writer, "{}", Value::Object(line))
    }
}
