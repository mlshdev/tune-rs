use std::fmt;
use std::time::SystemTime;

use serde_json::{Map, Value};
use tracing::field::{Field, Visit};
use tracing::{Event, Subscriber};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::{FmtContext, FormatEvent, FormatFields};
use tracing_subscriber::registry::LookupSpan;

const SERVICE: &str = "tune";

#[derive(Debug, thiserror::Error)]
pub enum LoggingError {
    #[error("invalid log level {level:?}: {source}")]
    Level {
        level: String,
        #[source]
        source: tracing_subscriber::filter::ParseError,
    },
    #[error("installing logger: {0}")]
    Install(String),
}

struct JsonFormat {
    environment: String,
}

#[derive(Default)]
struct FieldVisitor {
    message: String,
    fields: Map<String, Value>,
}

impl FieldVisitor {
    fn insert(&mut self, field: &Field, value: Value) {
        if field.name() == "message" {
            self.message = match value {
                Value::String(text) => text,
                other => other.to_string(),
            };
        } else {
            self.fields.insert(field.name().to_owned(), value);
        }
    }
}

impl Visit for FieldVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.insert(field, Value::from(value));
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.insert(field, Value::from(value));
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.insert(field, Value::from(value));
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.insert(field, Value::from(value));
    }

    fn record_f64(&mut self, field: &Field, value: f64) {
        self.insert(field, Value::from(value));
    }

    fn record_error(&mut self, field: &Field, value: &(dyn std::error::Error + 'static)) {
        self.insert(field, Value::from(value.to_string()));
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.insert(field, Value::from(format!("{value:?}")));
    }
}

impl<S, N> FormatEvent<S, N> for JsonFormat
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        _ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        let mut visitor = FieldVisitor::default();
        event.record(&mut visitor);
        let metadata = event.metadata();
        let mut object = Map::new();
        object.insert(
            "timestamp".into(),
            Value::from(rfc3339_utc(SystemTime::now())),
        );
        object.insert("severity".into(), Value::from(metadata.level().as_str()));
        object.insert("message".into(), Value::from(visitor.message));
        object.insert("service".into(), Value::from(SERVICE));
        object.insert("environment".into(), Value::from(self.environment.as_str()));
        object.insert("module".into(), Value::from(metadata.target()));
        for (key, value) in visitor.fields {
            object.entry(key).or_insert(value);
        }
        let line = serde_json::to_string(&Value::Object(object)).map_err(|_| fmt::Error)?;
        writeln!(writer, "{line}")
    }
}

pub fn init(level: &str, environment: &str) -> Result<(), LoggingError> {
    let directive = format!("{SERVICE}={level},warn");
    let filter = EnvFilter::try_new(&directive).map_err(|source| LoggingError::Level {
        level: level.to_owned(),
        source,
    })?;
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stdout)
        .event_format(JsonFormat {
            environment: environment.to_owned(),
        })
        .try_init()
        .map_err(|err| LoggingError::Install(err.to_string()))
}

fn rfc3339_utc(time: SystemTime) -> String {
    let since_epoch = time
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = since_epoch.as_secs();
    let millis = since_epoch.subsec_millis();
    let days = i64::try_from(secs / 86_400).unwrap_or(0);
    let rem = secs % 86_400;
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{millis:03}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = u32::try_from(doy - (153 * mp + 2) / 5 + 1).unwrap_or(1);
    let month = u32::try_from(if mp < 10 { mp + 3 } else { mp - 9 }).unwrap_or(1);
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn formats_timestamps() {
        assert_eq!(
            rfc3339_utc(SystemTime::UNIX_EPOCH),
            "1970-01-01T00:00:00.000Z"
        );
        let time = SystemTime::UNIX_EPOCH + Duration::from_millis(1_790_000_000_123);
        assert_eq!(rfc3339_utc(time), "2026-09-21T14:13:20.123Z");
        let leap = SystemTime::UNIX_EPOCH + Duration::from_secs(951_782_400);
        assert_eq!(rfc3339_utc(leap), "2000-02-29T00:00:00.000Z");
    }
}
