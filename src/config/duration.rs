use std::time::Duration;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DurationError {
    #[error("empty duration")]
    Empty,
    #[error("missing unit in duration")]
    MissingUnit,
    #[error("unknown unit {0:?} in duration")]
    UnknownUnit(String),
    #[error("invalid number in duration")]
    InvalidNumber,
    #[error("duration overflows")]
    Overflow,
}

/// Parses Go-style durations such as `24h`, `1m30s`, `500ms` or `0`.
pub fn parse_duration(input: &str) -> Result<Duration, DurationError> {
    let input = input.trim();
    if input.is_empty() {
        return Err(DurationError::Empty);
    }
    if input == "0" {
        return Ok(Duration::ZERO);
    }
    let mut total: u128 = 0;
    let mut rest = input;
    while !rest.is_empty() {
        let number_len = rest
            .find(|c: char| !(c.is_ascii_digit() || c == '.'))
            .ok_or(DurationError::MissingUnit)?;
        if number_len == 0 {
            return Err(DurationError::InvalidNumber);
        }
        let (number, tail) = rest.split_at(number_len);
        let unit_len = tail
            .find(|c: char| c.is_ascii_digit() || c == '.')
            .unwrap_or(tail.len());
        let (unit, tail) = tail.split_at(unit_len);
        let nanos_per_unit: u128 = match unit {
            "ns" => 1,
            "us" | "µs" | "μs" => 1_000,
            "ms" => 1_000_000,
            "s" => 1_000_000_000,
            "m" => 60_000_000_000,
            "h" => 3_600_000_000_000,
            other => return Err(DurationError::UnknownUnit(other.to_owned())),
        };
        total = total
            .checked_add(scale(number, nanos_per_unit)?)
            .ok_or(DurationError::Overflow)?;
        rest = tail;
    }
    let secs = u64::try_from(total / 1_000_000_000).map_err(|_| DurationError::Overflow)?;
    let nanos = u32::try_from(total % 1_000_000_000).map_err(|_| DurationError::Overflow)?;
    Ok(Duration::new(secs, nanos))
}

fn scale(number: &str, nanos_per_unit: u128) -> Result<u128, DurationError> {
    let (whole, fraction) = number.split_once('.').unwrap_or((number, ""));
    if whole.is_empty() && fraction.is_empty() {
        return Err(DurationError::InvalidNumber);
    }
    let whole: u128 = if whole.is_empty() {
        0
    } else {
        whole.parse().map_err(|_| DurationError::InvalidNumber)?
    };
    let mut value = whole
        .checked_mul(nanos_per_unit)
        .ok_or(DurationError::Overflow)?;
    let mut divisor: u128 = 1;
    for digit in fraction.chars() {
        let digit = u128::from(digit.to_digit(10).ok_or(DurationError::InvalidNumber)?);
        divisor = divisor.checked_mul(10).ok_or(DurationError::Overflow)?;
        value += digit * nanos_per_unit / divisor;
    }
    Ok(value)
}

pub fn format_duration(duration: Duration) -> String {
    let total = duration.as_secs();
    if total == 0 {
        return format!("{}ms", duration.as_millis());
    }
    let (hours, minutes, seconds) = (total / 3600, (total % 3600) / 60, total % 60);
    let mut out = String::new();
    if hours > 0 {
        out.push_str(&format!("{hours}h"));
    }
    if minutes > 0 {
        out.push_str(&format!("{minutes}m"));
    }
    if seconds > 0 || out.is_empty() {
        out.push_str(&format!("{seconds}s"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_go_durations() {
        assert_eq!(parse_duration("0"), Ok(Duration::ZERO));
        assert_eq!(parse_duration("24h"), Ok(Duration::from_secs(86_400)));
        assert_eq!(parse_duration("1m30s"), Ok(Duration::from_secs(90)));
        assert_eq!(parse_duration("500ms"), Ok(Duration::from_millis(500)));
        assert_eq!(parse_duration("1.5s"), Ok(Duration::from_millis(1500)));
        assert_eq!(parse_duration("25s"), Ok(Duration::from_secs(25)));
    }

    #[test]
    fn rejects_invalid() {
        assert_eq!(parse_duration(""), Err(DurationError::Empty));
        assert_eq!(parse_duration("10"), Err(DurationError::MissingUnit));
        assert!(matches!(
            parse_duration("10d"),
            Err(DurationError::UnknownUnit(_))
        ));
        assert_eq!(parse_duration("s"), Err(DurationError::InvalidNumber));
    }

    #[test]
    fn formats() {
        assert_eq!(format_duration(Duration::from_secs(3690)), "1h1m30s");
        assert_eq!(format_duration(Duration::from_millis(250)), "250ms");
    }
}
