use std::collections::HashMap;
use std::fmt::Display;
use std::path::Path;
use std::str::FromStr;
use std::time::Duration;

use super::ConfigError;
use super::duration::parse_duration;

#[derive(Clone, Debug, Default)]
pub struct Env {
    vars: HashMap<String, String>,
}

impl Env {
    pub fn from_process() -> Self {
        Self::from_pairs(std::env::vars())
    }

    pub fn from_pairs<I, K, V>(pairs: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        Self {
            vars: pairs
                .into_iter()
                .map(|(key, value)| (key.into(), value.into()))
                .collect(),
        }
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        let value = self.vars.get(key)?.trim();
        let value = strip_quotes(value);
        (!value.is_empty()).then_some(value)
    }

    pub fn get_first(&self, keys: &[&str]) -> Option<&str> {
        keys.iter().find_map(|key| self.get(key))
    }

    pub fn string(&self, keys: &[&str]) -> Option<String> {
        self.get_first(keys).map(str::to_owned)
    }

    pub fn lowercase(&self, keys: &[&str]) -> Option<String> {
        self.get_first(keys).map(str::to_lowercase)
    }

    pub fn bool(&self, keys: &[&str]) -> Result<Option<bool>, ConfigError> {
        let Some((key, value)) = self.first_pair(keys) else {
            return Ok(None);
        };
        parse_bool(value).map(Some).ok_or_else(|| {
            ConfigError::invalid(key, value, "expected on/off, yes/no or true/false")
        })
    }

    pub fn parse<T>(&self, keys: &[&str]) -> Result<Option<T>, ConfigError>
    where
        T: FromStr,
        T::Err: Display,
    {
        let Some((key, value)) = self.first_pair(keys) else {
            return Ok(None);
        };
        value
            .parse::<T>()
            .map(Some)
            .map_err(|err| ConfigError::invalid(key, value, err))
    }

    pub fn duration(&self, keys: &[&str]) -> Result<Option<Duration>, ConfigError> {
        let Some((key, value)) = self.first_pair(keys) else {
            return Ok(None);
        };
        parse_duration(value)
            .map(Some)
            .map_err(|err| ConfigError::invalid(key, value, err))
    }

    pub fn csv(&self, keys: &[&str]) -> Vec<String> {
        self.get_first(keys)
            .map(|value| {
                value
                    .split(',')
                    .map(str::trim)
                    .filter(|part| !part.is_empty())
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn csv_lowercase(&self, keys: &[&str]) -> Vec<String> {
        self.csv(keys)
            .into_iter()
            .map(|value| value.to_lowercase())
            .collect()
    }

    pub fn csv_parse<T>(&self, keys: &[&str]) -> Result<Vec<T>, ConfigError>
    where
        T: FromStr,
        T::Err: Display,
    {
        let key = keys.iter().find(|key| self.get(key).is_some()).copied();
        self.csv(keys)
            .into_iter()
            .map(|part| {
                part.parse::<T>()
                    .map_err(|err| ConfigError::invalid(key.unwrap_or_default(), &part, err))
            })
            .collect()
    }

    pub fn secret(
        &self,
        keys: &[&str],
        file_key: &str,
        default_file: &str,
    ) -> Result<Option<String>, ConfigError> {
        let path = self.get(file_key).unwrap_or(default_file);
        if let Some(content) = read_secret_file(Path::new(path))? {
            return Ok(Some(content));
        }
        Ok(self.string(keys))
    }

    fn first_pair<'a>(&'a self, keys: &[&'a str]) -> Option<(&'a str, &'a str)> {
        keys.iter()
            .find_map(|key| self.get(key).map(|value| (*key, value)))
    }
}

pub fn read_secret_file(path: &Path) -> Result<Option<String>, ConfigError> {
    match std::fs::read_to_string(path) {
        Ok(content) => {
            let trimmed = content.trim();
            Ok((!trimmed.is_empty()).then(|| trimmed.to_owned()))
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) if err.kind() == std::io::ErrorKind::IsADirectory => Ok(None),
        Err(source) => Err(ConfigError::ReadFile {
            path: path.to_path_buf(),
            source,
        }),
    }
}

pub fn parse_bool(value: &str) -> Option<bool> {
    match value.to_ascii_lowercase().as_str() {
        "on" | "yes" | "true" | "enabled" | "1" => Some(true),
        "off" | "no" | "false" | "disabled" | "0" => Some(false),
        _ => None,
    }
}

fn strip_quotes(value: &str) -> &str {
    for quote in ['"', '\''] {
        if let Some(inner) = value
            .strip_prefix(quote)
            .and_then(|rest| rest.strip_suffix(quote))
        {
            return inner.trim();
        }
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> Env {
        Env::from_pairs(pairs.iter().map(|(k, v)| (*k, *v)))
    }

    #[test]
    fn get_trims_and_strips_quotes() {
        let env = env(&[("A", "  \"value\" "), ("B", "''"), ("C", "   ")]);
        assert_eq!(env.get("A"), Some("value"));
        assert_eq!(env.get("B"), None);
        assert_eq!(env.get("C"), None);
    }

    #[test]
    fn retro_keys_take_first_set() {
        let env = env(&[("OLD", "old"), ("NEW", "new")]);
        assert_eq!(env.string(&["NEW", "OLD"]).as_deref(), Some("new"));
        assert_eq!(env.string(&["MISSING", "OLD"]).as_deref(), Some("old"));
    }

    #[test]
    fn bool_values() {
        let env = env(&[("A", "on"), ("B", "No"), ("C", "maybe")]);
        assert_eq!(env.bool(&["A"]).expect("valid"), Some(true));
        assert_eq!(env.bool(&["B"]).expect("valid"), Some(false));
        assert!(env.bool(&["C"]).is_err());
        assert_eq!(env.bool(&["D"]).expect("valid"), None);
    }

    #[test]
    fn csv_parse_values() {
        let env = env(&[("PORTS", "80, 443,,8080")]);
        let ports: Vec<u16> = env.csv_parse(&["PORTS"]).expect("valid");
        assert_eq!(ports, vec![80, 443, 8080]);
    }
}
