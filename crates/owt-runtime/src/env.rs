//! Configuration from the environment.
//!
//! An empty or all-blank variable counts as unset, so a manifest can clear one with
//! `VALUE: ""`. A variable that is set and does not parse is an error naming it, and
//! not quoting it: the error is logged, and the variable may be a secret.
//!
//! The free functions read the process environment; [`Vars`] reads any map, which is
//! how tests (and config built for a test) avoid mutating the process's.

use std::collections::HashMap;
use std::str::FromStr;
use std::time::Duration;

use anyhow::Context;

/// Where variables come from.
#[derive(Clone, Debug, Default)]
pub enum Vars {
    /// The process environment.
    #[default]
    Process,
    /// A fixed map.
    Map(HashMap<String, String>),
}

impl<K: Into<String>, V: Into<String>> FromIterator<(K, V)> for Vars {
    fn from_iter<I: IntoIterator<Item = (K, V)>>(iter: I) -> Self {
        Self::Map(
            iter.into_iter()
                .map(|(k, v)| (k.into(), v.into()))
                .collect(),
        )
    }
}

impl Vars {
    /// The variable's trimmed value, if it is set and not blank.
    #[must_use]
    pub fn var(&self, name: &str) -> Option<String> {
        let raw = match self {
            Self::Process => std::env::var(name).ok(),
            Self::Map(m) => m.get(name).cloned(),
        };
        raw.map(|v| v.trim().to_owned()).filter(|v| !v.is_empty())
    }

    /// The variable's value; an error naming it if unset.
    pub fn required(&self, name: &str) -> anyhow::Result<String> {
        self.var(name)
            .with_context(|| format!("{name} must be set"))
    }

    /// The variable parsed, if set.
    pub fn parse<T>(&self, name: &str) -> anyhow::Result<Option<T>>
    where
        T: FromStr,
        T::Err: std::fmt::Display,
    {
        self.var(name)
            .map(|v| {
                v.parse::<T>()
                    .map_err(|e| anyhow::anyhow!("{name} does not parse: {e}"))
            })
            .transpose()
    }

    /// The variable parsed, or `default` if unset.
    pub fn parse_or<T>(&self, name: &str, default: T) -> anyhow::Result<T>
    where
        T: FromStr,
        T::Err: std::fmt::Display,
    {
        Ok(self.parse(name)?.unwrap_or(default))
    }

    /// A boolean: `1`/`true`/`yes`/`on` or `0`/`false`/`no`/`off` (any case);
    /// `default` if unset.
    pub fn flag(&self, name: &str, default: bool) -> anyhow::Result<bool> {
        match self.var(name).map(|v| v.to_ascii_lowercase()).as_deref() {
            None => Ok(default),
            Some("1" | "true" | "yes" | "on") => Ok(true),
            Some("0" | "false" | "no" | "off") => Ok(false),
            Some(_) => anyhow::bail!("{name} is not a boolean"),
        }
    }

    /// A comma-separated list, blanks dropped; empty if unset.
    #[must_use]
    pub fn list(&self, name: &str) -> Vec<String> {
        self.var(name)
            .map(|v| {
                v.split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Whole seconds (`30`, `30s`) or milliseconds (`250ms`); `default` if unset.
    pub fn duration(&self, name: &str, default: Duration) -> anyhow::Result<Duration> {
        let Some(v) = self.var(name) else {
            return Ok(default);
        };
        let parsed = match v.strip_suffix("ms") {
            Some(ms) => ms.trim().parse::<u64>().map(Duration::from_millis),
            None => v
                .strip_suffix('s')
                .unwrap_or(&v)
                .trim()
                .parse::<u64>()
                .map(Duration::from_secs),
        };
        parsed.map_err(|e| anyhow::anyhow!("{name} is not a duration: {e}"))
    }
}

/// [`Vars::var`] on the process environment.
#[must_use]
pub fn var(name: &str) -> Option<String> {
    Vars::Process.var(name)
}

/// [`Vars::required`] on the process environment.
pub fn required(name: &str) -> anyhow::Result<String> {
    Vars::Process.required(name)
}

/// [`Vars::parse`] on the process environment.
pub fn parse<T>(name: &str) -> anyhow::Result<Option<T>>
where
    T: FromStr,
    T::Err: std::fmt::Display,
{
    Vars::Process.parse(name)
}

/// [`Vars::parse_or`] on the process environment.
pub fn parse_or<T>(name: &str, default: T) -> anyhow::Result<T>
where
    T: FromStr,
    T::Err: std::fmt::Display,
{
    Vars::Process.parse_or(name, default)
}

/// [`Vars::flag`] on the process environment.
pub fn flag(name: &str, default: bool) -> anyhow::Result<bool> {
    Vars::Process.flag(name, default)
}

/// [`Vars::list`] on the process environment.
#[must_use]
pub fn list(name: &str) -> Vec<String> {
    Vars::Process.list(name)
}

/// [`Vars::duration`] on the process environment.
pub fn duration(name: &str, default: Duration) -> anyhow::Result<Duration> {
    Vars::Process.duration(name, default)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blank_is_unset_and_garbage_is_an_error() {
        let v: Vars = [("BLANK", "  "), ("BAD", "x9")].into_iter().collect();
        assert_eq!(v.var("BLANK"), None);
        assert_eq!(v.parse_or::<u32>("BLANK", 4).unwrap(), 4);
        let e = v.parse::<u32>("BAD").unwrap_err().to_string();
        assert!(e.contains("BAD") && !e.contains("x9"), "{e}");
        assert!(
            v.required("MISSING")
                .unwrap_err()
                .to_string()
                .contains("MISSING")
        );
    }

    #[test]
    fn flags_lists_durations() {
        let v: Vars = [
            ("F", "Yes"),
            ("F2", "maybe"),
            ("L", "a, b,,c "),
            ("D1", "250ms"),
            ("D2", "30s"),
        ]
        .into_iter()
        .collect();
        assert!(v.flag("F", false).unwrap());
        assert!(v.flag("F2", false).is_err());
        assert!(!v.flag("NONE", false).unwrap());
        assert_eq!(v.list("L"), ["a", "b", "c"]);
        assert_eq!(
            v.duration("D1", Duration::ZERO).unwrap(),
            Duration::from_millis(250)
        );
        assert_eq!(
            v.duration("D2", Duration::ZERO).unwrap(),
            Duration::from_secs(30)
        );
    }
}
