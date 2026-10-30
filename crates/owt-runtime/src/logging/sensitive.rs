//! [`Sensitive`]: a value that never prints.

use std::fmt;

/// The text every redacted value prints as.
pub(crate) const REDACTED: &str = "[redacted]";

/// A value that cannot reach a log or a panic message by accident.
///
/// `Debug` and `Display` both print `[redacted]`, whatever `T` is, so a derived
/// `Debug` on a struct that holds a `Sensitive` member redacts that member too. There
/// is no `Deref` and no `AsRef`: reading the value is an explicit
/// [`expose`](Self::expose) or [`into_inner`](Self::into_inner), which a reviewer can
/// search for.
///
/// `Deserialize` is transparent, so a configuration or form struct can hold a
/// `Sensitive<String>` and read it from the same input as a `String`. There is no
/// `Serialize`: writing `"[redacted]"` into a cache, a queue or a stored document
/// would corrupt the value without an error, so persisting one is a compile error and
/// the code that stores it calls `expose()` on purpose.
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Sensitive<T>(T);

impl<T> Sensitive<T> {
    /// Wrap `value`.
    pub fn new(value: T) -> Self {
        Self(value)
    }

    /// Borrow the value. Each call is a deliberate read.
    pub fn expose(&self) -> &T {
        &self.0
    }

    /// Unwrap the value.
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> From<T> for Sensitive<T> {
    fn from(value: T) -> Self {
        Self(value)
    }
}

impl<T> fmt::Debug for Sensitive<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

impl<T> fmt::Display for Sensitive<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

impl<'de, T: serde::Deserialize<'de>> serde::Deserialize<'de> for Sensitive<T> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        T::deserialize(deserializer).map(Self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn prints_redacted_for_any_type() {
        assert_eq!(format!("{:?}", Sensitive::new("hunter2")), "[redacted]");
        assert_eq!(format!("{}", Sensitive::new(42_u32)), "[redacted]");
        assert_eq!(format!("{:#?}", Sensitive::new(vec![1, 2])), "[redacted]");
    }

    #[test]
    fn derived_debug_redacts_the_field() {
        #[derive(Debug)]
        #[allow(dead_code)]
        struct Form {
            user: String,
            pass: Sensitive<String>,
        }
        let form = Form {
            user: "ann".into(),
            pass: "hunter2".to_string().into(),
        };
        assert_eq!(
            format!("{form:?}"),
            r#"Form { user: "ann", pass: [redacted] }"#
        );
    }

    #[test]
    fn explicit_reads_return_the_value() {
        let s = Sensitive::new(String::from("v"));
        assert_eq!(s.expose(), "v");
        assert_eq!(s.into_inner(), "v");
    }

    #[test]
    fn deserializes_transparently() {
        #[derive(serde::Deserialize)]
        struct Form {
            pass: Sensitive<String>,
        }
        let form: Form = serde_json::from_str(r#"{"pass":"hunter2"}"#).unwrap();
        assert_eq!(form.pass.expose(), "hunter2");
    }

    #[test]
    fn equality_and_hash_follow_the_value() {
        use std::collections::HashSet;
        let a = Sensitive::new(1);
        assert_eq!(a, Sensitive::new(1));
        assert_ne!(a, Sensitive::new(2));
        assert_eq!(HashSet::from([a, Sensitive::new(1)]).len(), 1);
    }

    proptest! {
        #[test]
        fn a_sensitive_string_never_prints_its_content(s in any::<String>()) {
            let v = Sensitive::new(s);
            prop_assert_eq!(format!("{v}"), "[redacted]");
            prop_assert_eq!(format!("{v:?}"), "[redacted]");
            prop_assert_eq!(format!("{v:#?}"), "[redacted]");
        }
    }
}
