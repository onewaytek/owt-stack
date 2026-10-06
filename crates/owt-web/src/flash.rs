//! Messages shown once, on the next page: "Saved.", "That name is taken."
//!
//! They live in the session (so they survive the redirect after a POST) and are taken
//! by the next full page that draws them. The app's session data holds a
//! `Vec<Flash>` and says where with [`HasFlashes`]; [`Session`] then gains
//! [`flash`](Session::flash) and [`take_flashes`](Session::take_flashes).
//!
//! The serialized shape is `["success", "Saved."]`, compact because it rides in the
//! session cookie.

use serde::{Deserialize, Serialize};

use crate::session::Session;

/// How a message should look.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    /// Something worked.
    Success,
    /// For information.
    Info,
    /// Worked, with a caveat.
    Warning,
    /// Something did not work.
    Error,
}

impl Level {
    /// Lower-case name, for CSS classes and ARIA roles in templates.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
        }
    }
}

/// One message.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Flash(pub Level, pub String);

impl Flash {
    /// Its level.
    #[must_use]
    pub fn level(&self) -> Level {
        self.0
    }

    /// Its text.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.1
    }
}

/// Session data that carries flash messages.
pub trait HasFlashes {
    /// The pending messages.
    fn flashes(&self) -> &[Flash];
    /// The pending messages, to change.
    fn flashes_mut(&mut self) -> &mut Vec<Flash>;
}

impl<T: HasFlashes + Default + Clone> Session<T> {
    /// Show `text` on the next page.
    pub fn flash(&self, level: Level, text: impl Into<String>) {
        self.update(|d| d.flashes_mut().push(Flash(level, text.into())));
    }

    /// The messages waiting, once. Taking none leaves the session unchanged, so a
    /// page with nothing to show sets no cookie.
    #[must_use]
    pub fn take_flashes(&self) -> Vec<Flash> {
        if self.read(|d| d.flashes().is_empty()) {
            return Vec::new();
        }
        self.update(|d| std::mem::take(d.flashes_mut()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Default)]
    struct Data {
        messages: Vec<Flash>,
    }

    impl HasFlashes for Data {
        fn flashes(&self) -> &[Flash] {
            &self.messages
        }
        fn flashes_mut(&mut self) -> &mut Vec<Flash> {
            &mut self.messages
        }
    }

    #[test]
    fn shown_once() {
        let s = Session::<Data>::default();
        assert_eq!(s.take_flashes(), []);
        assert!(!s.is_modified(), "nothing to take sets no cookie");
        s.flash(Level::Error, "No.");
        assert_eq!(s.take_flashes(), [Flash(Level::Error, "No.".into())]);
        assert_eq!(s.take_flashes(), []);
    }

    #[test]
    fn compact_on_the_wire() {
        let f = Flash(Level::Success, "Saved.".into());
        assert_eq!(
            serde_json::to_string(&f).unwrap(),
            r#"["success","Saved."]"#
        );
    }
}
