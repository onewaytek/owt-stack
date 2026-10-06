//! Messages shown once, on the next page: "Saved.", "That name is taken."
//!
//! They live in the session (so they survive the redirect after a POST) and are taken
//! by the next full page that draws them. The app's session data holds a
//! `Vec<Flash>` and says where with [`HasFlashes`]; [`Session`] then gains
//! [`flash`](Session::flash) and [`take_flashes`](Session::take_flashes).
//!
//! The serialized shape is `["success", "Saved."]`, compact because it rides in the
//! session cookie. For the same reason the messages waiting are bounded: at most
//! [`MAX_PENDING`], the oldest dropped first, each at most [`MAX_CHARS`] long. A
//! browser drops a cookie over 4 KB without a word, and with it every later change
//! to the session, sign-out included, so messages that echo input (or pile up
//! behind htmx requests no full page follows) must not be able to grow it.
//!
//! Two requests from one browser at once can show a message twice: one takes it, and
//! the other, sealing the session it opened before that, puts it back. Sessions in a
//! cookie are last-write-wins.

use serde::{Deserialize, Serialize};

use crate::session::Session;

/// The most messages waiting at once.
pub const MAX_PENDING: usize = 5;

/// The longest message, in characters; a longer one is cut, ending in `…`.
pub const MAX_CHARS: usize = 300;

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
    /// Show `text` on the next page (within [`MAX_PENDING`] and [`MAX_CHARS`]).
    pub fn flash(&self, level: Level, text: impl Into<String>) {
        let mut text = text.into();
        if text.chars().count() > MAX_CHARS {
            let cut = text
                .char_indices()
                .nth(MAX_CHARS - 1)
                .map_or(text.len(), |(i, _)| i);
            text.truncate(cut);
            text.push('…');
        }
        self.update(|d| {
            let pending = d.flashes_mut();
            pending.push(Flash(level, text));
            let over = pending.len().saturating_sub(MAX_PENDING);
            pending.drain(..over);
        });
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
    fn pending_messages_are_bounded() {
        let s = Session::<Data>::default();
        for i in 0..MAX_PENDING + 3 {
            s.flash(Level::Info, i.to_string());
        }
        let taken = s.take_flashes();
        assert_eq!(taken.len(), MAX_PENDING);
        assert_eq!(taken[0].text(), "3", "the oldest are dropped");

        let exact = "é".repeat(MAX_CHARS);
        s.flash(Level::Info, exact.clone());
        s.flash(Level::Info, "é".repeat(MAX_CHARS + 1));
        let taken = s.take_flashes();
        assert_eq!(taken[0].text(), exact, "a message at the limit is whole");
        assert_eq!(taken[1].text().chars().count(), MAX_CHARS);
        assert!(taken[1].text().ends_with('…'));
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
