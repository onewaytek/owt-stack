//! Messages shown once, on the next page: "Saved.", "That name is taken."
//!
//! They live in the session (so they survive the redirect after a POST) and are taken
//! by the next full page that draws them. The app's session data holds a
//! `Vec<Flash>` and says where with [`HasFlashes`]; [`Session`] then gains
//! [`flash`](Session::flash) and [`take_flashes`](Session::take_flashes).
//!
//! The serialized shape is `["success", "Saved."]`, compact because it rides in the
//! session cookie. For the same reason the messages waiting are bounded: at most
//! [`MAX_PENDING`], the oldest dropped first, each at most [`MAX_CHARS`] long and
//! [`MAX_BYTES`] as serialized. A browser drops a cookie over 4 KB without a word,
//! and with it every later change to the session, sign-out included, so messages
//! that echo input (or pile up behind htmx requests no full page follows) must not
//! be able to grow it. The bound is in bytes as well as characters because the
//! cookie is: a character is up to four bytes, and six once JSON escapes it.
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

/// The longest message, in bytes of its JSON string; a longer one is cut, ending in
/// `…`. With [`MAX_PENDING`] waiting, that is about 2.8 KB of sealed cookie.
pub const MAX_BYTES: usize = 400;

/// The bytes `c` takes inside a JSON string, as `serde_json` writes it.
fn json_len(c: char) -> usize {
    match c {
        '"' | '\\' | '\n' | '\r' | '\t' | '\u{8}' | '\u{c}' => 2,
        c if c < ' ' => 6,
        c => c.len_utf8(),
    }
}

/// `text` within [`MAX_CHARS`] and [`MAX_BYTES`], cut and ended with `…` if it was not.
fn bounded(mut text: String) -> String {
    const ELLIPSIS: char = '…';
    let (mut chars, mut bytes) = (0, 0);
    // Where to cut so that the ellipsis still fits, if a cut turns out to be needed.
    let mut cut = 0;
    for (i, c) in text.char_indices() {
        chars += 1;
        bytes += json_len(c);
        if chars > MAX_CHARS || bytes > MAX_BYTES {
            text.truncate(cut);
            text.push(ELLIPSIS);
            return text;
        }
        if chars < MAX_CHARS && bytes + ELLIPSIS.len_utf8() <= MAX_BYTES {
            cut = i + c.len_utf8();
        }
    }
    text
}

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
    /// Show `text` on the next page (within [`MAX_PENDING`], [`MAX_CHARS`] and
    /// [`MAX_BYTES`]).
    pub fn flash(&self, level: Level, text: impl Into<String>) {
        let text = bounded(text.into());
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

        let exact = "e".repeat(MAX_CHARS);
        s.flash(Level::Info, exact.clone());
        s.flash(Level::Info, "e".repeat(MAX_CHARS + 1));
        let taken = s.take_flashes();
        assert_eq!(taken[0].text(), exact, "a message at the limit is whole");
        assert_eq!(taken[1].text().chars().count(), MAX_CHARS);
        assert!(taken[1].text().ends_with('…'));

        // Bytes bind before characters when the characters are wide or escaped.
        let exact = "é".repeat(MAX_BYTES / 2);
        assert_eq!(bounded(exact.clone()), exact);
        for (filler, each) in [("é", 2), ("漢", 3), ("\"", 2), ("\u{1}", 6), ("😀", 4)] {
            let cut = bounded(filler.repeat(MAX_BYTES));
            assert!(cut.ends_with('…'), "{filler:?}");
            let json = serde_json::to_string(&cut).unwrap();
            assert!(
                json.len() - 2 <= MAX_BYTES,
                "{filler:?}: {}",
                json.len() - 2
            );
            assert!(
                json.len() - 2 > MAX_BYTES - each - 3,
                "{filler:?} cut too soon"
            );
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

    #[test]
    fn the_most_that_can_wait_fits_a_cookie() {
        use crate::session::Sessions;
        #[derive(Clone, Default, Serialize, Deserialize)]
        struct Wire {
            #[serde(default)]
            m: Vec<Flash>,
        }
        impl HasFlashes for Wire {
            fn flashes(&self) -> &[Flash] {
                &self.m
            }
            fn flashes_mut(&mut self) -> &mut Vec<Flash> {
                &mut self.m
            }
        }
        let sessions = Sessions::<Wire>::new(
            cookie::Key::generate(),
            "__Host-session",
            std::time::Duration::from_secs(3600),
            true,
        );
        // Three-byte characters, quotes (two bytes in JSON) and control characters
        // (six): what a message echoing hostile input could hold.
        for filler in ["漢", "\"", "\u{1}"] {
            let s = Session::<Wire>::default();
            for _ in 0..=MAX_PENDING {
                s.flash(Level::Warning, filler.repeat(MAX_CHARS * 2));
            }
            let sealed = sessions.seal("abcdefghijklmnopqrstuvwxyz012345", &s.read(Clone::clone));
            assert!(
                sealed.len() < 3000,
                "{} bytes sealed with {filler:?}",
                sealed.len()
            );
        }
    }

    #[test]
    fn plain_text_at_the_character_limit_is_not_cut_for_bytes() {
        // A space is one byte in JSON, not an escaped control character.
        for filler in [" ", "a", "~", "'"] {
            let exact = filler.repeat(MAX_CHARS);
            assert_eq!(bounded(exact.clone()), exact, "{filler:?}");
        }
        assert_eq!(json_len(' '), 1);
        assert_eq!(json_len('\u{1f}'), 6);
        assert_eq!(json_len('\n'), 2);
        // The table agrees with serde_json for every character it could meet.
        for c in (0..=0x2100u32)
            .filter_map(char::from_u32)
            .chain(['😀', '\u{10ffff}'])
        {
            let json = serde_json::to_string(&c.to_string()).unwrap();
            assert_eq!(json_len(c), json.len() - 2, "{c:?}");
        }
    }
}
