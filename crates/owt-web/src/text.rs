//! Text as pages show it: slugs, word truncation, plain text made into paragraphs,
//! moments and counts in words, and a `LIKE` pattern's literal text.
//!
//! A moment is a [`SystemTime`], the one date type the standard library has: a
//! `time::OffsetDateTime` or a `chrono::DateTime<Utc>` converts with `.into()`. Every
//! rendering is in UTC and rounds down, so the same moment reads the same on every page.
//!
//! The functions take their moment and count by value or by reference, so they are
//! callable from Askama by path (which passes references):
//!
//! ```
//! use std::time::SystemTime;
//! use askama::Template;
//! use owt_web::text::{self, Words};
//!
//! #[derive(Template)]
//! #[template(ext = "html", source = r#"
//! <time>{{ owt_web::text::utc_minute(self.at) }}</time>
//! {{ self.n }} {{ owt_web::text::plural(self.n, "game", "games") }}"#)]
//! struct Row { at: SystemTime, n: u64 }
//! # let row = Row { at: SystemTime::UNIX_EPOCH, n: 2 };
//! # assert!(row.render().unwrap().contains("1970-01-01 00:00 UTC"));
//! ```

use std::borrow::Borrow;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Lower-case ASCII words joined by dashes; accents are folded, punctuation dropped.
#[must_use]
pub fn slugify(v: &str) -> String {
    use unicode_normalization::UnicodeNormalization;
    let ascii: String = v.nfkd().filter(char::is_ascii).collect();
    let mut out = String::with_capacity(ascii.len());
    let mut last_dash = false;
    for c in ascii.to_lowercase().chars() {
        if c.is_ascii_alphanumeric() || c == '_' {
            out.push(c);
            last_dash = false;
        } else if (c.is_whitespace() || c == '-') && !last_dash && !out.is_empty() {
            out.push('-');
            last_dash = true;
        }
    }
    out.trim_matches('-').to_owned()
}

/// The first `n` words, with an ellipsis if there were more.
#[must_use]
pub fn truncate_words(v: &str, n: usize) -> String {
    let words: Vec<&str> = v.split_whitespace().collect();
    if words.len() <= n {
        return words.join(" ");
    }
    format!("{} …", words[..n].join(" "))
}

/// HTML-escaped text with paragraphs at blank lines and `<br>` at single newlines.
/// The result is safe to emit unescaped.
#[must_use]
pub fn linebreaks(v: &str) -> String {
    v.replace("\r\n", "\n")
        .split("\n\n")
        .filter(|p| !p.trim().is_empty())
        .map(|p| {
            format!(
                "<p>{}</p>",
                html_escape::encode_text(p.trim()).replace('\n', "<br>")
            )
        })
        .collect::<Vec<_>>()
        .join("\n\n")
}

/// Seconds since the epoch, negative before it.
fn epoch_seconds(t: SystemTime) -> i64 {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => i64::try_from(d.as_secs()).unwrap_or(i64::MAX),
        Err(e) => i64::try_from(e.duration().as_secs()).map_or(i64::MIN, |s| -s),
    }
}

/// The proleptic Gregorian `(year, month, day)` of a day count from 1970-01-01.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days.saturating_add(719_468);
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

/// `YYYY-MM-DD` in UTC.
#[must_use]
pub fn iso_date(t: impl Borrow<SystemTime>) -> String {
    let (y, m, d) = civil_from_days(epoch_seconds(*t.borrow()).div_euclid(86_400));
    format!("{y:04}-{m:02}-{d:02}")
}

/// `YYYY-MM-DD HH:MM UTC`, the minute rounded down.
#[must_use]
pub fn utc_minute(t: impl Borrow<SystemTime>) -> String {
    let t = *t.borrow();
    let secs = epoch_seconds(t);
    let in_day = secs.rem_euclid(86_400);
    format!(
        "{} {:02}:{:02} UTC",
        iso_date(t),
        in_day / 3600,
        in_day % 3600 / 60
    )
}

/// `one` when `n` is 1, else `many`: English's rule. A language with other plural
/// forms picks its word in the app.
#[must_use]
pub fn plural<'a>(n: impl Borrow<u64>, one: &'a str, many: &'a str) -> &'a str {
    if *n.borrow() == 1 { one } else { many }
}

/// A unit of time in words: how it reads for one and for several.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Unit<'a> {
    /// With a count of 1: `minute`.
    pub one: &'a str,
    /// With any other count: `minutes`.
    pub many: &'a str,
}

/// The words [`ago`] and [`until`] use, so a page is not English-only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Words<'a> {
    /// Under a minute either way: `just now`.
    pub now: &'a str,
    /// A span in the past, with `{}` where the span goes: `{} ago`.
    pub ago: &'a str,
    /// A span ahead, with `{}` where the span goes: `in {}`.
    pub until: &'a str,
    /// A minute, 60 seconds.
    pub minute: Unit<'a>,
    /// An hour, 60 minutes.
    pub hour: Unit<'a>,
    /// A day, 24 hours.
    pub day: Unit<'a>,
    /// A month, always 30 days: `1 month ago` is 30 to 59 days, a calendar month's
    /// length is not consulted.
    pub month: Unit<'a>,
    /// A year, always 365 days (leap days are not counted).
    pub year: Unit<'a>,
}

impl Words<'static> {
    /// English: `just now`, `5 minutes ago`, `in 1 hour`.
    pub const ENGLISH: Self = Self {
        now: "just now",
        ago: "{} ago",
        until: "in {}",
        minute: Unit {
            one: "minute",
            many: "minutes",
        },
        hour: Unit {
            one: "hour",
            many: "hours",
        },
        day: Unit {
            one: "day",
            many: "days",
        },
        month: Unit {
            one: "month",
            many: "months",
        },
        year: Unit {
            one: "year",
            many: "years",
        },
    };
}

/// A span of `secs` seconds in its largest whole unit, rounded down (`3 days`), or
/// `None` under a minute.
fn span(secs: u64, w: &Words<'_>) -> Option<String> {
    let (n, unit) = match secs {
        0..60 => return None,
        60..3600 => (secs / 60, w.minute),
        3600..86_400 => (secs / 3600, w.hour),
        86_400..2_592_000 => (secs / 86_400, w.day),
        2_592_000..31_536_000 => (secs / 2_592_000, w.month),
        _ => (secs / 31_536_000, w.year),
    };
    Some(format!("{n} {}", plural(n, unit.one, unit.many)))
}

fn relative(from: SystemTime, to: SystemTime, pattern: &str, w: &Words<'_>) -> String {
    debug_assert!(
        pattern.contains("{}"),
        "a Words pattern holds {{}}: {pattern:?}"
    );
    let gap = to.duration_since(from).unwrap_or(Duration::ZERO);
    span(gap.as_secs(), w).map_or_else(|| w.now.to_owned(), |s| pattern.replacen("{}", &s, 1))
}

/// How long before `now` the moment `t` was (`5 minutes ago`). Months are 30 days
/// and years 365. A moment in the future, or under a minute back, is `words.now`.
#[must_use]
pub fn ago_at(
    t: impl Borrow<SystemTime>,
    now: impl Borrow<SystemTime>,
    words: &Words<'_>,
) -> String {
    relative(*t.borrow(), *now.borrow(), words.ago, words)
}

/// [`ago_at`] from the present.
#[must_use]
pub fn ago(t: impl Borrow<SystemTime>, words: &Words<'_>) -> String {
    ago_at(t, SystemTime::now(), words)
}

/// How long after `now` the moment `t` is (`in 2 days`). A moment in the past, or
/// under a minute ahead, is `words.now`.
#[must_use]
pub fn until_at(
    t: impl Borrow<SystemTime>,
    now: impl Borrow<SystemTime>,
    words: &Words<'_>,
) -> String {
    relative(*now.borrow(), *t.borrow(), words.until, words)
}

/// [`until_at`] from the present.
#[must_use]
pub fn until(t: impl Borrow<SystemTime>, words: &Words<'_>) -> String {
    until_at(t, SystemTime::now(), words)
}

/// `term` with `%`, `_` and `\` matched as themselves in a `LIKE` or `ILIKE`
/// pattern (Postgres's default escape character). A pattern built from a search
/// box without this treats what a person typed as wildcards.
#[must_use]
pub fn like_escape(term: &str) -> String {
    let mut out = String::with_capacity(term.len());
    for c in term.chars() {
        if matches!(c, '\\' | '%' | '_') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helpers() {
        assert_eq!(slugify("Hello  World Foo"), "hello-world-foo");
        assert_eq!(slugify("Crème Brûlée!"), "creme-brulee");
        // Punctuation is dropped, not turned into a dash.
        assert_eq!(slugify("a.b"), "ab");
        assert_eq!(slugify("rock & roll"), "rock-roll");
        assert_eq!(slugify("--x--"), "x");
        assert_eq!(truncate_words("Hello  World Foo", 2), "Hello World …");
        assert_eq!(
            linebreaks("a\nb\n\n<c>"),
            "<p>a<br>b</p>\n\n<p>&lt;c&gt;</p>"
        );
    }

    fn at(secs: i64) -> SystemTime {
        match u64::try_from(secs) {
            Ok(s) => UNIX_EPOCH + Duration::from_secs(s),
            Err(_) => UNIX_EPOCH - Duration::from_secs(secs.unsigned_abs()),
        }
    }

    #[test]
    fn dates_are_utc_and_round_down() {
        assert_eq!(iso_date(at(0)), "1970-01-01");
        assert_eq!(utc_minute(at(0)), "1970-01-01 00:00 UTC");
        // 2026-10-20 14:05:59 UTC
        assert_eq!(utc_minute(at(1_792_505_159)), "2026-10-20 14:05 UTC");
        // Leap days, century rules, the day before the epoch and a far past year.
        assert_eq!(iso_date(at(951_782_400)), "2000-02-29");
        assert_eq!(iso_date(at(4_107_542_400)), "2100-03-01");
        assert_eq!(utc_minute(at(-1)), "1969-12-31 23:59 UTC");
        assert_eq!(iso_date(at(-62_135_596_800)), "0001-01-01");
    }

    #[test]
    fn plural_is_one_only_for_one() {
        assert_eq!(plural(1, "game", "games"), "game");
        assert_eq!(plural(0, "game", "games"), "games");
        assert_eq!(plural(2, "game", "games"), "games");
    }

    #[test]
    fn relative_times_use_the_largest_whole_unit() {
        let w = Words::ENGLISH;
        let now = at(1_000_000_000);
        let back = |s: i64| ago_at(at(1_000_000_000 - s), now, &w);
        let ahead = |s: i64| until_at(at(1_000_000_000 + s), now, &w);
        assert_eq!(back(59), "just now");
        assert_eq!(back(60), "1 minute ago");
        assert_eq!(back(119), "1 minute ago");
        assert_eq!(back(3600 * 5), "5 hours ago");
        assert_eq!(back(86_400 * 29), "29 days ago");
        assert_eq!(back(86_400 * 30), "1 month ago");
        assert_eq!(back(86_400 * 400), "1 year ago");
        assert_eq!(ahead(3600), "in 1 hour");
        assert_eq!(ahead(86_400 * 2), "in 2 days");
        // The wrong direction, and the present, are "now".
        assert_eq!(back(-3600), "just now");
        assert_eq!(ahead(-3600), "just now");
        assert_eq!(back(0), "just now");
    }

    #[test]
    fn relative_times_take_the_apps_words() {
        let w = Words {
            now: "à l'instant",
            ago: "il y a {}",
            until: "dans {}",
            minute: Unit {
                one: "minute",
                many: "minutes",
            },
            ..Words::ENGLISH
        };
        let now = at(1_000_000_000);
        assert_eq!(ago_at(at(1_000_000_000 - 300), now, &w), "il y a 5 minutes");
        assert_eq!(until_at(at(1_000_000_000 + 60), now, &w), "dans 1 minute");
        assert_eq!(ago_at(now, now, &w), "à l'instant");
    }

    #[test]
    fn the_english_patterns_hold_the_span() {
        assert!(Words::ENGLISH.ago.contains("{}") && Words::ENGLISH.until.contains("{}"));
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "a Words pattern holds")]
    fn a_pattern_without_the_span_is_caught() {
        let w = Words {
            ago: "ago",
            ..Words::ENGLISH
        };
        let _ = ago_at(at(0), at(3600), &w);
    }

    #[test]
    fn like_escape_makes_wildcards_literal() {
        assert_eq!(like_escape("50%_off\\"), "50\\%\\_off\\\\");
        assert_eq!(like_escape("plain é"), "plain é");
    }
}
