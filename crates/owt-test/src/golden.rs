//! Golden-page tests: rendered HTML compared with a snapshot on disk.
//!
//! The comparison is modulo layout and escaping *style*. A [`Normalizer`] writes
//! every character reference one way (`&#60;`, `&#x3C;` and `&lt;` are all `&lt;`;
//! `&eacute;` is `é`), collapses whitespace, masks what differs between runs (ids,
//! dates, chrome shared by every page), and puts one tag per line, so a failure names
//! the first differing tag rather than a column in a megabyte line. Escaped and
//! unescaped markup stay different: a template that stops escaping fails its
//! snapshot.
//!
//! Collapsing whitespace is coarse: it also collapses it inside `<pre>` and
//! `<textarea>`, and `</b> <i>` compares equal to `</b><i>`. A snapshot does not
//! guard rendered whitespace.
//!
//! [`Golden::check`] compares every page taken and reports all the differences at
//! once. With `UPDATE_GOLDEN=1` it rewrites the snapshots instead; review the diff
//! before committing it, since it now is the claim. A `Golden` dropped with pages
//! taken and never checked fails the test.

use std::path::PathBuf;
use std::sync::LazyLock;

use regex::Regex;

enum Step {
    Pattern(Regex, String),
    Literal(String, String),
}

/// Turns rendered HTML into its comparable form. Masks apply in the order added.
#[derive(Default)]
pub struct Normalizer {
    steps: Vec<Step>,
}

impl Normalizer {
    /// No masks yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace matches of `pattern` with `with` (`$1` refers to a group). Masks see
    /// the normalized text: references written one way (`&amp;`), whitespace
    /// collapsed, and all on one line.
    ///
    /// # Panics
    /// If `pattern` is not a regex.
    #[must_use]
    pub fn mask(mut self, pattern: &str, with: &str) -> Self {
        self.steps.push(Step::Pattern(
            Regex::new(pattern).expect("a valid regex"),
            with.to_owned(),
        ));
        self
    }

    /// Replace every occurrence of `text` with `with` (today's date, say).
    #[must_use]
    pub fn replace(mut self, text: &str, with: &str) -> Self {
        self.steps
            .push(Step::Literal(text.to_owned(), with.to_owned()));
        self
    }

    /// Mask UUIDs (any version, either case) as `with`.
    #[must_use]
    pub fn uuids(self, with: &str) -> Self {
        self.mask(
            r"(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            with,
        )
    }

    /// `html` with its references canonical, collapsed, masked, one tag per line,
    /// newline-terminated.
    #[must_use]
    pub fn normalize(&self, html: &str) -> String {
        let canonical = canonical_references(html);
        let mut s = canonical
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .replace("> <", "><");
        for step in &self.steps {
            s = match step {
                Step::Pattern(re, with) => re.replace_all(&s, with.as_str()).into_owned(),
                Step::Literal(text, with) => s.replace(text.as_str(), with),
            };
        }
        s.replace("><", ">\n<") + "\n"
    }
}

/// Every character reference written one way. The five characters that markup is
/// made of stay escaped (`&amp;`, `&lt;`, `&gt;`, `&quot;`, `&#39;`), so escaped text
/// never compares equal to markup; every other reference becomes its character. A
/// bare `&` is `&amp;`: it cannot start markup, so escaping it or not is style.
fn canonical_references(html: &str) -> String {
    static REFERENCE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"&(?:#[0-9]+|#[xX][0-9a-fA-F]+|[A-Za-z][A-Za-z0-9]*);|&")
            .expect("a valid regex")
    });
    REFERENCE
        .replace_all(html, |m: &regex::Captures<'_>| {
            let reference = &m[0];
            let decoded = html_escape::decode_html_entities(reference);
            match decoded.as_ref() {
                "&" => "&amp;".to_owned(),
                "<" => "&lt;".to_owned(),
                ">" => "&gt;".to_owned(),
                "\"" => "&quot;".to_owned(),
                "'" => "&#39;".to_owned(),
                // Not a reference a browser knows: it shows the text as written.
                other if other == reference => format!("&amp;{}", &reference[1..]),
                other => other.to_owned(),
            }
        })
        .into_owned()
}

/// A set of snapshots in one directory, one `<name>.html` file each.
pub struct Golden {
    dir: PathBuf,
    taken: Vec<(String, String)>,
    checked: bool,
}

impl Golden {
    /// Snapshots in `dir` (relative to the crate being tested).
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self {
            dir: dir.into(),
            taken: Vec::new(),
            checked: false,
        }
    }

    /// Record `name`'s normalized HTML.
    ///
    /// # Panics
    /// If `name` is not a plain file name (it holds `/` or `\\`, or starts with `.`):
    /// snapshots are written only inside the directory.
    pub fn take(&mut self, name: &str, normalized: String) {
        assert!(
            !name.is_empty() && !name.starts_with('.') && !name.contains(['/', '\\']),
            "snapshot name {name:?} must be a plain file name"
        );
        self.taken.push((name.to_owned(), normalized));
    }

    /// Compare everything taken with its snapshot, failing with every difference;
    /// with `UPDATE_GOLDEN` set, write the snapshots instead. Only this set's files
    /// are written: other tests' snapshots in the same directory are left alone.
    ///
    /// # Panics
    /// On any difference, a missing snapshot, or an unwritable directory.
    pub fn check(self) {
        let update = matches!(std::env::var("UPDATE_GOLDEN").as_deref(), Ok("1" | "true"));
        self.check_or_update(update);
    }

    fn check_or_update(mut self, update: bool) {
        self.checked = true;
        if update {
            std::fs::create_dir_all(&self.dir).expect("create the snapshot directory");
            for (name, html) in &self.taken {
                std::fs::write(self.dir.join(format!("{name}.html")), html)
                    .expect("write a snapshot");
            }
            return;
        }
        let failed: Vec<String> = self
            .taken
            .iter()
            .filter_map(|(name, got)| {
                let path = self.dir.join(format!("{name}.html"));
                // A checkout that turned newlines into CRLF changes nothing.
                let Ok(want) = std::fs::read_to_string(&path).map(|w| w.replace('\r', "")) else {
                    return Some(format!(
                        "{name}: no snapshot at {} (run with UPDATE_GOLDEN=1)",
                        path.display()
                    ));
                };
                (want != *got).then(|| first_difference(name, &want, got))
            })
            .collect();
        assert!(
            failed.is_empty(),
            "{} page(s) differ from their snapshots:\n{}",
            failed.len(),
            failed.join("\n")
        );
    }
}

impl Drop for Golden {
    fn drop(&mut self) {
        assert!(
            self.checked || self.taken.is_empty() || std::thread::panicking(),
            "{} golden page(s) taken and never checked: call Golden::check",
            self.taken.len()
        );
    }
}

pub(crate) fn first_difference(name: &str, want: &str, got: &str) -> String {
    let line = want
        .lines()
        .zip(got.lines())
        .position(|(a, b)| a != b)
        .unwrap_or_else(|| want.lines().count().min(got.lines().count()));
    format!(
        "{name}: line {}\n  want: {}\n  got:  {}",
        line + 1,
        want.lines().nth(line).unwrap_or("<end>"),
        got.lines().nth(line).unwrap_or("<end>")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_layout_escaping_and_masks() {
        let n = Normalizer::new()
            .uuids("<uuid>")
            .replace("October 6, 2026", "TODAY")
            .mask(r"TODAY \d{2}:\d{2}", "TODAY HH:MM");
        let html = "<p class=\"a\">\n   Tom &amp; Jerry</p> <a href=\"/s/123E4567-e89b-42d3-a456-426614174000/\">October 6, 2026 09:30</a>";
        assert_eq!(
            n.normalize(html),
            "<p class=\"a\"> Tom &amp; Jerry</p>\n<a href=\"/s/<uuid>/\">TODAY HH:MM</a>\n"
        );
    }

    #[test]
    fn escaping_style_is_ignored_and_escaping_is_not() {
        let n = Normalizer::new();
        assert_eq!(
            n.normalize("<p>&#60;b&#x3E; &#34;x&#x27; caf&eacute; Tom & Jerry</p>"),
            n.normalize("<p>&lt;b&gt; &quot;x&#39; café Tom &amp; Jerry</p>"),
        );
        assert_ne!(
            n.normalize("<p>&lt;script&gt;</p>"),
            n.normalize("<p><script></p>"),
            "a template that stops escaping must fail its snapshot"
        );
        assert_eq!(
            n.normalize("<p>&bogus; &amp</p>"),
            "<p>&amp;bogus; &amp;amp</p>\n"
        );
    }

    fn scratch(test: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("owt-golden-{}-{test}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn update_writes_the_snapshots_a_check_then_passes() {
        let dir = scratch("update");
        let mut g = Golden::new(&dir);
        g.take("home", "<p>\n".into());
        g.check_or_update(true);
        assert_eq!(
            std::fs::read_to_string(dir.join("home.html")).unwrap(),
            "<p>\n"
        );
        // CRLF on disk compares equal.
        std::fs::write(dir.join("home.html"), "<p>\r\n").unwrap();
        let mut g = Golden::new(&dir);
        g.take("home", "<p>\n".into());
        g.check_or_update(false);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn every_difference_and_missing_snapshot_is_reported() {
        let dir = scratch("report");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("a.html"), "<a>\n").unwrap();
        std::fs::write(dir.join("b.html"), "<b>\n").unwrap();
        let mut g = Golden::new(&dir);
        g.take("a", "<a>\n".into());
        g.take("b", "<i>\n".into());
        g.take("c", "<c>\n".into());
        let failure = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            g.check_or_update(false);
        }))
        .unwrap_err();
        let msg = failure.downcast_ref::<String>().unwrap();
        assert!(msg.starts_with("2 page(s) differ"), "{msg}");
        assert!(
            msg.contains("b: line 1") && msg.contains("c: no snapshot"),
            "{msg}"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    #[should_panic(expected = "never checked")]
    fn pages_taken_and_never_checked_fail() {
        let mut g = Golden::new(scratch("unchecked"));
        g.take("home", String::new());
    }

    #[test]
    #[should_panic(expected = "plain file name")]
    fn names_stay_in_the_directory() {
        Golden::new(scratch("names")).take("../escape", String::new());
    }

    #[test]
    fn reports_the_first_differing_line() {
        let msg = first_difference("p", "<a>\n<b>\n", "<a>\n<c>\n");
        assert_eq!(msg, "p: line 2\n  want: <b>\n  got:  <c>");
        assert!(first_difference("p", "<a>\n", "<a>\n<b>\n").contains("want: <end>"));
    }
}
