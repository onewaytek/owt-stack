//! Golden-page tests: rendered HTML compared with a snapshot on disk.
//!
//! The comparison is modulo layout and escaping style. A [`Normalizer`] decodes
//! entities, collapses whitespace, masks what differs between runs (ids, dates,
//! chrome shared by every page), and puts one tag per line, so a failure names the
//! first differing tag rather than a column in a megabyte line.
//!
//! [`Golden::check`] compares every page taken and reports all the differences at
//! once. With `UPDATE_GOLDEN=1` it rewrites the snapshots instead; review the diff
//! before committing it, since it now is the claim.

use std::path::PathBuf;

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

    /// Replace matches of `pattern` with `with` (`$1` refers to a group).
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

    /// Mask v4-shaped UUIDs as `with`.
    #[must_use]
    pub fn uuids(self, with: &str) -> Self {
        self.mask(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            with,
        )
    }

    /// `html` decoded, collapsed, masked, one tag per line, newline-terminated.
    #[must_use]
    pub fn normalize(&self, html: &str) -> String {
        let decoded = html_escape::decode_html_entities(html);
        let mut s = decoded
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

/// A set of snapshots in one directory, one `<name>.html` file each.
pub struct Golden {
    dir: PathBuf,
    taken: Vec<(String, String)>,
}

impl Golden {
    /// Snapshots in `dir` (relative to the crate being tested).
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self {
            dir: dir.into(),
            taken: Vec::new(),
        }
    }

    /// Record `name`'s normalized HTML.
    pub fn take(&mut self, name: &str, normalized: String) {
        self.taken.push((name.to_owned(), normalized));
    }

    /// Compare everything taken with its snapshot, failing with every difference;
    /// with `UPDATE_GOLDEN` set, write the snapshots instead. Only this set's files
    /// are written: other tests' snapshots in the same directory are left alone.
    ///
    /// # Panics
    /// On any difference, a missing snapshot, or an unwritable directory.
    pub fn check(self) {
        if std::env::var_os("UPDATE_GOLDEN").is_some() {
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
                let Ok(want) = std::fs::read_to_string(&path) else {
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

fn first_difference(name: &str, want: &str, got: &str) -> String {
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
        let html = "<p class=\"a\">\n   Tom &amp; Jerry</p> <a href=\"/s/123e4567-e89b-42d3-a456-426614174000/\">October 6, 2026 09:30</a>";
        assert_eq!(
            n.normalize(html),
            "<p class=\"a\"> Tom & Jerry</p>\n<a href=\"/s/<uuid>/\">TODAY HH:MM</a>\n"
        );
    }

    #[test]
    fn reports_the_first_differing_line() {
        let msg = first_difference("p", "<a>\n<b>\n", "<a>\n<c>\n");
        assert_eq!(msg, "p: line 2\n  want: <b>\n  got:  <c>");
        assert!(first_difference("p", "<a>\n", "<a>\n<b>\n").contains("want: <end>"));
    }
}
