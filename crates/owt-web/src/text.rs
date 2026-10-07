//! Text as pages show it: slugs, word truncation, and plain text made into paragraphs.

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
}
