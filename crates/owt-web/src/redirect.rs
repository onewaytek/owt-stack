//! Redirect targets that came from the request.
//!
//! A sign-in page is handed `?next=` and redirects there afterwards. Unchecked, that
//! is an open redirect: a link to this site that lands on another, which is what a
//! phishing page wants.

/// `next` if it is a path on this site, else `None`.
///
/// A path here starts with one `/`. `//host` and `/\\host` are other sites to a
/// browser, and so is anything with a scheme. Control characters are refused
/// outright, because browsers strip tabs and newlines before parsing.
#[must_use]
pub fn local(next: &str) -> Option<&str> {
    let ok = next.starts_with('/')
        && !next.starts_with("//")
        && !next.contains('\\')
        && !next.chars().any(char::is_control);
    ok.then_some(next)
}

/// `next` if it is a path on this site, else `fallback`.
#[must_use]
pub fn local_or<'a>(next: Option<&'a str>, fallback: &'a str) -> &'a str {
    next.and_then(local).unwrap_or(fallback)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_paths_on_this_site_pass() {
        for ok in ["/", "/games/?a=1&b=2", "/a/b#c", "/a?next=https://x.test"] {
            assert_eq!(local(ok), Some(ok));
        }
        for bad in [
            "",
            "games",
            "https://evil.test/",
            "//evil.test",
            "/\\evil.test",
            "/a\\b",
            "\\/evil.test",
            "/\t/evil.test",
            "/\n/evil.test",
            " /x",
            "javascript:alert(1)",
        ] {
            assert_eq!(local(bad), None, "{bad:?}");
        }
        assert_eq!(local_or(Some("//evil.test"), "/"), "/");
        assert_eq!(local_or(None, "/home"), "/home");
        assert_eq!(local_or(Some("/x"), "/"), "/x");
    }
}
