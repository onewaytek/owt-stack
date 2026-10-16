//! Redirect targets that came from the request.
//!
//! A sign-in page is handed `?next=` and redirects there afterwards. Unchecked, that
//! is an open redirect: a link to this site that lands on another, which is what a
//! phishing page wants.

use axum::http::{HeaderMap, header};

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

/// The page an htmx request was sent from (`HX-Current-URL`), as a path and query on
/// this site: for a sign-in wall's `?next=`, which should name that page rather than
/// the fragment it asked for.
///
/// `None` unless the header is an `http(s)` URL of the request's own origin, compared
/// with its `Host` as the cross-origin check does (no user or password, the same
/// `host[:port]`), and its path passes [`local`]. Fall back to the request's own URI.
#[must_use]
pub fn htmx_current_page(headers: &HeaderMap) -> Option<String> {
    let get = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());
    let host = get(header::HOST.as_str()).filter(|h| !h.is_empty())?;
    let url = url::Url::parse(get("hx-current-url")?).ok()?;
    let same_origin = matches!(url.scheme(), "http" | "https")
        && url.username().is_empty()
        && url.password().is_none()
        && crate::csrf::authority(&url).eq_ignore_ascii_case(host);
    if !same_origin {
        return None;
    }
    let page = match url.query() {
        Some(q) => format!("{}?{q}", url.path()),
        None => url.path().to_owned(),
    };
    local(&page).is_some().then_some(page)
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::*;

    fn current(url: &'static str, host: &'static str) -> Option<String> {
        let mut h = HeaderMap::new();
        h.insert("hx-current-url", HeaderValue::from_static(url));
        if !host.is_empty() {
            h.insert(header::HOST, HeaderValue::from_static(host));
        }
        htmx_current_page(&h)
    }

    #[test]
    fn the_htmx_page_is_a_path_on_this_origin() {
        assert_eq!(
            current("https://app.test/worlds/3?tab=a#x", "app.test").as_deref(),
            Some("/worlds/3?tab=a")
        );
        assert_eq!(
            current("http://APP.test:8000/", "app.test:8000").as_deref(),
            Some("/")
        );
        for (url, host) in [
            ("https://evil.test/worlds/3", "app.test"),
            ("https://app.test:8443/x", "app.test"),
            ("https://app.test/x", ""),
            ("https://user@app.test/x", "app.test"),
            ("javascript://app.test/%0aalert(1)", "app.test"),
            ("/worlds/3", "app.test"),
            ("https://app.test//evil.test/x", "app.test"),
        ] {
            assert_eq!(current(url, host), None, "{url} on {host}");
        }
        assert_eq!(htmx_current_page(&HeaderMap::new()), None);
    }

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
