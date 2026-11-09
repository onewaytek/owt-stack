//! Redirect targets that came from the request.
//!
//! A sign-in page is handed `?next=` and redirects there afterwards. Unchecked, that
//! is an open redirect: a link to this site that lands on another, which is what a
//! phishing page wants.
//!
//! A link someone typed for others to follow (a profile's website, an event's page) is
//! the other way round: it must leave the site, but only for a web page. [`web_url`]
//! keeps `javascript:` and `data:` out of an `href`.

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
    same_origin_page(headers, "hx-current-url")
}

/// The page a request was sent from (`Referer`), as a path and query on this site:
/// where a form's `POST` came from, for a redirect that sends the visitor back to it
/// with a `GET`.
///
/// `None` under the same rules as [`htmx_current_page`]: an `http(s)` URL of the
/// request's own origin whose path passes [`local`]. A browser that sends no
/// `Referer` (a `no-referrer` policy) or only the origin gets `None` or `/`.
#[must_use]
pub fn referer_page(headers: &HeaderMap) -> Option<String> {
    same_origin_page(headers, header::REFERER.as_str())
}

/// `link` as an absolute `http` or `https` URL with a host, else `None`: for a link
/// someone supplied that the site shows to others as an `href`.
///
/// Any other scheme is refused: `javascript:` and `vbscript:` run in the page's
/// origin when followed, `data:` opens a document the attacker wrote, and `file:` or
/// a custom scheme reaches outside the browser. So is a relative link (it would point
/// into this site), a URL without a host, and one with a user or password
/// (`https://bank.example@evil.example/` reads as the bank). Check at the form, and
/// again where the page renders the link, so rows saved before the check are covered.
///
/// The `Url` is the parsed form: render `url.as_str()`, escaped by the template as
/// any text is, rather than the string as typed. The parser has already removed the
/// tabs and newlines a browser would strip, and leading and trailing spaces.
#[must_use]
pub fn web_url(link: &str) -> Option<url::Url> {
    let url = url::Url::parse(link).ok()?;
    let ok = matches!(url.scheme(), "http" | "https")
        && url.host_str().is_some_and(|h| !h.is_empty())
        && url.username().is_empty()
        && url.password().is_none();
    ok.then_some(url)
}

/// The URL in header `name`, as a path and query, when it names this origin.
fn same_origin_page(headers: &HeaderMap, name: &str) -> Option<String> {
    let get = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());
    let host = get(header::HOST.as_str()).filter(|h| !h.is_empty())?;
    let url = url::Url::parse(get(name)?).ok()?;
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
    fn the_referer_is_a_path_on_this_origin() {
        let referer = |url: &'static str| {
            let mut h = HeaderMap::new();
            h.insert(header::REFERER, HeaderValue::from_static(url));
            h.insert(header::HOST, HeaderValue::from_static("app.test"));
            referer_page(&h)
        };
        assert_eq!(
            referer("https://app.test/a/b?c=1").as_deref(),
            Some("/a/b?c=1")
        );
        assert_eq!(referer("https://evil.test/a"), None);
        assert_eq!(referer("javascript:alert(1)"), None);
        // A path a browser reads as another host: `//`, and `\` that the URL
        // parser turns into `/`.
        assert_eq!(referer("https://app.test//evil.test/a"), None);
        assert_eq!(referer("https://app.test/\\evil.test/a"), None);
        // Encoded slashes stay encoded, a path on this site.
        assert_eq!(
            referer("https://app.test/%2F%2Fevil.test").as_deref(),
            Some("/%2F%2Fevil.test")
        );
        assert_eq!(referer_page(&HeaderMap::new()), None);
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
    fn only_web_links_with_a_host_pass() {
        for (link, shown) in [
            ("https://example.com", "https://example.com/"),
            ("http://example.com/a?b=1#c", "http://example.com/a?b=1#c"),
            ("HTTPS://Example.COM/Path", "https://example.com/Path"),
            ("  https://example.com/x  ", "https://example.com/x"),
            ("https://exa\tmple.com/", "https://example.com/"),
            ("https://[::1]:8443/", "https://[::1]:8443/"),
            // Without slashes, a special scheme still names a host, as browsers read it.
            ("https:example.com", "https://example.com/"),
            ("https://bücher.example/", "https://xn--bcher-kva.example/"),
        ] {
            assert_eq!(
                web_url(link).map(String::from).as_deref(),
                Some(shown),
                "{link:?}"
            );
        }
        for bad in [
            "",
            "example.com",
            "/a/b",
            "//example.com/a",
            "javascript:alert(1)",
            "JavaScript:alert(1)",
            " javascript:alert(1)",
            "java\tscript:alert(1)",
            "javascript://example.com/%0aalert(1)",
            "data:text/html,<script>alert(1)</script>",
            "vbscript:msgbox(1)",
            "file:///etc/passwd",
            "ftp://example.com/",
            "mailto:a@example.com",
            "https://user@example.com/",
            "https://bank.example:pw@evil.example/",
            "http://",
        ] {
            assert_eq!(web_url(bad), None, "{bad:?}");
        }
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
