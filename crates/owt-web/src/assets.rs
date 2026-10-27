//! Fingerprinted static asset URLs, and the service that serves them.
//!
//! [`Assets::mount`] serves the directory under its prefix, and templates name a static
//! file through [`Assets::url`], which appends its content hash (`?v=`). A request
//! whose `v` matches the file's current hash is served `immutable`; anything else (no
//! `v`, or a hash another replica minted mid-rollout) is `no-cache`, so a stale file
//! can never be pinned in a browser or at the edge under a URL that claims to be
//! current.
//!
//! A `.css` file is served with its relative `url(...)` and `@import` references
//! rewritten to carry the referenced file's `?v=` hash, so the fonts and images a
//! stylesheet loads are `immutable` too. Absolute, root-relative, `data:`,
//! fragment-only, percent-encoded and already-queried URLs are left as written. The
//! stylesheet's hash folds in the hashes of what it references (a changed font
//! changes the stylesheet's URL); a reference cycle is cut where it closes.
//!
//! The hash is of the bytes on disk, memoized per existing file (misses are not
//! stored, so request paths cannot grow the map): the files are fixed once the app is
//! built, and a file replaced under a running process keeps its first hash. Call
//! [`Assets::warm`] before binding the listener to hash every file up front; a file
//! first hashed later is read on the first request that needs it (off the async
//! executor when that is the static service, on the caller's thread for
//! [`Assets::url`]). With `watch(true)`, typically in debug builds, it is recomputed
//! on every call, so a Tailwind `--watch` rebuild is never served under a stale
//! fingerprint.
//!
//! The directory is served as it is: symlinks in it are followed, so it must hold
//! only files meant to be public. A path with a dotfile or dot-directory component
//! (`.env`, `.git/config`) is a 404, `/.well-known/` included, so an app serves that
//! from a route of its own; and a path that leaves the directory is never
//! served.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::hash::{DefaultHasher, Hasher};
use std::ops::Range;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{Request, State};
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::middleware::{Next, from_fn_with_state};
use axum::response::{IntoResponse, Response};
use tower_http::services::ServeDir;

/// A directory of static files served under a URL prefix. Cheap to clone.
#[derive(Clone, Debug)]
pub struct Assets(Arc<Inner>);

#[derive(Debug)]
struct Inner {
    dir: PathBuf,
    prefix: String,
    watch: bool,
    hashes: RwLock<HashMap<String, String>>,
    sheets: RwLock<HashMap<String, Arc<Stylesheet>>>,
}

/// The prefix with one leading `/` and no trailing one (`static/` is `/static`); empty
/// stays empty.
fn normalize_prefix(prefix: &str) -> String {
    let trimmed = prefix.trim_matches('/');
    if trimmed.is_empty() {
        String::new()
    } else {
        format!("/{trimmed}")
    }
}

/// Whether a request path names a dotfile or dot-directory, in either spelling of the
/// dot (`.` or `%2e`).
fn names_dotfile(path: &str) -> bool {
    path.split('/')
        .any(|segment| segment.starts_with('.') || segment.to_ascii_lowercase().starts_with("%2e"))
}

/// `Cache-Control` for bytes fully determined by their URL.
pub const IMMUTABLE: &str = "public, max-age=31536000, immutable";

impl Assets {
    /// Files in `dir`, served under `prefix` (e.g. `/static`).
    pub fn new(dir: impl Into<PathBuf>, prefix: &str) -> Self {
        Self(Arc::new(Inner {
            dir: dir.into(),
            prefix: normalize_prefix(prefix),
            watch: false,
            hashes: RwLock::default(),
            sheets: RwLock::default(),
        }))
    }

    /// Rehash on every call instead of memoizing (development).
    #[must_use]
    pub fn watch(self, on: bool) -> Self {
        let inner = Arc::try_unwrap(self.0).unwrap_or_else(|a| Inner {
            dir: a.dir.clone(),
            prefix: a.prefix.clone(),
            watch: a.watch,
            hashes: RwLock::default(),
            sheets: RwLock::default(),
        });
        Self(Arc::new(Inner { watch: on, ..inner }))
    }

    /// The directory served.
    #[must_use]
    pub fn dir(&self) -> &std::path::Path {
        &self.0.dir
    }

    fn compute(&self, path: &str) -> Option<String> {
        let bytes = std::fs::read(self.0.dir.join(path)).ok()?;
        let mut h = DefaultHasher::new();
        h.write(&bytes);
        Some(format!("{:016x}", h.finish()))
    }

    /// Hash every file in the directory now, so no request reads one for its hash.
    /// Call it before binding the listener, in the blocking context of startup (it
    /// reads every file). Returns the number of files hashed. Dotfiles and
    /// dot-directories, which are never served, are skipped, as are symlinked
    /// directories; a file that cannot be read is left to the lazy path. A no-op with
    /// `watch(true)`, which hashes on every call.
    pub fn warm(&self) -> usize {
        if self.0.watch {
            return 0;
        }
        let mut count = 0;
        let mut pending = vec![String::new()];
        while let Some(rel) = pending.pop() {
            let Ok(entries) = std::fs::read_dir(self.0.dir.join(&rel)) else {
                continue;
            };
            for entry in entries.flatten() {
                let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                    continue;
                };
                if name.starts_with('.') {
                    continue;
                }
                let path = if rel.is_empty() {
                    name
                } else {
                    format!("{rel}/{name}")
                };
                let Ok(kind) = entry.file_type() else {
                    continue;
                };
                if kind.is_dir() {
                    pending.push(path);
                } else if (kind.is_file() || entry.path().is_file()) && self.hash(&path).is_some() {
                    count += 1;
                }
            }
        }
        count
    }

    /// The memoized hash of `path`, if there is one; never touches the disk.
    fn memoized(&self, path: &str) -> Option<String> {
        if self.0.watch {
            return None;
        }
        self.0.hashes.read().ok()?.get(path).cloned()
    }

    /// [`hash`](Self::hash) for async code: a memoized hash is returned as is, and a
    /// miss reads the file on the blocking pool, not on a runtime worker.
    async fn hash_blocking(&self, path: String) -> Option<String> {
        if let Some(h) = self.memoized(&path) {
            return Some(h);
        }
        let this = self.clone();
        tokio::task::spawn_blocking(move || this.hash(&path))
            .await
            .ok()
            .flatten()
    }

    /// The content hash of `path` (relative to the directory), or `None` if there is
    /// no such file. Paths that leave the directory (`..`, or an absolute path, which
    /// would replace it) have none.
    #[must_use]
    pub fn hash(&self, path: &str) -> Option<String> {
        self.hash_in(path, &mut Vec::new())
    }

    /// [`hash`](Self::hash) while building the stylesheets in `stack`, which a
    /// reference cycle must not enter again.
    fn hash_in(&self, path: &str, stack: &mut Vec<String>) -> Option<String> {
        if !is_inside(path) {
            return None;
        }
        if is_stylesheet(path) {
            return self.stylesheet_in(path, stack).map(|s| s.hash.clone());
        }
        if self.0.watch {
            return self.compute(path);
        }
        if let Some(h) = self.0.hashes.read().ok().and_then(|m| m.get(path).cloned()) {
            return Some(h);
        }
        let h = self.compute(path)?;
        if let Ok(mut m) = self.0.hashes.write() {
            m.insert(path.to_owned(), h.clone());
        }
        Some(h)
    }

    /// The stylesheet at `path`, its URLs versioned, built once and memoized (not with
    /// `watch(true)`).
    fn stylesheet(&self, path: &str) -> Option<Arc<Stylesheet>> {
        if !is_inside(path) {
            return None;
        }
        self.stylesheet_in(path, &mut Vec::new())
    }

    fn stylesheet_in(&self, path: &str, stack: &mut Vec<String>) -> Option<Arc<Stylesheet>> {
        if !self.0.watch {
            let memo = self.0.sheets.read().ok()?.get(path).cloned();
            if memo.is_some() {
                return memo;
            }
        }
        if stack.iter().any(|p| p == path) {
            return None;
        }
        stack.push(path.to_owned());
        let built = self.build_stylesheet(path, stack);
        stack.pop();
        let sheet = Arc::new(built?);
        // Only a top-level build is kept: one made inside another stylesheet's may
        // have been cut short by a reference cycle that its own build would not hit.
        if !self.0.watch
            && stack.is_empty()
            && let (Ok(mut sheets), Ok(mut hashes)) = (self.0.sheets.write(), self.0.hashes.write())
        {
            sheets.insert(path.to_owned(), sheet.clone());
            hashes.insert(path.to_owned(), sheet.hash.clone());
        }
        Some(sheet)
    }

    /// Read the stylesheet and add `?v=<hash>` to each relative URL in it that names a
    /// file in the directory. Its own hash is of its bytes and then of each
    /// referenced path and hash, so a changed font or import changes the
    /// stylesheet's URL too.
    fn build_stylesheet(&self, path: &str, stack: &mut Vec<String>) -> Option<Stylesheet> {
        let bytes = std::fs::read(self.0.dir.join(path)).ok()?;
        let mut h = DefaultHasher::new();
        h.write(&bytes);
        let mut body = String::new();
        if let Ok(text) = std::str::from_utf8(&bytes) {
            let dir = path.rsplit_once('/').map_or("", |(d, _)| d);
            let mut last = 0;
            for range in references(text) {
                let reference = text[range.clone()].trim();
                let (target, fragment) =
                    reference.split_at(reference.find('#').unwrap_or(reference.len()));
                let Some(resolved) = resolve(dir, target) else {
                    continue;
                };
                let Some(version) = self.hash_in(&resolved, stack) else {
                    continue;
                };
                h.write(resolved.as_bytes());
                h.write(version.as_bytes());
                body.push_str(&text[last..range.start]);
                let _ = write!(body, "{target}?v={version}{fragment}");
                last = range.end;
            }
            body.push_str(&text[last..]);
        }
        let body = if body.is_empty() {
            Bytes::from(bytes)
        } else {
            Bytes::from(body)
        };
        Some(Stylesheet {
            hash: format!("{:016x}", h.finish()),
            body,
        })
    }

    /// [`stylesheet`](Self::stylesheet) for async code, built on the blocking pool.
    async fn stylesheet_blocking(&self, path: String) -> Option<Arc<Stylesheet>> {
        let this = self.clone();
        tokio::task::spawn_blocking(move || this.stylesheet(&path))
            .await
            .ok()
            .flatten()
    }

    /// `<prefix>/<path>?v=<hash>`; a missing file degrades to the bare URL.
    #[must_use]
    pub fn url(&self, path: &str) -> String {
        let path = path.trim_start_matches('/');
        match self.hash(path) {
            Some(h) => format!("{}/{path}?v={h}", self.0.prefix),
            None => format!("{}/{path}", self.0.prefix),
        }
    }

    /// The directory as a router, paths relative to it, each response under
    /// [`cache_policy`](Self::cache_policy). A dotfile or dot-directory is a 404.
    /// Nest it at the prefix, or use [`mount`](Self::mount).
    pub fn service<S>(&self) -> Router<S>
    where
        S: Clone + Send + Sync + 'static,
    {
        Router::new()
            .fallback_service(ServeDir::new(&self.0.dir))
            .layer(from_fn_with_state(self.clone(), serve_stylesheet))
            .layer(axum::middleware::from_fn(refuse_dotfiles))
            .layer(from_fn_with_state(self.clone(), Self::cache_policy))
    }

    /// `router` with the directory served under the prefix (given with or without its
    /// leading `/`).
    ///
    /// # Panics
    /// If the prefix is empty (or `/`), which `Router::nest` refuses.
    pub fn mount<S>(&self, router: Router<S>) -> Router<S>
    where
        S: Clone + Send + Sync + 'static,
    {
        router.nest(&self.0.prefix, self.service())
    }

    /// Middleware body for the static service, nested under the prefix (so the URI
    /// path is relative to the directory): `immutable` when `v` is the current hash,
    /// else `no-cache`. A `304 Not Modified` for a pinned file keeps `immutable`, like
    /// the `2xx` it revalidates.
    pub async fn cache_policy(State(this): State<Self>, req: Request, next: Next) -> Response {
        let path = req.uri().path().trim_start_matches('/').to_owned();
        let version = req
            .uri()
            .query()
            .and_then(|q| q.split('&').find_map(|kv| kv.strip_prefix("v=")))
            .map(str::to_owned);
        let pinned = match version {
            Some(v) => this.hash_blocking(path).await.is_some_and(|h| h == v),
            None => false,
        };
        let mut res = next.run(req).await;
        let policy =
            if pinned && (res.status().is_success() || res.status() == StatusCode::NOT_MODIFIED) {
                IMMUTABLE
            } else {
                "no-cache"
            };
        res.headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static(policy));
        res
    }
}

/// A stylesheet with the URLs inside it versioned: its served bytes, and a hash that
/// folds in the hashes of the files it references.
#[derive(Debug)]
struct Stylesheet {
    hash: String,
    body: Bytes,
}

/// Whether `path` names a stylesheet.
fn is_stylesheet(path: &str) -> bool {
    path.len() > 4 && path[path.len() - 4..].eq_ignore_ascii_case(".css")
}

/// Whether `path` stays inside the directory it is relative to.
fn is_inside(path: &str) -> bool {
    use std::path::{Component, Path};
    !path.is_empty()
        && Path::new(path)
            .components()
            .all(|c| matches!(c, Component::Normal(_)))
}

/// The byte ranges of the URLs a stylesheet refers to: `url(...)` (quoted or not) and
/// `@import "..."`, outside comments and other strings.
fn references(css: &str) -> Vec<Range<usize>> {
    let b = css.as_bytes();
    let mut found = Vec::new();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'/' if b.get(i + 1) == Some(&b'*') => {
                i = css[i + 2..]
                    .find("*/")
                    .map_or(b.len(), |end| i + 2 + end + 2);
            }
            b'"' | b'\'' => i = string_end(b, i).1,
            b'@' if css[i..].len() >= 7 && css[i..i + 7].eq_ignore_ascii_case("@import") => {
                i += 7;
                let j = skip_space(b, i);
                if matches!(b.get(j), Some(b'"' | b'\'')) {
                    let (inner, next) = string_end(b, j);
                    found.push(inner);
                    i = next;
                }
            }
            b'u' | b'U'
                if css[i..].len() >= 4
                    && css[i..i + 4].eq_ignore_ascii_case("url(")
                    && (i == 0
                        || !(b[i - 1].is_ascii_alphanumeric()
                            || b[i - 1] == b'-'
                            || b[i - 1] == b'_')) =>
            {
                let j = skip_space(b, i + 4);
                if matches!(b.get(j), Some(b'"' | b'\'')) {
                    let (inner, next) = string_end(b, j);
                    found.push(inner);
                    i = next;
                } else {
                    let mut k = j;
                    while k < b.len() && b[k] != b')' && !b[k].is_ascii_whitespace() {
                        k += 1;
                    }
                    found.push(j..k);
                    i = k;
                }
            }
            _ => i += 1,
        }
    }
    found
}

fn skip_space(b: &[u8], mut i: usize) -> usize {
    while i < b.len() && b[i].is_ascii_whitespace() {
        i += 1;
    }
    i
}

/// For the string opening at `b[start]`: the range of its contents, and where the scan
/// resumes after it.
fn string_end(b: &[u8], start: usize) -> (Range<usize>, usize) {
    let quote = b[start];
    let mut k = start + 1;
    while k < b.len() && b[k] != quote {
        k += if b[k] == b'\\' { 2 } else { 1 };
    }
    let end = k.min(b.len());
    (start + 1..end, (end + 1).min(b.len()))
}

/// `reference` resolved against the directory of the stylesheet `dir` (relative to
/// the served directory), as a path under it; `None` for anything that is not a
/// plain relative URL to a file inside it.
fn resolve(dir: &str, reference: &str) -> Option<String> {
    let first = reference.split('/').next()?;
    if reference.is_empty()
        || reference.starts_with(['/', '#'])
        || reference.contains(['?', '\\', '%'])
        || first.contains(':')
    {
        return None;
    }
    let mut parts: Vec<&str> = dir.split('/').filter(|s| !s.is_empty()).collect();
    for seg in reference.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            s if s.starts_with('.') => return None,
            s => parts.push(s),
        }
    }
    Some(parts.join("/"))
}

/// Middleware body: a `.css` file is served with its URLs versioned, and an `ETag`
/// that is its hash; everything else falls through to the file service.
async fn serve_stylesheet(State(this): State<Assets>, req: Request, next: Next) -> Response {
    let path = req.uri().path().trim_start_matches('/').to_owned();
    let get = matches!(*req.method(), Method::GET | Method::HEAD);
    if !get || !is_stylesheet(&path) {
        return next.run(req).await;
    }
    let Some(sheet) = this.stylesheet_blocking(path).await else {
        return next.run(req).await;
    };
    let etag = format!("\"{}\"", sheet.hash);
    let unchanged = req
        .headers()
        .get_all(header::IF_NONE_MATCH)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .any(|tag| tag.trim() == "*" || tag.trim().trim_start_matches("W/") == etag);
    let mut res = if unchanged {
        StatusCode::NOT_MODIFIED.into_response()
    } else {
        let body = if req.method() == Method::HEAD {
            Body::empty()
        } else {
            Body::from(sheet.body.clone())
        };
        let mut res = Response::new(body);
        let headers = res.headers_mut();
        headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/css"));
        headers.insert(header::CONTENT_LENGTH, HeaderValue::from(sheet.body.len()));
        res
    };
    if let Ok(tag) = HeaderValue::from_str(&etag) {
        res.headers_mut().insert(header::ETAG, tag);
    }
    res
}

/// Middleware body: a request naming a dotfile is a 404 before the file service sees it.
async fn refuse_dotfiles(req: Request, next: Next) -> Response {
    if names_dotfile(req.uri().path()) {
        return StatusCode::NOT_FOUND.into_response();
    }
    next.run(req).await
}

/// Defines the app's one [`Assets`] and the `url` function its templates call, in
/// the module that invokes it: `assets::assets()` is the `Assets` (for
/// [`Assets::mount`] or `Stack::assets`), `assets::url("css/app.css")` the
/// fingerprinted URL. `directory` is relative to the working directory; files are
/// rehashed on every call in a debug build, and hashed once in a release build.
///
/// ```
/// mod assets {
///     owt_web::static_assets!("static", "/static");
/// }
/// let router = assets::assets().mount(axum::Router::new());
/// # let _: axum::Router = router;
/// assert!(assets::url("css/app.css").starts_with("/static/css/app.css"));
/// ```
#[macro_export]
macro_rules! static_assets {
    ($dir:expr, $prefix:expr) => {
        static ASSETS: ::std::sync::LazyLock<$crate::assets::Assets> =
            ::std::sync::LazyLock::new(|| {
                $crate::assets::Assets::new($dir, $prefix).watch(cfg!(debug_assertions))
            });

        /// The app's static files.
        pub fn assets() -> &'static $crate::assets::Assets {
            &ASSETS
        }

        /// The fingerprinted URL of a static file, for templates.
        #[must_use]
        pub fn url(path: &str) -> String {
            ASSETS.url(path)
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    mod defined {
        crate::static_assets!(
            std::env::temp_dir().join(format!("owt-assets-macro-{}", std::process::id())),
            "/s"
        );
    }

    async fn cache_control(app: Router, uri: &str) -> (u16, Option<String>) {
        let res = app
            .oneshot(Request::get(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let cc = res
            .headers()
            .get(header::CACHE_CONTROL)
            .map(|v| v.to_str().unwrap().to_owned());
        (res.status().as_u16(), cc)
    }

    #[tokio::test]
    async fn mounted_files_are_served_under_the_cache_policy() {
        let a = Assets::new(dir(), "/static");
        let app = a.mount(Router::new());
        let url = a.url("css/app.css");
        assert_eq!(
            cache_control(app.clone(), &url).await,
            (200, Some(IMMUTABLE.into()))
        );
        // No fingerprint, or another replica's: served, but revalidated.
        assert_eq!(
            cache_control(app.clone(), "/static/css/app.css").await,
            (200, Some("no-cache".into()))
        );
        assert_eq!(
            cache_control(app.clone(), "/static/css/app.css?v=0000").await,
            (200, Some("no-cache".into()))
        );
        // A miss is never pinned, whatever it claims.
        assert_eq!(
            cache_control(app, "/static/css/gone.css?v=0000").await,
            (404, Some("no-cache".into()))
        );
    }

    #[tokio::test]
    async fn a_pinned_revalidation_stays_immutable() {
        let d = dir().join("revalidate");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("app.js"), "1").unwrap();
        let a = Assets::new(&d, "/static");
        let app = a.mount(Router::new());
        let url = a.url("app.js");
        let first = app
            .clone()
            .oneshot(Request::get(&url).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let etag = first.headers().get(header::LAST_MODIFIED).cloned().unwrap();
        let req = Request::get(&url)
            .header(header::IF_MODIFIED_SINCE, etag)
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::NOT_MODIFIED);
        assert_eq!(res.headers()[header::CACHE_CONTROL], IMMUTABLE);
    }

    #[tokio::test]
    async fn dotfiles_and_traversal_are_not_served() {
        let d = dir();
        std::fs::write(d.join(".env"), "SECRET").unwrap();
        std::fs::create_dir_all(d.join(".git")).unwrap();
        std::fs::write(d.join(".git/config"), "x").unwrap();
        let name = format!("owt-assets-outside-{}.txt", std::process::id());
        let outside = d.parent().unwrap().join(&name);
        std::fs::write(&outside, "outside").unwrap();
        let a = Assets::new(&d, "/static");
        let app = a.mount(Router::new());
        let uris: Vec<String> = vec![
            "/static/.env".into(),
            "/static/%2eenv".into(),
            "/static/%2Eenv".into(),
            "/static/.git/config".into(),
            "/static/css/../.env".into(),
            format!("/static/../{name}"),
            format!("/static/%2e%2e/{name}"),
            format!("/static/%2E%2E/{name}"),
            format!("/static/css/%2e%2e/%2e%2e/{name}"),
            "/static//etc/passwd".into(),
            "/static/%2fetc%2fpasswd".into(),
        ];
        for uri in uris {
            let res = app
                .clone()
                .oneshot(Request::get(&uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(res.status(), StatusCode::NOT_FOUND, "{uri}");
        }
    }

    #[test]
    fn a_prefix_is_normalized() {
        for p in ["/static", "static", "/static/", "static/"] {
            assert_eq!(Assets::new("d", p).url("a.css"), "/static/a.css", "{p}");
        }
        assert_eq!(Assets::new("d", "/").url("a.css"), "/a.css");
    }

    #[test]
    fn the_macro_defines_assets_and_url() {
        let d = std::env::temp_dir().join(format!("owt-assets-macro-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("a.js"), "1").unwrap();
        let h = defined::assets().hash("a.js").unwrap();
        assert_eq!(defined::url("a.js"), format!("/s/a.js?v={h}"));
    }

    fn dir() -> PathBuf {
        let d = std::env::temp_dir().join(format!("owt-assets-{}", std::process::id()));
        std::fs::create_dir_all(d.join("css")).unwrap();
        std::fs::write(d.join("css/app.css"), "body{}").unwrap();
        d
    }

    #[test]
    fn urls_carry_the_content_hash() {
        let a = Assets::new(dir(), "/static/");
        let url = a.url("/css/app.css");
        let h = a.hash("css/app.css").unwrap();
        assert_eq!(url, format!("/static/css/app.css?v={h}"));
        assert_eq!(a.url("missing.js"), "/static/missing.js");
        assert_eq!(a.hash("../etc/passwd"), None);
        assert_eq!(a.hash("css/../../etc/passwd"), None);
        assert_eq!(a.hash("/etc/passwd"), None);
        assert_eq!(a.hash(""), None);
    }

    #[test]
    fn warming_hashes_every_served_file_up_front() {
        let d = dir().join("warm");
        std::fs::create_dir_all(d.join("sub/deep")).unwrap();
        std::fs::create_dir_all(d.join(".git")).unwrap();
        std::fs::write(d.join("a.js"), "1").unwrap();
        std::fs::write(d.join("sub/b.js"), "2").unwrap();
        std::fs::write(d.join("sub/deep/c.js"), "3").unwrap();
        std::fs::write(d.join(".env"), "SECRET").unwrap();
        std::fs::write(d.join(".git/config"), "x").unwrap();
        let a = Assets::new(&d, "/s");
        assert_eq!(a.warm(), 3);
        // Replaced after warming, a file keeps the hash it had at startup, and the
        // memo holds exactly the served files.
        let before = a.hash("sub/b.js");
        std::fs::write(d.join("sub/b.js"), "changed").unwrap();
        assert_eq!(a.hash("sub/b.js"), before);
        assert_eq!(a.0.hashes.read().unwrap().len(), 3);
        // Watching hashes on every call, so there is nothing to warm.
        assert_eq!(Assets::new(&d, "/s").watch(true).warm(), 0);
        assert_eq!(Assets::new(d.join("missing"), "/s").warm(), 0);
    }

    #[tokio::test]
    async fn a_cold_pinned_request_is_hashed_and_served_immutable() {
        // Hashed on the blocking pool the first time, and from the memo after.
        let d = dir().join("cold");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("app.js"), "1").unwrap();
        let url = Assets::new(&d, "/static").url("app.js");
        let cold = Assets::new(&d, "/static");
        let app = cold.mount(Router::new());
        assert!(cold.memoized("app.js").is_none());
        assert_eq!(
            cache_control(app.clone(), &url).await,
            (200, Some(IMMUTABLE.into()))
        );
        assert!(cold.memoized("app.js").is_some());
        assert_eq!(
            cache_control(app, &url).await,
            (200, Some(IMMUTABLE.into()))
        );
    }

    const SHEET: &str = r#"@import "base.css";
@font-face { src: url(../fonts/a.woff2) format("woff2"), url( 'b.woff2#frag' ); }
.d { background: url(data:image/png;base64,AAAA) }
.e { background: url(https://example.com/x.png), url(//cdn.example.com/y.png) }
.f { background: url(/abs.png), url(#id), url(../fonts/a.woff2?x=1), url(missing.png) }
/* url(../fonts/a.woff2) */
.g { content: "url(../fonts/a.woff2)" }
"#;

    /// A directory with a stylesheet that refers to a font and to another stylesheet.
    fn sheet_dir(name: &str, font: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("owt-assets-{name}-{}", std::process::id()));
        std::fs::create_dir_all(d.join("css")).unwrap();
        std::fs::create_dir_all(d.join("fonts")).unwrap();
        std::fs::write(d.join("css/app.css"), SHEET).unwrap();
        std::fs::write(d.join("css/base.css"), "body{margin:0}").unwrap();
        std::fs::write(d.join("css/b.woff2"), "bee").unwrap();
        std::fs::write(d.join("fonts/a.woff2"), font).unwrap();
        d
    }

    async fn get(app: &Router, req: Request<Body>) -> (Response, String) {
        let res = app.clone().oneshot(req).await.unwrap();
        let (parts, body) = res.into_parts();
        let bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
        (
            Response::from_parts(parts, Body::empty()),
            String::from_utf8(bytes.to_vec()).unwrap(),
        )
    }

    #[tokio::test]
    async fn stylesheet_urls_are_versioned() {
        let a = Assets::new(sheet_dir("sheet", "font-1"), "/static");
        let app = a.mount(Router::new());
        let font = a.hash("fonts/a.woff2").unwrap();
        let bee = a.hash("css/b.woff2").unwrap();
        let base = a.hash("css/base.css").unwrap();
        let (res, body) = get(
            &app,
            Request::get(a.url("css/app.css"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(res.headers()[header::CACHE_CONTROL], IMMUTABLE);
        assert_eq!(res.headers()[header::CONTENT_TYPE], "text/css");
        assert_eq!(
            res.headers()[header::CONTENT_LENGTH],
            body.len().to_string()
        );
        assert_eq!(
            res.headers()[header::ETAG],
            format!("\"{}\"", a.hash("css/app.css").unwrap())
        );
        assert_eq!(
            body,
            SHEET
                .replace("\"base.css\"", &format!("\"base.css?v={base}\""))
                .replacen(
                    "(../fonts/a.woff2)",
                    &format!("(../fonts/a.woff2?v={font})"),
                    1
                )
                .replace("'b.woff2#frag'", &format!("'b.woff2?v={bee}#frag'"))
        );

        // The fonts the stylesheet now names are pinned, under their own hash only.
        let pinned = format!("/static/fonts/a.woff2?v={font}");
        assert_eq!(
            cache_control(app.clone(), &pinned).await,
            (200, Some(IMMUTABLE.into()))
        );
        assert_eq!(
            cache_control(app.clone(), "/static/fonts/a.woff2?v=0000").await,
            (200, Some("no-cache".into()))
        );
        assert_eq!(
            cache_control(app, &format!("/static/css/base.css?v={base}")).await,
            (200, Some(IMMUTABLE.into()))
        );
    }

    #[tokio::test]
    async fn a_stylesheet_revalidates_by_etag_and_answers_head() {
        let a = Assets::new(sheet_dir("etag", "font-1"), "/static");
        let app = a.mount(Router::new());
        let url = a.url("css/app.css");
        let etag = format!("\"{}\"", a.hash("css/app.css").unwrap());
        for tags in [etag.clone(), format!("\"x\", W/{etag}"), "*".to_owned()] {
            let req = Request::get(&url)
                .header(header::IF_NONE_MATCH, tags)
                .body(Body::empty())
                .unwrap();
            let (res, body) = get(&app, req).await;
            assert_eq!(res.status(), StatusCode::NOT_MODIFIED);
            assert_eq!(res.headers()[header::CACHE_CONTROL], IMMUTABLE);
            assert_eq!(res.headers()[header::ETAG], etag.as_str());
            assert_eq!(body, "");
        }
        let req = Request::get(&url)
            .header(header::IF_NONE_MATCH, "\"other\"")
            .body(Body::empty())
            .unwrap();
        assert_eq!(get(&app, req).await.0.status(), StatusCode::OK);

        let (full, body) = get(&app, Request::get(&url).body(Body::empty()).unwrap()).await;
        let (head, empty) = get(&app, Request::head(&url).body(Body::empty()).unwrap()).await;
        assert_eq!(empty, "");
        assert_eq!(
            head.headers()[header::CONTENT_LENGTH],
            body.len().to_string()
        );
        assert_eq!(head.headers()[header::ETAG], full.headers()[header::ETAG]);
    }

    #[test]
    fn a_stylesheets_hash_folds_in_what_it_references() {
        let one = Assets::new(sheet_dir("fold1", "font-1"), "/s");
        let two = Assets::new(sheet_dir("fold2", "font-2"), "/s");
        assert_ne!(one.hash("css/app.css"), two.hash("css/app.css"));
        assert_eq!(one.hash("css/base.css"), two.hash("css/base.css"));
        // An imported stylesheet changing changes the importer.
        let d = sheet_dir("fold3", "font-1");
        let before = Assets::new(&d, "/s").hash("css/app.css");
        std::fs::write(d.join("css/base.css"), "body{margin:1px}").unwrap();
        assert_ne!(Assets::new(&d, "/s").hash("css/app.css"), before);
        // A stylesheet with nothing to version hashes as its bytes.
        let mut h = DefaultHasher::new();
        h.write(b"body{margin:0}");
        assert_eq!(
            one.hash("css/base.css"),
            Some(format!("{:016x}", h.finish()))
        );
    }

    #[tokio::test]
    async fn stylesheet_references_that_loop_or_escape_are_left_alone() {
        let d = std::env::temp_dir().join(format!("owt-assets-loop-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("a.css"), "@import 'b.css';").unwrap();
        std::fs::write(
            d.join("b.css"),
            "@import 'a.css'; i{background:url(../x.png)}",
        )
        .unwrap();
        let a = Assets::new(&d, "/s");
        let app = a.mount(Router::new());
        // Each is built with the other cut off where the loop closes; neither hangs.
        let (res, body) = get(&app, Request::get("/s/a.css").body(Body::empty()).unwrap()).await;
        assert_eq!(res.status(), StatusCode::OK);
        assert!(body.starts_with("@import 'b.css?v="), "{body}");
        let (res, body) = get(&app, Request::get("/s/b.css").body(Body::empty()).unwrap()).await;
        assert_eq!(res.status(), StatusCode::OK);
        assert!(body.starts_with("@import 'a.css?v="), "{body}");
        // A reference above the directory is not a file inside it.
        assert!(body.ends_with("i{background:url(../x.png)}"), "{body}");
    }

    #[test]
    fn resolving_a_reference_stays_inside_the_directory() {
        assert_eq!(resolve("css", "a.woff2").as_deref(), Some("css/a.woff2"));
        assert_eq!(
            resolve("css", "./../fonts//a.woff2").as_deref(),
            Some("fonts/a.woff2")
        );
        assert_eq!(resolve("", "a/b.png").as_deref(), Some("a/b.png"));
        for bad in [
            "",
            "#x",
            "/a.png",
            "//h/a.png",
            "data:x",
            "https://h/a",
            "../a.png",
            "css/../../a",
            ".env",
            "a/.git/x",
            "a?b",
            "a%20b",
            "a\\b",
        ] {
            let dir = if bad.starts_with("../") || bad.contains("../../") {
                ""
            } else {
                "css"
            };
            assert_eq!(resolve(dir, bad), None, "{bad}");
        }
    }

    #[test]
    fn references_skip_comments_and_strings() {
        let css = "a{b:url(x.png)} /* url(y.png) */ c{content:'url(z.png)'} @import \"q.css\"; @import url( 'w.css' ); d{e:URL(\"v.png\")} u{background:myurl(n.png)}";
        let found: Vec<&str> = references(css).into_iter().map(|r| &css[r]).collect();
        assert_eq!(found, ["x.png", "q.css", "w.css", "v.png"]);
    }

    #[test]
    fn watching_sees_rebuilds() {
        let d = dir().join("w");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("a.css"), "1").unwrap();
        let a = Assets::new(&d, "/s").watch(true);
        let before = a.hash("a.css");
        std::fs::write(d.join("a.css"), "2").unwrap();
        assert_ne!(a.hash("a.css"), before);
    }
}
