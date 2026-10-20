//! Fingerprinted static asset URLs, and the service that serves them.
//!
//! [`Assets::mount`] serves the directory under its prefix, and templates name a static
//! file through [`Assets::url`], which appends its content hash (`?v=`). A request
//! whose `v` matches the file's current hash is served `immutable`; anything else (no
//! `v`, or a hash another replica minted mid-rollout) is `no-cache`, so a stale file
//! can never be pinned in a browser or at the edge under a URL that claims to be
//! current.
//!
//! The hash is of the bytes on disk, computed on first use and memoized per existing
//! file (misses are not stored, so request paths cannot grow the map): the files are
//! fixed once the app is built, and a file replaced under a running process keeps its
//! first hash. With `watch(true)`, typically in debug builds, it is recomputed on
//! every call, so a Tailwind `--watch` rebuild is never served under a stale
//! fingerprint.
//!
//! The directory is served as it is: symlinks in it are followed, so it must hold
//! only files meant to be public. A path with a dotfile or dot-directory component
//! (`.env`, `.git/config`) is a 404, `/.well-known/` included, so an app serves that
//! from a route of its own; and a path that leaves the directory is never
//! served.

use std::collections::HashMap;
use std::hash::{DefaultHasher, Hasher};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use axum::Router;
use axum::extract::{Request, State};
use axum::http::{HeaderValue, StatusCode, header};
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

    /// The content hash of `path` (relative to the directory), or `None` if there is
    /// no such file. Paths that leave the directory (`..`, or an absolute path, which
    /// would replace it) have none.
    #[must_use]
    pub fn hash(&self, path: &str) -> Option<String> {
        use std::path::{Component, Path};
        let inside = Path::new(path)
            .components()
            .all(|c| matches!(c, Component::Normal(_)));
        if !inside || path.is_empty() {
            return None;
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
        let pinned = req
            .uri()
            .query()
            .and_then(|q| q.split('&').find_map(|kv| kv.strip_prefix("v=")))
            .is_some_and(|v| this.hash(&path).is_some_and(|h| h == v));
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
        let a = Assets::new(dir(), "/static");
        let app = a.mount(Router::new());
        let url = a.url("css/app.css");
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
