//! Fingerprinted static asset URLs.
//!
//! Templates name a static file through [`Assets::url`], which appends its content
//! hash (`?v=`). A request whose `v` matches the file's current hash is served
//! `immutable`; anything else (no `v`, or a hash another replica minted mid-rollout)
//! is `no-cache`, so a stale file can never be pinned in a browser or at the edge
//! under a URL that claims to be current.
//!
//! The hash is of the bytes on disk, computed on first use and memoized per existing
//! file (misses are not stored, so request paths cannot grow the map). With
//! `watch(true)`, typically in debug builds, it is recomputed on every call, so a
//! Tailwind `--watch` rebuild is never served under a stale fingerprint.

use std::collections::HashMap;
use std::hash::{DefaultHasher, Hasher};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use axum::extract::{Request, State};
use axum::http::{HeaderValue, header};
use axum::middleware::Next;
use axum::response::Response;

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

/// `Cache-Control` for bytes fully determined by their URL.
pub const IMMUTABLE: &str = "public, max-age=31536000, immutable";

impl Assets {
    /// Files in `dir`, served under `prefix` (e.g. `/static`).
    pub fn new(dir: impl Into<PathBuf>, prefix: &str) -> Self {
        Self(Arc::new(Inner {
            dir: dir.into(),
            prefix: prefix.trim_end_matches('/').to_owned(),
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

    /// Middleware body for the static service, nested under the prefix (so the URI
    /// path is relative to the directory): `immutable` when `v` is the current hash,
    /// else `no-cache`.
    pub async fn cache_policy(State(this): State<Self>, req: Request, next: Next) -> Response {
        let path = req.uri().path().trim_start_matches('/').to_owned();
        let pinned = req
            .uri()
            .query()
            .and_then(|q| q.split('&').find_map(|kv| kv.strip_prefix("v=")))
            .is_some_and(|v| this.hash(&path).is_some_and(|h| h == v));
        let mut res = next.run(req).await;
        let policy = if pinned && res.status().is_success() {
            IMMUTABLE
        } else {
            "no-cache"
        };
        res.headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static(policy));
        res
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
