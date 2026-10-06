//! Typed sessions sealed in a cookie.
//!
//! The session is the cookie: its value is the session's id, its expiry and the app's
//! data `T`, encrypted and authenticated with AES-GCM under a key derived from the
//! session secret. Nothing is stored server-side, so reading a session costs no query
//! and any replica opens any session. The costs of that choice:
//!
//! * **Size.** `T` travels on every request; keep it to identifiers and small flags.
//!   A sealed cookie over 4 KB is dropped by browsers (sign-out included); the layer
//!   logs a warning when it seals one.
//! * **Revocation.** A sealed cookie is valid until it lapses, and [`Session::flush`]
//!   only replaces the browser's copy: a copy taken earlier still opens. Revoke by
//!   epoch: store a per-account counter in `T` at sign-in, bump it at sign-out and at
//!   a password change, and compare the two in [`Sessions::validate_with`], which
//!   the layer asks about every session it opens.
//! * **Lifetime.** A change re-seals the cookie for another `max_age`, but never past
//!   [`Sessions::absolute_lifetime`] from when the session began (sign-in, or a
//!   guest's first id).
//! * **Secret rotation** signs everyone out, unless the old secret is kept for
//!   opening with [`Sessions::also_open_with`] until its sessions have lapsed.
//!
//! A response that sets the cookie is marked uncacheable, whatever the handler said:
//! a shared cache must never replay one person's session to the next.
//!
//! The id is opaque and random. It survives data changes, [`Session::cycle_id`]
//! replaces it (at sign-in, against fixation) and [`Session::flush`] replaces it and
//! the data (at sign-out). An app may use the id as a guest's identity.

use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::extract::{FromRequestParts, Request, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, header};
use axum::middleware::Next;
use axum::response::Response;
use cookie::{Cookie, Key, SameSite};
use rand::RngExt;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

/// What a session's data must be. Its serialized field names share the cookie with
/// the envelope's, so none may be `k`, `x` or `i`.
pub trait SessionData:
    Serialize + DeserializeOwned + Default + Clone + Send + Sync + 'static
{
}
impl<T: Serialize + DeserializeOwned + Default + Clone + Send + Sync + 'static> SessionData for T {}

/// A new random session id: 32 characters of `[a-z0-9]`.
#[must_use]
pub fn new_id() -> String {
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::rng();
    (0..32)
        .map(|_| CHARS[rng.random_range(0..CHARS.len())] as char)
        .collect()
}

/// The session secret as a cookie key: base64 of at least 64 random bytes.
pub fn key_from_base64(secret: &str) -> anyhow::Result<Key> {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(secret.trim())
        .map_err(|e| anyhow::anyhow!("the session secret is not base64: {e}"))?;
    anyhow::ensure!(
        bytes.len() >= 64,
        "the session secret must be at least 64 bytes (it is {})",
        bytes.len()
    );
    Ok(Key::from(&bytes))
}

/// How sessions are sealed and where they travel. Cheap to clone; hold one in the
/// app's state and hand it to [`Sessions::layer`].
pub struct Sessions<T> {
    inner: Arc<Config>,
    validator: Option<Validator<T>>,
}

impl<T> Clone for Sessions<T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            validator: self.validator.clone(),
        }
    }
}

type Validator<T> =
    Arc<dyn Fn(Presented<T>) -> Pin<Box<dyn Future<Output = Verdict> + Send>> + Send + Sync>;

/// What [`Sessions::validate_with`] decides about a session. A `bool` converts:
/// `true` is [`Verdict::Valid`], `false` is [`Verdict::Revoked`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// It stands.
    Valid,
    /// It was revoked: it is no session, and its cookie is removed.
    Revoked,
    /// It could not be checked (the database did not answer). It is no session for
    /// this request, and the cookie is kept: an outage must neither let a revoked
    /// session through nor sign everyone out. A handler's changes are dropped,
    /// except [`Session::flush`] and [`Session::cycle_id`], which replace it.
    Unknown,
}

impl From<bool> for Verdict {
    fn from(valid: bool) -> Self {
        if valid { Self::Valid } else { Self::Revoked }
    }
}

/// A session a request presented, as [`Sessions::validate_with`] sees it.
#[derive(Clone, Debug)]
pub struct Presented<T> {
    /// Its id.
    pub id: String,
    /// When it began, in Unix seconds.
    pub issued: u64,
    /// Its data.
    pub data: T,
}

#[derive(Clone)]
struct Config {
    key: Key,
    /// Keys that still open sessions and seal none: a rotation's predecessors.
    old_keys: Vec<Key>,
    cookie: String,
    max_age: Duration,
    absolute: Duration,
    secure: bool,
}

/// About the most a browser stores for one cookie, name and attributes included.
const MAX_COOKIE_BYTES: usize = 4096;

/// The longest a session lasts, however often it is re-sealed, unless
/// [`Sessions::absolute_lifetime`] says otherwise (or `max_age` is longer).
pub const ABSOLUTE_LIFETIME: Duration = Duration::from_secs(30 * 24 * 3600);

/// What the cookie holds, before sealing. Field names are short: they ride on every
/// request.
#[derive(Serialize, Deserialize)]
struct Sealed<T> {
    #[serde(rename = "k")]
    id: String,
    /// Unix seconds; the cookie is no session after this, whatever its holder does.
    #[serde(rename = "x")]
    expires: u64,
    /// Unix seconds at which the session began; a cookie without it began at 0, so
    /// it has outlived any lifetime.
    #[serde(rename = "i", default)]
    issued: u64,
    #[serde(flatten)]
    data: T,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

impl<T: SessionData> Sessions<T> {
    /// Sessions sealed with `key` in the cookie `cookie`, good for `max_age`, `Secure`
    /// when `secure` (always, outside plain-HTTP development). Name the cookie
    /// `__Host-<name>` in production: browsers then refuse a copy set over plain HTTP
    /// or by a sibling subdomain. A `__Host-` or `__Secure-` name is always `Secure`.
    pub fn new(key: Key, cookie: impl Into<String>, max_age: Duration, secure: bool) -> Self {
        let cookie = cookie.into();
        let secure = secure || cookie.starts_with("__Host-") || cookie.starts_with("__Secure-");
        Self {
            inner: Arc::new(Config {
                key,
                old_keys: Vec::new(),
                cookie,
                max_age,
                absolute: ABSOLUTE_LIFETIME.max(max_age),
                secure,
            }),
            validator: None,
        }
    }

    /// End every session this long after it began, however recently it was re-sealed.
    #[must_use]
    pub fn absolute_lifetime(mut self, lifetime: Duration) -> Self {
        Arc::make_mut(&mut self.inner).absolute = lifetime;
        self
    }

    /// Also open sessions sealed with `key`, the secret before a rotation. Drop it
    /// once `max_age` has passed since the rotation.
    #[must_use]
    pub fn also_open_with(mut self, key: Key) -> Self {
        Arc::make_mut(&mut self.inner).old_keys.push(key);
        self
    }

    /// Ask `valid` about every session the layer opens; it answers with a
    /// [`Verdict`], or a `bool`. This is where revocation lives: compare the epoch in
    /// the session's data with the account's (see the module docs), and answer
    /// [`Verdict::Unknown`] when the comparison could not be made. It runs on every
    /// request that carries a session, so make it one indexed read, or a cached one.
    #[must_use]
    pub fn validate_with<F, Fut, V>(mut self, valid: F) -> Self
    where
        F: Fn(Presented<T>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = V> + Send + 'static,
        V: Into<Verdict>,
    {
        self.validator = Some(Arc::new(move |p| {
            let verdict = valid(p);
            Box::pin(async move { verdict.await.into() })
        }));
        self
    }

    /// The cookie's name.
    #[must_use]
    pub fn cookie_name(&self) -> &str {
        &self.inner.cookie
    }

    /// The cookie value for a session with `id` and `data`, beginning now and
    /// expiring `max_age` from now: what a seeder hands a load generator.
    pub fn seal(&self, id: &str, data: &T) -> String {
        self.seal_begun(id, now(), data)
    }

    /// The cookie value for a session that began at `issued`: good for `max_age`
    /// from now, and never past its absolute lifetime.
    fn seal_begun(&self, id: &str, issued: u64, data: &T) -> String {
        let sealed = Sealed {
            id: id.to_owned(),
            expires: (now() + self.inner.max_age.as_secs())
                .min(issued.saturating_add(self.inner.absolute.as_secs())),
            issued,
            data: data.clone(),
        };
        let plain = serde_json::to_string(&sealed).unwrap_or_default();
        let mut jar = cookie::CookieJar::new();
        jar.private_mut(&self.inner.key)
            .add(Cookie::new(self.inner.cookie.clone(), plain));
        jar.get(&self.inner.cookie)
            .map(|c| c.value().to_owned())
            .unwrap_or_default()
    }

    /// The id and data `value` seals, if it was sealed with this key and hasn't lapsed.
    /// Anything else (tampered, forged, another secret, expired, another shape) is no
    /// session.
    #[must_use]
    pub fn unseal(&self, value: &str) -> Option<(String, T)> {
        self.unseal_presented(value).map(|p| (p.id, p.data))
    }

    fn unseal_presented(&self, value: &str) -> Option<Presented<T>> {
        let mut jar = cookie::CookieJar::new();
        jar.add_original(Cookie::new(self.inner.cookie.clone(), value.to_owned()));
        let opened = std::iter::once(&self.inner.key)
            .chain(&self.inner.old_keys)
            .find_map(|key| jar.private(key).get(&self.inner.cookie))?;
        let sealed: Sealed<T> = serde_json::from_str(opened.value()).ok()?;
        let now = now();
        let alive = sealed.expires > now
            && sealed.issued.saturating_add(self.inner.absolute.as_secs()) > now;
        alive.then_some(Presented {
            id: sealed.id,
            issued: sealed.issued,
            data: sealed.data,
        })
    }

    fn open(&self, headers: &HeaderMap) -> Option<Presented<T>> {
        headers
            .get_all(header::COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|raw| {
                Cookie::split_parse_encoded(raw.to_owned())
                    .flatten()
                    .collect::<Vec<_>>()
            })
            .filter(|c| c.name() == self.inner.cookie)
            .find_map(|c| self.unseal_presented(c.value()))
    }

    fn cookie(&self, value: String, max_age: u64) -> Option<HeaderValue> {
        let max_age = i64::try_from(max_age).unwrap_or(i64::MAX);
        let c = Cookie::build((self.inner.cookie.clone(), value))
            .path("/")
            .http_only(true)
            .secure(self.inner.secure)
            .same_site(SameSite::Lax)
            .max_age(cookie::time::Duration::seconds(max_age))
            .build();
        let encoded = c.encoded().to_string();
        if encoded.len() > MAX_COOKIE_BYTES {
            // Browsers drop it without a word, and every later change with it.
            tracing::warn!(
                cookie = %self.inner.cookie,
                bytes = encoded.len(),
                "session cookie over 4 KB; browsers will ignore it"
            );
        }
        HeaderValue::from_str(&encoded).ok()
    }

    /// The `Set-Cookie` value for a session.
    fn set_cookie(&self, id: &str, issued: u64, data: &T) -> Option<HeaderValue> {
        self.cookie(
            self.seal_begun(id, issued, data),
            self.inner.max_age.as_secs(),
        )
    }

    /// Middleware body, for `from_fn_with_state(sessions, Sessions::layer)`: open the
    /// request's session, expose it to handlers as [`Session<T>`], and seal it afresh
    /// into the response if anything changed it. A response that sets the cookie is
    /// never cacheable.
    pub async fn layer(State(this): State<Self>, mut req: Request, next: Next) -> Response {
        let session = Session::<T>::default();
        let (mut refused, mut unchecked) = (false, false);
        if let Some(presented) = this.open(req.headers()) {
            let verdict = match &this.validator {
                Some(valid) => valid(presented.clone()).await,
                None => Verdict::Valid,
            };
            match verdict {
                Verdict::Valid => {
                    let mut inner = session.inner();
                    inner.id = Some(presented.id);
                    inner.issued = Some(presented.issued);
                    inner.data = presented.data;
                }
                Verdict::Revoked => refused = true,
                Verdict::Unknown => unchecked = true,
            }
        }
        req.extensions_mut().insert(session.clone());
        let mut response = next.run(req).await;
        let changed = {
            let inner = session.inner();
            // A handler that saw no session because it could not be checked must not
            // replace the cookie with the empty one it was shown, unless it replaced
            // the session outright: a sign-out or sign-in during an outage stands.
            (inner.modified && (!unchecked || inner.replaced)).then(|| {
                (
                    inner.id.clone().unwrap_or_else(new_id),
                    inner.issued.unwrap_or_else(now),
                    inner.data.clone(),
                )
            })
        };
        let set = match changed {
            Some((id, issued, data)) => this.set_cookie(&id, issued, &data),
            // Take a refused session's cookie away rather than open it every request.
            None if refused => this.cookie(String::new(), 0),
            None => None,
        };
        if let Some(v) = set {
            let h = response.headers_mut();
            h.append(header::SET_COOKIE, v);
            h.insert(
                header::CACHE_CONTROL,
                HeaderValue::from_static(crate::headers::NEVER_CACHE),
            );
        }
        response
    }
}

struct Inner<T> {
    id: Option<String>,
    /// When the session began; `None` until it is first sealed.
    issued: Option<u64>,
    data: T,
    modified: bool,
    /// The id was replaced ([`Session::cycle_id`], [`Session::flush`]): the handler
    /// means this session, whatever the one presented was.
    replaced: bool,
}

impl<T: Default> Default for Inner<T> {
    fn default() -> Self {
        Self {
            id: None,
            issued: None,
            data: T::default(),
            modified: false,
            replaced: false,
        }
    }
}

/// The current request's session. Cheap to clone; clones share state. A handler may
/// change it; the layer seals the change into the response.
pub struct Session<T>(Arc<Mutex<Inner<T>>>);

impl<T> Clone for Session<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T: Default> Default for Session<T> {
    fn default() -> Self {
        Self(Arc::default())
    }
}

impl<T> std::fmt::Debug for Session<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session").finish_non_exhaustive()
    }
}

impl<T: Default + Clone> Session<T> {
    fn inner(&self) -> MutexGuard<'_, Inner<T>> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The session's id, if it has one yet.
    #[must_use]
    pub fn id(&self) -> Option<String> {
        self.inner().id.clone()
    }

    /// The session's id, creating (and so persisting) one if it has none.
    #[must_use]
    pub fn ensure_id(&self) -> String {
        let mut inner = self.inner();
        if let Some(id) = &inner.id {
            return id.clone();
        }
        let id = new_id();
        inner.id = Some(id.clone());
        inner.modified = true;
        id
    }

    /// Read the data.
    pub fn read<R>(&self, f: impl FnOnce(&T) -> R) -> R {
        f(&self.inner().data)
    }

    /// Change the data; it is sealed into the response.
    pub fn update<R>(&self, f: impl FnOnce(&mut T) -> R) -> R {
        let mut inner = self.inner();
        inner.modified = true;
        f(&mut inner.data)
    }

    /// When the session began, in Unix seconds, if it has been sealed.
    #[must_use]
    pub fn issued(&self) -> Option<u64> {
        self.inner().issued
    }

    /// Whether anything changed it, so the response will reseal it.
    #[must_use]
    pub fn is_modified(&self) -> bool {
        self.inner().modified
    }

    /// A new id, the same data, and a new beginning: at sign-in, against session
    /// fixation.
    pub fn cycle_id(&self) {
        let mut inner = self.inner();
        inner.id = Some(new_id());
        inner.issued = None;
        inner.modified = true;
        inner.replaced = true;
    }

    /// A new id and empty data: at sign-out. The cookie it replaces still opens if
    /// someone kept a copy; revoke that with [`Sessions::validate_with`].
    pub fn flush(&self) {
        let mut inner = self.inner();
        inner.id = Some(new_id());
        inner.issued = None;
        inner.data = T::default();
        inner.modified = true;
        inner.replaced = true;
    }
}

impl<S: Send + Sync, T: SessionData> FromRequestParts<S> for Session<T> {
    type Rejection = std::convert::Infallible;

    /// The layer's session; an empty one (never persisted) where no layer ran.
    fn from_request_parts(
        parts: &mut Parts,
        _: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        std::future::ready(Ok(parts
            .extensions
            .get::<Session<T>>()
            .cloned()
            .unwrap_or_default()))
    }
}

#[cfg(test)]
mod tests {
    use axum::Router;
    use axum::body::Body;
    use axum::middleware::from_fn_with_state;
    use axum::routing::get;
    use tower::ServiceExt;

    use super::*;

    #[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
    struct Data {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        user: Option<i64>,
    }

    fn sessions() -> Sessions<Data> {
        Sessions::new(Key::generate(), "sid", Duration::from_secs(3600), true)
    }

    #[test]
    fn seals_round_trip_and_refuse_tampering() {
        let s = sessions();
        let v = s.seal("abc", &Data { user: Some(7) });
        assert_eq!(s.unseal(&v), Some(("abc".into(), Data { user: Some(7) })));
        let mut forged = v.clone().into_bytes();
        let last = forged.len() - 2;
        forged[last] = if forged[last] == b'A' { b'B' } else { b'A' };
        assert_eq!(s.unseal(std::str::from_utf8(&forged).unwrap()), None);
        assert_eq!(sessions().unseal(&v), None, "another key opens nothing");
    }

    #[test]
    fn lapsed_seals_are_no_session() {
        let s = Sessions::<Data>::new(Key::generate(), "sid", Duration::ZERO, true);
        assert_eq!(s.unseal(&s.seal("abc", &Data::default())), None);
    }

    #[test]
    fn keys_must_be_long_enough() {
        use base64::Engine;
        let b64 = |n| base64::engine::general_purpose::STANDARD.encode(vec![7u8; n]);
        assert!(key_from_base64(&b64(64)).is_ok());
        assert!(key_from_base64(&b64(32)).is_err());
        assert!(key_from_base64("not base64!").is_err());
    }

    #[tokio::test]
    async fn the_layer_seals_changes_and_only_changes() {
        let s = sessions();
        let app = Router::new()
            .route(
                "/login",
                get(|sess: Session<Data>| async move { sess.update(|d| d.user = Some(1)) }),
            )
            .route(
                "/who",
                get(|sess: Session<Data>| async move { format!("{:?}", sess.read(|d| d.user)) }),
            )
            .layer(from_fn_with_state(s.clone(), Sessions::<Data>::layer));

        let res = app
            .clone()
            .oneshot(Request::get("/login").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let set = res.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .to_owned();
        assert!(set.contains("HttpOnly") && set.contains("Secure") && set.contains("SameSite=Lax"));
        let pair = set.split(';').next().unwrap().to_owned();

        let res = app
            .oneshot(
                Request::get("/who")
                    .header(header::COOKIE, pair)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(
            res.headers().get(header::SET_COOKIE).is_none(),
            "reading changes nothing"
        );
        let body = http_body_util::BodyExt::collect(res.into_body())
            .await
            .unwrap()
            .to_bytes();
        assert_eq!(&body[..], b"Some(1)");
    }

    fn who() -> Router {
        Router::new()
            .route(
                "/login",
                get(|sess: Session<Data>| async move {
                    sess.update(|d| d.user = Some(1));
                    ([(header::CACHE_CONTROL, "public, s-maxage=600")], "in")
                }),
            )
            .route(
                "/who",
                get(|sess: Session<Data>| async move { format!("{:?}", sess.read(|d| d.user)) }),
            )
    }

    async fn get_with(app: Router, uri: &str, cookie: Option<&str>) -> Response {
        let mut req = Request::get(uri);
        if let Some(c) = cookie {
            req = req.header(header::COOKIE, c);
        }
        app.oneshot(req.body(Body::empty()).unwrap()).await.unwrap()
    }

    async fn text(res: Response) -> String {
        let body = http_body_util::BodyExt::collect(res.into_body())
            .await
            .unwrap()
            .to_bytes();
        String::from_utf8(body.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn a_response_that_sets_the_cookie_is_never_cacheable() {
        let app = who().layer(from_fn_with_state(sessions(), Sessions::<Data>::layer));
        let res = get_with(app, "/login", None).await;
        assert!(res.headers().contains_key(header::SET_COOKIE));
        assert_eq!(
            res.headers()[header::CACHE_CONTROL],
            crate::headers::NEVER_CACHE,
            "the handler's public policy is overridden"
        );
    }

    #[test]
    fn sessions_end_at_their_absolute_lifetime_however_fresh_the_seal() {
        let s = sessions().absolute_lifetime(Duration::from_secs(7200));
        let data = Data { user: Some(7) };
        assert!(
            s.unseal(&s.seal_begun("abc", now() - 7000, &data))
                .is_some()
        );
        // Sealed while the lifetime was longer, so its own expiry is still ahead.
        let lenient = s.clone().absolute_lifetime(ABSOLUTE_LIFETIME);
        let v = lenient.seal_begun("abc", now() - 7300, &data);
        assert!(lenient.unseal(&v).is_some());
        assert_eq!(s.unseal(&v), None);
    }

    #[test]
    fn a_rotated_key_still_opens_and_no_longer_seals() {
        let old = Sessions::<Data>::new(Key::generate(), "sid", Duration::from_secs(3600), true);
        let v = old.seal("abc", &Data { user: Some(7) });
        let new = sessions();
        assert_eq!(new.unseal(&v), None);
        let new = new.also_open_with(old.inner.key.clone());
        assert_eq!(new.unseal(&v), Some(("abc".into(), Data { user: Some(7) })));
        assert_eq!(old.unseal(&new.seal("abc", &Data::default())), None);
    }

    #[test]
    fn host_prefixed_cookies_are_always_secure() {
        let s = Sessions::<Data>::new(
            Key::generate(),
            "__Host-sid",
            Duration::from_secs(60),
            false,
        );
        let set = s.set_cookie("abc", now(), &Data::default()).unwrap();
        assert!(set.to_str().unwrap().contains("Secure"));
    }

    #[tokio::test]
    async fn a_refused_session_is_no_session_and_loses_its_cookie() {
        let s = sessions();
        let cookie = format!("sid={}", s.seal("abc", &Data { user: Some(7) }));
        let open = who().layer(from_fn_with_state(s.clone(), Sessions::<Data>::layer));
        assert_eq!(
            text(get_with(open, "/who", Some(&cookie)).await).await,
            "Some(7)"
        );

        let revoking = s.validate_with(|p: Presented<Data>| async move { p.data.user != Some(7) });
        let app = who().layer(from_fn_with_state(revoking, Sessions::<Data>::layer));
        let res = get_with(app, "/who", Some(&cookie)).await;
        let set = res.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .to_owned();
        assert!(
            set.starts_with("sid=;") && set.contains("Max-Age=0"),
            "{set}"
        );
        assert_eq!(text(res).await, "None");
    }

    #[tokio::test]
    async fn a_session_that_cannot_be_checked_is_withheld_and_kept() {
        let s = sessions();
        let cookie = format!("sid={}", s.seal("abc", &Data { user: Some(7) }));
        let down = s.validate_with(|_: Presented<Data>| async { Verdict::Unknown });
        let app = who().layer(from_fn_with_state(down, Sessions::<Data>::layer));
        let res = get_with(app.clone(), "/who", Some(&cookie)).await;
        assert!(
            res.headers().get(header::SET_COOKIE).is_none(),
            "the cookie is kept"
        );
        assert_eq!(text(res).await, "None");
        // Nor may a handler's change overwrite the cookie it never saw.
        let res = get_with(app, "/login", Some(&cookie)).await;
        assert!(res.headers().get(header::SET_COOKIE).is_none());
    }

    #[tokio::test]
    async fn a_sign_out_during_an_outage_still_replaces_the_cookie() {
        let s = sessions();
        let cookie = format!("sid={}", s.seal("abc", &Data { user: Some(7) }));
        let down = s
            .clone()
            .validate_with(|_: Presented<Data>| async { Verdict::Unknown });
        let app = Router::new()
            .route(
                "/logout",
                get(|sess: Session<Data>| async move { sess.flush() }),
            )
            .layer(from_fn_with_state(down, Sessions::<Data>::layer));
        let res = get_with(app, "/logout", Some(&cookie)).await;
        let set = res.headers()[header::SET_COOKIE].to_str().unwrap();
        let set = Cookie::parse_encoded(set).unwrap();
        let (id, data) = s.unseal(set.value()).unwrap();
        assert_ne!(id, "abc");
        assert_eq!(data, Data::default());
    }
}
