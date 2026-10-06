//! Typed sessions sealed in a cookie.
//!
//! The session is the cookie: its value is the session's id, its expiry and the app's
//! data `T`, encrypted and authenticated with AES-GCM under a key derived from the
//! session secret. Nothing is stored server-side, so reading a session costs no query
//! and any replica opens any session. The costs of that choice:
//!
//! * **Size.** `T` travels on every request; keep it to identifiers and small flags.
//! * **Revocation.** A sealed cookie is valid until it lapses. Revoke by epoch: store a
//!   per-account counter in `T` at sign-in, compare on every load, bump it to sign the
//!   account out everywhere.
//! * **Secret rotation** signs everyone out.
//!
//! The id is opaque and random. It survives data changes, [`Session::cycle_id`]
//! replaces it (at sign-in, against fixation) and [`Session::flush`] replaces it and
//! the data (at sign-out). An app may use the id as a guest's identity.

use std::marker::PhantomData;
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

/// What a session's data must be.
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
    _data: PhantomData<fn() -> T>,
}

impl<T> Clone for Sessions<T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            _data: PhantomData,
        }
    }
}

struct Config {
    key: Key,
    cookie: String,
    max_age: Duration,
    secure: bool,
}

/// What the cookie holds, before sealing. Field names are short: they ride on every
/// request.
#[derive(Serialize, Deserialize)]
struct Sealed<T> {
    #[serde(rename = "k")]
    id: String,
    /// Unix seconds; the cookie is no session after this, whatever its holder does.
    #[serde(rename = "x")]
    expires: u64,
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
    /// when `secure` (always, outside plain-HTTP development).
    pub fn new(key: Key, cookie: impl Into<String>, max_age: Duration, secure: bool) -> Self {
        Self {
            inner: Arc::new(Config {
                key,
                cookie: cookie.into(),
                max_age,
                secure,
            }),
            _data: PhantomData,
        }
    }

    /// The cookie's name.
    #[must_use]
    pub fn cookie_name(&self) -> &str {
        &self.inner.cookie
    }

    /// The cookie value for a session with `id` and `data`, expiring `max_age` from
    /// now: what a response sets, and what a seeder hands a load generator.
    pub fn seal(&self, id: &str, data: &T) -> String {
        let sealed = Sealed {
            id: id.to_owned(),
            expires: now() + self.inner.max_age.as_secs(),
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
        let mut jar = cookie::CookieJar::new();
        jar.add_original(Cookie::new(self.inner.cookie.clone(), value.to_owned()));
        let opened = jar.private(&self.inner.key).get(&self.inner.cookie)?;
        let sealed: Sealed<T> = serde_json::from_str(opened.value()).ok()?;
        (sealed.expires > now()).then_some((sealed.id, sealed.data))
    }

    fn open(&self, headers: &HeaderMap) -> Option<(String, T)> {
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
            .find_map(|c| self.unseal(c.value()))
    }

    /// The `Set-Cookie` value for a session.
    fn set_cookie(&self, id: &str, data: &T) -> Option<HeaderValue> {
        let max_age = i64::try_from(self.inner.max_age.as_secs()).unwrap_or(i64::MAX);
        let c = Cookie::build((self.inner.cookie.clone(), self.seal(id, data)))
            .path("/")
            .http_only(true)
            .secure(self.inner.secure)
            .same_site(SameSite::Lax)
            .max_age(cookie::time::Duration::seconds(max_age))
            .build();
        HeaderValue::from_str(&c.encoded().to_string()).ok()
    }

    /// Middleware body, for `from_fn_with_state(sessions, Sessions::layer)`: open the
    /// request's session, expose it to handlers as [`Session<T>`], and seal it afresh
    /// into the response if anything changed it.
    pub async fn layer(State(this): State<Self>, mut req: Request, next: Next) -> Response {
        let session = Session::<T>::default();
        if let Some((id, data)) = this.open(req.headers()) {
            let mut inner = session.inner();
            inner.id = Some(id);
            inner.data = data;
        }
        req.extensions_mut().insert(session.clone());
        let mut response = next.run(req).await;
        let changed = {
            let inner = session.inner();
            inner
                .modified
                .then(|| (inner.id.clone().unwrap_or_else(new_id), inner.data.clone()))
        };
        if let Some(v) = changed.and_then(|(id, data)| this.set_cookie(&id, &data)) {
            response.headers_mut().append(header::SET_COOKIE, v);
        }
        response
    }
}

struct Inner<T> {
    id: Option<String>,
    data: T,
    modified: bool,
}

impl<T: Default> Default for Inner<T> {
    fn default() -> Self {
        Self {
            id: None,
            data: T::default(),
            modified: false,
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

    /// A new id, the same data: at sign-in, against session fixation.
    pub fn cycle_id(&self) {
        let mut inner = self.inner();
        inner.id = Some(new_id());
        inner.modified = true;
    }

    /// A new id and empty data: at sign-out.
    pub fn flush(&self) {
        let mut inner = self.inner();
        inner.id = Some(new_id());
        inner.data = T::default();
        inner.modified = true;
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
}
