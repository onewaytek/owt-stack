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
//! * **Revocation.** A sealed cookie is valid until it lapses (the idle timeout or
//!   the absolute lifetime, whichever comes first), and [`Session::flush`] only
//!   replaces the browser's copy: a copy taken earlier still opens. Revoke by
//!   epoch: store a per-account counter in `T` at sign-in, bump it at sign-out and at
//!   a password change, and compare the two in [`Sessions::validate_with`], which
//!   the layer asks about every session it opens.
//! * **Lifetime.** A change re-seals the cookie for another `max_age`, but never past
//!   [`Sessions::absolute_lifetime`] ([`ABSOLUTE_LIFETIME`], 24 hours, unless set)
//!   from when the session began (sign-in, or a guest's first id).
//! * **Idle timeout.** [`Sessions::idle_timeout`] ([`IDLE_TIMEOUT`], 30 minutes,
//!   unless set or turned off with [`Sessions::without_idle_timeout`]): the cookie
//!   also carries when its holder was last active, and a session idle longer than the timeout is no
//!   session (its cookie is removed, and [`Session::idle_expired`] says why).
//!   Activity reseals that time, at most once per [`Sessions::idle_refresh`], so a
//!   busy page does not rewrite the cookie on every request. A request marked
//!   passive (the [`PASSIVE_HEADER`] header, or [`Session::passive`]) is not
//!   activity: a poll must not keep an unattended session alive.
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
/// the envelope's, so none may be `k`, `x`, `i` or `$s`.
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

/// The session secret as a cookie key: base64 of at least 64 random bytes. Prefer
/// [`key_for`], which keeps a secret copied between environments from being one key.
///
/// The secret is everything: whoever holds it seals a session for any account. Give
/// each app, in each environment, a secret of its own; a staging copy of
/// production's lets a staging account's cookie open production as the account with
/// the same id. [`key_for`] derives a key per app and environment, so a shared
/// secret is not also a shared key.
pub fn key_from_base64(secret: &str) -> anyhow::Result<Key> {
    Ok(Key::from(&secret_bytes(secret)?))
}

/// The key for sessions of `purpose` (the app and its environment, such as
/// `myapp/production` or the namespace it runs in), derived from the secret with
/// HKDF-SHA256. Two deployments whose purposes differ cannot open each other's
/// cookies even if they were given the same secret. Changing the purpose signs
/// everyone out, as changing the secret does.
///
/// The purpose is taken exactly: one with surrounding whitespace or a control
/// character is refused rather than trimmed, since `myapp/prod\n` (a stray newline
/// in a `ConfigMap`) would be another key, splitting replicas or signing everyone out.
pub fn key_for(secret: &str, purpose: &str) -> anyhow::Result<Key> {
    check_purpose(purpose)?;
    let master = secret_bytes(secret)?;
    let hkdf = hkdf::Hkdf::<sha2::Sha256>::new(Some(b"owt-web session key v1"), &master);
    let mut key = [0u8; 64];
    hkdf.expand(purpose.as_bytes(), &mut key)
        .map_err(|_| anyhow::anyhow!("HKDF-SHA256 refused a 64-byte key"))?;
    Ok(Key::from(&key))
}

/// A purpose [`key_for`] takes: not empty, without surrounding whitespace or a
/// control character.
fn check_purpose(purpose: &str) -> anyhow::Result<()> {
    anyhow::ensure!(!purpose.is_empty(), "a session key's purpose is empty");
    anyhow::ensure!(
        purpose.trim() == purpose && !purpose.chars().any(char::is_control),
        "a session key's purpose has surrounding whitespace or a control character: {purpose:?}"
    );
    Ok(())
}

/// The purpose [`Sessions::from_env`] derives its key for: `SESSION_KEY_PURPOSE`, the
/// whole purpose, when it is set; else `{app}/` and then `SESSION_PURPOSE`, else the
/// namespace the pod runs in (`POD_NAMESPACE`, which the downward API sets), else
/// `local`. `var` reads a variable; a blank one counts as unset.
///
/// Changing the purpose signs everyone out. An app moving onto this from a purpose of
/// its own keeps it: `SESSION_PURPOSE` set to what followed its `app/`, or
/// `SESSION_KEY_PURPOSE` set to the whole purpose when it has another shape. The
/// whole purpose is taken exactly, as [`key_for`] takes it.
#[must_use]
pub fn purpose_from(app: &str, var: impl Fn(&str) -> Option<String>) -> String {
    let set = |name: &str| var(name).filter(|v| !v.trim().is_empty());
    if let Some(purpose) = set("SESSION_KEY_PURPOSE") {
        return purpose;
    }
    let environment = set("SESSION_PURPOSE")
        .or_else(|| set("POD_NAMESPACE"))
        .unwrap_or_else(|| "local".into());
    format!("{app}/{environment}")
}

/// Fewer distinct byte values than this in a secret is a pattern, not randomness:
/// 64 random bytes take about 57 values, and fewer than 8 has odds far below 1e-60.
/// Low enough that base64 of text (hex digits take 16 values) still passes; that
/// is weaker than raw bytes for its length, but not a pattern.
const MIN_DISTINCT_BYTES: usize = 8;

/// The secret's bytes: base64 of at least 64, not a repetition.
fn secret_bytes(secret: &str) -> anyhow::Result<Vec<u8>> {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(secret.trim())
        .map_err(|e| anyhow::anyhow!("the session secret is not base64: {e}"))?;
    anyhow::ensure!(
        bytes.len() >= 64,
        "the session secret must be at least 64 bytes (it is {})",
        bytes.len()
    );
    let distinct = bytes
        .iter()
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    anyhow::ensure!(
        distinct >= MIN_DISTINCT_BYTES,
        "the session secret is a pattern ({distinct} distinct bytes), not random: \
         make one with `openssl rand 64 | base64 -w0`"
    );
    Ok(bytes)
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
    /// A session idle this long is no session.
    idle: Option<Duration>,
    /// The least time between two reseals of the last-active time.
    idle_refresh: Option<Duration>,
    secure: bool,
}

/// A request header that, set to `1`, marks the request as passive: not the person's
/// activity, so it does not extend an idle timeout (an htmx poll sends it with
/// `hx-headers='{"owt-passive": "1"}'`). Any other value is not passive.
pub const PASSIVE_HEADER: &str = "owt-passive";

/// The response header that tells the page how many whole seconds its session has
/// left before the idle timeout, on every response to a request that carried a
/// session, when [`Sessions::idle_timeout`] is set.
pub const IDLE_REMAINING_HEADER: &str = "owt-idle-remaining";

/// About the most a browser stores for one cookie, name and attributes included.
const MAX_COOKIE_BYTES: usize = 4096;

/// A `Set-Cookie` of this many bytes is one browsers drop without a word.
fn oversized(encoded_len: usize) -> bool {
    encoded_len > MAX_COOKIE_BYTES
}

/// The longest a session lasts, however often it is re-sealed, unless
/// [`Sessions::absolute_lifetime`] says otherwise (or `max_age` is longer): 24 hours,
/// NIST SP 800-63B-4's reauthentication bound at AAL2, so a copied cookie is good for
/// a day at most.
pub const ABSOLUTE_LIFETIME: Duration = Duration::from_hours(24);

/// How long a session lasts without activity, unless [`Sessions::idle_timeout`] says
/// otherwise or [`Sessions::without_idle_timeout`] turns it off: 30 minutes, NIST SP
/// 800-63B-4's inactivity bound at AAL2. A workforce app handling health data sets
/// less (15 minutes, AAL3's).
pub const IDLE_TIMEOUT: Duration = Duration::from_mins(30);

/// What the cookie holds, before sealing. Field names are short: they ride on every
/// request.
#[derive(Serialize, Deserialize)]
struct Sealed<T> {
    #[serde(rename = "k")]
    id: String,
    /// Unix seconds; the cookie is no session after this, whatever its holder does.
    #[serde(rename = "x")]
    expires: u64,
    /// Unix seconds at which the session began.
    #[serde(rename = "i")]
    issued: u64,
    /// Unix seconds of the holder's last recorded activity; a cookie without it was
    /// last active when it began. A name no Rust field serializes to unrenamed.
    #[serde(rename = "$s", default, skip_serializing_if = "Option::is_none")]
    seen: Option<u64>,
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
    /// when `secure` (always, outside plain-HTTP development), ending after
    /// [`IDLE_TIMEOUT`] without activity and [`ABSOLUTE_LIFETIME`] (or `max_age`, if
    /// longer) after they began. Name the cookie
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
                idle: Some(IDLE_TIMEOUT),
                idle_refresh: None,
                secure,
            }),
            validator: None,
        }
    }

    /// Sessions as [`new`](Self::new) makes them, keyed from the environment: the
    /// secret `SESSION_SECRET` (required), derived with [`key_for`] for the purpose
    /// [`purpose_from`] reads (`myapp/production`, `myapp/local`).
    ///
    /// # Errors
    ///
    /// `SESSION_SECRET` is unset or not a secret [`key_for`] takes, the purpose is not
    /// one it takes, or the app runs in a pod (`KUBERNETES_SERVICE_HOST` is set) and
    /// none of `SESSION_KEY_PURPOSE`, `SESSION_PURPOSE` and `POD_NAMESPACE` is: `local`
    /// is for development.
    /// The error names the variable, never the secret.
    pub fn from_env(
        app: &str,
        cookie: impl Into<String>,
        max_age: Duration,
        secure: bool,
    ) -> anyhow::Result<Self> {
        Self::from_vars(app, cookie, max_age, secure, |name| {
            std::env::var(name).ok()
        })
    }

    /// [`from_env`](Self::from_env), reading variables through `var`: a test's map,
    /// or configuration the app gathered itself.
    ///
    /// # Errors
    ///
    /// As [`from_env`](Self::from_env).
    pub fn from_vars(
        app: &str,
        cookie: impl Into<String>,
        max_age: Duration,
        secure: bool,
        var: impl Fn(&str) -> Option<String>,
    ) -> anyhow::Result<Self> {
        let secret = var("SESSION_SECRET")
            .filter(|v| !v.trim().is_empty())
            .ok_or_else(|| anyhow::anyhow!("SESSION_SECRET is not set"))?;
        let set = |name: &str| var(name).filter(|v| !v.trim().is_empty());
        // `local` is for development: in a pod it would make every environment's
        // purpose one, and a secret copied between them one key again.
        anyhow::ensure!(
            set("SESSION_KEY_PURPOSE").is_some()
                || set("SESSION_PURPOSE").is_some()
                || set("POD_NAMESPACE").is_some()
                || set("KUBERNETES_SERVICE_HOST").is_none(),
            "set SESSION_PURPOSE, SESSION_KEY_PURPOSE or POD_NAMESPACE: in a pod the session key's purpose is not `{app}/local`"
        );
        let purpose = purpose_from(app, &var);
        check_purpose(&purpose).map_err(|e| {
            let from = ["SESSION_KEY_PURPOSE", "SESSION_PURPOSE", "POD_NAMESPACE"]
                .into_iter()
                .find(|name| set(name).is_some())
                .unwrap_or("the app's name");
            anyhow::anyhow!("the session key's purpose, from {from}: {e}")
        })?;
        let key = key_for(&secret, &purpose)
            .map_err(|e| anyhow::anyhow!("the session key from SESSION_SECRET: {e}"))?;
        Ok(Self::new(key, cookie, max_age, secure))
    }

    /// End every session this long after it began, however recently it was re-sealed.
    #[must_use]
    pub fn absolute_lifetime(mut self, lifetime: Duration) -> Self {
        Arc::make_mut(&mut self.inner).absolute = lifetime;
        self
    }

    /// End a session after `timeout` without activity ([`IDLE_TIMEOUT`] unless set; a
    /// workforce app handling health data: 15 minutes, say). Activity is any request carrying the session
    /// that is not passive ([`PASSIVE_HEADER`], [`Session::passive`]) and does not end
    /// in a server error. The last-active time is resealed at most every
    /// [`idle_refresh`](Self::idle_refresh) (a tenth of the timeout, at least 15 s, by
    /// default), so a session ends between `timeout` minus that and `timeout` after
    /// the last activity.
    #[must_use]
    pub fn idle_timeout(mut self, timeout: Duration) -> Self {
        Arc::make_mut(&mut self.inner).idle = Some(timeout.max(Duration::from_secs(1)));
        self
    }

    /// Never end a session for inactivity, only at its absolute lifetime: for an app
    /// whose sessions guard nothing a copied cookie could misuse (a game's guest
    /// identity, say). A page then gets no [`IDLE_REMAINING_HEADER`].
    #[must_use]
    pub fn without_idle_timeout(mut self) -> Self {
        Arc::make_mut(&mut self.inner).idle = None;
        self
    }

    /// Reseal the last-active time at most this often (see
    /// [`idle_timeout`](Self::idle_timeout)).
    #[must_use]
    pub fn idle_refresh(mut self, every: Duration) -> Self {
        Arc::make_mut(&mut self.inner).idle_refresh = Some(every);
        self
    }

    /// The idle timeout, unless [`without_idle_timeout`](Self::without_idle_timeout)
    /// turned it off.
    #[must_use]
    pub fn idle(&self) -> Option<Duration> {
        self.inner.idle
    }

    /// The least age at which activity reseals the last-active time: the configured
    /// refresh (a tenth of the timeout, at least 15 s, by default), never more than
    /// half the timeout (or an active session could lapse between two reseals) and
    /// never under a second.
    fn refresh(&self) -> u64 {
        let Some(idle) = self.inner.idle else {
            return u64::MAX;
        };
        let wanted = self
            .inner
            .idle_refresh
            .unwrap_or_else(|| (idle / 10).max(Duration::from_secs(15)));
        wanted.min(idle / 2).max(Duration::from_secs(1)).as_secs()
    }

    /// The cookie that carries an activity-only refresh of the last-active time.
    fn seen_cookie_name(&self) -> String {
        format!("{}-seen", self.inner.cookie)
    }

    /// The sealed value of the last-active cookie for session `id`.
    fn seal_seen(&self, id: &str, seen: u64) -> String {
        let name = self.seen_cookie_name();
        let plain = serde_json::to_string(&Seen {
            id: id.to_owned(),
            seen,
        })
        .unwrap_or_default();
        let mut jar = cookie::CookieJar::new();
        jar.private_mut(&self.inner.key)
            .add(Cookie::new(name.clone(), plain));
        jar.get(&name)
            .map(|c| c.value().to_owned())
            .unwrap_or_default()
    }

    /// The last-active time a last-active cookie records for session `id`.
    fn unseal_seen(&self, value: &str, id: &str) -> Option<u64> {
        let name = self.seen_cookie_name();
        let mut jar = cookie::CookieJar::new();
        jar.add_original(Cookie::new(name.clone(), value.to_owned()));
        let opened = std::iter::once(&self.inner.key)
            .chain(&self.inner.old_keys)
            .find_map(|key| jar.private(key).get(&name))?;
        let seen: Seen = serde_json::from_str(opened.value()).ok()?;
        (seen.id == id).then_some(seen.seen)
    }

    /// Whether a session last active at `seen` is past the idle timeout.
    fn idle_lapsed(&self, seen: u64) -> bool {
        self.inner
            .idle
            .is_some_and(|idle| now().saturating_sub(seen) >= idle.as_secs())
    }

    /// Also open sessions sealed with `key`, the secret before a rotation. Drop it
    /// once `max_age` has passed since the rotation. Never after a compromise: a
    /// rotation because the old secret leaked must not open what it sealed, since its
    /// holder can seal any session, for any account, with any dates.
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

    /// Whether these sessions open one sealed with `key` under the same cookie name
    /// and lifetimes: what an app's test asserts before it changes the key's purpose
    /// or secret, so that the change, with [`also_open_with`](Self::also_open_with),
    /// signs no one out.
    #[must_use]
    pub fn opens(&self, key: &Key) -> bool {
        let mut config = (*self.inner).clone();
        config.key = key.clone();
        config.old_keys.clear();
        let other = Self {
            inner: Arc::new(config),
            validator: None,
        };
        self.unseal(&other.seal(&new_id(), &T::default())).is_some()
    }

    /// The cookie value for a session with `id` and `data`, beginning now and
    /// expiring `max_age` from now: what a seeder hands a load generator.
    pub fn seal(&self, id: &str, data: &T) -> String {
        let now = now();
        self.seal_begun(id, now, now, data)
    }

    /// The cookie value for a session that began at `issued` and was last active at
    /// `seen`: good for `max_age` from now, and never past its absolute lifetime.
    fn seal_begun(&self, id: &str, issued: u64, seen: u64, data: &T) -> String {
        let sealed = Sealed {
            id: id.to_owned(),
            expires: (now() + self.inner.max_age.as_secs())
                .min(issued.saturating_add(self.inner.absolute.as_secs())),
            issued,
            seen: self.inner.idle.map(|_| seen),
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
        match self.unseal_presented(value)? {
            Opened::Live(p, seen) if !self.idle_lapsed(seen) => Some((p.id, p.data)),
            _ => None,
        }
    }

    fn unseal_presented(&self, value: &str) -> Option<Opened<T>> {
        let mut jar = cookie::CookieJar::new();
        jar.add_original(Cookie::new(self.inner.cookie.clone(), value.to_owned()));
        let opened = std::iter::once(&self.inner.key)
            .chain(&self.inner.old_keys)
            .find_map(|key| jar.private(key).get(&self.inner.cookie))?;
        let sealed: Sealed<T> = serde_json::from_str(opened.value()).ok()?;
        let now = now();
        let alive = sealed.expires > now
            && sealed.issued.saturating_add(self.inner.absolute.as_secs()) > now;
        if !alive {
            return None;
        }
        // A time ahead of this replica's clock (another replica's skew) counts as now.
        let seen = sealed.seen.unwrap_or(sealed.issued).min(now);
        Some(Opened::Live(
            Presented {
                id: sealed.id,
                issued: sealed.issued,
                data: sealed.data,
            },
            seen,
        ))
    }

    /// The request's session: the session cookie, its last-active time raised by the
    /// last-active cookie when that names the same session, and the idle timeout
    /// applied.
    fn open(&self, headers: &HeaderMap) -> Option<Opened<T>> {
        let cookies: Vec<Cookie<'static>> = headers
            .get_all(header::COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|raw| {
                Cookie::split_parse_encoded(raw.to_owned())
                    .flatten()
                    .collect::<Vec<_>>()
            })
            .collect();
        let opened = cookies
            .iter()
            .filter(|c| c.name() == self.inner.cookie)
            .find_map(|c| self.unseal_presented(c.value()))?;
        let Opened::Live(presented, mut seen) = opened else {
            return Some(opened);
        };
        if self.inner.idle.is_some() {
            let seen_name = self.seen_cookie_name();
            if let Some(later) = cookies
                .iter()
                .filter(|c| c.name() == seen_name)
                .find_map(|c| self.unseal_seen(c.value(), &presented.id))
            {
                seen = seen.max(later.min(now()));
            }
            if self.idle_lapsed(seen) {
                return Some(Opened::Idle);
            }
        }
        Some(Opened::Live(presented, seen))
    }

    fn cookie(&self, value: String, max_age: u64) -> Option<HeaderValue> {
        self.named_cookie(self.inner.cookie.clone(), value, max_age)
    }

    fn named_cookie(&self, name: String, value: String, max_age: u64) -> Option<HeaderValue> {
        let max_age = i64::try_from(max_age).unwrap_or(i64::MAX);
        let c = Cookie::build((name, value))
            .path("/")
            .http_only(true)
            .secure(self.inner.secure)
            .same_site(SameSite::Lax)
            .max_age(cookie::time::Duration::seconds(max_age))
            .build();
        let encoded = c.encoded().to_string();
        if oversized(encoded.len()) {
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
    fn set_cookie(&self, id: &str, issued: u64, seen: u64, data: &T) -> Option<HeaderValue> {
        self.cookie(
            self.seal_begun(id, issued, seen, data),
            self.inner.max_age.as_secs(),
        )
    }

    /// Middleware body, for `from_fn_with_state(sessions, Sessions::layer)`: open the
    /// request's session, expose it to handlers as [`Session<T>`], and seal it afresh
    /// into the response if anything changed it. A response that sets the cookie is
    /// never cacheable. A server error (5xx, the `Limits` timeout's 503 included)
    /// keeps the session the request came with: a handler that signed someone in and
    /// then failed, or timed out, leaves them as they were. A sign-out
    /// ([`Session::flush`]) stands whatever the response: a server error after one
    /// seals an empty session, dropping anything the handler did after it.
    pub async fn layer(State(this): State<Self>, mut req: Request, next: Next) -> Response {
        let session = Session::<T>::default();
        {
            let mut inner = session.inner();
            inner.idle = this.inner.idle;
            inner.absolute = Some(this.inner.absolute);
        }
        let (mut refused, mut unchecked) = (false, false);
        let passive = req
            .headers()
            .get(PASSIVE_HEADER)
            .is_some_and(|v| v.as_bytes() == b"1");
        match this.open(req.headers()) {
            Some(Opened::Live(presented, seen)) => {
                let verdict = match &this.validator {
                    Some(valid) => valid(presented.clone()).await,
                    None => Verdict::Valid,
                };
                match verdict {
                    Verdict::Valid => {
                        let mut inner = session.inner();
                        inner.id = Some(presented.id);
                        inner.issued = Some(presented.issued);
                        inner.seen = Some(seen);
                        inner.data = presented.data;
                    }
                    Verdict::Revoked => refused = true,
                    Verdict::Unknown => unchecked = true,
                }
            }
            Some(Opened::Idle) => {
                refused = true;
                session.inner().idle_expired = true;
            }
            None => {}
        }
        req.extensions_mut().insert(session.clone());
        let mut response = next.run(req).await;
        let failed = response.status().is_server_error();
        let now = now();
        let changed = {
            let inner = session.inner();
            // A handler that saw no session because it could not be checked must not
            // replace the cookie with the empty one it was shown, unless it replaced
            // the session outright: a sign-out or sign-in during an outage stands.
            // A server error keeps the session the request came with, except a
            // sign-out: failing after it leaves an empty session, whatever the
            // handler did after it (a sign-in into the emptied session included).
            // A change reseals the session, with the last-active time at now unless
            // the request was passive. Activity alone, once the time is a refresh old,
            // sets only the last-active cookie, bound to the session's id: a request
            // that read a session another tab has since signed out of or into cannot
            // put that session back.
            let active = !passive && !inner.passive;
            let reseal = if failed {
                inner.flushed.then(|| (new_id(), now, now, T::default()))
            } else {
                (inner.modified && (!unchecked || inner.replaced)).then(|| {
                    let seen = match inner.seen {
                        Some(seen) if !active && inner.issued.is_some() => seen,
                        _ => now,
                    };
                    (
                        inner.id.clone().unwrap_or_else(new_id),
                        inner.issued.unwrap_or(now),
                        seen,
                        inner.data.clone(),
                    )
                })
            };
            let touch = (reseal.is_none()
                && !failed
                && !unchecked
                && active
                && this.inner.idle.is_some()
                && inner
                    .seen
                    .is_some_and(|seen| now.saturating_sub(seen) >= this.refresh()))
            .then(|| inner.id.clone())
            .flatten();
            // The time left, for a session that still stands: not after a sign-out.
            let seen = match (&reseal, &touch) {
                (Some(_), _) if inner.flushed => None,
                (Some((_, _, seen, _)), _) => Some(*seen),
                (None, Some(_)) => Some(now),
                (None, None) => inner.seen,
            };
            (reseal, touch, seen)
        };
        let (reseal, touch, seen) = changed;
        this.write(response.headers_mut(), reseal, touch, seen, refused, now);
        response
    }

    /// Write what the layer decided into the response's headers: the resealed
    /// session, a refused session's removal, the last-active cookie, the time left,
    /// and the cache policy any of them requires.
    fn write(
        &self,
        h: &mut HeaderMap,
        reseal: Option<(String, u64, u64, T)>,
        touch: Option<String>,
        seen: Option<u64>,
        refused: bool,
        now: u64,
    ) {
        let this = self;
        let mut set = Vec::new();
        match reseal {
            Some((id, issued, seen, data)) => set.extend(this.set_cookie(&id, issued, seen, &data)),
            // Take a refused session's cookies away rather than open them every request.
            None if refused => {
                set.extend(this.cookie(String::new(), 0));
                if this.inner.idle.is_some() {
                    set.extend(this.named_cookie(this.seen_cookie_name(), String::new(), 0));
                }
            }
            None => {}
        }
        if let Some(id) = touch {
            set.extend(this.named_cookie(
                this.seen_cookie_name(),
                this.seal_seen(&id, now),
                this.inner.max_age.as_secs(),
            ));
        }
        let mut private = !set.is_empty();
        for v in set {
            h.append(header::SET_COOKIE, v);
        }
        if let (Some(idle), Some(seen)) = (this.inner.idle, seen) {
            let left = idle.as_secs().saturating_sub(now.saturating_sub(seen));
            h.insert(IDLE_REMAINING_HEADER, HeaderValue::from(left));
            h.append(header::VARY, HeaderValue::from_static("cookie"));
            private = true;
        }
        if private {
            // One person's cookie, or their time left: never for a shared cache.
            h.insert(
                header::CACHE_CONTROL,
                HeaderValue::from_static(crate::headers::NEVER_CACHE),
            );
        }
    }
}

/// What the last-active cookie holds, before sealing: the session it belongs to and
/// when its holder was last active.
#[derive(Serialize, Deserialize)]
struct Seen {
    #[serde(rename = "k")]
    id: String,
    #[serde(rename = "s")]
    seen: u64,
}

/// A cookie that opened: a live session and its last-active time, or one past its
/// idle timeout.
enum Opened<T> {
    Live(Presented<T>, u64),
    Idle,
}

#[expect(
    clippy::struct_excessive_bools,
    reason = "independent facts about one request's session"
)]
struct Inner<T> {
    id: Option<String>,
    /// When the session began; `None` until it is first sealed.
    issued: Option<u64>,
    /// When its holder was last active, as the cookie recorded it.
    seen: Option<u64>,
    /// The idle timeout in force.
    idle: Option<Duration>,
    /// The absolute lifetime in force.
    absolute: Option<Duration>,
    /// The request presented a session that had passed its idle timeout.
    idle_expired: bool,
    /// The handler marked this request as not the person's activity.
    passive: bool,
    data: T,
    modified: bool,
    /// The id was replaced ([`Session::cycle_id`], [`Session::flush`]): the handler
    /// means this session, whatever the one presented was.
    replaced: bool,
    /// Emptied ([`Session::flush`]) at some point in the request: a sign-out, which
    /// stands even when the response is a server error. Nothing clears it.
    flushed: bool,
}

impl<T: Default> Default for Inner<T> {
    fn default() -> Self {
        Self {
            id: None,
            issued: None,
            seen: None,
            idle: None,
            absolute: None,
            idle_expired: false,
            passive: false,
            data: T::default(),
            modified: false,
            replaced: false,
            flushed: false,
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

    /// The last moment its cookie can open, in Unix seconds: when it began plus the
    /// absolute lifetime. `None` until it has been sealed, or outside the layer. A
    /// record kept against this session (a revocation) can be forgotten after it.
    #[must_use]
    pub fn expires(&self) -> Option<u64> {
        let inner = self.inner();
        Some(inner.issued?.saturating_add(inner.absolute?.as_secs()))
    }

    /// Whether the request presented a session that had passed its idle timeout, and
    /// so has none. True only for that request (its response removes the cookie): a
    /// guard that sees it redirects with a reason (`/login?reason=idle`) for the
    /// sign-in page to show.
    #[must_use]
    pub fn idle_expired(&self) -> bool {
        self.inner().idle_expired
    }

    /// How long until the idle timeout ends this session, counted from its last
    /// recorded activity; `None` without a timeout or a session. A handler that is
    /// not passive extends it to the whole timeout when the response reseals.
    #[must_use]
    pub fn idle_remaining(&self) -> Option<Duration> {
        let inner = self.inner();
        let (idle, seen) = (inner.idle?, inner.seen?);
        Some(idle.saturating_sub(Duration::from_secs(now().saturating_sub(seen))))
    }

    /// Mark this request as not the person's activity: it does not extend the idle
    /// timeout (an endpoint the page polls to show the time left).
    pub fn passive(&self) {
        self.inner().passive = true;
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
        inner.flushed = true;
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
mod env_tests {
    use super::*;

    /// Session data, as an app's is: a map of fields.
    #[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
    struct D {
        n: u8,
    }

    fn secret() -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode((0..64u8).collect::<Vec<_>>())
    }

    fn vars(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: std::collections::HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        move |name| map.get(name).cloned()
    }

    #[test]
    fn the_purpose_is_the_apps_and_its_environments() {
        let p = |pairs: &[(&str, &str)]| purpose_from("myapp", vars(pairs));
        assert_eq!(p(&[]), "myapp/local");
        assert_eq!(p(&[("POD_NAMESPACE", "myapp-prod")]), "myapp/myapp-prod");
        assert_eq!(
            p(&[
                ("SESSION_PURPOSE", "production"),
                ("POD_NAMESPACE", "myapp-prod")
            ]),
            "myapp/production"
        );
        assert_eq!(
            p(&[("SESSION_PURPOSE", " "), ("POD_NAMESPACE", "ns")]),
            "myapp/ns",
            "blank is unset"
        );
        assert_eq!(
            p(&[
                ("SESSION_KEY_PURPOSE", "myapp https://myapp.example"),
                ("SESSION_PURPOSE", "production"),
                ("POD_NAMESPACE", "ns")
            ]),
            "myapp https://myapp.example",
            "the whole purpose wins, taken as it is"
        );
        assert_eq!(
            p(&[
                ("SESSION_KEY_PURPOSE", " "),
                ("SESSION_PURPOSE", "production")
            ]),
            "myapp/production",
            "blank is unset"
        );
    }

    #[test]
    fn a_whole_purpose_keeps_an_apps_existing_key() {
        let s = secret();
        let age = Duration::from_secs(60);
        let old = "myapp https://myapp.example";
        let existing = Sessions::<D>::new(key_for(&s, old).unwrap(), "s", age, true);
        let sealed = existing.seal("id", &D { n: 3 });
        let adopted: Sessions<D> = Sessions::from_vars(
            "myapp",
            "s",
            age,
            true,
            vars(&[
                ("SESSION_SECRET", &s),
                ("SESSION_KEY_PURPOSE", old),
                ("KUBERNETES_SERVICE_HOST", "10.0.0.1"),
            ]),
        )
        .unwrap();
        assert_eq!(adopted.unseal(&sealed), Some(("id".to_owned(), D { n: 3 })));
        assert!(adopted.opens(&key_for(&s, old).unwrap()));

        let surrounded = Sessions::<D>::from_vars(
            "myapp",
            "s",
            age,
            true,
            vars(&[("SESSION_SECRET", &s), ("SESSION_KEY_PURPOSE", "myapp/x\n")]),
        )
        .err()
        .expect("refused, not trimmed");
        assert!(surrounded.to_string().contains("control"), "{surrounded}");
        assert!(
            surrounded.to_string().contains("from SESSION_KEY_PURPOSE"),
            "names the variable, not the secret: {surrounded}"
        );
    }

    #[test]
    fn opens_tells_whether_a_purpose_change_keeps_sessions() {
        let s = secret();
        let age = Duration::from_secs(60);
        let (old, new) = (
            key_for(&s, "myapp/production").unwrap(),
            key_for(&s, "myapp/myapp-prod").unwrap(),
        );
        let moved = Sessions::<D>::new(new.clone(), "s", age, true);
        assert!(moved.opens(&new));
        assert!(!moved.opens(&old), "a new purpose alone signs everyone out");
        assert!(moved.also_open_with(old.clone()).opens(&old));
    }

    #[test]
    fn sessions_from_the_environment_open_only_their_own_purpose() {
        let s = secret();
        let age = Duration::from_secs(60);
        let prod: Sessions<D> = Sessions::from_vars(
            "myapp",
            "s",
            age,
            true,
            vars(&[("SESSION_SECRET", &s), ("SESSION_PURPOSE", "production")]),
        )
        .unwrap();
        let same = Sessions::<D>::new(key_for(&s, "myapp/production").unwrap(), "s", age, true);
        let sealed = prod.seal("id", &D { n: 7 });
        assert_eq!(same.unseal(&sealed), Some(("id".to_owned(), D { n: 7 })));
        let staging: Sessions<D> = Sessions::from_vars(
            "myapp",
            "s",
            age,
            true,
            vars(&[("SESSION_SECRET", &s), ("POD_NAMESPACE", "staging")]),
        )
        .unwrap();
        assert_eq!(
            staging.unseal(&sealed),
            None,
            "a copied secret is another key"
        );

        let missing = Sessions::<D>::from_vars("myapp", "s", age, true, vars(&[]))
            .err()
            .expect("refused");
        assert!(missing.to_string().contains("SESSION_SECRET is not set"));
        let short = Sessions::<D>::from_vars(
            "myapp",
            "s",
            age,
            true,
            vars(&[("SESSION_SECRET", "c2hvcnQ=")]),
        )
        .err()
        .expect("refused");
        assert!(!short.to_string().contains("c2hvcnQ"), "{short}");
        assert!(short.to_string().contains("SESSION_SECRET"), "{short}");
        let in_a_pod = Sessions::<D>::from_vars(
            "myapp",
            "s",
            age,
            true,
            vars(&[
                ("SESSION_SECRET", &s),
                ("KUBERNETES_SERVICE_HOST", "10.0.0.1"),
            ]),
        )
        .err()
        .expect("refused");
        assert!(in_a_pod.to_string().contains("POD_NAMESPACE"), "{in_a_pod}");
        assert!(
            Sessions::<D>::from_vars(
                "myapp",
                "s",
                age,
                true,
                vars(&[
                    ("SESSION_SECRET", &s),
                    ("KUBERNETES_SERVICE_HOST", "10.0.0.1"),
                    ("POD_NAMESPACE", "myapp-prod"),
                ]),
            )
            .is_ok()
        );
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
            .without_idle_timeout()
    }

    #[test]
    fn sessions_end_when_idle_and_after_a_day_by_default() {
        let s = Sessions::<Data>::new(Key::generate(), "sid", Duration::from_secs(3600), true);
        assert_eq!(s.idle(), Some(IDLE_TIMEOUT));
        assert_eq!(IDLE_TIMEOUT, Duration::from_mins(30));
        assert_eq!(s.inner.absolute, ABSOLUTE_LIFETIME);
        assert_eq!(s.without_idle_timeout().idle(), None);
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

    /// A seal is a shape as well as a signature. One without `i`, or made by anything
    /// that is not this library, is no session even under the right key: a missing
    /// field never defaults to "began at zero" or "began now".
    #[test]
    fn a_correctly_sealed_payload_of_another_shape_is_no_session() {
        let s = sessions();
        let seal_plain = |plain: &str| {
            let mut jar = cookie::CookieJar::new();
            jar.private_mut(&s.inner.key)
                .add(Cookie::new("sid", plain.to_owned()));
            jar.get("sid").unwrap().value().to_owned()
        };
        let far = now() + 3000;
        for plain in [
            format!(r#"{{"k":"abc","x":{far}}}"#),
            format!(r#"{{"k":"abc","i":{}}}"#, now()),
            format!(r#"{{"x":{far},"i":{}}}"#, now()),
            format!(r#"{{"k":"abc","x":"{far}","i":{}}}"#, now()),
            format!(r#"{{"k":"abc","x":{far},"i":-1}}"#),
            "[]".to_owned(),
            "null".to_owned(),
            String::new(),
        ] {
            assert_eq!(s.unseal(&seal_plain(&plain)), None, "{plain} opened");
        }
        let whole = format!(r#"{{"k":"abc","x":{far},"i":{}}}"#, now());
        assert!(s.unseal(&seal_plain(&whole)).is_some(), "the control case");
    }

    #[test]
    fn the_cookie_size_warning_starts_past_four_kilobytes() {
        assert!(!oversized(0));
        assert!(!oversized(MAX_COOKIE_BYTES));
        assert!(oversized(MAX_COOKIE_BYTES + 1));
    }

    #[test]
    fn keys_must_be_long_enough() {
        use base64::Engine;
        let b64 =
            |n: u8| base64::engine::general_purpose::STANDARD.encode((0..n).collect::<Vec<_>>());
        assert!(key_from_base64(&b64(64)).is_ok());
        assert!(key_from_base64(&b64(32)).is_err());
        assert!(key_from_base64("not base64!").is_err());
        let pattern = |bytes: &[u8]| {
            base64::engine::general_purpose::STANDARD.encode(bytes.repeat(64 / bytes.len()))
        };
        assert!(key_from_base64(&pattern(&[0])).is_err(), "all zeros");
        assert!(
            key_from_base64(&pattern(b"abcd")).is_err(),
            "a repeated word"
        );
        assert!(key_for(&pattern(&[7]), "myapp").is_err());
    }

    /// One secret, two purposes: neither opens the other's cookies.
    #[test]
    fn a_key_for_one_purpose_opens_nothing_of_another() {
        use base64::Engine;
        let secret =
            base64::engine::general_purpose::STANDARD.encode((0..64u8).collect::<Vec<_>>());
        let at = |purpose| {
            Sessions::<Data>::new(
                key_for(&secret, purpose).unwrap(),
                "__Host-session",
                Duration::from_secs(3600),
                true,
            )
        };
        let (prod, staging) = (at("myapp/production"), at("myapp/staging"));
        let sealed = staging.seal("abc", &Data { user: Some(1) });
        assert_eq!(prod.unseal(&sealed), None);
        assert!(staging.unseal(&sealed).is_some());
        assert!(
            at("myapp/production")
                .unseal(&prod.seal("x", &Data::default()))
                .is_some()
        );
        assert!(key_for(&secret, " ").is_err());
        assert!(key_for(&secret, "").is_err());
        assert!(
            key_for(&secret, "myapp/production\n").is_err(),
            "a stray newline"
        );
        assert!(key_for(&secret, " myapp/production").is_err());
        assert!(key_for(&secret, "myapp/\u{0}production").is_err());
        assert!(key_for("short", "myapp").is_err());
    }

    /// A handler that changes the session and then fails (or is timed out) leaves
    /// the browser's session as it was.
    #[tokio::test]
    async fn a_server_error_seals_nothing() {
        let s = sessions();
        let app = Router::new()
            .route(
                "/fail",
                get(|sess: Session<Data>| async move {
                    sess.cycle_id();
                    sess.update(|d| d.user = Some(1));
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR
                }),
            )
            .route(
                "/unavailable",
                get(|sess: Session<Data>| async move {
                    sess.update(|d| d.user = Some(2));
                    axum::http::StatusCode::SERVICE_UNAVAILABLE
                }),
            )
            .route(
                "/out-then-fail",
                get(|sess: Session<Data>| async move {
                    sess.flush();
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR
                }),
            )
            .route(
                "/out-in-then-fail",
                get(|sess: Session<Data>| async move {
                    sess.flush();
                    sess.update(|d| d.user = Some(42));
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR
                }),
            )
            .route(
                "/switch-then-fail",
                get(|sess: Session<Data>| async move {
                    sess.flush();
                    sess.cycle_id();
                    sess.update(|d| d.user = Some(43));
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR
                }),
            )
            .route(
                "/refused",
                get(|sess: Session<Data>| async move {
                    sess.update(|d| d.user = Some(3));
                    axum::http::StatusCode::FORBIDDEN
                }),
            )
            .layer(from_fn_with_state(s.clone(), Sessions::<Data>::layer));
        for path in ["/fail", "/unavailable"] {
            let res = app
                .clone()
                .oneshot(Request::get(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert!(res.headers().get(header::SET_COOKIE).is_none(), "{path}");
        }
        // A sign-out stands even when what follows it fails, and so does nothing
        // after it: a sign-in into the emptied session (or an account switch) that
        // then fails leaves an empty session, not the new account.
        for path in ["/out-then-fail", "/out-in-then-fail", "/switch-then-fail"] {
            let res = app
                .clone()
                .oneshot(Request::get(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            let set = res.headers().get(header::SET_COOKIE).expect(path);
            let set = Cookie::parse_encoded(set.to_str().unwrap()).unwrap();
            let (_, data) = s.unseal(set.value()).expect(path);
            assert_eq!(data, Data::default(), "{path}");
        }
        // A 4xx is an answer, not a failure: its change stands.
        let res = app
            .oneshot(Request::get("/refused").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert!(res.headers().get(header::SET_COOKIE).is_some());
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

    fn idle_app(s: &Sessions<Data>) -> Router {
        who()
            .route(
                "/expired",
                get(|sess: Session<Data>| async move { format!("{}", sess.idle_expired()) }),
            )
            .route(
                "/poll",
                get(|sess: Session<Data>| async move {
                    sess.passive();
                    format!("{:?}", sess.idle_remaining().map(|d| d.as_secs() / 60))
                }),
            )
            .layer(from_fn_with_state(s.clone(), Sessions::<Data>::layer))
    }

    fn idle_sessions() -> Sessions<Data> {
        sessions()
            .idle_timeout(Duration::from_mins(15))
            .idle_refresh(Duration::from_mins(1))
    }

    /// A cookie for user 1 that began an hour ago and was last active `ago` ago.
    fn cookie_seen(s: &Sessions<Data>, ago: u64) -> String {
        let now = now();
        format!(
            "sid={}",
            s.seal_begun("abc", now - 3600, now - ago, &Data { user: Some(1) })
        )
    }

    #[tokio::test]
    async fn an_idle_session_is_no_session_and_loses_its_cookie() {
        let s = idle_sessions();
        let stale = cookie_seen(&s, 15 * 60 + 1);
        let res = get_with(idle_app(&s), "/who", Some(&stale)).await;
        let set = res
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        assert!(set.contains("Max-Age=0"), "{set}");
        assert!(!res.headers().contains_key(IDLE_REMAINING_HEADER));
        assert_eq!(text(res).await, "None");
        let res = get_with(idle_app(&s), "/expired", Some(&stale)).await;
        assert_eq!(text(res).await, "true");
        // Within the timeout it stands.
        let fresh = cookie_seen(&s, 14 * 60);
        assert_eq!(
            text(get_with(idle_app(&s), "/who", Some(&fresh)).await).await,
            "Some(1)"
        );
        assert_eq!(s.unseal(&stale["sid=".len()..]), None);
    }

    fn set_cookies(res: &Response) -> Vec<Cookie<'static>> {
        res.headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|v| Cookie::parse_encoded(v.to_str().unwrap().to_owned()).unwrap())
            .collect()
    }

    #[tokio::test]
    async fn activity_refreshes_the_last_active_time_at_most_once_a_refresh() {
        let s = idle_sessions();
        // Active a moment ago: nothing set; the page learns the time left, privately.
        let res = get_with(idle_app(&s), "/who", Some(&cookie_seen(&s, 5))).await;
        assert_eq!(set_cookies(&res).len(), 0);
        let left: u64 = res.headers()[IDLE_REMAINING_HEADER]
            .to_str()
            .unwrap()
            .parse()
            .unwrap();
        assert!((890..=895).contains(&left), "{left}");
        assert_eq!(
            res.headers()[header::CACHE_CONTROL],
            crate::headers::NEVER_CACHE
        );
        assert_eq!(res.headers()[header::VARY], "cookie");
        // Active ten minutes ago: only the last-active cookie is set, the whole
        // timeout left.
        let main = cookie_seen(&s, 600);
        let res = get_with(idle_app(&s), "/who", Some(&main)).await;
        let set = set_cookies(&res);
        assert_eq!(set.len(), 1);
        assert_eq!(set[0].name(), "sid-seen");
        assert_eq!(res.headers()[IDLE_REMAINING_HEADER], "900");
        // With it, the session counts from now even when the main cookie is old.
        let both = format!("{main}; sid-seen={}", set[0].value());
        let res = get_with(idle_app(&s), "/who", Some(&both)).await;
        assert_eq!(res.headers()[IDLE_REMAINING_HEADER], "900");
        // A last-active cookie of another session (one signed out of) counts for
        // nothing.
        let other = format!("{main}; sid-seen={}", s.seal_seen("someone-else", now()));
        let res = get_with(idle_app(&s), "/poll", Some(&other)).await;
        assert_eq!(text(res).await, "Some(5)");
        let stale = cookie_seen(&s, 15 * 60 + 5);
        let res = get_with(
            idle_app(&s),
            "/who",
            Some(&format!(
                "{stale}; sid-seen={}",
                s.seal_seen("someone-else", now())
            )),
        )
        .await;
        assert_eq!(text(res).await, "None");
    }

    #[test]
    fn a_refresh_never_outlasts_half_the_timeout() {
        let s = sessions().idle_timeout(Duration::from_mins(15));
        assert_eq!(
            s.clone().idle_refresh(Duration::from_mins(15)).refresh(),
            450
        );
        assert_eq!(s.clone().idle_refresh(Duration::ZERO).refresh(), 1);
        assert_eq!(s.refresh(), 90);
    }

    #[tokio::test]
    async fn a_signed_out_or_public_response_tells_no_time_left() {
        let s = idle_sessions();
        let app = who()
            .route(
                "/logout",
                get(|sess: Session<Data>| async move {
                    sess.flush();
                }),
            )
            .route(
                "/public",
                get(|| async { ([(header::CACHE_CONTROL, "public, max-age=60")], "x") }),
            )
            .layer(from_fn_with_state(s.clone(), Sessions::<Data>::layer));
        let res = get_with(app.clone(), "/logout", Some(&cookie_seen(&s, 5))).await;
        assert!(!res.headers().contains_key(IDLE_REMAINING_HEADER));
        let res = get_with(app, "/public", Some(&cookie_seen(&s, 5))).await;
        assert_eq!(
            res.headers()[header::CACHE_CONTROL],
            crate::headers::NEVER_CACHE
        );
    }

    #[tokio::test]
    async fn a_passive_request_does_not_extend_the_session() {
        let s = idle_sessions();
        let ten_ago = cookie_seen(&s, 600);
        // By header.
        let app = idle_app(&s);
        let req = Request::get("/who")
            .header(header::COOKIE, &ten_ago)
            .header(PASSIVE_HEADER, "1")
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert!(!res.headers().contains_key(header::SET_COOKIE));
        assert_eq!(res.headers()[IDLE_REMAINING_HEADER], "300");
        // Only "1" is passive.
        let req = Request::get("/who")
            .header(header::COOKIE, &ten_ago)
            .header(PASSIVE_HEADER, "0")
            .body(Body::empty())
            .unwrap();
        let res = idle_app(&s).oneshot(req).await.unwrap();
        assert!(res.headers().contains_key(header::SET_COOKIE));
        // By the handler.
        let res = get_with(idle_app(&s), "/poll", Some(&ten_ago)).await;
        assert!(!res.headers().contains_key(header::SET_COOKIE));
        assert_eq!(text(res).await, "Some(5)");
    }

    #[tokio::test]
    async fn without_an_idle_timeout_nothing_changes() {
        let s = sessions();
        let v = s.seal("abc", &Data { user: Some(1) });
        assert!(s.unseal(&v).is_some());
        let res = get_with(idle_app(&s), "/who", Some(&format!("sid={v}"))).await;
        assert!(!res.headers().contains_key(IDLE_REMAINING_HEADER));
        assert!(!res.headers().contains_key(header::SET_COOKIE));
        // A cookie sealed before the timeout was set was last active when it began.
        let old = format!(
            "sid={}",
            s.seal_begun("abc", now() - 3600, now(), &Data { user: Some(1) })
        );
        let idle = s.clone().idle_timeout(Duration::from_mins(15));
        assert_eq!(
            text(get_with(idle_app(&idle), "/who", Some(&old)).await).await,
            "None"
        );
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
            s.unseal(&s.seal_begun("abc", now() - 7000, now(), &data))
                .is_some()
        );
        // Sealed while the lifetime was longer, so its own expiry is still ahead.
        let lenient = s.clone().absolute_lifetime(ABSOLUTE_LIFETIME);
        let v = lenient.seal_begun("abc", now() - 7300, now(), &data);
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
        let set = s.set_cookie("abc", now(), now(), &Data::default()).unwrap();
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

    #[test]
    fn ids_are_random_and_well_formed() {
        let ids: std::collections::HashSet<String> = (0..2000).map(|_| new_id()).collect();
        assert_eq!(ids.len(), 2000, "an id repeated");
        for id in &ids {
            assert_eq!(id.len(), 32);
            assert!(
                id.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
            );
        }
        // Every character of the alphabet turns up, at every position's worth of
        // draws: a generator stuck on part of it would not get here.
        let seen: std::collections::HashSet<u8> = ids.iter().flat_map(|i| i.bytes()).collect();
        assert_eq!(seen.len(), 36);
    }

    #[test]
    fn the_handle_reports_what_it_holds() {
        let s = Session::<Data>::default();
        assert_eq!((s.id(), s.issued(), s.is_modified()), (None, None, false));
        let id = s.ensure_id();
        assert_eq!(id.len(), 32);
        assert_eq!(s.id().as_deref(), Some(id.as_str()));
        assert_eq!(s.ensure_id(), id, "it keeps the id it has");
        assert!(s.is_modified());

        let s = Session::<Data>::default();
        s.cycle_id();
        let first = s.id().unwrap();
        s.cycle_id();
        assert_ne!(s.id().unwrap(), first, "cycling replaces the id");
        s.update(|d| d.user = Some(3));
        s.flush();
        assert_eq!(s.read(|d| d.user), None);
        assert_ne!(s.id().unwrap(), first);
    }

    #[tokio::test]
    async fn the_layer_tells_handlers_the_id_and_when_the_session_began() {
        let s = sessions();
        let began = now() - 600;
        let cookie = format!(
            "sid={}",
            s.seal_begun("abc", began, began, &Data { user: Some(7) })
        );
        let app =
            Router::new()
                .route(
                    "/",
                    get(|sess: Session<Data>| async move {
                        format!("{:?} {:?}", sess.id(), sess.issued())
                    }),
                )
                .route(
                    "/touch",
                    get(|sess: Session<Data>| async move { sess.update(|d| d.user = Some(8)) }),
                )
                .layer(from_fn_with_state(s.clone(), Sessions::<Data>::layer));
        let res = get_with(app.clone(), "/", Some(&cookie)).await;
        assert_eq!(text(res).await, format!("Some(\"abc\") Some({began})"));
        // A change re-seals it under the same id and the same beginning.
        let res = get_with(app, "/touch", Some(&cookie)).await;
        let set = res.headers()[header::SET_COOKIE].to_str().unwrap();
        let resealed = Cookie::parse_encoded(set).unwrap();
        assert_eq!(resealed.name(), s.cookie_name());
        assert_eq!(s.cookie_name(), "sid");
        let Some(Opened::Live(opened, _)) = s.unseal_presented(resealed.value()) else {
            panic!("a live session");
        };
        assert_eq!((opened.id.as_str(), opened.issued), ("abc", began));
        assert_eq!(opened.data, Data { user: Some(8) });
    }

    #[test]
    fn a_seal_lapses_after_max_age_and_not_before() {
        let s = Sessions::<Data>::new(Key::generate(), "sid", Duration::from_secs(1), true);
        let v = s.seal("abc", &Data::default());
        assert!(s.unseal(&v).is_some(), "good for its max_age");
        std::thread::sleep(Duration::from_millis(2100));
        assert_eq!(s.unseal(&v), None);
    }

    #[test]
    fn the_absolute_lifetime_ends_on_the_second() {
        assert_eq!(ABSOLUTE_LIFETIME, Duration::from_hours(24), "a day");
        let s = sessions().absolute_lifetime(Duration::from_secs(7200));
        let lenient = s.clone().absolute_lifetime(ABSOLUTE_LIFETIME);
        let data = Data::default();
        // Begun exactly its lifetime ago: over. (If the clock ticks between the two
        // lines it is a second further over.)
        let on_the_dot = lenient.seal_begun("abc", now() - 7200, now(), &data);
        assert_eq!(s.unseal(&on_the_dot), None);
        let a_minute_left = lenient.seal_begun("abc", now() - 7140, now(), &data);
        assert!(s.unseal(&a_minute_left).is_some());
        // The default never undercuts a longer max_age.
        let year = Duration::from_hours(365 * 24);
        let long = Sessions::<Data>::new(Key::generate(), "sid", year, true);
        assert!(
            long.unseal(&long.seal_begun("abc", now() - 200 * 86_400, now(), &data))
                .is_some()
        );
    }
}
