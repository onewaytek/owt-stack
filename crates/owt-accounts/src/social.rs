//! Sign-in with a provider (Google, Discord, Twitch, any OIDC issuer): the routes,
//! their configuration, and the pieces an app's pages show.
//!
//! [`owt_auth::oauth`] speaks the protocol and [`crate::identities`] resolves who
//! came back; this module is the HTTP glue between them, written once:
//!
//! | Route (default path) | What it does |
//! |---|---|
//! | `POST /auth/{provider}/start` | Begins: keeps the pending sign-in in the session, sends the browser to the provider. Form fields: `next` (where to land), `connect` (add the provider to the signed-in account instead of signing in). |
//! | `GET /auth/{provider}/callback` | Ends: checks the state and provider, trades the code, then signs in ([`identities::arrive`]) or links ([`identities::link`]), and redirects. |
//! | `POST /auth/connections/{id}/remove` | Unlinks one of the signed-in account's identities, never its last way in. |
//!
//! Every failure redirects with `?social=<code>` to the sign-in page (or, for a
//! connect, the connections page); [`outcome`] turns the code into a message for
//! [`owt_web::ui::Alerts`]. Nothing here renders a page of its own: the app's sign-in
//! and settings pages embed [`Buttons`] and [`Connections`].
//!
//! A connect is bound to the account that began it and needs a recent sign-in
//! ([`SocialSignIn::connect_within`]): a borrowed or stolen session cannot quietly
//! add a provider that would let its holder back in after a password reset.
//!
//! **Configuration** ([`Providers::from_env`]): `PUBLIC_BASE_URL`, and for each
//! provider `<PROVIDER>_CLIENT_ID` with `<PROVIDER>_CLIENT_SECRET`. The README's
//! "Sign-in with a provider" section lists every requirement, at the providers too.

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use askama::Template;
use askama::filters::HtmlSafe;
use axum::Router;
use axum::extract::{Form, Path, Query, State};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use owt_auth::oauth;
use owt_web::cache::CachePolicy;
use owt_web::csrf::CrossOrigin;
use owt_web::flash::{Flash, Level};
use owt_web::redirect;
use owt_web::session::{Session, SessionData};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

use crate::identities::{self, Arrival, Welcome};
use crate::session::Signed as SignedData;
use crate::{Account, Maybe, Refused, Signed, session};

/// The variable naming this site's public origin (`https://myapp.example`): the
/// redirect URI each provider is told is built from it.
pub const PUBLIC_BASE_URL: &str = "PUBLIC_BASE_URL";

/// The callback path when the app names none; `{provider}` is the provider's id.
pub const DEFAULT_CALLBACK: &str = "/auth/{provider}/callback";
/// The start path.
pub const START: &str = "/auth/{provider}/start";
/// The path that removes a connection; `{id}` is the identity's row id.
pub const REMOVE: &str = "/auth/connections/{id}/remove";

/// The presets [`Providers::from_env`] reads, by the variable prefix each uses.
/// A preset's constructor.
type Preset = fn() -> oauth::Provider;

const PRESETS: [(&str, Preset); 3] = [
    ("GOOGLE", oauth::google),
    ("DISCORD", oauth::discord),
    ("TWITCH", oauth::twitch),
];

/// A configuration that cannot be used. Each says which variable to fix, so a
/// deployment fails at start rather than at someone's first sign-in.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConfigError {
    /// A provider's id is set without its secret, or the reverse.
    #[error("set both {0}_CLIENT_ID and {0}_CLIENT_SECRET, or neither")]
    Half(String),
    /// A provider is configured and `PUBLIC_BASE_URL` is not.
    #[error("{PUBLIC_BASE_URL} must be set when a sign-in provider is configured")]
    NoBaseUrl,
    /// `PUBLIC_BASE_URL` is not an origin this can redirect to.
    #[error(
        "{PUBLIC_BASE_URL} must be an https origin with no path (http is accepted for localhost): {0}"
    )]
    BaseUrl(String),
    /// The callback path is not a path naming `{provider}` once and nothing else.
    #[error(
        "the callback path must start with / and name {{provider}} once, with no other {{…}}, *, ?, # or //: {0}"
    )]
    Callback(String),
    /// Two providers share an id.
    #[error("two providers have the id {0}")]
    Duplicate(String),
}

/// The providers this site signs in with, and the URLs they were registered with.
#[derive(Clone)]
pub struct Providers {
    clients: Vec<oauth::Client>,
    base: String,
    callback: String,
}

impl fmt::Debug for Providers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Providers")
            .field("clients", &self.clients)
            .field("base", &self.base)
            .field("callback", &self.callback)
            .finish()
    }
}

impl Providers {
    /// No providers yet, for a site at `public_base_url` whose callback route is
    /// `callback` ([`DEFAULT_CALLBACK`] unless the providers were registered with
    /// another).
    ///
    /// # Errors
    ///
    /// When the URL is not an origin or the callback names no `{provider}`.
    pub fn new(public_base_url: &str, callback: &str) -> Result<Self, ConfigError> {
        Ok(Self {
            clients: Vec::new(),
            base: origin(public_base_url)?,
            callback: callback_path(callback)?,
        })
    }

    /// Read `PUBLIC_BASE_URL` and the presets' credentials: `GOOGLE_CLIENT_ID` and
    /// `GOOGLE_CLIENT_SECRET`, and the same for `DISCORD` and `TWITCH`. A provider
    /// with neither variable is off; none configured is an empty set (no buttons).
    ///
    /// # Errors
    ///
    /// See [`ConfigError`].
    pub fn from_env(callback: &str) -> Result<Self, ConfigError> {
        Self::from_values(env_var, callback)
    }

    /// [`Providers::from_env`] over `get` instead of the environment.
    ///
    /// # Errors
    ///
    /// See [`ConfigError`].
    pub fn from_values(
        get: impl Fn(&str) -> Option<String>,
        callback: &str,
    ) -> Result<Self, ConfigError> {
        let callback = callback_path(callback)?;
        let mut found = Vec::new();
        for (prefix, preset) in PRESETS {
            let id = get(&format!("{prefix}_CLIENT_ID"));
            let secret = get(&format!("{prefix}_CLIENT_SECRET"));
            match (id, secret) {
                (None, None) => {}
                (Some(id), Some(secret)) => found.push((preset(), id, secret)),
                _ => return Err(ConfigError::Half(prefix.to_owned())),
            }
        }
        let base = match get(PUBLIC_BASE_URL) {
            Some(url) => origin(&url)?,
            None if found.is_empty() => String::new(),
            None => return Err(ConfigError::NoBaseUrl),
        };
        let mut this = Self {
            clients: Vec::new(),
            base,
            callback,
        };
        for (provider, id, secret) in found {
            this = this.with(provider, id, secret)?;
        }
        Ok(this)
    }

    /// Add `provider` with this site's registration at it: an [`oauth::oidc`]
    /// issuer (`oidc(…)?`), or a preset pointed elsewhere in a test. Its redirect URI is this
    /// set's [`redirect_uri`](Self::redirect_uri).
    ///
    /// # Errors
    ///
    /// When a provider with that id is already in the set, or the set has no
    /// public base URL.
    pub fn with(
        mut self,
        provider: oauth::Provider,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
    ) -> Result<Self, ConfigError> {
        if self.base.is_empty() {
            return Err(ConfigError::NoBaseUrl);
        }
        if self.get(provider.id).is_some() {
            return Err(ConfigError::Duplicate(provider.id.to_owned()));
        }
        let redirect_uri = self.redirect_uri(provider.id);
        self.clients.push(oauth::Client {
            provider,
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            redirect_uri,
        });
        Ok(self)
    }

    /// The redirect URI to register at the provider `id`, exactly:
    /// `PUBLIC_BASE_URL` followed by the callback path.
    #[must_use]
    pub fn redirect_uri(&self, id: &str) -> String {
        format!("{}{}", self.base, self.callback.replace("{provider}", id))
    }

    /// The provider `id`, if configured.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<&oauth::Client> {
        self.clients.iter().find(|c| c.provider.id == id)
    }

    /// The configured providers, in the order added (Google, Discord, Twitch, then
    /// any [`with`](Self::with)).
    pub fn iter(&self) -> impl Iterator<Item = &oauth::Client> {
        self.clients.iter()
    }

    /// No provider is configured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.clients.is_empty()
    }

    /// The origins of the providers' consent pages, for the Content-Security-Policy
    /// `form-action` directive: the start form's redirect lands there, and a browser
    /// enforcing `form-action 'self'` refuses it.
    #[must_use]
    pub fn form_action_sources(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .clients
            .iter()
            .filter_map(|c| url::Url::parse(&c.provider.authorize_url).ok())
            .map(|u| u.origin().ascii_serialization())
            .collect();
        out.sort();
        out.dedup();
        out
    }
}

fn env_var(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|v| v.trim().to_owned())
        .filter(|v| !v.is_empty())
}

/// `https://host[:port]`, no trailing slash; `http` only for this machine
/// (`localhost`, `127.0.0.1`, `[::1]`).
fn origin(raw: &str) -> Result<String, ConfigError> {
    // The error names the value, without any credentials it carries: it is logged.
    let shown = match url::Url::parse(raw.trim()) {
        Ok(mut u) if !u.username().is_empty() || u.password().is_some() => {
            let _ = u.set_username("");
            let _ = u.set_password(None);
            format!("{u} (with credentials, removed here)")
        }
        Err(_) if raw.contains('@') => "(an unparsable URL with an @)".to_owned(),
        Ok(_) | Err(_) => raw.to_owned(),
    };
    let bad = || ConfigError::BaseUrl(shown.clone());
    let url = url::Url::parse(raw.trim()).map_err(|_| bad())?;
    let local = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
    let scheme_ok = url.scheme() == "https" || (url.scheme() == "http" && local);
    let bare = matches!(url.path(), "" | "/") && url.query().is_none() && url.fragment().is_none();
    if !scheme_ok
        || !bare
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(bad());
    }
    Ok(url.origin().ascii_serialization())
}

/// A path with `{provider}` as its only capture: another capture, a wildcard or a
/// query would route and then fail every callback.
fn callback_path(raw: &str) -> Result<String, ConfigError> {
    let rest = raw.replacen("{provider}", "", 1);
    let ok = raw.starts_with('/')
        && raw.contains("{provider}")
        && !rest.contains(['{', '}', '*', '?', '#'])
        && !raw.contains("//");
    if ok {
        Ok(raw.to_owned())
    } else {
        Err(ConfigError::Callback(raw.to_owned()))
    }
}

/// The longest `next` kept: the pending sign-in rides in the session cookie, and a
/// browser drops a cookie over about 4 KB (which would lose the sign-in).
pub const MAX_NEXT: usize = 1024;

/// How long a sign-in begun at a provider may take to come back: the callback after
/// that is `expired`. A copy of the session cookie made while one was pending opens
/// nothing once it has passed.
pub const PENDING_FOR: Duration = Duration::from_secs(10 * 60);

/// A sign-in on its way to a provider and back, kept in the session between the two.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Started {
    /// The state, provider and PKCE verifier sent out.
    #[serde(rename = "p")]
    pub pending: oauth::Pending,
    /// Where to land afterwards; checked to be on this site when used.
    #[serde(rename = "n", default, skip_serializing_if = "String::is_empty")]
    pub next: String,
    /// Adding the provider to this account (the one signed in when it began), not
    /// signing in. The callback links only for that account.
    #[serde(rename = "c", default, skip_serializing_if = "Option::is_none")]
    pub connect: Option<i64>,
    /// When it began, in Unix seconds; it lapses [`PENDING_FOR`] later.
    #[serde(rename = "t", default)]
    pub at: u64,
    /// The id of the session it began in. Signing in (or out) replaces the id, so a
    /// sign-in begun on a shared browser before its owner signed in cannot finish
    /// in the owner's session.
    #[serde(rename = "s", default)]
    pub session: String,
}

/// Session data that can hold a [`Started`] sign-in as well as the signature. An
/// app with its own session type adds a field and these two methods; one without
/// uses [`Data`].
pub trait Social: SignedData {
    /// The sign-in in progress, if any.
    fn started(&self) -> Option<&Started>;
    /// Keep `started`, or clear it with `None`.
    fn set_started(&mut self, started: Option<Started>);
}

/// [`session::Data`](crate::session::Data) with room for a [`Started`] sign-in:
/// the session type for an app that keeps nothing else in its session.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Data {
    /// The signature.
    #[serde(flatten)]
    pub signed: session::Data,
    /// The sign-in in progress.
    #[serde(rename = "o", default, skip_serializing_if = "Option::is_none")]
    pub started: Option<Started>,
}

impl SignedData for Data {
    fn signature(&self) -> Option<session::Signature> {
        self.signed.signature()
    }

    fn set_signature(&mut self, signature: Option<session::Signature>) {
        self.signed.set_signature(signature);
    }
}

impl Social for Data {
    fn started(&self) -> Option<&Started> {
        self.started.as_ref()
    }

    fn set_started(&mut self, started: Option<Started>) {
        self.started = started;
    }
}

/// Every `?social=` code this module sends. An app that shows the outcomes in its
/// own words (another language, say) translates each, and a test of its own can hold
/// it to this list: a code added here is then one it is told about.
pub const CODES: [&str; 10] = [
    "expired",
    "cancelled",
    "failed",
    "unknown",
    "taken",
    "sign-in-first",
    "sign-in-again",
    "connected",
    "removed",
    "last-way-in",
];

/// What a `?social=` code means, in English, as a message for
/// [`owt_web::ui::Alerts`]; `None` for a code this module never sends ([`CODES`]).
///
/// ```
/// # fn page(info: owt_web::request::RequestInfo) {
/// let flashes: Vec<_> = owt_accounts::social::outcome(info.query_value("social")).into_iter().collect();
/// let alerts = owt_web::ui::Alerts { flashes: &flashes };
/// # let _ = alerts; }
/// ```
#[must_use]
pub fn outcome(code: Option<&str>) -> Option<Flash> {
    let (level, text) = match code? {
        "expired" => (
            Level::Error,
            "That sign-in expired or was started elsewhere. Please try again.",
        ),
        "cancelled" => (Level::Warning, "Sign-in was cancelled at the provider."),
        "failed" => (
            Level::Error,
            "The provider could not complete the sign-in. Please try again.",
        ),
        "unknown" => (
            Level::Error,
            "That sign-in cannot be used here. If you have an account, sign in another way, then connect it from your settings.",
        ),
        "sign-in-again" => (
            Level::Warning,
            "For your security, sign in again, then connect the new sign-in.",
        ),
        "taken" => (
            Level::Error,
            "That sign-in is already connected to a different account.",
        ),
        "sign-in-first" => (Level::Error, "Sign in before connecting another sign-in."),
        "connected" => (
            Level::Success,
            "Connected. You can sign in with it from now on.",
        ),
        "removed" => (Level::Success, "Connection removed."),
        "last-way-in" => (
            Level::Error,
            "That is the only way into your account, so it cannot be removed. Set a password or connect another first.",
        ),
        _ => return None,
    };
    Some(Flash(level, text.to_owned()))
}

/// A sign-in with a provider about to sign `account` in, for
/// [`SocialSignIn::on_arrival`].
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct Arrived {
    /// The account it signs in.
    pub account: Account,
    /// The account was created by this sign-in (a first sign-in, with
    /// `Welcome { create: true }`).
    pub created: bool,
    /// The provider's id (`google`).
    pub provider: String,
    /// What the provider's token endpoint granted at this sign-in, for an app that
    /// calls the provider's APIs as the person. Nothing here keeps them: store them
    /// sealed, never in the clear. Their `Debug` leaves the tokens out.
    pub tokens: oauth::Tokens,
}

impl Arrived {
    /// An arrival built by hand, for an app's tests of its own hook: the callback
    /// builds the real ones. Its tokens are an empty bearer token until
    /// [`with_tokens`](Self::with_tokens).
    #[doc(hidden)]
    #[must_use]
    pub fn new(account: Account, created: bool, provider: impl Into<String>) -> Self {
        Self {
            account,
            created,
            provider: provider.into(),
            tokens: oauth::Tokens::bearer(""),
        }
    }

    /// This arrival with `tokens` granted.
    #[doc(hidden)]
    #[must_use]
    pub fn with_tokens(mut self, tokens: oauth::Tokens) -> Self {
        self.tokens = tokens;
        self
    }
}

/// A provider just connected to the signed-in `account`, for
/// [`SocialSignIn::on_connect`].
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct Connected {
    /// The account it was connected to.
    pub account: Account,
    /// The provider's id (`google`).
    pub provider: String,
    /// What the provider's token endpoint granted, as [`Arrived::tokens`].
    pub tokens: oauth::Tokens,
}

impl Connected {
    /// A connection built by hand, for an app's tests of its own hook, as
    /// [`Arrived::new`].
    #[doc(hidden)]
    #[must_use]
    pub fn new(account: Account, provider: impl Into<String>) -> Self {
        Self {
            account,
            provider: provider.into(),
            tokens: oauth::Tokens::bearer(""),
        }
    }

    /// This connection with `tokens` granted.
    #[doc(hidden)]
    #[must_use]
    pub fn with_tokens(mut self, tokens: oauth::Tokens) -> Self {
        self.tokens = tokens;
        self
    }
}

/// An app's hook, boxed.
type Hook<A> =
    Arc<dyn Fn(A) -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send>> + Send + Sync>;

/// Sign-in with providers, configured. Cheap to clone: keep one in the app's state
/// for the pages that show [`Buttons`] and [`Connections`], and merge
/// [`SocialSignIn::routes`] into the router. Configure it fully first: the routes
/// keep the configuration they were made with.
#[derive(Clone)]
pub struct SocialSignIn(Arc<Inner>);

#[derive(Clone)]
struct Inner {
    pool: PgPool,
    http: reqwest::Client,
    providers: Providers,
    welcome: Welcome,
    sign_in_page: String,
    connections_page: String,
    after_sign_in: String,
    connect_within: Duration,
    on_arrival: Option<Hook<Arrived>>,
    on_connect: Option<Hook<Connected>>,
}

impl fmt::Debug for SocialSignIn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SocialSignIn")
            .field("providers", &self.0.providers)
            .field("welcome", &self.0.welcome)
            .finish_non_exhaustive()
    }
}

impl SocialSignIn {
    /// Sign-in with `providers` over `pool`'s accounts, by `welcome`'s policy for a
    /// first sign-in. `http` is [`oauth::http_client`]'s client. Pages default to
    /// `/login` (sign-in), `/account/connections` (settings) and `/` (after).
    #[must_use]
    pub fn new(
        pool: PgPool,
        http: reqwest::Client,
        providers: Providers,
        welcome: Welcome,
    ) -> Self {
        Self(Arc::new(Inner {
            pool,
            http,
            providers,
            welcome,
            sign_in_page: "/login".into(),
            connections_page: "/account/connections".into(),
            after_sign_in: "/".into(),
            connect_within: Duration::from_secs(15 * 60),
            on_arrival: None,
            on_connect: None,
        }))
    }

    fn edit(mut self, f: impl FnOnce(&mut Inner)) -> Self {
        // A copy when a clone (a router's state, say) shares it: that one keeps
        // what it was made with, and this one takes the change.
        f(Arc::make_mut(&mut self.0));
        self
    }

    /// The app's sign-in page: failures of a sign-in land here with `?social=`.
    #[must_use]
    pub fn sign_in_page(self, path: impl Into<String>) -> Self {
        let path = path.into();
        self.edit(|i| i.sign_in_page = path)
    }

    /// The app's page listing [`Connections`]: connects and removals land here.
    #[must_use]
    pub fn connections_page(self, path: impl Into<String>) -> Self {
        let path = path.into();
        self.edit(|i| i.connections_page = path)
    }

    /// Where a sign-in lands when the start form gave no `next` on this site.
    #[must_use]
    pub fn after_sign_in(self, path: impl Into<String>) -> Self {
        let path = path.into();
        self.edit(|i| i.after_sign_in = path)
    }

    /// How recent a sign-in a connect needs (15 minutes unless set): older, and
    /// the person is sent to the sign-in page (`?social=sign-in-again`) to sign in
    /// again first, so the app's sign-in page must let a signed-in person do that.
    #[must_use]
    pub fn connect_within(self, window: Duration) -> Self {
        self.edit(|i| i.connect_within = window)
    }

    /// Run the app's own code for each sign-in with a provider, after the account is
    /// found or created and before the session is signed in: what every new account
    /// gets (a profile), a stamp of its own, or keeping the provider's tokens
    /// ([`Arrived::tokens`]). An error is logged and signs nobody in: the person
    /// lands on the sign-in page with the `failed` outcome, and the pending sign-in
    /// stays used up. An account it created stays, and its next
    /// sign-in arrives with `created` false, so set-up that must happen should also be
    /// done where it is missing later (on first use), not only here. Connecting a
    /// provider to a signed-in account signs nobody in and does not call it
    /// ([`on_connect`](Self::on_connect) does). Calling this again replaces the
    /// earlier hook.
    #[must_use]
    pub fn on_arrival<F, Fut>(self, f: F) -> Self
    where
        F: Fn(Arrived) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = anyhow::Result<()>> + Send + 'static,
    {
        let f: Hook<Arrived> = Arc::new(move |arrived| Box::pin(f(arrived)));
        self.edit(|i| i.on_arrival = Some(f))
    }

    /// Run the app's own code each time a provider is connected to the signed-in
    /// account, after the identity is linked: for an app that keeps the provider's
    /// tokens ([`Connected::tokens`]), which a person who signed up another way
    /// hands over here first. An error is logged and the person lands on the
    /// connections page with the `failed` outcome; the identity stays linked, and
    /// signing in with it calls [`on_arrival`](Self::on_arrival) with fresh tokens.
    /// Calling this again replaces the earlier hook.
    #[must_use]
    pub fn on_connect<F, Fut>(self, f: F) -> Self
    where
        F: Fn(Connected) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = anyhow::Result<()>> + Send + 'static,
    {
        let f: Hook<Connected> = Arc::new(move |connected| Box::pin(f(connected)));
        self.edit(|i| i.on_connect = Some(f))
    }

    /// The providers.
    #[must_use]
    pub fn providers(&self) -> &Providers {
        &self.0.providers
    }

    /// The routes, at full paths (merge them; do not nest), for session data `T`.
    /// Install them inside the session layer and the accounts layer. They refuse a
    /// cross-origin `POST` themselves ([`CrossOrigin`]), whatever the app layers: a
    /// sibling subdomain is same-site, so its forms come with `Lax` cookies.
    pub fn routes<T, S>(&self) -> Router<S>
    where
        T: Social + SessionData,
        S: Clone + Send + Sync + 'static,
    {
        Router::new()
            .route(START, post(start::<T>))
            .route(&self.0.providers.callback, get(callback::<T>))
            .route(REMOVE, post(remove))
            .with_state(self.clone())
            .layer(axum::middleware::from_fn_with_state(
                CrossOrigin::new(),
                CrossOrigin::layer,
            ))
    }

    /// The sign-in buttons, one form per provider, landing on `next` afterwards
    /// (empty: [`after_sign_in`](Self::after_sign_in)). Renders nothing when no
    /// provider is configured.
    #[must_use]
    pub fn buttons<'a>(&'a self, next: &'a str) -> Buttons<'a> {
        Buttons {
            items: self.items(|_| true),
            next,
            connect: false,
            words: ButtonWords::ENGLISH,
        }
    }

    fn items(&self, keep: impl Fn(&str) -> bool) -> Vec<ButtonItem> {
        self.0
            .providers
            .iter()
            .filter(|c| keep(c.provider.id))
            .map(|c| ButtonItem {
                action: START.replace("{provider}", c.provider.id),
                name: c.provider.name,
            })
            .collect()
    }

    /// The account's connections and the providers it could still connect, for the
    /// app's settings page.
    ///
    /// # Errors
    ///
    /// The database.
    pub async fn connections(&self, account_id: i64) -> sqlx::Result<Connections<'static>> {
        let linked = identities::list(&self.0.pool, account_id).await?;
        let keys: Vec<&str> = linked.iter().map(|l| l.provider.as_str()).collect();
        let rows = linked
            .iter()
            .map(|l| ConnectionRow {
                remove: REMOVE.replace("{id}", &l.id.to_string()),
                provider: self
                    .0
                    .providers
                    .iter()
                    .find(|c| c.provider.key() == l.provider)
                    .map_or_else(|| l.provider.clone(), |c| c.provider.name.to_owned()),
                label: l.label().to_owned(),
            })
            .collect();
        let items = self.items(|id| {
            self.0
                .providers
                .get(id)
                .is_some_and(|c| !keys.contains(&c.provider.key()))
        });
        Ok(Connections {
            rows,
            items,
            words: ConnectionWords::ENGLISH,
        })
    }
}

/// A provider's button.
#[derive(Clone, Debug)]
struct ButtonItem {
    action: String,
    name: &'static str,
}

/// What a provider's button says; `{provider}` is replaced by its name (`Google`).
/// English unless the app passes its own ([`Buttons::words`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ButtonWords<'a> {
    /// A sign-in button: `Continue with {provider}`.
    pub continue_with: &'a str,
    /// A button adding the provider to the signed-in account: `Connect {provider}`.
    pub connect: &'a str,
}

impl ButtonWords<'static> {
    /// `Continue with {provider}`, `Connect {provider}`.
    pub const ENGLISH: Self = Self {
        continue_with: "Continue with {provider}",
        connect: "Connect {provider}",
    };
}

impl Default for ButtonWords<'_> {
    fn default() -> Self {
        ButtonWords::ENGLISH
    }
}

/// `pattern` with the provider's name in place of `{provider}`.
fn named(pattern: &str, provider: &str) -> String {
    pattern.replace("{provider}", provider)
}

/// The sign-in buttons: `{{ buttons }}` on the sign-in page.
///
/// ```html
/// <div class="owt-actions"><form method="post" action="/auth/google/start"><input type="hidden" name="next" value="/games"><button class="owt-button owt-button-secondary" type="submit">Continue with Google</button></form></div>
/// ```
#[derive(Template, Clone, Debug)]
#[template(
    source = r#"{% if !items.is_empty() %}<div class="owt-actions">{% for b in items %}<form method="post" action="{{ b.action }}">{% if !next.is_empty() %}<input type="hidden" name="next" value="{{ next }}">{% endif %}{% if connect %}<input type="hidden" name="connect" value="1">{% endif %}<button class="owt-button owt-button-secondary" type="submit">{% if connect %}{{ crate::social::named(words.connect, b.name) }}{% else %}{{ crate::social::named(words.continue_with, b.name) }}{% endif %}</button></form>{% endfor %}</div>
{% endif %}"#,
    ext = "html"
)]
pub struct Buttons<'a> {
    items: Vec<ButtonItem>,
    next: &'a str,
    connect: bool,
    words: ButtonWords<'a>,
}
impl HtmlSafe for Buttons<'_> {}

impl<'a> Buttons<'a> {
    /// In the page's language.
    #[must_use]
    pub fn words(mut self, words: ButtonWords<'a>) -> Self {
        self.words = words;
        self
    }
}

/// A connected identity.
#[derive(Clone, Debug)]
struct ConnectionRow {
    remove: String,
    provider: String,
    label: String,
}

/// The words [`Connections`] writes. English unless the app passes its own
/// ([`Connections::words`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectionWords<'a> {
    /// Shown when the account has none: `No sign-in connections yet.`
    pub none: &'a str,
    /// The provider column's heading.
    pub provider: &'a str,
    /// The heading of the column naming the account at the provider.
    pub account: &'a str,
    /// The buttons column's heading, read by assistive technology only.
    pub actions: &'a str,
    /// The button that removes a connection.
    pub remove: &'a str,
    /// A button adding a provider: `Connect {provider}`.
    pub connect: &'a str,
}

impl ConnectionWords<'static> {
    /// `No sign-in connections yet.`, `Provider`, `Account there`, `Actions`,
    /// `Remove`, and [`ButtonWords::ENGLISH`]'s `Connect {provider}`.
    pub const ENGLISH: Self = Self {
        none: "No sign-in connections yet.",
        provider: "Provider",
        account: "Account there",
        actions: "Actions",
        remove: "Remove",
        connect: ButtonWords::ENGLISH.connect,
    };
}

impl Default for ConnectionWords<'_> {
    fn default() -> Self {
        ConnectionWords::ENGLISH
    }
}

/// An account's connections, each with a Remove button, then a Connect button per
/// provider not yet connected: `{{ connections }}` on the settings page.
#[derive(Template, Clone, Debug)]
#[template(
    source = r#"{% if rows.is_empty() %}<p class="owt-hint">{{ words.none }}</p>
{% else %}<table class="owt-table"><thead><tr><th scope="col">{{ words.provider }}</th><th scope="col">{{ words.account }}</th><th scope="col"><span class="owt-sr">{{ words.actions }}</span></th></tr></thead><tbody>
{% for r in rows %}<tr><td>{{ r.provider }}</td><td>{{ r.label }}</td><td><form method="post" action="{{ r.remove }}"><button class="owt-button owt-button-quiet" type="submit">{{ words.remove }}</button></form></td></tr>
{% endfor %}</tbody></table>
{% endif %}{% if !items.is_empty() %}<div class="owt-actions">{% for b in items %}<form method="post" action="{{ b.action }}"><input type="hidden" name="connect" value="1"><button class="owt-button owt-button-secondary" type="submit">{{ crate::social::named(words.connect, b.name) }}</button></form>{% endfor %}</div>
{% endif %}"#,
    ext = "html"
)]
pub struct Connections<'a> {
    rows: Vec<ConnectionRow>,
    items: Vec<ButtonItem>,
    words: ConnectionWords<'a>,
}
impl HtmlSafe for Connections<'_> {}

impl<'a> Connections<'a> {
    /// In the page's language.
    #[must_use]
    pub fn words(mut self, words: ConnectionWords<'a>) -> Self {
        self.words = words;
        self
    }
}

/// `path?social=code`.
fn landing(path: &str, code: &str) -> Response {
    let sep = if path.contains('?') { '&' } else { '?' };
    (
        CachePolicy::no_store(),
        Redirect::to(&format!("{path}{sep}social={code}")),
    )
        .into_response()
}

#[derive(Deserialize)]
struct StartForm {
    #[serde(default)]
    next: String,
    #[serde(default)]
    connect: String,
}

async fn start<T: Social + SessionData>(
    State(this): State<SocialSignIn>,
    session: Session<T>,
    Maybe(me): Maybe,
    Path(provider): Path<String>,
    Form(form): Form<StartForm>,
) -> owt_web::Result<Response> {
    let Some(client) = this.0.providers.get(&provider) else {
        return Err(owt_web::Error::NotFound);
    };
    let connect = if form.connect.is_empty() {
        None
    } else {
        let Some(me) = me else {
            return Ok(landing(&this.0.sign_in_page, "sign-in-first"));
        };
        if !signed_in_within(&session, this.0.connect_within) {
            return Ok(landing(&this.0.sign_in_page, "sign-in-again"));
        }
        Some(me.id)
    };
    let (url, pending) = client
        .begin()
        .map_err(|e| owt_web::Error::Internal(e.into()))?;
    let next = if form.next.len() > MAX_NEXT {
        String::new()
    } else {
        redirect::local_or(Some(&form.next), "").to_owned()
    };
    let session_id = session.ensure_id();
    session.update(|d| {
        d.set_started(Some(Started {
            pending,
            next,
            connect,
            at: now(),
            session: session_id,
        }));
    });
    Ok((CachePolicy::no_store(), Redirect::to(&url)).into_response())
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// The session began (signed in: signing in starts a new one) within `window`.
fn signed_in_within<T: SessionData>(session: &Session<T>, window: Duration) -> bool {
    session
        .issued()
        .is_some_and(|issued| now().saturating_sub(issued) <= window.as_secs())
}

#[derive(Deserialize)]
struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

/// Whether the app's hook `name`, if there is one, took `arg` (for `account`); its
/// error is logged.
async fn heard<A>(
    hook: Option<&Hook<A>>,
    name: &str,
    arg: A,
    account: i64,
    provider: &str,
) -> bool {
    let Some(hook) = hook else {
        return true;
    };
    match hook(arg).await {
        Ok(()) => true,
        Err(e) => {
            tracing::error!(
                account,
                provider = %provider,
                error = %e,
                "the app's {name} failed"
            );
            false
        }
    }
}

async fn callback<T: Social + SessionData>(
    State(this): State<SocialSignIn>,
    session: Session<T>,
    Maybe(me): Maybe,
    Path(provider): Path<String>,
    Query(q): Query<CallbackQuery>,
) -> owt_web::Result<Response> {
    let inner = &this.0;
    let Some(client) = inner.providers.get(&provider) else {
        return Err(owt_web::Error::NotFound);
    };
    // Taken whatever happens next: a pending sign-in is good for one callback.
    let started = session.update(|d| {
        let s = d.started().cloned();
        d.set_started(None);
        s
    });
    // Lapsed, or begun in another session (before a sign-in or sign-out on this
    // browser): a sign-in nobody here is waiting for.
    let current = session.id().unwrap_or_default();
    let Some(started) = started.filter(|s| {
        now().saturating_sub(s.at) <= PENDING_FOR.as_secs()
            && s.at <= now().saturating_add(60)
            && !s.session.is_empty()
            && s.session == current
    }) else {
        return Ok(landing(&inner.sign_in_page, "expired"));
    };
    let back = if started.connect.is_some() {
        inner.connections_page.as_str()
    } else {
        inner.sign_in_page.as_str()
    };
    if q.error.is_some() {
        return Ok(landing(back, "cancelled"));
    }
    let (Some(state), Some(code)) = (q.state, q.code) else {
        return Ok(landing(back, "failed"));
    };
    let (identity, tokens) = match client
        .complete_with_tokens(&inner.http, &started.pending, &state, &code)
        .await
    {
        Ok(done) => done,
        Err(oauth::Error::State | oauth::Error::Provider) => {
            return Ok(landing(back, "expired"));
        }
        Err(e) => {
            tracing::warn!(provider = %provider, error = %e, "a provider sign-in failed");
            return Ok(landing(back, "failed"));
        }
    };
    if let Some(began_as) = started.connect {
        // Only for the account that began it: whoever is signed in now may be
        // someone else on the same browser.
        let Some(me) = me.filter(|me| me.id == began_as) else {
            return Ok(landing(&inner.sign_in_page, "sign-in-first"));
        };
        // Recent at the end too, not only at the start: the sign-in that allowed it
        // must not have aged out while the provider was visited (or a copy of the
        // cookie waited).
        if !signed_in_within(&session, inner.connect_within) {
            return Ok(landing(&inner.sign_in_page, "sign-in-again"));
        }
        return Ok(connect(inner, me, client, &identity, tokens).await);
    }
    let arrival = match identities::arrive(&inner.pool, &client.provider, &identity, inner.welcome)
        .await
    {
        Ok(arrival) => arrival,
        Err(e) if e.refused() == Some(&Refused::NoSubject) => {
            return Ok(landing(&inner.sign_in_page, "failed"));
        }
        // A connect of the same identity, elsewhere, won the race.
        Err(e) if e.refused() == Some(&Refused::IdentityTaken) => {
            return Ok(landing(&inner.sign_in_page, "taken"));
        }
        // A redirect, not a 500, as for a connect (`connect`).
        Err(e) => {
            tracing::error!(provider = %provider, error = %e, "a provider sign-in failed on the database");
            return Ok(landing(&inner.sign_in_page, "failed"));
        }
    };
    // Unknown: nothing linked and no self-signup, or linked to a deactivated
    // account; one message for both.
    let Some(account) = arrival.account() else {
        return Ok(landing(&inner.sign_in_page, "unknown"));
    };
    let created = matches!(arrival, Arrival::Created(_));
    // A redirect, not a 500, as above.
    let arrived = Arrived {
        account: account.clone(),
        created,
        provider: provider.clone(),
        tokens,
    };
    if !heard(
        inner.on_arrival.as_ref(),
        "on_arrival",
        arrived,
        account.id,
        &provider,
    )
    .await
    {
        return Ok(landing(&inner.sign_in_page, "failed"));
    }
    session::sign_in(&session, account);
    tracing::info!(
        account = account.id,
        provider = %provider,
        created,
        "signed in with a provider"
    );
    let to = redirect::local_or(Some(&started.next), &inner.after_sign_in).to_owned();
    Ok((CachePolicy::no_store(), Redirect::to(&to)).into_response())
}

/// The end of a connect: link `identity` to `me`, then tell the app. Every outcome
/// is a redirect, never a 500: a 5xx seals no session change, and the pending
/// sign-in the callback took must stay used up.
async fn connect(
    inner: &Inner,
    me: Account,
    client: &oauth::Client,
    identity: &oauth::Identity,
    tokens: oauth::Tokens,
) -> Response {
    let provider = client.provider.id;
    match identities::link(&inner.pool, me.id, &client.provider, identity).await {
        Ok(_) => {
            tracing::info!(account = me.id, provider, "connected a provider");
            let id = me.id;
            let connected = Connected {
                account: me,
                provider: provider.to_owned(),
                tokens,
            };
            if heard(
                inner.on_connect.as_ref(),
                "on_connect",
                connected,
                id,
                provider,
            )
            .await
            {
                landing(&inner.connections_page, "connected")
            } else {
                landing(&inner.connections_page, "failed")
            }
        }
        Err(e) if e.refused() == Some(&Refused::IdentityTaken) => {
            landing(&inner.connections_page, "taken")
        }
        Err(e) if e.refused() == Some(&Refused::NoSubject) => {
            landing(&inner.connections_page, "failed")
        }
        Err(e) => {
            tracing::error!(account = me.id, provider, error = %e, "connecting a provider failed");
            landing(&inner.connections_page, "failed")
        }
    }
}

async fn remove(
    State(this): State<SocialSignIn>,
    Signed(me): Signed,
    Path(id): Path<i64>,
) -> owt_web::Result<Response> {
    let inner = &this.0;
    match identities::unlink(&inner.pool, me.id, id).await {
        Ok(true) => {
            tracing::info!(account = me.id, identity = id, "removed a connection");
            Ok(landing(&inner.connections_page, "removed"))
        }
        Ok(false) => Err(owt_web::Error::NotFound),
        Err(e) if e.refused() == Some(&Refused::LastWayIn) => {
            Ok(landing(&inner.connections_page, "last-way-in"))
        }
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |name| {
            pairs
                .iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| (*v).to_owned())
        }
    }

    #[test]
    fn nothing_configured_is_no_providers() {
        let p = Providers::from_values(env(&[]), DEFAULT_CALLBACK).unwrap();
        assert!(p.is_empty());
    }

    /// The refusal is logged at start: it names the URL without its password.
    #[test]
    fn a_refused_base_url_is_shown_without_its_credentials() {
        let err = origin("https://user:hunter2@myapp.example").unwrap_err();
        let shown = err.to_string();
        assert!(
            !shown.contains("hunter2") && !shown.contains("user:"),
            "{shown}"
        );
        assert!(matches!(err, ConfigError::BaseUrl(_)));
    }

    #[test]
    fn a_provider_needs_both_halves_and_the_public_url() {
        let half = Providers::from_values(env(&[("GOOGLE_CLIENT_ID", "id")]), DEFAULT_CALLBACK);
        assert_eq!(half.unwrap_err(), ConfigError::Half("GOOGLE".into()));
        let no_base = Providers::from_values(
            env(&[("GOOGLE_CLIENT_ID", "id"), ("GOOGLE_CLIENT_SECRET", "s")]),
            DEFAULT_CALLBACK,
        );
        assert_eq!(no_base.unwrap_err(), ConfigError::NoBaseUrl);
        let p = Providers::from_values(
            env(&[
                ("PUBLIC_BASE_URL", "https://myapp.example/"),
                ("GOOGLE_CLIENT_ID", "id"),
                ("GOOGLE_CLIENT_SECRET", "s"),
                ("TWITCH_CLIENT_ID", "tid"),
                ("TWITCH_CLIENT_SECRET", "ts"),
            ]),
            DEFAULT_CALLBACK,
        )
        .unwrap();
        let ids: Vec<_> = p.iter().map(|c| c.provider.id).collect();
        assert_eq!(ids, ["google", "twitch"]);
        assert_eq!(
            p.get("google").unwrap().redirect_uri,
            "https://myapp.example/auth/google/callback"
        );
        assert_eq!(
            p.form_action_sources(),
            ["https://accounts.google.com", "https://id.twitch.tv"]
        );
    }

    #[test]
    fn the_public_url_is_an_https_origin() {
        for ok in [
            "https://myapp.example",
            "https://myapp.example:8443/",
            "http://localhost:8000",
            "http://127.0.0.1:8000",
            "http://[::1]:8000",
        ] {
            assert!(origin(ok).is_ok(), "{ok}");
        }
        assert_eq!(
            origin("https://MyApp.example/").unwrap(),
            "https://myapp.example"
        );
        for bad in [
            "http://myapp.example",
            "http://localhost.evil.example",
            "http://127.0.0.1.evil.example",
            "https://myapp.example/app",
            "https://myapp.example/?x=1",
            "https://myapp.example/#f",
            "myapp.example",
            "https://user@myapp.example",
            "https://:pw@myapp.example",
            "",
        ] {
            assert!(origin(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_registered_callback_path_can_be_kept() {
        let p = Providers::new(
            "https://myapp.example",
            "/accounts/{provider}/login/callback/",
        )
        .unwrap()
        .with(oauth::discord(), "id", "s")
        .unwrap();
        assert_eq!(
            p.redirect_uri("discord"),
            "https://myapp.example/accounts/discord/login/callback/"
        );
        for bad in [
            "/auth/callback",
            "auth/{provider}",
            "/{lang}/auth/{provider}/callback",
            "/auth/{provider}/{provider}",
            "/auth/{provider}/{*rest}",
            "/auth/{provider}/callback?x=1",
            "/auth/{provider}#f",
            "//evil.example/{provider}",
        ] {
            assert!(
                Providers::new("https://myapp.example", bad).is_err(),
                "{bad}"
            );
        }
        assert_eq!(
            p.with(oauth::discord(), "again", "s").unwrap_err(),
            ConfigError::Duplicate("discord".into())
        );
    }

    #[test]
    fn every_code_sent_has_a_message() {
        for code in CODES {
            assert!(outcome(Some(code)).is_some(), "{code}");
        }
        // And `CODES` is exactly the codes the landing calls above the tests send. Without
        // whitespace, a call rustfmt wraps reads like one it doesn't.
        let source = include_str!("social.rs");
        let code: String = source[..source.find("#[cfg(test)]").unwrap()]
            .split_whitespace()
            .collect();
        let sent: std::collections::BTreeSet<&str> = code
            .match_indices("landing(")
            .filter(|&(at, _)| !code[..at].ends_with("fn"))
            .map(|(at, call)| {
                let args = &code[at + call.len()..];
                let args = &args[..args.find(')').unwrap()];
                let last = args.trim_end_matches(',').rsplit(',').next().unwrap();
                last.strip_prefix('"')
                    .and_then(|c| c.strip_suffix('"'))
                    .unwrap_or_else(|| panic!("landing({args}): the code isn't a string literal"))
            })
            .collect();
        assert_eq!(sent, CODES.into_iter().collect());
        assert!(outcome(Some("<script>")).is_none());
        assert!(outcome(None).is_none());
    }

    #[test]
    fn the_buttons_and_connections_speak_the_pages_language() {
        let item = || ButtonItem {
            action: "/auth/google/start".into(),
            name: "Google",
        };
        let english = Buttons {
            items: vec![item()],
            next: "",
            connect: false,
            words: ButtonWords::ENGLISH,
        };
        assert!(
            english
                .render()
                .unwrap()
                .contains(">Continue with Google</button>")
        );
        let spanish = english.words(ButtonWords {
            continue_with: "Continuar con {provider}",
            connect: "Conectar {provider}",
        });
        assert!(
            spanish
                .render()
                .unwrap()
                .contains(">Continuar con Google</button>")
        );

        let none = Connections {
            rows: Vec::new(),
            items: vec![item()],
            words: ConnectionWords::ENGLISH,
        };
        let html = none.clone().render().unwrap();
        assert!(html.contains("No sign-in connections yet.") && html.contains(">Connect Google<"));
        let html = Connections {
            rows: vec![ConnectionRow {
                remove: "/auth/connections/1/remove".into(),
                provider: "Google".into(),
                label: "ada@example.com".into(),
            }],
            ..none
        }
        .words(ConnectionWords {
            none: "Aún no hay conexiones.",
            provider: "Proveedor",
            account: "Cuenta allí",
            actions: "Acciones",
            remove: "Quitar",
            connect: "Conectar {provider}",
        })
        .render()
        .unwrap();
        for words in [
            "Proveedor",
            "Cuenta allí",
            "Acciones",
            ">Quitar<",
            ">Conectar Google<",
        ] {
            assert!(html.contains(words), "{words}: {html}");
        }
        assert!(!html.contains("Remove") && !html.contains("Provider"));
    }

    #[test]
    fn the_session_carries_short_names() {
        let d = Data::default();
        assert_eq!(serde_json::to_string(&d).unwrap(), "{}");
    }
}
