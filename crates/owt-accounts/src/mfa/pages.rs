//! The second-factor pages, ready to mount: enrolling an authenticator, the sign-in
//! challenge, step-up re-authentication, and the page where a person sees, removes or
//! sets up again their factors.
//!
//! [`MfaPages`] wires the functions of [`Mfa`] to routes, as [`crate::admin`] does for
//! the accounts admin, and the same way: the app supplies its layout through a
//! [`Chrome`] function, and the bodies come from [`Views`] (by default [`Tailwind`],
//! `owt-*` classes from `tailwind/owt.css`), which an app overrides page by page. The
//! routes, the checks, the throttle and the audit events stay here.
//!
//! | Route | What it is |
//! |---|---|
//! | `GET {base}` | the account's factors, with buttons to set up, remove or set up again the authenticator and to make new recovery codes |
//! | `GET, POST {base}/challenge?next=` | the code a pending sign-in waits for ([`Next::Challenge`]): a TOTP code or a recovery code |
//! | `GET, POST {base}/enroll?next=` | a fresh secret as a QR code and as text; the first code turns it on and shows the recovery codes once |
//! | `POST {base}/remove` | removes the authenticator and its recovery codes |
//! | `POST {base}/reenroll` | removes it, then sends the person to enroll a new one |
//! | `POST {base}/recovery-codes` | replaces the recovery codes, shown once |
//! | `GET, POST {reauth}?next=` | step-up: the password (if the account has one) and the second factor (if it has one) |
//! | `GET, POST {base}/passkeys/add?next=` | names and creates a passkey (behind step-up, or for a pending enrollment); the first factor shows the recovery codes once |
//! | `POST {base}/passkeys/{id}/rename` | renames one of the account's passkeys (`name`) |
//! | `POST {base}/passkeys/{id}/remove` | removes one, behind step-up; never the last factor under a required policy |
//! | `GET {base}/passkey.js` | the script the passkey buttons run (same origin, so a CSP of `script-src 'self'` allows it) |
//!
//! The passkey routes, and the passkey buttons on the challenge and re-authentication
//! pages, appear once [`Mfa::passkeys`] names the site; each page that shows a button
//! begins its ceremony as it renders, and the answer is posted with the form
//! (`passkey_token`, `passkey_credential`).
//!
//! `base` is `/mfa` and `reauth` is `/reauth` unless [`MfaPages::at`] and
//! [`MfaPages::reauth_at`] say otherwise; they are the defaults of
//! [`Accounts::enroll_at`](crate::Accounts::enroll_at) (`{base}/enroll`) and
//! [`Accounts::reauth_at`](crate::Accounts::reauth_at), where [`RecentMfa`] and
//! [`Recent`](super::Recent) send a visitor. An app that moves them tells both.
//!
//! What the pages hold to:
//!
//! * **`?next=` stays on this site.** It is followed only when it is a path here
//!   ([`owt_web::redirect::local`]): `https://evil.example`, `//evil.example` and
//!   `/\evil.example` become `/`.
//! * **Changing a factor needs step-up.** Removing, setting up again and new recovery
//!   codes go through [`Mfa::authorize_change`]: a second factor used within
//!   [`MfaPages::change_within`] (15 minutes, the admin's [`STEP_UP`](crate::admin::STEP_UP)),
//!   or for a first enrollment a recent sign-in. Without it the person is sent to
//!   `{reauth}` and back. A provider's sign-in or a link never counts as a second
//!   factor ([`RecentMfa`]), and re-authentication here asks for the account's own.
//! * **Every code is charged to the throttle** under a key of the account's, the
//!   enrollment's first code included, so six digits cannot be guessed; a wrong
//!   answer does not say which part was wrong.
//! * **Secrets are shown once.** The enrollment and recovery-code pages are `no-store`,
//!   as is every response here, and none is framed. A `POST` from another origin is
//!   refused ([`CrossOrigin`]), whether or not the app layers it too.
//! * **Events go to the app's [`Recorder`]** ([`MfaPages::audit`]): each [`Event`] the
//!   operations return, and the lock event of the answer that locked the
//!   authenticator. Email the owner on the ones [`Event`] names.
//!
//! The app provides the sealer ([`Mfa::sealer`]; a release build refuses
//! [`Unsealed`](super::Unsealed)), the layout ([`Chrome`]), and its own sign-in page, which
//! sends [`Next::Challenge`] to `{base}/challenge` and [`Next::Enroll`] to
//! `{base}/enroll`, each with `?next=`.

use std::fmt;
use std::future::Future;
use std::marker::PhantomData;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use askama::Template;
use axum::Router;
use axum::extract::{Form, FromRequestParts, OriginalUri, Query, State};
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use owt_web::cache::CachePolicy;
use owt_web::client_ip::ClientIp;
use owt_web::csrf::CrossOrigin;
use owt_web::session::Session;
use serde::Deserialize;
use sqlx::PgPool;

use super::passkey::{
    Ceremony, PasskeyInfo, PublicKeyCredential, RegisterPublicKeyCredential,
    RequestChallengeResponse,
};
use super::{
    Answer, Event, Key, Kind, Limiter, Mfa, MfaError, MfaSession, Next, Throttled, TotpEnrollment,
};
use crate::admin::Body;
use crate::layer::{self, Maybe};
use crate::session::Data;
use crate::store::{self, Account};

/// How recently a second factor must have been used to change one: 15 minutes.
pub const CHANGE_WITHIN: Duration = Duration::from_mins(15);

/// What the app's [`Chrome`] wraps: one of these pages.
#[non_exhaustive]
pub struct Page<'a> {
    /// The request, for whatever the app's layout reads from it. Its `uri` is the one
    /// the client sent.
    pub request: &'a Parts,
    /// The account signed in, if any: the challenge and an enrollment a pending
    /// sign-in makes are for someone not signed in yet.
    pub account: Option<&'a Account>,
    /// The page's title, as plain text. Escape it (an Askama layout does).
    pub title: &'a str,
    /// The page's content, escaped already: embed it as it is (`{{ page.body }}`).
    pub body: Body,
}

/// The app's layout: wraps a page's body in the app's shell. A closure
/// `|page: Page<'_>| -> owt_web::Result<Response>` is one; a layout that awaits
/// implements [`AsyncChrome`].
pub trait Chrome: Send + Sync + 'static {
    /// The whole page.
    ///
    /// # Errors
    ///
    /// When the app's template does not render.
    fn page(&self, page: Page<'_>) -> owt_web::Result<Response>;
}

impl<F> Chrome for F
where
    F: Fn(Page<'_>) -> owt_web::Result<Response> + Send + Sync + 'static,
{
    fn page(&self, page: Page<'_>) -> owt_web::Result<Response> {
        self(page)
    }
}

/// The app's layout, awaited (it reads something per page before wrapping the body).
/// Every [`Chrome`] is one.
pub trait AsyncChrome: Send + Sync + 'static {
    /// The whole page.
    ///
    /// # Errors
    ///
    /// When the app's template does not render, or what the layout reads fails.
    fn page<'a>(
        &'a self,
        page: Page<'a>,
    ) -> Pin<Box<dyn Future<Output = owt_web::Result<Response>> + Send + 'a>>;
}

impl<T: Chrome> AsyncChrome for T {
    fn page<'a>(
        &'a self,
        page: Page<'a>,
    ) -> Pin<Box<dyn Future<Output = owt_web::Result<Response>> + Send + 'a>> {
        Box::pin(std::future::ready(Chrome::page(self, page)))
    }
}

/// The app's audit log: handed each [`Event`] after the change it records is made.
/// The change is committed by then, so a recorder that fails is logged at `error` and
/// the person's answer stands.
pub trait Recorder: Send + Sync + 'static {
    /// Record `event`, made by the request `request`.
    ///
    /// # Errors
    ///
    /// When it cannot be recorded.
    fn record<'a>(
        &'a self,
        request: &'a Parts,
        event: &'a Event,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send + 'a>>;
}

/// How each page's body is drawn from its view model. Every method has the
/// [`Tailwind`] body as its default; an app overrides the pages it draws itself, with
/// templates that escape HTML ([`Body::render`]). The field names each form posts are
/// fixed: `code`, `recovery_code`, `password` and `next`.
pub trait Views: Send + Sync + 'static {
    /// The sign-in challenge.
    ///
    /// # Errors
    ///
    /// When the template does not render.
    fn challenge(&self, request: &Parts, view: &ChallengeView) -> owt_web::Result<Body> {
        let _ = request;
        Body::render(&ChallengeHtml { v: view })
    }

    /// Step-up re-authentication.
    ///
    /// # Errors
    ///
    /// When the template does not render.
    fn reauth(&self, request: &Parts, view: &ReauthView) -> owt_web::Result<Body> {
        let _ = request;
        Body::render(&ReauthHtml { v: view })
    }

    /// An authenticator being set up. [`EnrollView::qr_svg`] is markup the library made:
    /// embed it unescaped (`|safe`); everything else is text.
    ///
    /// # Errors
    ///
    /// When the template does not render.
    fn enroll(&self, request: &Parts, view: &EnrollView<'_>) -> owt_web::Result<Body> {
        let _ = request;
        Body::render(&EnrollHtml { v: view })
    }

    /// New recovery codes, shown once.
    ///
    /// # Errors
    ///
    /// When the template does not render.
    fn recovery_codes(&self, request: &Parts, view: &CodesView) -> owt_web::Result<Body> {
        let _ = request;
        Body::render(&CodesHtml { v: view })
    }

    /// The account's factors.
    ///
    /// # Errors
    ///
    /// When the template does not render.
    fn settings(&self, request: &Parts, view: &SettingsView) -> owt_web::Result<Body> {
        let _ = request;
        Body::render(&SettingsHtml { v: view })
    }

    /// The page that names and creates a passkey.
    ///
    /// # Errors
    /// When the template does not render.
    fn add_passkey(&self, request: &Parts, view: &PasskeyAddView) -> owt_web::Result<Body> {
        let _ = request;
        Body::render(&PasskeyAddHtml { v: view })
    }
}

/// The pages in `owt-*` classes from `tailwind/owt.css`: what [`MfaPages`] draws unless
/// given other [`Views`].
#[derive(Clone, Copy, Debug, Default)]
pub struct Tailwind;

impl Views for Tailwind {}

/// The sign-in challenge. Its form posts `code` or `recovery_code`, and `next`, to
/// `action`.
#[derive(Debug)]
#[non_exhaustive]
pub struct ChallengeView {
    /// Where the form posts.
    pub action: String,
    /// Where the person goes once through, a path on this site.
    pub next: String,
    /// Why the last answer was refused.
    pub error: Option<String>,
    /// The passkey button, when the account has a passkey: a second form posting
    /// `passkey_token`, `passkey_credential` and `next` to `action`.
    pub passkey: Option<PasskeyPrompt>,
}

/// A passkey ceremony begun for a page: what its button needs.
#[derive(Debug)]
#[non_exhaustive]
pub struct PasskeyPrompt {
    /// The token to post back as `passkey_token`.
    pub token: String,
    /// The options for `navigator.credentials`, as JSON (put it in `data-options`;
    /// the template escapes it).
    pub options: String,
    /// The URL of the script that runs the button.
    pub script: String,
}

/// The page that names and creates a passkey. Its form posts `name`,
/// `passkey_token`, `passkey_credential` (filled by the script) and `next` to
/// `action`.
#[derive(Debug)]
#[non_exhaustive]
pub struct PasskeyAddView {
    /// Where the form posts.
    pub action: String,
    /// Where the person goes once through, a path on this site.
    pub next: String,
    /// The token to post back as `passkey_token`.
    pub token: String,
    /// The options for `navigator.credentials.create()`, as JSON.
    pub options: String,
    /// The URL of the script that runs the button.
    pub script: String,
    /// Why the last answer was refused.
    pub error: Option<String>,
    /// The person is not signed in yet: the policy requires a factor before they are.
    pub pending: bool,
}

/// One passkey on the settings page, with where its forms post.
#[derive(Debug)]
#[non_exhaustive]
pub struct PasskeyRow {
    /// The passkey.
    pub info: PasskeyInfo,
    /// Where "rename" posts (`name`).
    pub rename: String,
    /// Where "remove" posts.
    pub remove: String,
}

/// Step-up re-authentication. Its form posts `password` (when asked), `code` or
/// `recovery_code` (when asked), and `next`, to `action`.
#[derive(Debug)]
#[non_exhaustive]
pub struct ReauthView {
    /// Where the form posts.
    pub action: String,
    /// Where the person goes once through, a path on this site.
    pub next: String,
    /// The account has a password: ask for it.
    pub password: bool,
    /// The account has a second factor: ask for a code.
    pub code: bool,
    /// Why the last answer was refused, or why nothing here can prove who the person
    /// is (an account with neither, which must sign in again).
    pub error: Option<String>,
    /// The sign-in page, for an account with nothing to prove here.
    pub sign_in: String,
    /// The passkey button, when the account has a passkey: it posts
    /// `passkey_token` and `passkey_credential` with the password.
    pub passkey: Option<PasskeyPrompt>,
}

/// An authenticator being set up. Its form posts `code` and `next` to `action`.
#[non_exhaustive]
pub struct EnrollView<'a> {
    /// Where the form posts.
    pub action: String,
    /// Where the person goes once through, a path on this site.
    pub next: String,
    /// The QR code, an SVG document the library made: embed it unescaped.
    pub qr_svg: &'a str,
    /// The secret as base32, to type into an app that cannot scan.
    pub secret: &'a str,
    /// Why the last code was refused.
    pub error: Option<String>,
    /// The person is not signed in yet: the policy requires a factor before they are.
    pub pending: bool,
    /// The page that adds a passkey instead, when passkeys are on.
    pub add_passkey: Option<String>,
}

impl fmt::Debug for EnrollView<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EnrollView")
            .field("action", &self.action)
            .field("next", &self.next)
            .field("error", &self.error)
            .field("pending", &self.pending)
            .finish_non_exhaustive()
    }
}

/// Recovery codes, shown once.
#[non_exhaustive]
pub struct CodesView {
    /// The codes.
    pub codes: Vec<String>,
    /// Where "continue" goes.
    pub next: String,
}

impl fmt::Debug for CodesView {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CodesView")
            .field("codes", &self.codes.len())
            .field("next", &self.next)
            .finish()
    }
}

/// The account's factors and what can be done with them; each action is a `POST`
/// form with no fields.
#[derive(Debug)]
#[non_exhaustive]
pub struct SettingsView {
    /// An authenticator is set up.
    pub totp: bool,
    /// It is locked after too many wrong codes.
    pub locked: bool,
    /// Recovery codes not yet used.
    pub codes_left: i64,
    /// What was just done, or refused.
    pub notice: Option<Notice>,
    /// The enrollment page (a `GET` link).
    pub enroll: String,
    /// Where "remove" posts.
    pub remove: String,
    /// Where "set up again" posts.
    pub reenroll: String,
    /// Where "new recovery codes" posts.
    pub recovery_codes: String,
    /// The page that adds a passkey (a `GET` link), when passkeys are on; `None`
    /// hides the passkey section.
    pub add_passkey: Option<String>,
    /// The account's passkeys.
    pub passkeys: Vec<PasskeyRow>,
}

/// A sentence for the settings page, after a redirect.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct Notice {
    /// It reports a refusal.
    pub error: bool,
    /// The sentence.
    pub text: &'static str,
}

impl Notice {
    fn named(name: Option<&str>) -> Option<Self> {
        let (error, text) = match name? {
            "removed" => (
                false,
                "The authenticator was removed, with its recovery codes.",
            ),
            "already" => (false, "An authenticator is already set up."),
            "last-factor" => (
                true,
                "This account must keep a second factor, so it cannot be removed.",
            ),
            "not-enrolled" => (true, "This account has no authenticator."),
            "passkey-added" => (false, "The passkey was added."),
            "passkey-renamed" => (false, "The passkey was renamed."),
            "passkey-removed" => (false, "The passkey was removed."),
            "passkey-unknown" => (true, "This account has no such passkey."),
            "passkey-name" => (true, "Give the passkey a name of 1 to 64 characters."),
            _ => return None,
        };
        Some(Self { error, text })
    }
}

#[derive(Template)]
#[template(path = "mfa/challenge.html")]
struct ChallengeHtml<'a> {
    v: &'a ChallengeView,
}

#[derive(Template)]
#[template(path = "mfa/reauth.html")]
struct ReauthHtml<'a> {
    v: &'a ReauthView,
}

#[derive(Template)]
#[template(path = "mfa/enroll.html")]
struct EnrollHtml<'a, 'b> {
    v: &'a EnrollView<'b>,
}

#[derive(Template)]
#[template(path = "mfa/codes.html")]
struct CodesHtml<'a> {
    v: &'a CodesView,
}

#[derive(Template)]
#[template(path = "mfa/passkey_add.html")]
struct PasskeyAddHtml<'a> {
    v: &'a PasskeyAddView,
}

#[derive(Template)]
#[template(path = "mfa/settings.html")]
struct SettingsHtml<'a> {
    v: &'a SettingsView,
}

/// A [`Key`] that owns its login, so a boxed charge borrows only the limiter.
enum OwnedKey {
    Login(String),
    SecondFactor(i64),
    Reauth(i64),
}

impl OwnedKey {
    fn of(key: Key<'_>) -> Self {
        match key {
            Key::Login(login) => Self::Login(login.to_owned()),
            Key::SecondFactor(id) => Self::SecondFactor(id),
            Key::Reauth(id) => Self::Reauth(id),
        }
    }

    fn key(&self) -> Key<'_> {
        match self {
            Self::Login(login) => Key::Login(login),
            Self::SecondFactor(id) => Key::SecondFactor(*id),
            Self::Reauth(id) => Key::Reauth(*id),
        }
    }
}

/// A [`Limiter`] behind a pointer: [`Limiter::charge`] answers an `impl Future`, so the
/// trait is not object safe.
trait Charge: Send + Sync {
    fn charge_boxed(
        &self,
        ip: IpAddr,
        key: OwnedKey,
    ) -> Pin<Box<dyn Future<Output = Result<(), Throttled>> + Send + '_>>;
}

impl<L: Limiter> Charge for L {
    fn charge_boxed(
        &self,
        ip: IpAddr,
        key: OwnedKey,
    ) -> Pin<Box<dyn Future<Output = Result<(), Throttled>> + Send + '_>> {
        Box::pin(async move { self.charge(ip, key.key()).await })
    }
}

#[derive(Clone)]
struct Erased(Arc<dyn Charge>);

impl Limiter for Erased {
    fn charge(
        &self,
        ip: IpAddr,
        key: Key<'_>,
    ) -> impl Future<Output = Result<(), Throttled>> + Send {
        self.0.charge_boxed(ip, OwnedKey::of(key))
    }
}

/// The pages, configured. Build them, then merge [`MfaPages::routes`] into the app's
/// router inside the accounts layer. `T` is the session data type
/// ([`Data`] unless [`MfaPages::session`] says otherwise).
pub struct MfaPages<T = Data> {
    pool: PgPool,
    mfa: Mfa,
    limiter: Erased,
    chrome: Arc<dyn AsyncChrome>,
    views: Arc<dyn Views>,
    recorder: Option<Arc<dyn Recorder>>,
    base: String,
    reauth: String,
    change_within: Duration,
    data: PhantomData<fn() -> T>,
}

impl<T> fmt::Debug for MfaPages<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MfaPages")
            .field("base", &self.base)
            .field("reauth", &self.reauth)
            .field("mfa", &self.mfa)
            .finish_non_exhaustive()
    }
}

/// A path below the root, without a trailing slash.
fn path(p: &str, what: &str) -> String {
    let p = p.trim_end_matches('/').to_owned();
    assert!(
        p.starts_with('/') && p.len() > 1 && !p.starts_with("//"),
        "the {what} is a path below the root, such as /mfa"
    );
    p
}

impl MfaPages<Data> {
    /// The pages over `pool`'s accounts with `mfa`'s configuration (the same [`Mfa`]
    /// given to [`Accounts::require_mfa`](crate::Accounts::require_mfa)), charging every
    /// attempt to `limiter` (the app's sign-in throttle), drawn inside `chrome`.
    pub fn new(
        pool: PgPool,
        mfa: Mfa,
        limiter: impl Limiter + 'static,
        chrome: impl AsyncChrome,
    ) -> Self {
        Self {
            pool,
            mfa,
            limiter: Erased(Arc::new(limiter)),
            chrome: Arc::new(chrome),
            views: Arc::new(Tailwind),
            recorder: None,
            base: "/mfa".to_owned(),
            reauth: "/reauth".to_owned(),
            change_within: CHANGE_WITHIN,
            data: PhantomData,
        }
    }
}

impl<T: MfaSession> MfaPages<T> {
    /// Serve the pages below `base` rather than `/mfa`. Tell
    /// [`Accounts::enroll_at`](crate::Accounts::enroll_at) `{base}/enroll`.
    ///
    /// # Panics
    ///
    /// When `base` is not a path below the root.
    #[must_use]
    pub fn at(mut self, base: impl Into<String>) -> Self {
        self.base = path(&base.into(), "base");
        self
    }

    /// Serve step-up re-authentication at `path` rather than `/reauth`. Tell
    /// [`Accounts::reauth_at`](crate::Accounts::reauth_at) the same.
    ///
    /// # Panics
    ///
    /// When `path` is not a path below the root.
    #[must_use]
    pub fn reauth_at(mut self, reauth: impl Into<String>) -> Self {
        self.reauth = path(&reauth.into(), "re-authentication path");
        self
    }

    /// Draw the bodies with `views` rather than [`Tailwind`].
    #[must_use]
    pub fn views(mut self, views: impl Views) -> Self {
        self.views = Arc::new(views);
        self
    }

    /// Hand each [`Event`] to `recorder`, the app's audit log. Without one, events are
    /// logged at `info` only, and [`MfaPages::routes`] warns.
    #[must_use]
    pub fn audit(mut self, recorder: impl Recorder) -> Self {
        self.recorder = Some(Arc::new(recorder));
        self
    }

    /// How recently a second factor must have been used to change one
    /// ([`CHANGE_WITHIN`] by default).
    #[must_use]
    pub fn change_within(mut self, within: Duration) -> Self {
        self.change_within = within;
        self
    }

    /// Read and write session data `U`, the type the app's session layer carries.
    #[must_use]
    pub fn session<U: MfaSession>(self) -> MfaPages<U> {
        MfaPages {
            pool: self.pool,
            mfa: self.mfa,
            limiter: self.limiter,
            chrome: self.chrome,
            views: self.views,
            recorder: self.recorder,
            base: self.base,
            reauth: self.reauth,
            change_within: self.change_within,
            data: PhantomData,
        }
    }

    /// The routes, at the paths [`MfaPages::at`] and [`MfaPages::reauth_at`] set: merge
    /// them into the app's router, inside the session layer and the accounts layer
    /// ([`crate::Accounts::load`]).
    pub fn routes<S: Clone + Send + Sync + 'static>(self) -> Router<S> {
        if self.recorder.is_none() {
            tracing::warn!(
                base = %self.base,
                "the second-factor pages record no audit events: give them a Recorder with MfaPages::audit"
            );
        }
        let base = self.base.clone();
        let reauth = self.reauth.clone();
        let pages = Arc::new(self);
        Router::new()
            .route(&base, get(settings::<T>))
            .route(
                &format!("{base}/challenge"),
                get(challenge_form::<T>).post(challenge::<T>),
            )
            .route(
                &format!("{base}/enroll"),
                get(enroll_form::<T>).post(enroll::<T>),
            )
            .route(&format!("{base}/remove"), post(remove::<T>))
            .route(&format!("{base}/reenroll"), post(reenroll::<T>))
            .route(&format!("{base}/recovery-codes"), post(recovery_codes::<T>))
            .route(&format!("{base}/passkey.js"), get(passkey_script))
            .route(
                &format!("{base}/passkeys/add"),
                get(passkey_add_form::<T>).post(passkey_add::<T>),
            )
            .route(
                &format!("{base}/passkeys/{{id}}/rename"),
                post(passkey_rename::<T>),
            )
            .route(
                &format!("{base}/passkeys/{{id}}/remove"),
                post(passkey_remove::<T>),
            )
            .route(&reauth, get(reauth_form::<T>).post(reauth_post::<T>))
            .with_state(pages)
            .layer(axum::middleware::from_fn_with_state(
                CrossOrigin::new(),
                CrossOrigin::layer,
            ))
            .layer(axum::middleware::map_response(
                crate::admin::never_cached_or_framed,
            ))
    }

    fn enroll_url(&self) -> String {
        format!("{}/enroll", self.base)
    }

    fn script_url(&self) -> String {
        format!("{}/passkey.js", self.base)
    }

    fn add_passkey_url(&self) -> Option<String> {
        self.mfa
            .relying_party()
            .map(|_| format!("{}/passkeys/add", self.base))
    }

    /// The passkey button for `account`, when it has a passkey and they are on.
    async fn passkey_prompt(
        &self,
        session: &Session<T>,
        account: &Account,
    ) -> Result<Option<PasskeyPrompt>, MfaError> {
        let Some(begun) = self
            .mfa
            .begin_passkey_challenge(&self.pool, session, account)
            .await?
        else {
            return Ok(None);
        };
        Ok(Some(self.prompt(&begun)?))
    }

    fn prompt(
        &self,
        begun: &Ceremony<RequestChallengeResponse>,
    ) -> Result<PasskeyPrompt, MfaError> {
        Ok(PasskeyPrompt {
            token: begun.token.clone(),
            options: begun.options_json()?,
            script: self.script_url(),
        })
    }

    async fn render(
        &self,
        request: &Parts,
        account: Option<&Account>,
        title: &str,
        status: StatusCode,
        body: owt_web::Result<Body>,
    ) -> Response {
        let page = match body {
            Ok(body) => {
                self.chrome
                    .page(Page {
                        request,
                        account,
                        title,
                        body,
                    })
                    .await
            }
            Err(e) => Err(e),
        };
        match page {
            Ok(response) => {
                let mut response = (CachePolicy::no_store(), response).into_response();
                if status != StatusCode::OK {
                    *response.status_mut() = status;
                }
                response
            }
            Err(e) => e.into_response(),
        }
    }

    async fn record(&self, request: &Parts, events: &[Event]) {
        for event in events {
            tracing::info!(
                account = event.account,
                event = event.name(),
                "second factor"
            );
            if let Some(recorder) = &self.recorder
                && let Err(e) = recorder.record(request, event).await
            {
                tracing::error!(
                    error = %e,
                    account = event.account,
                    event = event.name(),
                    "a second-factor event could not be recorded"
                );
            }
        }
    }

    /// The account that may enroll: the one signed in, or the pending sign-in the policy
    /// holds to enrollment.
    async fn enrolling(
        &self,
        parts: &Parts,
        session: &Session<T>,
    ) -> owt_web::Result<Option<(Account, bool)>> {
        if let Some(account) = Maybe::of(&parts.extensions).0 {
            return Ok(Some((account, false)));
        }
        Ok(self
            .mfa
            .pending_account(&self.pool, session)
            .await?
            .filter(|(_, kind)| *kind == Kind::Enroll)
            .map(|(account, _)| (account, true)))
    }
}

type Shared<T> = State<Arc<MfaPages<T>>>;

/// The request's parts, with the URI the client sent (`OriginalUri`) in place of the
/// one a nested router sees.
struct Req(Parts);

// Answers without awaiting; the trait is async.
#[allow(clippy::unused_async_trait_impl)]
impl<S: Send + Sync> FromRequestParts<S> for Req {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        let mut whole = parts.clone();
        if let Some(original) = parts.extensions.get::<OriginalUri>() {
            whole.uri = original.0.clone();
        }
        Ok(Self(whole))
    }
}

#[derive(Deserialize)]
struct NextQuery {
    next: Option<String>,
    notice: Option<String>,
}

#[derive(Deserialize)]
struct CodeForm {
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    recovery_code: Option<String>,
    #[serde(default)]
    passkey_token: Option<String>,
    #[serde(default)]
    passkey_credential: Option<String>,
    #[serde(default)]
    next: Option<String>,
}

/// A passkey answer a form carried: its token and the browser's credential, parsed.
struct PasskeyAnswer<C> {
    token: String,
    credential: C,
}

/// The passkey answer in `token` and `credential`, if both were posted; `Err` when the
/// credential is not the JSON the browser sends.
fn passkey_answer<C: serde::de::DeserializeOwned>(
    token: Option<&String>,
    credential: Option<&String>,
) -> Option<Result<PasskeyAnswer<C>, MfaError>> {
    let token = token.map(|t| t.trim()).filter(|t| !t.is_empty())?;
    let credential = credential.map(|c| c.trim()).filter(|c| !c.is_empty())?;
    Some(
        serde_json::from_str(credential)
            .map(|credential| PasskeyAnswer {
                token: token.to_owned(),
                credential,
            })
            .map_err(|_| MfaError::Invalid),
    )
}

impl CodeForm {
    fn passkey(&self) -> Option<Result<PasskeyAnswer<PublicKeyCredential>, MfaError>> {
        passkey_answer(
            self.passkey_token.as_ref(),
            self.passkey_credential.as_ref(),
        )
    }

    fn answer(&self) -> Option<Answer<'_>> {
        fn given(s: Option<&String>) -> Option<&str> {
            s.map(|s| s.trim()).filter(|s| !s.is_empty())
        }
        given(self.code.as_ref())
            .map(Answer::Totp)
            .or_else(|| given(self.recovery_code.as_ref()).map(Answer::Recovery))
    }
}

impl fmt::Debug for CodeForm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CodeForm(<redacted>)")
    }
}

/// `next` when it is a path on this site, else `fallback`.
fn local_next(next: Option<&str>, fallback: &str) -> String {
    owt_web::redirect::local_or(next, fallback).to_owned()
}

/// `path` with `?next=` set to `next`.
fn with_next(path: &str, next: &str) -> String {
    let mut url = String::from(path);
    url.push(if path.contains('?') { '&' } else { '?' });
    url.push_str("next=");
    url.extend(url::form_urlencoded::byte_serialize(next.as_bytes()));
    url
}

fn see_other(to: &str) -> Response {
    (CachePolicy::no_store(), Redirect::to(to)).into_response()
}

#[expect(
    clippy::result_large_err,
    reason = "the error is the response the handler answers at once"
)]
fn client_ip(parts: &Parts) -> Result<IpAddr, Response> {
    ClientIp::of(parts).ok_or_else(|| {
        owt_web::Error::Internal(anyhow::anyhow!(
            "the second-factor pages need the client's address (ConnectInfo)"
        ))
        .into_response()
    })
}

/// The sentence for a refusal the person can act on; a fault is the error page.
#[expect(
    clippy::result_large_err,
    reason = "the error is the response the handler answers at once"
)]
fn refusal(e: MfaError) -> Result<(StatusCode, String), Response> {
    match e {
        MfaError::Fault(_) | MfaError::Unavailable => Err(owt_web::Error::from(e).into_response()),
        other => Ok((other.status(), other.to_string())),
    }
}

/// The sign-in page, sending the person back to `next` afterwards.
fn to_sign_in(parts: &Parts, next: &str) -> Response {
    see_other(&with_next(layer::sign_in_at(&parts.extensions), next))
}

async fn challenge_form<T: MfaSession>(
    State(p): Shared<T>,
    Req(parts): Req,
    session: Session<T>,
    Query(q): Query<NextQuery>,
) -> Response {
    let next = local_next(q.next.as_deref(), "/");
    if Maybe::of(&parts.extensions).0.is_some() {
        return see_other(&next);
    }
    let account = match p.mfa.pending_account(&p.pool, &session).await {
        Ok(Some((account, Kind::Challenge))) => account,
        Ok(Some((_, Kind::Enroll))) => return see_other(&with_next(&p.enroll_url(), &next)),
        Ok(_) => return to_sign_in(&parts, &next),
        Err(e) => return owt_web::Error::from(e).into_response(),
    };
    challenge_page(&p, &parts, &session, &account, next, None).await
}

/// The challenge page for the pending `account`, with `error` if the last answer was
/// refused.
async fn challenge_page<T: MfaSession>(
    p: &MfaPages<T>,
    parts: &Parts,
    session: &Session<T>,
    account: &Account,
    next: String,
    error: Option<(StatusCode, String)>,
) -> Response {
    let passkey = match p.passkey_prompt(session, account).await {
        Ok(prompt) => prompt,
        Err(e) => return owt_web::Error::from(e).into_response(),
    };
    let (status, error) = error.map_or((StatusCode::OK, None), |(s, e)| (s, Some(e)));
    let view = ChallengeView {
        action: format!("{}/challenge", p.base),
        next,
        error,
        passkey,
    };
    let body = p.views.challenge(parts, &view);
    p.render(parts, None, "Confirm it is you", status, body)
        .await
}

async fn challenge<T: MfaSession>(
    State(p): Shared<T>,
    Req(parts): Req,
    session: Session<T>,
    Form(form): Form<CodeForm>,
) -> Response {
    let next = local_next(form.next.as_deref(), "/");
    let ip = match client_ip(&parts) {
        Ok(ip) => ip,
        Err(r) => return r,
    };
    let pending = session.read(|d| d.mfa().pending.map(|p| p.account));
    let attempt = match (form.passkey(), form.answer()) {
        (Some(Ok(pk)), _) => Some(
            p.mfa
                .challenge_passkey(&p.pool, &p.limiter, &session, ip, &pk.token, &pk.credential)
                .await,
        ),
        (Some(Err(e)), _) => Some(Err(e)),
        (None, Some(answer)) => Some(
            p.mfa
                .challenge(&p.pool, &p.limiter, &session, ip, answer)
                .await,
        ),
        (None, None) => None,
    };
    let refused = match attempt {
        None => (StatusCode::UNPROCESSABLE_ENTITY, "Enter a code.".to_owned()),
        Some(attempt) => {
            match attempt {
                Ok((_, events)) => {
                    p.record(&parts, &events).await;
                    return see_other(&next);
                }
                Err(MfaError::NoChallenge) => {
                    // A sign-in held to enrollment has no code to answer: it enrolls.
                    let enrolling = matches!(
                        p.mfa.pending_account(&p.pool, &session).await,
                        Ok(Some((_, Kind::Enroll)))
                    );
                    return if enrolling {
                        see_other(&with_next(&p.enroll_url(), &next))
                    } else {
                        to_sign_in(&parts, &next)
                    };
                }
                Err(e) => {
                    if let Some(event) = pending.and_then(|a| e.event(a)) {
                        p.record(&parts, &[event]).await;
                    }
                    match refusal(e) {
                        Ok(r) => r,
                        Err(r) => return r,
                    }
                }
            }
        }
    };
    match p.mfa.pending_account(&p.pool, &session).await {
        Ok(Some((account, Kind::Challenge))) => {
            challenge_page(&p, &parts, &session, &account, next, Some(refused)).await
        }
        Ok(_) => to_sign_in(&parts, &next),
        Err(e) => owt_web::Error::from(e).into_response(),
    }
}

/// The reauthentication page for `account`, with `error` if the last answer was refused.
async fn reauth_page<T: MfaSession>(
    p: &MfaPages<T>,
    parts: &Parts,
    session: &Session<T>,
    account: &Account,
    next: String,
    error: Option<(StatusCode, String)>,
) -> Response {
    let has_password = match store::has_password(&p.pool, account.id).await {
        Ok(has) => has,
        Err(e) => return owt_web::Error::from(e).into_response(),
    };
    let has_factor = match p.mfa.factors(&p.pool, account.id).await {
        Ok(f) => f.any(),
        Err(e) => return owt_web::Error::from(e).into_response(),
    };
    let (status, error) = match error {
        Some((status, text)) => (status, Some(text)),
        None if !has_password && !has_factor => {
            (StatusCode::OK, Some(MfaError::NothingToProve.to_string()))
        }
        None => (StatusCode::OK, None),
    };
    let passkey = match p.passkey_prompt(session, account).await {
        Ok(prompt) => prompt,
        Err(e) => return owt_web::Error::from(e).into_response(),
    };
    let view = ReauthView {
        action: p.reauth.clone(),
        sign_in: with_next(layer::sign_in_at(&parts.extensions), &next),
        next,
        password: has_password,
        code: has_factor,
        error,
        passkey,
    };
    let body = p.views.reauth(parts, &view);
    p.render(parts, Some(account), "Confirm it is you", status, body)
        .await
}

async fn reauth_form<T: MfaSession>(
    State(p): Shared<T>,
    Req(parts): Req,
    session: Session<T>,
    Query(q): Query<NextQuery>,
) -> Response {
    let Some(account) = Maybe::of(&parts.extensions).0 else {
        return layer::wall(&parts).into_response();
    };
    let next = local_next(q.next.as_deref(), "/");
    reauth_page(&p, &parts, &session, &account, next, None).await
}

async fn reauth_post<T: MfaSession>(
    State(p): Shared<T>,
    Req(parts): Req,
    session: Session<T>,
    Form(form): Form<CodeForm>,
) -> Response {
    let Some(account) = Maybe::of(&parts.extensions).0 else {
        return layer::wall(&parts).into_response();
    };
    let next = local_next(form.next.as_deref(), "/");
    let ip = match client_ip(&parts) {
        Ok(ip) => ip,
        Err(r) => return r,
    };
    let has_factor = match p.mfa.factors(&p.pool, account.id).await {
        Ok(f) => f.any(),
        Err(e) => return owt_web::Error::from(e).into_response(),
    };
    let answer = form.answer();
    let passkey = form.passkey();
    if has_factor && answer.is_none() && passkey.is_none() {
        let error = (StatusCode::UNPROCESSABLE_ENTITY, "Enter a code.".to_owned());
        return reauth_page(&p, &parts, &session, &account, next, Some(error)).await;
    }
    let begun = p
        .mfa
        .begin_reauth(
            &p.pool,
            &p.limiter,
            &session,
            ip,
            &account,
            form.password.as_deref(),
        )
        .await;
    let outcome = match (begun, passkey, answer) {
        (Ok(Next::Challenge), Some(Ok(pk)), _) => p
            .mfa
            .challenge_passkey(&p.pool, &p.limiter, &session, ip, &pk.token, &pk.credential)
            .await
            .map(|(_, events)| events),
        (Ok(Next::Challenge), Some(Err(e)), _) | (Err(e), _, _) => Err(e),
        (Ok(Next::Challenge), None, Some(answer)) => p
            .mfa
            .challenge(&p.pool, &p.limiter, &session, ip, answer)
            .await
            .map(|(_, events)| events),
        (Ok(Next::Challenge), None, None) => Err(MfaError::Invalid),
        (Ok(_), _, _) => Ok(Vec::new()),
    };
    match outcome {
        Ok(events) => {
            p.record(&parts, &events).await;
            see_other(&next)
        }
        // The session is no longer signed in as the account: the form cannot help.
        Err(MfaError::NoChallenge) => to_sign_in(&parts, &next),
        Err(e) => {
            if let Some(event) = e.event(account.id) {
                p.record(&parts, &[event]).await;
            }
            match refusal(e) {
                Ok(error) => reauth_page(&p, &parts, &session, &account, next, Some(error)).await,
                Err(r) => r,
            }
        }
    }
}

/// Where a refused [`Mfa::authorize_change`] sends the person: to re-authenticate and
/// back to `back`, or to sign in.
fn step_up_or_sign_in<T: MfaSession>(
    p: &MfaPages<T>,
    parts: &Parts,
    e: MfaError,
    back: &str,
) -> Response {
    match e {
        MfaError::StepUp(_) => see_other(&with_next(&p.reauth, back)),
        MfaError::NoChallenge => to_sign_in(parts, back),
        other => owt_web::Error::from(other).into_response(),
    }
}

async fn enroll_page<T: MfaSession>(
    p: &MfaPages<T>,
    parts: &Parts,
    account: &Account,
    pending: bool,
    enrollment: &TotpEnrollment,
    next: String,
    error: Option<(StatusCode, String)>,
) -> Response {
    let (status, error) = error.map_or((StatusCode::OK, None), |(s, e)| (s, Some(e)));
    let view = EnrollView {
        action: p.enroll_url(),
        next,
        qr_svg: &enrollment.qr_svg,
        secret: &enrollment.secret,
        error,
        pending,
        add_passkey: p.add_passkey_url(),
    };
    let body = p.views.enroll(parts, &view);
    let signed = (!pending).then_some(account);
    p.render(parts, signed, "Set up your authenticator", status, body)
        .await
}

async fn enroll_form<T: MfaSession>(
    State(p): Shared<T>,
    Req(parts): Req,
    session: Session<T>,
    Query(q): Query<NextQuery>,
) -> Response {
    let this = layer::asked_for(&parts.extensions, &parts.uri).to_owned();
    let (account, pending) = match p.enrolling(&parts, &session).await {
        Ok(Some(found)) => found,
        Ok(None) => return to_sign_in(&parts, &this),
        Err(e) => return e.into_response(),
    };
    let next = local_next(q.next.as_deref(), if pending { "/" } else { &p.base });
    let proof = match p
        .mfa
        .authorize_change(&p.pool, &session, &account, p.change_within)
        .await
    {
        Ok(proof) => proof,
        Err(e) => return step_up_or_sign_in(&p, &parts, e, &this),
    };
    // A refresh, a prefetch or a second tab shows the secret already begun, which the
    // person may have scanned; a fresh one only when none is waiting.
    let begun = match p.mfa.resume_totp(&p.pool, &account).await {
        Ok(Some(enrollment)) => Ok(enrollment),
        Ok(None) => p.mfa.begin_totp(&p.pool, &account, &proof).await,
        Err(e) => Err(e),
    };
    match begun {
        Ok(enrollment) => enroll_page(&p, &parts, &account, pending, &enrollment, next, None).await,
        Err(MfaError::AlreadyEnrolled) => see_other(&format!("{}?notice=already", p.base)),
        Err(e) => owt_web::Error::from(e).into_response(),
    }
}

async fn enroll<T: MfaSession>(
    State(p): Shared<T>,
    Req(parts): Req,
    session: Session<T>,
    Form(form): Form<CodeForm>,
) -> Response {
    let (account, pending) = match p.enrolling(&parts, &session).await {
        Ok(Some(found)) => found,
        Ok(None) => return to_sign_in(&parts, &p.enroll_url()),
        Err(e) => return e.into_response(),
    };
    let next = local_next(form.next.as_deref(), if pending { "/" } else { &p.base });
    let again = with_next(&p.enroll_url(), &next);
    let ip = match client_ip(&parts) {
        Ok(ip) => ip,
        Err(r) => return r,
    };
    let proof = match p
        .mfa
        .authorize_change(&p.pool, &session, &account, p.change_within)
        .await
    {
        Ok(proof) => proof,
        Err(e) => return step_up_or_sign_in(&p, &parts, e, &again),
    };
    let code = form.code.as_deref().map_or_default(str::trim);
    let refused = if code.is_empty() {
        MfaError::Invalid
    } else if let Err(t) = p.limiter.charge(ip, Key::SecondFactor(account.id)).await {
        MfaError::from(t)
    } else {
        match p
            .mfa
            .confirm_totp(&p.pool, &session, &account, &proof, code)
            .await
        {
            Ok(confirmed) => {
                p.record(&parts, &confirmed.events).await;
                let view = CodesView {
                    codes: confirmed
                        .recovery_codes
                        .into_iter()
                        .map(|r| r.code)
                        .collect(),
                    next,
                };
                let body = p.views.recovery_codes(&parts, &view);
                return p
                    .render(
                        &parts,
                        Some(&account),
                        "Your recovery codes",
                        StatusCode::OK,
                        body,
                    )
                    .await;
            }
            Err(MfaError::NotEnrolling) => return see_other(&again),
            // No lock event here: an unconfirmed authenticator counts no wrong codes, so
            // `confirm_totp` never answers `Locked`.
            Err(e) => e,
        }
    };
    let error = match refusal(refused) {
        Ok(error) => error,
        Err(r) => return r,
    };
    match p.mfa.resume_totp(&p.pool, &account).await {
        Ok(Some(enrollment)) => {
            enroll_page(
                &p,
                &parts,
                &account,
                pending,
                &enrollment,
                next,
                Some(error),
            )
            .await
        }
        Ok(None) => see_other(&again),
        Err(e) => owt_web::Error::from(e).into_response(),
    }
}

async fn settings<T: MfaSession>(
    State(p): Shared<T>,
    Req(parts): Req,
    Query(q): Query<NextQuery>,
) -> Response {
    let Some(account) = Maybe::of(&parts.extensions).0 else {
        return layer::wall(&parts).into_response();
    };
    let factors = match p.mfa.factors(&p.pool, account.id).await {
        Ok(f) => f,
        Err(e) => return owt_web::Error::from(e).into_response(),
    };
    let passkeys =
        if p.mfa.relying_party().is_some() || factors.passkeys + factors.passkeys_disabled > 0 {
            match p.mfa.list_passkeys(&p.pool, account.id).await {
                Ok(list) => list,
                Err(e) => return owt_web::Error::from(e).into_response(),
            }
        } else {
            Vec::new()
        };
    let passkeys = passkeys
        .into_iter()
        .map(|info| PasskeyRow {
            rename: format!("{}/passkeys/{}/rename", p.base, info.id),
            remove: format!("{}/passkeys/{}/remove", p.base, info.id),
            info,
        })
        .collect();
    let view = SettingsView {
        add_passkey: p.add_passkey_url(),
        passkeys,
        totp: factors.totp_confirmed_at.is_some(),
        locked: factors.totp_locked,
        codes_left: factors.recovery_codes_left,
        notice: Notice::named(q.notice.as_deref()),
        enroll: p.enroll_url(),
        remove: format!("{}/remove", p.base),
        reenroll: format!("{}/reenroll", p.base),
        recovery_codes: format!("{}/recovery-codes", p.base),
    };
    let body = p.views.settings(&parts, &view);
    p.render(
        &parts,
        Some(&account),
        "Second factor",
        StatusCode::OK,
        body,
    )
    .await
}

/// Remove the authenticator, then go to `then`.
async fn remove_then<T: MfaSession>(
    p: &MfaPages<T>,
    parts: &Parts,
    session: &Session<T>,
    then: &str,
) -> Response {
    let Some(account) = Maybe::of(&parts.extensions).0 else {
        return layer::wall(parts).into_response();
    };
    let proof = match p
        .mfa
        .authorize_change(&p.pool, session, &account, p.change_within)
        .await
    {
        Ok(proof) => proof,
        Err(e) => return step_up_or_sign_in(p, parts, e, &p.base),
    };
    match p.mfa.remove_totp(&p.pool, session, &account, &proof).await {
        Ok(event) => {
            p.record(parts, &[event]).await;
            see_other(then)
        }
        Err(MfaError::LastFactor) => see_other(&format!("{}?notice=last-factor", p.base)),
        Err(MfaError::NotEnrolled) => see_other(&format!("{}?notice=not-enrolled", p.base)),
        Err(e) => owt_web::Error::from(e).into_response(),
    }
}

async fn remove<T: MfaSession>(
    State(p): Shared<T>,
    Req(parts): Req,
    session: Session<T>,
) -> Response {
    let then = format!("{}?notice=removed", p.base);
    remove_then(&p, &parts, &session, &then).await
}

async fn reenroll<T: MfaSession>(
    State(p): Shared<T>,
    Req(parts): Req,
    session: Session<T>,
) -> Response {
    let then = with_next(&p.enroll_url(), &p.base);
    remove_then(&p, &parts, &session, &then).await
}

async fn recovery_codes<T: MfaSession>(
    State(p): Shared<T>,
    Req(parts): Req,
    session: Session<T>,
) -> Response {
    let Some(account) = Maybe::of(&parts.extensions).0 else {
        return layer::wall(&parts).into_response();
    };
    let proof = match p
        .mfa
        .authorize_change(&p.pool, &session, &account, p.change_within)
        .await
    {
        Ok(proof) => proof,
        Err(e) => return step_up_or_sign_in(&p, &parts, e, &p.base),
    };
    match p
        .mfa
        .regenerate_recovery_codes(&p.pool, &session, &account, &proof)
        .await
    {
        Ok((codes, event)) => {
            p.record(&parts, &[event]).await;
            let view = CodesView {
                codes: codes.into_iter().map(|r| r.code).collect(),
                next: p.base.clone(),
            };
            let body = p.views.recovery_codes(&parts, &view);
            p.render(
                &parts,
                Some(&account),
                "Your recovery codes",
                StatusCode::OK,
                body,
            )
            .await
        }
        Err(MfaError::NotEnrolled) => see_other(&format!("{}?notice=not-enrolled", p.base)),
        Err(e) => owt_web::Error::from(e).into_response(),
    }
}

/// The script the passkey buttons run.
async fn passkey_script() -> Response {
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/javascript; charset=utf-8",
        )],
        include_str!("../../assets/passkey.js"),
    )
        .into_response()
}

#[derive(Deserialize)]
struct PasskeyForm {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    passkey_token: Option<String>,
    #[serde(default)]
    passkey_credential: Option<String>,
    #[serde(default)]
    next: Option<String>,
}

impl fmt::Debug for PasskeyForm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PasskeyForm(<redacted>)")
    }
}

/// The add-a-passkey page with a fresh ceremony, and `error` if the last answer was
/// refused.
#[allow(clippy::too_many_arguments)] // each is a separate input of the page
async fn passkey_add_page<T: MfaSession>(
    p: &MfaPages<T>,
    parts: &Parts,
    session: &Session<T>,
    account: &Account,
    proof: &super::ChangeProof,
    pending: bool,
    next: String,
    error: Option<(StatusCode, String)>,
) -> Response {
    let begun = match p
        .mfa
        .begin_passkey_registration(&p.pool, session, account, proof)
        .await
    {
        Ok(begun) => begun,
        Err(e) => return owt_web::Error::from(e).into_response(),
    };
    let options = match begun.options_json() {
        Ok(o) => o,
        Err(e) => return owt_web::Error::from(e).into_response(),
    };
    let (status, error) = error.map_or((StatusCode::OK, None), |(s, e)| (s, Some(e)));
    let view = PasskeyAddView {
        action: format!("{}/passkeys/add", p.base),
        next,
        token: begun.token,
        options,
        script: p.script_url(),
        error,
        pending,
    };
    let body = p.views.add_passkey(parts, &view);
    let signed = (!pending).then_some(account);
    p.render(parts, signed, "Add a passkey", status, body).await
}

async fn passkey_add_form<T: MfaSession>(
    State(p): Shared<T>,
    Req(parts): Req,
    session: Session<T>,
    Query(q): Query<NextQuery>,
) -> Response {
    let this = layer::asked_for(&parts.extensions, &parts.uri).to_owned();
    if p.mfa.relying_party().is_none() {
        return see_other(&p.base);
    }
    let (account, pending) = match p.enrolling(&parts, &session).await {
        Ok(Some(found)) => found,
        Ok(None) => return to_sign_in(&parts, &this),
        Err(e) => return e.into_response(),
    };
    let next = local_next(q.next.as_deref(), if pending { "/" } else { &p.base });
    let proof = match p
        .mfa
        .authorize_change(&p.pool, &session, &account, p.change_within)
        .await
    {
        Ok(proof) => proof,
        Err(e) => return step_up_or_sign_in(&p, &parts, e, &this),
    };
    passkey_add_page(&p, &parts, &session, &account, &proof, pending, next, None).await
}

async fn passkey_add<T: MfaSession>(
    State(p): Shared<T>,
    Req(parts): Req,
    session: Session<T>,
    Form(form): Form<PasskeyForm>,
) -> Response {
    let add = format!("{}/passkeys/add", p.base);
    let (account, pending) = match p.enrolling(&parts, &session).await {
        Ok(Some(found)) => found,
        Ok(None) => return to_sign_in(&parts, &add),
        Err(e) => return e.into_response(),
    };
    let next = local_next(form.next.as_deref(), if pending { "/" } else { &p.base });
    let again = with_next(&add, &next);
    let ip = match client_ip(&parts) {
        Ok(ip) => ip,
        Err(r) => return r,
    };
    let proof = match p
        .mfa
        .authorize_change(&p.pool, &session, &account, p.change_within)
        .await
    {
        Ok(proof) => proof,
        Err(e) => return step_up_or_sign_in(&p, &parts, e, &again),
    };
    let answer = passkey_answer::<RegisterPublicKeyCredential>(
        form.passkey_token.as_ref(),
        form.passkey_credential.as_ref(),
    );
    let refused = match answer {
        None => MfaError::Invalid,
        Some(Err(e)) => e,
        Some(Ok(_))
            if p.limiter
                .charge(ip, Key::SecondFactor(account.id))
                .await
                .is_err() =>
        {
            MfaError::Throttled
        }
        Some(Ok(pk)) => match p
            .mfa
            .finish_passkey_registration(
                &p.pool,
                &session,
                &account,
                &proof,
                &pk.token,
                form.name.as_deref().unwrap_or_default(),
                &pk.credential,
            )
            .await
        {
            Ok(confirmed) => {
                p.record(&parts, &confirmed.events).await;
                if confirmed.recovery_codes.is_empty() {
                    let to = if pending {
                        next
                    } else {
                        format!("{}?notice=passkey-added", p.base)
                    };
                    return see_other(&to);
                }
                let view = CodesView {
                    codes: confirmed
                        .recovery_codes
                        .into_iter()
                        .map(|r| r.code)
                        .collect(),
                    next,
                };
                let body = p.views.recovery_codes(&parts, &view);
                return p
                    .render(
                        &parts,
                        Some(&account),
                        "Your recovery codes",
                        StatusCode::OK,
                        body,
                    )
                    .await;
            }
            Err(e) => e,
        },
    };
    let error = match refusal(refused) {
        Ok(error) => error,
        Err(r) => return r,
    };
    passkey_add_page(
        &p,
        &parts,
        &session,
        &account,
        &proof,
        pending,
        next,
        Some(error),
    )
    .await
}

#[derive(Deserialize)]
struct NameForm {
    #[serde(default)]
    name: String,
}

async fn passkey_rename<T: MfaSession>(
    State(p): Shared<T>,
    Req(parts): Req,
    axum::extract::Path(id): axum::extract::Path<i64>,
    Form(form): Form<NameForm>,
) -> Response {
    let Some(account) = Maybe::of(&parts.extensions).0 else {
        return layer::wall(&parts).into_response();
    };
    match p
        .mfa
        .rename_passkey(&p.pool, &account, id, &form.name)
        .await
    {
        Ok(event) => {
            p.record(&parts, &[event]).await;
            see_other(&format!("{}?notice=passkey-renamed", p.base))
        }
        Err(MfaError::BadName) => see_other(&format!("{}?notice=passkey-name", p.base)),
        Err(MfaError::NotEnrolled) => see_other(&format!("{}?notice=passkey-unknown", p.base)),
        Err(e) => owt_web::Error::from(e).into_response(),
    }
}

async fn passkey_remove<T: MfaSession>(
    State(p): Shared<T>,
    Req(parts): Req,
    session: Session<T>,
    axum::extract::Path(id): axum::extract::Path<i64>,
) -> Response {
    let Some(account) = Maybe::of(&parts.extensions).0 else {
        return layer::wall(&parts).into_response();
    };
    let proof = match p
        .mfa
        .authorize_change(&p.pool, &session, &account, p.change_within)
        .await
    {
        Ok(proof) => proof,
        Err(e) => return step_up_or_sign_in(&p, &parts, e, &p.base),
    };
    match p
        .mfa
        .remove_passkey(&p.pool, &session, &account, &proof, id)
        .await
    {
        Ok(event) => {
            p.record(&parts, &[event]).await;
            see_other(&format!("{}?notice=passkey-removed", p.base))
        }
        Err(MfaError::LastFactor) => see_other(&format!("{}?notice=last-factor", p.base)),
        Err(MfaError::NotEnrolled) => see_other(&format!("{}?notice=passkey-unknown", p.base)),
        Err(e) => owt_web::Error::from(e).into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn next_stays_on_this_site() {
        for evil in [
            "https://evil.example/",
            "//evil.example",
            "/\\evil.example",
            "javascript:alert(1)",
            "",
        ] {
            assert_eq!(local_next(Some(evil), "/"), "/", "{evil}");
        }
        assert_eq!(local_next(Some("/a?b=1"), "/"), "/a?b=1");
        assert_eq!(local_next(None, "/mfa"), "/mfa");
    }

    #[test]
    fn next_is_encoded() {
        assert_eq!(
            with_next("/reauth", "/a?b=1&c"),
            "/reauth?next=%2Fa%3Fb%3D1%26c"
        );
    }

    #[test]
    fn the_pages_render() {
        let view = ChallengeView {
            action: "/mfa/challenge".into(),
            next: "/x\"><script>".into(),
            error: Some("<b>no</b>".into()),
            passkey: None,
        };
        let html = Tailwind.challenge(&dummy(), &view).unwrap().to_string();
        assert!(html.contains("name=\"code\"") && html.contains("name=\"recovery_code\""));
        assert!(
            !html.contains("<script>") && !html.contains("<b>no</b>"),
            "{html}"
        );
        let html = Tailwind
            .enroll(
                &dummy(),
                &EnrollView {
                    action: "/mfa/enroll".into(),
                    next: "/".into(),
                    qr_svg: "<svg></svg>",
                    secret: "ABCD",
                    error: None,
                    pending: false,
                    add_passkey: None,
                },
            )
            .unwrap()
            .to_string();
        assert!(html.contains("<svg></svg>") && html.contains("ABCD"));
    }

    fn dummy() -> Parts {
        axum::http::Request::new(()).into_parts().0
    }
}
