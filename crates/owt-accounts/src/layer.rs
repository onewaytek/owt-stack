//! The signed-in account, once per request, and the extractors that name it.
//!
//! [`Accounts::load`] runs after the session layer: it reads the session's
//! signature, loads the account if the epoch still matches, and puts the result in
//! the request's extensions. The extractors read it from there, so a handler naming
//! [`Signed`] and a template helper naming [`Maybe`] cost one query between them.
//! That query also reads what the gates ask about the account (whether it holds a
//! second factor, for [`Accounts::require_mfa`], and which policy versions it
//! accepted, for [`Policies::gate`](crate::policies::Policies::gate)), so a signed-in
//! request costs one query for all of them.
//!
//! A signature whose epoch no longer matches (signed out everywhere, password
//! changed, deactivated) is dropped from the session, so the cookie stops carrying
//! it. A database error leaves the request anonymous and the cookie as it was: an
//! outage must neither admit a revoked session nor sign everyone out. [`Signed`] and
//! [`Staff`] then answer 503 rather than sending the visitor to a sign-in page where
//! signing in would fail too; [`Maybe`] reads as anonymous, since page chrome has
//! nothing better to show.
//!
//! An htmx request (not a boosted navigation) that meets the sign-in wall gets
//! `HX-Redirect` instead of the 303, so htmx loads the sign-in page as a whole page
//! rather than following the redirect and swapping it into the element it was
//! updating; `?next=` names the page the visitor was on, not the fragment.

// The extractors answer from the extensions without awaiting; the trait is async.
#![allow(clippy::unused_async_trait_impl)]

use axum::extract::{FromRequestParts, OriginalUri, Request, State};
use axum::http::request::Parts;
use axum::http::{Extensions, HeaderName, HeaderValue, StatusCode, Uri, header};
use axum::middleware::Next;
use axum::response::Response;
use owt_web::Error;
use owt_web::session::Session;
use sqlx::PgPool;

use std::sync::Arc;

use crate::mfa::{Mfa, MfaSession};
use crate::session::Signed as SignedData;
use crate::store::{self, Account, Extra, Standing};

/// The layer's state: the pool and where the sign-in page is.
#[derive(Clone, Debug)]
pub struct Accounts {
    pool: PgPool,
    sign_in: String,
    reauth: String,
    enroll: String,
    mfa: Option<MfaGate>,
}

/// The second-factor gate [`Accounts::require_mfa`] fixes for one session data type:
/// it reads the session, the account and whether the account holds a factor.
type GateFn<T> = dyn Fn(&Session<T>, &Account, bool) -> Gate + Send + Sync;

#[derive(Clone, Debug)]
struct MfaGate {
    /// The session data type the gate was made for.
    data: std::any::TypeId,
    /// An `Arc<GateFn<T>>` of that type.
    gate: Arc<dyn std::any::Any + Send + Sync>,
}

/// What the second-factor gate decided about a signature.
enum Gate {
    /// It stands; whether the account has a second factor, if the gate looked.
    Open(Option<bool>),
    /// It does not (yet): the visitor is anonymous.
    Held,
}

impl Accounts {
    /// Accounts in `pool`; a handler that needs one sends the visitor to `sign_in`
    /// (a path, such as `/login`) with `?next=` set.
    pub fn new(pool: PgPool, sign_in: impl Into<String>) -> Self {
        Self {
            pool,
            sign_in: sign_in.into(),
            reauth: "/reauth".to_owned(),
            enroll: "/mfa/enroll".to_owned(),
            mfa: None,
        }
    }

    /// Hold every signature to the second factor, wherever it came from. [`load`](Self::load)
    /// and [`load_with`](Self::load_with) then treat a signature for an account that has a
    /// confirmed factor, or that `mfa`'s policy requires to have one, as signed in only when
    /// the session shows a second factor passed for that account and epoch. Until then the
    /// request is anonymous, and the session becomes the pending sign-in a challenge or
    /// enrollment page continues ([`Mfa::pending_account`]). A password sign-in, a link, a
    /// provider and [`session::password_gate`](crate::session::password_gate) are all
    /// closed by it, including an old `/login` route left in place.
    ///
    /// `T` is the session data type, and must be the one `load::<T>` is installed with:
    /// `load::<Other>` on an `Accounts` that requires MFA for `T` logs an error and answers
    /// 503 to anyone signed in, rather than run single-factor.
    #[must_use]
    pub fn require_mfa<T: MfaSession>(mut self, mfa: Mfa) -> Self {
        let gate: Arc<GateFn<T>> =
            Arc::new(move |session: &Session<T>, account: &Account, has: bool| {
                match mfa.gate(session, account, has) {
                    Some(has) => Gate::Open(Some(has)),
                    None => Gate::Held,
                }
            });
        self.mfa = Some(MfaGate {
            data: std::any::TypeId::of::<T>(),
            gate: Arc::new(gate),
        });
        self
    }

    /// Where [`RecentMfa`](crate::mfa::RecentMfa) sends an account that has no second
    /// factor (a path, `/mfa/enroll` by default), with `?next=` set.
    #[must_use]
    pub fn enroll_at(mut self, path: impl Into<String>) -> Self {
        self.enroll = path.into();
        self
    }

    /// Where [`Recent`](crate::mfa::Recent) sends a visitor whose last sign-in is too
    /// old for the page (a path, `/reauth` by default), with `?next=` set.
    #[must_use]
    pub fn reauth_at(mut self, path: impl Into<String>) -> Self {
        self.reauth = path.into();
        self
    }

    /// The middleware. Install it with
    /// `axum::middleware::from_fn_with_state(accounts, Accounts::load::<T>)`, where
    /// `T` is the session data type, *inside* the session layer (so it runs after
    /// it).
    pub async fn load<T: SignedData>(
        State(this): State<Self>,
        req: Request,
        next: Next,
    ) -> Response {
        this.load_by::<T, _, _, _>(req, next, |pool, id, epoch, session| async move {
            let account = store::standing_in_epoch(&pool, id, epoch, session.as_deref()).await?;
            Ok(account.map(|(account, standing)| (account, (), standing)))
        })
        .await
    }

    /// [`load`](Self::load), also reading `X` about the account in the same query as
    /// the epoch check (see [`store::Extra`]), for [`SignedWith`] and [`MaybeWith`].
    /// [`Maybe`], [`Signed`] and [`Staff`] read the account as under `load`. Install it
    /// as `Accounts::load_with::<T, X>` in place of `load`.
    pub async fn load_with<T: SignedData, X: Extra + Clone>(
        State(this): State<Self>,
        req: Request,
        next: Next,
    ) -> Response {
        this.load_by::<T, _, _, _>(req, next, |pool, id, epoch, session| async move {
            store::standing_in_epoch_with::<X>(&pool, id, epoch, session.as_deref()).await
        })
        .await
    }

    /// What the second-factor gate, if one is required, makes of this signature for
    /// `account`, which holds a factor if `has_factor`.
    fn hold<T: SignedData>(
        &self,
        session: Option<&Session<T>>,
        account: &Account,
        has_factor: bool,
    ) -> sqlx::Result<Gate> {
        let (Some(required), Some(session)) = (&self.mfa, session) else {
            return Ok(Gate::Open(None));
        };
        let gate = (required.data == std::any::TypeId::of::<T>())
            .then(|| required.gate.downcast_ref::<Arc<GateFn<T>>>())
            .flatten();
        let Some(gate) = gate else {
            tracing::error!(
                data = std::any::type_name::<T>(),
                "Accounts::require_mfa was made for another session data type than the one \
                 load is installed with: refusing every signed-in request"
            );
            return Err(sqlx::Error::Configuration(
                "require_mfa and load name different session data types".into(),
            ));
        };
        Ok(gate(session, account, has_factor))
    }

    /// The middleware, with `read` asking for the session's account (by id, in its
    /// epoch), what comes with it and its standing, in one query.
    async fn load_by<T, X, F, R>(self, mut req: Request, next: Next, read: R) -> Response
    where
        T: SignedData,
        X: Clone + Send + Sync + 'static,
        F: Future<Output = sqlx::Result<Option<(Account, X, Standing)>>>,
        R: FnOnce(PgPool, i64, i32, Option<String>) -> F,
    {
        let session = req.extensions().get::<Session<T>>().cloned();
        let loaded = match session.as_ref().and_then(|s| s.read(SignedData::signature)) {
            None => Loaded::Anonymous,
            Some(signature) => {
                let id = session.as_ref().and_then(Session::id);
                match read(self.pool.clone(), signature.account, signature.epoch, id).await {
                    Ok(Some((account, extra, standing))) => {
                        let held = self.hold::<T>(session.as_ref(), &account, standing.has_factor);
                        match held {
                            Ok(Gate::Open(has_factor)) => {
                                req.extensions_mut().insert(LoadedExtra(extra));
                                req.extensions_mut()
                                    .insert(AcceptedVersions(standing.accepted.into()));
                                if let Some(has) = has_factor {
                                    req.extensions_mut().insert(HasFactor(has));
                                }
                                Loaded::Account(account)
                            }
                            Ok(Gate::Held) => Loaded::Anonymous,
                            Err(e) => {
                                tracing::warn!(error = %e, "the session's second factor could not be checked");
                                Loaded::Unknown
                            }
                        }
                    }
                    Ok(None) => {
                        // Revoked: the cookie must stop carrying it.
                        if let Some(session) = &session {
                            session.update(|data| data.set_signature(None));
                        }
                        Loaded::Anonymous
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "the session's account could not be read");
                        Loaded::Unknown
                    }
                }
            }
        };
        req.extensions_mut().insert(loaded);
        req.extensions_mut().insert(SignInAt(self.sign_in.clone()));
        req.extensions_mut().insert(ReauthAt(self.reauth.clone()));
        req.extensions_mut().insert(EnrollAt(self.enroll.clone()));
        let htmx = HtmxWall::of(&req, &self.sign_in);
        let mut response = next.run(req).await;
        if let Some(htmx) = htmx {
            htmx.replace_wall(&mut response);
        }
        response
    }
}

const HX_REDIRECT: HeaderName = HeaderName::from_static("hx-redirect");

/// The sign-in wall as an htmx request (not a boosted navigation) meets it. htmx
/// would follow the wall's 303 inside its request and swap the sign-in page into the
/// element it was updating, and `?next=` would name the fragment. `HX-Redirect` has
/// htmx load the sign-in page as a whole page instead, with `?next=` naming the page
/// the visitor was on: `HX-Current-URL`'s path and query when it is this site's,
/// else the request's own (see [`owt_web::redirect::htmx_current_page`]).
struct HtmxWall {
    /// The `Location` the wall answers this request with.
    wall: String,
    /// Where `HX-Redirect` sends the visitor instead.
    instead: String,
}

impl HtmxWall {
    fn of(req: &Request, sign_in: &str) -> Option<Self> {
        let flag = |name: &str| {
            req.headers()
                .get(name)
                .is_some_and(|v| v.as_bytes() == b"true")
        };
        if !flag("hx-request") || flag("hx-boosted") {
            return None;
        }
        let asked = asked_for(req.extensions(), req.uri());
        let page = owt_web::redirect::htmx_current_page(req.headers());
        let (Error::Redirect(wall), Error::Redirect(instead)) = (
            Error::login_required(sign_in, asked),
            Error::login_required(sign_in, page.as_deref().unwrap_or(asked)),
        ) else {
            return None;
        };
        Some(Self { wall, instead })
    }

    /// `response`, if it is the wall's 303, becomes a 204 carrying `HX-Redirect`.
    /// Any other response, a handler's own redirect included, is left as it is.
    fn replace_wall(self, response: &mut Response) {
        let is_wall = response.status() == StatusCode::SEE_OTHER
            && response
                .headers()
                .get(header::LOCATION)
                .is_some_and(|l| l.as_bytes() == self.wall.as_bytes());
        if let (true, Ok(instead)) = (is_wall, HeaderValue::from_str(&self.instead)) {
            *response.status_mut() = StatusCode::NO_CONTENT;
            let h = response.headers_mut();
            h.remove(header::LOCATION);
            h.insert(HX_REDIRECT, instead);
            h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        }
    }
}

/// The path and query the client sent (`OriginalUri`): under `Router::nest`, the
/// request's own URI has had the prefix removed. Only its path and query, so an
/// absolute-form request target cannot put a host into `next`.
pub(crate) fn asked_for<'a>(extensions: &'a Extensions, uri: &'a Uri) -> &'a str {
    let uri = extensions.get::<OriginalUri>().map_or(uri, |u| &u.0);
    uri.path_and_query().map_or("/", |p| p.as_str())
}

/// What the layer found out, kept in the request's extensions.
#[derive(Clone, Debug)]
enum Loaded {
    /// No signature, or a revoked one.
    Anonymous,
    /// A signature whose epoch still stands.
    Account(Account),
    /// A signature the database could not be asked about.
    Unknown,
}

/// What the layer read beside the account, kept beside [`Loaded::Account`]: `()` under
/// [`Accounts::load`], the app's type under [`Accounts::load_with`].
#[derive(Clone, Debug)]
struct LoadedExtra<X>(X);

/// Where the sign-in page is, for the extractors' redirect.
#[derive(Clone, Debug)]
struct SignInAt(String);

/// Where the re-authentication page is, for [`Recent`](crate::mfa::Recent)'s redirect.
#[derive(Clone, Debug)]
pub(crate) struct ReauthAt(pub(crate) String);

/// Where the enrollment page is, for [`RecentMfa`](crate::mfa::RecentMfa)'s redirect.
#[derive(Clone, Debug)]
pub(crate) struct EnrollAt(pub(crate) String);

/// Whether the signed-in account has a second factor, when the layer looked
/// ([`Accounts::require_mfa`]).
#[derive(Clone, Copy, Debug)]
pub(crate) struct HasFactor(pub(crate) bool);

/// The policy versions the signed-in account accepted (`policy_acceptances` ids), read
/// with the account, for [`Policies::gate`](crate::policies::Policies::gate). Present
/// whenever [`Loaded::Account`] is.
#[derive(Clone, Debug)]
pub(crate) struct AcceptedVersions(pub(crate) Arc<[i64]>);

/// The signed-in account, if any. Available to anything with the request's
/// extensions (a page-context extractor, say), not only as a handler argument.
#[derive(Clone, Debug, Default)]
pub struct Maybe(pub Option<Account>);

impl Maybe {
    /// The account the request's extensions hold, or none if the layer is not
    /// installed or could not read it.
    #[must_use]
    pub fn of(extensions: &axum::http::Extensions) -> Self {
        match extensions.get::<Loaded>() {
            Some(Loaded::Account(account)) => Self(Some(account.clone())),
            Some(Loaded::Anonymous | Loaded::Unknown) | None => Self(None),
        }
    }
}

impl<S: Send + Sync> FromRequestParts<S> for Maybe {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        Ok(Self::of(&parts.extensions))
    }
}

/// The signed-in account and what [`Accounts::load_with`] read with it, if any: none
/// also when the layer is [`Accounts::load`], or `load_with` of another type, which
/// logs a warning (the app installed the wrong layer).
#[derive(Clone, Debug)]
pub struct MaybeWith<X>(pub Option<(Account, X)>);

impl<X: Clone + Send + Sync + 'static> MaybeWith<X> {
    /// What the request's extensions hold, as [`Maybe::of`].
    #[must_use]
    pub fn of(extensions: &axum::http::Extensions) -> Self {
        let account = Maybe::of(extensions).0;
        let extra = extensions.get::<LoadedExtra<X>>().map(|e| e.0.clone());
        if account.is_some() && extra.is_none() {
            tracing::warn!(
                "MaybeWith<{}> needs the layer Accounts::load_with of that type; \
                 the signed-in viewer reads as anonymous",
                std::any::type_name::<X>()
            );
        }
        Self(account.zip(extra))
    }
}

impl<S: Send + Sync, X: Clone + Send + Sync + 'static> FromRequestParts<S> for MaybeWith<X> {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        Ok(Self::of(&parts.extensions))
    }
}

/// The sentence a walled page answers with while the database is unreachable.
const UNAVAILABLE: &str = "Signing in is unavailable for a moment. Please try again shortly.";

/// The wall an anonymous visitor meets: the sign-in redirect, or 503 when the
/// database could not say who they are, since the sign-in page would fail them too.
///
/// `?next=` is the URI the client sent ([`asked_for`]): a visitor sent back to
/// `/profile` instead of `/es/profile` lands on a 404 or another page. On an htmx
/// request [`Accounts::load`] turns the redirect into [`HtmxWall`]'s.
pub(crate) fn wall(parts: &Parts) -> Error {
    if matches!(parts.extensions.get::<Loaded>(), Some(Loaded::Unknown)) {
        return Error::unavailable(UNAVAILABLE);
    }
    let next = asked_for(&parts.extensions, &parts.uri);
    let login = parts
        .extensions
        .get::<SignInAt>()
        .map_or("/login", |s| s.0.as_str());
    Error::login_required(login, next)
}

/// A signed-in account: the handler is walled, and an anonymous visitor is sent to
/// the sign-in page with `?next=` naming this request.
#[derive(Clone, Debug)]
pub struct Signed(pub Account);

impl<S: Send + Sync> FromRequestParts<S> for Signed {
    type Rejection = Error;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        match Maybe::of(&parts.extensions).0 {
            Some(account) => Ok(Self(account)),
            None => Err(wall(parts)),
        }
    }
}

/// A signed-in account and what [`Accounts::load_with`] read with it, walled as
/// [`Signed`] is. Signed in under a layer that read no `X` ([`Accounts::load`], or
/// `load_with` of another type), it answers 500: the app installed the wrong layer.
#[derive(Clone, Debug)]
pub struct SignedWith<X>(pub Account, pub X);

impl<S: Send + Sync, X: Clone + Send + Sync + 'static> FromRequestParts<S> for SignedWith<X> {
    type Rejection = Error;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        let Some(account) = Maybe::of(&parts.extensions).0 else {
            return Err(wall(parts));
        };
        match parts.extensions.get::<LoadedExtra<X>>() {
            Some(extra) => Ok(Self(account, extra.0.clone())),
            None => Err(Error::Internal(anyhow::anyhow!(
                "SignedWith<{}> needs the layer Accounts::load_with of that type",
                std::any::type_name::<X>()
            ))),
        }
    }
}

/// A signed-in member of staff. Anyone else signed in gets a 403; an anonymous
/// visitor goes to the sign-in page.
#[derive(Clone, Debug)]
pub struct Staff(pub Account);

impl<S: Send + Sync> FromRequestParts<S> for Staff {
    type Rejection = Error;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        match Maybe::of(&parts.extensions).0 {
            Some(account) if account.is_staff => Ok(Self(account)),
            Some(_) => Err(Error::Forbidden("Only staff can open this page.".into())),
            None => Err(wall(parts)),
        }
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

    fn app() -> Router {
        let pool = PgPool::connect_lazy("postgres://nobody@127.0.0.1:1/none").unwrap();
        let accounts = Accounts::new(pool, "/login");
        Router::new()
            .route("/worlds/3/panel", get(|_: Signed| async {}))
            .route(
                "/redirects",
                get(|| async { Error::Redirect("/elsewhere".into()) }),
            )
            .layer(from_fn_with_state(
                accounts,
                Accounts::load::<crate::session::Data>,
            ))
    }

    async fn call(uri: &str, headers: &[(&str, &str)]) -> Response {
        let mut req = Request::get(uri).header("host", "app.test");
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        app()
            .oneshot(req.body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    fn header<'a>(r: &'a Response, name: &str) -> Option<&'a str> {
        r.headers().get(name).map(|v| v.to_str().unwrap())
    }

    const HTMX: (&str, &str) = ("hx-request", "true");

    #[tokio::test]
    async fn a_page_meets_the_303() {
        let r = call("/worlds/3/panel?x=4", &[]).await;
        assert_eq!(r.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            header(&r, "location"),
            Some("/login?next=%2Fworlds%2F3%2Fpanel%3Fx%3D4")
        );
        assert_eq!(header(&r, "hx-redirect"), None);
    }

    #[tokio::test]
    async fn an_htmx_request_is_sent_to_sign_in_from_its_page() {
        let r = call(
            "/worlds/3/panel?x=4",
            &[
                HTMX,
                ("hx-current-url", "https://app.test/worlds/3?tab=map"),
            ],
        )
        .await;
        assert_eq!(r.status(), StatusCode::NO_CONTENT);
        assert_eq!(header(&r, "location"), None);
        assert_eq!(
            header(&r, "hx-redirect"),
            Some("/login?next=%2Fworlds%2F3%3Ftab%3Dmap")
        );
        assert_eq!(header(&r, "cache-control"), Some("no-store"));
    }

    #[tokio::test]
    async fn without_a_current_page_of_this_site_next_is_the_request() {
        for current in [
            None,
            Some("https://evil.test/phish"),
            Some("https://app.test//evil.test/"),
            Some("not a url"),
        ] {
            let mut headers = vec![HTMX];
            headers.extend(current.map(|c| ("hx-current-url", c)));
            let r = call("/worlds/3/panel?x=4", &headers).await;
            assert_eq!(r.status(), StatusCode::NO_CONTENT, "{current:?}");
            assert_eq!(
                header(&r, "hx-redirect"),
                Some("/login?next=%2Fworlds%2F3%2Fpanel%3Fx%3D4"),
                "{current:?}"
            );
        }
    }

    #[tokio::test]
    async fn a_boosted_navigation_and_other_redirects_keep_the_303() {
        let r = call(
            "/worlds/3/panel",
            &[
                HTMX,
                ("hx-boosted", "true"),
                ("hx-current-url", "https://app.test/"),
            ],
        )
        .await;
        assert_eq!(r.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            header(&r, "location"),
            Some("/login?next=%2Fworlds%2F3%2Fpanel")
        );
        let r = call("/redirects", &[HTMX]).await;
        assert_eq!(r.status(), StatusCode::SEE_OTHER);
        assert_eq!(header(&r, "location"), Some("/elsewhere"));
    }
}
