//! The accounts admin: pages where staff find an account and change who it is and
//! what it may do. Mount it once; the app keeps its own pages for anything else it
//! stores about a person, and the admin links to them ([`Admin::more`]).
//!
//! - **Find:** search by username or email, and by the app's own columns
//!   ([`Admin::search`]); filter by staff, by each of the app's [roles](crate::roles),
//!   or deactivated; paged.
//! - **Create:** username, email, staff and roles; no password. The way in is
//!   given afterwards, once: a generated password or a sign-in link.
//! - **Change:** email, active, staff, each role; reset to a generated password,
//!   issue a sign-in link ([`Admin::sign_in_links`]), sign out everywhere, unlink a
//!   provider identity, turn password sign-in on or off
//!   ([`store::set_password_sign_in`]), retire a local identity
//!   ([`identities::forget_as`]). An account with password sign-in off is badged in
//!   the list, and its page offers no password.
//!
//! What it refuses: taking away your own staff access, deactivating yourself, turning
//! your own password sign-in off or retiring your own local identity, a
//! change by someone who stopped being staff after their request began, unlinking an
//! account's only way in, and every refusal the [`store`] makes (a taken email, say).
//! Each change runs in a transaction that first locks the acting member of staff's
//! row and the account's, in id order, and checks the actor is still active staff in
//! their session's epoch: two staff removing each other's access at once queue, and
//! the second is refused, so staff never reach zero this way.
//!
//! A password or link is shown once, in the answer to the `POST` that made it; every
//! page here is `no-store`. Each change is logged at `info` with who made it and what
//! it changed.
//!
//! The app supplies its layout through a [`Chrome`] function: the admin renders the
//! page's body and the app wraps it, as it would any page. The body comes from
//! [`Views`]: by default [`Tailwind`], which uses only `owt-*` classes (from
//! `tailwind/owt.css`); an app with another design system implements [`Views`] and
//! renders each page's view model ([`ListView`], [`NewView`], [`AccountView`]) with
//! its own templates. Either way the routes, the checks and the log stay here: only
//! [`Staff`] reach the routes, and the routes refuse a cross-origin `POST` themselves
//! ([`CrossOrigin`]), whether or not the app layers it too: a sibling subdomain is
//! same-site, so `SameSite=Lax` alone would let it post.

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use askama::Template;
use askama::filters::HtmlSafe;
use axum::Router;
use axum::extract::{Form, FromRequestParts, Path, Query, State};
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use owt_web::cache::CachePolicy;
use owt_web::csrf::CrossOrigin;
use owt_web::pager::Pager;
use owt_web::request::RequestInfo;
use owt_web::ui::{Field, Pagination};
use serde::Deserialize;
use sqlx::{PgConnection, PgExecutor, PgPool};

use crate::roles::{self, Role};
use crate::store::{self, Account, COLUMNS, New};
use crate::{Refused, Staff, identities, links};

/// Accounts on one list page.
pub const PER_PAGE: usize = 50;

/// The rendered body of an admin page, for the app's layout to embed as
/// `{{ page.body }}`: HTML the admin escaped already, so an Askama layout does not
/// escape it again.
#[derive(Clone, Debug)]
pub struct Body(pub(crate) String);

impl fmt::Display for Body {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl HtmlSafe for Body {}

impl Body {
    /// `template`, rendered: what a [`Views`] method answers. The body is embedded
    /// as it is, never escaped again, so `template` must be one Askama escapes HTML
    /// in: a file ending `.html` (`path = "admin/list.html"`) or a `source` with
    /// `ext = "html"`. A `.txt` or `.md` template, or `escape = "none"`, prints the
    /// view models' text raw, and a username, email or provider label its owner chose
    /// becomes markup on a staff page. Never `|safe` a view model's text.
    ///
    /// # Errors
    ///
    /// When the template does not render.
    pub fn render(template: &impl Template) -> owt_web::Result<Self> {
        template
            .render()
            .map(Self)
            .map_err(|e| owt_web::Error::Internal(e.into()))
    }
}

/// What the app's [`Chrome`] wraps: an admin page.
#[non_exhaustive]
pub struct Page<'a> {
    /// The request, for whatever the app's layout reads from it (its extensions hold
    /// the session, the CSP nonce, the signed-in account).
    pub request: &'a Parts,
    /// The member of staff looking at it.
    pub me: &'a Account,
    /// The page's title, as plain text: `Accounts`, or an account's username, which
    /// its owner chose. Escape it (an Askama layout does); never format it into HTML.
    pub title: &'a str,
    /// The page's content.
    pub body: Body,
}

/// The app's layout: wraps an admin page's body in the app's shell and answers it.
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

/// How the admin draws each page's body from its view model. Every method has the
/// [`Tailwind`] body as its default, so an app overrides the pages it draws itself
/// (all of them, for a design system of its own).
///
/// A view model carries what the page shows and the URLs its links and forms use;
/// the field names each form posts are on its view model. The routes check what is
/// posted whatever the markup: a page that offers less (no "Staff" box on your own
/// account) is a choice of the app's, and one that offers more is refused.
///
/// Much of a view model's text is chosen by someone other than staff (usernames,
/// emails, provider labels): render it only through an HTML-escaping template, as
/// [`Body::render`] says.
pub trait Views: Send + Sync + 'static {
    /// The list of accounts.
    ///
    /// # Errors
    ///
    /// When the app's template does not render.
    fn list(&self, request: &Parts, view: &ListView<'_>) -> owt_web::Result<Body> {
        let _ = request;
        Body::render(&ListHtml { v: view })
    }

    /// The form for a new account, empty or with what was posted and why it was
    /// refused.
    ///
    /// # Errors
    ///
    /// When the app's template does not render.
    fn new_account(&self, request: &Parts, view: &NewView<'_>) -> owt_web::Result<Body> {
        let _ = request;
        Body::render(&NewHtml {
            v: view,
            username: Field::text("username", "Username")
                .value(view.username)
                .hint("One word, no “@”. It does not change later.")
                .required()
                .autofocus(),
            email: Field::email("email", "Email")
                .value(view.email)
                .hint("Optional. It signs in with the password, as the username does; a provider sign-in never matches it."),
        })
    }

    /// An account's page.
    ///
    /// When it fails on a page carrying a [`Secret`] (the answer to setting a password
    /// or issuing a link, both already made), the error is logged and the
    /// [`Tailwind`] page shows the secret instead: nothing could show it again.
    ///
    /// # Errors
    ///
    /// When the app's template does not render.
    fn account(&self, request: &Parts, view: &AccountView<'_>) -> owt_web::Result<Body> {
        let _ = request;
        Body::render(&AccountHtml {
            v: view,
            email: Field::email("email", "Email")
                .value(&view.email)
                .error(view.email_error.as_deref())
                .hint("It signs in with the password, as the username does; a provider sign-in never matches it."),
        })
    }
}

/// The admin's own pages, in `owt-*` classes from `tailwind/owt.css`: what an
/// [`Admin`] draws unless given other [`Views`].
#[derive(Clone, Copy, Debug, Default)]
pub struct Tailwind;

impl Views for Tailwind {}

/// The list of accounts, at the admin's base. Its search form `GET`s [`ListView::url`]
/// with `q` (the term) and `role` (a filter's value); its pages are
/// [`ListView::pagination`]'s links, which keep both.
#[derive(Debug)]
#[non_exhaustive]
pub struct ListView<'a> {
    /// The list's URL: where the search form goes.
    pub url: String,
    /// The new-account form's URL.
    pub new_account: String,
    /// The search term, trimmed.
    pub q: &'a str,
    /// What the search box finds: `Username or email`, or with the app's own
    /// ([`Admin::search`]) `Username, email or nickname`.
    pub placeholder: String,
    /// A failure to report: the app's search failed.
    pub notice: Option<Notice>,
    /// The filter in force: a value of [`ListView::filters`], or empty for everyone.
    pub filter: &'a str,
    /// The filters, as `(value, label)`: staff, each of the app's roles, deactivated.
    pub filters: Vec<(String, String)>,
    /// How many accounts match, on every page.
    pub total: i64,
    /// This page's accounts, by username.
    pub rows: Vec<Row>,
    /// The page links: `items()` for the app's own markup (it displays as `owt-*`).
    pub pagination: Pagination<'a>,
}

/// An account in the list.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct Row {
    /// The account's id.
    pub id: i64,
    /// Its page's URL.
    pub href: String,
    /// Its username.
    pub username: String,
    /// Its email, or empty.
    pub email: String,
    /// What it is, in words: deactivated, staff, each role, `User` when none of
    /// those; then `Password sign-in off` when it is.
    pub badges: Vec<Badge>,
    /// Whether a password may open it ([`store::set_password_sign_in`]).
    pub password_sign_in: bool,
    /// The day it last signed in (`YYYY-MM-DD`), or empty for never.
    pub last_sign_in: String,
}

/// A word beside an account in the list.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct Badge {
    /// The word: `Staff`, a role's label.
    pub text: String,
    /// Drawn quieter: `Deactivated`, `User`, a role the app does not declare.
    pub quiet: bool,
}

/// The new-account form. It `POST`s [`NewView::action`] with `username`, `email`,
/// `staff` (a checkbox, present when ticked) and a `role` for each role ticked (its
/// [`RoleChoice::name`]). There is no password: the account's page gives a way in.
#[derive(Debug)]
#[non_exhaustive]
pub struct NewView<'a> {
    /// Where the form posts.
    pub action: String,
    /// The list's URL.
    pub list: String,
    /// Why the last attempt was refused (a taken username, say).
    pub error: Option<String>,
    /// The username, as posted.
    pub username: &'a str,
    /// The email, as posted.
    pub email: &'a str,
    /// Whether staff is ticked.
    pub staff: bool,
    /// The app's roles, ticked as posted.
    pub roles: Vec<RoleChoice>,
}

/// An account's page. Its forms `POST` no fields except these:
///
/// - [`AccountView::save`]: `email`, `active` and `staff` (checkboxes, present when
///   ticked), and a `role` for each role ticked, declared or
///   [undeclared](AccountView::undeclared) (unticking an undeclared one revokes it).
///   On your own account ([`AccountView::myself`]) send `active` and `staff` ticked:
///   taking either away is refused.
/// - [`AccountView::set_password`] and [`AccountView::issue_link`] answer this page
///   with the [`AccountView::secret`]. Setting a password is refused (409) while
///   [`AccountView::password_sign_in`] is off: offer it only when on.
/// - [`AccountView::set_password_sign_in`]: `password_sign_in`, `on` or `off`.
///   Turning it off removes the password and signs the account out everywhere; it is
///   refused on your own account.
/// - [`AccountView::sign_out`] and each [`Connection::unlink`] redirect back here.
/// - Each [`LocalIdentity::forget`]: its `key` and `subject`. It signs the account
///   out everywhere, and is refused on your own account.
#[derive(Debug)]
#[non_exhaustive]
pub struct AccountView<'a> {
    /// The account. Its username is the page's title.
    pub account: &'a Account,
    /// Whether it is the staff member's own.
    pub myself: bool,
    /// The outcome of the last change.
    pub notice: Option<Notice>,
    /// A password or sign-in link to show this once: nothing can show it again.
    pub secret: Option<Secret>,
    /// The email for the form: the account's, or what was posted when it was refused.
    pub email: String,
    /// Why the posted email was refused.
    pub email_error: Option<String>,
    /// The app's roles, ticked where the account holds them.
    pub roles: Vec<RoleChoice>,
    /// Roles the account holds that the app does not declare: shown ticked, so staff
    /// can revoke them; never granted here.
    pub undeclared: Vec<String>,
    /// Whether it has a password.
    pub has_password: bool,
    /// Whether a password may open it: off for an account reached only through a
    /// provider, a local identity or a link ([`store::set_password_sign_in`]).
    pub password_sign_in: bool,
    /// The day it was created (`YYYY-MM-DD`).
    pub joined: String,
    /// When it last signed in (`YYYY-MM-DD HH:MM`), or `never`.
    pub last_sign_in: String,
    /// Its linked provider identities.
    pub connections: Vec<Connection>,
    /// The identities the app reaches it by ([`identities::arrive_as`]).
    pub local_identities: Vec<LocalIdentity>,
    /// The app's own page about it, as `(label, href)` ([`Admin::more`]).
    pub more: Option<(&'static str, String)>,
    /// The list's URL.
    pub list: String,
    /// Where the account's form posts.
    pub save: String,
    /// Where "set a generated password" posts.
    pub set_password: String,
    /// Where turning password sign-in on or off posts.
    pub set_password_sign_in: String,
    /// Where "issue a sign-in link" posts, when the admin offers them
    /// ([`Admin::sign_in_links`]).
    pub issue_link: Option<String>,
    /// How long an issued link lasts, in words (`24 hours`); empty without links.
    pub link_lifetime: String,
    /// Where "sign out everywhere" posts.
    pub sign_out: String,
}

/// A provider identity linked to an account.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct Connection {
    /// Its id.
    pub id: i64,
    /// The provider (`google`).
    pub provider: String,
    /// Who it is there, as the provider showed it.
    pub label: String,
    /// Where "remove" posts: it signs the account out everywhere, and is refused for
    /// the account's last way in.
    pub unlink: String,
}

/// An identity the app reaches an account by, `subject` under a `key` of its own
/// ([`identities::arrive_as`]).
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct LocalIdentity {
    /// The app's namespace (`kiosk`, `system`).
    pub key: String,
    /// Who or what it is there (`desk-1`).
    pub subject: String,
    /// The day it was first used (`YYYY-MM-DD`).
    pub created: String,
    /// When it last reached the account (`YYYY-MM-DD HH:MM`).
    pub last_sign_in: String,
    /// Where "retire" posts, with `key` and `subject` ([`identities::forget_as`]).
    pub forget: String,
}

/// A role as a checkbox, posted as `role` with [`RoleChoice::name`] as its value.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct RoleChoice {
    /// The role's name: the value posted.
    pub name: String,
    /// Its label.
    pub label: String,
    /// What it allows.
    pub description: String,
    /// Whether staff hold it anyway.
    pub staff: bool,
    /// Whether it is ticked.
    pub checked: bool,
}

/// How a [`Notice`] reads. A level may be added in a minor release, so a `match` on
/// it ends with a `_` arm ([`Notice::is_error`] answers for all of them).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Level {
    /// It worked.
    Success,
    /// It was refused, or failed.
    Error,
}

/// A one-line outcome above the page.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct Notice {
    /// Success or error.
    pub level: Level,
    /// The sentence.
    pub text: String,
}

/// A password or link, shown once.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct Secret {
    /// What it is and whose, as a sentence.
    pub what: String,
    /// The password or the link.
    pub value: String,
}

#[derive(Template)]
#[template(path = "admin/list.html")]
struct ListHtml<'a, 'b> {
    v: &'a ListView<'b>,
}

#[derive(Template)]
#[template(path = "admin/new.html")]
struct NewHtml<'a, 'b> {
    v: &'a NewView<'b>,
    username: Field<'a>,
    email: Field<'a>,
}

#[derive(Template)]
#[template(path = "admin/detail.html")]
struct AccountHtml<'a, 'b> {
    v: &'a AccountView<'b>,
    email: Field<'a>,
}

type LinkUrl = Box<dyn Fn(&str) -> String + Send + Sync>;
type MoreHref = Box<dyn Fn(&Account) -> String + Send + Sync>;
type Search = Box<
    dyn Fn(String) -> Pin<Box<dyn Future<Output = anyhow::Result<Vec<i64>>> + Send>> + Send + Sync,
>;

/// The admin, configured. Build it, then merge [`Admin::routes`] into the app.
pub struct Admin {
    pool: PgPool,
    base: String,
    roles: Vec<Role>,
    chrome: Box<dyn Chrome>,
    views: Box<dyn Views>,
    links: Option<(Duration, LinkUrl)>,
    more: Option<(&'static str, MoreHref)>,
    search: Option<(&'static str, Search)>,
}

impl fmt::Debug for Admin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Admin")
            .field("base", &self.base)
            .field("roles", &self.roles)
            .finish_non_exhaustive()
    }
}

impl Admin {
    /// The admin over `pool`'s accounts, at `base` (`/staff/accounts`), drawn inside
    /// `chrome`.
    ///
    /// # Panics
    ///
    /// When `base` is not a path below the root (`/`, `staff`).
    pub fn new(pool: PgPool, base: impl Into<String>, chrome: impl Chrome) -> Self {
        let base = base.into().trim_end_matches('/').to_owned();
        assert!(
            base.starts_with('/') && base.len() > 1,
            "the admin's base is a path below the root, such as /staff/accounts"
        );
        Self {
            pool,
            base,
            roles: Vec::new(),
            chrome: Box::new(chrome),
            views: Box::new(Tailwind),
            links: None,
            more: None,
            search: None,
        }
    }

    /// The app's roles, as checkboxes and list filters, in this order.
    #[must_use]
    pub fn roles(mut self, roles: &[Role]) -> Self {
        self.roles = roles.to_vec();
        self
    }

    /// Draw the pages' bodies with `views` (the app's own templates) rather than
    /// [`Tailwind`].
    #[must_use]
    pub fn views(mut self, views: impl Views) -> Self {
        self.views = Box::new(views);
        self
    }

    /// Offer one-time sign-in links good for `ttl` (capped at [`links::MAX_TTL`]),
    /// at the URL `url` makes from a token: the app's route that calls
    /// [`links::redeem`].
    #[must_use]
    pub fn sign_in_links(
        mut self,
        ttl: Duration,
        url: impl Fn(&str) -> String + Send + Sync + 'static,
    ) -> Self {
        self.links = Some((ttl, Box::new(url)));
        self
    }

    /// Link each account's page to the app's own page about it (a profile, what it
    /// owns), labelled `label`.
    #[must_use]
    pub fn more(
        mut self,
        label: &'static str,
        href: impl Fn(&Account) -> String + Send + Sync + 'static,
    ) -> Self {
        self.more = Some((label, Box::new(href)));
        self
    }

    /// Also find accounts by the app's own columns (a nickname in its profile table),
    /// named `what` in the search box (`nickname`). `find` gets the term as typed,
    /// trimmed, and answers the ids of the accounts it matches; the list shows those
    /// with the username and email matches, once each, in the same order and filters
    /// and pages. An id with no account is ignored. It is not asked when the term is
    /// empty. When it fails, the error is logged at `warn` and the list shows the
    /// username and email matches alone, saying so.
    ///
    /// The term is the staff member's text: bind it, never format it into SQL.
    #[must_use]
    pub fn search<F, Fut>(mut self, what: &'static str, find: F) -> Self
    where
        F: Fn(String) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = anyhow::Result<Vec<i64>>> + Send + 'static,
    {
        self.search = Some((what, Box::new(move |term| Box::pin(find(term)))));
        self
    }

    /// The routes, at the `base` given to [`Admin::new`]: merge them into the app's
    /// router, inside the accounts layer ([`crate::Accounts::load`]). They refuse a
    /// cross-origin `POST` on their own.
    pub fn routes<S: Clone + Send + Sync + 'static>(self) -> Router<S> {
        let base = self.base.clone();
        let pages = Router::new()
            .route("/", get(list).post(create))
            .route("/new", get(new_form))
            .route("/{id}", get(detail).post(save))
            .route("/{id}/password", post(reset_password))
            .route("/{id}/link", post(issue_link))
            .route("/{id}/sign-out", post(sign_out))
            .route("/{id}/identities/{identity}/unlink", post(unlink))
            .route("/{id}/password-sign-in", post(set_password_sign_in))
            .route("/{id}/local-identities/forget", post(forget_local))
            .with_state(Arc::new(self))
            .layer(axum::middleware::from_fn_with_state(
                CrossOrigin::new(),
                CrossOrigin::layer,
            ))
            .layer(axum::middleware::map_response(never_framed));
        Router::new().nest(&base, pages)
    }

    fn render(
        &self,
        request: &Parts,
        me: &Account,
        title: &str,
        body: owt_web::Result<Body>,
    ) -> Response {
        let page = body.and_then(|body| {
            self.chrome.page(Page {
                request,
                me,
                title,
                body,
            })
        });
        match page {
            Ok(response) => (CachePolicy::no_store(), response).into_response(),
            Err(e) => e.into_response(),
        }
    }

    fn redirect(&self, id: i64, notice: &str) -> Response {
        (
            CachePolicy::no_store(),
            Redirect::to(&format!("{}/{id}?notice={notice}", self.base)),
        )
            .into_response()
    }
}

type Shared = State<Arc<Admin>>;

/// The request's parts, for the app's chrome.
struct Req(Parts);

// Answers without awaiting; the trait is async.
#[allow(clippy::unused_async_trait_impl)]
impl<S: Send + Sync> FromRequestParts<S> for Req {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        Ok(Self(parts.clone()))
    }
}

impl Notice {
    fn success(text: impl Into<String>) -> Self {
        Self {
            level: Level::Success,
            text: text.into(),
        }
    }

    fn error(text: impl Into<String>) -> Self {
        Self {
            level: Level::Error,
            text: text.into(),
        }
    }

    /// Whether it reports a refusal or failure.
    #[must_use]
    pub fn is_error(&self) -> bool {
        self.level == Level::Error
    }

    /// The notice a redirect named; unknown names show nothing.
    fn named(name: Option<&str>) -> Option<Self> {
        Some(match name? {
            "created" => Self::success("Account created. Give it a way in below."),
            "saved" => Self::success("Saved."),
            "signed-out" => Self::success("Signed out everywhere."),
            "unlinked" => {
                Self::success("Sign-in connection removed, and the account signed out everywhere.")
            }
            "last-way-in" => Self::error(Refused::LastWayIn.to_string()),
            "password-sign-in-on" => Self::success(
                "Password sign-in is on. The account has no password until one is set.",
            ),
            "password-sign-in-off" => Self::success(
                "Password sign-in is off: its password is gone, and the account signed out everywhere.",
            ),
            "forgotten" => {
                Self::success("Local identity retired, and the account signed out everywhere.")
            }
            _ => return None,
        })
    }
}

/// The declared roles, ticked where `ticked` names them.
fn boxes(roles: &[Role], ticked: &[String]) -> Vec<RoleChoice> {
    roles
        .iter()
        .map(|r| RoleChoice {
            name: r.name.to_owned(),
            label: r.label.to_owned(),
            description: r.description.to_owned(),
            staff: r.staff,
            checked: ticked.iter().any(|h| h == r.name),
        })
        .collect()
}

/// The roles an account holds that the app does not declare (it dropped one, or
/// another app shares the table): shown, ticked, so staff can revoke them. A name
/// declared again later would otherwise grant whatever it means then.
fn undeclared<'a>(roles: &'a [Role], held: &'a [String]) -> impl Iterator<Item = &'a String> {
    held.iter()
        .filter(|h| !roles.iter().any(|r| r.name == h.as_str()))
}

#[derive(Deserialize)]
struct ListQuery {
    #[serde(default)]
    q: String,
    #[serde(default)]
    role: String,
    page: Option<String>,
}

/// `%`, `_` and `\` matched as themselves in an `ILIKE` pattern.
fn like_escaped(term: &str) -> String {
    term.replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

/// The search's rows: a term in the username or email or one of the app's matches
/// (`$4`), and a filter (`staff`, `inactive`, or a role's name, staff counted when the
/// role says so).
const FROM: &str = "FROM accounts
     WHERE ($1 = '' OR username ILIKE '%' || $1 || '%' OR email ILIKE '%' || $1 || '%'
            OR id = ANY($4))
       AND CASE $2
           WHEN '' THEN true
           WHEN 'staff' THEN is_staff
           WHEN 'inactive' THEN NOT is_active
           ELSE ($3 AND is_staff) OR EXISTS (
               SELECT 1 FROM account_roles r WHERE r.account_id = accounts.id AND r.role = $2)
       END";

async fn list(
    State(admin): Shared,
    Staff(me): Staff,
    Req(parts): Req,
    info: RequestInfo,
    Query(query): Query<ListQuery>,
) -> owt_web::Result<Response> {
    let term = like_escaped(query.q.trim());
    let role = admin.roles.iter().find(|r| r.name == query.role);
    let filter = match query.role.as_str() {
        "staff" | "inactive" => query.role.as_str(),
        _ => role.map_or("", |r| r.name),
    };
    let staff_hold = role.is_some_and(|r| r.staff);
    let (matched, notice) = app_matches(&admin, query.q.trim()).await;
    let total: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(format!("SELECT count(*) {FROM}")))
        .bind(&term)
        .bind(filter)
        .bind(staff_hold)
        .bind(&matched)
        .fetch_one(&admin.pool)
        .await?;
    let pager = Pager::clamped(
        query.page.as_deref(),
        usize::try_from(total).unwrap_or(0),
        PER_PAGE,
    );
    let offset = i64::try_from(pager.offset(PER_PAGE)).unwrap_or(i64::MAX);
    let accounts: Vec<(Account, String, bool)> = sqlx::query_as::<
        _,
        (
            i64,
            String,
            String,
            bool,
            bool,
            i32,
            Vec<String>,
            String,
            bool,
        ),
    >(sqlx::AssertSqlSafe(format!(
        "SELECT {COLUMNS}, coalesce(to_char(last_sign_in, 'YYYY-MM-DD'), ''), password_sign_in
             {FROM}
             ORDER BY username LIMIT $5 OFFSET $6"
    )))
    .bind(&term)
    .bind(filter)
    .bind(staff_hold)
    .bind(&matched)
    .bind(i64::try_from(PER_PAGE).unwrap_or(50))
    .bind(offset)
    .fetch_all(&admin.pool)
    .await?
    .into_iter()
    .map(
        |(id, username, email, is_staff, is_active, session_epoch, roles, last, pw)| {
            (
                Account {
                    id,
                    username,
                    email,
                    is_staff,
                    is_active,
                    session_epoch,
                    roles,
                },
                last,
                pw,
            )
        },
    )
    .collect();
    let rows = accounts
        .into_iter()
        .map(|(a, last_sign_in, password_sign_in)| Row {
            badges: badges(&admin.roles, &a, password_sign_in),
            password_sign_in,
            href: format!("{}/{}", admin.base, a.id),
            id: a.id,
            username: a.username,
            email: a.email,
            last_sign_in,
        })
        .collect();
    let view = ListView {
        url: admin.base.clone(),
        new_account: format!("{}/new", admin.base),
        q: query.q.trim(),
        placeholder: admin.search.as_ref().map_or_else(
            || "Username or email".to_owned(),
            |(what, _)| format!("Username, email or {what}"),
        ),
        notice,
        filter,
        filters: filters(&admin.roles),
        total,
        rows,
        pagination: Pagination::new(pager, &info),
    };
    let body = admin.views.list(&parts, &view);
    Ok(admin.render(&parts, &me, "Accounts", body))
}

/// The list's filters, as `(value, label)`: staff, each role, deactivated.
fn filters(roles: &[Role]) -> Vec<(String, String)> {
    let mut filters = vec![("staff".to_owned(), "Staff".to_owned())];
    filters.extend(
        roles
            .iter()
            .map(|r| (r.name.to_owned(), r.label.to_owned())),
    );
    filters.push(("inactive".to_owned(), "Deactivated".to_owned()));
    filters
}

/// The accounts the app's own search matches for `term`: none when it has none, the
/// term is empty, or it failed (with a notice saying so).
async fn app_matches(admin: &Admin, term: &str) -> (Vec<i64>, Option<Notice>) {
    let Some((what, find)) = admin.search.as_ref().filter(|_| !term.is_empty()) else {
        return (Vec::new(), None);
    };
    match find(term.to_owned()).await {
        Ok(ids) => (ids, None),
        Err(e) => {
            tracing::warn!(error = ?e, "the app's admin search failed");
            let notice = Notice::error(format!(
                "Searching by {what} failed, so these are username and email matches only."
            ));
            (Vec::new(), Some(notice))
        }
    }
}

fn badges(roles: &[Role], a: &Account, password_sign_in: bool) -> Vec<Badge> {
    let mut out = Vec::new();
    if !a.is_active {
        out.push(Badge {
            text: "Deactivated".into(),
            quiet: true,
        });
    }
    if a.is_staff {
        out.push(Badge {
            text: "Staff".into(),
            quiet: false,
        });
    }
    for r in roles.iter().filter(|r| a.roles.iter().any(|h| h == r.name)) {
        out.push(Badge {
            text: r.label.into(),
            quiet: false,
        });
    }
    for name in undeclared(roles, &a.roles) {
        out.push(Badge {
            text: format!("{name} (undeclared)"),
            quiet: true,
        });
    }
    if out.is_empty() {
        out.push(Badge {
            text: "User".into(),
            quiet: true,
        });
    }
    if !password_sign_in {
        out.push(Badge {
            text: "Password sign-in off".into(),
            quiet: true,
        });
    }
    out
}

/// A posted form, as its pairs: checkboxes repeat a name (`role=host&role=editor`).
struct Posted(Vec<(String, String)>);

impl Posted {
    fn value(&self, name: &str) -> &str {
        self.0
            .iter()
            .find(|(k, _)| k == name)
            .map_or("", |(_, v)| v.as_str())
    }

    fn ticked(&self, name: &str) -> bool {
        self.0.iter().any(|(k, _)| k == name)
    }

    fn roles(&self) -> Vec<String> {
        self.0
            .iter()
            .filter(|(k, _)| k == "role")
            .map(|(_, v)| v.clone())
            .collect()
    }
}

/// The new-account form, with what was posted and why it was refused.
fn new_page(
    admin: &Admin,
    parts: &Parts,
    me: &Account,
    form: &Posted,
    error: Option<String>,
) -> Response {
    let view = NewView {
        action: admin.base.clone(),
        list: admin.base.clone(),
        error,
        username: form.value("username"),
        email: form.value("email"),
        staff: form.ticked("staff"),
        roles: boxes(&admin.roles, &form.roles()),
    };
    let body = admin.views.new_account(parts, &view);
    admin.render(parts, me, "New account", body)
}

async fn new_form(State(admin): Shared, Staff(me): Staff, Req(parts): Req) -> Response {
    new_page(&admin, &parts, &me, &Posted(Vec::new()), None)
}

/// Lock the acting member of staff's row and `target`'s, in id order (two staff
/// acting on each other queue rather than deadlock), and check the actor is still
/// active staff in the epoch their session signed in under. 403 when not; 404 when
/// `target` does not exist.
async fn lock(conn: &mut PgConnection, me: &Account, target: i64) -> owt_web::Result<()> {
    let rows: Vec<(i64, bool)> = sqlx::query_as(
        "SELECT id, is_staff AND is_active AND session_epoch = $3 FROM accounts
         WHERE id IN ($1, $2) ORDER BY id FOR UPDATE",
    )
    .bind(me.id)
    .bind(target)
    .bind(me.session_epoch)
    .fetch_all(&mut *conn)
    .await?;
    if !rows.iter().any(|&(id, staff)| id == me.id && staff) {
        return Err(owt_web::Error::Forbidden(
            "Only staff can open this page.".into(),
        ));
    }
    if !rows.iter().any(|&(id, _)| id == target) {
        return Err(owt_web::Error::NotFound);
    }
    Ok(())
}

async fn create(
    State(admin): Shared,
    Staff(me): Staff,
    Req(parts): Req,
    Form(pairs): Form<Vec<(String, String)>>,
) -> owt_web::Result<Response> {
    let form = Posted(pairs);
    let mut tx = admin.pool.begin().await?;
    lock(&mut tx, &me, me.id).await?;
    let made = store::create_in(
        &mut tx,
        New {
            username: form.value("username"),
            email: form.value("email"),
            password: None,
            is_staff: form.ticked("staff"),
        },
    )
    .await;
    let account = match made {
        Ok(account) => account,
        Err(crate::Error::Refused(r)) => {
            let mut response = new_page(&admin, &parts, &me, &form, Some(r.to_string()));
            *response.status_mut() = StatusCode::UNPROCESSABLE_ENTITY;
            return Ok(response);
        }
        Err(e) => return Err(e.into()),
    };
    let wanted = form.roles();
    let mut granted = Vec::new();
    for role in admin
        .roles
        .iter()
        .filter(|r| wanted.iter().any(|w| w == r.name))
    {
        roles::grant(&mut *tx, account.id, role, Some(me.id)).await?;
        granted.push(role.name);
    }
    tx.commit().await?;
    tracing::info!(by = me.id, account = account.id, staff = account.is_staff, roles = ?granted, "admin created an account");
    Ok(admin.redirect(account.id, "created"))
}

/// An account as its page shows it.
struct Loaded {
    account: Account,
    joined: String,
    last_sign_in: String,
    password_sign_in: bool,
}

/// The account, active or not, with its dates as text.
async fn load(db: impl PgExecutor<'_>, id: i64) -> owt_web::Result<Loaded> {
    let row = sqlx::query_as::<
        _,
        (
            i64,
            String,
            String,
            bool,
            bool,
            i32,
            Vec<String>,
            String,
            String,
            bool,
        ),
    >(sqlx::AssertSqlSafe(format!(
        "SELECT {COLUMNS}, to_char(created_at, 'YYYY-MM-DD'),
                    coalesce(to_char(last_sign_in, 'YYYY-MM-DD HH24:MI'), 'never'),
                    password_sign_in
             FROM accounts WHERE id = $1"
    )))
    .bind(id)
    .fetch_optional(db)
    .await?
    .ok_or(owt_web::Error::NotFound)?;
    let (id, username, email, is_staff, is_active, session_epoch, roles, joined, last, pw) = row;
    Ok(Loaded {
        account: Account {
            id,
            username,
            email,
            is_staff,
            is_active,
            session_epoch,
            roles,
        },
        joined,
        last_sign_in: last,
        password_sign_in: pw,
    })
}

/// The account's local identities ([`identities::arrive_as`]), as `(key, subject,
/// created, last sign-in)`, by key and subject.
async fn local_identities(
    db: impl PgExecutor<'_>,
    id: i64,
) -> sqlx::Result<Vec<(String, String, String, String)>> {
    sqlx::query_as(
        "SELECT key, subject, to_char(created_at, 'YYYY-MM-DD'),
                to_char(last_sign_in, 'YYYY-MM-DD HH24:MI')
         FROM account_local_identities WHERE account_id = $1 ORDER BY key, subject",
    )
    .bind(id)
    .fetch_all(db)
    .await
}

/// The account's page, with an outcome or a secret above it.
async fn show(
    admin: &Admin,
    parts: &Parts,
    me: &Account,
    id: i64,
    notice: Option<Notice>,
    secret: Option<Secret>,
    email_value: Option<&str>,
) -> owt_web::Result<Response> {
    let Loaded {
        account,
        joined,
        last_sign_in,
        password_sign_in,
    } = load(&admin.pool, id).await?;
    let has_password = store::has_password(&admin.pool, id).await?;
    let at = format!("{}/{id}", admin.base);
    let local_identities = local_identities(&admin.pool, id)
        .await?
        .into_iter()
        .map(|(key, subject, created, last_sign_in)| LocalIdentity {
            key,
            subject,
            created,
            last_sign_in,
            forget: format!("{at}/local-identities/forget"),
        })
        .collect();
    let connections = identities::list(&admin.pool, id)
        .await?
        .into_iter()
        .map(|l| Connection {
            unlink: format!("{}/{id}/identities/{}/unlink", admin.base, l.id),
            id: l.id,
            label: l.label().to_owned(),
            provider: l.provider,
        })
        .collect();
    let link_lifetime = admin
        .links
        .as_ref()
        .map_or_else(String::new, |(ttl, _)| human(ttl.min(&links::MAX_TTL)));
    let more = admin
        .more
        .as_ref()
        .map(|(label, href)| (*label, href(&account)));
    let email_error = notice
        .as_ref()
        .filter(|n| n.is_error() && email_value.is_some())
        .map(|n| n.text.clone());
    let view = AccountView {
        account: &account,
        myself: account.id == me.id,
        notice,
        secret,
        email: email_value.unwrap_or(&account.email).to_owned(),
        email_error,
        roles: boxes(&admin.roles, &account.roles),
        undeclared: undeclared(&admin.roles, &account.roles).cloned().collect(),
        has_password,
        password_sign_in,
        joined,
        last_sign_in,
        connections,
        local_identities,
        more,
        list: admin.base.clone(),
        save: at.clone(),
        set_password: format!("{at}/password"),
        set_password_sign_in: format!("{at}/password-sign-in"),
        issue_link: admin.links.as_ref().map(|_| format!("{at}/link")),
        link_lifetime,
        sign_out: format!("{at}/sign-out"),
    };
    let body = match admin.views.account(parts, &view) {
        // The secret is made and committed: a 500 would lose it.
        Err(e) if view.secret.is_some() => {
            tracing::error!(error = ?e, "the app's admin page failed; showing the secret in Tailwind");
            Tailwind.account(parts, &view)
        }
        body => body,
    };
    Ok(admin.render(parts, me, &account.username, body))
}

/// A lifetime in words: `15 minutes`, `24 hours`, `7 days`.
fn human(d: &Duration) -> String {
    let s = d.as_secs();
    let (n, unit) = if s.is_multiple_of(86_400) && s >= 86_400 {
        (s / 86_400, "day")
    } else if s.is_multiple_of(3_600) && s >= 3_600 {
        (s / 3_600, "hour")
    } else {
        ((s / 60).max(1), "minute")
    };
    format!("{n} {unit}{}", if n == 1 { "" } else { "s" })
}

#[derive(Deserialize)]
struct NoticeQuery {
    notice: Option<String>,
}

async fn detail(
    State(admin): Shared,
    Staff(me): Staff,
    Req(parts): Req,
    Path(id): Path<i64>,
    Query(q): Query<NoticeQuery>,
) -> owt_web::Result<Response> {
    show(
        &admin,
        &parts,
        &me,
        id,
        Notice::named(q.notice.as_deref()),
        None,
        None,
    )
    .await
}

/// No admin page is shown inside another's frame, whatever the app's own CSP (one in
/// report-only mode enforces no `frame-ancestors`, and browsers then obey
/// `X-Frame-Options`): framed by a hostile sibling subdomain, which `SameSite=Lax`
/// and [`CrossOrigin`] treat as the site itself, a click would act with staff's
/// authority. No `Content-Security-Policy` of its own: the app's `Csp` layer adds its
/// policy only to a response that has none, so one here would replace it.
pub(crate) async fn never_framed(mut response: Response) -> Response {
    response.headers_mut().insert(
        axum::http::header::X_FRAME_OPTIONS,
        axum::http::HeaderValue::from_static("DENY"),
    );
    response
}

async fn save(
    State(admin): Shared,
    Staff(me): Staff,
    Req(parts): Req,
    Path(id): Path<i64>,
    Form(pairs): Form<Vec<(String, String)>>,
) -> owt_web::Result<Response> {
    let form = Posted(pairs);
    let (active, staff) = (form.ticked("active"), form.ticked("staff"));
    if id == me.id && (!active || !staff) {
        let mut response = show(
            &admin,
            &parts,
            &me,
            id,
            Some(Notice::error(
                "You cannot take away your own staff access or deactivate yourself. Ask another member of staff.",
            )),
            None,
            None,
        )
        .await?;
        *response.status_mut() = StatusCode::FORBIDDEN;
        return Ok(response);
    }
    let mut tx = admin.pool.begin().await?;
    lock(&mut tx, &me, id).await?;
    let Loaded { account, .. } = load(&mut *tx, id).await?;
    let email_changed = store::normalize(form.value("email")) != account.email;
    if let Err(e) = store::set_email(&mut *tx, id, form.value("email")).await {
        let Some(refused) = e.refused() else {
            return Err(e.into());
        };
        let notice = Notice::error(refused.to_string());
        // Its locks and connection go before the page takes three more.
        drop(tx);
        let mut response = show(
            &admin,
            &parts,
            &me,
            id,
            Some(notice),
            None,
            Some(form.value("email")),
        )
        .await?;
        *response.status_mut() = StatusCode::UNPROCESSABLE_ENTITY;
        return Ok(response);
    }
    store::set_active(&mut *tx, id, active).await?;
    store::set_staff(&mut *tx, id, staff).await?;
    let wanted = form.roles();
    let (mut granted, mut revoked) = (Vec::new(), Vec::new());
    for role in &admin.roles {
        if wanted.iter().any(|w| w == role.name) {
            if roles::grant(&mut *tx, id, role, Some(me.id)).await? {
                granted.push(role.name);
            }
        } else if roles::revoke(&mut *tx, id, role).await? {
            revoked.push(role.name);
        }
    }
    // An undeclared role can only be kept or revoked: the form cannot grant one.
    for name in undeclared(&admin.roles, &account.roles) {
        if !wanted.contains(name) && roles::revoke_named(&mut *tx, id, name).await? {
            revoked.push(name.as_str());
        }
    }
    tx.commit().await?;
    tracing::info!(
        by = me.id,
        account = id,
        email_changed,
        active_was = account.is_active,
        active,
        staff_was = account.is_staff,
        staff,
        granted = ?granted,
        revoked = ?revoked,
        "admin saved an account"
    );
    Ok(admin.redirect(id, "saved"))
}

/// Twenty letters and digits: passes every rule in [`crate::password`] unless it
/// happens to contain the username, when another is drawn.
fn generated_password(account: &Account) -> String {
    use rand::RngExt;
    const ALPHABET: &[u8] = b"abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut rng = rand::rng();
    loop {
        // Uniform over the alphabet (no modulo bias): 20 × log2(56) ≈ 116 bits.
        let password: String = (0..20)
            .map(|_| char::from(ALPHABET[rng.random_range(0..ALPHABET.len())]))
            .collect();
        if crate::password::check(&password, &[&account.username, &account.email]).is_empty() {
            return password;
        }
    }
}

async fn reset_password(
    State(admin): Shared,
    Staff(me): Staff,
    Req(parts): Req,
    Path(id): Path<i64>,
) -> owt_web::Result<Response> {
    let mut tx = admin.pool.begin().await?;
    lock(&mut tx, &me, id).await?;
    let Loaded {
        account,
        password_sign_in,
        ..
    } = load(&mut *tx, id).await?;
    // Refused before the hash; the row is locked, so the flag holds until commit and
    // `set_password` (which refuses it too) agrees.
    if !password_sign_in {
        drop(tx);
        let notice = Notice::error(Refused::NoPasswordSignIn.to_string());
        let mut response = show(&admin, &parts, &me, id, Some(notice), None, None).await?;
        *response.status_mut() = StatusCode::CONFLICT;
        return Ok(response);
    }
    let password = generated_password(&account);
    store::set_password(&mut *tx, &account, &password).await?;
    tx.commit().await?;
    tracing::info!(by = me.id, account = id, "admin set a generated password");
    let secret = Secret {
        what: format!(
            "New password for {}. It has signed out every session and voided its unused sign-in links.",
            account.username
        ),
        value: password,
    };
    show(&admin, &parts, &me, id, None, Some(secret), None).await
}

async fn issue_link(
    State(admin): Shared,
    Staff(me): Staff,
    Req(parts): Req,
    Path(id): Path<i64>,
) -> owt_web::Result<Response> {
    let Some((ttl, url)) = &admin.links else {
        return Err(owt_web::Error::NotFound);
    };
    let mut tx = admin.pool.begin().await?;
    lock(&mut tx, &me, id).await?;
    let Loaded { account, .. } = load(&mut *tx, id).await?;
    if !account.is_active {
        drop(tx);
        let notice =
            Notice::error("A deactivated account cannot use a sign-in link. Activate it first.");
        let mut response = show(&admin, &parts, &me, id, Some(notice), None, None).await?;
        *response.status_mut() = StatusCode::CONFLICT;
        return Ok(response);
    }
    let reason = format!("issued in the admin by {} (id {})", me.username, me.id);
    let minted = links::mint(&mut *tx, account.id, *ttl, &reason).await?;
    tx.commit().await?;
    tracing::info!(by = me.id, account = id, "admin issued a sign-in link");
    let secret = Secret {
        what: format!(
            "Sign-in link for {}, good once within {}.",
            account.username,
            human(&(*ttl).min(links::MAX_TTL))
        ),
        value: url(&minted.token),
    };
    show(&admin, &parts, &me, id, None, Some(secret), None).await
}

async fn sign_out(
    State(admin): Shared,
    Staff(me): Staff,
    Path(id): Path<i64>,
) -> owt_web::Result<Response> {
    let mut tx = admin.pool.begin().await?;
    lock(&mut tx, &me, id).await?;
    store::sign_out_everywhere(&mut *tx, id).await?;
    tx.commit().await?;
    tracing::info!(
        by = me.id,
        account = id,
        "admin signed an account out everywhere"
    );
    Ok(admin.redirect(id, "signed-out"))
}

async fn unlink(
    State(admin): Shared,
    Staff(me): Staff,
    Path((id, identity)): Path<(i64, i64)>,
) -> owt_web::Result<Response> {
    let mut tx = admin.pool.begin().await?;
    lock(&mut tx, &me, id).await?;
    match identities::unlink_in(&mut tx, id, identity).await {
        // Removed: whoever signed in through it is signed out with everyone else.
        Ok(true) => {
            store::sign_out_everywhere(&mut *tx, id).await?;
            tx.commit().await?;
            tracing::info!(
                by = me.id,
                account = id,
                identity,
                "admin unlinked an identity"
            );
            Ok(admin.redirect(id, "unlinked"))
        }
        Ok(false) => Err(owt_web::Error::NotFound),
        Err(e) if e.refused() == Some(&Refused::LastWayIn) => Ok(admin.redirect(id, "last-way-in")),
        Err(e) => Err(e.into()),
    }
}

/// The account's page answering a change refused on staff's own account: 403.
async fn not_on_yourself(
    admin: &Admin,
    parts: &Parts,
    me: &Account,
    what: &str,
) -> owt_web::Result<Response> {
    let notice = Notice::error(format!(
        "You cannot {what} on your own account. Ask another member of staff."
    ));
    let mut response = show(admin, parts, me, me.id, Some(notice), None, None).await?;
    *response.status_mut() = StatusCode::FORBIDDEN;
    Ok(response)
}

async fn set_password_sign_in(
    State(admin): Shared,
    Staff(me): Staff,
    Req(parts): Req,
    Path(id): Path<i64>,
    Form(pairs): Form<Vec<(String, String)>>,
) -> owt_web::Result<Response> {
    let allowed = match Posted(pairs).value("password_sign_in") {
        "on" => true,
        "off" => false,
        _ => {
            return Err(owt_web::Error::Unprocessable(
                "Say on or off for password sign-in.".into(),
            ));
        }
    };
    // Turning it off removes the password and ends every session, the actor's too.
    if id == me.id && !allowed {
        return not_on_yourself(&admin, &parts, &me, "turn password sign-in off").await;
    }
    let mut tx = admin.pool.begin().await?;
    lock(&mut tx, &me, id).await?;
    let Loaded {
        password_sign_in: was,
        ..
    } = load(&mut *tx, id).await?;
    store::set_password_sign_in(&mut *tx, id, allowed).await?;
    tx.commit().await?;
    tracing::info!(
        by = me.id,
        account = id,
        password_sign_in_was = was,
        password_sign_in = allowed,
        "admin set password sign-in"
    );
    let notice = if allowed {
        "password-sign-in-on"
    } else {
        "password-sign-in-off"
    };
    Ok(admin.redirect(id, notice))
}

async fn forget_local(
    State(admin): Shared,
    Staff(me): Staff,
    Req(parts): Req,
    Path(id): Path<i64>,
    Form(pairs): Form<Vec<(String, String)>>,
) -> owt_web::Result<Response> {
    let form = Posted(pairs);
    let (key, subject) = (form.value("key"), form.value("subject"));
    // Retiring one signs the account out everywhere and may leave it no way in.
    if id == me.id {
        return not_on_yourself(&admin, &parts, &me, "retire a local identity").await;
    }
    let mut tx = admin.pool.begin().await?;
    lock(&mut tx, &me, id).await?;
    // Only a pair of this account's, checked before it goes: the URL names the account
    // staff are looking at. Its row is locked, so the pair cannot move to another.
    let theirs: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM account_local_identities
                        WHERE account_id = $1 AND key = $2 AND subject = $3)",
    )
    .bind(id)
    .bind(key)
    .bind(subject)
    .fetch_one(&mut *tx)
    .await?;
    if !theirs {
        return Err(owt_web::Error::NotFound);
    }
    // The account forget_as signed out must be this one; anything else rolls back.
    let forgotten = identities::forget_as(&mut *tx, key, subject).await?;
    if forgotten != Some(id) {
        return Err(owt_web::Error::Internal(anyhow::anyhow!(
            "retiring a local identity of account {id} reached {forgotten:?}"
        )));
    }
    tx.commit().await?;
    tracing::info!(
        by = me.id,
        account = id,
        key,
        subject,
        "admin retired a local identity"
    );
    Ok(admin.redirect(id, "forgotten"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_search_term_matches_its_wildcards_literally() {
        assert_eq!(like_escaped("50%_off\\"), "50\\%\\_off\\\\");
    }

    #[test]
    fn lifetimes_read_as_words() {
        assert_eq!(human(&Duration::from_secs(900)), "15 minutes");
        assert_eq!(human(&Duration::from_secs(3_600)), "1 hour");
        assert_eq!(human(&Duration::from_secs(86_400 * 7)), "7 days");
        assert_eq!(human(&Duration::from_secs(5_400)), "90 minutes");
    }

    #[test]
    fn a_generated_password_passes_the_rules() {
        let a = Account {
            id: 1,
            username: "ada".into(),
            email: "ada@example.com".into(),
            is_staff: false,
            is_active: true,
            session_epoch: 0,
            roles: Vec::new(),
        };
        for _ in 0..100 {
            let p = generated_password(&a);
            assert_eq!(p.chars().count(), 20);
            assert_eq!(
                crate::password::check(&p, &["ada", "ada@example.com"]),
                Vec::new()
            );
        }
    }

    /// The templates name only classes `tailwind/owt.css` defines: an app's
    /// stylesheet never scans this crate.
    #[test]
    fn every_class_the_templates_use_is_in_owt_css() {
        let css = include_str!("../../../tailwind/owt.css");
        let templates = [
            include_str!("../templates/admin/list.html"),
            include_str!("../templates/admin/new.html"),
            include_str!("../templates/admin/detail.html"),
            include_str!("../templates/policies/document.html"),
            include_str!("../templates/policies/agree.html"),
            include_str!("../templates/policies/admin_list.html"),
            include_str!("../templates/policies/admin_form.html"),
        ];
        for t in templates {
            for attr in t.split("class=\"").skip(1) {
                let value = attr.split('"').next().unwrap_or_default();
                for class in value.split_whitespace().filter(|c| !c.contains('{')) {
                    assert!(
                        class.starts_with("owt-"),
                        "a utility class in a template: {class}"
                    );
                    assert!(
                        css.contains(&format!(".{class} "))
                            || css.contains(&format!(".{class},"))
                            || css.contains(&format!(".{class}:")),
                        "{class} is not in owt.css"
                    );
                }
            }
        }
    }
}
