//! The accounts admin: pages where staff find an account and change who it is and
//! what it may do. Mount it once; the app keeps its own pages for anything else it
//! stores about a person, and the admin links to them ([`Admin::more`]).
//!
//! - **Find:** search by username or email, filter by staff, by each of the app's
//!   [roles](crate::roles), or deactivated; paged.
//! - **Create:** username, email, staff and roles; no password. The way in is
//!   given afterwards, once: a generated password or a sign-in link.
//! - **Change:** email, active, staff, each role; reset to a generated password,
//!   issue a sign-in link ([`Admin::sign_in_links`]), sign out everywhere, unlink a
//!   provider identity.
//!
//! What it refuses: taking away your own staff access or deactivating yourself, a
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
//! page's body (only `owt-*` classes, from `tailwind/owt.css`) and the app wraps it,
//! as it would any page. Only [`Staff`] reach the routes, and the routes refuse a
//! cross-origin `POST` themselves ([`CrossOrigin`]), whether or not the app layers it
//! too: a sibling subdomain is same-site, so `SameSite=Lax` alone would let it post.

use std::fmt;
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
pub struct Body(String);

impl fmt::Display for Body {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl HtmlSafe for Body {}

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

type LinkUrl = Box<dyn Fn(&str) -> String + Send + Sync>;
type MoreHref = Box<dyn Fn(&Account) -> String + Send + Sync>;

/// The admin, configured. Build it, then merge [`Admin::routes`] into the app.
pub struct Admin {
    pool: PgPool,
    base: String,
    roles: Vec<Role>,
    chrome: Box<dyn Chrome>,
    links: Option<(Duration, LinkUrl)>,
    more: Option<(&'static str, MoreHref)>,
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
            links: None,
            more: None,
        }
    }

    /// The app's roles, as checkboxes and list filters, in this order.
    #[must_use]
    pub fn roles(mut self, roles: &[Role]) -> Self {
        self.roles = roles.to_vec();
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
            .with_state(Arc::new(self))
            .layer(axum::middleware::from_fn_with_state(
                CrossOrigin::new(),
                CrossOrigin::layer,
            ))
            .layer(axum::middleware::map_response(never_framed));
        Router::new().nest(&base, pages)
    }

    fn render(&self, request: &Parts, me: &Account, title: &str, body: &impl Template) -> Response {
        let page = body
            .render()
            .map_err(|e| owt_web::Error::Internal(e.into()))
            .and_then(|html| {
                self.chrome.page(Page {
                    request,
                    me,
                    title,
                    body: Body(html),
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

/// A one-line outcome above the page.
#[derive(Clone, Debug)]
struct Notice {
    level: &'static str,
    text: String,
}

impl Notice {
    fn success(text: impl Into<String>) -> Self {
        Self {
            level: "success",
            text: text.into(),
        }
    }

    fn error(text: impl Into<String>) -> Self {
        Self {
            level: "error",
            text: text.into(),
        }
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
            _ => return None,
        })
    }
}

/// A password or link, shown once.
#[derive(Clone, Debug)]
struct Secret {
    what: String,
    value: String,
}

/// A role as a checkbox.
#[derive(Clone, Debug)]
struct RoleBox {
    name: String,
    label: String,
    description: String,
    staff: bool,
    checked: bool,
}

/// The declared roles, ticked where `ticked` names them.
fn boxes(roles: &[Role], ticked: &[String]) -> Vec<RoleBox> {
    roles
        .iter()
        .map(|r| RoleBox {
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

/// A word beside an account in the list.
#[derive(Clone, Debug)]
struct Badge {
    text: String,
    quiet: bool,
}

struct Row {
    id: i64,
    username: String,
    email: String,
    badges: Vec<Badge>,
    last_sign_in: String,
}

#[derive(Template)]
#[template(path = "admin/list.html")]
struct ListPage<'a> {
    base: &'a str,
    q: &'a str,
    role: &'a str,
    filters: Vec<(String, String)>,
    total: i64,
    rows: Vec<Row>,
    pagination: Pagination<'a>,
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

/// The search's rows: a term in the username or email, and a filter (`staff`,
/// `inactive`, or a role's name, staff counted when the role says so).
const FROM: &str = "FROM accounts
     WHERE ($1 = '' OR username ILIKE '%' || $1 || '%' OR email ILIKE '%' || $1 || '%')
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
    let total: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(format!("SELECT count(*) {FROM}")))
        .bind(&term)
        .bind(filter)
        .bind(staff_hold)
        .fetch_one(&admin.pool)
        .await?;
    let pager = Pager::clamped(
        query.page.as_deref(),
        usize::try_from(total).unwrap_or(0),
        PER_PAGE,
    );
    let offset = i64::try_from(pager.offset(PER_PAGE)).unwrap_or(i64::MAX);
    let accounts: Vec<(Account, String)> = sqlx::query_as::<
        _,
        (i64, String, String, bool, bool, i32, Vec<String>, String),
    >(sqlx::AssertSqlSafe(format!(
        "SELECT {COLUMNS}, coalesce(to_char(last_sign_in, 'YYYY-MM-DD'), '') {FROM}
             ORDER BY username LIMIT $4 OFFSET $5"
    )))
    .bind(&term)
    .bind(filter)
    .bind(staff_hold)
    .bind(i64::try_from(PER_PAGE).unwrap_or(50))
    .bind(offset)
    .fetch_all(&admin.pool)
    .await?
    .into_iter()
    .map(
        |(id, username, email, is_staff, is_active, session_epoch, roles, last)| {
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
            )
        },
    )
    .collect();
    let rows = accounts
        .into_iter()
        .map(|(a, last_sign_in)| Row {
            badges: badges(&admin.roles, &a),
            id: a.id,
            username: a.username,
            email: a.email,
            last_sign_in,
        })
        .collect();
    let mut filters = vec![("staff".to_owned(), "Staff".to_owned())];
    filters.extend(
        admin
            .roles
            .iter()
            .map(|r| (r.name.to_owned(), r.label.to_owned())),
    );
    filters.push(("inactive".to_owned(), "Deactivated".to_owned()));
    let page = ListPage {
        base: &admin.base,
        q: query.q.trim(),
        role: filter,
        filters,
        total,
        rows,
        pagination: Pagination::new(pager, &info),
    };
    Ok(admin.render(&parts, &me, "Accounts", &page))
}

fn badges(roles: &[Role], a: &Account) -> Vec<Badge> {
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

#[derive(Template)]
#[template(path = "admin/new.html")]
struct NewPage<'a> {
    base: &'a str,
    error: Option<String>,
    username: Field<'a>,
    email: Field<'a>,
    staff: bool,
    roles: Vec<RoleBox>,
}

fn new_page<'a>(admin: &'a Admin, form: &'a Posted, error: Option<String>) -> NewPage<'a> {
    NewPage {
        base: &admin.base,
        error,
        username: Field::text("username", "Username")
            .value(form.value("username"))
            .hint("One word, no “@”. It does not change later.")
            .required()
            .autofocus(),
        email: Field::email("email", "Email")
            .value(form.value("email"))
            .hint("Optional. Contact only: it never decides who someone is."),
        staff: form.ticked("staff"),
        roles: boxes(&admin.roles, &form.roles()),
    }
}

async fn new_form(State(admin): Shared, Staff(me): Staff, Req(parts): Req) -> Response {
    let empty = Posted(Vec::new());
    admin.render(&parts, &me, "New account", &new_page(&admin, &empty, None))
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
    let made = store::create(
        &mut *tx,
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
            let page = new_page(&admin, &form, Some(r.to_string()));
            let mut response = admin.render(&parts, &me, "New account", &page);
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

/// A linked identity, for the page.
struct IdentityRow {
    id: i64,
    provider: String,
    label: String,
}

#[derive(Template)]
#[template(path = "admin/detail.html")]
struct DetailPage<'a> {
    base: &'a str,
    account: &'a Account,
    myself: bool,
    notice: Option<Notice>,
    secret: Option<Secret>,
    email: Field<'a>,
    roles: Vec<RoleBox>,
    undeclared: Vec<String>,
    has_password: bool,
    joined: String,
    last_sign_in: String,
    identities: Vec<IdentityRow>,
    links_for: String,
    more: Option<(&'static str, String)>,
}

/// The account, active or not, with its dates as text.
async fn load(db: impl PgExecutor<'_>, id: i64) -> owt_web::Result<(Account, String, String)> {
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
        ),
    >(sqlx::AssertSqlSafe(format!(
        "SELECT {COLUMNS}, to_char(created_at, 'YYYY-MM-DD'),
                    coalesce(to_char(last_sign_in, 'YYYY-MM-DD HH24:MI'), 'never')
             FROM accounts WHERE id = $1"
    )))
    .bind(id)
    .fetch_optional(db)
    .await?
    .ok_or(owt_web::Error::NotFound)?;
    let (id, username, email, is_staff, is_active, session_epoch, roles, joined, last) = row;
    Ok((
        Account {
            id,
            username,
            email,
            is_staff,
            is_active,
            session_epoch,
            roles,
        },
        joined,
        last,
    ))
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
    let (account, joined, last_sign_in) = load(&admin.pool, id).await?;
    let has_password = store::has_password(&admin.pool, id).await?;
    let identities = identities::list(&admin.pool, id)
        .await?
        .into_iter()
        .map(|l| IdentityRow {
            id: l.id,
            label: l.label().to_owned(),
            provider: l.provider,
        })
        .collect();
    let links_for = admin
        .links
        .as_ref()
        .map_or_else(String::new, |(ttl, _)| human(ttl.min(&links::MAX_TTL)));
    let more = admin
        .more
        .as_ref()
        .map(|(label, href)| (*label, href(&account)));
    let error = notice
        .as_ref()
        .filter(|n| n.level == "error" && email_value.is_some())
        .map(|n| n.text.clone());
    let email_shown = email_value.unwrap_or(&account.email).to_owned();
    let body = DetailPage {
        base: &admin.base,
        account: &account,
        myself: account.id == me.id,
        notice,
        secret,
        email: Field::email("email", "Email")
            .value(&email_shown)
            .error(error.as_deref())
            .hint("Contact only: it never decides who someone is."),
        roles: boxes(&admin.roles, &account.roles),
        undeclared: undeclared(&admin.roles, &account.roles).cloned().collect(),
        has_password,
        joined,
        last_sign_in,
        identities,
        links_for,
        more,
    };
    let response = admin.render(parts, me, &account.username, &body);
    Ok(response)
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
/// report-only mode enforces no `frame-ancestors`): framed by a hostile sibling
/// subdomain, which `SameSite=Lax` and [`CrossOrigin`] treat as the site itself, a
/// click would act with staff's authority.
async fn never_framed(mut response: Response) -> Response {
    let h = response.headers_mut();
    h.insert(
        axum::http::header::X_FRAME_OPTIONS,
        axum::http::HeaderValue::from_static("DENY"),
    );
    h.append(
        axum::http::header::CONTENT_SECURITY_POLICY,
        axum::http::HeaderValue::from_static("frame-ancestors 'none'"),
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
    let (account, ..) = load(&mut *tx, id).await?;
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
    let (account, ..) = load(&mut *tx, id).await?;
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
    let (account, ..) = load(&mut *tx, id).await?;
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
