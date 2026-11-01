//! Site policies: the documents an app asks people to agree to (its terms, its
//! privacy notice), with versions, and who agreed to which.
//!
//! - A **version** is written as a draft in the staff pages, then published.
//!   Publishing numbers it (1, 2, 3... per document), fixes its text for good (a
//!   database trigger refuses any later change) and records the SHA-256 of that text.
//! - **The gate** ([`Policies::gate`]): until a signed-in account has accepted the
//!   current version of each document, every full page it loads goes to the page that
//!   asks first. A new version reaches people already signed in on their next page,
//!   and a new account (one made through a provider included) agrees before it does
//!   anything else.
//! - **Acceptances** are kept twice: each account's latest per document
//!   (`policy_acceptances`, which also keeps that version from being deleted), and an
//!   append-only record of every acceptance with the version's number, its text's
//!   hash, the time, the address and the browser (`policy_acceptance_events`).
//! - **Retention:** an older version is kept while it is somebody's latest acceptance.
//!   [`prune`] removes the rest; the current version is never removed.
//!
//! The app declares its documents ([`Document`]), writes their text, and supplies its
//! layout through a [`Chrome`] function, as for [the accounts admin](crate::admin).
//! The pages here carry only `owt-*` classes from `tailwind/owt.css`; an app with a
//! design of its own draws them with [`Views`], in its [`Words`].

use std::fmt;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use askama::Template;
use axum::Router;
use axum::extract::{Form, FromRequestParts, OriginalUri, Path, Query, Request, State};
use axum::http::request::Parts;
use axum::http::{Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use owt_web::cache::CachePolicy;
use owt_web::client_ip::Source;
use owt_web::csrf::CrossOrigin;
use owt_web::ui::Field;
use serde::Deserialize;
use sqlx::{PgExecutor, PgPool};

use crate::admin::{Body, Level, Notice};
use crate::{Maybe, Signed, Staff};

/// A document an app asks people to agree to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Document {
    /// Its key in the tables and its path: `terms` is read at `/terms`. A lower-case
    /// letter, then up to 31 lower-case letters, digits and `-`.
    pub slug: &'static str,
    /// Its name, as headings and links show it: `Terms of Service`.
    pub label: &'static str,
}

impl Document {
    /// A document at `/{slug}`, named `label`.
    #[must_use]
    pub const fn new(slug: &'static str, label: &'static str) -> Self {
        Self { slug, label }
    }

    /// The slug is one the table takes.
    fn slug_ok(slug: &str) -> bool {
        let mut chars = slug.chars();
        chars.next().is_some_and(|c| c.is_ascii_lowercase())
            && slug.len() <= 32
            && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    }
}

/// The terms of service, at `/terms`.
pub const TERMS: Document = Document::new("terms", "Terms of Service");
/// The privacy notice, at `/privacy`.
pub const PRIVACY: Document = Document::new("privacy", "Privacy Notice");

/// One version of a document, published or a draft. Times are UTC, as text.
#[derive(Clone, Debug, PartialEq, Eq, sqlx::FromRow)]
#[non_exhaustive]
pub struct Version {
    /// Its row.
    pub id: i64,
    /// The document's slug.
    pub kind: String,
    /// Its number, from 1 per document; `None` while a draft.
    pub version: Option<i32>,
    /// The heading the document shows.
    pub title: String,
    /// The text, as Markdown ([`render_markdown`]).
    pub body_markdown: String,
    /// What changed, shown to people asked to agree to it again.
    pub summary: String,
    /// The "last updated" date it shows: `YYYY-MM-DD`.
    pub effective_date: String,
    /// When it was published (`YYYY-MM-DD HH:MM`); `None` while a draft.
    pub published_at: Option<String>,
    /// The SHA-256 of `body_markdown` at publication, in hex.
    pub content_sha256: Option<String>,
}

impl Version {
    /// Its number, 0 for a draft.
    #[must_use]
    pub fn number(&self) -> i32 {
        self.version.unwrap_or_default()
    }
}

const COLUMNS: &str = "id, kind, version, title, body_markdown, summary,
     to_char(effective_date, 'YYYY-MM-DD') AS effective_date,
     to_char(published_at AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI') AS published_at,
     content_sha256";

/// Render a document's text. Raw HTML in it is shown as text, not markup: whoever
/// writes the text in the staff pages cannot put a script on a page.
#[must_use]
pub fn render_markdown(markdown: &str) -> String {
    use pulldown_cmark::{Event, Options, Parser, html};
    let parser = Parser::new_ext(
        markdown,
        Options::ENABLE_TABLES | Options::ENABLE_STRIKETHROUGH,
    )
    .map(|e| match e {
        Event::Html(s) | Event::InlineHtml(s) => Event::Text(s),
        other => other,
    });
    let mut out = String::new();
    html::push_html(&mut out, parser);
    out
}

/// The current (latest published) version of `kind`.
pub async fn current(db: impl PgExecutor<'_>, kind: &str) -> sqlx::Result<Option<Version>> {
    sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT {COLUMNS} FROM policy_versions
         WHERE kind = $1 AND published_at IS NOT NULL ORDER BY version DESC LIMIT 1"
    )))
    .bind(kind)
    .fetch_optional(db)
    .await
}

/// The current version of each of `kinds` that has one.
async fn current_of(db: impl PgExecutor<'_>, kinds: &[&str]) -> sqlx::Result<Vec<Version>> {
    sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT DISTINCT ON (kind) {COLUMNS} FROM policy_versions
         WHERE kind = ANY($1) AND published_at IS NOT NULL ORDER BY kind, version DESC"
    )))
    .bind(kinds)
    .fetch_all(db)
    .await
}

/// Published version `version` of `kind`, while it is on record.
pub async fn published(
    db: impl PgExecutor<'_>,
    kind: &str,
    version: i32,
) -> sqlx::Result<Option<Version>> {
    sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT {COLUMNS} FROM policy_versions
         WHERE kind = $1 AND version = $2 AND published_at IS NOT NULL"
    )))
    .bind(kind)
    .bind(version)
    .fetch_optional(db)
    .await
}

/// A version by its row, draft or published.
pub async fn by_id(db: impl PgExecutor<'_>, id: i64) -> sqlx::Result<Option<Version>> {
    sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT {COLUMNS} FROM policy_versions WHERE id = $1"
    )))
    .bind(id)
    .fetch_optional(db)
    .await
}

/// Every version of `kind`: drafts first, then published, newest first.
pub async fn all(db: impl PgExecutor<'_>, kind: &str) -> sqlx::Result<Vec<Version>> {
    sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT {COLUMNS} FROM policy_versions
         WHERE kind = $1 ORDER BY version DESC NULLS FIRST, id DESC"
    )))
    .bind(kind)
    .fetch_all(db)
    .await
}

/// An account's latest acceptance of one document.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Accepted {
    /// The document's slug.
    pub kind: String,
    /// The version's row.
    pub version_id: i64,
    /// The version's number.
    pub version: i32,
    /// The day it was accepted (UTC): `YYYY-MM-DD`.
    pub accepted_at: String,
}

/// What `account_id` last accepted of each document.
pub async fn accepted(db: impl PgExecutor<'_>, account_id: i64) -> sqlx::Result<Vec<Accepted>> {
    let rows: Vec<(String, i64, i32, String)> = sqlx::query_as(
        "SELECT a.kind, a.version_id, coalesce(v.version, 0),
                to_char(a.accepted_at AT TIME ZONE 'UTC', 'YYYY-MM-DD')
         FROM policy_acceptances a JOIN policy_versions v ON v.id = a.version_id
         WHERE a.account_id = $1",
    )
    .bind(account_id)
    .fetch_all(db)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(kind, version_id, version, accepted_at)| Accepted {
            kind,
            version_id,
            version,
            accepted_at,
        })
        .collect())
}

/// Those of `current` that `accepted` does not hold: what the account is asked to
/// agree to.
#[must_use]
pub fn outstanding<'a>(current: &'a [Version], accepted: &[Accepted]) -> Vec<&'a Version> {
    current
        .iter()
        .filter(|v| !accepted.iter().any(|a| a.version_id == v.id))
        .collect()
}

/// Record that `account_id` accepted the published versions `version_ids` (the
/// latest of them per document; drafts and unknown rows are ignored), from `ip` with
/// `user_agent` (cut to 512 characters). Returns how many it recorded.
///
/// An app that seeds accounts (a load test's) calls it for each, with a `user_agent`
/// that says so.
pub async fn accept(
    db: impl PgExecutor<'_>,
    account_id: i64,
    version_ids: &[i64],
    ip: Option<&str>,
    user_agent: Option<&str>,
) -> sqlx::Result<u64> {
    let user_agent = user_agent.map(|u| u.chars().take(512).collect::<String>());
    let done = sqlx::query(
        "WITH v AS (
             SELECT DISTINCT ON (kind) id, kind, version, content_sha256 FROM policy_versions
             WHERE id = ANY($2) AND published_at IS NOT NULL ORDER BY kind, version DESC
         ), latest AS (
             INSERT INTO policy_acceptances (account_id, kind, version_id)
             SELECT $1, kind, id FROM v
             ON CONFLICT (account_id, kind)
                 DO UPDATE SET version_id = EXCLUDED.version_id, accepted_at = now()
         )
         INSERT INTO policy_acceptance_events
             (account_id, kind, version, content_sha256, ip, user_agent)
         SELECT $1, kind, version, content_sha256, $3, $4 FROM v",
    )
    .bind(account_id)
    .bind(version_ids)
    .bind(ip)
    .bind(user_agent)
    .execute(db)
    .await?;
    Ok(done.rows_affected())
}

/// Record that `account_id` accepted the current version of every document (test
/// fixtures: the policy gate then lets the account through). Returns how many it
/// recorded. [`accept`] is what a deployment calls.
///
/// # Errors
///
/// The database.
#[cfg(feature = "test-util")]
pub async fn agree_to_current(db: &PgPool, account_id: i64) -> sqlx::Result<u64> {
    let ids: Vec<i64> = sqlx::query_scalar(
        "SELECT DISTINCT ON (kind) id FROM policy_versions
         WHERE published_at IS NOT NULL ORDER BY kind, version DESC",
    )
    .fetch_all(db)
    .await?;
    accept(db, account_id, &ids, None, Some("owt-test")).await
}

/// A draft's fields, as typed.
#[derive(Clone, Copy, Debug)]
pub struct Draft<'a> {
    /// The heading.
    pub title: &'a str,
    /// The "last updated" date: `YYYY-MM-DD`.
    pub effective_date: &'a str,
    /// What changed since the current version.
    pub summary: &'a str,
    /// The text, as Markdown.
    pub body_markdown: &'a str,
}

impl Draft<'_> {
    /// What is wrong with it, as sentences for the form; empty when it can be saved.
    #[must_use]
    pub fn problems(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if self.title.trim().is_empty() {
            out.push("Enter a title.");
        }
        if !is_date(self.effective_date.trim()) {
            out.push("Enter the date as YYYY-MM-DD.");
        }
        out
    }

    /// The text as stored: browsers send a textarea's lines ending CRLF, and the
    /// published hash is of LF text.
    fn body(&self) -> String {
        self.body_markdown.replace("\r\n", "\n")
    }
}

/// `YYYY-MM-DD`, a day that exists.
fn is_date(text: &str) -> bool {
    let bytes = text.as_bytes();
    let number = |at: std::ops::Range<usize>| {
        bytes
            .get(at.clone())
            .filter(|digits| digits.iter().all(u8::is_ascii_digit))
            .and_then(|_| text[at].parse::<u32>().ok())
    };
    if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
        return false;
    }
    let (Some(year), Some(month), Some(day)) = (number(0..4), number(5..7), number(8..10)) else {
        return false;
    };
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    year >= 1 && (1..=days).contains(&day)
}

/// A new draft of `kind` by `author`. Check [`Draft::problems`] first: the database
/// refuses a blank title or a bad date as an error.
///
/// # Panics
///
/// When `kind` is not a slug [`Document`] allows.
pub async fn draft(
    db: impl PgExecutor<'_>,
    kind: &str,
    draft: Draft<'_>,
    author: Option<i64>,
) -> sqlx::Result<Version> {
    assert!(Document::slug_ok(kind), "{kind:?} is not a document slug");
    sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "INSERT INTO policy_versions (kind, title, effective_date, summary, body_markdown, created_by)
         VALUES ($1, $2, $3::date, $4, $5, $6) RETURNING {COLUMNS}"
    )))
    .bind(kind)
    .bind(draft.title.trim())
    .bind(draft.effective_date.trim())
    .bind(draft.summary.trim())
    .bind(draft.body())
    .bind(author)
    .fetch_one(db)
    .await
}

/// Change draft `id`; `None` when it is not a draft (published, or gone).
pub async fn save(
    db: impl PgExecutor<'_>,
    id: i64,
    draft: Draft<'_>,
) -> sqlx::Result<Option<Version>> {
    sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "UPDATE policy_versions
         SET title = $2, effective_date = $3::date, summary = $4, body_markdown = $5
         WHERE id = $1 AND published_at IS NULL RETURNING {COLUMNS}"
    )))
    .bind(id)
    .bind(draft.title.trim())
    .bind(draft.effective_date.trim())
    .bind(draft.summary.trim())
    .bind(draft.body())
    .fetch_optional(db)
    .await
}

/// Publish draft `id`: number it after its document's latest version and fix its
/// text, hashed as it is now. `None` when it is not a draft or has no text.
///
/// The pages of this replica's [`Policies`] see it at once; other replicas within
/// [`Policies::refresh`].
pub async fn publish(db: impl PgExecutor<'_>, id: i64) -> sqlx::Result<Option<Version>> {
    sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "UPDATE policy_versions p
         SET version = (SELECT coalesce(max(version), 0) + 1 FROM policy_versions o
                        WHERE o.kind = p.kind),
             published_at = now(),
             content_sha256 = encode(sha256(convert_to(body_markdown, 'UTF8')), 'hex')
         WHERE id = $1 AND published_at IS NULL AND btrim(body_markdown) <> ''
         RETURNING {COLUMNS}"
    )))
    .bind(id)
    .fetch_optional(db)
    .await
}

/// Delete draft `id`; false when it is not a draft.
pub async fn discard(db: impl PgExecutor<'_>, id: i64) -> sqlx::Result<bool> {
    let done = sqlx::query("DELETE FROM policy_versions WHERE id = $1 AND published_at IS NULL")
        .bind(id)
        .execute(db)
        .await?;
    Ok(done.rows_affected() > 0)
}

/// Delete the published versions nobody needs: not a document's current one, and not
/// one that is anybody's latest acceptance. Drafts stay. Returns the (document,
/// version) of each removed. Run it on a schedule, or from the staff pages.
pub async fn prune(db: impl PgExecutor<'_>) -> sqlx::Result<Vec<(String, i32)>> {
    sqlx::query_as(
        "DELETE FROM policy_versions v
         WHERE v.published_at IS NOT NULL
           AND v.version < (SELECT max(version) FROM policy_versions c
                            WHERE c.kind = v.kind AND c.published_at IS NOT NULL)
           AND NOT EXISTS (SELECT 1 FROM policy_acceptances a WHERE a.version_id = v.id)
         RETURNING kind, version",
    )
    .fetch_all(db)
    .await
}

/// How many accounts' latest acceptance is each version, by row.
async fn holders(db: impl PgExecutor<'_>) -> sqlx::Result<Vec<(i64, i64)>> {
    sqlx::query_as("SELECT version_id, count(*) FROM policy_acceptances GROUP BY version_id")
        .fetch_all(db)
        .await
}

/// What the app's [`Chrome`] wraps: one of these pages.
#[non_exhaustive]
pub struct Page<'a> {
    /// The request, for whatever the app's layout reads from it (its extensions hold
    /// the session, the CSP nonce, the signed-in account). Its `uri` is the one the
    /// client sent (`/staff/policies/4`), not the path as a nested router sees it, so
    /// a layout's "you are here" and sign-in links name the page.
    pub request: &'a Parts,
    /// The page's title, as plain text: a document's title, which staff wrote. Escape
    /// it (an Askama layout does); never format it into HTML.
    pub title: &'a str,
    /// The page's content.
    pub body: Body,
}

/// The app's layout: wraps a page's body in the app's shell and answers it,
/// without awaiting anything. A closure `|page: Page<'_>| -> owt_web::Result<Response>`
/// is one. A layout that awaits (a nav count, the viewer's name from the database)
/// implements [`AsyncChrome`] instead; every `Chrome` is an `AsyncChrome` too.
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

/// The app's layout, awaited: for a shell that reads something per page (an inbox
/// count, the viewer's display name, a feature flag) before it wraps the body. The
/// future borrows the page, so it is boxed:
///
/// ```
/// use std::pin::Pin;
/// use axum::response::{Html, IntoResponse, Response};
/// use owt_accounts::policies::{AsyncChrome, Page};
///
/// struct Shell { pool: sqlx::PgPool }
///
/// impl AsyncChrome for Shell {
///     fn page<'a>(&'a self, page: Page<'a>) -> Pin<Box<dyn Future<Output = owt_web::Result<Response>> + Send + 'a>> {
///         Box::pin(async move {
///             let open: i64 = sqlx::query_scalar("SELECT count(*) FROM policy_versions WHERE published_at IS NULL")
///                 .fetch_one(&self.pool)
///                 .await?;
///             // An Askama layout escapes the title and embeds the body as it is.
///             Ok(Html(format!("<title>{}</title><nav>{open}</nav>{}", page.title, page.body)).into_response())
///         })
///     }
/// }
/// ```
///
/// Every [`Chrome`] is an `AsyncChrome` whose future is ready at once, so the sync
/// closures still go wherever one is asked for.
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

/// The pages' markup, for an app with a design of its own: each method answers a
/// page's body from its view model, and the app's [`Chrome`] wraps it as for the
/// [`Tailwind`] pages. Every method defaults to the `Tailwind` page, so an app
/// overrides only the pages it draws:
///
/// ```
/// use axum::http::request::Parts;
/// use owt_accounts::admin::Body;
/// use owt_accounts::policies::{AgreeView, Views};
///
/// #[derive(askama::Template)]
/// #[template(source = r#"<form method="post" action="{{ v.action }}">
/// <input type="hidden" name="next" value="{{ v.next }}">
/// {% for a in v.asked %}<h2><a href="{{ a.href }}">{{ a.version.title }}</a></h2>
/// <input type="hidden" name="version" value="{{ a.version.id }}">{% endfor %}
/// <label><input type="checkbox" name="agree" value="yes" required> {{ v.agreement }}</label>
/// <button>{{ v.words.agree }}</button></form>"#, ext = "html")]
/// struct Agree<'a, 'b> { v: &'a AgreeView<'b> }
///
/// struct Mine;
///
/// impl Views for Mine {
///     fn agree(&self, _: &Parts, view: &AgreeView<'_>) -> owt_web::Result<Body> {
///         Body::render(&Agree { v: view })
///     }
/// }
/// ```
///
/// [`Body::render`] says which templates are safe to answer with: one that escapes
/// HTML. A view model's text (a document's title and summary, which staff wrote) is
/// text, never markup; its [`Body`] fields are the rendered Markdown, safe as they are.
pub trait Views: Send + Sync + 'static {
    /// A document: its current version or an older one.
    ///
    /// # Errors
    ///
    /// When the app's template does not render.
    fn document(&self, request: &Parts, view: &DocumentView<'_>) -> owt_web::Result<Body> {
        let _ = request;
        Body::render(&DocumentHtml { v: view })
    }

    /// The page that asks. Its form posts to [`AgreeView::action`]: `agree=yes`,
    /// `next`, and one `version` per [`AgreeView::asked`] holding its
    /// [`Version::id`]. A form that leaves one out is asked again.
    ///
    /// # Errors
    ///
    /// When the app's template does not render.
    fn agree(&self, request: &Parts, view: &AgreeView<'_>) -> owt_web::Result<Body> {
        let _ = request;
        Body::render(&AgreeHtml { v: view })
    }

    /// The staff list of documents and their versions.
    ///
    /// # Errors
    ///
    /// When the app's template does not render.
    fn admin_list(&self, request: &Parts, view: &AdminListView<'_>) -> owt_web::Result<Body> {
        let _ = request;
        Body::render(&AdminListHtml { v: view })
    }

    /// A version's staff page: the draft's form (`title`, `effective_date`,
    /// `summary`, `body_markdown`, posted to [`AdminFormView::save`]), or a published
    /// version's record.
    ///
    /// # Errors
    ///
    /// When the app's template does not render.
    fn admin_form(&self, request: &Parts, view: &AdminFormView<'_>) -> owt_web::Result<Body> {
        let _ = request;
        Body::render(&AdminFormHtml {
            v: view,
            title: Field::text("title", "Title")
                .value(&view.version.title)
                .required(),
            effective_date: Field::new("date", "effective_date", "Last updated")
                .value(&view.version.effective_date)
                .hint("The date the document shows.")
                .required(),
        })
    }
}

/// The policy pages in `owt-*` classes from `tailwind/owt.css`: what [`Policies`]
/// draws unless given other [`Views`].
#[derive(Clone, Copy, Debug, Default)]
pub struct Tailwind;

impl Views for Tailwind {}

/// The words of the pages everyone reads (a document and the page that asks), in
/// the app's language: English ([`Words::ENGLISH`]) unless the app passes its own to
/// [`Policies::words`], built with struct update syntax:
/// `Words { agree: "Accepter et continuer", ..Words::ENGLISH }`. A sentence's
/// `{n}`, `{date}` and `{version}` are filled in where they stand, so a language
/// puts them in its own order; a `{version}` the page links stays a link. The staff
/// pages are in English; an app draws them in its own words with [`Views`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Words {
    /// The page that asks, to an account that has agreed to nothing: `Before you continue`.
    pub first_time: &'static str,
    /// The page that asks, again: `We have updated our policies`.
    pub updated: &'static str,
    /// Under it, for one document: `Please read this and agree to continue.`
    pub read_one: &'static str,
    /// Under it, for several: `Please read these and agree to continue.`
    pub read_many: &'static str,
    /// A version, as a heading or link names it: `Version {n}`.
    pub version: &'static str,
    /// A version, inside a sentence: `version {n}`.
    pub version_in_sentence: &'static str,
    /// A version and its date, on the page that asks and in a document's list of
    /// versions, where `{version}` is the link: `{version}, last updated {date}`.
    pub version_dated: &'static str,
    /// Under a document's title: `{version} · Last updated {date}`.
    pub header: &'static str,
    /// On an older version: `Not the current version.`
    pub not_current: &'static str,
    /// Its link to the current one: `Read the current version`.
    pub read_current: &'static str,
    /// To a signed-in reader who agreed to it: `You agreed to {version} on {date}.`
    pub you_agreed: &'static str,
    /// Their link to the version they agreed to, when this is another: `Read the version you agreed to`.
    pub read_yours: &'static str,
    /// The heading over a document's versions: `Versions on record`.
    pub versions_on_record: &'static str,
    /// On the page that asks, where `{version}` links the version agreed to:
    /// `You last agreed to {version}.`
    pub last_agreed: &'static str,
    /// Before a version's summary: `What changed:`
    pub what_changed: &'static str,
    /// The button that agrees: `Agree and continue`.
    pub agree: &'static str,
    /// The button that signs out instead ([`Policies::sign_out`]): `Sign out instead`.
    pub sign_out: &'static str,
    /// The page that asks, as its title: `Review and agree`.
    pub agree_title: &'static str,
    /// The box was not ticked: `Tick the box to agree, or sign out.`
    pub not_ticked: &'static str,
    /// A version was published while the account read: `A document changed while you
    /// were reading. Please review it and agree again.`
    pub changed: &'static str,
}

impl Words {
    /// The English the pages write unless given others.
    pub const ENGLISH: Self = Self {
        first_time: "Before you continue",
        updated: "We have updated our policies",
        read_one: "Please read this and agree to continue.",
        read_many: "Please read these and agree to continue.",
        version: "Version {n}",
        version_in_sentence: "version {n}",
        version_dated: "{version}, last updated {date}",
        header: "{version} · Last updated {date}",
        not_current: "Not the current version.",
        read_current: "Read the current version",
        you_agreed: "You agreed to {version} on {date}.",
        read_yours: "Read the version you agreed to",
        versions_on_record: "Versions on record",
        last_agreed: "You last agreed to {version}.",
        what_changed: "What changed:",
        agree: "Agree and continue",
        sign_out: "Sign out instead",
        agree_title: "Review and agree",
        not_ticked: "Tick the box to agree, or sign out.",
        changed: "A document changed while you were reading. Please review it and agree again.",
    };
}

impl Default for Words {
    fn default() -> Self {
        Self::ENGLISH
    }
}

/// `pattern` with `{n}` filled in.
fn numbered(pattern: &str, n: impl fmt::Display) -> String {
    pattern.replace("{n}", &n.to_string())
}

/// `pattern` with `{version}` and `{date}` filled in.
fn sentence(pattern: &str, version: impl AsRef<str>, date: impl AsRef<str>) -> String {
    pattern
        .replace("{version}", version.as_ref())
        .replace("{date}", date.as_ref())
}

/// `pattern` with `{date}` filled in, split around `{version}`, which the page draws
/// as a link between the two halves.
fn around(pattern: &str, date: impl AsRef<str>) -> (String, String) {
    let filled = pattern.replace("{date}", date.as_ref());
    match filled.split_once("{version}") {
        Some((before, after)) => (before.to_owned(), after.to_owned()),
        None => (filled, String::new()),
    }
}

/// A published version, as a page links it.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct VersionLink {
    /// Its number.
    pub number: i32,
    /// Its "last updated" date, or for an account's acceptance the day it agreed,
    /// written as the app writes dates ([`Policies::dates`]).
    pub date: String,
    /// Its page.
    pub href: String,
}

/// A document's page.
#[derive(Debug)]
#[non_exhaustive]
pub struct DocumentView<'a> {
    /// The version shown.
    pub version: &'a Version,
    /// Its text, rendered: HTML with no markup of its author's.
    pub body: Body,
    /// Its "last updated" date, as the app writes dates.
    pub date: String,
    /// It is the current version.
    pub current: bool,
    /// The current version's page.
    pub current_href: String,
    /// The published versions, newest first.
    pub versions: Vec<VersionLink>,
    /// The version the signed-in reader last agreed to, dated the day they did.
    pub mine: Option<VersionLink>,
    /// The words the page writes ([`Policies::words`]).
    pub words: Words,
}

/// A document the page that asks shows.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct Asked {
    /// Its current version: the one agreed to.
    pub version: Version,
    /// The document's page.
    pub href: String,
    /// Its "last updated" date, as the app writes dates.
    pub date: String,
    /// The version of it the account last agreed to, dated the day it did.
    pub previous: Option<VersionLink>,
}

/// The page that asks.
#[derive(Debug)]
#[non_exhaustive]
pub struct AgreeView<'a> {
    /// Where its form posts.
    pub action: &'a str,
    /// Where the account goes afterwards: the form's `next`.
    pub next: &'a str,
    /// What it is asked to agree to, in the declared order.
    pub asked: Vec<Asked>,
    /// It has agreed to none of them before.
    pub first_time: bool,
    /// The words beside the checkbox ([`Policies::agreement`]).
    pub agreement: &'a str,
    /// Why the last post was refused.
    pub error: Option<&'a str>,
    /// The app's sign-out route, for a "sign out instead" form that posts to it
    /// ([`Policies::sign_out`]).
    pub sign_out: Option<&'a str>,
    /// The words the page writes ([`Policies::words`]).
    pub words: Words,
}

/// The staff list.
#[derive(Debug)]
#[non_exhaustive]
pub struct AdminListView<'a> {
    /// The staff pages' base ([`Policies::admin`]).
    pub base: &'a str,
    /// Where a form posts to remove the versions nobody holds.
    pub prune: String,
    /// The outcome of what staff last did.
    pub notice: Option<Notice>,
    /// The declared documents, in order.
    pub documents: Vec<AdminDocument>,
}

/// A document in the staff list.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct AdminDocument {
    /// The document.
    pub document: Document,
    /// Its public page.
    pub href: String,
    /// Where a form posts to start a draft of it.
    pub new_draft: String,
    /// Its versions, drafts first, then the newest published.
    pub versions: Vec<AdminVersion>,
}

/// A version in the staff list.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct AdminVersion {
    /// The version.
    pub version: Version,
    /// Its staff page.
    pub href: String,
    /// It is the current version.
    pub current: bool,
    /// Accounts whose latest acceptance it is.
    pub holders: i64,
}

/// A version's staff page.
#[derive(Debug)]
#[non_exhaustive]
pub struct AdminFormView<'a> {
    /// The staff pages' base, the list's address.
    pub base: &'a str,
    /// The document's label.
    pub label: &'a str,
    /// The version: a draft as saved, or as posted when refused.
    pub version: &'a Version,
    /// The outcome of what staff last did.
    pub notice: Option<Notice>,
    /// Why the draft posted was refused.
    pub errors: Vec<&'static str>,
    /// Accounts whose latest acceptance it is.
    pub holders: i64,
    /// Its text, rendered.
    pub preview: Body,
    /// Where the draft's form posts.
    pub save: String,
    /// Where a form posts to publish the saved draft.
    pub publish: String,
    /// Where a form posts to delete the draft.
    pub delete: String,
    /// A published version's public page.
    pub public_href: Option<String>,
}

#[derive(Template)]
#[template(path = "policies/document.html")]
struct DocumentHtml<'a, 'b> {
    v: &'a DocumentView<'b>,
}

#[derive(Template)]
#[template(path = "policies/agree.html")]
struct AgreeHtml<'a, 'b> {
    v: &'a AgreeView<'b>,
}

#[derive(Template)]
#[template(path = "policies/admin_list.html")]
struct AdminListHtml<'a, 'b> {
    v: &'a AdminListView<'b>,
}

#[derive(Template)]
#[template(path = "policies/admin_form.html")]
struct AdminFormHtml<'a, 'b> {
    v: &'a AdminFormView<'b>,
    title: Field<'a>,
    effective_date: Field<'a>,
}

/// Filled-in view models for an app's tests of its own [`Views`] templates (feature
/// `test-util`): every field holds a representative value, and a title and a
/// summary hold a `<`, so a template that stops escaping fails. The values are
/// fixed; the URLs are what policies with documents at the root and staff pages at
/// `/staff/policies` hand over.
#[cfg(feature = "test-util")]
mod examples {
    use std::sync::LazyLock;

    use super::{
        AdminDocument, AdminFormView, AdminListView, AdminVersion, AgreeView, Asked, Body,
        DocumentView, Level, Notice, TERMS, Version, VersionLink, Words,
    };

    static CURRENT: LazyLock<Version> = LazyLock::new(|| Version {
        id: 7,
        kind: "terms".into(),
        version: Some(2),
        title: "Terms <of> Service".into(),
        body_markdown: "## Use\n\nBe kind.".into(),
        summary: "Clearer <wording>.".into(),
        effective_date: "2026-10-01".into(),
        published_at: Some("2026-10-01 09:30".into()),
        content_sha256: Some("ab".repeat(32)),
    });

    static DRAFT: LazyLock<Version> = LazyLock::new(|| Version {
        id: 9,
        version: None,
        published_at: None,
        content_sha256: None,
        ..CURRENT.clone()
    });

    fn link(number: i32, date: &str) -> VersionLink {
        VersionLink {
            number,
            date: date.into(),
            href: format!("/terms/v/{number}"),
        }
    }

    impl DocumentView<'static> {
        /// An older version's page, to a reader who agreed to the current one.
        #[must_use]
        pub fn example() -> Self {
            static OLD: LazyLock<Version> = LazyLock::new(|| Version {
                id: 5,
                version: Some(1),
                effective_date: "2026-01-01".into(),
                ..CURRENT.clone()
            });
            Self {
                version: &OLD,
                body: Body("<h2>Use</h2>\n<p>Be kind.</p>\n".into()),
                date: "2026-01-01".into(),
                current: false,
                current_href: "/terms".into(),
                versions: vec![link(2, "2026-10-01"), link(1, "2026-01-01")],
                mine: Some(link(2, "2026-10-02")),
                words: Words::ENGLISH,
            }
        }
    }

    impl AgreeView<'static> {
        /// Asked again for the terms, after a refused post, with a sign-out route.
        #[must_use]
        pub fn example() -> Self {
            Self {
                action: "/agree",
                next: "/games?page=2",
                asked: vec![Asked {
                    version: CURRENT.clone(),
                    href: "/terms".into(),
                    date: "2026-10-01".into(),
                    previous: Some(link(1, "2026-01-02")),
                }],
                first_time: false,
                agreement: "I have read and agree to the documents above.",
                error: Some(Words::ENGLISH.not_ticked),
                sign_out: Some("/sign-out"),
                words: Words::ENGLISH,
            }
        }
    }

    impl AdminListView<'static> {
        /// The terms with a draft, a current version held by two accounts and an
        /// older one, after a publish.
        #[must_use]
        pub fn example() -> Self {
            let base = "/staff/policies";
            let row = |version: &Version, current: bool, holders: i64| AdminVersion {
                href: format!("{base}/{}", version.id),
                version: version.clone(),
                current,
                holders,
            };
            Self {
                base,
                prune: format!("{base}/prune"),
                notice: Some(Notice {
                    level: Level::Success,
                    text: "Draft saved.".into(),
                }),
                documents: vec![AdminDocument {
                    document: TERMS,
                    href: "/terms".into(),
                    new_draft: format!("{base}/new/terms"),
                    versions: vec![row(&DRAFT, false, 0), row(&CURRENT, true, 2)],
                }],
            }
        }
    }

    impl AdminFormView<'static> {
        /// A draft's form, refused for an effective date.
        #[must_use]
        pub fn example() -> Self {
            Self {
                base: "/staff/policies",
                label: "Terms of Service",
                version: &DRAFT,
                notice: None,
                errors: vec!["Give the date as YYYY-MM-DD."],
                holders: 0,
                preview: Body("<h2>Use</h2>\n<p>Be kind.</p>\n".into()),
                save: "/staff/policies/9".into(),
                publish: "/staff/policies/9/publish".into(),
                delete: "/staff/policies/9/delete".into(),
                public_href: None,
            }
        }

        /// A published version's record.
        #[must_use]
        pub fn published() -> Self {
            Self {
                version: &CURRENT,
                errors: Vec::new(),
                holders: 2,
                public_href: Some("/terms/v/2".into()),
                ..Self::example()
            }
        }
    }
}

/// This replica's copy of the current versions, read on every page load.
type Cached = Mutex<Option<(Instant, Arc<Vec<Version>>)>>;

#[derive(Clone)]
struct Inner {
    pool: PgPool,
    documents: Vec<Document>,
    chrome: Arc<dyn AsyncChrome>,
    views: Arc<dyn Views>,
    words: Words,
    dates: Arc<dyn Fn(&str) -> String + Send + Sync>,
    prefix: String,
    sign_out: Option<String>,
    agree: String,
    admin: Option<String>,
    agreement: String,
    exempt: Vec<String>,
    client_ip: Source,
    refresh: Duration,
    cached: Arc<Cached>,
}

/// The documents, the pages and the gate, configured. Build it, merge
/// [`Policies::routes`] into the app, and layer [`Policies::gate`] inside the
/// accounts layer.
#[derive(Clone)]
pub struct Policies(Arc<Inner>);

impl fmt::Debug for Policies {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Policies")
            .field("documents", &self.0.documents)
            .field("agree", &self.0.agree)
            .field("admin", &self.0.admin)
            .finish_non_exhaustive()
    }
}

/// The checkbox's words, unless the app gives its own.
const AGREEMENT: &str = "I have read and agree to the documents above.";

impl Policies {
    /// `documents` over `pool`, drawn inside `chrome` (a [`Chrome`] closure, or an
    /// [`AsyncChrome`] that awaits). Each is read at `/{slug}`, and the page that asks
    /// is at `/agree`.
    ///
    /// # Panics
    ///
    /// When there is no document, a slug is not one [`Document`] allows, or two
    /// documents share one.
    pub fn new(pool: PgPool, chrome: impl AsyncChrome, documents: &[Document]) -> Self {
        assert!(!documents.is_empty(), "declare at least one document");
        for (i, d) in documents.iter().enumerate() {
            assert!(
                Document::slug_ok(d.slug),
                "{:?} is not a document slug: a lower-case letter, then up to 31 of a-z, 0-9 and -",
                d.slug
            );
            assert!(
                documents[..i].iter().all(|o| o.slug != d.slug),
                "two documents are at /{}",
                d.slug
            );
        }
        Self(Arc::new(Inner {
            pool,
            documents: documents.to_vec(),
            chrome: Arc::new(chrome),
            views: Arc::new(Tailwind),
            words: Words::ENGLISH,
            dates: Arc::new(str::to_owned),
            prefix: String::new(),
            sign_out: None,
            agree: "/agree".into(),
            admin: None,
            agreement: AGREEMENT.into(),
            exempt: Vec::new(),
            client_ip: Source::Peer,
            refresh: Duration::from_secs(30),
            cached: Arc::default(),
        }))
    }

    fn with(mut self, f: impl FnOnce(&mut Inner)) -> Self {
        f(Arc::make_mut(&mut self.0));
        self
    }

    /// Where the page that asks is, instead of `/agree`.
    ///
    /// # Panics
    ///
    /// When `path` is not a path below the root.
    #[must_use]
    pub fn agree_at(self, path: impl Into<String>) -> Self {
        let path = below_root(&path.into());
        self.with(|i| i.agree = path)
    }

    /// The staff pages, at `base` (`/staff/policies`): write a draft, preview it,
    /// publish it, remove versions nobody holds. Without it, versions are published
    /// with [`draft`] and [`publish`].
    ///
    /// # Panics
    ///
    /// When `base` is not a path below the root.
    #[must_use]
    pub fn admin(self, base: impl Into<String>) -> Self {
        let base = below_root(&base.into());
        self.with(|i| i.admin = Some(base))
    }

    /// The words beside the checkbox that agrees, instead of "I have read and agree
    /// to the documents above.": an age the app requires, say.
    #[must_use]
    pub fn agreement(self, text: impl Into<String>) -> Self {
        let text = text.into();
        self.with(|i| i.agreement = text)
    }

    /// Paths under any of `prefixes` are never sent to the page that asks (`/static/`,
    /// a live socket's). A prefix matches at a path-segment boundary: `/api` exempts
    /// `/api` and `/api/...`, not `/apiary`; one ending in `/` exempts what starts
    /// with it. The documents, the page that asks and the staff pages are already
    /// exempt; so is anything but a full page load.
    #[must_use]
    pub fn exempt(self, prefixes: &[&str]) -> Self {
        self.with(|i| i.exempt.extend(prefixes.iter().map(|p| (*p).to_owned())))
    }

    /// Where an acceptance's recorded address comes from, as the app is deployed;
    /// the socket's peer unless set.
    #[must_use]
    pub fn client_ip(self, source: Source) -> Self {
        self.with(|i| i.client_ip = source)
    }

    /// The pages' markup, instead of the [`Tailwind`] pages: an app with a design of
    /// its own draws them from their view models.
    #[must_use]
    pub fn views(self, views: impl Views) -> Self {
        let views: Arc<dyn Views> = Arc::new(views);
        self.with(|i| i.views = views)
    }

    /// The words of the pages everyone reads, instead of English.
    #[must_use]
    pub fn words(self, words: Words) -> Self {
        self.with(|i| i.words = words)
    }

    /// How the pages everyone reads write a date, which they are given as
    /// `YYYY-MM-DD`: `|d| format_date(d, "fr")`. They write it as given unless set.
    #[must_use]
    pub fn dates(self, format: impl Fn(&str) -> String + Send + Sync + 'static) -> Self {
        let format: Arc<dyn Fn(&str) -> String + Send + Sync> = Arc::new(format);
        self.with(|i| i.dates = format)
    }

    /// Each document at `{prefix}/{slug}` (`/legal/terms`) instead of `/{slug}`, and
    /// its older versions below it.
    ///
    /// # Panics
    ///
    /// When `prefix` is not a path below the root.
    #[must_use]
    pub fn documents_at(self, prefix: impl Into<String>) -> Self {
        let prefix = below_root(&prefix.into());
        self.with(|i| i.prefix = prefix)
    }

    /// The app's sign-out route: the page that asks offers a button posting to it, for
    /// someone who would rather not agree. The route answers the `POST` as the app's
    /// own sign-out does.
    ///
    /// # Panics
    ///
    /// When `path` is not a path below the root.
    #[must_use]
    pub fn sign_out(self, path: impl Into<String>) -> Self {
        let path = below_root(&path.into());
        self.with(|i| i.sign_out = Some(path))
    }

    /// How long this replica keeps the current versions before reading them again,
    /// instead of 30 seconds: how soon a version published on another replica is
    /// asked for here.
    #[must_use]
    pub fn refresh(self, every: Duration) -> Self {
        self.with(|i| i.refresh = every)
    }

    /// The routes: each document at `/{slug}` and its older versions at
    /// `/{slug}/v/{n}` ([`documents_at`](Self::documents_at) puts a prefix before
    /// them), the page that asks, and the staff pages if configured. Merge
    /// them into the app's router, inside the accounts layer
    /// ([`crate::Accounts::load`]). They refuse a cross-origin `POST` on their own.
    pub fn routes<S: Clone + Send + Sync + 'static>(&self) -> Router<S> {
        let mut pages = Router::new();
        for doc in &self.0.documents {
            let slug = doc.slug;
            pages = pages
                .route(
                    &format!("{}/{slug}", self.0.prefix),
                    get(move |p: Shared, me: Maybe, r: Req| show(p, me, r, slug, None)),
                )
                .route(
                    &format!("{}/{slug}/v/{{n}}", self.0.prefix),
                    get(move |p: Shared, me: Maybe, r: Req, Path(n): Path<i32>| {
                        show(p, me, r, slug, Some(n))
                    }),
                );
        }
        pages = pages.route(&self.0.agree, get(agree_form).post(agree));
        if let Some(base) = &self.0.admin {
            let admin = Router::new()
                .route("/", get(list))
                .route("/prune", post(prune_old))
                .route("/new/{kind}", post(new_draft))
                .route("/{id}", get(edit).post(save_draft))
                .route("/{id}/publish", post(publish_draft))
                .route("/{id}/delete", post(delete_draft));
            pages = pages.nest(base, admin);
        }
        Router::new().merge(
            pages
                .with_state(self.clone())
                .layer(axum::middleware::from_fn_with_state(
                    CrossOrigin::new(),
                    CrossOrigin::layer,
                ))
                .layer(axum::middleware::map_response(
                    crate::admin::never_cached_or_framed,
                )),
        )
    }

    /// The middleware that sends a signed-in account which has not accepted the
    /// current version of every document to the page that asks, with `?next=` naming
    /// where it was going. Only a document load is sent (a `GET` for a
    /// `Sec-Fetch-Dest: document` or, without that header, one asking for
    /// `text/html`; an htmx request only when it is a boosted navigation), so an
    /// image, a stylesheet, a script, a fetch, a socket, a stream or a fragment is
    /// never interrupted. When the database cannot say, the request goes through.
    ///
    /// Install it inside the accounts layer, which it reads the account from:
    /// `.layer(from_fn_with_state(policies.clone(), Policies::gate))` before
    /// `.layer(from_fn_with_state(accounts, Accounts::load::<…>))`.
    pub async fn gate(State(this): State<Self>, req: Request, next: Next) -> Response {
        let uri = req
            .extensions()
            .get::<OriginalUri>()
            .map_or_else(|| req.uri().clone(), |u| u.0.clone());
        if !is_page(&req) || this.exempted(uri.path()) {
            return next.run(req).await;
        }
        let Some(account) = Maybe::of(req.extensions()).0 else {
            return next.run(req).await;
        };
        let asked = match this.asked(account.id).await {
            Ok(asked) => asked,
            Err(e) => {
                tracing::error!(error = %e, "could not read the site policies an account accepted");
                return next.run(req).await;
            }
        };
        if asked.is_empty() {
            return next.run(req).await;
        }
        let here = uri.path_and_query().map_or("/", |p| p.as_str());
        let next: String = url::form_urlencoded::byte_serialize(here.as_bytes()).collect();
        (
            CachePolicy::no_store(),
            Redirect::to(&format!("{}?next={next}", this.0.agree)),
        )
            .into_response()
    }

    /// The current versions of the declared documents, from this replica's copy.
    async fn current(&self) -> sqlx::Result<Arc<Vec<Version>>> {
        let cached = self
            .0
            .cached
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        if let Some((at, docs)) = cached
            && at.elapsed() < self.0.refresh
        {
            return Ok(docs);
        }
        let kinds: Vec<&str> = self.0.documents.iter().map(|d| d.slug).collect();
        let docs = Arc::new(current_of(&self.0.pool, &kinds).await?);
        *self.0.cached.lock().unwrap_or_else(PoisonError::into_inner) =
            Some((Instant::now(), docs.clone()));
        Ok(docs)
    }

    fn forget_current(&self) {
        *self.0.cached.lock().unwrap_or_else(PoisonError::into_inner) = None;
    }

    /// The current versions `account_id` has not accepted, in the declared order.
    async fn asked(&self, account_id: i64) -> sqlx::Result<Vec<Version>> {
        let current = self.current().await?;
        if current.is_empty() {
            return Ok(Vec::new());
        }
        let accepted = accepted(&self.0.pool, account_id).await?;
        let mut asked: Vec<Version> = outstanding(&current, &accepted)
            .into_iter()
            .cloned()
            .collect();
        asked.sort_by_key(|v| self.0.documents.iter().position(|d| d.slug == v.kind));
        Ok(asked)
    }

    /// Never sent to the page that asks: it, the documents, the staff pages and the
    /// app's exemptions.
    fn exempted(&self, path: &str) -> bool {
        let under = |base: &str| path == base || path.starts_with(&format!("{base}/"));
        under(&self.0.agree)
            || self.0.admin.as_deref().is_some_and(under)
            || self
                .0
                .documents
                .iter()
                .any(|d| under(&self.href(d.slug, None)))
            || self.0.exempt.iter().any(|p| {
                if p.ends_with('/') {
                    path.starts_with(p.as_str())
                } else {
                    under(p)
                }
            })
    }

    fn document(&self, slug: &str) -> Option<&Document> {
        self.0.documents.iter().find(|d| d.slug == slug)
    }

    fn label<'a>(&'a self, slug: &'a str) -> &'a str {
        self.document(slug).map_or(slug, |d| d.label)
    }

    /// A document's page, or its version `n`'s.
    fn href(&self, slug: &str, n: Option<i32>) -> String {
        match n {
            Some(n) => format!("{}/{slug}/v/{n}", self.0.prefix),
            None => format!("{}/{slug}", self.0.prefix),
        }
    }

    /// A `YYYY-MM-DD` date, as the app writes dates.
    fn date(&self, date: &str) -> String {
        (self.0.dates)(date)
    }

    /// Version `n` of `slug`, dated `date`.
    fn link(&self, slug: &str, n: i32, date: &str) -> VersionLink {
        VersionLink {
            number: n,
            date: self.date(date),
            href: self.href(slug, Some(n)),
        }
    }

    async fn render(&self, request: &Parts, title: &str, body: owt_web::Result<Body>) -> Response {
        let page = match body {
            Ok(body) => {
                self.0
                    .chrome
                    .page(Page {
                        request,
                        title,
                        body,
                    })
                    .await
            }
            Err(e) => Err(e),
        };
        match page {
            Ok(response) => (CachePolicy::no_store(), response).into_response(),
            Err(e) => e.into_response(),
        }
    }

    fn base(&self) -> &str {
        self.0.admin.as_deref().unwrap_or_default()
    }

    fn redirect(&self, to: &str, notice: &str) -> Response {
        (
            CachePolicy::no_store(),
            Redirect::to(&format!("{}{to}?notice={notice}", self.base())),
        )
            .into_response()
    }
}

/// `path` without a trailing `/`, checked to be below the root.
fn below_root(path: &str) -> String {
    let path = path.trim_end_matches('/').to_owned();
    assert!(
        path.starts_with('/') && path.len() > 1,
        "{path:?} is not a path below the root, such as /agree"
    );
    path
}

/// A full page load: what the gate may redirect. A `GET` the browser makes for a
/// document, and nothing it makes for a page's parts: an `<img>`, a stylesheet, a
/// script or a fetch sent to `/agree` would be answered with a page they cannot use,
/// and the page would break. Browsers say what a request is for in
/// `Sec-Fetch-Dest` (`document` for a navigation); where it is absent, a navigation
/// is the request that asks for `text/html` by name (an `<img>` asks for images and
/// `*/*`, a fetch for `*/*` or JSON). An htmx request is a fragment, whatever it says,
/// except a boosted navigation (`HX-Boosted`): that is a whole page swapped in, and
/// htmx follows the 303 to the page that asks as a browser would.
fn is_page(req: &Request) -> bool {
    let flag = |name: &str| {
        req.headers()
            .get(name)
            .is_some_and(|v| v.as_bytes() == b"true")
    };
    let header = |name: &str| req.headers().get(name).and_then(|v| v.to_str().ok());
    if flag("hx-request") {
        return req.method() == Method::GET && flag("hx-boosted");
    }
    let document = match header("sec-fetch-dest") {
        Some(dest) => dest.eq_ignore_ascii_case("document"),
        None => header(header::ACCEPT.as_str()).is_some_and(|a| a.contains("text/html")),
    };
    req.method() == Method::GET && document
}

type Shared = State<Policies>;

/// The request's parts, for the app's chrome, with the URI the client sent: the
/// staff pages are nested, so the parts' own URI has the base stripped (`/` for
/// the list at `/staff/policies`), and a layout that reads it would name the wrong
/// page. `OriginalUri` (axum sets it on every request) is put in its place.
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

/// The document's text, rendered: HTML with no markup of its author's.
fn rendered(v: &Version) -> Body {
    Body(render_markdown(&v.body_markdown))
}

/// A document: its current version, or version `n`.
async fn show(
    State(this): Shared,
    Maybe(me): Maybe,
    Req(parts): Req,
    slug: &'static str,
    n: Option<i32>,
) -> owt_web::Result<Response> {
    let current = current(&this.0.pool, slug)
        .await?
        .ok_or(owt_web::Error::NotFound)?;
    let doc = match n {
        Some(n) if n != current.number() => published(&this.0.pool, slug, n)
            .await?
            .ok_or(owt_web::Error::NotFound)?,
        _ => current.clone(),
    };
    let versions = all(&this.0.pool, slug)
        .await?
        .into_iter()
        .filter_map(|v| v.version.map(|n| this.link(slug, n, &v.effective_date)))
        .collect();
    let mine = match me {
        Some(me) => accepted(&this.0.pool, me.id)
            .await?
            .into_iter()
            .find(|a| a.kind == slug)
            .map(|a| this.link(slug, a.version, &a.accepted_at)),
        None => None,
    };
    let view = DocumentView {
        body: rendered(&doc),
        date: this.date(&doc.effective_date),
        current: doc.id == current.id,
        current_href: this.href(slug, None),
        version: &doc,
        versions,
        mine,
        words: this.0.words,
    };
    let body = this.0.views.document(&parts, &view);
    Ok(this.render(&parts, &doc.title, body).await)
}

#[derive(Deserialize)]
struct NextQuery {
    next: Option<String>,
}

/// The page that asks, for what `me` has not accepted; `None` when that is nothing.
async fn asking(
    this: &Policies,
    parts: &Parts,
    me: i64,
    next: &str,
    error: Option<&str>,
) -> owt_web::Result<Option<Response>> {
    let asked = this.asked(me).await?;
    if asked.is_empty() {
        return Ok(None);
    }
    let held = accepted(&this.0.pool, me).await?;
    let asked: Vec<Asked> = asked
        .into_iter()
        .map(|version| Asked {
            previous: held
                .iter()
                .find(|a| a.kind == version.kind)
                .map(|a| this.link(&version.kind, a.version, &a.accepted_at)),
            href: this.href(&version.kind, None),
            date: this.date(&version.effective_date),
            version,
        })
        .collect();
    let view = AgreeView {
        action: &this.0.agree,
        first_time: asked.iter().all(|a| a.previous.is_none()),
        asked,
        next,
        agreement: &this.0.agreement,
        error,
        sign_out: this.0.sign_out.as_deref(),
        words: this.0.words,
    };
    let body = this.0.views.agree(parts, &view);
    Ok(Some(
        this.render(parts, this.0.words.agree_title, body).await,
    ))
}

async fn agree_form(
    State(this): Shared,
    Signed(me): Signed,
    Req(parts): Req,
    Query(q): Query<NextQuery>,
) -> owt_web::Result<Response> {
    let next = owt_web::redirect::local_or(q.next.as_deref(), "/");
    Ok(match asking(&this, &parts, me.id, next, None).await? {
        Some(page) => page,
        None => Redirect::to(next).into_response(),
    })
}

/// What the agree form posts: `agree`, `next`, and a `version` per document shown.
struct Posted(Vec<(String, String)>);

impl Posted {
    fn value(&self, name: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    fn versions(&self) -> Vec<i64> {
        let mut ids: Vec<i64> = self
            .0
            .iter()
            .filter(|(k, _)| k == "version")
            .filter_map(|(_, v)| v.parse().ok())
            .collect();
        ids.sort_unstable();
        ids
    }
}

/// Record the account's agreement to the versions it was shown, if they are still
/// what it is asked: a version published while it read is asked for again.
async fn agree(
    State(this): Shared,
    Signed(me): Signed,
    Req(parts): Req,
    Form(pairs): Form<Vec<(String, String)>>,
) -> owt_web::Result<Response> {
    let form = Posted(pairs);
    let next = owt_web::redirect::local_or(form.value("next"), "/");
    let mut asked: Vec<i64> = this.asked(me.id).await?.iter().map(|v| v.id).collect();
    if asked.is_empty() {
        return Ok(Redirect::to(next).into_response());
    }
    asked.sort_unstable();
    let refusal = if form.value("agree") != Some("yes") {
        Some((StatusCode::UNPROCESSABLE_ENTITY, this.0.words.not_ticked))
    } else if form.versions() != asked {
        Some((StatusCode::CONFLICT, this.0.words.changed))
    } else {
        None
    };
    if let Some((status, error)) = refusal {
        return Ok(
            match asking(&this, &parts, me.id, next, Some(error)).await? {
                Some(mut page) => {
                    *page.status_mut() = status;
                    page
                }
                None => Redirect::to(next).into_response(),
            },
        );
    }
    let ip = owt_web::client_ip::peer(&parts).map(|peer| {
        this.0
            .client_ip
            .client_ip(&parts.headers, peer.ip())
            .to_string()
    });
    let user_agent = parts
        .headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok());
    accept(&this.0.pool, me.id, &asked, ip.as_deref(), user_agent).await?;
    Ok((CachePolicy::no_store(), Redirect::to(next)).into_response())
}

/// The notice a staff page's redirect named; unknown names show nothing.
fn notice(name: Option<&str>) -> Option<Notice> {
    let (level, text) = match name? {
        "saved" => (Level::Success, "Draft saved."),
        "published" => (
            Level::Success,
            "Published. Everyone signed in is asked to agree to it on their next page.",
        ),
        "deleted" => (Level::Success, "Draft deleted."),
        "summary" => (
            Level::Error,
            "Say what changed before publishing: people asked to agree again read it.",
        ),
        "empty" => (Level::Error, "Write the document before publishing it."),
        "not-draft" => (
            Level::Error,
            "That version is published: it cannot be changed or deleted.",
        ),
        _ => return None,
    };
    Some(Notice {
        level,
        text: text.to_owned(),
    })
}

#[derive(Deserialize)]
struct NoticeQuery {
    notice: Option<String>,
}

async fn listing(
    this: &Policies,
    parts: &Parts,
    notice: Option<Notice>,
) -> owt_web::Result<Response> {
    let holders = holders(&this.0.pool).await?;
    let base = this.base();
    let mut documents = Vec::new();
    for doc in &this.0.documents {
        let versions = all(&this.0.pool, doc.slug).await?;
        let current = versions.iter().find(|v| v.version.is_some()).map(|v| v.id);
        let versions = versions
            .into_iter()
            .map(|version| AdminVersion {
                href: format!("{base}/{}", version.id),
                current: Some(version.id) == current,
                holders: holders
                    .iter()
                    .find(|(id, _)| *id == version.id)
                    .map_or(0, |(_, n)| *n),
                version,
            })
            .collect();
        documents.push(AdminDocument {
            document: *doc,
            href: this.href(doc.slug, None),
            new_draft: format!("{base}/new/{}", doc.slug),
            versions,
        });
    }
    let view = AdminListView {
        base,
        prune: format!("{base}/prune"),
        notice,
        documents,
    };
    let body = this.0.views.admin_list(parts, &view);
    Ok(this.render(parts, "Site policies", body).await)
}

async fn list(
    State(this): Shared,
    Staff(_): Staff,
    Req(parts): Req,
    Query(q): Query<NoticeQuery>,
) -> owt_web::Result<Response> {
    listing(&this, &parts, notice(q.notice.as_deref())).await
}

/// A new draft of a document, from its current version's text.
async fn new_draft(
    State(this): Shared,
    Staff(me): Staff,
    Path(kind): Path<String>,
) -> owt_web::Result<Response> {
    let doc = *this.document(&kind).ok_or(owt_web::Error::NotFound)?;
    let base = current(&this.0.pool, doc.slug).await?;
    let today: String = sqlx::query_scalar("SELECT to_char(current_date, 'YYYY-MM-DD')")
        .fetch_one(&this.0.pool)
        .await?;
    let made = draft(
        &this.0.pool,
        doc.slug,
        Draft {
            title: base.as_ref().map_or(doc.label, |v| v.title.as_str()),
            effective_date: &today,
            summary: "",
            body_markdown: base.as_ref().map_or("", |v| v.body_markdown.as_str()),
        },
        Some(me.id),
    )
    .await?;
    tracing::info!(
        by = me.id,
        kind = doc.slug,
        draft = made.id,
        "staff started a policy draft"
    );
    Ok((
        CachePolicy::no_store(),
        Redirect::to(&format!("{}/{}", this.base(), made.id)),
    )
        .into_response())
}

/// A version's staff page: its form while a draft, its record once published.
fn form_view<'a>(
    this: &'a Policies,
    doc: &'a Version,
    notice: Option<Notice>,
    errors: Vec<&'static str>,
    holders: i64,
) -> AdminFormView<'a> {
    let base = this.base();
    AdminFormView {
        base,
        label: this.label(&doc.kind),
        notice,
        errors,
        holders,
        preview: rendered(doc),
        save: format!("{base}/{}", doc.id),
        publish: format!("{base}/{}/publish", doc.id),
        delete: format!("{base}/{}/delete", doc.id),
        public_href: doc.version.map(|n| this.href(&doc.kind, Some(n))),
        version: doc,
    }
}

async fn edit(
    State(this): Shared,
    Staff(_): Staff,
    Req(parts): Req,
    Path(id): Path<i64>,
    Query(q): Query<NoticeQuery>,
) -> owt_web::Result<Response> {
    let doc = by_id(&this.0.pool, id)
        .await?
        .ok_or(owt_web::Error::NotFound)?;
    let holders = holders(&this.0.pool)
        .await?
        .into_iter()
        .find(|(v, _)| *v == id)
        .map_or(0, |(_, n)| n);
    let view = form_view(
        &this,
        &doc,
        notice(q.notice.as_deref()),
        Vec::new(),
        holders,
    );
    let title = format!("{}: {}", this.label(&doc.kind), doc.title);
    let body = this.0.views.admin_form(&parts, &view);
    Ok(this.render(&parts, &title, body).await)
}

#[derive(Deserialize)]
struct DraftForm {
    title: String,
    effective_date: String,
    #[serde(default)]
    summary: String,
    #[serde(default)]
    body_markdown: String,
}

async fn save_draft(
    State(this): Shared,
    Staff(me): Staff,
    Req(parts): Req,
    Path(id): Path<i64>,
    Form(form): Form<DraftForm>,
) -> owt_web::Result<Response> {
    let doc = by_id(&this.0.pool, id)
        .await?
        .ok_or(owt_web::Error::NotFound)?;
    if doc.version.is_some() {
        return Ok(this.redirect(&format!("/{id}"), "not-draft"));
    }
    let typed = Draft {
        title: &form.title,
        effective_date: &form.effective_date,
        summary: &form.summary,
        body_markdown: &form.body_markdown,
    };
    let errors = typed.problems();
    if errors.is_empty() {
        if save(&this.0.pool, id, typed).await?.is_none() {
            return Ok(this.redirect(&format!("/{id}"), "not-draft"));
        }
        tracing::info!(by = me.id, draft = id, "staff saved a policy draft");
        return Ok(this.redirect(&format!("/{id}"), "saved"));
    }
    let shown = Version {
        title: form.title.clone(),
        effective_date: form.effective_date.clone(),
        summary: form.summary.clone(),
        body_markdown: typed.body(),
        ..doc
    };
    let view = form_view(&this, &shown, None, errors, 0);
    let title = format!("{}: {}", this.label(&shown.kind), shown.title);
    let body = this.0.views.admin_form(&parts, &view);
    let mut response = this.render(&parts, &title, body).await;
    *response.status_mut() = StatusCode::UNPROCESSABLE_ENTITY;
    Ok(response)
}

async fn publish_draft(
    State(this): Shared,
    Staff(me): Staff,
    Path(id): Path<i64>,
) -> owt_web::Result<Response> {
    let doc = by_id(&this.0.pool, id)
        .await?
        .ok_or(owt_web::Error::NotFound)?;
    if doc.version.is_some() {
        return Ok(this.redirect(&format!("/{id}"), "not-draft"));
    }
    if doc.body_markdown.trim().is_empty() {
        return Ok(this.redirect(&format!("/{id}"), "empty"));
    }
    if doc.summary.is_empty() && current(&this.0.pool, &doc.kind).await?.is_some() {
        return Ok(this.redirect(&format!("/{id}"), "summary"));
    }
    let Some(done) = publish(&this.0.pool, id).await? else {
        return Ok(this.redirect(&format!("/{id}"), "not-draft"));
    };
    this.forget_current();
    tracing::info!(
        by = me.id,
        kind = done.kind,
        version = done.number(),
        sha256 = done.content_sha256,
        "staff published a policy version"
    );
    Ok(this.redirect("", "published"))
}

async fn delete_draft(
    State(this): Shared,
    Staff(me): Staff,
    Path(id): Path<i64>,
) -> owt_web::Result<Response> {
    if !discard(&this.0.pool, id).await? {
        return Ok(this.redirect(&format!("/{id}"), "not-draft"));
    }
    tracing::info!(by = me.id, draft = id, "staff deleted a policy draft");
    Ok(this.redirect("", "deleted"))
}

async fn prune_old(
    State(this): Shared,
    Staff(me): Staff,
    Req(parts): Req,
) -> owt_web::Result<Response> {
    let gone = prune(&this.0.pool).await?;
    tracing::info!(by = me.id, removed = ?gone, "staff removed policy versions nobody holds");
    let text = if gone.is_empty() {
        "Nothing to remove: every older version is still someone's latest agreement.".to_owned()
    } else {
        let names: Vec<String> = gone
            .iter()
            .map(|(kind, n)| format!("{} version {n}", this.label(kind)))
            .collect();
        format!("Removed {}.", names.join(", "))
    };
    listing(
        &this,
        &parts,
        Some(Notice {
            level: Level::Success,
            text,
        }),
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn version(id: i64, kind: &str) -> Version {
        Version {
            id,
            kind: kind.into(),
            version: Some(1),
            title: "T".into(),
            body_markdown: "x".into(),
            summary: String::new(),
            effective_date: "2026-01-01".into(),
            published_at: Some("2026-01-01 00:00".into()),
            content_sha256: Some("0".repeat(64)),
        }
    }

    fn held(version_id: i64, kind: &str) -> Accepted {
        Accepted {
            kind: kind.into(),
            version_id,
            version: 1,
            accepted_at: "2026-01-01".into(),
        }
    }

    #[cfg(feature = "test-util")]
    fn parts() -> Parts {
        axum::http::Request::new(()).into_parts().0
    }

    #[cfg(feature = "test-util")]
    #[test]
    fn the_examples_render_on_the_crates_own_pages() {
        let r = parts();
        let pages = [
            Tailwind.document(&r, &DocumentView::example()),
            Tailwind.agree(&r, &AgreeView::example()),
            Tailwind.admin_list(&r, &AdminListView::example()),
            Tailwind.admin_form(&r, &AdminFormView::example()),
            Tailwind.admin_form(&r, &AdminFormView::published()),
        ]
        .map(|page| page.unwrap().0);
        for html in &pages {
            assert!(
                !html.contains("<of>") && !html.contains("<wording>"),
                "{html}"
            );
        }
        let [document, agree, list, draft, published] = &pages;
        assert!(
            document.contains("Terms &#60;of&#62; Service"),
            "{document}"
        );
        assert!(
            document.contains("You agreed to version 2 on 2026-10-02.")
                && document.contains(
                    "<li><a href=\"/terms/v/2\">Version 2</a>, last updated 2026-10-01</li>"
                )
                && document.contains("<li>Version 1, last updated 2026-01-01</li>")
                && document.contains("<a href=\"/terms\">Read the current version</a>"),
            "{document}"
        );
        assert!(
            agree.contains("You last agreed to <a href=\"/terms/v/1\" target=\"_blank\" rel=\"noopener\">version 1</a>.")
                && agree.contains("Version 2, last updated 2026-10-01")
                && agree.contains("Clearer &#60;wording&#62;.")
                && agree.contains("name=\"version\" value=\"7\"")
                && agree.contains("action=\"/sign-out\"")
                && agree.contains("Tick the box"),
            "{agree}"
        );
        assert!(
            list.contains("action=\"/staff/policies/new/terms\"")
                && list.contains("href=\"/staff/policies/9\"")
                && list.contains("Draft saved."),
            "{list}"
        );
        assert!(
            draft.contains("action=\"/staff/policies/9/publish\"")
                && draft.contains("Give the date as YYYY-MM-DD."),
            "{draft}"
        );
        assert!(
            published.contains("<a href=\"/terms/v/2\">/terms/v/2</a>"),
            "{published}"
        );
    }

    #[cfg(feature = "test-util")]
    #[test]
    fn the_pages_write_the_words_given() {
        let words = Words {
            version: "Fassung {n}",
            version_in_sentence: "Fassung {n}",
            version_dated: "{version} vom {date}",
            header: "{version} vom {date}",
            you_agreed: "Am {date} haben Sie {version} zugestimmt.",
            read_current: "Zur aktuellen Fassung",
            last_agreed: "Zuletzt zugestimmt: {version}.",
            updated: "Unsere Richtlinien sind neu",
            agree: "Zustimmen und weiter",
            sign_out: "Lieber abmelden",
            ..Words::ENGLISH
        };
        let r = parts();
        let mut document = DocumentView::example();
        document.words = words;
        let html = Tailwind.document(&r, &document).unwrap().0;
        assert!(
            html.contains("Fassung 1 vom 2026-01-01 ·")
                && html.contains("Am 2026-10-02 haben Sie Fassung 2 zugestimmt.")
                && html.contains("<li><a href=\"/terms/v/2\">Fassung 2</a> vom 2026-10-01</li>")
                && html.contains("Zur aktuellen Fassung")
                && !html.contains("Version 1")
                && !html.contains("last updated"),
            "{html}"
        );
        let mut agree = AgreeView::example();
        agree.words = words;
        let html = Tailwind.agree(&r, &agree).unwrap().0;
        assert!(
            html.contains("Unsere Richtlinien sind neu")
                && html.contains("Zuletzt zugestimmt: <a href=\"/terms/v/1\" target=\"_blank\" rel=\"noopener\">Fassung 1</a>.")
                && html.contains("Zustimmen und weiter")
                && html.contains("Lieber abmelden")
                && !html.contains("Agree and continue"),
            "{html}"
        );
    }

    #[test]
    fn a_sentence_puts_its_parts_where_they_stand() {
        assert_eq!(numbered("Version {n}", 3), "Version 3");
        assert_eq!(
            sentence("{date}: {version}", "v3", "2026-01-01"),
            "2026-01-01: v3"
        );
        assert_eq!(
            around("Le {date}, {version}.", "1er"),
            ("Le 1er, ".to_owned(), ".".to_owned())
        );
        assert_eq!(
            around("no link", "x"),
            ("no link".to_owned(), String::new())
        );
    }

    #[test]
    fn markdown_renders_but_html_does_not() {
        let html = render_markdown("## Terms\n\n- **one**\n\n<script>alert(1)</script>");
        assert!(html.contains("<h2>Terms</h2>") && html.contains("<strong>one</strong>"));
        assert!(!html.contains("<script>"), "{html}");
        assert!(html.contains("&lt;script&gt;"));
        let inline = render_markdown("a <img src=x onerror=alert(1)> b");
        assert!(!inline.contains("<img"), "{inline}");
    }

    #[test]
    fn outstanding_is_what_the_account_does_not_hold() {
        let current = [version(3, "terms"), version(7, "privacy")];
        let none: Vec<&Version> = Vec::new();
        assert_eq!(
            outstanding(&current, &[held(3, "terms"), held(7, "privacy")]),
            none
        );
        let asked = outstanding(&current, &[held(2, "terms"), held(7, "privacy")]);
        assert_eq!(asked.iter().map(|v| v.id).collect::<Vec<_>>(), [3]);
        assert_eq!(outstanding(&current, &[]).len(), 2);
        assert_eq!(outstanding(&[], &[]), none, "no version yet asks nothing");
    }

    /// Only a document load is a page: a browser's navigation says so in
    /// `Sec-Fetch-Dest`, or asks for `text/html`; what a page loads for itself
    /// (an image, a script, a fetch) and a non-browser client never are.
    #[test]
    fn only_a_document_load_is_a_page() {
        let get = |pairs: &[(&str, &str)]| {
            let mut req = Request::get("/");
            for (k, v) in pairs {
                req = req.header(*k, *v);
            }
            req.body(axum::body::Body::empty()).unwrap()
        };
        for pairs in [
            &[("sec-fetch-dest", "document")][..],
            &[("sec-fetch-dest", "document"), ("accept", "*/*")],
            &[("accept", "text/html,application/xhtml+xml,*/*;q=0.8")],
            &[("accept", "text/html")],
        ] {
            assert!(is_page(&get(pairs)), "{pairs:?}");
        }
        for pairs in [
            &[
                ("sec-fetch-dest", "image"),
                ("accept", "image/avif,image/webp,*/*"),
            ][..],
            &[("sec-fetch-dest", "empty"), ("accept", "text/html")],
            &[("sec-fetch-dest", "script")],
            &[("sec-fetch-dest", "iframe")],
            &[("accept", "image/avif,image/webp,*/*")],
            &[("accept", "*/*")],
            &[("accept", "application/json")],
            &[],
            &[("sec-fetch-dest", "document"), ("hx-request", "true")],
            &[
                ("hx-request", "true"),
                ("hx-boosted", "true"),
                ("sec-fetch-dest", "empty"),
            ][..1],
        ] {
            assert!(!is_page(&get(pairs)), "{pairs:?}");
        }
        // A boosted navigation is a page, whatever else it sends.
        assert!(is_page(&get(&[
            ("hx-request", "true"),
            ("hx-boosted", "true"),
            ("sec-fetch-dest", "empty"),
            ("accept", "*/*"),
        ])));
        let mut post = Request::post("/")
            .header("sec-fetch-dest", "document")
            .body(axum::body::Body::empty())
            .unwrap();
        assert!(!is_page(&post));
        *post.method_mut() = Method::GET;
        assert!(is_page(&post));
    }

    #[test]
    fn slugs_are_lower_case_paths() {
        for ok in ["terms", "privacy", "cookie-policy", "a1"] {
            assert!(Document::slug_ok(ok), "{ok}");
        }
        for bad in ["", "Terms", "1terms", "-x", "a/b", "a_b", &"a".repeat(33)] {
            assert!(!Document::slug_ok(bad), "{bad}");
        }
    }

    #[test]
    fn dates_are_days_that_exist() {
        for ok in ["2026-10-16", "2024-02-29", "2000-02-29", "1999-12-31"] {
            assert!(is_date(ok), "{ok}");
        }
        for bad in [
            "2026-02-29",
            "1900-02-29",
            "2026-13-01",
            "2026-00-10",
            "2026-04-31",
            "2026-1-01",
            "26-01-01",
            "2026/01/01",
            "２０２６-01-01",
            "",
        ] {
            assert!(!is_date(bad), "{bad}");
        }
    }

    #[tokio::test]
    async fn the_gate_leaves_its_own_pages_and_the_apps_exemptions_alone() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://localhost/x")
            .unwrap();
        let chrome = |_: Page<'_>| -> owt_web::Result<Response> { Ok(().into_response()) };
        let p = Policies::new(pool, chrome, &[TERMS, PRIVACY])
            .admin("/staff/policies/")
            .exempt(&["/static/", "/ws/", "/api"]);
        for path in [
            "/agree",
            "/terms",
            "/terms/v/1",
            "/privacy",
            "/staff/policies",
            "/staff/policies/4",
            "/static/app.css",
            "/ws/x",
            "/api",
            "/api/v1/x",
        ] {
            assert!(p.exempted(path), "{path}");
        }
        for path in [
            "/",
            "/termsandmore",
            "/agreeable",
            "/staff",
            "/staff/accounts",
            // A prefix without a trailing slash stops at a segment boundary.
            "/apiary",
            "/static",
        ] {
            assert!(!p.exempted(path), "{path}");
        }
    }

    #[tokio::test]
    #[should_panic(expected = "two documents")]
    async fn two_documents_cannot_share_a_path() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://localhost/x")
            .unwrap();
        let chrome = |_: Page<'_>| -> owt_web::Result<Response> { Ok(().into_response()) };
        let _ = Policies::new(
            pool,
            chrome,
            &[TERMS, Document::new("terms", "Terms again")],
        );
    }
}
