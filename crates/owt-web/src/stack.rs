//! The standard layer stack, in the one correct order.
//!
//! axum applies a layer to everything added before it, so the order written is the
//! reverse of the order run, and a mistake in it is silent. [`Stack::apply`] wraps an
//! app's routes in this order, innermost first:
//!
//! 1. the `NotFound` fallback, so an unmatched path is a marked 404;
//! 2. the account loader ([`Stack::accounts`]), inside the limits so its database
//!    read counts against the request's deadline;
//! 3. the [`Limits`] timeout and body cap, so a timed-out request is a 503 the
//!    layers outside see;
//! 4. the metrics timer ([`Stack::timer`]), outside the limits so it records the 503;
//! 5. the error pages ([`Stack::error_pages`]), which draw the marked 404, 500 and 503;
//! 6. the session layer, which opens the cookie before the loader reads it, and keeps
//!    the request's session through a 5xx (a sign-out aside);
//! 7. [`CrossOrigin`], which refuses a foreign request before a session is opened.
//!
//! The static files ([`Stack::assets`]) sit beside those routes, outside the session
//! and the error pages, and also outside the limits and the timer: a static request
//! has no deadline of its own and is absent from the duration metric. Then everything
//! is wrapped in:
//!
//! 8. [`Csp`], which mints the nonce the pages read, and sends the policy with every
//!    response, the error pages and refusals included;
//! 9. the default cache policy ([`headers::private_by_default`], or
//!    [`headers::no_store_by_default`]);
//! 10. [`headers::security`];
//! 11. [`headers::noindex`], when asked for.
//!
//! `owt-accounts` depends on this crate, so the account loader and the timer (in
//! `owt-runtime`) are handed in as closures over the router: see
//! [`accounts`](Stack::accounts).

use std::sync::Arc;

use axum::Router;
use axum::http::StatusCode;
use axum::middleware::{from_fn, from_fn_with_state};
use axum::response::Html;

use crate::assets::Assets;
use crate::csrf::CrossOrigin;
use crate::error::{self, Error};
use crate::headers::{self, Csp};
use crate::limits::Limits;
use crate::session::{SessionData, Sessions};

type Wrap = Box<dyn FnOnce(Router) -> Router>;
type Page = Arc<dyn Fn(StatusCode) -> Option<Html<String>> + Send + Sync>;

/// The layers of an app, set by builder methods and applied by [`apply`](Self::apply).
/// Only the sessions are required; every other piece is off, or the library's default.
#[must_use]
pub struct Stack<T> {
    sessions: Sessions<T>,
    limits: Limits,
    cross_origin: CrossOrigin,
    csp: Csp,
    timer: Option<Wrap>,
    accounts: Option<Wrap>,
    pages: Option<Page>,
    assets: Option<Assets>,
    own_fallback: bool,
    no_store: bool,
    noindex: bool,
}

impl<T: SessionData> Stack<T> {
    /// A stack around `sessions`, with a marked `NotFound` fallback installed on the
    /// routes handed to [`apply`](Self::apply). That **replaces** a fallback the
    /// router already has, since `Router::fallback` replaces rather than composes; an
    /// app with its own (a sign-in redirect, a catch-all page) calls
    /// [`keep_fallback`](Self::keep_fallback). The rest are
    /// defaults: [`Limits::default`], a [`CrossOrigin`] that
    /// trusts only the request's own origin, and a [`Csp`] of [`Csp::new`].
    pub fn new(sessions: Sessions<T>) -> Self {
        Self {
            sessions,
            limits: Limits::default(),
            cross_origin: CrossOrigin::new(),
            csp: Csp::new(),
            timer: None,
            accounts: None,
            pages: None,
            assets: None,
            own_fallback: false,
            no_store: false,
            noindex: false,
        }
    }

    /// The timeout and body cap, on the routes, their handlers and the account
    /// loader. The session validator runs outside the deadline, as does `/static`.
    pub fn limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// The cross-origin policy, for trusted origins and bypassed paths.
    pub fn cross_origin(mut self, cross_origin: CrossOrigin) -> Self {
        self.cross_origin = cross_origin;
        self
    }

    /// The content security policy.
    pub fn csp(mut self, csp: Csp) -> Self {
        self.csp = csp;
        self
    }

    /// The request timer, given the router with the limits applied:
    ///
    /// ```ignore
    /// .timer(|r| r.layer(from_fn_with_state(HttpTimer("myapp_http_request_seconds"), metrics::http)))
    /// ```
    ///
    /// It sits outside the limits, so a timed-out request is recorded as a 503, and
    /// inside the routing, so it sees the matched route.
    pub fn timer(mut self, wrap: impl FnOnce(Router) -> Router + 'static) -> Self {
        self.timer = Some(Box::new(wrap));
        self
    }

    /// The account loader, given the router with the `NotFound` fallback applied; the
    /// stack puts the limits, the timer, the error pages and the session layer around
    /// the result, so the loader's database read counts against the request's deadline
    /// and its 503 is drawn as an error page:
    ///
    /// ```ignore
    /// .accounts(|r| r.layer(from_fn_with_state(accounts, Accounts::load::<session::Data>)))
    /// ```
    ///
    /// It is a closure because `owt-accounts` depends on this crate.
    pub fn accounts(mut self, wrap: impl FnOnce(Router) -> Router + 'static) -> Self {
        self.accounts = Some(Box::new(wrap));
        self
    }

    /// The app's pages for the marked statuses (404, 500, 503): see
    /// [`error::error_pages`]. Without it the marked responses keep their plain text.
    pub fn error_pages(
        mut self,
        page: impl Fn(StatusCode) -> Option<Html<String>> + Send + Sync + 'static,
    ) -> Self {
        self.pages = Some(Arc::new(page));
        self
    }

    /// Serve `assets` under its prefix, outside the session, the account loader and
    /// the error pages (a missing file is a plain 404), inside the security headers
    /// and the policy.
    pub fn assets(mut self, assets: Assets) -> Self {
        self.assets = Some(assets);
        self
    }

    /// Keep the router's own fallback instead of replacing it with the marked
    /// `NotFound` one (an unmatched path is then whatever the app's fallback answers,
    /// and the error pages draw it only if it is marked).
    pub fn keep_fallback(mut self) -> Self {
        self.own_fallback = true;
        self
    }

    /// `no-store` on any response that sets no `Cache-Control`
    /// ([`headers::no_store_by_default`]), where the default is `private` for HTML
    /// only ([`headers::private_by_default`]).
    pub fn no_store_by_default(mut self) -> Self {
        self.no_store = true;
        self
    }

    /// `X-Robots-Tag: noindex, nofollow` on everything: staging hostnames.
    pub fn noindex(mut self, on: bool) -> Self {
        self.noindex = on;
        self
    }

    /// `routes` inside the stack. A router with state takes `with_state` first.
    ///
    /// Unless [`keep_fallback`](Self::keep_fallback) was called, this replaces the
    /// fallback `routes` has with the marked `NotFound` one.
    pub fn apply(self, routes: Router) -> Router {
        let mut pages = routes;
        if !self.own_fallback {
            pages = pages.fallback(|| async { Error::NotFound });
        }
        if let Some(wrap) = self.accounts {
            pages = wrap(pages);
        }
        pages = self.limits.apply(pages);
        if let Some(wrap) = self.timer {
            pages = wrap(pages);
        }
        if let Some(page) = self.pages {
            pages = pages.layer(from_fn(move |req, next| {
                let page = page.clone();
                async move { error::error_pages(req, next, move |status| page(status)).await }
            }));
        }
        let pages = pages
            .layer(from_fn_with_state(self.sessions, Sessions::<T>::layer))
            .layer(from_fn_with_state(self.cross_origin, CrossOrigin::layer));
        let app = match self.assets {
            Some(assets) => assets.mount(Router::new()).merge(pages),
            None => pages,
        };
        let app = app.layer(from_fn_with_state(self.csp, Csp::layer));
        let app = if self.no_store {
            app.layer(from_fn(headers::no_store_by_default))
        } else {
            app.layer(from_fn(headers::private_by_default))
        };
        let app = app.layer(from_fn(headers::security));
        if self.noindex {
            app.layer(from_fn(headers::noindex))
        } else {
            app
        }
    }
}
