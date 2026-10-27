//! The context every full page is drawn with: who is looking, which request it is,
//! the messages to show, the CSP nonce.
//!
//! [`PageCtx`] is an extractor. It reads the viewer the layer loaded
//! ([`crate::layer::MaybeWith`]), the request ([`RequestInfo`]), the nonce
//! ([`Nonce`]) and holds the session, from which [`flashes`](PageCtx::flashes) takes the
//! flash messages when the page is drawn. An app with fields of its own
//! wraps it: its context holds a `PageCtx`, extracts one first in its own
//! `FromRequestParts`, and derefs to it.
//!
//! Layer order, outermost first: the session layer, [`crate::Accounts`], and the
//! nonce's [`owt_web::headers::Csp`] anywhere above the handler. Without the session
//! layer there are no messages and no viewer; without the nonce layer the nonce
//! matches nothing; neither fails the request. The session layer must hold the
//! session type `T` the context names: with another type's layer, or none, the context
//! reads an empty session and takes no messages, and a `debug` log line (target
//! `owt_accounts::page`) says so on each full-page request.

use std::ops::Deref;
use std::sync::{Arc, OnceLock};

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use owt_web::flash::{Flash, HasFlashes};
use owt_web::headers::Nonce;
use owt_web::request::RequestInfo;
use owt_web::session::{Session, SessionData};

use crate::layer::MaybeWith;
use crate::session::Data;
use crate::store::Account;

/// What a full page is drawn with. `T` is the app's session data (it holds the
/// flash messages: [`HasFlashes`]), [`Data`] unless named; `X` is what
/// [`crate::Accounts::load_with`] read about the viewer, `()` under
/// [`crate::Accounts::load`].
///
/// The messages are taken from the session exactly once, by the first call to
/// [`flashes`](Self::flashes) (a handler draws the page, so that is render time):
/// extracting the context takes nothing, so a context that is dropped unrendered, or
/// a later extractor in the same handler that rejects (a `Form` or `Json` after it),
/// leaves them in the session for the next page. Clones share the taken messages, and
/// a second `PageCtx` extracted in the request finds the session empty once the first
/// has taken them: extract it once per request and clone it or take its
/// [`bare`](Self::bare) for the rest. A request htmx sent for a fragment takes none,
/// and draws none: they wait for the next full page, which is where they are shown. A fragment is `HX-Request` without `HX-Boosted` and without
/// `HX-History-Restore-Request` (a restore after a cache miss wants a whole page).
/// Derefs to the [`RequestInfo`], so a template writes `page.path` and
/// `page.url_with(..)`.
pub struct PageCtx<T = Data, X = ()> {
    /// The signed-in account, if any. None also when the database could not say.
    pub viewer: Option<Account>,
    /// What [`crate::Accounts::load_with`] read with the viewer; `Some(())` for a
    /// signed-in viewer under [`crate::Accounts::load`]. None when nobody is signed in.
    pub extra: Option<X>,
    /// The request, as templates read it.
    pub request: RequestInfo,
    /// The request's CSP nonce, for `<script nonce="{{ page.nonce }}">`.
    pub nonce: Nonce,
    flashes: Arc<Pending<T>>,
}

/// The session the messages wait in, and the messages once taken.
struct Pending<T> {
    /// None for a fragment, and for a [`PageCtx::bare`] context.
    session: Option<Session<T>>,
    taken: OnceLock<Vec<Flash>>,
}

impl<T, X: std::fmt::Debug> std::fmt::Debug for PageCtx<T, X> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PageCtx")
            .field("viewer", &self.viewer)
            .field("extra", &self.extra)
            .field("request", &self.request)
            .field("flashes", &self.flashes.taken.get())
            .field("nonce", &self.nonce)
            .finish()
    }
}

impl<T, X: Clone> Clone for PageCtx<T, X> {
    fn clone(&self) -> Self {
        Self {
            viewer: self.viewer.clone(),
            extra: self.extra.clone(),
            request: self.request.clone(),
            flashes: self.flashes.clone(),
            nonce: self.nonce.clone(),
        }
    }
}

impl<T, X> PageCtx<T, X> {
    /// This context as if the request were for `path` (a path with an optional
    /// query, [`RequestInfo::at`]): the "you are here" of a page drawn for another
    /// address, such as an error page or a form shown again at its own URL. The
    /// viewer, messages and nonce stay.
    #[must_use]
    pub fn at(mut self, path: &str) -> Self {
        self.request = RequestInfo::at(path);
        self
    }

    /// The context for a fragment drawn beside or within this page: the same viewer,
    /// request and nonce, and no messages, so they are shown once, by the page.
    #[must_use]
    pub fn bare(&self) -> Self
    where
        X: Clone,
    {
        Self {
            flashes: Arc::new(Pending {
                session: None,
                taken: OnceLock::new(),
            }),
            ..self.clone()
        }
    }
}

impl<T: SessionData + HasFlashes, X> PageCtx<T, X> {
    /// The messages to show, taken from the session for this page alone: the first
    /// call takes them, later calls (and clones) return the same. Empty for a fragment
    /// request and for a [`bare`](Self::bare) context. Call it when the page is drawn,
    /// not before an extractor that might reject.
    pub fn flashes(&self) -> &[Flash] {
        self.flashes.taken.get_or_init(|| {
            self.flashes
                .session
                .as_ref()
                .map(Session::take_flashes)
                .unwrap_or_default()
        })
    }
}

impl<T, X> Deref for PageCtx<T, X> {
    type Target = RequestInfo;

    fn deref(&self) -> &RequestInfo {
        &self.request
    }
}

impl<S, T, X> FromRequestParts<S> for PageCtx<T, X>
where
    S: Send + Sync,
    T: SessionData + HasFlashes,
    X: Clone + Send + Sync + 'static,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let request = RequestInfo::from_request_parts(parts, state).await?;
        let nonce = Nonce::from_request_parts(parts, state).await?;
        let (viewer, extra) = match MaybeWith::<X>::of(&parts.extensions).0 {
            Some((account, extra)) => (Some(account), Some(extra)),
            None => (None, None),
        };
        let restore = parts
            .headers
            .get("hx-history-restore-request")
            .is_some_and(|v| v.as_bytes() == b"true");
        let fragment = request.is_htmx && !request.is_boosted && !restore;
        let session = if fragment {
            None
        } else {
            if parts.extensions.get::<Session<T>>().is_none() {
                tracing::debug!(
                    session = std::any::type_name::<T>(),
                    "PageCtx found no session layer of this type; it takes no flash messages"
                );
            }
            Some(Session::<T>::from_request_parts(parts, state).await?)
        };
        Ok(Self {
            viewer,
            extra,
            request,
            flashes: Arc::new(Pending {
                session,
                taken: OnceLock::new(),
            }),
            nonce,
        })
    }
}
