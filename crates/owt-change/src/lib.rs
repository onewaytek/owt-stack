//! Change requests from a site's own pages.
//!
//! A signed-in admin presses a floating "Request a change" button, points at the
//! part of the page they mean, and says what should change. The site's server
//! forwards that, with who asked, to a work tracker: a `POST` of [`ChangeRequest`]
//! as JSON to [`Config::endpoint`], under the site's key as a bearer.
//!
//! - **The browser never holds the key.** It posts to the site, same origin, with
//!   the admin's session cookie; the app's `CrossOrigin` layer refuses anything else.
//! - **Who asked comes from the session.** [`Admin::requester`] fills
//!   `requested_by`; a browser cannot name somebody else.
//! - **Off unless configured.** Without [`Config`] the routes answer 404 and the
//!   [`Button`] renders nothing, so an app can ship the wiring everywhere and turn it
//!   on per deployment.
//!
//! The button is `change.js`, served by these routes under the default
//! Content-Security-Policy: no inline script, no style attributes, only the
//! `owt-change-*` classes `tailwind/owt.css` defines.

use std::fmt;
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use askama::Template;
use askama::filters::HtmlSafe;
use axum::extract::rejection::JsonRejection;
use axum::extract::{FromRequestParts, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

/// The variable naming where requests go.
pub const URL_VAR: &str = "CHANGE_REQUESTS_URL";
/// The variable holding the site's key.
pub const KEY_VAR: &str = "CHANGE_REQUESTS_KEY";

/// The longest title: a card title, not a paragraph.
pub const TITLE_MAX: usize = 200;
/// The longest description an admin may write.
pub const DESCRIPTION_MAX: usize = 5_000;

/// How long the tracker gets to answer before the admin is told to try again.
const FORWARD_TIMEOUT: Duration = Duration::from_secs(10);

const SCRIPT: &str = include_str!("../assets/change.js");

/// The script's content hash, its URL's `?v=`.
static SCRIPT_HASH: LazyLock<String> = LazyLock::new(|| {
    use std::fmt::Write;
    Sha256::digest(SCRIPT.as_bytes())[..8]
        .iter()
        .fold(String::new(), |mut hex, b| {
            // Writing to a String cannot fail.
            let _ = write!(hex, "{b:02x}");
            hex
        })
});

/// Where requests go and the key they go under.
#[derive(Clone)]
pub struct Config {
    /// The tracker's change-request endpoint.
    pub endpoint: url::Url,
    /// The site's key, sent as `Authorization: Bearer`.
    pub key: String,
}

// The key stays out of logs.
impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("endpoint", &self.endpoint.as_str())
            .field("key", &"<redacted>")
            .finish()
    }
}

/// A configuration that cannot be used.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// One of the two variables is set without the other.
    #[error("set both {URL_VAR} and {KEY_VAR}, or neither")]
    Half,
    /// The endpoint is not an `http(s)` URL.
    #[error("{URL_VAR} is not an http(s) URL")]
    Url,
}

impl Config {
    /// Read [`URL_VAR`] and [`KEY_VAR`]. Neither set (or both blank) is `None`: the
    /// feature is off. One without the other is an error, so a half-made deployment
    /// fails at start rather than when an admin presses the button.
    pub fn from_env() -> Result<Option<Self>, ConfigError> {
        let var = |name| std::env::var(name).ok().filter(|v| !v.trim().is_empty());
        Self::from_values(var(URL_VAR), var(KEY_VAR))
    }

    /// [`Config::from_env`] over given values.
    pub fn from_values(
        url: Option<String>,
        key: Option<String>,
    ) -> Result<Option<Self>, ConfigError> {
        match (url, key) {
            (None, None) => Ok(None),
            (Some(url), Some(key)) => {
                let endpoint = url::Url::parse(url.trim()).map_err(|_| ConfigError::Url)?;
                if !matches!(endpoint.scheme(), "http" | "https") {
                    return Err(ConfigError::Url);
                }
                Ok(Some(Self {
                    endpoint,
                    key: key.trim().to_owned(),
                }))
            }
            _ => Err(ConfigError::Half),
        }
    }
}

/// Who asked, by the site's own sign-in.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Requester {
    /// The account's username.
    pub username: String,
    /// The account's email; empty when it has none.
    #[serde(default)]
    pub email: String,
}

/// Where on the page the admin pointed.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Element {
    /// A short CSS path to it.
    #[serde(default)]
    pub selector: String,
    /// Its text, trimmed.
    #[serde(default)]
    pub text: String,
}

/// The protocol: what the site's server posts to the tracker, as JSON.
///
/// The tracker answers `2xx` when it filed the request, and `4xx`/`5xx` with
/// `{"error": "<a sentence for the admin>"}` when it did not.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChangeRequest {
    /// What should change, in a line.
    pub title: String,
    /// The detail, in the admin's words.
    #[serde(default)]
    pub description: String,
    /// The page the admin was on.
    #[serde(default)]
    pub page_url: String,
    /// What they pointed at.
    #[serde(default)]
    pub element: Element,
    /// Text they had selected, if any.
    #[serde(default)]
    pub selection: String,
    /// The window's size, as `WIDTHxHEIGHT`.
    #[serde(default)]
    pub viewport: String,
    /// The browser's `User-Agent`.
    #[serde(default)]
    pub user_agent: String,
    /// Who asked. Set by the site's server, never taken from the browser.
    pub requested_by: Requester,
}

/// What the browser sends: the request without `requested_by` or `user_agent`,
/// which the server fills.
#[derive(Deserialize)]
struct Draft {
    #[serde(default)]
    title: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    page_url: String,
    #[serde(default)]
    element: Element,
    #[serde(default)]
    selection: String,
    #[serde(default)]
    viewport: String,
}

/// An extractor for whoever may send requests, saying who they are. The routes
/// refuse a request whose extractor rejects it, with that rejection.
pub trait Admin {
    /// Who asked.
    fn requester(&self) -> Requester;
}

impl Admin for owt_accounts::Staff {
    fn requester(&self) -> Requester {
        Requester {
            username: self.0.username.clone(),
            email: self.0.email.clone(),
        }
    }
}

/// The feature: its configuration and the client it forwards with. Cheap to clone.
#[derive(Clone)]
pub struct ChangeRequests(Arc<Inner>);

struct Inner {
    config: Option<Config>,
    http: reqwest::Client,
}

impl ChangeRequests {
    /// The feature, on when `config` is `Some`. `http` is the app's client.
    #[must_use]
    pub fn new(config: Option<Config>, http: reqwest::Client) -> Self {
        Self(Arc::new(Inner { config, http }))
    }

    /// Whether requests can be sent.
    #[must_use]
    pub fn enabled(&self) -> bool {
        self.0.config.is_some()
    }

    /// `POST /change-requests` and `GET /change.js`, for whoever `A` admits. Nest
    /// them where the app's accounts layer runs, and pass the same prefix to
    /// [`ChangeRequests::button`].
    pub fn routes<A, S>(&self) -> Router<S>
    where
        A: Admin + FromRequestParts<Self> + Send + 'static,
        S: Clone + Send + Sync + 'static,
    {
        Router::new()
            .route("/change-requests", post(send::<A>))
            .route("/change.js", get(script))
            .with_state(self.clone())
    }

    /// The button, for a page: the script tag when the feature is on and `admin` is
    /// true, nothing otherwise. `base` is where the routes are nested.
    #[must_use]
    pub fn button<'a>(&self, base: &'a str, admin: bool) -> Button<'a> {
        Button {
            base,
            visible: admin && self.enabled(),
            hash: SCRIPT_HASH.as_str(),
        }
    }
}

/// The script tag that puts the button on a page, or nothing.
///
/// ```html
/// <script src="/staff/change.js?v=…" data-endpoint="/staff/change-requests" defer></script>
/// ```
#[derive(Template, Clone, Copy, Debug)]
#[template(
    source = r#"{% if visible %}<script src="{{ base }}/change.js?v={{ hash }}" data-endpoint="{{ base }}/change-requests" defer></script>{% endif %}"#,
    ext = "html"
)]
pub struct Button<'a> {
    base: &'a str,
    visible: bool,
    hash: &'a str,
}
impl HtmlSafe for Button<'_> {}

fn answer(status: StatusCode, error: &str) -> Response {
    (status, Json(json!({ "error": error }))).into_response()
}

/// Cut `s` to at most `max` characters, on a character boundary.
fn clip(s: &str, max: usize) -> String {
    s.trim().chars().take(max).collect()
}

async fn send<A: Admin>(
    State(feature): State<ChangeRequests>,
    admin: A,
    headers: HeaderMap,
    body: Result<Json<Draft>, JsonRejection>,
) -> Response {
    let Some(config) = &feature.0.config else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Ok(Json(draft)) = body else {
        return answer(
            StatusCode::UNPROCESSABLE_ENTITY,
            "That request couldn't be read. Reload the page and try again.",
        );
    };
    let title = draft.title.trim();
    if title.is_empty() {
        return answer(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Give the request a short title.",
        );
    }
    if title.chars().count() > TITLE_MAX {
        return answer(
            StatusCode::UNPROCESSABLE_ENTITY,
            &format!("Keep the title under {TITLE_MAX} characters. Put the detail below it."),
        );
    }
    if draft.description.chars().count() > DESCRIPTION_MAX {
        return answer(
            StatusCode::UNPROCESSABLE_ENTITY,
            &format!("Keep the description under {DESCRIPTION_MAX} characters."),
        );
    }
    let user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    let request = ChangeRequest {
        title: title.to_owned(),
        description: draft.description.trim().to_owned(),
        page_url: clip(&draft.page_url, 2_000),
        element: Element {
            selector: clip(&draft.element.selector, 500),
            text: clip(&draft.element.text, 300),
        },
        selection: clip(&draft.selection, 2_000),
        viewport: clip(&draft.viewport, 40),
        user_agent: clip(user_agent, 300),
        requested_by: admin.requester(),
    };
    forward(&feature.0.http, config, &request).await
}

/// Send `request` on and turn the tracker's answer into one for the admin.
async fn forward(http: &reqwest::Client, config: &Config, request: &ChangeRequest) -> Response {
    const AGAIN: &str = "Couldn't send that request. Try again in a minute.";
    let sent = http
        .post(config.endpoint.clone())
        .bearer_auth(&config.key)
        .json(request)
        .timeout(FORWARD_TIMEOUT)
        .send()
        .await;
    let response = match sent {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "change request: the tracker is unreachable");
            return answer(StatusCode::BAD_GATEWAY, AGAIN);
        }
    };
    let status = response.status();
    if status.is_success() {
        return (StatusCode::CREATED, Json(json!({ "sent": true }))).into_response();
    }
    if matches!(status.as_u16(), 401 | 403) {
        tracing::warn!(%status, "change request: the tracker refused this site's key");
        return answer(
            StatusCode::BAD_GATEWAY,
            "This site's key for change requests was refused. Tell whoever runs the site.",
        );
    }
    let sentence = response
        .json::<serde_json::Value>()
        .await
        .ok()
        .and_then(|v| v.get("error")?.as_str().map(str::to_owned));
    match (status.as_u16(), sentence) {
        (422, Some(sentence)) => answer(StatusCode::UNPROCESSABLE_ENTITY, &sentence),
        (503, Some(sentence)) => answer(StatusCode::SERVICE_UNAVAILABLE, &sentence),
        _ => {
            tracing::warn!(%status, "change request: the tracker did not file it");
            answer(StatusCode::BAD_GATEWAY, AGAIN)
        }
    }
}

#[derive(Deserialize)]
struct Version {
    v: Option<String>,
}

async fn script(State(feature): State<ChangeRequests>, Query(q): Query<Version>) -> Response {
    if !feature.enabled() {
        return StatusCode::NOT_FOUND.into_response();
    }
    // Immutable only under the URL that names these bytes, as `owt_web::assets` does.
    let cache = if q.v.as_deref() == Some(SCRIPT_HASH.as_str()) {
        owt_web::assets::IMMUTABLE
    } else {
        "no-cache"
    };
    (
        [
            (header::CONTENT_TYPE, "text/javascript; charset=utf-8"),
            (header::CACHE_CONTROL, cache),
        ],
        SCRIPT,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_variables_or_neither() {
        assert!(Config::from_values(None, None).unwrap().is_none());
        assert!(matches!(
            Config::from_values(Some("https://t.test/x".into()), None),
            Err(ConfigError::Half)
        ));
        assert!(matches!(
            Config::from_values(Some("ftp://t.test/x".into()), Some("k".into())),
            Err(ConfigError::Url)
        ));
        let config = Config::from_values(Some("https://t.test/x".into()), Some(" k ".into()))
            .unwrap()
            .unwrap();
        assert_eq!(config.key, "k");
    }

    #[test]
    fn the_key_stays_out_of_debug() {
        let config = Config::from_values(
            Some("https://t.test/x".into()),
            Some("kys_secretsecret".into()),
        )
        .unwrap()
        .unwrap();
        assert!(!format!("{config:?}").contains("secret"));
    }

    #[test]
    fn clip_cuts_on_a_character() {
        assert_eq!(clip("  héllo  ", 2), "hé");
    }
}
