//! A guard for forms anyone can post: a honeypot, a Turnstile check and a budget.
//!
//! An anonymous form with no budget is a free write into the app's database or an
//! operator's inbox. [`Guard::check`] answers what to do with a post:
//!
//! * [`Verdict::TooMany`] when the address is over its budget: answer 429.
//! * [`Verdict::Pretend`] when the honeypot was filled: answer exactly as for a
//!   person (the same redirect, the same thanks) and store or send nothing. A bot
//!   told it failed tries again, differently; one told it succeeded moves on.
//! * [`Verdict::Failed`] when Turnstile is on and the token is missing, refused, or
//!   could not be checked: show the form again with a message. It is a person's
//!   expired token as often as a bot, so it is not pretended away. The guard logs
//!   why: a refusal that means a wrong secret (see [`Outcome::is_misconfigured`]) at
//!   `error`, since it refuses every post, and the rest at `debug`.
//! * [`Verdict::Accept`] otherwise.
//!
//! The budget is checked first, so a flood costs a map lookup, not a Turnstile
//! request, and the honeypot before Turnstile, so a bot that tripped it costs none.
//! Give the guard a [`Throttle`] of its own, with budgets sized for a form (a few a
//! minute), so forms do not spend the sign-in budget and the reverse. The address is
//! the client's: see `owt_web::client_ip`.
//!
//! Turnstile is configured by `TURNSTILE_SITE_KEY` and `TURNSTILE_SECRET_KEY`
//! ([`Turnstile::from_env`]); with neither set it is off and the guard is a honeypot
//! and a budget.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use crate::throttle::Throttle;

/// The environment variable holding the Turnstile site key (public, in the page).
pub const SITE_KEY_VAR: &str = "TURNSTILE_SITE_KEY";
/// The environment variable holding the Turnstile secret key.
pub const SECRET_KEY_VAR: &str = "TURNSTILE_SECRET_KEY";

/// Turnstile's verification endpoint.
const SITEVERIFY: &str = "https://challenges.cloudflare.com/turnstile/v0/siteverify";

/// The longest token read: Turnstile's own limit is 2048 characters.
const MAX_TOKEN_BYTES: usize = 2048;

/// A field real visitors never see and bots fill in.
///
/// Render [`markup`](Self::markup) inside the form; a post whose field has anything
/// in it came from something that reads markup, not from a person.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Honeypot {
    field: &'static str,
}

impl Honeypot {
    /// A honeypot posted as `field`: a plausible name for something a form might ask
    /// (`company_url`), so a bot fills it. Not a name browsers autofill for people
    /// (`website`, `email`, `phone`). ASCII letters, digits, `-` and `_` only.
    ///
    /// # Panics
    ///
    /// If `field` is empty or has another character: it is written into markup.
    #[must_use]
    pub const fn new(field: &'static str) -> Self {
        let b = field.as_bytes();
        assert!(!b.is_empty(), "a honeypot field needs a name");
        let mut i = 0;
        while i < b.len() {
            assert!(
                b[i].is_ascii_alphanumeric() || b[i] == b'-' || b[i] == b'_',
                "a honeypot field is ASCII letters, digits, - and _"
            );
            i += 1;
        }
        Self { field }
    }

    /// The field's name, for the form struct (`#[serde(default)]`) and its parser.
    #[must_use]
    pub const fn field(&self) -> &'static str {
        self.field
    }

    /// The input, in a wrapper the `hidden` attribute keeps out of sight and out of
    /// the tab order and the accessibility tree (no style attribute, so a strict
    /// CSP needs nothing). Safe to emit unescaped.
    #[must_use]
    pub fn markup(&self) -> String {
        format!(
            r#"<div hidden aria-hidden="true"><input type="text" name="{}" tabindex="-1" autocomplete="off" value=""></div>"#,
            self.field
        )
    }

    /// Whether the posted `value` of the field trips it: anything but whitespace.
    #[must_use]
    pub fn tripped(&self, value: &str) -> bool {
        !value.trim().is_empty()
    }

    /// [`tripped`](Self::tripped) over the posted `(name, value)` pairs, for a form
    /// parsed into a map.
    #[must_use]
    pub fn tripped_in<K: AsRef<str>, V: AsRef<str>>(
        &self,
        pairs: impl IntoIterator<Item = (K, V)>,
    ) -> bool {
        pairs
            .into_iter()
            .any(|(k, v)| k.as_ref() == self.field && self.tripped(v.as_ref()))
    }
}

/// Turnstile misconfigured.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ConfigError {
    /// One of the two variables is set without the other.
    #[error("set both {SITE_KEY_VAR} and {SECRET_KEY_VAR}, or neither")]
    Half,
    /// The HTTP client could not be built (no TLS roots, say), so tokens could not be
    /// checked.
    #[error("building the Turnstile HTTP client failed")]
    Client,
}

/// Why a token could not be checked (as opposed to being refused).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum VerifyError {
    /// Turnstile could not be reached, answered late, or answered nonsense.
    #[error("talking to Turnstile: {0}")]
    Http(#[from] reqwest::Error),
}

/// siteverify's `error-codes` that mean the deployment is wrong, not the visitor: no
/// secret sent, or one Cloudflare does not know (mistyped, revoked, or a test key in
/// production). Every token is refused until it is fixed.
const MISCONFIGURED_CODES: [&str; 2] = ["missing-input-secret", "invalid-input-secret"];

/// What Turnstile made of a token it could be asked about.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Outcome {
    /// The token is good (and, if one is expected, for the right hostname).
    Passed,
    /// The token was refused.
    Refused {
        /// siteverify's `error-codes`, such as `timeout-or-duplicate`; empty for a
        /// blank or oversized token, which is refused without a request.
        codes: Vec<String>,
    },
    /// The token is good but was issued for another site than
    /// [`Turnstile::expect_hostname`] names.
    WrongHostname {
        /// The hostname Cloudflare reported, if it reported one.
        got: Option<String>,
    },
}

impl Outcome {
    /// Whether the token passed.
    #[must_use]
    pub const fn is_passed(&self) -> bool {
        matches!(self, Self::Passed)
    }

    /// Whether the refusal says the deployment is wrong rather than the visitor: the
    /// secret is missing or invalid, so every post will be refused. Log those at
    /// `warn` or `error`, and the rest at `debug`.
    #[must_use]
    pub fn is_misconfigured(&self) -> bool {
        match self {
            Self::Refused { codes } => codes
                .iter()
                .any(|c| MISCONFIGURED_CODES.contains(&c.as_str())),
            Self::Passed | Self::WrongHostname { .. } => false,
        }
    }
}

/// Cloudflare Turnstile: the site key a page embeds and the secret a server checks
/// tokens with.
#[derive(Clone)]
pub struct Turnstile {
    site_key: String,
    secret: String,
    http: reqwest::Client,
    endpoint: String,
    hostname: Option<String>,
}

impl std::fmt::Debug for Turnstile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Turnstile")
            .field("site_key", &self.site_key)
            .finish_non_exhaustive()
    }
}

#[derive(serde::Deserialize)]
struct SiteVerify {
    success: bool,
    hostname: Option<String>,
    #[serde(default, rename = "error-codes")]
    error_codes: Vec<String>,
}

impl Turnstile {
    /// Read [`SITE_KEY_VAR`] and [`SECRET_KEY_VAR`]. Neither set (or both blank) is
    /// `None`: Turnstile is off. One without the other is an error, so a half-made
    /// deployment fails at start rather than letting every post through unchecked.
    pub fn from_env() -> Result<Option<Self>, ConfigError> {
        let var = |name| std::env::var(name).ok();
        Self::from_values(var(SITE_KEY_VAR), var(SECRET_KEY_VAR))
    }

    /// [`Turnstile::from_env`] over given values.
    pub fn from_values(
        site_key: Option<String>,
        secret: Option<String>,
    ) -> Result<Option<Self>, ConfigError> {
        let clean = |v: Option<String>| v.map(|v| v.trim().to_owned()).filter(|v| !v.is_empty());
        match (clean(site_key), clean(secret)) {
            (None, None) => Ok(None),
            (Some(site_key), Some(secret)) => Ok(Some(Self {
                site_key,
                secret,
                http: reqwest::Client::builder()
                    .timeout(Duration::from_secs(5))
                    .redirect(reqwest::redirect::Policy::none())
                    .build()
                    .map_err(|_| ConfigError::Client)?,
                endpoint: SITEVERIFY.to_owned(),
                hostname: None,
            })),
            _ => Err(ConfigError::Half),
        }
    }

    /// Check tokens at `endpoint` instead of Cloudflare's: a stand-in server in tests.
    #[must_use]
    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = endpoint.into();
        self
    }

    /// Accept only tokens Turnstile issued for `hostname`, the site the widget ran on
    /// (compared without case). A token solved on another site that shares the keys
    /// is refused.
    #[must_use]
    pub fn expect_hostname(mut self, hostname: impl Into<String>) -> Self {
        self.hostname = Some(hostname.into());
        self
    }

    /// The site key the page embeds (`data-sitekey`).
    #[must_use]
    pub fn site_key(&self) -> &str {
        &self.site_key
    }

    /// What Turnstile makes of `token` (the form's `cf-turnstile-response`) for a post
    /// from `ip`. A missing, blank or oversized token is refused without a request.
    pub async fn verify(&self, token: &str, ip: IpAddr) -> Result<Outcome, VerifyError> {
        let token = token.trim();
        if token.is_empty() || token.len() > MAX_TOKEN_BYTES {
            return Ok(Outcome::Refused { codes: Vec::new() });
        }
        let ip = ip.to_string();
        let answer: SiteVerify = self
            .http
            .post(&self.endpoint)
            .form(&[
                ("secret", self.secret.as_str()),
                ("response", token),
                ("remoteip", ip.as_str()),
            ])
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        if !answer.success {
            return Ok(Outcome::Refused {
                codes: answer.error_codes,
            });
        }
        let right_site = self.hostname.as_deref().is_none_or(|want| {
            answer
                .hostname
                .as_deref()
                .is_some_and(|got| got.eq_ignore_ascii_case(want))
        });
        Ok(if right_site {
            Outcome::Passed
        } else {
            Outcome::WrongHostname {
                got: answer.hostname,
            }
        })
    }
}

/// What to do with a post.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Verdict {
    /// Handle it.
    Accept,
    /// A bot: answer as for a person, store and send nothing.
    Pretend,
    /// The address is over its budget: answer 429.
    TooMany,
    /// Turnstile refused the token or could not be asked: show the form again.
    Failed,
}

/// The honeypot, the budget and (when configured) Turnstile, in the order that spends
/// least on a bot.
#[derive(Clone, Debug)]
pub struct Guard {
    honeypot: Honeypot,
    turnstile: Option<Turnstile>,
    throttle: Arc<Throttle>,
}

impl Guard {
    /// A guard counting posts in `throttle` ([`Throttle::attempt`]).
    #[must_use]
    pub fn new(honeypot: Honeypot, turnstile: Option<Turnstile>, throttle: Arc<Throttle>) -> Self {
        Self {
            honeypot,
            turnstile,
            throttle,
        }
    }

    /// The honeypot, for the form's markup and field name.
    #[must_use]
    pub const fn honeypot(&self) -> &Honeypot {
        &self.honeypot
    }

    /// The Turnstile in use, if any, for the page's widget.
    #[must_use]
    pub const fn turnstile(&self) -> Option<&Turnstile> {
        self.turnstile.as_ref()
    }

    /// Decide a post from `ip`, with the honeypot field's posted `honeypot` value
    /// and the form's `cf-turnstile-response` as `token`.
    pub async fn check(&self, ip: IpAddr, honeypot: &str, token: &str) -> Verdict {
        if !self.throttle.attempt(ip) {
            return Verdict::TooMany;
        }
        if self.honeypot.tripped(honeypot) {
            return Verdict::Pretend;
        }
        let Some(turnstile) = &self.turnstile else {
            return Verdict::Accept;
        };
        match turnstile.verify(token, ip).await {
            Ok(Outcome::Passed) => Verdict::Accept,
            Ok(outcome) => {
                if outcome.is_misconfigured() {
                    tracing::error!(
                        ?outcome,
                        "turnstile rejected the secret key; refusing every post"
                    );
                } else if matches!(outcome, Outcome::WrongHostname { .. }) {
                    tracing::warn!(?outcome, "turnstile token was issued for another hostname");
                } else {
                    tracing::debug!(?outcome, "turnstile refused the token");
                }
                Verdict::Failed
            }
            Err(e) => {
                tracing::warn!(error = %e, "turnstile could not be reached; refusing the post");
                Verdict::Failed
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use axum::Router;
    use axum::routing::post;

    use super::*;
    use crate::throttle::Budgets;

    const HP: Honeypot = Honeypot::new("company_url");

    fn ip(last: u8) -> IpAddr {
        IpAddr::from([10, 0, 0, last])
    }

    fn throttle(n: u32) -> Arc<Throttle> {
        Arc::new(Throttle::new(Budgets {
            attempts_per_address: n,
            ..Budgets::default()
        }))
    }

    /// A Turnstile that accepts the token `good` and counts the requests it gets.
    async fn stand_in(calls: Arc<AtomicUsize>) -> Turnstile {
        let app = Router::new().route(
            "/siteverify",
            post(move |body: String| {
                calls.fetch_add(1, Ordering::SeqCst);
                async move {
                    let known = body.contains("secret=sekrit");
                    let ok = known
                        && body.contains("response=good")
                        && body.contains("remoteip=10.0.0.1");
                    let code = if known {
                        "timeout-or-duplicate"
                    } else {
                        "invalid-input-secret"
                    };
                    axum::Json(serde_json::json!({
                        "success": ok,
                        "hostname": "app.example",
                        "error-codes": if ok { vec![] } else { vec![code] },
                    }))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/siteverify", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await });
        Turnstile::from_values(Some("site".into()), Some("sekrit".into()))
            .unwrap()
            .unwrap()
            .with_endpoint(url)
    }

    #[test]
    fn the_honeypot_renders_a_hidden_input() {
        let m = HP.markup();
        assert!(
            m.contains(r#"name="company_url""#) && m.contains("hidden"),
            "{m}"
        );
        assert!(m.contains(r#"tabindex="-1""#) && m.contains(r#"autocomplete="off""#));
        assert!(!m.contains("style="), "{m}");
        assert!(!HP.tripped("") && !HP.tripped("  \n"));
        assert!(HP.tripped("http://spam"));
        assert!(HP.tripped_in([("name", "Ann"), ("company_url", "x")]));
        assert!(!HP.tripped_in([("name", "x"), ("company_url", " ")]));
        assert!(!HP.tripped_in([("site", "x")]));
    }

    #[test]
    #[should_panic(expected = "ASCII letters")]
    fn a_field_name_cannot_carry_markup() {
        let _ = Honeypot::new("a\"><script>");
    }

    #[test]
    fn turnstile_is_off_unless_both_keys_are_set() {
        let t = |a: Option<&str>, b: Option<&str>| {
            Turnstile::from_values(a.map(Into::into), b.map(Into::into))
        };
        assert!(t(None, None).unwrap().is_none());
        assert!(t(Some(" "), Some("")).unwrap().is_none());
        assert_eq!(t(Some("a"), None).unwrap_err(), ConfigError::Half);
        assert_eq!(t(None, Some("b")).unwrap_err(), ConfigError::Half);
        let on = t(Some(" site "), Some("sec")).unwrap().unwrap();
        assert_eq!(on.site_key(), "site");
        assert!(
            !format!("{on:?}").contains("sec\""),
            "the secret stays out of Debug"
        );
    }

    #[tokio::test]
    async fn without_turnstile_a_guard_is_a_honeypot_and_a_budget() {
        let g = Guard::new(HP, None, throttle(2));
        assert_eq!(g.check(ip(1), "", "").await, Verdict::Accept);
        assert_eq!(g.check(ip(1), "spam", "").await, Verdict::Pretend);
        // A bot spends budget too: it is still a post from that address.
        assert_eq!(g.check(ip(1), "", "").await, Verdict::TooMany);
        assert_eq!(g.check(ip(2), "", "").await, Verdict::Accept);
    }

    #[tokio::test]
    async fn turnstile_decides_what_the_honeypot_lets_by() {
        let calls = Arc::new(AtomicUsize::new(0));
        let g = Guard::new(HP, Some(stand_in(calls.clone()).await), throttle(100));
        assert_eq!(g.check(ip(1), "", "good").await, Verdict::Accept);
        assert_eq!(g.check(ip(1), "", "bad").await, Verdict::Failed);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        // No token, or one too long, is refused without asking Cloudflare.
        assert_eq!(g.check(ip(1), "", "").await, Verdict::Failed);
        assert_eq!(g.check(ip(1), "", &"x".repeat(5000)).await, Verdict::Failed);
        // A tripped honeypot is not worth a request.
        assert_eq!(g.check(ip(1), "spam", "good").await, Verdict::Pretend);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn an_expected_hostname_must_match() {
        let calls = Arc::new(AtomicUsize::new(0));
        let t = stand_in(calls).await;
        let ip1 = ip(1);
        assert_eq!(
            t.clone()
                .expect_hostname("APP.example")
                .verify("good", ip1)
                .await
                .unwrap(),
            Outcome::Passed
        );
        let wrong = t
            .expect_hostname("other.example")
            .verify("good", ip1)
            .await
            .unwrap();
        assert_eq!(
            wrong,
            Outcome::WrongHostname {
                got: Some("app.example".into())
            }
        );
        assert!(!wrong.is_passed() && !wrong.is_misconfigured());
    }

    #[tokio::test]
    async fn a_refusal_carries_siteverifys_error_codes() {
        let t = stand_in(Arc::new(AtomicUsize::new(0))).await;
        let refused = t.verify("stale", ip(1)).await.unwrap();
        assert_eq!(
            refused,
            Outcome::Refused {
                codes: vec!["timeout-or-duplicate".into()]
            }
        );
        assert!(!refused.is_passed() && !refused.is_misconfigured());
        // A blank token is refused without a request, so there are no codes.
        assert_eq!(
            t.verify(" ", ip(1)).await.unwrap(),
            Outcome::Refused { codes: vec![] }
        );
    }

    #[tokio::test]
    async fn a_wrong_secret_is_a_misconfiguration() {
        let t = stand_in(Arc::new(AtomicUsize::new(0))).await;
        let wrong = Turnstile::from_values(Some("site".into()), Some("nope".into()))
            .unwrap()
            .unwrap()
            .with_endpoint(t.endpoint.clone());
        let outcome = wrong.verify("good", ip(1)).await.unwrap();
        assert_eq!(
            outcome,
            Outcome::Refused {
                codes: vec!["invalid-input-secret".into()]
            }
        );
        assert!(outcome.is_misconfigured());
        for code in ["missing-input-secret", "invalid-input-secret"] {
            let o = Outcome::Refused {
                codes: vec!["other".into(), code.into()],
            };
            assert!(o.is_misconfigured(), "{code}");
        }
        assert!(!Outcome::Passed.is_misconfigured());
        assert!(
            !Outcome::Refused {
                codes: vec!["invalid-input-response".into()]
            }
            .is_misconfigured()
        );
        // The guard still just fails the post.
        let g = Guard::new(HP, Some(wrong), throttle(10));
        assert_eq!(g.check(ip(1), "", "good").await, Verdict::Failed);
    }

    #[tokio::test]
    async fn an_address_over_budget_costs_no_request() {
        let calls = Arc::new(AtomicUsize::new(0));
        let g = Guard::new(HP, Some(stand_in(calls.clone()).await), throttle(1));
        assert_eq!(g.check(ip(1), "", "good").await, Verdict::Accept);
        assert_eq!(g.check(ip(1), "", "good").await, Verdict::TooMany);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn an_unreachable_turnstile_fails_closed() {
        let t = Turnstile::from_values(Some("s".into()), Some("k".into()))
            .unwrap()
            .unwrap()
            .with_endpoint("http://127.0.0.1:9/siteverify");
        let g = Guard::new(HP, Some(t), throttle(10));
        assert_eq!(g.check(ip(1), "", "good").await, Verdict::Failed);
    }
}
