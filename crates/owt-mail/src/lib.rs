//! Outgoing email for apps on owt-stack.
//!
//! One [`Mailer`] trait and the transports apps choose between: [`Smtp`] (any
//! provider's relay, through lettre), [`Resend`] and [`Ses`] (HTTP APIs), and
//! [`Outbox`], which keeps messages in memory and delivers nothing (tests, CI, a
//! workstation). [`Mail`] is the handle an app keeps in its state: a transport, or
//! none at all, in which case [`Mail::send`] answers [`Delivery::NotConfigured`] and
//! the caller says so instead of failing. [`Allowlisted`] wraps any transport so a
//! demo deployment mails only the addresses on a list.
//!
//! [`Mail::from_env`] picks the transport from the environment:
//!
//! - `MAIL_URL=smtp://user:pass@host:587` (STARTTLS) or `smtps://user:pass@host:465`
//!   (TLS), as lettre reads the URL; `MAIL_URL=memory:` is the outbox.
//! - `RESEND_API_KEY`: Resend.
//! - `SES_REGION`, with `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`
//!   (`AWS_SESSION_TOKEN` and `SES_ENDPOINT` optional): SES's v2 `SendEmail`.
//! - `MAIL_FROM`, the sender, with any of them but the outbox.
//!
//! Two of the three set at once is a configuration error, not a precedence rule.
//! None set: whatever [`Unconfigured`] says.
//!
//! Every address is parsed as a mailbox before anything is sent, and a subject may
//! not hold a line break, so no caller can add a header. A message's [`Debug`] shows
//! its subject only: recipients are personal data and bodies carry sign-in links.

use std::sync::Arc;
use std::time::Duration;

use futures::future::BoxFuture;
use lettre::message::Mailbox;
use owt_runtime::env::Vars;

mod allow;
mod outbox;
mod resend;
mod ses;
mod smtp;

pub use allow::{Allowlisted, MailAllow};
pub use outbox::{Failing, Outbox, first_link};
pub use resend::Resend;
pub use ses::Ses;
pub use smtp::Smtp;

/// How long one delivery may take before it fails: a request usually waits on it.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// One message to one address: plain text, and optionally an HTML alternative.
#[derive(Clone, PartialEq, Eq)]
pub struct Email {
    /// The recipient, an address or `Name <address>`.
    pub to: String,
    /// The subject, one line.
    pub subject: String,
    /// The plain-text body.
    pub text: String,
    /// The HTML alternative; mail clients that show HTML show it instead.
    pub html: Option<String>,
}

impl Email {
    /// A plain-text message.
    pub fn new(to: impl Into<String>, subject: impl Into<String>, text: impl Into<String>) -> Self {
        Self {
            to: to.into(),
            subject: subject.into(),
            text: text.into(),
            html: None,
        }
    }

    /// With an HTML alternative to the text.
    #[must_use]
    pub fn with_html(mut self, html: impl Into<String>) -> Self {
        self.html = Some(html.into());
        self
    }

    /// The recipient as a mailbox, and a subject without a line break: what every
    /// transport checks before sending.
    pub(crate) fn checked_recipient(&self) -> Result<Mailbox, Error> {
        if self.subject.contains(['\r', '\n']) {
            return Err(Error::Header);
        }
        parse_mailbox(&self.to).ok_or(Error::Address)
    }
}

impl std::fmt::Debug for Email {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Email")
            .field("to", &"[redacted]")
            .field("subject", &self.subject)
            .field("text", &"[redacted]")
            .field("html", &self.html.as_ref().map(|_| "[redacted]"))
            .finish()
    }
}

/// An address or `Name <address>`, refusing anything lettre would not put in a
/// header as one mailbox (a line break, a second address).
pub(crate) fn parse_mailbox(s: &str) -> Option<Mailbox> {
    if s.contains(['\r', '\n']) {
        return None;
    }
    s.trim().parse().ok()
}

/// Why a message was not sent.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The recipient is not one email address. The address is left out of the text,
    /// which ends up in logs.
    #[error("the recipient is not an email address")]
    Address,
    /// The subject holds a line break.
    #[error("the subject holds a line break")]
    Header,
    /// [`Allowlisted`] refused the recipient.
    #[error("this deployment does not send email to that address")]
    Refused,
    /// The provider answered, and refused the message. `reason` is its own words,
    /// at most 300 characters, never the credentials.
    #[error("{provider} refused the message: {reason}")]
    Rejected {
        /// `smtp`, `resend`, `ses` or `test`.
        provider: &'static str,
        /// What the provider said.
        reason: String,
    },
    /// The provider could not be reached, or did not answer in time.
    #[error("{provider} could not be reached: {source}")]
    Unreachable {
        /// `smtp`, `resend` or `ses`.
        provider: &'static str,
        /// The transport's error.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
}

/// A way to send an [`Email`]. Implement it for a transport of your own; the crate's
/// are [`Smtp`], [`Resend`], [`Ses`], [`Outbox`] and [`Failing`].
pub trait Mailer: Send + Sync + 'static {
    /// Deliver `email`, or say why not.
    fn send<'a>(&'a self, email: &'a Email) -> BoxFuture<'a, Result<(), Error>>;

    /// The transport's name for logs and [`Mail`]'s `Debug`.
    fn kind(&self) -> &'static str;

    /// The outbox, when this transport keeps messages instead of delivering them.
    fn outbox(&self) -> Option<&Outbox> {
        None
    }
}

/// What became of a message [`Mail::send`] was given.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub enum Delivery {
    /// Handed to a provider.
    Sent,
    /// Kept in the [`Outbox`]; nobody receives it.
    Kept,
    /// No transport is configured: nothing was sent, and the caller says so ("no
    /// email sent: mail isn't configured").
    NotConfigured,
}

/// What [`Mail::from_env`] does when no transport is configured.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Unconfigured {
    /// No mail: [`Mail::send`] answers [`Delivery::NotConfigured`].
    Off,
    /// The [`Outbox`], logging each message's text so a workstation reads its
    /// sign-in links from the log. Not for production, where it would log them.
    Outbox,
}

/// The app's mailer: a transport, or none. Cheap to clone.
#[derive(Clone, Default)]
pub struct Mail(Option<Arc<dyn Mailer>>);

impl std::fmt::Debug for Mail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Mail")
            .field(&self.0.as_deref().map_or("none", Mailer::kind))
            .finish()
    }
}

impl Mail {
    /// No transport: nothing is sent.
    #[must_use]
    pub fn none() -> Self {
        Self(None)
    }

    /// Send through `mailer`.
    pub fn new(mailer: impl Mailer) -> Self {
        Self(Some(Arc::new(mailer)))
    }

    /// Send through a shared `mailer`.
    #[must_use]
    pub fn from_arc(mailer: Arc<dyn Mailer>) -> Self {
        Self(Some(mailer))
    }

    /// An [`Outbox`], and the handle that sends into it: for tests.
    #[must_use]
    pub fn outbox() -> (Self, Outbox) {
        let outbox = Outbox::default();
        (Self::new(outbox.clone()), outbox)
    }

    /// The transport the process environment describes (see the crate docs).
    pub fn from_env(unconfigured: Unconfigured) -> anyhow::Result<Self> {
        Self::from_vars(&Vars::Process, unconfigured)
    }

    /// The transport `vars` describes (see the crate docs).
    pub fn from_vars(vars: &Vars, unconfigured: Unconfigured) -> anyhow::Result<Self> {
        let url = vars.var("MAIL_URL");
        let resend = vars.var("RESEND_API_KEY").is_some();
        let ses = vars.var("SES_REGION");
        let set = [url.is_some(), resend, ses.is_some()]
            .into_iter()
            .filter(|s| *s)
            .count();
        anyhow::ensure!(
            set <= 1,
            "set one of MAIL_URL, RESEND_API_KEY and SES_REGION, not {set}"
        );
        let from = || -> anyhow::Result<Mailbox> {
            let from = vars.required("MAIL_FROM")?;
            parse_mailbox(&from)
                .ok_or_else(|| anyhow::anyhow!("MAIL_FROM={from:?} is not an email address"))
        };
        if let Some(url) = url {
            if url == "memory:" {
                return Ok(Self::new(Outbox::default()));
            }
            return Ok(Self::new(Smtp::from_url(
                &vars.secret("MAIL_URL")?,
                from()?,
                DEFAULT_TIMEOUT,
            )?));
        }
        if resend {
            return Ok(Self::new(Resend::new(
                vars.secret("RESEND_API_KEY")?,
                from()?,
                DEFAULT_TIMEOUT,
            )?));
        }
        if let Some(region) = ses {
            let ses = Ses::new(
                &region,
                from()?,
                vars.required("AWS_ACCESS_KEY_ID")?,
                vars.secret("AWS_SECRET_ACCESS_KEY")?,
                vars.var("AWS_SESSION_TOKEN")
                    .map(owt_runtime::logging::Sensitive::new),
                DEFAULT_TIMEOUT,
            )?;
            let ses = match vars.var("SES_ENDPOINT") {
                Some(endpoint) => ses.with_endpoint(&endpoint)?,
                None => ses,
            };
            return Ok(Self::new(ses));
        }
        Ok(match unconfigured {
            Unconfigured::Off => Self::none(),
            Unconfigured::Outbox => Self::new(Outbox::default().logging_text()),
        })
    }

    /// Only the addresses `allow` lists receive mail; others fail with
    /// [`Error::Refused`]. No transport stays no transport.
    #[must_use]
    pub fn allow_only(self, allow: MailAllow) -> Self {
        match self.0 {
            Some(inner) => Self::new(Allowlisted::new(inner, allow)),
            None => self,
        }
    }

    /// Whether a transport is configured (the outbox counts).
    #[must_use]
    pub fn is_configured(&self) -> bool {
        self.0.is_some()
    }

    /// Whether messages reach anyone: a transport that is not the outbox. A
    /// production deployment refuses to start without it, if it sends sign-in links.
    #[must_use]
    pub fn delivers(&self) -> bool {
        self.0.as_deref().is_some_and(|m| m.outbox().is_none())
    }

    /// The outbox, when that is the transport.
    #[must_use]
    pub fn outbox_ref(&self) -> Option<&Outbox> {
        self.0.as_deref().and_then(Mailer::outbox)
    }

    /// What the outbox holds, oldest first; empty for any other transport.
    #[must_use]
    pub fn sent(&self) -> Vec<Email> {
        self.outbox_ref().map(Outbox::sent).unwrap_or_default()
    }

    /// Send `email`.
    pub async fn send(&self, email: &Email) -> Result<Delivery, Error> {
        let Some(mailer) = self.0.as_deref() else {
            return Ok(Delivery::NotConfigured);
        };
        mailer.send(email).await?;
        Ok(if mailer.outbox().is_some() {
            Delivery::Kept
        } else {
            Delivery::Sent
        })
    }
}

/// The reason in a provider's error answer: its `message` field, else the body,
/// trimmed and at most 300 characters.
pub(crate) fn refusal(body: &str) -> String {
    let message = serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| {
            v.get("message")
                .or_else(|| v.get("Message"))?
                .as_str()
                .map(str::to_owned)
        })
        .unwrap_or_else(|| body.trim().to_owned());
    message.chars().take(300).collect()
}

/// An HTTP provider's endpoint: `https://`, or `http://` to a loopback host (a fake
/// in a test). Returns the origin without a trailing slash.
pub(crate) fn endpoint(raw: &str, what: &str) -> anyhow::Result<url::Url> {
    let url = url::Url::parse(raw.trim_end_matches('/'))
        .map_err(|_| anyhow::anyhow!("{what} is not a URL"))?;
    let loopback = matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"));
    anyhow::ensure!(
        url.scheme() == "https" || (url.scheme() == "http" && loopback),
        "{what} is an https:// origin"
    );
    anyhow::ensure!(
        url.path() == "/"
            && url.query().is_none()
            && url.username().is_empty()
            && url.password().is_none(),
        "{what} is an origin, with no path, query or credentials"
    );
    Ok(url)
}

pub(crate) fn http_client(timeout: Duration) -> anyhow::Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .build()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vars(pairs: &[(&str, &str)]) -> Vars {
        pairs.iter().copied().collect()
    }

    #[tokio::test]
    async fn without_a_transport_nothing_is_sent() {
        let mail = Mail::from_vars(&vars(&[]), Unconfigured::Off).unwrap();
        assert!(!mail.is_configured() && !mail.delivers());
        assert_eq!(
            mail.send(&Email::new("a@example.com", "Hi", "Body"))
                .await
                .unwrap(),
            Delivery::NotConfigured
        );
        assert_eq!(format!("{mail:?}"), "Mail(\"none\")");
    }

    #[tokio::test]
    async fn unconfigured_can_mean_the_outbox() {
        let mail = Mail::from_vars(&vars(&[]), Unconfigured::Outbox).unwrap();
        assert!(mail.is_configured() && !mail.delivers());
        assert_eq!(
            mail.send(&Email::new("a@example.com", "Hi", "Body"))
                .await
                .unwrap(),
            Delivery::Kept
        );
        assert_eq!(mail.sent().len(), 1);
    }

    #[tokio::test]
    async fn memory_is_the_outbox_and_needs_no_sender() {
        let mail = Mail::from_vars(&vars(&[("MAIL_URL", "memory:")]), Unconfigured::Off).unwrap();
        let email = Email::new("Ana <a@example.com>", "Hi", "Body").with_html("<p>Body</p>");
        assert_eq!(mail.send(&email).await.unwrap(), Delivery::Kept);
        assert_eq!(mail.sent(), [email]);
    }

    #[test]
    fn each_transport_is_chosen_by_its_variable() {
        let from = ("MAIL_FROM", "Site <noreply@example.com>");
        let smtp = Mail::from_vars(
            &vars(&[("MAIL_URL", "smtps://u:hunter2@smtp.example.com:465"), from]),
            Unconfigured::Off,
        )
        .unwrap();
        assert_eq!(format!("{smtp:?}"), "Mail(\"smtp\")");
        assert!(smtp.delivers());
        let resend = Mail::from_vars(
            &vars(&[("RESEND_API_KEY", "re_123"), from]),
            Unconfigured::Off,
        )
        .unwrap();
        assert_eq!(format!("{resend:?}"), "Mail(\"resend\")");
        let ses = Mail::from_vars(
            &vars(&[
                ("SES_REGION", "us-east-1"),
                ("AWS_ACCESS_KEY_ID", "AKID"),
                ("AWS_SECRET_ACCESS_KEY", "s"),
                from,
            ]),
            Unconfigured::Off,
        )
        .unwrap();
        assert_eq!(format!("{ses:?}"), "Mail(\"ses\")");
    }

    #[test]
    fn misconfiguration_fails_start_up_without_echoing_secrets() {
        let err = |pairs: &[(&str, &str)]| {
            Mail::from_vars(&vars(pairs), Unconfigured::Off)
                .unwrap_err()
                .to_string()
        };
        assert!(
            err(&[
                ("MAIL_URL", "smtp://h"),
                ("RESEND_API_KEY", "k"),
                ("MAIL_FROM", "a@b.c")
            ])
            .contains("not 2")
        );
        assert!(err(&[("RESEND_API_KEY", "k")]).contains("MAIL_FROM"));
        assert!(
            err(&[("RESEND_API_KEY", "k"), ("MAIL_FROM", "nobody")])
                .contains("not an email address")
        );
        let bad = err(&[("MAIL_URL", "ftp://u:hunter2@h"), ("MAIL_FROM", "a@b.c")]);
        assert!(!bad.contains("hunter2"), "{bad}");
        assert!(
            err(&[("SES_REGION", "us-east-1"), ("MAIL_FROM", "a@b.c")])
                .contains("AWS_ACCESS_KEY_ID")
        );
    }

    #[tokio::test]
    async fn no_caller_adds_a_header() {
        let (mail, outbox) = Mail::outbox();
        for email in [
            Email::new("a@example.com\r\nBcc: x@evil.example", "Hi", "b"),
            Email::new("a@example.com, x@evil.example", "Hi", "b"),
            Email::new("not an address", "Hi", "b"),
        ] {
            assert!(
                matches!(mail.send(&email).await, Err(Error::Address)),
                "{:?}",
                email.to
            );
        }
        let header = Email::new("a@example.com", "Hi\r\nBcc: x@evil.example", "b");
        assert!(matches!(mail.send(&header).await, Err(Error::Header)));
        assert_eq!(outbox.sent(), Vec::<Email>::new());
    }

    #[test]
    fn debug_shows_only_the_subject() {
        let email = Email::new(
            "ana@example.com",
            "Your link",
            "https://x.example/link/secret",
        )
        .with_html("<a>secret</a>");
        let shown = format!("{email:?}");
        assert!(shown.contains("Your link"));
        assert!(
            !shown.contains("ana@") && !shown.contains("secret"),
            "{shown}"
        );
    }

    #[test]
    fn a_refusal_is_the_providers_message_clipped() {
        assert_eq!(
            refusal(r#"{"statusCode":403,"message":"The example.com domain is not verified."}"#),
            "The example.com domain is not verified."
        );
        assert_eq!(
            refusal(r#"{"Message":"Email address is not verified."}"#),
            "Email address is not verified."
        );
        assert_eq!(refusal(" bad gateway \n"), "bad gateway");
        assert_eq!(refusal(&"x".repeat(500)).len(), 300);
    }

    #[test]
    fn endpoints_are_https_origins_or_loopback() {
        assert!(endpoint("https://email.us-east-1.amazonaws.com", "E").is_ok());
        assert!(endpoint("https://api.resend.com/", "E").is_ok());
        assert!(endpoint("http://127.0.0.1:9000", "E").is_ok());
        assert!(endpoint("http://email.example", "E").is_err());
        assert!(endpoint("https://email.example/x", "E").is_err());
        assert!(endpoint("https://u:p@email.example", "E").is_err());
    }
}
