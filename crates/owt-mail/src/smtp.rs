//! SMTP through lettre.

use std::time::Duration;

use futures::future::BoxFuture;
use lettre::message::{Mailbox, MultiPart, SinglePart, header::ContentType};
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use owt_runtime::logging::Sensitive;

use crate::{Email, Error, Mailer};

/// How [`Smtp`] protects the connection to the relay, as its URL decides.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SmtpTls {
    /// `smtps://`: TLS from the first byte (port 465 by default).
    Implicit,
    /// `smtp://`, with no `tls` parameter or `?tls=required`: STARTTLS before
    /// anything else is said, and the delivery fails if the relay doesn't offer it
    /// (port 587 by default).
    StartTls,
    /// `smtp://…?tls=none`: plaintext, for a local mail catcher. Credentials are
    /// accepted only towards a loopback host.
    None,
}

/// Any provider's SMTP relay. The URL carries the relay's credentials and is never
/// kept or printed; `Debug` shows the sender and the TLS mode only.
pub struct Smtp {
    from: Mailbox,
    transport: AsyncSmtpTransport<Tokio1Executor>,
    timeout: Duration,
    tls: SmtpTls,
}

impl std::fmt::Debug for Smtp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Smtp")
            .field("from", &self.from.to_string())
            .field("tls", &self.tls)
            .finish_non_exhaustive()
    }
}

/// The TLS mode `url` asks for and the URL lettre is given for it. No error quotes
/// the URL: it carries the relay's password.
fn tls_of(url: &str) -> anyhow::Result<(SmtpTls, String)> {
    let mut url = url::Url::parse(url)
        .map_err(|_| anyhow::anyhow!("MAIL_URL is not an smtp:// or smtps:// URL"))?;
    let tls = url
        .query_pairs()
        .find(|(k, _)| k == "tls")
        .map(|(_, v)| v.into_owned());
    let mode = match (url.scheme(), tls.as_deref()) {
        ("smtps", None) => SmtpTls::Implicit,
        ("smtp", None | Some("required")) => SmtpTls::StartTls,
        ("smtp", Some("none")) => SmtpTls::None,
        ("smtp", Some("opportunistic")) => anyhow::bail!(
            "MAIL_URL asks for tls=opportunistic, which falls back to plaintext: \
             use smtps://, smtp:// (STARTTLS required) or, for a local mail catcher, ?tls=none"
        ),
        ("smtp" | "smtps", Some(_)) => anyhow::bail!(
            "MAIL_URL's tls parameter must be `required` or `none` (smtp://), or absent"
        ),
        _ => anyhow::bail!("MAIL_URL is not an smtp:// or smtps:// URL"),
    };
    if mode == SmtpTls::None && (!url.username().is_empty() || url.password().is_some()) {
        let loopback = match url.host() {
            // `smtp:` isn't a scheme the URL standard knows, so an IPv4 host stays text.
            Some(url::Host::Domain(d)) => {
                d.eq_ignore_ascii_case("localhost")
                    || d.parse::<std::net::IpAddr>()
                        .is_ok_and(|ip| ip.is_loopback())
            }
            Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
            Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
            None => false,
        };
        anyhow::ensure!(
            loopback,
            "MAIL_URL sends credentials with tls=none to a host that is not loopback: \
             use smtps:// or smtp:// (STARTTLS)"
        );
    }
    // lettre reads `smtp://` without `tls` as plaintext and doesn't know `none`.
    let rest: Vec<(String, String)> = url
        .query_pairs()
        .filter(|(k, _)| k != "tls")
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    url.set_query(None);
    if !rest.is_empty() || mode == SmtpTls::StartTls {
        let mut query = url.query_pairs_mut();
        query.extend_pairs(rest);
        if mode == SmtpTls::StartTls {
            query.append_pair("tls", "required");
        }
    }
    Ok((mode, url.into()))
}

impl Smtp {
    /// The relay `url` names, sending as `from`: `smtps://user:pass@host:465` for
    /// TLS from the start, `smtp://user:pass@host:587` for STARTTLS (required: a
    /// relay that doesn't offer it fails the delivery, so the password never travels
    /// in plaintext), and `smtp://host:1025?tls=none` for a local mail catcher (no
    /// credentials, or credentials towards a loopback host only). The URL is read as
    /// lettre reads it otherwise; `tls=opportunistic`, which falls back to
    /// plaintext, is refused, as is any other `tls` value.
    /// `timeout` bounds each exchange with the relay and the whole delivery: a relay
    /// that answers every command slowly still fails in `timeout`.
    pub fn from_url(
        url: &Sensitive<String>,
        from: Mailbox,
        timeout: Duration,
    ) -> anyhow::Result<Self> {
        let (tls, url) = tls_of(url.expose().trim())?;
        let transport = AsyncSmtpTransport::<Tokio1Executor>::from_url(&url)
            // lettre's error can quote the URL: never pass it on.
            .map_err(|_| {
                anyhow::anyhow!("MAIL_URL is not an smtp:// or smtps:// URL lettre accepts")
            })?
            .timeout(Some(timeout))
            .build();
        Ok(Self {
            from,
            transport,
            timeout,
            tls,
        })
    }

    /// How the connection to the relay is protected.
    #[must_use]
    pub fn tls(&self) -> SmtpTls {
        self.tls
    }

    /// The message as it goes on the wire.
    pub(crate) fn message(&self, email: &Email) -> Result<Message, Error> {
        let to = email.checked_recipient()?;
        let builder = Message::builder()
            .from(self.from.clone())
            .to(to)
            .subject(email.subject.clone());
        let built = match &email.html {
            Some(html) => builder.multipart(MultiPart::alternative_plain_html(
                email.text.clone(),
                html.clone(),
            )),
            None => builder.singlepart(
                SinglePart::builder()
                    .header(ContentType::TEXT_PLAIN)
                    .body(email.text.clone()),
            ),
        };
        built.map_err(|e| Error::Rejected {
            provider: "smtp",
            reason: e.to_string(),
        })
    }
}

impl Mailer for Smtp {
    fn send<'a>(&'a self, email: &'a Email) -> BoxFuture<'a, Result<(), Error>> {
        Box::pin(async move {
            let message = self.message(email)?;
            let sent = tokio::time::timeout(self.timeout, self.transport.send(message))
                .await
                .map_err(|elapsed| Error::Unreachable {
                    provider: "smtp",
                    source: Box::new(elapsed),
                })?;
            sent.map(drop).map_err(|e| {
                if e.is_permanent() || e.is_transient() {
                    Error::Rejected {
                        provider: "smtp",
                        reason: e.to_string().chars().take(300).collect(),
                    }
                } else {
                    Error::Unreachable {
                        provider: "smtp",
                        source: Box::new(e),
                    }
                }
            })
        })
    }

    fn kind(&self) -> &'static str {
        "smtp"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn smtp() -> Smtp {
        Smtp::from_url(
            &Sensitive::new("smtps://u:hunter2@smtp.example.com:465".into()),
            "Site <noreply@example.com>".parse().unwrap(),
            crate::DEFAULT_TIMEOUT,
        )
        .unwrap()
    }

    #[test]
    fn text_and_html_go_as_alternatives() {
        let wire = String::from_utf8(
            smtp()
                .message(
                    &Email::new("Ana <ana@example.com>", "Hi", "plain words")
                        .with_html("<p>rich</p>"),
                )
                .unwrap()
                .formatted(),
        )
        .unwrap();
        assert!(wire.contains("multipart/alternative"), "{wire}");
        assert!(
            wire.contains("To: Ana <ana@example.com>")
                && wire.contains("From: Site <noreply@example.com>")
        );
        assert!(wire.contains("plain words") && wire.contains("<p>rich</p>"));
        let plain = String::from_utf8(
            smtp()
                .message(&Email::new("ana@example.com", "Hi", "plain"))
                .unwrap()
                .formatted(),
        )
        .unwrap();
        assert!(plain.contains("text/plain") && !plain.contains("multipart"));
    }

    #[test]
    fn the_url_is_never_printed() {
        assert!(!format!("{:?}", smtp()).contains("hunter2"));
        let err = Smtp::from_url(
            &Sensitive::new("ftp://u:hunter2@h".into()),
            "a@b.c".parse().unwrap(),
            crate::DEFAULT_TIMEOUT,
        )
        .unwrap_err();
        assert!(!format!("{err:#}").contains("hunter2"));
    }

    #[test]
    fn lettre_gets_a_url_that_keeps_tls() {
        let lettre = |url: &str| tls_of(url).unwrap().1;
        assert_eq!(lettre("smtp://u:p@h:587"), "smtp://u:p@h:587?tls=required");
        assert_eq!(
            lettre("smtp://u:p@h:587/ehlo.example?tls=required"),
            "smtp://u:p@h:587/ehlo.example?tls=required"
        );
        assert_eq!(lettre("smtp://h:1025?tls=none"), "smtp://h:1025");
        assert_eq!(lettre("smtps://u:p%40x@h:465"), "smtps://u:p%40x@h:465");
    }
}
