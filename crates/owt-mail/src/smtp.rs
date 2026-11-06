//! SMTP through lettre.

use std::time::Duration;

use futures::future::BoxFuture;
use lettre::message::{Mailbox, MultiPart, SinglePart, header::ContentType};
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use owt_runtime::logging::Sensitive;

use crate::{Email, Error, Mailer};

/// Any provider's SMTP relay. The URL carries the relay's credentials and is never
/// kept or printed; `Debug` shows the sender only.
pub struct Smtp {
    from: Mailbox,
    transport: AsyncSmtpTransport<Tokio1Executor>,
}

impl std::fmt::Debug for Smtp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Smtp")
            .field("from", &self.from.to_string())
            .finish_non_exhaustive()
    }
}

impl Smtp {
    /// The relay `url` names (`smtp://user:pass@host:587` for STARTTLS,
    /// `smtps://user:pass@host:465` for TLS, as lettre reads it), sending as `from`,
    /// each exchange bounded by `timeout`.
    pub fn from_url(
        url: &Sensitive<String>,
        from: Mailbox,
        timeout: Duration,
    ) -> anyhow::Result<Self> {
        let transport = AsyncSmtpTransport::<Tokio1Executor>::from_url(url.expose().trim())
            // lettre's error can quote the URL: never pass it on.
            .map_err(|_| {
                anyhow::anyhow!("MAIL_URL is not an smtp:// or smtps:// URL lettre accepts")
            })?
            .timeout(Some(timeout))
            .build();
        Ok(Self { from, transport })
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
            self.transport.send(message).await.map(drop).map_err(|e| {
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
}
