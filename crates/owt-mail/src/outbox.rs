//! The in-memory transport, and one that always fails.

use std::sync::{Arc, Mutex, PoisonError};

use futures::future::BoxFuture;

use crate::{Email, Error, Mailer};

/// Keeps every message in memory and delivers nothing: tests, CI, a workstation.
/// Clones share one list. It logs each message's subject; [`Outbox::logging_text`]
/// logs the text too, so a sign-in link can be read from a workstation's log.
#[derive(Clone, Default)]
pub struct Outbox {
    sent: Arc<Mutex<Vec<Email>>>,
    log_text: bool,
}

impl Outbox {
    /// Also log each message's text (never in production: it carries links).
    #[must_use]
    pub fn logging_text(mut self) -> Self {
        self.log_text = true;
        self
    }

    /// Every message kept so far, oldest first.
    #[must_use]
    pub fn sent(&self) -> Vec<Email> {
        self.sent
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The last message kept for `to` (compared exactly).
    #[must_use]
    pub fn last_to(&self, to: &str) -> Option<Email> {
        self.sent().into_iter().rev().find(|e| e.to == to)
    }

    /// Forget every message kept so far.
    pub fn clear(&self) {
        self.sent
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
    }
}

impl std::fmt::Debug for Outbox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Outbox")
            .field(
                "kept",
                &self
                    .sent
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .len(),
            )
            .finish()
    }
}

impl Mailer for Outbox {
    fn send<'a>(&'a self, email: &'a Email) -> BoxFuture<'a, Result<(), Error>> {
        Box::pin(async move {
            email.checked_recipient()?;
            if self.log_text {
                tracing::info!(subject = %email.subject, text = %email.text, "email kept in the outbox, not sent");
            } else {
                tracing::info!(subject = %email.subject, "email kept in the outbox, not sent");
            }
            self.sent
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(email.clone());
            Ok(())
        })
    }

    fn kind(&self) -> &'static str {
        "outbox"
    }

    fn outbox(&self) -> Option<&Outbox> {
        Some(self)
    }
}

/// Refuses every message, as a provider does with an unverified sender: for tests of
/// what a caller does when mail fails.
#[derive(Clone, Copy, Debug, Default)]
pub struct Failing;

impl Mailer for Failing {
    fn send<'a>(&'a self, _email: &'a Email) -> BoxFuture<'a, Result<(), Error>> {
        Box::pin(async {
            Err(Error::Rejected {
                provider: "test",
                reason: "the sender domain is not verified".into(),
            })
        })
    }

    fn kind(&self) -> &'static str {
        "failing"
    }
}

/// The first `http…` URL in `text`, up to whitespace: the link a sign-in or
/// invitation message carries, for a test to follow.
#[must_use]
pub fn first_link(text: &str) -> Option<&str> {
    let start = text.find("http")?;
    let rest = &text[start..];
    Some(rest.split_whitespace().next().unwrap_or(rest))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Mail;

    #[tokio::test]
    async fn the_outbox_keeps_messages_and_finds_the_link() {
        let (mail, outbox) = Mail::outbox();
        let first = Email::new("a@example.com", "One", "Sign in: https://x.example/l/1 now");
        let second = Email::new("a@example.com", "Two", "Sign in: https://x.example/l/2");
        let _ = mail.send(&first).await.unwrap();
        let _ = mail.send(&second).await.unwrap();
        assert_eq!(outbox.last_to("a@example.com").as_ref(), Some(&second));
        assert_eq!(first_link(&first.text), Some("https://x.example/l/1"));
        assert_eq!(first_link("none"), None);
        outbox.clear();
        assert!(mail.sent().is_empty());
    }

    #[tokio::test]
    async fn failing_fails() {
        let mail = Mail::new(Failing);
        let err = mail
            .send(&Email::new("a@example.com", "s", "t"))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("not verified"));
        assert!(mail.delivers());
    }
}
