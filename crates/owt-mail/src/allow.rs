//! Mail only the addresses on a list: a demo or staging deployment.

use std::sync::Arc;

use futures::future::BoxFuture;

use crate::{Email, Error, Mailer, Outbox};

/// The addresses a deployment may mail: a comma-separated list of whole addresses
/// (`ana@example.com`) and domains (`@example.com`, that domain exactly, not its
/// subdomains). Compared without regard to case.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MailAllow {
    entries: Vec<String>,
}

impl MailAllow {
    /// Parse the list (an app reads it from a variable of its choosing).
    pub fn parse(list: &str) -> anyhow::Result<Self> {
        let mut entries = Vec::new();
        for entry in list.split(',').map(str::trim).filter(|e| !e.is_empty()) {
            let entry = entry.to_ascii_lowercase();
            let bad = || anyhow::anyhow!("{entry:?} is neither an address nor @domain");
            let (local, domain) = entry.split_once('@').ok_or_else(bad)?;
            let ok = !local.contains('@')
                && !domain.contains('@')
                && domain.contains('.')
                && !domain.starts_with('.')
                && !domain.ends_with('.')
                && !entry.contains(char::is_whitespace);
            anyhow::ensure!(ok, bad());
            entries.push(entry);
        }
        Ok(Self { entries })
    }

    /// No entry: nothing may be mailed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Whether `address` (an address or `Name <address>`) is on the list.
    #[must_use]
    pub fn allows(&self, address: &str) -> bool {
        let Some(mailbox) = crate::parse_mailbox(address) else {
            return false;
        };
        let address = mailbox.email.to_string().to_ascii_lowercase();
        let domain = mailbox.email.domain().to_ascii_lowercase();
        self.entries
            .iter()
            .any(|entry| match entry.strip_prefix('@') {
                Some(allowed) => domain == allowed,
                None => address == *entry,
            })
    }
}

/// A [`Mailer`] that passes to its inner one only what [`MailAllow`] allows, and
/// fails the rest with [`Error::Refused`] (logged with the subject, never the
/// address).
pub struct Allowlisted {
    inner: Arc<dyn Mailer>,
    allow: MailAllow,
}

impl Allowlisted {
    /// `inner`, for `allow`'s addresses only.
    #[must_use]
    pub fn new(inner: Arc<dyn Mailer>, allow: MailAllow) -> Self {
        Self { inner, allow }
    }
}

impl Mailer for Allowlisted {
    fn send<'a>(&'a self, email: &'a Email) -> BoxFuture<'a, Result<(), Error>> {
        Box::pin(async move {
            email.checked_recipient()?;
            if !self.allow.allows(&email.to) {
                tracing::warn!(subject = %email.subject, "email refused: the recipient is not on the allowlist");
                return Err(Error::Refused);
            }
            self.inner.send(email).await
        })
    }

    fn kind(&self) -> &'static str {
        self.inner.kind()
    }

    fn outbox(&self) -> Option<&Outbox> {
        self.inner.outbox()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Delivery, Mail};

    #[test]
    fn the_list_takes_addresses_and_domains() {
        let allow = MailAllow::parse(" Ana@Example.com, @team.example ,").unwrap();
        assert!(allow.allows("ana@example.com"));
        assert!(allow.allows("Ana <ANA@example.COM>"));
        assert!(allow.allows("bo@team.example"));
        assert!(!allow.allows("bo@sub.team.example"));
        assert!(!allow.allows("bo@example.com"));
        assert!(!allow.allows("ana@example.com.evil.example"));
        assert!(MailAllow::parse("").unwrap().is_empty());
        for bad in ["nobody", "a@b@c.d", "@nodot", "@.example", "a b@c.d"] {
            assert!(MailAllow::parse(bad).is_err(), "{bad}");
        }
    }

    #[tokio::test]
    async fn only_listed_addresses_get_through() {
        let (mail, outbox) = Mail::outbox();
        let mail = mail.allow_only(MailAllow::parse("@team.example").unwrap());
        assert_eq!(
            mail.send(&Email::new("bo@team.example", "s", "t"))
                .await
                .unwrap(),
            Delivery::Kept
        );
        assert!(matches!(
            mail.send(&Email::new("ana@example.com", "s", "t")).await,
            Err(Error::Refused)
        ));
        assert_eq!(outbox.sent().len(), 1);
        assert!(
            !Mail::none()
                .allow_only(MailAllow::default())
                .is_configured()
        );
    }
}
