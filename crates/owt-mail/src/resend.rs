//! Resend's HTTP API.

use std::time::Duration;

use futures::future::BoxFuture;
use lettre::message::Mailbox;
use owt_runtime::logging::Sensitive;
use serde_json::json;

use crate::{Email, Error, Mailer};

/// Resend (`POST https://api.resend.com/emails`). `Debug` leaves out the key.
pub struct Resend {
    http: reqwest::Client,
    endpoint: url::Url,
    api_key: Sensitive<String>,
    from: Mailbox,
}

impl std::fmt::Debug for Resend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Resend")
            .field("from", &self.from.to_string())
            .finish_non_exhaustive()
    }
}

impl Resend {
    /// Resend with `api_key`, sending as `from` (a domain verified there), each
    /// request bounded by `timeout`.
    pub fn new(
        api_key: Sensitive<String>,
        from: Mailbox,
        timeout: Duration,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            http: crate::http_client(timeout)?,
            endpoint: crate::endpoint("https://api.resend.com", "the Resend endpoint")?,
            api_key,
            from,
        })
    }

    /// Another origin for the API: `https://`, or `http://` on loopback (a fake).
    pub fn with_endpoint(mut self, origin: &str) -> anyhow::Result<Self> {
        self.endpoint = crate::endpoint(origin, "the Resend endpoint")?;
        Ok(self)
    }
}

impl Mailer for Resend {
    fn send<'a>(&'a self, email: &'a Email) -> BoxFuture<'a, Result<(), Error>> {
        Box::pin(async move {
            let to = email.checked_recipient()?;
            let mut body = json!({
                "from": self.from.to_string(),
                "to": [to.to_string()],
                "subject": email.subject,
                "text": email.text,
            });
            if let Some(html) = &email.html {
                body["html"] = json!(html);
            }
            let unreachable = |e: reqwest::Error| Error::Unreachable {
                provider: "resend",
                source: Box::new(e.without_url()),
            };
            let response = self
                .http
                .post(self.endpoint.join("emails").expect("a relative path joins"))
                .bearer_auth(self.api_key.expose())
                .json(&body)
                .send()
                .await
                .map_err(unreachable)?;
            let status = response.status();
            if status.is_success() {
                return Ok(());
            }
            let text = response.text().await.unwrap_or_default();
            Err(Error::Rejected {
                provider: "resend",
                reason: format!("{status}: {}", crate::refusal(&text)),
            })
        })
    }

    fn kind(&self) -> &'static str {
        "resend"
    }
}
