//! AWS SES's v2 `SendEmail`, signed with Signature Version 4.

use std::fmt::Write as _;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures::future::BoxFuture;
use hmac::{Hmac, KeyInit, Mac};
use lettre::message::Mailbox;
use owt_runtime::logging::Sensitive;
use sha2::{Digest, Sha256};

use crate::{Email, Error, Mailer};

const PATH: &str = "/v2/email/outbound-emails";

/// SES in one region. `Debug` leaves out the credentials.
pub struct Ses {
    http: reqwest::Client,
    endpoint: url::Url,
    region: String,
    from: Mailbox,
    access_key: String,
    secret_key: Sensitive<String>,
    session_token: Option<Sensitive<String>>,
}

impl std::fmt::Debug for Ses {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ses")
            .field("region", &self.region)
            .field("from", &self.from.to_string())
            .finish_non_exhaustive()
    }
}

impl Ses {
    /// SES in `region` (`us-east-1`), sending as `from` (an identity verified
    /// there), each request bounded by `timeout`.
    pub fn new(
        region: &str,
        from: Mailbox,
        access_key: String,
        secret_key: Sensitive<String>,
        session_token: Option<Sensitive<String>>,
        timeout: Duration,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            !region.is_empty()
                && region
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
            "SES_REGION is an AWS region name"
        );
        Ok(Self {
            http: crate::http_client(timeout)?,
            endpoint: crate::endpoint(
                &format!("https://email.{region}.amazonaws.com"),
                "the SES endpoint",
            )?,
            region: region.to_owned(),
            from,
            access_key,
            secret_key,
            session_token,
        })
    }

    /// Another origin for the API (`SES_ENDPOINT`): `https://`, or `http://` on
    /// loopback (a fake).
    pub fn with_endpoint(mut self, origin: &str) -> anyhow::Result<Self> {
        self.endpoint = crate::endpoint(origin, "SES_ENDPOINT")?;
        Ok(self)
    }

    fn host(&self) -> String {
        let host = self.endpoint.host_str().unwrap_or_default();
        match self.endpoint.port() {
            Some(port) => format!("{host}:{port}"),
            None => host.to_owned(),
        }
    }
}

impl Mailer for Ses {
    fn send<'a>(&'a self, email: &'a Email) -> BoxFuture<'a, Result<(), Error>> {
        Box::pin(async move {
            let to = email.checked_recipient()?;
            let mut content = serde_json::json!({
                "Subject": { "Data": email.subject, "Charset": "UTF-8" },
                "Body": { "Text": { "Data": email.text, "Charset": "UTF-8" } },
            });
            if let Some(html) = &email.html {
                content["Body"]["Html"] = serde_json::json!({ "Data": html, "Charset": "UTF-8" });
            }
            let body = serde_json::json!({
                "FromEmailAddress": self.from.to_string(),
                "Destination": { "ToAddresses": [to.to_string()] },
                "Content": { "Simple": content },
            })
            .to_string();
            let amz_date = amz_date(SystemTime::now());
            let mut headers = vec![
                ("content-type".to_owned(), "application/json".to_owned()),
                ("host".to_owned(), self.host()),
                ("x-amz-date".to_owned(), amz_date.clone()),
            ];
            if let Some(token) = &self.session_token {
                headers.push(("x-amz-security-token".to_owned(), token.expose().clone()));
            }
            let credentials = Credentials {
                access_key: &self.access_key,
                secret_key: self.secret_key.expose(),
                region: &self.region,
                service: "ses",
            };
            let authorization = authorization(
                &credentials,
                "POST",
                PATH,
                &headers,
                body.as_bytes(),
                &amz_date,
            );
            let mut request = self
                .http
                .post(self.endpoint.join(PATH).expect("an absolute path joins"))
                .header("authorization", authorization)
                .body(body);
            for (name, value) in headers.iter().filter(|(n, _)| n != "host") {
                request = request.header(name.as_str(), value.as_str());
            }
            let response = request.send().await.map_err(|e| Error::Unreachable {
                provider: "ses",
                source: Box::new(e.without_url()),
            })?;
            let status = response.status();
            if status.is_success() {
                return Ok(());
            }
            let text = response.text().await.unwrap_or_default();
            Err(Error::Rejected {
                provider: "ses",
                reason: format!("{status}: {}", crate::refusal(&text)),
            })
        })
    }

    fn kind(&self) -> &'static str {
        "ses"
    }
}

/// What Signature Version 4 signs with.
struct Credentials<'a> {
    access_key: &'a str,
    secret_key: &'a str,
    region: &'a str,
    service: &'a str,
}

/// `YYYYMMDDTHHMMSSZ` in UTC.
fn amz_date(t: SystemTime) -> String {
    let secs = t.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let days = i64::try_from(secs / 86_400).unwrap_or(0);
    let rem = secs % 86_400;
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}{m:02}{d:02}T{:02}{:02}{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// The proleptic Gregorian date `days` after 1970-01-01 (Howard Hinnant's
/// `civil_from_days`).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = u32::try_from(doy - (153 * mp + 2) / 5 + 1).unwrap_or(1);
    let m = u32::try_from(if mp < 10 { mp + 3 } else { mp - 9 }).unwrap_or(1);
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC takes a key of any length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

/// The signing key for `date` (`YYYYMMDD`).
fn signing_key(c: &Credentials<'_>, date: &str) -> Vec<u8> {
    let k_date = hmac(format!("AWS4{}", c.secret_key).as_bytes(), date.as_bytes());
    let k_region = hmac(&k_date, c.region.as_bytes());
    let k_service = hmac(&k_region, c.service.as_bytes());
    hmac(&k_service, b"aws4_request")
}

/// The `Authorization` header of a request with no query string, whose `headers`
/// (lower-case names) are every header signed.
fn authorization(
    c: &Credentials<'_>,
    method: &str,
    path: &str,
    headers: &[(String, String)],
    payload: &[u8],
    amz_date: &str,
) -> String {
    let mut sorted: Vec<&(String, String)> = headers.iter().collect();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    let canonical_headers = sorted.iter().fold(String::new(), |mut out, (n, v)| {
        let _ = writeln!(out, "{n}:{}", v.trim());
        out
    });
    let signed_headers = sorted
        .iter()
        .map(|(n, _)| n.as_str())
        .collect::<Vec<_>>()
        .join(";");
    let canonical = format!(
        "{method}\n{path}\n\n{canonical_headers}\n{signed_headers}\n{}",
        sha256_hex(payload)
    );
    let date = &amz_date[..8];
    let scope = format!("{date}/{}/{}/aws4_request", c.region, c.service);
    let to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        sha256_hex(canonical.as_bytes())
    );
    let signature = hex::encode(hmac(&signing_key(c, date), to_sign.as_bytes()));
    format!(
        "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={signature}",
        c.access_key
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";

    #[test]
    fn the_signing_key_matches_awss_published_example() {
        let c = Credentials {
            access_key: "AKIDEXAMPLE",
            secret_key: SECRET,
            region: "us-east-1",
            service: "iam",
        };
        assert_eq!(
            hex::encode(signing_key(&c, "20120215")),
            "f4780e2d9f65fa895f9c67b32ce1baf0b0d8a43505a000a1a9e090d414db404d"
        );
    }

    #[test]
    fn a_signature_matches_the_sigv4_test_suites_get_vanilla() {
        let c = Credentials {
            access_key: "AKIDEXAMPLE",
            secret_key: SECRET,
            region: "us-east-1",
            service: "service",
        };
        let headers = vec![
            ("host".to_owned(), "example.amazonaws.com".to_owned()),
            ("x-amz-date".to_owned(), "20150830T123600Z".to_owned()),
        ];
        assert_eq!(
            authorization(&c, "GET", "/", &headers, b"", "20150830T123600Z"),
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, \
             SignedHeaders=host;x-amz-date, \
             Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
        );
    }

    #[test]
    fn dates_are_utc_calendar_dates() {
        assert_eq!(amz_date(UNIX_EPOCH), "19700101T000000Z");
        assert_eq!(
            amz_date(UNIX_EPOCH + Duration::from_mins(24_015_636)),
            "20150830T123600Z"
        );
        assert_eq!(
            amz_date(UNIX_EPOCH + Duration::from_hours(264_384)),
            "20000229T000000Z"
        );
    }

    #[test]
    fn regions_and_endpoints_are_checked() {
        let ses = |region: &str| {
            Ses::new(
                region,
                "a@example.com".parse().unwrap(),
                "AKID".into(),
                Sensitive::new("s".into()),
                None,
                crate::DEFAULT_TIMEOUT,
            )
        };
        assert!(ses("us-east-1").is_ok());
        assert!(ses("US East").is_err());
        assert!(
            ses("us-east-1")
                .unwrap()
                .with_endpoint("http://email.example")
                .is_err()
        );
        assert!(!format!("{:?}", ses("us-east-1").unwrap()).contains("AKID"));
    }
}
