//! An [`Anchor`] in an S3 bucket under an Object Lock retention.
//!
//! Each manifest is PUT with `x-amz-object-lock-mode: COMPLIANCE` and a
//! `retain-until` date; until it passes, no credential, the account's root included,
//! can overwrite, delete or shorten the object. The requests are signed here (AWS
//! Signature Version 4, path-style) because the object-store crates do not send
//! the lock headers. The signer is checked against AWS's published examples.

use std::fmt::Write as _;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, bail};
use base64::Engine as _;
use hmac::{Hmac, KeyInit, Mac};
use md5::Md5;
use sha2::{Digest, Sha256};

use super::Anchor;

type HmacSha256 = Hmac<Sha256>;

/// Where and as whom [`S3ObjectLock`] writes.
#[derive(Clone)]
pub struct S3Config {
    /// The endpoint's origin, such as `https://s3.us-west-004.backblazeb2.com`.
    /// Requests are path-style: `<endpoint>/<bucket>/<key>`.
    pub endpoint: String,
    /// The bucket, created with Object Lock enabled.
    pub bucket: String,
    /// The signing region, such as `us-west-004`.
    pub region: String,
    /// The access key id.
    pub access_key: String,
    /// The secret access key.
    pub secret_key: String,
    /// How long each manifest stays locked, counted from its upload.
    pub retention: Duration,
}

impl std::fmt::Debug for S3Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3Config")
            .field("endpoint", &self.endpoint)
            .field("bucket", &self.bucket)
            .field("region", &self.region)
            .field("access_key", &self.access_key)
            .field("secret_key", &"<redacted>")
            .field("retention", &self.retention)
            .finish()
    }
}

/// Anchors manifests as COMPLIANCE-mode locked objects in an S3 bucket.
#[derive(Clone, Debug)]
pub struct S3ObjectLock {
    config: S3Config,
    http: reqwest::Client,
}

/// A signed request, before it is sent.
#[derive(Debug, PartialEq, Eq)]
struct Prepared {
    url: String,
    headers: Vec<(String, String)>,
}

impl S3ObjectLock {
    /// An anchor for `config`.
    pub fn new(config: S3Config) -> anyhow::Result<Self> {
        if !(config.endpoint.starts_with("https://") || config.endpoint.starts_with("http://")) {
            bail!("the S3 endpoint must be an http(s) origin");
        }
        if config.bucket.is_empty() || config.bucket.contains('/') {
            bail!("the S3 bucket name is empty or contains a slash");
        }
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()?;
        Ok(Self { config, http })
    }

    /// Start-up check: fails unless the bucket has Object Lock enabled. A bucket
    /// without it would accept manifests that can then be deleted.
    pub async fn verify_bucket(&self) -> anyhow::Result<()> {
        let req = self.prepare("GET", "", "object-lock=", &[], b"", SystemTime::now());
        let resp = self.send(&req, "GET", Vec::new()).await?;
        let status = resp.status();
        let body = resp.text().await?;
        if !status.is_success() {
            bail!(
                "the bucket {:?} has no Object Lock configuration ({status}): create it with Object Lock enabled",
                self.config.bucket
            );
        }
        if !body.contains("<ObjectLockEnabled>Enabled</ObjectLockEnabled>") {
            bail!(
                "Object Lock is not enabled on the bucket {:?}",
                self.config.bucket
            );
        }
        Ok(())
    }

    /// Read a stored manifest back, for `audit verify --manifest`.
    pub async fn fetch(&self, key: &str) -> anyhow::Result<Vec<u8>> {
        let req = self.prepare("GET", key, "", &[], b"", SystemTime::now());
        let resp = self.send(&req, "GET", Vec::new()).await?;
        let status = resp.status();
        if !status.is_success() {
            bail!("reading {key:?} from the anchor bucket failed: {status}");
        }
        Ok(resp.bytes().await?.to_vec())
    }

    /// The signed PUT of `bytes` under `key`, as of `now`.
    fn prepare_put(&self, key: &str, bytes: &[u8], now: SystemTime) -> Prepared {
        let until = now + self.config.retention;
        let extra = [
            (
                "content-md5",
                base64::engine::general_purpose::STANDARD.encode(Md5::digest(bytes)),
            ),
            ("if-none-match", "*".to_owned()),
            ("x-amz-object-lock-mode", "COMPLIANCE".to_owned()),
            ("x-amz-object-lock-retain-until-date", iso8601(until)),
        ];
        self.prepare("PUT", key, "", &extra, bytes, now)
    }

    fn prepare(
        &self,
        method: &str,
        key: &str,
        query: &str,
        extra: &[(&str, String)],
        body: &[u8],
        now: SystemTime,
    ) -> Prepared {
        let c = &self.config;
        let origin = c.endpoint.trim_end_matches('/');
        let host = origin.split_once("://").map_or(origin, |(_, h)| h);
        let path = if key.is_empty() {
            format!("/{}", c.bucket)
        } else {
            format!("/{}/{}", c.bucket, key)
        };
        let amz_date = amz_date(now);
        let payload = hex(&Sha256::digest(body));
        let mut headers: Vec<(String, String)> = vec![
            ("host".into(), host.into()),
            ("x-amz-content-sha256".into(), payload.clone()),
            ("x-amz-date".into(), amz_date.clone()),
        ];
        headers.extend(extra.iter().map(|(k, v)| ((*k).to_owned(), v.clone())));
        headers.sort();
        let authorization = authorization(
            &Creds {
                access_key: &c.access_key,
                secret_key: &c.secret_key,
                region: &c.region,
            },
            method,
            &encode_path(&path),
            query,
            &headers,
            &payload,
            &amz_date,
        );
        headers.push(("authorization".into(), authorization));
        let url = if query.is_empty() {
            format!("{origin}{}", encode_path(&path))
        } else {
            format!("{origin}{}?{query}", encode_path(&path))
        };
        Prepared { url, headers }
    }

    async fn send(
        &self,
        req: &Prepared,
        method: &str,
        body: Vec<u8>,
    ) -> anyhow::Result<reqwest::Response> {
        let mut b = self.http.request(method.parse()?, &req.url);
        for (k, v) in &req.headers {
            // `host` is derived from the URL, which is the value that was signed.
            if k != "host" {
                b = b.header(k, v);
            }
        }
        if method == "PUT" {
            b = b.body(body);
        }
        b.send().await.context("the S3 request failed")
    }
}

impl Anchor for S3ObjectLock {
    fn name(&self) -> &'static str {
        "s3-object-lock"
    }

    /// PUT the manifest locked until now plus the configured retention, refusing to
    /// replace an existing object. The receipt is the object's version id, or its
    /// `ETag` where the store does not version.
    async fn put(&self, key: &str, bytes: &[u8]) -> anyhow::Result<String> {
        let req = self.prepare_put(key, bytes, SystemTime::now());
        let resp = self.send(&req, "PUT", bytes.to_vec()).await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            bail!(
                "anchoring {key:?} failed: {status}: {}",
                body.chars().take(300).collect::<String>()
            );
        }
        let h = resp.headers();
        let header = |n: &str| {
            h.get(n)
                .and_then(|v| v.to_str().ok())
                .map(|v| v.trim_matches('"').to_owned())
        };
        header("x-amz-version-id")
            .or_else(|| header("etag"))
            .context("the store returned neither a version id nor an ETag")
    }
}

struct Creds<'a> {
    access_key: &'a str,
    secret_key: &'a str,
    region: &'a str,
}

/// The `Authorization` header value. `headers` are lowercase names, sorted, and all
/// signed. `path` is already percent-encoded.
fn authorization(
    creds: &Creds<'_>,
    method: &str,
    path: &str,
    query: &str,
    headers: &[(String, String)],
    payload_hash: &str,
    amz_date: &str,
) -> String {
    let signed = headers
        .iter()
        .map(|(k, _)| k.as_str())
        .collect::<Vec<_>>()
        .join(";");
    let canonical_headers = headers.iter().fold(String::new(), |mut out, (k, v)| {
        let _ = writeln!(out, "{k}:{}", v.trim());
        out
    });
    let canonical =
        format!("{method}\n{path}\n{query}\n{canonical_headers}\n{signed}\n{payload_hash}");
    let day = &amz_date[..8];
    let scope = format!("{day}/{}/s3/aws4_request", creds.region);
    let to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        hex(&Sha256::digest(canonical.as_bytes()))
    );
    let k = hmac(
        format!("AWS4{}", creds.secret_key).as_bytes(),
        day.as_bytes(),
    );
    let k = hmac(&k, creds.region.as_bytes());
    let k = hmac(&k, b"s3");
    let k = hmac(&k, b"aws4_request");
    let signature = hex(&hmac(&k, to_sign.as_bytes()));
    format!(
        "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed}, Signature={signature}",
        creds.access_key
    )
}

fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut m = HmacSha256::new_from_slice(key).expect("HMAC accepts keys of any length");
    m.update(data);
    m.finalize().into_bytes().to_vec()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// Percent-encode each byte but unreserved characters and `/`, as `SigV4` does for S3.
fn encode_path(path: &str) -> String {
    path.bytes().fold(String::new(), |mut s, b| {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~' | b'/') {
            s.push(char::from(b));
        } else {
            let _ = write!(s, "%{b:02X}");
        }
        s
    })
}

/// A UTC date and time of day.
struct Civil {
    year: i64,
    month: u32,
    day: u32,
    hour: u64,
    minute: u64,
    second: u64,
}

fn civil(t: SystemTime) -> Civil {
    let secs = t.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let days = i64::try_from(secs / 86_400).unwrap_or(0) + 719_468;
    let era = days.div_euclid(146_097);
    let doe = days.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = u32::try_from(doy - (153 * mp + 2) / 5 + 1).unwrap_or(1);
    let month = u32::try_from(if mp < 10 { mp + 3 } else { mp - 9 }).unwrap_or(1);
    let rem = secs % 86_400;
    Civil {
        year: yoe + era * 400 + i64::from(month <= 2),
        month,
        day,
        hour: rem / 3_600,
        minute: rem % 3_600 / 60,
        second: rem % 60,
    }
}

/// `20130524T000000Z`.
fn amz_date(t: SystemTime) -> String {
    let c = civil(t);
    format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
        c.year, c.month, c.day, c.hour, c.minute, c.second
    )
}

/// `2013-05-24T00:00:00Z`, the retain-until format.
fn iso8601(t: SystemTime) -> String {
    let c = civil(t);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        c.year, c.month, c.day, c.hour, c.minute, c.second
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const AK: &str = "AKIAIOSFODNN7EXAMPLE";
    const SK: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

    fn at(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }

    fn h(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).into(), (*v).into()))
            .collect()
    }

    fn anchor() -> S3ObjectLock {
        S3ObjectLock::new(S3Config {
            endpoint: "http://127.0.0.1:9000".into(),
            bucket: "audit".into(),
            region: "us-east-1".into(),
            access_key: AK.into(),
            secret_key: SK.into(),
            retention: Duration::from_hours(7 * 365 * 24),
        })
        .unwrap()
    }

    fn header<'a>(p: &'a Prepared, name: &str) -> &'a str {
        p.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
            .unwrap()
    }

    #[test]
    fn matches_the_published_get_example() {
        // AWS docs, "Example: GET Object" (Range header).
        let creds = Creds {
            access_key: AK,
            secret_key: SK,
            region: "us-east-1",
        };
        let headers = h(&[
            ("host", "examplebucket.s3.amazonaws.com"),
            ("range", "bytes=0-9"),
            (
                "x-amz-content-sha256",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            ("x-amz-date", "20130524T000000Z"),
        ]);
        let a = authorization(
            &creds,
            "GET",
            "/test.txt",
            "",
            &headers,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "20130524T000000Z",
        );
        assert!(
            a.ends_with(
                "Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
            ),
            "{a}"
        );
    }

    #[test]
    fn matches_the_published_put_example() {
        // AWS docs, "Example: PUT Object".
        let creds = Creds {
            access_key: AK,
            secret_key: SK,
            region: "us-east-1",
        };
        let payload = hex(&Sha256::digest(b"Welcome to Amazon S3."));
        assert_eq!(
            payload,
            "44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072"
        );
        let headers = h(&[
            ("date", "Fri, 24 May 2013 00:00:00 GMT"),
            ("host", "examplebucket.s3.amazonaws.com"),
            ("x-amz-content-sha256", &payload),
            ("x-amz-date", "20130524T000000Z"),
            ("x-amz-storage-class", "REDUCED_REDUNDANCY"),
        ]);
        let a = authorization(
            &creds,
            "PUT",
            &encode_path("/test$file.text"),
            "",
            &headers,
            &payload,
            "20130524T000000Z",
        );
        assert!(
            a.ends_with(
                "Signature=98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd"
            ),
            "{a}"
        );
    }

    #[test]
    fn formats_dates() {
        assert_eq!(amz_date(at(1_369_353_600)), "20130524T000000Z");
        assert_eq!(iso8601(at(1_369_353_600)), "2013-05-24T00:00:00Z");
        // A leap day.
        assert_eq!(iso8601(at(1_709_208_000)), "2024-02-29T12:00:00Z");
    }

    #[test]
    fn a_put_carries_the_lock_headers() {
        let now = at(1_369_353_600);
        let p = anchor().prepare_put("owt-audit/0001-ab.json", b"{}", now);
        assert_eq!(p.url, "http://127.0.0.1:9000/audit/owt-audit/0001-ab.json");
        assert_eq!(header(&p, "x-amz-object-lock-mode"), "COMPLIANCE");
        // 7 * 365 days after 2013-05-24.
        assert_eq!(
            header(&p, "x-amz-object-lock-retain-until-date"),
            "2020-05-22T00:00:00Z"
        );
        assert_eq!(header(&p, "if-none-match"), "*");
        // MD5 of "{}", base64.
        assert_eq!(header(&p, "content-md5"), "mZFLkyvTelC5g8XnyQrpOw==");
        assert_eq!(
            header(&p, "x-amz-content-sha256"),
            hex(&Sha256::digest(b"{}"))
        );
        let auth = header(&p, "authorization");
        assert!(auth.contains(
            "SignedHeaders=content-md5;host;if-none-match;x-amz-content-sha256;x-amz-date;x-amz-object-lock-mode;x-amz-object-lock-retain-until-date,"
        ), "{auth}");
        assert!(auth.starts_with(&format!(
            "AWS4-HMAC-SHA256 Credential={AK}/20130524/us-east-1/s3/aws4_request"
        )));
    }

    #[test]
    fn the_bucket_check_signs_the_object_lock_subresource() {
        let p = anchor().prepare("GET", "", "object-lock=", &[], b"", at(1_369_353_600));
        assert_eq!(p.url, "http://127.0.0.1:9000/audit?object-lock=");
    }

    #[test]
    fn rejects_bad_configuration() {
        let mut c = anchor().config;
        c.endpoint = "s3.example.com".into();
        assert!(S3ObjectLock::new(c.clone()).is_err());
        c.endpoint = "https://s3.example.com".into();
        c.bucket = "a/b".into();
        assert!(S3ObjectLock::new(c).is_err());
    }

    #[test]
    fn debug_hides_the_secret() {
        assert!(!format!("{:?}", anchor()).contains(SK));
    }
}
