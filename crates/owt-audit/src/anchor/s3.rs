//! An [`Anchor`] in an S3 bucket under an Object Lock retention.
//!
//! Each manifest is PUT with `x-amz-object-lock-mode: COMPLIANCE` and a
//! `retain-until` date; until it passes, no credential, the account's root included,
//! can overwrite, delete or shorten the object. The requests are signed here (AWS
//! Signature Version 4, path-style) because the object-store crates do not send
//! the lock headers. The signer is checked against AWS's published examples.
//!
//! A PUT's response does not say whether the lock took effect, and a store may
//! ignore the headers, so [`S3ObjectLock::put`] reads the stored version's retention
//! back and fails unless it is COMPLIANCE and runs at least until the requested
//! date. The first `put` also runs [`S3ObjectLock::verify_bucket`].
//!
//! The retain-until date is computed from the local clock. A host clock set back
//! shortens the lock, so every response's `Date` header is compared with it and a
//! drift over five minutes fails the request.

use std::fmt::Write as _;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, bail};
use base64::Engine as _;
use hmac::{Hmac, KeyInit, Mac};
use md5::Md5;
use reqwest::Url;
use sha2::{Digest, Sha256};
use tokio::sync::OnceCell;
use zeroize::Zeroizing;

use super::Anchor;

type HmacSha256 = Hmac<Sha256>;

/// The largest manifest `fetch` accepts.
const MAX_MANIFEST: usize = 16 * 1024 * 1024;
/// The largest bucket or retention document read.
const MAX_DOCUMENT: usize = 64 * 1024;
/// The most of an error body that is read.
const MAX_ERROR: usize = 4 * 1024;
/// The clock drift between this host and the store that is tolerated.
const MAX_DRIFT: Duration = Duration::from_mins(5);
/// The shortest and longest retention accepted.
const MIN_RETENTION: Duration = Duration::from_hours(24);
const MAX_RETENTION: Duration = Duration::from_hours(100 * 365 * 24);

/// Where and as whom [`S3ObjectLock`] writes.
#[derive(Clone)]
pub struct S3Config {
    /// The endpoint's origin, such as `https://s3.us-west-004.backblazeb2.com`: a
    /// scheme, a host and an optional port, with no path, userinfo or query.
    /// Requests are path-style: `<endpoint>/<bucket>/<key>`. It must be `https://`,
    /// unless the host is a loopback IP literal or `allow_insecure_http` is set.
    pub endpoint: String,
    /// Permit a plain `http://` endpoint on a host that is not a loopback IP
    /// literal. For a `MinIO` inside the cluster's own network only: the manifest,
    /// the access key id and the signed request cross the wire in clear.
    pub allow_insecure_http: bool,
    /// The bucket, created with Object Lock enabled.
    pub bucket: String,
    /// The signing region, such as `us-west-004`.
    pub region: String,
    /// The access key id.
    pub access_key: String,
    /// The secret access key, wiped from memory when dropped.
    pub secret_key: Zeroizing<String>,
    /// How long each manifest stays locked, counted from its upload on this host's
    /// clock: at least one day, at most 100 years.
    pub retention: Duration,
}

impl std::fmt::Debug for S3Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3Config")
            .field("endpoint", &self.endpoint)
            .field("allow_insecure_http", &self.allow_insecure_http)
            .field("bucket", &self.bucket)
            .field("region", &self.region)
            .field("access_key", &self.access_key)
            .field("secret_key", &"<redacted>")
            .field("retention", &self.retention)
            .finish()
    }
}

/// Anchors manifests as COMPLIANCE-mode locked objects in an S3 bucket.
#[derive(Clone)]
pub struct S3ObjectLock {
    config: S3Config,
    /// `scheme://host[:port]`, the origin requests are sent to.
    origin: String,
    /// The `Host` header value: the lowercased host, and the port when not the
    /// scheme's default.
    host: String,
    http: reqwest::Client,
    verified: Arc<OnceCell<()>>,
}

impl std::fmt::Debug for S3ObjectLock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3ObjectLock")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

/// A signed request, before it is sent.
#[derive(Debug, PartialEq, Eq)]
struct Prepared {
    url: Url,
    headers: Vec<(String, String)>,
}

impl S3ObjectLock {
    /// An anchor for `config`.
    pub fn new(config: S3Config) -> anyhow::Result<Self> {
        let url = Url::parse(&config.endpoint).context("the S3 endpoint is not a URL")?;
        if !matches!(url.scheme(), "http" | "https") {
            bail!("the S3 endpoint must be an http(s) origin");
        }
        if !url.username().is_empty() || url.password().is_some() {
            bail!("the S3 endpoint must not carry userinfo");
        }
        if !matches!(url.path(), "" | "/") || url.query().is_some() || url.fragment().is_some() {
            bail!("the S3 endpoint must be an origin: no path, query or fragment");
        }
        let host = url
            .host_str()
            .context("the S3 endpoint has no host")?
            .to_ascii_lowercase();
        if url.scheme() == "http" && !config.allow_insecure_http && !is_loopback(&host) {
            bail!(
                "the S3 endpoint is http:// on a host that is not a loopback address: use https://, or set allow_insecure_http for an in-cluster MinIO"
            );
        }
        let host = match url.port() {
            Some(port) => format!("{host}:{port}"),
            None => host,
        };
        let origin = format!("{}://{host}", url.scheme());
        if config.bucket.is_empty()
            || config.bucket.contains('/')
            || matches!(config.bucket.as_str(), "." | "..")
        {
            bail!("the S3 bucket name is empty, a dot segment or contains a slash");
        }
        if config.retention < MIN_RETENTION || config.retention > MAX_RETENTION {
            bail!("the retention must be between one day and 100 years");
        }
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        Ok(Self {
            config,
            origin,
            host,
            http,
            verified: Arc::new(OnceCell::new()),
        })
    }

    /// Start-up check: fails unless the bucket has Object Lock enabled. A bucket
    /// without it would accept manifests that can then be deleted. Object Lock
    /// implies versioning, so versioning is not checked separately. `put` runs this
    /// once before its first upload.
    pub async fn verify_bucket(&self) -> anyhow::Result<()> {
        let req = self.prepare(
            "GET",
            "",
            &[("object-lock", "")],
            &[],
            b"",
            SystemTime::now(),
        )?;
        let resp = self.send(&req, "GET", Vec::new()).await?;
        let status = resp.status();
        if !status.is_success() {
            let detail = error_detail(resp).await;
            if status == reqwest::StatusCode::NOT_FOUND
                || detail.contains("ObjectLockConfigurationNotFoundError")
            {
                bail!(
                    "the bucket {:?} has no Object Lock configuration ({detail}): create it with Object Lock enabled",
                    self.config.bucket
                );
            }
            bail!(
                "reading the Object Lock configuration of the bucket {:?} failed: {detail}",
                self.config.bucket
            );
        }
        let body = String::from_utf8_lossy(&read_capped(resp, MAX_DOCUMENT).await?).into_owned();
        if xml_text(&body, "ObjectLockEnabled") != Some("Enabled") {
            bail!(
                "Object Lock is not enabled on the bucket {:?}",
                self.config.bucket
            );
        }
        Ok(())
    }

    /// Read a stored manifest back, for `audit verify --manifest`. Pass the receipt
    /// `put` returned as `version_id`: without it the latest version is read, which
    /// a credential able to write the key again could have replaced.
    pub async fn fetch(&self, key: &str, version_id: Option<&str>) -> anyhow::Result<Vec<u8>> {
        validate_key(key)?;
        let query: Vec<(&str, &str)> = version_id.map(|v| ("versionId", v)).into_iter().collect();
        let req = self.prepare("GET", key, &query, &[], b"", SystemTime::now())?;
        let resp = self.send(&req, "GET", Vec::new()).await?;
        let status = resp.status();
        if !status.is_success() {
            bail!(
                "reading {key:?} from the anchor bucket failed: {}",
                error_detail(resp).await
            );
        }
        read_capped(resp, MAX_MANIFEST).await
    }

    /// The signed PUT of `bytes` under `key`, as of `now`.
    fn prepare_put(&self, key: &str, bytes: &[u8], now: SystemTime) -> anyhow::Result<Prepared> {
        validate_key(key)?;
        let until = now
            .checked_add(self.config.retention)
            .context("the retention overflows the clock")?;
        let extra = [
            (
                "content-md5",
                base64::engine::general_purpose::STANDARD.encode(Md5::digest(bytes)),
            ),
            ("if-none-match", "*".to_owned()),
            ("x-amz-object-lock-mode", "COMPLIANCE".to_owned()),
            ("x-amz-object-lock-retain-until-date", iso8601(until)),
        ];
        self.prepare("PUT", key, &[], &extra, bytes, now)
    }

    /// Sign a request. The URL is built from the same host and path that are
    /// signed, and checked against them once parsed.
    fn prepare(
        &self,
        method: &str,
        key: &str,
        query: &[(&str, &str)],
        extra: &[(&str, String)],
        body: &[u8],
        now: SystemTime,
    ) -> anyhow::Result<Prepared> {
        let c = &self.config;
        let path = encode_path(&if key.is_empty() {
            format!("/{}", c.bucket)
        } else {
            format!("/{}/{}", c.bucket, key)
        });
        let query = canonical_query(query);
        let full = if query.is_empty() {
            format!("{}{path}", self.origin)
        } else {
            format!("{}{path}?{query}", self.origin)
        };
        let url = Url::parse(&full).context("the request URL is malformed")?;
        let sent_host = match url.port() {
            Some(port) => format!("{}:{port}", url.host_str().unwrap_or_default()),
            None => url.host_str().unwrap_or_default().to_owned(),
        };
        if url.path() != path || sent_host != self.host || url.query().unwrap_or("") != query {
            bail!("the request URL does not match what is signed");
        }
        let amz_date = amz_date(now);
        let payload = hex(&Sha256::digest(body));
        let mut headers: Vec<(String, String)> = vec![
            ("host".into(), self.host.clone()),
            ("x-amz-content-sha256".into(), payload.clone()),
            ("x-amz-date".into(), amz_date.clone()),
        ];
        headers.extend(extra.iter().map(|(k, v)| ((*k).to_owned(), v.clone())));
        headers.sort();
        let signing = signing_key(&c.secret_key, &amz_date[..8], &c.region);
        let authorization = authorization(
            &Creds {
                access_key: &c.access_key,
                signing_key: &signing,
                region: &c.region,
            },
            method,
            &path,
            &query,
            &headers,
            &payload,
            &amz_date,
        );
        headers.push(("authorization".into(), authorization));
        Ok(Prepared { url, headers })
    }

    /// Send a signed request. A redirect and a clock far from the store's are
    /// errors.
    async fn send(
        &self,
        req: &Prepared,
        method: &str,
        body: Vec<u8>,
    ) -> anyhow::Result<reqwest::Response> {
        let mut b = self.http.request(method.parse()?, req.url.clone());
        for (k, v) in &req.headers {
            // `host` is derived from the URL, which is the value that was signed.
            if k != "host" {
                b = b.header(k, v);
            }
        }
        if method == "PUT" {
            b = b.body(body);
        }
        let resp = b.send().await.context("the S3 request failed")?;
        if resp.status().is_redirection() {
            bail!(
                "the S3 endpoint answered {} (a redirect): the region or the endpoint is probably wrong",
                resp.status()
            );
        }
        if let Some(date) = resp.headers().get("date") {
            let date = date
                .to_str()
                .ok()
                .and_then(parse_http_date)
                .context("the store's Date header is not a valid HTTP date")?;
            let drift = SystemTime::now()
                .duration_since(date)
                .unwrap_or_else(|e| e.duration());
            if drift > MAX_DRIFT {
                bail!(
                    "this host's clock differs from the store's by {}s; the retain-until date follows the local clock, so fix it first",
                    drift.as_secs()
                );
            }
        }
        Ok(resp)
    }

    /// Read the stored version's retention back and require COMPLIANCE until at
    /// least `until`.
    async fn check_lock(
        &self,
        key: &str,
        version_id: &str,
        until: SystemTime,
    ) -> anyhow::Result<()> {
        let req = self.prepare(
            "GET",
            key,
            &[("retention", ""), ("versionId", version_id)],
            &[],
            b"",
            SystemTime::now(),
        )?;
        let resp = self.send(&req, "GET", Vec::new()).await?;
        if !resp.status().is_success() {
            bail!(
                "{key:?} was stored but its retention could not be read back: {}",
                error_detail(resp).await
            );
        }
        let body = String::from_utf8_lossy(&read_capped(resp, MAX_DOCUMENT).await?).into_owned();
        let mode = xml_text(&body, "Mode");
        let held = xml_text(&body, "RetainUntilDate").and_then(parse_iso8601);
        let wanted = secs(until);
        match (mode, held) {
            (Some("COMPLIANCE"), Some(held)) if secs(held) >= wanted => Ok(()),
            _ => bail!(
                "{key:?} was stored without the requested lock (mode {mode:?}, retain-until {:?}): the store ignores Object Lock or the bucket does not enforce it",
                xml_text(&body, "RetainUntilDate")
            ),
        }
    }
}

impl Anchor for S3ObjectLock {
    fn name(&self) -> &'static str {
        "s3-object-lock"
    }

    /// PUT the manifest locked until now plus the configured retention, refusing to
    /// replace an existing object, then read the stored version's retention back and
    /// require COMPLIANCE until at least the requested date. The receipt is the
    /// object's version id, which `fetch` takes. The first call also runs
    /// [`S3ObjectLock::verify_bucket`].
    ///
    /// A retry of a `put` whose response was lost gets a 412 (the key exists)
    /// although the object is anchored; `anchor` mints a fresh key per run.
    async fn put(&self, key: &str, bytes: &[u8]) -> anyhow::Result<String> {
        self.verified
            .get_or_try_init(|| self.verify_bucket())
            .await?;
        let now = SystemTime::now();
        let until = now
            .checked_add(self.config.retention)
            .context("the retention overflows the clock")?;
        let req = self.prepare_put(key, bytes, now)?;
        let resp = self.send(&req, "PUT", bytes.to_vec()).await?;
        let status = resp.status();
        if !status.is_success() {
            let detail = error_detail(resp).await;
            if status == reqwest::StatusCode::PRECONDITION_FAILED {
                bail!("anchoring {key:?} failed: the key already exists ({detail})");
            }
            bail!("anchoring {key:?} failed: {detail}");
        }
        let version = resp
            .headers()
            .get("x-amz-version-id")
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
            .filter(|v| !v.is_empty() && *v != "null")
            .map(str::to_owned)
            .context("the store returned no version id, so no Object Lock is in effect")?;
        self.check_lock(key, &version, until).await?;
        Ok(version)
    }
}

/// Reject keys whose path would be rewritten by URL normalization.
fn validate_key(key: &str) -> anyhow::Result<()> {
    if key.is_empty() || key.starts_with('/') {
        bail!("the object key is empty or starts with a slash");
    }
    if key.split('/').any(|s| matches!(s, "" | "." | "..")) {
        bail!("the object key has an empty, `.` or `..` segment");
    }
    Ok(())
}

fn is_loopback(host: &str) -> bool {
    host.trim_matches(['[', ']'])
        .parse::<std::net::IpAddr>()
        .is_ok_and(|ip| ip.is_loopback())
}

/// The body of `resp`, refusing more than `cap` bytes.
async fn read_capped(mut resp: reqwest::Response, cap: usize) -> anyhow::Result<Vec<u8>> {
    if resp
        .content_length()
        .is_some_and(|n| n > u64::try_from(cap).unwrap_or(u64::MAX))
    {
        bail!("the response is larger than {cap} bytes");
    }
    let mut out = Vec::new();
    while let Some(chunk) = resp.chunk().await.context("reading the response failed")? {
        if out.len() + chunk.len() > cap {
            bail!("the response is larger than {cap} bytes");
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

/// `404 Not Found (NoSuchKey: The specified key does not exist.)`, from a failed
/// response: the status and only the S3 `<Code>` and `<Message>`.
async fn error_detail(mut resp: reqwest::Response) -> String {
    let status = resp.status();
    let mut body = Vec::new();
    while body.len() < MAX_ERROR {
        match resp.chunk().await {
            Ok(Some(c)) => body.extend_from_slice(&c),
            _ => break,
        }
    }
    body.truncate(MAX_ERROR);
    let body = String::from_utf8_lossy(&body);
    match (xml_text(&body, "Code"), xml_text(&body, "Message")) {
        (Some(code), Some(msg)) => {
            format!(
                "{status} ({code}: {})",
                msg.chars().take(200).collect::<String>()
            )
        }
        (Some(code), None) => format!("{status} ({code})"),
        _ => status.to_string(),
    }
}

/// The trimmed text of the first `<tag>…</tag>` element.
fn xml_text<'a>(xml: &'a str, tag: &str) -> Option<&'a str> {
    let open = format!("<{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&format!("</{tag}>"))? + start;
    Some(xml[start..end].trim())
}

struct Creds<'a> {
    access_key: &'a str,
    signing_key: &'a [u8],
    region: &'a str,
}

/// The `SigV4` signing key for `day` (`YYYYMMDD`).
fn signing_key(secret_key: &str, day: &str, region: &str) -> Zeroizing<Vec<u8>> {
    let seed = Zeroizing::new(format!("AWS4{secret_key}"));
    let k = hmac(seed.as_bytes(), day.as_bytes());
    let k = hmac(&k, region.as_bytes());
    let k = hmac(&k, b"s3");
    hmac(&k, b"aws4_request")
}

/// The canonical query string: names and values percent-encoded, sorted by name.
fn canonical_query(pairs: &[(&str, &str)]) -> String {
    let mut encoded: Vec<(String, String)> = pairs
        .iter()
        .map(|(k, v)| (encode(k, false), encode(v, false)))
        .collect();
    encoded.sort();
    encoded
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

/// The `Authorization` header value. `headers` are lowercase names, sorted, and all
/// signed. `path` is already percent-encoded, and `query` canonical.
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
    let signature = hex(&hmac(creds.signing_key, to_sign.as_bytes()));
    format!(
        "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed}, Signature={signature}",
        creds.access_key
    )
}

fn hmac(key: &[u8], data: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut m = HmacSha256::new_from_slice(key).expect("HMAC accepts keys of any length");
    m.update(data);
    Zeroizing::new(m.finalize().into_bytes().to_vec())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// Percent-encode each byte but unreserved characters and, when `keep_slash`, `/`.
fn encode(text: &str, keep_slash: bool) -> String {
    text.bytes().fold(String::new(), |mut s, b| {
        if b.is_ascii_alphanumeric()
            || matches!(b, b'-' | b'_' | b'.' | b'~')
            || (keep_slash && b == b'/')
        {
            s.push(char::from(b));
        } else {
            let _ = write!(s, "%{b:02X}");
        }
        s
    })
}

/// A path, as `SigV4` encodes it for S3.
fn encode_path(path: &str) -> String {
    encode(path, true)
}

fn secs(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
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
    let secs = secs(t);
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

/// The instant of a UTC date and time of day.
fn from_civil(year: i64, month: i64, day: i64, h: u64, m: u64, s: u64) -> Option<SystemTime> {
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || h > 23 || m > 59 || s > 60 {
        return None;
    }
    let y = year - i64::from(month <= 2);
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = u64::try_from(era * 146_097 + doe - 719_468).ok()?;
    Some(UNIX_EPOCH + Duration::from_secs(days * 86_400 + h * 3_600 + m * 60 + s))
}

/// `Fri, 24 May 2013 00:00:00 GMT`.
fn parse_http_date(s: &str) -> Option<SystemTime> {
    let p: Vec<&str> = s.split_whitespace().collect();
    if p.len() != 6 || p[5] != "GMT" {
        return None;
    }
    let month = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ]
    .iter()
    .position(|m| *m == p[2])?;
    let mut t = p[4].split(':');
    from_civil(
        p[3].parse().ok()?,
        i64::try_from(month).ok()? + 1,
        p[1].parse().ok()?,
        t.next()?.parse().ok()?,
        t.next()?.parse().ok()?,
        t.next()?.parse().ok()?,
    )
}

/// `2013-05-24T00:00:00Z`, with optional fractional seconds.
fn parse_iso8601(s: &str) -> Option<SystemTime> {
    let s = s.strip_suffix('Z')?;
    let (date, time) = s.split_once('T')?;
    let time = time.split_once('.').map_or(time, |(t, _)| t);
    let mut d = date.split('-');
    let mut t = time.split(':');
    from_civil(
        d.next()?.parse().ok()?,
        d.next()?.parse().ok()?,
        d.next()?.parse().ok()?,
        t.next()?.parse().ok()?,
        t.next()?.parse().ok()?,
        t.next()?.parse().ok()?,
    )
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

    fn config(endpoint: &str) -> S3Config {
        S3Config {
            endpoint: endpoint.into(),
            allow_insecure_http: false,
            bucket: "audit".into(),
            region: "us-east-1".into(),
            access_key: AK.into(),
            secret_key: SK.to_owned().into(),
            retention: Duration::from_hours(7 * 365 * 24),
        }
    }

    fn anchor() -> S3ObjectLock {
        S3ObjectLock::new(config("http://127.0.0.1:9000")).unwrap()
    }

    fn creds(key: &[u8]) -> Creds<'_> {
        Creds {
            access_key: AK,
            signing_key: key,
            region: "us-east-1",
        }
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
        let key = signing_key(SK, "20130524", "us-east-1");
        let creds = creds(&key);
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
        let key = signing_key(SK, "20130524", "us-east-1");
        let creds = creds(&key);
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
        let p = anchor()
            .prepare_put("owt-audit/0001-ab.json", b"{}", now)
            .unwrap();
        assert_eq!(
            p.url.as_str(),
            "http://127.0.0.1:9000/audit/owt-audit/0001-ab.json"
        );
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
        let p = anchor()
            .prepare(
                "GET",
                "",
                &[("object-lock", "")],
                &[],
                b"",
                at(1_369_353_600),
            )
            .unwrap();
        assert_eq!(p.url.as_str(), "http://127.0.0.1:9000/audit?object-lock=");
    }

    #[test]
    fn matches_the_published_lifecycle_example() {
        // AWS docs, "Example: GET Bucket Lifecycle" (a query string).
        let key = signing_key(SK, "20130524", "us-east-1");
        let empty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let headers = h(&[
            ("host", "examplebucket.s3.amazonaws.com"),
            ("x-amz-content-sha256", empty),
            ("x-amz-date", "20130524T000000Z"),
        ]);
        let a = authorization(
            &creds(&key),
            "GET",
            "/",
            &canonical_query(&[("lifecycle", "")]),
            &headers,
            empty,
            "20130524T000000Z",
        );
        assert!(
            a.ends_with(
                "Signature=fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543"
            ),
            "{a}"
        );
    }

    #[test]
    fn matches_the_published_list_objects_example() {
        // AWS docs, "Example: GET Bucket (List Objects)": two parameters, sorted.
        let key = signing_key(SK, "20130524", "us-east-1");
        let empty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let headers = h(&[
            ("host", "examplebucket.s3.amazonaws.com"),
            ("x-amz-content-sha256", empty),
            ("x-amz-date", "20130524T000000Z"),
        ]);
        let query = canonical_query(&[("prefix", "J"), ("max-keys", "2")]);
        assert_eq!(query, "max-keys=2&prefix=J");
        let a = authorization(
            &creds(&key),
            "GET",
            "/",
            &query,
            &headers,
            empty,
            "20130524T000000Z",
        );
        assert!(
            a.ends_with(
                "Signature=34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7"
            ),
            "{a}"
        );
    }

    #[test]
    fn queries_are_encoded_and_sorted() {
        assert_eq!(
            canonical_query(&[("versionId", "a b/c+d"), ("retention", "")]),
            "retention=&versionId=a%20b%2Fc%2Bd"
        );
    }

    #[test]
    fn keys_with_special_characters_sign_the_path_that_is_sent() {
        let p = anchor()
            .prepare(
                "GET",
                "a b/c+d$é.json",
                &[("versionId", "v 1")],
                &[],
                b"",
                at(0),
            )
            .unwrap();
        assert_eq!(
            p.url.as_str(),
            "http://127.0.0.1:9000/audit/a%20b/c%2Bd%24%C3%A9.json?versionId=v%201"
        );
    }

    #[test]
    fn rejects_bad_keys() {
        for key in ["", "/a", "a//b", "a/./b", "x/../y", "a/", ".."] {
            assert!(validate_key(key).is_err(), "{key:?}");
        }
        assert!(validate_key("owt-audit/0001-ab.json").is_ok());
        assert!(anchor().prepare_put("x/../y", b"", at(0)).is_err());
    }

    #[test]
    fn the_signed_host_is_the_sent_host() {
        let a = S3ObjectLock::new(config("https://host.example:443")).unwrap();
        let p = a.prepare("GET", "k", &[], &[], b"", at(0)).unwrap();
        assert_eq!(header(&p, "host"), "host.example");
        assert_eq!(p.url.as_str(), "https://host.example/audit/k");

        let a = S3ObjectLock::new(config("https://S3.Example.COM:9000/")).unwrap();
        let p = a.prepare("GET", "k", &[], &[], b"", at(0)).unwrap();
        assert_eq!(header(&p, "host"), "s3.example.com:9000");
        assert_eq!(p.url.as_str(), "https://s3.example.com:9000/audit/k");
    }

    #[test]
    fn rejects_bad_configuration() {
        let reject = |f: &dyn Fn(&mut S3Config)| {
            let mut c = config("https://s3.example.com");
            f(&mut c);
            assert!(S3ObjectLock::new(c).is_err());
        };
        reject(&|c| c.endpoint = "s3.example.com".into());
        reject(&|c| c.endpoint = "ftp://s3.example.com".into());
        reject(&|c| c.endpoint = "https://s3.example.com/prefix".into());
        reject(&|c| c.endpoint = "https://u:p@s3.example.com".into());
        reject(&|c| c.endpoint = "https://s3.example.com/?x=1".into());
        reject(&|c| c.bucket = "a/b".into());
        reject(&|c| c.bucket = String::new());
        reject(&|c| c.retention = Duration::ZERO);
        reject(&|c| c.retention = Duration::from_hours(23));
        reject(&|c| c.retention = Duration::MAX);
        reject(&|c| c.retention = Duration::from_hours(101 * 365 * 24));
    }

    #[test]
    fn plain_http_needs_loopback_or_consent() {
        assert!(S3ObjectLock::new(config("http://s3.example.com")).is_err());
        assert!(S3ObjectLock::new(config("http://minio.svc:9000")).is_err());
        assert!(S3ObjectLock::new(config("http://127.0.0.1:9000")).is_ok());
        assert!(S3ObjectLock::new(config("http://[::1]:9000")).is_ok());
        let mut c = config("http://minio.svc:9000");
        c.allow_insecure_http = true;
        assert!(S3ObjectLock::new(c).is_ok());
    }

    #[test]
    fn parses_xml_and_dates() {
        let xml = "<R>\n  <ObjectLockEnabled>\n Enabled\n </ObjectLockEnabled>\n</R>";
        assert_eq!(xml_text(xml, "ObjectLockEnabled"), Some("Enabled"));
        assert_eq!(xml_text(xml, "Mode"), None);
        assert_eq!(
            parse_http_date("Fri, 24 May 2013 00:00:00 GMT"),
            Some(at(1_369_353_600))
        );
        assert_eq!(
            parse_iso8601("2013-05-24T00:00:00.000Z"),
            Some(at(1_369_353_600))
        );
        assert_eq!(parse_iso8601("2013-05-24"), None);
    }

    #[test]
    fn debug_hides_the_secret() {
        assert!(!format!("{:?}", anchor()).contains(SK));
    }
}
