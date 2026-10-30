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
    /// The secret access key, overwritten when dropped (best effort: the HMAC
    /// implementation keeps its own copies of derived keys while it runs).
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
/// No `Debug`: the authorization header is a credential.
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
        // Signed requests go straight to the endpoint: `.no_proxy()` ignores the
        // `HTTPS_PROXY`, `HTTP_PROXY` and `ALL_PROXY` environment variables, so
        // the environment cannot route them through a third party. A proxy is not
        // supported.
        let http = reqwest::Client::builder()
            .no_proxy()
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
            match detail.code.as_deref() {
                Some("ObjectLockConfigurationNotFoundError") => bail!(
                    "the bucket {:?} has no Object Lock configuration ({detail}): create it with Object Lock enabled",
                    self.config.bucket
                ),
                Some("NoSuchBucket") => bail!(
                    "the bucket {:?} does not exist ({detail})",
                    self.config.bucket
                ),
                _ => {}
            }
            bail!(
                "reading the Object Lock configuration of the bucket {:?} failed: {detail}",
                self.config.bucket
            );
        }
        let body = String::from_utf8_lossy(&read_capped(resp, MAX_DOCUMENT).await?).into_owned();
        let enabled = xml_child(&body, "ObjectLockConfiguration", "ObjectLockEnabled");
        if enabled.as_deref() != Some("Enabled") {
            bail!(
                "Object Lock is not enabled on the bucket {:?}",
                self.config.bucket
            );
        }
        Ok(())
    }

    /// Read a stored manifest back, for `audit verify --manifest`. Pass the receipt
    /// `put` returned as `version_id`: without it the latest version is read, which
    /// a credential able to write the key again could have replaced. With it, the
    /// response must name that same version in `x-amz-version-id`, and the version's
    /// retention must still be COMPLIANCE and in the future, so only a locked
    /// version is trusted.
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
        if let Some(pinned) = version_id {
            let served = resp
                .headers()
                .get("x-amz-version-id")
                .and_then(|v| v.to_str().ok())
                .map(str::trim);
            if served != Some(pinned) {
                bail!(
                    "reading {key:?} returned version {served:?} where {pinned:?} was pinned: the store did not serve the receipt's version"
                );
            }
        }
        let body = read_capped(resp, MAX_MANIFEST).await?;
        if let Some(pinned) = version_id {
            self.check_lock(key, pinned, SystemTime::now()).await?;
        }
        Ok(body)
    }

    /// The signed PUT of `bytes` under `key`, as of `now`.
    fn prepare_put(&self, key: &str, bytes: &[u8], now: SystemTime) -> anyhow::Result<Prepared> {
        validate_key(key)?;
        let until = now
            .checked_add(self.config.retention)
            .context("the retention overflows the clock")?;
        // S3 requires `Content-MD5` (or a checksum header) on a PUT that carries
        // Object Lock headers. MD5 here is the integrity check the API demands, not
        // a security primitive: the SigV4 signature and the `x-amz-content-sha256`
        // payload hash are what authenticate the body.
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

    /// Send a signed request. A redirect is an error, and so is a success response
    /// whose `Date` is missing or far from this host's clock. Other failures are
    /// returned for the caller to report.
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
        if !resp.status().is_success() {
            // The caller reports the store's error, which a missing or skewed
            // `Date` on a failure must not hide.
            return Ok(resp);
        }
        // Every S3-compatible store sends `Date`; without it the clock cannot be
        // checked, so a success response is refused. On a PUT this can arrive after the
        // object is locked, to a date that follows a wrong clock.
        let date = resp
            .headers()
            .get("date")
            .and_then(|d| d.to_str().ok())
            .and_then(parse_http_date)
            .context("the store's response has no valid Date header")?;
        let drift = SystemTime::now()
            .duration_since(date)
            .unwrap_or_else(|e| e.duration());
        if drift > MAX_DRIFT {
            bail!(
                "this host's clock differs from the store's by {}s; the retain-until date follows the local clock, so fix it first",
                drift.as_secs()
            );
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
                "the retention of {key:?} could not be read back: {}",
                error_detail(resp).await
            );
        }
        let body = String::from_utf8_lossy(&read_capped(resp, MAX_DOCUMENT).await?).into_owned();
        let mode = xml_child(&body, "Retention", "Mode");
        let until_text = xml_child(&body, "Retention", "RetainUntilDate");
        let held = until_text.as_deref().and_then(parse_iso8601);
        let wanted = secs(until);
        match (mode.as_deref(), held) {
            (Some("COMPLIANCE"), Some(held)) if secs(held) >= wanted => Ok(()),
            _ => bail!(
                "{key:?} is held without the required lock (mode {mode:?}, retain-until {until_text:?}): the store ignores Object Lock or the bucket does not enforce it",
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

/// A failed response's status and the S3 error document's `<Code>` and `<Message>`,
/// reduced to printable text so a store cannot inject control characters or long
/// lines into logs.
struct S3Error {
    status: reqwest::StatusCode,
    code: Option<String>,
    message: Option<String>,
}

impl std::fmt::Display for S3Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.status)?;
        match (&self.code, &self.message) {
            (Some(c), Some(m)) => write!(f, " ({c}: {m})"),
            (Some(c), None) => write!(f, " ({c})"),
            _ => Ok(()),
        }
    }
}

async fn error_detail(mut resp: reqwest::Response) -> S3Error {
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
    let code = xml_child(&body, "Error", "Code").map(|c| {
        c.chars()
            .filter(char::is_ascii_alphanumeric)
            .take(64)
            .collect::<String>()
    });
    let message = xml_child(&body, "Error", "Message").map(|m| {
        m.chars()
            .map(|c| if c.is_control() { ' ' } else { c })
            .take(200)
            .collect::<String>()
    });
    S3Error {
        status,
        code: code.filter(|c| !c.is_empty()),
        message,
    }
}

/// The trimmed text of the leaf element `child` directly under the document root
/// `root`, or `None` when the document is not a `root` element, has no such child,
/// the child has any element inside it (mixed content included), or the document is
/// not plain XML: comments, CDATA and DTDs are refused, every element must close in
/// order, and the root's close tag must end the document.
fn xml_child(xml: &str, root: &str, child: &str) -> Option<String> {
    let mut s = xml.trim_start();
    if s.starts_with("<?xml") {
        s = s[s.find("?>")? + 2..].trim_start();
    }
    let open = s.strip_prefix('<')?.strip_prefix(root)?;
    if !open.starts_with(['>', ' ', '\t', '\r', '\n', '/']) {
        return None;
    }
    let end = tag_end(open)?;
    if open[..end].ends_with('/') {
        return None;
    }
    let mut rest = &open[end + 1..];
    // The names of the open elements below the root.
    let mut stack: Vec<&str> = Vec::new();
    // Whether the direct child being read holds an element.
    let mut nested = false;
    let mut found: Option<String> = None;
    loop {
        let lt = rest.find('<')?;
        let before = &rest[..lt];
        let tag_len = tag_end(&rest[lt..])?;
        let tag = &rest[lt + 1..lt + tag_len];
        let after = &rest[lt + tag_len + 1..];
        if tag.starts_with(['!', '?']) {
            return None;
        }
        if let Some(name) = tag.strip_prefix('/') {
            let name = name.trim();
            let Some(open_name) = stack.pop() else {
                // The root's close tag ends the document.
                return (name == root && after.trim().is_empty())
                    .then_some(found)
                    .flatten();
            };
            if open_name != name {
                return None;
            }
            if stack.is_empty() && name == child {
                if nested {
                    return None;
                }
                found.get_or_insert_with(|| before.trim().to_owned());
            }
        } else {
            let self_closing = tag.ends_with('/');
            let name = tag
                .trim_end_matches('/')
                .split(|c: char| c.is_whitespace())
                .next()?;
            if stack.is_empty() {
                nested = false;
                if self_closing {
                    if name == child {
                        found.get_or_insert_with(String::new);
                    }
                } else {
                    stack.push(name);
                }
            } else {
                // Any element inside the child, self-closing or not.
                nested = true;
                if !self_closing {
                    stack.push(name);
                }
            }
        }
        rest = after;
    }
}

/// The index of the `>` that ends the tag starting at the `<` that opens `s`,
/// skipping any inside a quoted attribute value.
fn tag_end(s: &str) -> Option<usize> {
    let mut quote: Option<char> = None;
    for (i, c) in s.char_indices() {
        match (quote, c) {
            (None, '>') => return Some(i),
            (None, '"' | '\'') => quote = Some(c),
            (Some(q), c) if c == q => quote = None,
            _ => {}
        }
    }
    None
}

struct Creds<'a> {
    access_key: &'a str,
    signing_key: &'a [u8],
    region: &'a str,
}

/// The `SigV4` signing key for `day` (`YYYYMMDD`).
fn signing_key(secret_key: &str, day: &str, region: &str) -> Zeroizing<Vec<u8>> {
    // Built at its final size so growth does not leave unwiped copies behind.
    let mut seed = Zeroizing::new(Vec::with_capacity(4 + secret_key.len()));
    seed.extend_from_slice(b"AWS4");
    seed.extend_from_slice(secret_key.as_bytes());
    let k = hmac(&seed, day.as_bytes());
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

/// The instant of a UTC date and time of day, for years 1970 to 9999 and real
/// calendar days only.
fn from_civil(year: i64, month: i64, day: i64, h: u64, m: u64, s: u64) -> Option<SystemTime> {
    if !(1970..=9999).contains(&year) || !(1..=12).contains(&month) || h > 23 || m > 59 || s > 60 {
        return None;
    }
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let in_month = match month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    if !(1..=in_month).contains(&day) {
        return None;
    }
    let y = year - i64::from(month <= 2);
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = u64::try_from(era * 146_097 + doe - 719_468).ok()?;
    let total = days
        .checked_mul(86_400)?
        .checked_add(h * 3_600 + m * 60 + s)?;
    UNIX_EPOCH.checked_add(Duration::from_secs(total))
}

/// An unsigned decimal integer: digits only, so no sign, space or underscore.
fn digits<T: std::str::FromStr>(s: &str) -> Option<T> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
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
        digits(p[3])?,
        i64::try_from(month).ok()? + 1,
        digits(p[1])?,
        digits(t.next()?)?,
        digits(t.next()?)?,
        digits(t.next()?)?,
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
        digits(d.next()?)?,
        digits(d.next()?)?,
        digits(d.next()?)?,
        digits(t.next()?)?,
        digits(t.next()?)?,
        digits(t.next()?)?,
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
    fn parses_xml_structurally() {
        let xml = "<?xml version=\"1.0\"?>\n<ObjectLockConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\n  <ObjectLockEnabled>\n Enabled\n </ObjectLockEnabled>\n <Rule><DefaultRetention><Mode>X</Mode></DefaultRetention></Rule></ObjectLockConfiguration>";
        let get = |r, c| xml_child(xml, r, c);
        assert_eq!(
            get("ObjectLockConfiguration", "ObjectLockEnabled").as_deref(),
            Some("Enabled")
        );
        // Not a direct child, and not the root.
        assert_eq!(get("ObjectLockConfiguration", "Mode"), None);
        assert_eq!(get("Retention", "ObjectLockEnabled"), None);
        // Comments, CDATA and bodies that are not the document are refused.
        assert_eq!(
            xml_child(
                "<Retention><!-- x --><Mode>A</Mode></Retention>",
                "Retention",
                "Mode"
            ),
            None
        );
        assert_eq!(
            xml_child("{\"Mode\":1}<Mode>COMPLIANCE</Mode>", "Retention", "Mode"),
            None
        );
        assert_eq!(
            xml_child(
                "<RetentionX><Mode>A</Mode></RetentionX>",
                "Retention",
                "Mode"
            ),
            None
        );
        assert_eq!(
            xml_child("<Retention><Mode>A</Mode></Retention>", "Retention", "Mode").as_deref(),
            Some("A")
        );
    }

    #[test]
    fn rejects_malformed_documents() {
        let get = |x| xml_child(x, "Retention", "Mode");
        // Mixed content, with a self-closing or an open child.
        assert_eq!(
            get("<Retention><Mode>X<a/>COMPLIANCE</Mode></Retention>"),
            None
        );
        assert_eq!(get("<Retention><Mode>X<a>y</a></Mode></Retention>"), None);
        // No closing root, a wrong one, or trailing content.
        assert_eq!(get("<Retention><Mode>A</Mode>"), None);
        assert_eq!(get("<Retention><Mode>A</Mode></Other>"), None);
        assert_eq!(get("<Retention><Mode>A</Mode></Retention><x/>"), None);
        assert_eq!(
            get("<Retention><Mode>A</Mode></Retention> \n").as_deref(),
            Some("A")
        );
        // Mismatched nesting.
        assert_eq!(
            get("<Retention><Mode>A</Mode><b><c></b></c></Retention>"),
            None
        );
        // A `>` inside a quoted attribute does not end the tag.
        assert_eq!(
            get("<Retention a=\"x>y\"><Mode b='>'>A</Mode></Retention>").as_deref(),
            Some("A")
        );
        assert_eq!(get("<Retention><Mode b=\"x>A</Mode></Retention>"), None);
    }

    #[test]
    fn integers_have_no_sign() {
        assert_eq!(parse_iso8601("+2013-05-24T00:00:00Z"), None);
        assert_eq!(parse_iso8601("2013-+5-24T00:00:00Z"), None);
        assert_eq!(parse_iso8601("2013-05-24T+0:00:00Z"), None);
        assert_eq!(parse_http_date("Fri, +4 May 2013 00:00:00 GMT"), None);
        assert_eq!(parse_http_date("Fri, 24 May +2013 00:00:00 GMT"), None);
        assert_eq!(parse_http_date("Fri, 24 May 2013 00:+0:00 GMT"), None);
    }

    #[test]
    fn parses_dates_without_panicking() {
        assert_eq!(
            parse_http_date("Fri, 24 May 2013 00:00:00 GMT"),
            Some(at(1_369_353_600))
        );
        assert_eq!(
            parse_iso8601("2013-05-24T00:00:00.000Z"),
            Some(at(1_369_353_600))
        );
        assert_eq!(parse_iso8601("2013-05-24"), None);
        assert_eq!(parse_iso8601("999999999999-01-01T00:00:00Z"), None);
        assert_eq!(parse_iso8601("10000-01-01T00:00:00Z"), None);
        assert_eq!(parse_iso8601("1969-12-31T23:59:59Z"), None);
        assert_eq!(parse_iso8601("2013-02-31T00:00:00Z"), None);
        assert_eq!(parse_iso8601("2013-04-31T00:00:00Z"), None);
        assert_eq!(parse_iso8601("2013-02-29T00:00:00Z"), None);
        assert!(parse_iso8601("2024-02-29T00:00:00Z").is_some());
        assert_eq!(
            parse_http_date("Fri, 24 May 999999999999 00:00:00 GMT"),
            None
        );
    }

    #[test]
    fn debug_hides_the_secret() {
        assert!(!format!("{:?}", anchor()).contains(SK));
    }

    // A loopback server that answers the n-th connection with the n-th canned
    // response, for the branches that decide whether a lock is genuine.
    mod fake {
        use super::*;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        pub fn http_date(t: SystemTime) -> String {
            // The weekday is not read by the parser.
            let c = civil(t);
            let mon = [
                "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
            ][usize::try_from(c.month - 1).unwrap()];
            format!(
                "Mon, {:02} {mon} {:04} {:02}:{:02}:{:02} GMT",
                c.day, c.year, c.hour, c.minute, c.second
            )
        }

        /// A response with a current `Date` unless `date` says otherwise.
        pub fn reply(
            status: &str,
            headers: &[(&str, &str)],
            body: &str,
            date: Option<SystemTime>,
        ) -> String {
            let mut out = format!(
                "HTTP/1.1 {status}\r\nConnection: close\r\nContent-Length: {}\r\n",
                body.len()
            );
            if let Some(d) = date {
                let _ = write!(out, "Date: {}\r\n", http_date(d));
            }
            for (k, v) in headers {
                let _ = write!(out, "{k}: {v}\r\n");
            }
            out + "\r\n" + body
        }

        pub fn ok(headers: &[(&str, &str)], body: &str) -> String {
            reply("200 OK", headers, body, Some(SystemTime::now()))
        }

        pub async fn serve(responses: Vec<String>) -> String {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            tokio::spawn(async move {
                for r in responses {
                    let Ok((mut sock, _)) = listener.accept().await else {
                        return;
                    };
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 4096];
                    // Read the head, then the body its Content-Length announces.
                    loop {
                        let n = sock.read(&mut chunk).await.unwrap_or(0);
                        if n == 0 {
                            break;
                        }
                        buf.extend_from_slice(&chunk[..n]);
                        let text = String::from_utf8_lossy(&buf).to_lowercase();
                        if let Some(end) = text.find("\r\n\r\n") {
                            let len = text
                                .lines()
                                .find_map(|l| l.strip_prefix("content-length:"))
                                .and_then(|v| v.trim().parse::<usize>().ok())
                                .unwrap_or(0);
                            if buf.len() >= end + 4 + len {
                                break;
                            }
                        }
                    }
                    let _ = sock.write_all(r.as_bytes()).await;
                    let _ = sock.shutdown().await;
                }
            });
            format!("http://{addr}")
        }

        pub const LOCK_ON: &str = "<ObjectLockConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><ObjectLockEnabled>Enabled</ObjectLockEnabled></ObjectLockConfiguration>";

        pub fn retention(mode: &str, until: SystemTime) -> String {
            format!(
                "<Retention><Mode>{mode}</Mode><RetainUntilDate>{}</RetainUntilDate></Retention>",
                iso8601(until)
            )
        }

        pub fn years(n: u64) -> SystemTime {
            SystemTime::now() + Duration::from_hours(n * 365 * 24)
        }

        pub async fn put(responses: Vec<String>) -> anyhow::Result<String> {
            let endpoint = serve(responses).await;
            S3ObjectLock::new(config(&endpoint))
                .unwrap()
                .put("owt-audit/1.json", b"{}")
                .await
        }
    }

    use fake::{LOCK_ON, ok, put, reply, retention, years};

    fn ok_status(status: &str, body: &str) -> String {
        reply(status, &[], body, Some(SystemTime::now()))
    }

    fn err(r: anyhow::Result<String>) -> String {
        format!("{:#}", r.unwrap_err())
    }

    #[tokio::test]
    async fn a_genuine_lock_is_accepted() {
        let got = put(vec![
            ok(&[], LOCK_ON),
            ok(&[("x-amz-version-id", "v1")], ""),
            ok(&[], &retention("COMPLIANCE", years(8))),
        ])
        .await;
        assert_eq!(got.unwrap(), "v1");
    }

    #[tokio::test]
    async fn a_put_without_a_version_id_fails() {
        let e = err(put(vec![ok(&[], LOCK_ON), ok(&[("ETag", "\"abc\"")], "")]).await);
        assert!(e.contains("no version id"), "{e}");
    }

    #[tokio::test]
    async fn the_wrong_mode_fails() {
        let e = err(put(vec![
            ok(&[], LOCK_ON),
            ok(&[("x-amz-version-id", "v1")], ""),
            ok(&[], &retention("GOVERNANCE", years(8))),
        ])
        .await);
        assert!(e.contains("without the required lock"), "{e}");
    }

    #[tokio::test]
    async fn a_short_retain_until_fails() {
        let e = err(put(vec![
            ok(&[], LOCK_ON),
            ok(&[("x-amz-version-id", "v1")], ""),
            ok(&[], &retention("COMPLIANCE", years(1))),
        ])
        .await);
        assert!(e.contains("without the required lock"), "{e}");
    }

    #[tokio::test]
    async fn a_body_in_place_of_retention_fails() {
        // A store that ignores `?retention` and returns the object, even one that
        // contains the elements.
        let e = err(put(vec![
            ok(&[], LOCK_ON),
            ok(&[("x-amz-version-id", "v1")], ""),
            ok(
                &[],
                &format!("{{\"a\":\"{}\"}}", retention("COMPLIANCE", years(8))),
            ),
        ])
        .await);
        assert!(e.contains("without the required lock"), "{e}");
    }

    #[tokio::test]
    async fn a_missing_date_fails_closed() {
        let e = err(put(vec![reply("200 OK", &[], LOCK_ON, None)]).await);
        assert!(e.contains("Date"), "{e}");
    }

    #[tokio::test]
    async fn a_skewed_date_fails_on_the_put_response_too() {
        let e = err(put(vec![
            ok(&[], LOCK_ON),
            reply(
                "200 OK",
                &[("x-amz-version-id", "v1")],
                "",
                Some(SystemTime::now() - Duration::from_hours(1)),
            ),
        ])
        .await);
        assert!(e.contains("clock differs"), "{e}");
    }

    #[tokio::test]
    async fn a_redirect_is_an_error() {
        let e = err(put(vec![reply(
            "301 Moved Permanently",
            &[("Location", "https://elsewhere.example/")],
            "",
            Some(SystemTime::now()),
        )])
        .await);
        assert!(e.contains("redirect"), "{e}");
    }

    #[tokio::test]
    async fn the_bucket_check_tells_its_failures_apart() {
        let no_bucket = "<Error><Code>NoSuchBucket</Code><Message>x\ny</Message></Error>";
        let e = err(put(vec![reply(
            "404 Not Found",
            &[],
            no_bucket,
            Some(SystemTime::now()),
        )])
        .await);
        assert!(e.contains("does not exist") && !e.contains('\n'), "{e}");
        let no_lock = "<Error><Code>ObjectLockConfigurationNotFoundError</Code></Error>";
        let e = err(put(vec![reply(
            "404 Not Found",
            &[],
            no_lock,
            Some(SystemTime::now()),
        )])
        .await);
        assert!(e.contains("no Object Lock configuration"), "{e}");
        let denied = "<Error><Code>AccessDenied</Code><Message>no</Message></Error>";
        let e = err(put(vec![reply(
            "403 Forbidden",
            &[],
            denied,
            Some(SystemTime::now()),
        )])
        .await);
        assert!(
            e.contains("403") && e.contains("AccessDenied") && !e.contains("create it"),
            "{e}"
        );
    }

    #[tokio::test]
    async fn a_precondition_failure_maps_to_an_existing_key() {
        let e = err(put(vec![
            ok(&[], LOCK_ON),
            ok_status(
                "412 Precondition Failed",
                "<Error><Code>PreconditionFailed</Code></Error>",
            ),
        ])
        .await);
        assert!(
            e.contains("key already exists") && e.contains("PreconditionFailed"),
            "{e}"
        );
    }

    #[tokio::test]
    async fn a_failure_without_a_date_reports_the_store_error() {
        let denied = "<Error><Code>AccessDenied</Code><Message>no</Message></Error>";
        let e = err(put(vec![
            ok(&[], LOCK_ON),
            reply("403 Forbidden", &[], denied, None),
        ])
        .await);
        assert!(e.contains("AccessDenied") && !e.contains("Date"), "{e}");
    }

    async fn fetch(version: Option<&str>, responses: Vec<String>) -> anyhow::Result<Vec<u8>> {
        let endpoint = fake::serve(responses).await;
        S3ObjectLock::new(config(&endpoint))
            .unwrap()
            .fetch("owt-audit/1.json", version)
            .await
    }

    #[tokio::test]
    async fn fetch_by_version_needs_the_same_version_and_a_lock() {
        let got = fetch(
            Some("v1"),
            vec![
                ok(&[("x-amz-version-id", "v1")], "manifest"),
                ok(&[], &retention("COMPLIANCE", years(1))),
            ],
        )
        .await;
        assert_eq!(got.unwrap(), b"manifest");

        let mismatch = fetch(Some("v1"), vec![ok(&[("x-amz-version-id", "v2")], "m")]).await;
        let e = format!("{:#}", mismatch.unwrap_err());
        assert!(e.contains("was pinned"), "{e}");
        let missing = fetch(Some("v1"), vec![ok(&[], "m")]).await;
        assert!(format!("{:#}", missing.unwrap_err()).contains("was pinned"));

        let governance = fetch(
            Some("v1"),
            vec![
                ok(&[("x-amz-version-id", "v1")], "m"),
                ok(&[], &retention("GOVERNANCE", years(1))),
            ],
        )
        .await;
        let e = format!("{:#}", governance.unwrap_err());
        assert!(e.contains("without the required lock"), "{e}");

        let expired = fetch(
            Some("v1"),
            vec![
                ok(&[("x-amz-version-id", "v1")], "m"),
                ok(
                    &[],
                    &retention("COMPLIANCE", SystemTime::now() - Duration::from_hours(48)),
                ),
            ],
        )
        .await;
        assert!(expired.is_err());
    }

    #[tokio::test]
    async fn fetch_of_the_latest_version_reads_one_object() {
        let got = fetch(None, vec![ok(&[], "manifest")]).await;
        assert_eq!(got.unwrap(), b"manifest");
    }
}
