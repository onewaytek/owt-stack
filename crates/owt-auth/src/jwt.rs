//! Bearer tokens an identity provider issued, verified locally.
//!
//! For machine clients (agents, services) arriving with a `client_credentials` token.
//! Verification is strict and needs no call to the provider beyond fetching its keys:
//!
//! * the signature, against a key from the provider's JWKS, chosen by `kid`;
//! * the algorithm, which must be one the verifier accepts (asymmetric ones only, by
//!   default: a token cannot pick `HS256` and sign with the public key) and the one
//!   the key is published for, when the key names one;
//! * `iss` against the configured issuer;
//! * `aud` against the configured audience: what stops a token minted for another
//!   service being replayed here;
//! * `exp` (and `nbf`), with a small leeway for clock skew.
//!
//! Keys are cached. An unknown `kid` refetches the set (the provider rotated), at most
//! once per [`Verifier::min_refresh`] (a failed fetch is retried after five seconds), so
//! a stream of forged `kid`s cannot turn into a stream of requests to the provider,
//! even while it is down. A fetch never holds up tokens signed with keys already known.

use std::sync::Arc;
use std::time::{Duration, Instant};

use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::de::DeserializeOwned;
use tokio::sync::{Mutex, RwLock};

/// The algorithms a verifier accepts unless [`Verifier::algorithms`] narrows them.
pub const ASYMMETRIC: &[Algorithm] = &[
    Algorithm::RS256,
    Algorithm::RS384,
    Algorithm::RS512,
    Algorithm::PS256,
    Algorithm::PS384,
    Algorithm::PS512,
    Algorithm::ES256,
    Algorithm::ES384,
    Algorithm::EdDSA,
];

/// How soon the keys are asked for again after a fetch that failed (if that is sooner
/// than [`Verifier::min_refresh`]): a provider's blip should not lock clients out for
/// the whole interval.
const RETRY_AFTER_FAILURE: Duration = Duration::from_secs(5);

/// How long a fetch of the provider's keys (or its discovery document) may take.
const FETCH_TIMEOUT: Duration = Duration::from_secs(10);

/// Why a token was refused.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Not a JWT, a bad signature, the wrong issuer or audience, expired, ...
    #[error("invalid token: {0}")]
    Invalid(#[from] jsonwebtoken::errors::Error),
    /// The token names no key, or a key the provider does not publish.
    #[error("unknown signing key")]
    UnknownKey,
    /// The token asks for an algorithm the verifier does not accept, or another than
    /// its key is published for.
    #[error("algorithm {0:?} is not accepted")]
    Algorithm(Algorithm),
    /// The keys could not be fetched.
    #[error("fetching the provider's keys: {0}")]
    Keys(#[from] reqwest::Error),
    /// The provider did not answer in time.
    #[error("fetching the provider's keys timed out")]
    Timeout,
    /// The discovery document is not this issuer's, or points somewhere unsafe.
    #[error("the issuer's discovery document is not acceptable: {0}")]
    Discovery(&'static str),
}

/// Verifies tokens from one issuer for one audience. Cheap to clone.
#[derive(Clone)]
pub struct Verifier(Arc<Inner>);

#[derive(Clone)]
struct Config {
    issuer: String,
    audience: String,
    jwks_uri: String,
    algorithms: Vec<Algorithm>,
    leeway: u64,
    min_refresh: Duration,
    retry_after_failure: Duration,
    http: reqwest::Client,
}

struct Inner {
    config: Config,
    keys: RwLock<Option<JwkSet>>,
    /// When the keys were last asked for, and whether they came. Held across the
    /// fetch, so one caller fetches and the rest wait for its answer.
    attempted: Mutex<Option<(Instant, bool)>>,
}

/// `https`, or plain `http` to this machine (a test's fake provider).
fn safe_url(url: &str) -> bool {
    url::Url::parse(url).is_ok_and(|u| {
        u.scheme() == "https"
            || (u.scheme() == "http"
                && matches!(u.host_str(), Some("127.0.0.1" | "localhost" | "[::1]")))
    })
}

/// The claims every verified token has; deserialize your own type for more.
#[derive(Clone, Debug, serde::Deserialize)]
pub struct Claims {
    /// Who the token is for: the client or account at the provider.
    pub sub: String,
}

impl Verifier {
    /// Tokens from `issuer` for `audience`, with keys at `jwks_uri`.
    #[must_use]
    pub fn new(http: reqwest::Client, issuer: &str, audience: &str, jwks_uri: &str) -> Self {
        Self::with(Config {
            issuer: issuer.to_owned(),
            audience: audience.to_owned(),
            jwks_uri: jwks_uri.to_owned(),
            algorithms: ASYMMETRIC.to_vec(),
            leeway: 5,
            min_refresh: Duration::from_secs(60),
            retry_after_failure: RETRY_AFTER_FAILURE,
            http,
        })
    }

    fn with(config: Config) -> Self {
        Self(Arc::new(Inner {
            config,
            keys: RwLock::new(None),
            attempted: Mutex::new(None),
        }))
    }

    /// Accept only these algorithms: the ones the provider is known to sign with.
    /// Symmetric ones are refused whatever this says. The verifier starts over with
    /// no cached keys.
    #[must_use]
    pub fn algorithms(self, algorithms: &[Algorithm]) -> Self {
        let mut config = self.0.config.clone();
        config.algorithms = algorithms
            .iter()
            .copied()
            .filter(|a| ASYMMETRIC.contains(a))
            .collect();
        Self::with(config)
    }

    /// Like [`Verifier::new`], finding the keys through the issuer's `OpenID` discovery
    /// document (`<issuer>/.well-known/openid-configuration`).
    pub async fn discover(
        http: reqwest::Client,
        issuer: &str,
        audience: &str,
    ) -> Result<Self, Error> {
        #[derive(serde::Deserialize)]
        struct Discovery {
            issuer: String,
            jwks_uri: String,
        }
        let url = format!(
            "{}/.well-known/openid-configuration",
            issuer.trim_end_matches('/')
        );
        let fetch = async {
            http.get(url)
                .send()
                .await?
                .error_for_status()?
                .json::<Discovery>()
                .await
        };
        let d = tokio::time::timeout(FETCH_TIMEOUT, fetch)
            .await
            .map_err(|_| Error::Timeout)??;
        // OpenID Connect Discovery §4.3: the document must be the issuer's own.
        // Exactly, trailing slash included, as it will be compared with every token's
        // `iss`: a near match here would pass discovery and then refuse every token.
        if d.issuer != issuer {
            return Err(Error::Discovery("it names another issuer"));
        }
        if !safe_url(&d.jwks_uri) {
            return Err(Error::Discovery("its jwks_uri is not https"));
        }
        Ok(Self::new(http, issuer, audience, &d.jwks_uri))
    }

    /// The least time between two refetches of the key set.
    #[must_use]
    pub fn min_refresh(&self) -> Duration {
        self.0.config.min_refresh
    }

    async fn fetch(&self) -> Result<JwkSet, Error> {
        let fetch = async {
            self.0
                .config
                .http
                .get(&self.0.config.jwks_uri)
                .send()
                .await?
                .error_for_status()?
                .json::<JwkSet>()
                .await
        };
        Ok(tokio::time::timeout(FETCH_TIMEOUT, fetch)
            .await
            .map_err(|_| Error::Timeout)??)
    }

    /// The key `kid` among the cached ones, checked against the token's algorithm.
    async fn cached(&self, kid: &str, alg: Algorithm) -> Option<Result<DecodingKey, Error>> {
        let keys = self.0.keys.read().await;
        let jwk = keys.as_ref()?.find(kid)?;
        // A key published for one algorithm verifies no other.
        if let Some(published) = jwk.common.key_algorithm
            && Algorithm::try_from(published).ok() != Some(alg)
        {
            return Some(Err(Error::Algorithm(alg)));
        }
        Some(DecodingKey::from_jwk(jwk).map_err(Error::from))
    }

    /// The key `kid`, refetching the set if it is unknown and the last attempt is old
    /// enough.
    async fn key(&self, kid: &str, alg: Algorithm) -> Result<DecodingKey, Error> {
        if let Some(found) = self.cached(kid, alg).await {
            return found;
        }
        {
            let mut attempted = self.0.attempted.lock().await;
            let min = self.0.config.min_refresh;
            let due = attempted.is_none_or(|(at, came)| {
                at.elapsed()
                    >= if came {
                        min
                    } else {
                        min.min(self.0.config.retry_after_failure)
                    }
            });
            if due {
                // Before the fetch, so a failure counts as an attempt too.
                *attempted = Some((Instant::now(), false));
                let set = self.fetch().await?;
                *self.0.keys.write().await = Some(set);
                *attempted = Some((Instant::now(), true));
            }
        }
        // Whether this caller fetched or waited for one that did.
        self.cached(kid, alg)
            .await
            .unwrap_or(Err(Error::UnknownKey))
    }

    /// Verify `token` and read its claims as `C`.
    pub async fn verify<C: DeserializeOwned>(&self, token: &str) -> Result<C, Error> {
        let config = &self.0.config;
        let header = jsonwebtoken::decode_header(token)?;
        if !config.algorithms.contains(&header.alg) {
            return Err(Error::Algorithm(header.alg));
        }
        let kid = header.kid.ok_or(Error::UnknownKey)?;
        let key = self.key(&kid, header.alg).await?;
        let mut v = Validation::new(header.alg);
        v.leeway = config.leeway;
        v.validate_nbf = true;
        v.set_issuer(&[&config.issuer]);
        v.set_audience(&[&config.audience]);
        v.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
        Ok(jsonwebtoken::decode::<C>(token, &key, &v)?.claims)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use axum::Json;
    use axum::routing::get;
    use base64::Engine;
    use jsonwebtoken::{EncodingKey, Header};
    use rsa::pkcs1::EncodeRsaPrivateKey;
    use rsa::traits::PublicKeyParts;

    use super::*;

    struct Idp {
        base: String,
        key: EncodingKey,
        fetches: Arc<AtomicUsize>,
    }

    async fn idp() -> Idp {
        let private = rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).unwrap();
        let b64 = |b: Vec<u8>| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b);
        let jwks = serde_json::json!({"keys": [{
            "kty": "RSA", "kid": "k1", "alg": "RS256", "use": "sig",
            "n": b64(private.n().to_bytes_be()), "e": b64(private.e().to_bytes_be()),
        }]});
        let fetches = Arc::new(AtomicUsize::new(0));
        let f = fetches.clone();
        let app = axum::Router::new().route(
            "/jwks",
            get(move || {
                f.fetch_add(1, Ordering::SeqCst);
                let jwks = jwks.clone();
                async move { Json(jwks) }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await });
        let key = EncodingKey::from_rsa_der(private.to_pkcs1_der().unwrap().as_bytes());
        Idp { base, key, fetches }
    }

    fn token(idp: &Idp, kid: &str, aud: &str, exp_in: i64) -> String {
        token_with(idp, kid, aud, exp_in, 0, Algorithm::RS256)
    }

    fn token_with(
        idp: &Idp,
        kid: &str,
        aud: &str,
        exp_in: i64,
        nbf_in: i64,
        alg: Algorithm,
    ) -> String {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let claims = serde_json::json!({
            "sub": "agent-7", "iss": "https://idp.test", "aud": aud,
            "exp": now.cast_signed() + exp_in,
            "nbf": now.cast_signed() + nbf_in,
        });
        let mut h = Header::new(alg);
        h.kid = Some(kid.into());
        jsonwebtoken::encode(&h, &claims, &idp.key).unwrap()
    }

    #[tokio::test]
    async fn verifies_signature_issuer_audience_and_expiry() {
        let idp = idp().await;
        let v = Verifier::new(
            reqwest::Client::new(),
            "https://idp.test",
            "kynestro",
            &format!("{}/jwks", idp.base),
        );
        let claims: Claims = v.verify(&token(&idp, "k1", "kynestro", 60)).await.unwrap();
        assert_eq!(claims.sub, "agent-7");
        assert!(matches!(
            v.verify::<Claims>(&token(&idp, "k1", "other", 60)).await,
            Err(Error::Invalid(_))
        ));
        assert!(matches!(
            v.verify::<Claims>(&token(&idp, "k1", "kynestro", -60))
                .await,
            Err(Error::Invalid(_))
        ));
        assert!(v.verify::<Claims>("not.a.token").await.is_err());
    }

    #[tokio::test]
    async fn unknown_keys_refetch_at_most_once_per_interval() {
        let idp = idp().await;
        let v = Verifier::new(
            reqwest::Client::new(),
            "https://idp.test",
            "kynestro",
            &format!("{}/jwks", idp.base),
        );
        v.verify::<Claims>(&token(&idp, "k1", "kynestro", 60))
            .await
            .unwrap();
        for _ in 0..5 {
            assert!(matches!(
                v.verify::<Claims>(&token(&idp, "forged", "kynestro", 60))
                    .await,
                Err(Error::UnknownKey)
            ));
        }
        assert_eq!(idp.fetches.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn symmetric_algorithms_are_refused() {
        let mut h = Header::new(Algorithm::HS256);
        h.kid = Some("k1".into());
        let t = jsonwebtoken::encode(
            &h,
            &serde_json::json!({"sub": "x"}),
            &EncodingKey::from_secret(b"pub"),
        )
        .unwrap();
        let v = Verifier::new(reqwest::Client::new(), "i", "a", "http://127.0.0.1:9/jwks");
        assert!(matches!(
            v.verify::<Claims>(&t).await,
            Err(Error::Algorithm(Algorithm::HS256))
        ));
    }

    fn verifier(idp: &Idp) -> Verifier {
        Verifier::new(
            reqwest::Client::new(),
            "https://idp.test",
            "kynestro",
            &format!("{}/jwks", idp.base),
        )
    }

    #[tokio::test]
    async fn tokens_not_yet_valid_are_refused() {
        let idp = idp().await;
        let early = token_with(&idp, "k1", "kynestro", 600, 300, Algorithm::RS256);
        assert!(matches!(
            verifier(&idp).verify::<Claims>(&early).await,
            Err(Error::Invalid(_))
        ));
    }

    #[tokio::test]
    async fn the_algorithm_must_be_accepted_and_the_keys_own() {
        let idp = idp().await;
        // The key is published for RS256; the same RSA key signs a valid RS384 token.
        let other = token_with(&idp, "k1", "kynestro", 60, 0, Algorithm::RS384);
        assert!(matches!(
            verifier(&idp).verify::<Claims>(&other).await,
            Err(Error::Algorithm(Algorithm::RS384))
        ));
        let narrowed = verifier(&idp).algorithms(&[Algorithm::ES256, Algorithm::HS256]);
        assert!(matches!(
            narrowed
                .verify::<Claims>(&token(&idp, "k1", "kynestro", 60))
                .await,
            Err(Error::Algorithm(Algorithm::RS256))
        ));
    }

    #[tokio::test]
    async fn a_provider_that_is_down_is_asked_once_per_interval() {
        let fetches = Arc::new(AtomicUsize::new(0));
        let f = fetches.clone();
        let app = axum::Router::new().route(
            "/jwks",
            get(move || {
                f.fetch_add(1, Ordering::SeqCst);
                async { axum::http::StatusCode::SERVICE_UNAVAILABLE }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await });
        let idp = Idp {
            base,
            fetches,
            ..idp().await
        };
        let v = verifier(&idp);
        assert!(matches!(
            v.verify::<Claims>(&token(&idp, "k1", "kynestro", 60)).await,
            Err(Error::Keys(_))
        ));
        for _ in 0..5 {
            assert!(matches!(
                v.verify::<Claims>(&token(&idp, "k1", "kynestro", 60)).await,
                Err(Error::UnknownKey)
            ));
        }
        assert_eq!(idp.fetches.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn discovery_must_be_the_issuers_own_and_point_at_https() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let doc = |issuer: String, jwks: &'static str| {
            get(
                move || async move { Json(serde_json::json!({"issuer": issuer, "jwks_uri": jwks})) },
            )
        };
        let app = axum::Router::new()
            .route(
                "/other/.well-known/openid-configuration",
                doc(
                    "https://elsewhere.test".into(),
                    "https://elsewhere.test/jwks",
                ),
            )
            .route(
                "/plain/.well-known/openid-configuration",
                doc(format!("{base}/plain"), "http://keys.test/jwks"),
            )
            .route(
                "/good/.well-known/openid-configuration",
                doc(format!("{base}/good"), "https://keys.test/jwks"),
            );
        tokio::spawn(async move { axum::serve(listener, app).await });
        let discover = |path: &'static str| {
            let issuer = format!("{base}{path}");
            async move { Verifier::discover(reqwest::Client::new(), &issuer, "a").await }
        };
        assert!(matches!(discover("/other").await, Err(Error::Discovery(_))));
        assert!(matches!(discover("/plain").await, Err(Error::Discovery(_))));
        assert!(discover("/good").await.is_ok());
        // The same issuer but for a trailing slash is another issuer.
        assert!(matches!(discover("/good/").await, Err(Error::Discovery(_))));
    }

    #[tokio::test]
    async fn a_failed_fetch_is_retried_sooner_than_a_good_one() {
        let idp = idp().await;
        let upstream = format!("{}/jwks", idp.base);
        let calls = Arc::new(AtomicUsize::new(0));
        let c = calls.clone();
        // Down for the first request, then the provider's real keys.
        let app = axum::Router::new().route(
            "/jwks",
            get(move || {
                let first = c.fetch_add(1, Ordering::SeqCst) == 0;
                let upstream = upstream.clone();
                async move {
                    if first {
                        return Err(axum::http::StatusCode::SERVICE_UNAVAILABLE);
                    }
                    let keys: serde_json::Value =
                        reqwest::get(upstream).await.unwrap().json().await.unwrap();
                    Ok(Json(keys))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let flaky = format!("http://{}/jwks", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await });
        let v = Verifier::new(
            reqwest::Client::new(),
            "https://idp.test",
            "kynestro",
            &flaky,
        );
        let v = Verifier::with(Config {
            retry_after_failure: Duration::from_millis(200),
            ..v.0.config.clone()
        });
        let good = token(&idp, "k1", "kynestro", 60);
        assert!(matches!(
            v.verify::<Claims>(&good).await,
            Err(Error::Keys(_))
        ));
        // Inside the retry interval the provider is left alone.
        assert!(matches!(
            v.verify::<Claims>(&good).await,
            Err(Error::UnknownKey)
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        // Past it (and long before min_refresh's minute), it is asked again.
        tokio::time::sleep(Duration::from_millis(250)).await;
        assert_eq!(v.verify::<Claims>(&good).await.unwrap().sub, "agent-7");
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    /// Every character of a token is covered by its signature or is the signature:
    /// change any one, to anything, and it is no token.
    #[tokio::test]
    async fn any_edit_to_a_token_voids_it() {
        const ALPHABET: &[u8] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.";
        let idp = idp().await;
        let v = verifier(&idp);
        let good = token(&idp, "k1", "kynestro", 60);
        v.verify::<Claims>(&good).await.unwrap();
        for at in 0..good.len() {
            // Three replacements per position, spread over the alphabet.
            for step in [1, 23, 47] {
                let was = ALPHABET
                    .iter()
                    .position(|c| *c == good.as_bytes()[at])
                    .unwrap();
                let to = ALPHABET[(was + step) % ALPHABET.len()];
                let mut edited = good.clone().into_bytes();
                edited[at] = to;
                let edited = String::from_utf8(edited).unwrap();
                assert!(
                    v.verify::<Claims>(&edited).await.is_err(),
                    "position {at} of {} accepted {:?}",
                    good.len(),
                    to as char
                );
            }
        }
        // Nor a token with its signature cut off, or another token's signature.
        let (signed, _signature) = good.rsplit_once('.').unwrap();
        assert!(v.verify::<Claims>(&format!("{signed}.")).await.is_err());
        let other = token(&idp, "k1", "kynestro", 61);
        let grafted = format!("{signed}.{}", other.rsplit_once('.').unwrap().1);
        assert!(v.verify::<Claims>(&grafted).await.is_err());
    }

    /// A claim the verifier requires cannot be left out, and the issuer and audience
    /// cannot be near misses.
    #[tokio::test]
    async fn required_claims_and_exact_names() {
        let idp = idp().await;
        let v = verifier(&idp);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let sign = |claims: serde_json::Value| {
            let mut h = Header::new(Algorithm::RS256);
            h.kid = Some("k1".into());
            jsonwebtoken::encode(&h, &claims, &idp.key).unwrap()
        };
        let whole = serde_json::json!({
            "sub": "agent-7", "iss": "https://idp.test", "aud": "kynestro", "exp": now + 60,
        });
        v.verify::<Claims>(&sign(whole.clone())).await.unwrap();
        for missing in ["sub", "iss", "aud", "exp"] {
            let mut claims = whole.clone();
            claims.as_object_mut().unwrap().remove(missing);
            assert!(
                v.verify::<Claims>(&sign(claims)).await.is_err(),
                "without {missing}"
            );
        }
        for (claim, near) in [
            ("iss", serde_json::json!("https://idp.test/")),
            ("iss", serde_json::json!("https://idp.test.evil.example")),
            ("iss", serde_json::json!("http://idp.test")),
            ("aud", serde_json::json!("kynestro2")),
            ("aud", serde_json::json!("KYNESTRO")),
            ("aud", serde_json::json!(["other", "another"])),
            ("exp", serde_json::json!(now - 6)),
            ("exp", serde_json::json!("never")),
        ] {
            let mut claims = whole.clone();
            claims[claim] = near.clone();
            assert!(
                v.verify::<Claims>(&sign(claims)).await.is_err(),
                "{claim} = {near}"
            );
        }
        // An audience list that includes this service is this service's token.
        let mut listed = whole.clone();
        listed["aud"] = serde_json::json!(["other", "kynestro"]);
        v.verify::<Claims>(&sign(listed)).await.unwrap();
    }

    /// A cold verifier under a burst asks the provider once: one caller fetches and
    /// the rest wait for its answer.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_burst_on_a_cold_verifier_fetches_the_keys_once() {
        let idp = idp().await;
        let v = verifier(&idp);
        let good = token(&idp, "k1", "kynestro", 60);
        let forged = token(&idp, "nobody", "kynestro", 60);
        let tasks: Vec<_> = (0..64)
            .map(|i| {
                let (v, t) = (
                    v.clone(),
                    if i % 2 == 0 {
                        good.clone()
                    } else {
                        forged.clone()
                    },
                );
                tokio::spawn(async move { v.verify::<Claims>(&t).await.is_ok() })
            })
            .collect();
        let mut accepted = 0;
        for t in tasks {
            accepted += usize::from(t.await.unwrap());
        }
        assert_eq!(accepted, 32, "the good tokens, and only them");
        assert_eq!(idp.fetches.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn key_urls_are_https_or_this_machine() {
        for ok in [
            "https://keys.example/jwks",
            "http://127.0.0.1:8080/jwks",
            "http://localhost/jwks",
            "http://[::1]:9/jwks",
        ] {
            assert!(safe_url(ok), "{ok}");
        }
        for bad in [
            "http://keys.example/jwks",
            "http://127.0.0.1.evil.example/jwks",
            "ftp://127.0.0.1/jwks",
            "file:///etc/passwd",
            "//keys.example/jwks",
            "",
        ] {
            assert!(!safe_url(bad), "{bad}");
        }
    }

    #[test]
    fn the_refresh_interval_is_a_minute() {
        let v = Verifier::new(reqwest::Client::new(), "i", "a", "http://127.0.0.1:9/jwks");
        assert_eq!(v.min_refresh(), Duration::from_secs(60));
    }
}
